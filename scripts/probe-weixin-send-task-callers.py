#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT = r"""
const BASELINE_SECONDS = {{BASELINE_SECONDS}};
const TARGET_CONVERSATION = {{TARGET_CONVERSATION}};
const TARGET_BODY = {{TARGET_BODY}};

function readStdString(addr) {
  try {
    const len = addr.add(0x10).readU32();
    const cap = addr.add(0x18).readU32();
    if (len === 0) return '';
    if (len > 0x4000 || cap > 0x100000) return null;
    let dataPtr = addr;
    if (cap > 15) {
      dataPtr = addr.readPointer();
      if (dataPtr.isNull()) return null;
    }
    return dataPtr.readUtf8String(len);
  } catch (_) {
    return null;
  }
}

function safePtrString(p) {
  try {
    if (p === null || p.isNull()) return '0x0';
    return p.toString();
  } catch (_) {
    return '0x0';
  }
}

function isConversationId(s) {
  if (!s) return false;
  return s.indexOf('@chatroom') >= 0 || s.indexOf('wxid_') === 0 || s === 'filehelper' || s === 'weixin';
}

function looksLikeMsgsource(s) {
  return !!s && s.indexOf('<msgsource') === 0;
}

function plausibleBody(s) {
  if (!s) return false;
  if (s.length < 1 || s.length > 4096) return false;
  if (looksLikeMsgsource(s)) return false;
  if (isConversationId(s)) return false;
  return /^[\x20-\x7e\u00a0-\uffff\r\n\t]+$/.test(s);
}

function parseSendTask(taskPtr) {
  const sender38 = readStdString(taskPtr.add(0x38));
  const convo58 = readStdString(taskPtr.add(0x58));
  const sender78 = readStdString(taskPtr.add(0x78));
  const convo98 = readStdString(taskPtr.add(0x98));
  const bodyE0 = readStdString(taskPtr.add(0xe0));
  const nestedSender10 = readStdString(taskPtr.add(0x28).add(0x10));
  const nestedConvo30 = readStdString(taskPtr.add(0x28).add(0x30));
  const nestedSender50 = readStdString(taskPtr.add(0x28).add(0x50));
  const nestedConvo70 = readStdString(taskPtr.add(0x28).add(0x70));
  const nestedBody0 = readStdString(taskPtr.add(0x110).add(0x0));
  const nestedBody20 = readStdString(taskPtr.add(0x110).add(0x20));

  const conversationId = isConversationId(convo58) ? convo58 :
    (isConversationId(convo98) ? convo98 :
      (isConversationId(nestedConvo30) ? nestedConvo30 :
        (isConversationId(nestedConvo70) ? nestedConvo70 : null)));

  const senderUsername = sender38 || sender78 || nestedSender10 || nestedSender50 || null;
  const body = plausibleBody(bodyE0) ? bodyE0 :
    (plausibleBody(nestedBody0) ? nestedBody0 :
      (plausibleBody(nestedBody20) ? nestedBody20 : null));

  if (!conversationId || !senderUsername || !body) return null;
  return {
    task_ptr: safePtrString(taskPtr),
    conversation_id: conversationId,
    sender_username: senderUsername,
    content: body,
  };
}

function frameInfo(addr) {
  try {
    const symbol = DebugSymbol.fromAddress(addr);
    const owner = Process.findModuleByAddress(addr);
    let rel = null;
    try {
      if (owner) rel = ptr(addr).sub(owner.base).toString();
    } catch (_) {
    }
    return {
      address: safePtrString(addr),
      relative: rel,
      owner_base: owner ? safePtrString(owner.base) : null,
      owner_name: owner ? owner.name : null,
      name: symbol && symbol.name ? symbol.name : null,
      module: symbol && symbol.moduleName ? symbol.moduleName : null,
    };
  } catch (_) {
    return {
      address: safePtrString(addr),
      relative: null,
      name: null,
      module: null,
    };
  }
}

const mod = Process.getModuleByName('Weixin.dll');
const scheduleFn = mod.base.add(0x314950);
const seen = new Set();
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);

send({
  kind: 'status',
  schedule_function: safePtrString(scheduleFn),
  baseline_seconds: BASELINE_SECONDS,
  target_conversation: TARGET_CONVERSATION,
  target_body: TARGET_BODY,
});

Interceptor.attach(scheduleFn, {
  onEnter(args) {
    try {
      const taskHolder = args[1];
      const taskPtr = taskHolder.readPointer();
      if (!taskPtr || taskPtr.isNull()) return;
      const event = parseSendTask(taskPtr);
      if (!event) return;
      if (event.conversation_id !== TARGET_CONVERSATION || event.content !== TARGET_BODY) return;

      const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .slice(0, 20)
        .map((addr) => frameInfo(addr));
      const key = JSON.stringify(bt.map((x) => x.relative || x.address));
      if (seen.has(key)) return;
      seen.add(key);
      if (Date.now() < baselineUntil) return;

      send({
        kind: 'send_task_caller',
        event,
        thread_id: Process.getCurrentThreadId(),
        return_address: frameInfo(this.returnAddress),
        backtrace: bt,
      });
    } catch (e) {
      send({ kind: 'error', where: 'schedule_enter', error: String(e) });
    }
  }
});

setTimeout(() => send({ kind: 'armed', seen_count: seen.size }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat', seen_count: seen.size }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--baseline-seconds", type=int, default=1)
    parser.add_argument("--conversation", default="27208021116@chatroom")
    parser.add_argument("--body", default="skynet2")
    args = parser.parse_args()

    rendered = (
        SCRIPT.replace("{{BASELINE_SECONDS}}", str(args.baseline_seconds))
        .replace("{{TARGET_CONVERSATION}}", repr(args.conversation))
        .replace("{{TARGET_BODY}}", repr(args.body))
    )

    device = frida.get_local_device()
    session = device.attach(args.pid)
    script = session.create_script(rendered)

    def on_message(message, data):
      payload = message.get("payload", message)
      sys.stdout.write(str(payload) + "\n")
      sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    sys.stdout.write(f"attached pid={args.pid}\n")
    sys.stdout.flush()
    threading.Event().wait()


if __name__ == "__main__":
    main()
