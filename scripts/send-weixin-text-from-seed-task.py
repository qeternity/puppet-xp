#!/usr/bin/env python
import argparse
import json
import sys
import threading

import frida


SCRIPT = r"""
const TARGET_BODY = {{TARGET_BODY_JSON}};
const TARGET_CONVO = {{TARGET_CONVO_JSON}};
const TRIGGER_BODY = {{TRIGGER_BODY_JSON}};
const BASELINE_SECONDS = {{BASELINE_SECONDS}};

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
  } catch (e) {
    return null;
  }
}

function safePtrString(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (e) {
    return '0x0';
  }
}

function writeInlineStdString(addr, value) {
  const bytes = Array.from(value).map(ch => ch.charCodeAt(0));
  if (bytes.length > 15) {
    throw new Error('inline std::string write only supports <= 15 chars');
  }
  addr.writeByteArray(new Uint8Array(16));
  for (let i = 0; i < bytes.length; i++) {
    addr.add(i).writeU8(bytes[i]);
  }
  addr.add(bytes.length).writeU8(0);
  addr.add(0x10).writeU32(bytes.length);
  addr.add(0x14).writeU32(0);
  addr.add(0x18).writeU32(15);
  addr.add(0x1c).writeU32(0);
}

function getSelfUsername(mod) {
  try {
    const getSnapshotMgr = new NativeFunction(mod.base.add(0x1f540), 'pointer', []);
    const buildSnapshot = new NativeFunction(mod.base.add(0x20aa0), 'pointer', ['pointer', 'pointer', 'uchar']);
    const snapshotMgr = getSnapshotMgr();
    const snapshotBuf = Memory.alloc(0x200);
    snapshotBuf.writeByteArray(new Uint8Array(0x200));
    buildSnapshot(snapshotMgr, snapshotBuf, 1);
    return readStdString(snapshotBuf.add(0x0));
  } catch (e) {
    return null;
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

const mod = Process.getModuleByName('Weixin.dll');
const wxAlloc = new NativeFunction(mod.base.add(0x6309d1c), 'pointer', ['ulong']);
const getRoot = new NativeFunction(mod.base.add(0x20800), 'pointer', ['pointer']);
const getSvc = new NativeFunction(mod.base.add(0x2fbff0), 'void', ['pointer', 'pointer']);
const getSchedCtx = new NativeFunction(mod.base.add(0x633270), 'void', ['pointer', 'pointer']);
const scheduleTask = new NativeFunction(mod.base.add(0x314950), 'void', ['pointer', 'pointer', 'pointer', 'pointer']);
const scheduleFn = mod.base.add(0x314950);

const selfUsername = getSelfUsername(mod);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
let fired = false;

function writeHeapStdString(addr, value) {
  const utf8 = Array.from(value).map(ch => ch.charCodeAt(0));
  const buf = wxAlloc(utf8.length + 1);
  for (let i = 0; i < utf8.length; i++) {
    buf.add(i).writeU8(utf8[i]);
  }
  buf.add(utf8.length).writeU8(0);
  addr.writeByteArray(new Uint8Array(16));
  addr.writePointer(buf);
  addr.add(0x10).writeU32(utf8.length);
  addr.add(0x14).writeU32(0);
  addr.add(0x18).writeU32(utf8.length);
  addr.add(0x1c).writeU32(0);
}

function parseTask(taskPtr) {
  const sender38 = readStdString(taskPtr.add(0x38));
  const convo58 = readStdString(taskPtr.add(0x58));
  const sender78 = readStdString(taskPtr.add(0x78));
  const convo98 = readStdString(taskPtr.add(0x98));
  const bodyE0 = readStdString(taskPtr.add(0xe0));
  const msgsource100 = readStdString(taskPtr.add(0x100));
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
  const msgsource = looksLikeMsgsource(msgsource100) ? msgsource100 : '';

  return {
    sender38, convo58, sender78, convo98, bodyE0, msgsource100,
    nestedSender10, nestedConvo30, nestedSender50, nestedConvo70,
    nestedBody0, nestedBody20,
    conversationId, senderUsername, body, msgsource
  };
}

function cloneTaskWithOwnedStrings(srcPtr, targetBody, targetConvo) {
  const clone = wxAlloc(0x158);
  Memory.copy(clone, srcPtr, 0x158);
  const src = parseTask(srcPtr);

  const senderA = src.sender38 || src.sender78 || src.nestedSender10 || src.nestedSender50 || selfUsername || '';
  const senderB = src.sender78 || src.sender38 || src.nestedSender50 || src.nestedSender10 || senderA;
  const convoA = targetConvo || src.convo58 || src.convo98 || src.nestedConvo30 || src.nestedConvo70 || '';
  const convoB = targetConvo || src.convo98 || src.convo58 || src.nestedConvo70 || src.nestedConvo30 || convoA;
  const nestedConvoA = targetConvo || src.nestedConvo30 || src.nestedConvo70 || src.convo58 || src.convo98 || '';
  const nestedConvoB = targetConvo || src.nestedConvo70 || src.nestedConvo30 || src.convo98 || src.convo58 || nestedConvoA;
  const msgsource = src.msgsource100 || '';

  if (senderA) writeHeapStdString(clone.add(0x38), senderA);
  if (convoA) writeHeapStdString(clone.add(0x58), convoA);
  if (senderB) writeHeapStdString(clone.add(0x78), senderB);
  if (convoB) writeHeapStdString(clone.add(0x98), convoB);
  if (msgsource) writeHeapStdString(clone.add(0x100), msgsource);

  if (senderA) writeHeapStdString(clone.add(0x28).add(0x10), senderA);
  if (nestedConvoA) writeHeapStdString(clone.add(0x28).add(0x30), nestedConvoA);
  if (senderB) writeHeapStdString(clone.add(0x28).add(0x50), senderB);
  if (nestedConvoB) writeHeapStdString(clone.add(0x28).add(0x70), nestedConvoB);

  writeInlineStdString(clone.add(0xe0), targetBody);
  return clone;
}

function resubmitClone(srcPtr, targetBody, targetConvo) {
  const clonedTask = cloneTaskWithOwnedStrings(srcPtr, targetBody, targetConvo);

  const out58 = Memory.alloc(0x20);
  out58.writeByteArray(new Uint8Array(0x20));
  getRoot(out58);
  const v58 = out58.readPointer();

  const out40 = Memory.alloc(0x20);
  out40.writeByteArray(new Uint8Array(0x20));
  getSvc(v58, out40);
  const v40 = out40.readPointer();

  const out78 = Memory.alloc(0x20);
  out78.writeByteArray(new Uint8Array(0x20));
  getSchedCtx(v40, out78);

  const holder = Memory.alloc(Process.pointerSize);
  holder.writePointer(clonedTask);

  scheduleTask(out78, holder, ptr(0), ptr(0));

  return {
    cloned_task_ptr: safePtrString(clonedTask),
    root_ctx: safePtrString(v58),
    svc_ctx: safePtrString(v40),
    target_body: targetBody,
    target_conversation: targetConvo,
    clone_sender38: readStdString(clonedTask.add(0x38)),
    clone_convo58: readStdString(clonedTask.add(0x58)),
    clone_bodyE0: readStdString(clonedTask.add(0xe0)),
    clone_msgsource100: readStdString(clonedTask.add(0x100)),
  };
}

send({
  kind: 'status',
  self_username: selfUsername,
  baseline_seconds: BASELINE_SECONDS,
  trigger_body: TRIGGER_BODY,
  target_conversation: TARGET_CONVO,
  target_body: TARGET_BODY,
  schedule_function: scheduleFn.toString(),
});

Interceptor.attach(scheduleFn, {
  onEnter(args) {
    try {
      if (fired) return;
      const taskHolder = args[1];
      const taskPtr = taskHolder.readPointer();
      if (taskPtr.isNull()) return;
      const parsed = parseTask(taskPtr);
      if (!parsed.body || !parsed.conversationId || !parsed.senderUsername) return;
      if (Date.now() < baselineUntil) return;
      if (parsed.body === TARGET_BODY) return;
      if (TRIGGER_BODY && parsed.body !== TRIGGER_BODY) return;

      const seed = {
        task_ptr: safePtrString(taskPtr),
        conversation_id: parsed.conversationId,
        sender_username: parsed.senderUsername,
        body: parsed.body,
        msgsource: parsed.msgsource,
      };

      fired = true;
      const submit = resubmitClone(taskPtr, TARGET_BODY, TARGET_CONVO || parsed.conversationId);
      send({ kind: 'seed_task_seen', seed, submit });
    } catch (e) {
      send({ kind: 'error', where: 'scheduleFn', error: String(e) });
    }
  }
});

setTimeout(() => send({ kind: 'armed' }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat', fired }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="Exact Weixin.exe PID to attach to")
    parser.add_argument("--body", required=True, help="Outgoing message body (<= 15 UTF-8 bytes)")
    parser.add_argument("--conversation-id", help="Target conversation id override")
    parser.add_argument("--trigger-body", help="Only clone when the real seed send body matches this text")
    parser.add_argument("--baseline-seconds", type=int, default=3)
    args = parser.parse_args()

    if len(args.body.encode("utf-8")) > 15:
        raise SystemExit("Body must be <= 15 UTF-8 bytes")

    device = frida.get_local_device()
    if args.pid is not None:
        pid = args.pid
    else:
        matches = [p for p in device.enumerate_processes() if p.name.lower() == "weixin.exe"]
        if not matches:
            raise SystemExit("Weixin.exe not found")
        pid = sorted(matches, key=lambda p: p.pid)[0].pid

    session = device.attach(pid)
    rendered = (
        SCRIPT.replace("{{TARGET_BODY_JSON}}", json.dumps(args.body))
        .replace("{{TARGET_CONVO_JSON}}", json.dumps(args.conversation_id))
        .replace("{{TRIGGER_BODY_JSON}}", json.dumps(args.trigger_body))
        .replace("{{BASELINE_SECONDS}}", str(args.baseline_seconds))
    )
    script = session.create_script(rendered)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.buffer.write((str(payload) + "\n").encode("utf-8", errors="replace"))
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    sys.stdout.buffer.write((f"attached pid={pid}\n").encode("utf-8"))
    sys.stdout.flush()
    threading.Event().wait()


if __name__ == "__main__":
    main()
