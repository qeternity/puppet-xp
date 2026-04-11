#!/usr/bin/env python
import argparse
import json
import sys
import threading

import frida


SCRIPT = r"""
const TARGET_MATCH = {{TARGET_MATCH}};
const HIJACK_CONVERSATION = {{HIJACK_CONVERSATION}};
const HIJACK_BODY = {{HIJACK_BODY}};
const BASELINE_SECONDS = {{BASELINE_SECONDS}};

const mod = Process.getModuleByName('Weixin.dll');
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
let fired = false;

function safe(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (_) {
    return '0x0';
  }
}

function readStdString(addr) {
  try {
    const len = addr.add(0x10).readU32();
    const cap = addr.add(0x18).readU32();
    if (len === 0) return '';
    if (len > 0x4000 || cap > 0x100000) return null;
    let dataPtr = addr;
    if (cap > 15) dataPtr = addr.readPointer();
    if (!dataPtr || dataPtr.isNull()) return null;
    return dataPtr.readUtf8String(len);
  } catch (_) {
    return null;
  }
}

function writeHeapStdString(addr, value) {
  const bytes = Array.from(value).map(ch => ch.charCodeAt(0));
  if (bytes.length <= 15) {
    addr.writeByteArray(new Uint8Array(16));
    for (let i = 0; i < bytes.length; i++) addr.add(i).writeU8(bytes[i]);
    addr.add(bytes.length).writeU8(0);
    addr.add(0x10).writeU32(bytes.length);
    addr.add(0x14).writeU32(0);
    addr.add(0x18).writeU32(15);
    addr.add(0x1c).writeU32(0);
    return;
  }
  const wxAlloc = new NativeFunction(mod.base.add(0x6309d1c), 'pointer', ['ulong']);
  const cap = bytes.length;
  const buf = wxAlloc(cap + 1);
  for (let i = 0; i < bytes.length; i++) buf.add(i).writeU8(bytes[i]);
  buf.add(bytes.length).writeU8(0);
  addr.writeByteArray(new Uint8Array(16));
  addr.writePointer(buf);
  addr.add(0x10).writeU32(bytes.length);
  addr.add(0x14).writeU32(0);
  addr.add(0x18).writeU32(cap);
  addr.add(0x1c).writeU32(0);
}

function cloneBlock(src, size) {
  const wxAlloc = new NativeFunction(mod.base.add(0x6309d1c), 'pointer', ['ulong']);
  const dst = wxAlloc(size);
  Memory.copy(dst, src, size);
  return dst;
}

function emit(kind, payload) {
  if (Date.now() < baselineUntil) return;
  send({ kind, payload });
}

Interceptor.attach(mod.base.add(0x159ef90), {
  onEnter(args) {
    try {
      const arg0 = args[0];
      const arg1 = args[1];
      const convo = readStdString(arg1.add(0x38));
      const sender = readStdString(arg1.add(0x58));
      const msgsource = readStdString(arg1.add(0x140));
      const body = readStdString(arg1.add(0x180));
      emit('wrapper_seen', {
        thread_id: Process.getCurrentThreadId(),
        arg0: safe(arg0),
        arg1: safe(arg1),
        convo,
        sender,
        body,
        msgsource,
      });
      if (fired) return;
      if (body !== TARGET_MATCH) return;
      fired = true;

      const clone = cloneBlock(arg1, 0x400);
      if (HIJACK_CONVERSATION) writeHeapStdString(clone.add(0x38), HIJACK_CONVERSATION);
      if (sender) writeHeapStdString(clone.add(0x58), sender);
      if (msgsource) writeHeapStdString(clone.add(0x140), msgsource);
      if (HIJACK_BODY) writeHeapStdString(clone.add(0x180), HIJACK_BODY);

      emit('wrapper_clone_ready', {
        thread_id: Process.getCurrentThreadId(),
        arg0: safe(arg0),
        original_arg1: safe(arg1),
        clone: safe(clone),
        clone_fields: {
          convo: readStdString(clone.add(0x38)),
          sender: readStdString(clone.add(0x58)),
          msgsource: readStdString(clone.add(0x140)),
          body: readStdString(clone.add(0x180)),
        },
      });

      const resend = new NativeFunction(mod.base.add(0x159ef90), 'void', ['pointer', 'pointer']);
      resend(arg0, clone);
      emit('wrapper_clone_invoked', {
        thread_id: Process.getCurrentThreadId(),
        clone: safe(clone),
      });
    } catch (e) {
      send({ kind: 'error', where: 'FUN_18159ef90', error: String(e) });
    }
  }
});

send({
  kind: 'status',
  function: safe(mod.base.add(0x159ef90)),
  baseline_seconds: BASELINE_SECONDS,
  target_match: TARGET_MATCH,
  hijack_conversation: HIJACK_CONVERSATION,
  hijack_body: HIJACK_BODY,
});

setTimeout(() => send({ kind: 'armed' }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat', fired }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--target-match", default="skynet")
    parser.add_argument("--conversation-id", default="27208021116@chatroom")
    parser.add_argument("--body", default="autonomous-resend-1")
    parser.add_argument("--baseline-seconds", type=int, default=0)
    args = parser.parse_args()

    rendered = (
        SCRIPT.replace("{{TARGET_MATCH}}", json.dumps(args.target_match))
        .replace("{{HIJACK_CONVERSATION}}", json.dumps(args.conversation_id))
        .replace("{{HIJACK_BODY}}", json.dumps(args.body))
        .replace("{{BASELINE_SECONDS}}", str(args.baseline_seconds))
    )
    device = frida.get_local_device()
    session = device.attach(args.pid)
    script = session.create_script(rendered)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    print(json.dumps({"kind": "attached", "pid": args.pid}, ensure_ascii=False), flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
