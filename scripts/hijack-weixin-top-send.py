#!/usr/bin/env python
import argparse
import json
import sys
import threading

import frida


SCRIPT = r"""
const TARGET_CONVERSATION = {{TARGET_CONVERSATION_JSON}};
const TARGET_BODY = {{TARGET_BODY_JSON}};
const TRIGGER_BODY = {{TRIGGER_BODY_JSON}};
const BASELINE_SECONDS = {{BASELINE_SECONDS}};

function safePtrString(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (e) {
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
    if (cap > 15) {
      dataPtr = addr.readPointer();
      if (dataPtr.isNull()) return null;
    }
    return dataPtr.readUtf8String(len);
  } catch (e) {
    return null;
  }
}

function writeHeapStdString(addr, value, wxAlloc) {
  const utf8 = Array.from(value).map(ch => ch.charCodeAt(0));
  if (utf8.length <= 15) {
    addr.writeByteArray(new Uint8Array(16));
    for (let i = 0; i < utf8.length; i++) {
      addr.add(i).writeU8(utf8[i]);
    }
    addr.add(utf8.length).writeU8(0);
    addr.add(0x10).writeU32(utf8.length);
    addr.add(0x14).writeU32(0);
    addr.add(0x18).writeU32(15);
    addr.add(0x1c).writeU32(0);
    return;
  }

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

function readVector(base) {
  try {
    const begin = base.readPointer();
    const end = base.add(Process.pointerSize).readPointer();
    const count = end.sub(begin).toInt32() / 0x10;
    return { begin, end, count };
  } catch (e) {
    return null;
  }
}

const mod = Process.getModuleByName('Weixin.dll');
const wxAlloc = new NativeFunction(mod.base.add(0x6309d1c), 'pointer', ['ulong']);
const topSendFn = mod.base.add(0x15af8e0);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
let fired = false;

send({
  kind: 'status',
  target_fn: topSendFn.toString(),
  trigger_body: TRIGGER_BODY,
  target_conversation: TARGET_CONVERSATION,
  target_body: TARGET_BODY,
  baseline_seconds: BASELINE_SECONDS,
});

Interceptor.attach(topSendFn, {
  onEnter(args) {
    try {
      if (Date.now() < baselineUntil) return;
      if (fired) return;

      const wrapper = args[0];
      const vec = readVector(wrapper.add(0x8));
      if (!vec || vec.count < 1) return;

      const pair = vec.begin;
      const sourceObj = pair.readPointer();
      if (sourceObj.isNull()) return;

      const currentConversation = readStdString(sourceObj.add(0xb0));
      const currentBody = readStdString(sourceObj.add(0x660));
      const currentUuid = readStdString(sourceObj.add(0x600));

      if (currentBody !== TRIGGER_BODY) return;

      writeHeapStdString(sourceObj.add(0xb0), TARGET_CONVERSATION, wxAlloc);
      writeHeapStdString(sourceObj.add(0x660), TARGET_BODY, wxAlloc);
      fired = true;

      send({
        kind: 'top_send_hijack',
        wrapper_ptr: safePtrString(wrapper),
        source_obj: safePtrString(sourceObj),
        before: {
          conversation: currentConversation,
          body: currentBody,
          uuid: currentUuid,
        },
        after: {
          conversation: readStdString(sourceObj.add(0xb0)),
          body: readStdString(sourceObj.add(0x660)),
          uuid: readStdString(sourceObj.add(0x600)),
        }
      });
    } catch (e) {
      send({ kind: 'error', where: 'topSendFn', error: String(e) });
    }
  }
});

setTimeout(() => send({ kind: 'armed' }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat', fired }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="Exact Weixin.exe PID to attach to")
    parser.add_argument("--conversation-id", required=True)
    parser.add_argument("--body", required=True)
    parser.add_argument("--trigger-body", required=True)
    parser.add_argument("--baseline-seconds", type=int, default=3)
    args = parser.parse_args()

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
        SCRIPT.replace("{{TARGET_CONVERSATION_JSON}}", json.dumps(args.conversation_id))
        .replace("{{TARGET_BODY_JSON}}", json.dumps(args.body))
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
