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
const activeThreads = new Set();
let activeOriginalBody = null;

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

function emit(kind, payload) {
  if (Date.now() < baselineUntil) return;
  send({ kind, payload });
}

function shouldMatch(body) {
  if (!TARGET_MATCH || TARGET_MATCH === '*') return true;
  return body === TARGET_MATCH;
}

function rewritePayload(payloadPtr) {
  if (HIJACK_CONVERSATION) writeHeapStdString(payloadPtr.add(0x38), HIJACK_CONVERSATION);
  if (HIJACK_BODY) writeHeapStdString(payloadPtr.add(0x180), HIJACK_BODY);
}

function rewriteIfMatches(base, offsets) {
  if (!activeOriginalBody) return [];
  const rewrites = [];
  offsets.forEach((off) => {
    try {
      const slot = base.add(off);
      const value = readStdString(slot);
      if (value === activeOriginalBody) {
        writeHeapStdString(slot, HIJACK_BODY);
        rewrites.push({ offset: '0x' + off.toString(16), before: value, after: readStdString(slot) });
      }
    } catch (_) {}
  });
  return rewrites;
}

Interceptor.attach(mod.base.add(0x159ef90), {
  onEnter(args) {
    try {
      const tid = Process.getCurrentThreadId();
      const arg1 = args[1];
      const convo = readStdString(arg1.add(0x38));
      const sender = readStdString(arg1.add(0x58));
      const msgsource = readStdString(arg1.add(0x140));
      const body = readStdString(arg1.add(0x180));
      emit('wrapper_seen', {
        thread_id: tid,
        arg0: safe(args[0]),
        arg1: safe(arg1),
        convo,
        sender,
        body,
        msgsource,
      });
      if (fired) return;
      if (!shouldMatch(body)) return;
      fired = true;
      activeOriginalBody = body;
      activeThreads.add(tid);
      rewritePayload(arg1);

      emit('wrapper_rewritten', {
        thread_id: tid,
        arg1: safe(arg1),
        fields: {
          convo: readStdString(arg1.add(0x38)),
          sender: readStdString(arg1.add(0x58)),
          msgsource: readStdString(arg1.add(0x140)),
          body: readStdString(arg1.add(0x180)),
        },
      });
    } catch (e) {
      send({ kind: 'error', where: 'FUN_18159ef90', error: String(e) });
    }
  }
});

Interceptor.attach(mod.base.add(0x159e480), {
  onEnter(args) {
    try {
      const tid = Process.getCurrentThreadId();
      const arg2 = args[2];
      const convo = readStdString(arg2.add(0x38));
      const sender = readStdString(arg2.add(0x58));
      const msgsource = readStdString(arg2.add(0x140));
      const body = readStdString(arg2.add(0x180));
      emit('wrapper2_seen', {
        thread_id: tid,
        arg0: safe(args[0]),
        arg1: safe(args[1]),
        arg2: safe(arg2),
        convo,
        sender,
        body,
        msgsource,
      });
      if (!activeThreads.has(tid)) return;
      if (body && !shouldMatch(body) && body !== HIJACK_BODY) return;
      rewritePayload(arg2);
      emit('wrapper2_rewritten', {
        thread_id: tid,
        arg2: safe(arg2),
        fields: {
          convo: readStdString(arg2.add(0x38)),
          sender: readStdString(arg2.add(0x58)),
          msgsource: readStdString(arg2.add(0x140)),
          body: readStdString(arg2.add(0x180)),
        },
      });
    } catch (e) {
      send({ kind: 'error', where: 'FUN_18159e480', error: String(e) });
    }
  }
});

Interceptor.attach(mod.base.add(0x30a20), {
  onEnter(args) {
    try {
      if (!fired || !activeOriginalBody) return;
      const cb = args[0];
      const param2 = args[1];
      const rewrites = [];
      rewrites.push(...rewriteIfMatches(cb, [0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0, 0x100, 0x120, 0x140, 0x160, 0x180, 0x1a0, 0x1c0]));
      rewrites.push(...rewriteIfMatches(param2, [0x0, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0, 0x100, 0x120, 0x140, 0x160, 0x180]));
      const p1b = cb.add(0xd8).readPointer();
      const p1c = cb.add(0xe0).readPointer();
      if (p1b && !p1b.isNull()) rewrites.push(...rewriteIfMatches(p1b, [0x60, 0x80, 0xa0, 0xc0, 0xe0, 0x100]));
      if (p1c && !p1c.isNull()) rewrites.push(...rewriteIfMatches(p1c, [0x60, 0x80, 0xa0, 0xc0, 0xe0, 0x100]));
      if (rewrites.length > 0) {
        emit('callback_rewritten', {
          thread_id: Process.getCurrentThreadId(),
          cb: safe(cb),
          param2: safe(param2),
          p1b: safe(p1b),
          p1c: safe(p1c),
          original_body: activeOriginalBody,
          rewrites,
        });
      }
    } catch (e) {
      send({ kind: 'error', where: 'FUN_180030a20', error: String(e) });
    }
  }
});

send({
  kind: 'status',
  function: safe(mod.base.add(0x159ef90)),
  function2: safe(mod.base.add(0x159e480)),
  function3: safe(mod.base.add(0x30a20)),
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
    parser.add_argument("--body", default="autonomous-resend-2")
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
