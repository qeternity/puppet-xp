#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT = r"""
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

function readU32(base, off) {
  try {
    return base.add(off).readU32();
  } catch (e) {
    return null;
  }
}

function readPtr(base, off) {
  try {
    return base.add(off).readPointer();
  } catch (e) {
    return ptr(0);
  }
}

function scanPayloadPtrs(payloadBase) {
  const interesting = [];
  for (const off of [0x8,0x48,0x88,0xc8,0xe0]) {
    const p = readPtr(payloadBase, off);
    if (p.isNull()) {
      interesting.push({ offset: '0x' + off.toString(16), ptr: '0x0' });
      continue;
    }
    let refs = null;
    try {
      refs = {
        ref8: p.add(0x8).readU32(),
        refc: p.add(0xc).readU32(),
      };
    } catch (e) {}
    interesting.push({
      offset: '0x' + off.toString(16),
      ptr: safePtrString(p),
      vtable: safePtrString(readPtr(p, 0)),
      refs,
    });
  }
  return interesting;
}

const mod = Process.getModuleByName('Weixin.dll');
const scheduleFn = mod.base.add(0x314950);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
let seen = {};

send({
  kind: 'status',
  schedule_function: scheduleFn.toString(),
  baseline_seconds: BASELINE_SECONDS,
});

Interceptor.attach(scheduleFn, {
  onEnter(args) {
    try {
      if (Date.now() < baselineUntil) return;
      const taskHolder = args[1];
      const taskPtr = taskHolder.readPointer();
      if (taskPtr.isNull()) return;
      const payloadBase = taskPtr.add(0x28);
      const conversation = readStdString(taskPtr.add(0x58));
      const body = readStdString(taskPtr.add(0xe0));
      if (!conversation || !body) return;
      const info = {
        task_ptr: safePtrString(taskPtr),
        payload_base: safePtrString(payloadBase),
        conversation,
        body,
        payload_string_f0: readStdString(payloadBase.add(0xf0)),
        payload_string_118: readStdString(payloadBase.add(0x118)),
        payload_string_140: readStdString(payloadBase.add(0x140)),
        payload_int_108: readU32(payloadBase, 0x108),
        payload_int_110: readU32(payloadBase, 0x110),
        payload_int_130: readU32(payloadBase, 0x130),
        payload_refs: scanPayloadPtrs(payloadBase),
      };
      const key = JSON.stringify([conversation, body]);
      if (seen[key]) return;
      seen[key] = true;
      send({ kind: 'task_payload', info });
    } catch (e) {
      send({ kind: 'error', where: 'scheduleFn', error: String(e) });
    }
  }
});

setTimeout(() => send({ kind: 'armed' }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat', seen_count: Object.keys(seen).length }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--baseline-seconds", type=int, default=1)
    args = parser.parse_args()

    device = frida.get_local_device()
    session = device.attach(args.pid)
    rendered = SCRIPT.replace("{{BASELINE_SECONDS}}", str(args.baseline_seconds))
    script = session.create_script(rendered)

    def on_message(message, data):
      payload = message.get("payload", message)
      sys.stdout.buffer.write((str(payload) + "\n").encode("utf-8", errors="replace"))
      sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    sys.stdout.buffer.write((f"attached pid={args.pid}\n").encode("utf-8"))
    sys.stdout.flush()
    threading.Event().wait()


if __name__ == "__main__":
    main()
