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

function readVector(base) {
  try {
    const begin = base.readPointer();
    const end = base.add(Process.pointerSize).readPointer();
    const cap = base.add(Process.pointerSize * 2).readPointer();
    const count = end.sub(begin).toInt32() / 0x10;
    return { begin, end, cap, count };
  } catch (e) {
    return null;
  }
}

function scanPointers(sourceObj, ownerBase) {
  const out = [];
  for (let off = 0; off < 0x700; off += 8) {
    try {
      const p = sourceObj.add(off).readPointer();
      if (p.isNull()) continue;

      const exactSource = p.equals(sourceObj);
      const exactOwner = p.equals(ownerBase);
      const inOwner =
        p.compare(ownerBase) >= 0 &&
        p.compare(ownerBase.add(0x710)) < 0;

      if (!exactSource && !exactOwner && !inOwner) continue;

      out.push({
        offset: '0x' + off.toString(16),
        value: safePtrString(p),
        exact_source: exactSource,
        exact_owner: exactOwner,
        in_owner_block: inOwner,
      });
    } catch (e) {
    }
  }
  return out;
}

const mod = Process.getModuleByName('Weixin.dll');
const targetFn = mod.base.add(0x15af8e0);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
let seen = {};

send({
  kind: 'status',
  target_fn: targetFn.toString(),
  baseline_seconds: BASELINE_SECONDS,
});

Interceptor.attach(targetFn, {
  onEnter(args) {
    try {
      const wrapper = args[0];
      const vec = readVector(wrapper.add(0x8));
      if (!vec || vec.count < 1) return;

      const pair = vec.begin;
      const sourceObj = pair.readPointer();
      const ownerBase = pair.add(Process.pointerSize).readPointer();
      if (sourceObj.isNull() || ownerBase.isNull()) return;

      const conversation = readStdString(sourceObj.add(0xb0));
      const uuid = readStdString(sourceObj.add(0x600));
      const body = readStdString(sourceObj.add(0x660));
      const refs = {
        ref1: ownerBase.add(0x8).readU32(),
        ref2: ownerBase.add(0xc).readU32(),
      };
      const interesting = scanPointers(sourceObj, ownerBase);

      const payload = {
        wrapper: safePtrString(wrapper),
        source_obj: safePtrString(sourceObj),
        owner_base: safePtrString(ownerBase),
        source_minus_owner: sourceObj.sub(ownerBase).toInt32(),
        conversation,
        uuid,
        body,
        refs,
        interesting_pointers: interesting,
      };
      const key = JSON.stringify([conversation, uuid, body, interesting]);
      if (seen[key]) return;
      seen[key] = true;
      if (Date.now() < baselineUntil) return;
      send({ kind: 'source_pointer_scan', payload });
    } catch (e) {
      send({ kind: 'error', where: 'targetFn', error: String(e) });
    }
  }
});

setTimeout(() => send({ kind: 'armed' }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat', seen_count: Object.keys(seen).length }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="Exact Weixin.exe PID to attach to")
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
    rendered = SCRIPT.replace("{{BASELINE_SECONDS}}", str(args.baseline_seconds))
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
