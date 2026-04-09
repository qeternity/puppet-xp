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

function scanPtrs(base, size, ownerBase, sourceObj) {
  const out = [];
  for (let off = 0; off < size; off += 8) {
    try {
      const p = base.add(off).readPointer();
      if (p.isNull()) continue;
      const pointsToOwner = p.equals(ownerBase);
      const pointsToSource = p.equals(sourceObj);
      const inOwner = p.compare(ownerBase) >= 0 && p.compare(ownerBase.add(0x710)) < 0;
      if (!pointsToOwner && !pointsToSource && !inOwner) continue;
      out.push({
        offset: '0x' + off.toString(16),
        value: safePtrString(p),
        points_to_owner: pointsToOwner,
        points_to_source: pointsToSource,
        in_owner_block: inOwner,
      });
    } catch (e) {
    }
  }
  return out;
}

function scanStd(base, offsets) {
  const out = [];
  for (const off of offsets) {
    try {
      const s = readStdString(base.add(off));
      if (!s) continue;
      out.push({ offset: '0x' + off.toString(16), value: s });
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
      if (Date.now() < baselineUntil) return;
      const wrapper = args[0];
      const vec = readVector(wrapper.add(0x8));
      if (!vec || vec.count < 1) return;

      const pair = vec.begin;
      const sourceObj = pair.readPointer();
      const ownerBase = pair.add(Process.pointerSize).readPointer();
      if (sourceObj.isNull() || ownerBase.isNull()) return;

      const conversation = readStdString(sourceObj.add(0xb0));
      const body = readStdString(sourceObj.add(0x660));
      const uuid = readStdString(sourceObj.add(0x600));

      const payload = {
        wrapper: safePtrString(wrapper),
        source_obj: safePtrString(sourceObj),
        owner_base: safePtrString(ownerBase),
        conversation,
        body,
        uuid,
        meta_pointers: scanPtrs(wrapper.add(0x20), 0x100, ownerBase, sourceObj),
        meta_strings: scanStd(wrapper.add(0x20), [0x0,0x20,0x40,0x60,0x80,0xa0,0xc0,0xe0]),
      };

      const key = JSON.stringify([conversation, body, uuid, payload.meta_pointers, payload.meta_strings]);
      if (seen[key]) return;
      seen[key] = true;
      send({ kind: 'wrapper_meta', payload });
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
