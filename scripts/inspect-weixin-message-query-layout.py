#!/usr/bin/env python
import sys
import threading

import frida


SCRIPT = r"""
function readStdString(addr) {
  try {
    const len = addr.add(0x10).readU32();
    const cap = addr.add(0x18).readU32();
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

function tryReadPointer(addr) {
  try {
    return addr.readPointer();
  } catch (e) {
    return null;
  }
}

function tryReadU32(addr) {
  try {
    return addr.readU32();
  } catch (e) {
    return null;
  }
}

function tryReadU64(addr) {
  try {
    return addr.readU64().toString();
  } catch (e) {
    return null;
  }
}

function describeMaybeVector(ptrValue) {
  if (!ptrValue || ptrValue.isNull()) return null;
  try {
    const begin = ptrValue.readPointer();
    const end = ptrValue.add(Process.pointerSize).readPointer();
    const cap = ptrValue.add(Process.pointerSize * 2).readPointer();
    if (begin.isNull() || end.isNull() || end.compare(begin) < 0) {
      return {
        begin: begin.toString(),
        end: end.toString(),
        cap: cap.toString(),
        count290: 0,
      };
    }
    const bytes = parseInt(end.sub(begin).toString(), 16);
    return {
      begin: begin.toString(),
      end: end.toString(),
      cap: cap.toString(),
      bytes,
      count290: Math.floor(bytes / 0x290),
    };
  } catch (e) {
    return null;
  }
}

function describePointer(ptrValue) {
  if (!ptrValue || ptrValue.isNull()) return null;
  let inlineStd = null;
  let pointedStd = null;
  let q0 = null;
  let q1 = null;
  let q2 = null;
  let u0 = null;
  let u1 = null;
  let vectorLike = null;
  try { inlineStd = readStdString(ptrValue); } catch (e) {}
  try { pointedStd = readStdString(ptrValue.readPointer()); } catch (e) {}
  try { q0 = ptrValue.readPointer().toString(); } catch (e) {}
  try { q1 = ptrValue.add(0x8).readPointer().toString(); } catch (e) {}
  try { q2 = ptrValue.add(0x10).readPointer().toString(); } catch (e) {}
  try { u0 = ptrValue.readU32(); } catch (e) {}
  try { u1 = ptrValue.add(0x4).readU32(); } catch (e) {}
  try { vectorLike = describeMaybeVector(ptrValue); } catch (e) {}
  return {
    ptr: ptrValue.toString(),
    inlineStd,
    pointedStd,
    q0,
    q1,
    q2,
    u0,
    u1,
    vectorLike,
  };
}

function dumpQueryLayout(obj) {
  const fields = [];
  for (let off = 0; off <= 0x60; off += 0x8) {
    const slot = obj.add(off);
    const ptrValue = tryReadPointer(slot);
    fields.push({
      off: '0x' + off.toString(16),
      slotAddr: slot.toString(),
      rawQword: tryReadU64(slot),
      u32: tryReadU32(slot),
      inlineStd: readStdString(slot),
      ptrValue: ptrValue ? ptrValue.toString() : null,
      ptrDesc: describePointer(ptrValue),
    });
  }
  return fields;
}

const mod = Process.getModuleByName('Weixin.dll');
const fIter = mod.base.add(0x13ff7c0);
const fWrapA = mod.base.add(0x1405470);
const fWrapB = mod.base.add(0x1411990);

send({
  kind: 'status',
  iter: fIter.toString(),
  wrapA: fWrapA.toString(),
  wrapB: fWrapB.toString(),
});

Interceptor.attach(fIter, {
  onEnter(args) {
    const queryObj = args[0];
    const dbCtx = args[1];
    send({
      kind: 'iter_enter_layout',
      queryObj: queryObj.toString(),
      dbCtx: dbCtx.toString(),
      layout: dumpQueryLayout(queryObj),
    });
  },
});

Interceptor.attach(fWrapA, {
  onEnter(args) {
    send({
      kind: 'wrapA_enter_layout',
      obj: args[0].toString(),
      layout: dumpQueryLayout(args[0]),
    });
  },
});

Interceptor.attach(fWrapB, {
  onEnter(args) {
    send({
      kind: 'wrapB_enter_layout',
      obj: args[0].toString(),
      layout: dumpQueryLayout(args[0]),
    });
  },
});

setInterval(() => send({ kind: 'heartbeat' }), 30000);
"""


def main() -> None:
    device = frida.get_local_device()
    matches = [p for p in device.enumerate_processes() if p.name.lower() == "weixin.exe"]
    if not matches:
        raise SystemExit("Weixin.exe not found")
    pid = sorted(matches, key=lambda p: p.pid)[0].pid
    session = device.attach(pid)
    script = session.create_script(SCRIPT)

    def on_message(message, data):
        if message["type"] == "send":
            sys.stdout.buffer.write((str(message["payload"]) + "\n").encode("utf-8", errors="replace"))
            sys.stdout.flush()
        else:
            sys.stdout.buffer.write((str(message) + "\n").encode("utf-8", errors="replace"))
            sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    sys.stdout.buffer.write((f"attached pid={pid}\n").encode("utf-8"))
    sys.stdout.flush()
    threading.Event().wait()


if __name__ == "__main__":
    main()
