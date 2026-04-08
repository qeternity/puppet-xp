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

function tryReadPtr(addr) {
  try {
    return addr.readPointer();
  } catch (e) {
    return null;
  }
}

function dumpQueryObject(obj) {
  const fields = [];
  for (let off = 0; off <= 0x60; off += 8) {
    const slot = obj.add(off);
    const ptrValue = tryReadPtr(slot);
    let inlineStr = null;
    let ptrStr = null;
    try { inlineStr = readStdString(slot); } catch (e) {}
    if (ptrValue && !ptrValue.isNull()) {
      try { ptrStr = readStdString(ptrValue); } catch (e) {}
    }
    fields.push({
      off: '0x' + off.toString(16),
      ptr: ptrValue ? ptrValue.toString() : null,
      u32: (function () { try { return slot.readU32(); } catch (e) { return null; } })(),
      inlineStr,
      ptrStr,
    });
  }
  return fields;
}

function dumpVector(vecPtr) {
  try {
    const holder = vecPtr.readPointer();
    const begin = holder.readPointer();
    const end = holder.add(Process.pointerSize).readPointer();
    const cap = holder.add(Process.pointerSize * 2).readPointer();
    const bytes = begin.isNull() || end.isNull() || end.compare(begin) < 0
      ? 0
      : parseInt(end.sub(begin).toString(), 16);
    return {
      vecPtr: vecPtr.toString(),
      holder: holder.toString(),
      begin: begin.toString(),
      end: end.toString(),
      cap: cap.toString(),
      rowCount: Math.floor(bytes / 0x290),
    };
  } catch (e) {
    return { error: String(e) };
  }
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
    this.queryObj = args[0];
    this.dbCtx = args[1];
    send({
      kind: 'iter_enter',
      queryObj: this.queryObj.toString(),
      dbCtx: this.dbCtx.toString(),
      queryFields: dumpQueryObject(this.queryObj),
    });
  },
  onLeave(retval) {
    try {
      send({
        kind: 'iter_leave',
        retval: retval.toString(),
        vector: dumpVector(this.queryObj.add(0x50)),
      });
    } catch (e) {
      send({ kind: 'iter_leave_error', error: String(e) });
    }
  },
});

Interceptor.attach(fWrapA, {
  onEnter(args) {
    send({
      kind: 'wrapA_enter',
      obj: args[0].toString(),
      fields: dumpQueryObject(args[0]),
    });
  },
});

Interceptor.attach(fWrapB, {
  onEnter(args) {
    send({
      kind: 'wrapB_enter',
      obj: args[0].toString(),
      fields: dumpQueryObject(args[0]),
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
