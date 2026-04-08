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

function readVector(vecPtr, rowSize, maxRows) {
  try {
    const begin = vecPtr.readPointer();
    const end = vecPtr.add(Process.pointerSize).readPointer();
    const cap = vecPtr.add(Process.pointerSize * 2).readPointer();
    if (begin.isNull() || end.isNull() || end.compare(begin) < 0) {
      return { vecPtr: vecPtr.toString(), begin: begin.toString(), end: end.toString(), cap: cap.toString(), count: 0, rows: [] };
    }
    const totalBytes = parseInt(end.sub(begin).toString(), 16);
    const count = Math.floor(totalBytes / rowSize);
    const rows = [];
    for (let i = 0; i < Math.min(count, maxRows); i++) {
      const row = begin.add(i * rowSize);
      rows.push({
        index: i,
        row: row.toString(),
        strings: {
          s18: readStdString(row.add(0x18)),
          s38: readStdString(row.add(0x38)),
          s58: readStdString(row.add(0x58)),
          s140: readStdString(row.add(0x140)),
          s180: readStdString(row.add(0x180)),
        },
        ints: {
          i104: row.add(0x104).readU32(),
          i108: row.add(0x108).readU32(),
          i110: row.add(0x110).readU32(),
          i118: row.add(0x118).readU32(),
          i120: row.add(0x120).readU32(),
          i124: row.add(0x124).readU32(),
          i128: row.add(0x128).readU32(),
          i134: row.add(0x134).readU32(),
          i138: row.add(0x138).readU32(),
          i1c0: row.add(0x1c0).readU32(),
          i1c4: row.add(0x1c4).readU32(),
        },
      });
    }
    return { vecPtr: vecPtr.toString(), begin: begin.toString(), end: end.toString(), cap: cap.toString(), count, rows };
  } catch (e) {
    return { error: String(e) };
  }
}

function readBytePtr(addr) {
  try {
    const p = addr.readPointer();
    if (p.isNull()) return null;
    return { ptr: p.toString(), value: p.readU8() };
  } catch (e) {
    return null;
  }
}

const mod = Process.getModuleByName('Weixin.dll');
const fn = mod.base.add(0x13f62e0);
send({ kind: 'status', fn: fn.toString() });

Interceptor.attach(fn, {
  onEnter(args) {
    this.param1 = args[0];
    this.talker = readStdString(args[0].add(0x8));
    this.ctx = args[0].add(0x20).readPointer().toString();
    this.rangeVec = args[0].add(0x10).readPointer().toString();
    this.snapshotVec = args[0].add(0x18).readPointer().toString();
    this.outVec = args[0].add(0x28).readPointer().toString();
    this.flag = readBytePtr(args[0].add(0x30));
    send({
      kind: 'snapshot_enter',
      param1: this.param1.toString(),
      talker: this.talker,
      ctx: this.ctx,
      rangeVec: this.rangeVec,
      snapshotVec: this.snapshotVec,
      outVec: this.outVec,
      flag: this.flag,
    });
  },
  onLeave(retval) {
    try {
      const outVecPtr = this.param1.add(0x28).readPointer();
      const info = readVector(outVecPtr, 0x290, 16);
      send({
        kind: 'snapshot_leave',
        retval: retval.toString(),
        talker: this.talker,
        param1: this.param1.toString(),
        outVec: outVecPtr.toString(),
        flagAfter: readBytePtr(this.param1.add(0x30)),
        vector: info,
      });
    } catch (e) {
      send({ kind: 'snapshot_leave_error', error: String(e) });
    }
  }
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
