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

function readStringFields(base, offsets) {
  const out = {};
  for (const off of offsets) {
    const value = readStdString(base.add(off));
    if (value && value.length > 0) out['0x' + off.toString(16)] = value;
  }
  return out;
}

function readIntFields(base, offsets) {
  const out = {};
  for (const off of offsets) {
    try {
      out['0x' + off.toString(16)] = base.add(off).readU32();
    } catch (e) {}
  }
  return out;
}

function dumpRows(beginPtr, endPtr, maxRows) {
  const rowSize = 0x290;
  const rows = [];
  const begin = ptr(beginPtr);
  const end = ptr(endPtr);
  if (begin.isNull() || end.isNull() || end.compare(begin) < 0) {
    return rows;
  }
  const totalBytes = end.sub(begin).toUInt32();
  const count = Math.min(Math.floor(totalBytes / rowSize), maxRows);
  for (let i = 0; i < count; i++) {
    const row = begin.add(i * rowSize);
    const strings = readStringFields(row, [0x18, 0x38, 0x58, 0x78, 0x98, 0xc0, 0xe0, 0x140, 0x160, 0x180, 0x270]);
    const ints = readIntFields(row, [0x10, 0x120, 0x124, 0x128, 0x12c, 0x130, 0x134, 0x138, 0x194, 0x198, 0x19c, 0x1a0, 0x1a4, 0x1a8, 0x1ac, 0x1c0, 0x1c4]);
    rows.push({
      index: i,
      row: row.toString(),
      strings,
      ints,
    });
  }
  return rows;
}

const mod = Process.getModuleByName('Weixin.dll');
const fn = mod.base.add(0x13f62e0);

send({ kind: 'status', msg: 'hooking', fn: fn.toString() });

Interceptor.attach(fn, {
  onEnter(args) {
    this.param1 = args[0];
    try {
      this.talker = readStdString(args[0].add(0x8));
    } catch (e) {
      this.talker = null;
    }
  },
  onLeave(retval) {
    try {
      const talker = this.talker || '';
      const outVecPtr = this.param1.add(0x28).readPointer();
      const begin = outVecPtr.readPointer();
      const end = outVecPtr.add(Process.pointerSize).readPointer();
      const cap = outVecPtr.add(Process.pointerSize * 2).readPointer();
      const totalBytes = end.sub(begin).toUInt32();
      const count = begin.isNull() || end.isNull() || end.compare(begin) < 0 ? 0 : Math.floor(totalBytes / 0x290);
      const interesting =
        talker === 'wxid_3a40v7q8y4kk12' ||
        talker === 'Glenn' ||
        count > 0;
      if (!interesting) return;
      send({
        kind: 'message_query',
        retval: retval.toString(),
        talker,
        queryObj: this.param1.toString(),
        outVecPtr: outVecPtr.toString(),
        begin: begin.toString(),
        end: end.toString(),
        cap: cap.toString(),
        count,
        rows: dumpRows(begin, end, 12),
      });
    } catch (e) {
      send({ kind: 'error', where: 'FUN_1813f62e0', error: String(e) });
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
