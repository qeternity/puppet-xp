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

function readU32Ptr(addr) {
  try {
    const p = addr.readPointer();
    if (p.isNull()) return null;
    return { ptr: p.toString(), value: p.readU32() };
  } catch (e) {
    return null;
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

function readRow(row) {
  const rowPtr = ptr(row);
  const strings = {};
  for (const off of [0x18, 0x28, 0x38, 0x58, 0x78, 0x140, 0x180]) {
    const s = readStdString(rowPtr.add(off));
    if (s && s.length > 0) strings['0x' + off.toString(16)] = s;
  }
  const ints = {};
  for (const off of [0x10, 0x104, 0x108, 0x110, 0x118, 0x120, 0x124, 0x128, 0x134, 0x138, 0x1c0, 0x1c4]) {
    try {
      ints['0x' + off.toString(16)] = rowPtr.add(off).readU32();
    } catch (e) {}
  }
  return {
    row: rowPtr.toString(),
    strings,
    ints,
  };
}

const mod = Process.getModuleByName('Weixin.dll');
const pager = mod.base.add(0x13f86b0);
const sink = mod.base.add(0x13e1c00);

send({ kind: 'status', pager: pager.toString(), sink: sink.toString() });

const activeByThread = {};

Interceptor.attach(pager, {
  onEnter(args) {
    const tid = Process.getCurrentThreadId();
    const param1 = args[0];
    const talker = readStdString(param1.add(0x8));
    const matchString = readStdString(param1.add(0x20));
    const stopFlag = readBytePtr(param1.add(0x10));
    const threshold = readU32Ptr(param1.add(0x28));
    let ctx = null;
    try {
      const p18 = param1.add(0x18).readPointer();
      ctx = {
        ptr: p18.toString(),
        inner8: p18.isNull() ? null : p18.add(0x8).readPointer().toString(),
      };
    } catch (e) {}
    const rec = {
      param1: param1.toString(),
      talker,
      matchString,
      stopFlag,
      threshold,
      ctx,
      sinkObj: param1.add(0x30).readPointer().toString(),
      rows: [],
    };
    activeByThread[tid] = rec;
    send({
      kind: 'pager_enter',
      tid,
      param1: rec.param1,
      talker: rec.talker,
      matchString: rec.matchString,
      stopFlag: rec.stopFlag,
      threshold: rec.threshold,
      ctx: rec.ctx,
      sinkObj: rec.sinkObj,
    });
  },
  onLeave(retval) {
    const tid = Process.getCurrentThreadId();
    const rec = activeByThread[tid];
    if (!rec) return;
    let stopFlagAfter = null;
    let thresholdAfter = null;
    try {
      stopFlagAfter = readBytePtr(ptr(rec.param1).add(0x10));
      thresholdAfter = readU32Ptr(ptr(rec.param1).add(0x28));
    } catch (e) {}
    send({
      kind: 'pager_leave',
      tid,
      retval: retval.toString(),
      talker: rec.talker,
      matchString: rec.matchString,
      rowCount: rec.rows.length,
      rows: rec.rows,
      stopFlagAfter,
      thresholdAfter,
    });
    delete activeByThread[tid];
  }
});

Interceptor.attach(sink, {
  onEnter(args) {
    const tid = Process.getCurrentThreadId();
    const rec = activeByThread[tid];
    if (!rec) return;
    try {
      const rowInfo = readRow(args[1]);
      rec.rows.push(rowInfo);
      if (rec.rows.length <= 20) {
        send({
          kind: 'pager_row',
          tid,
          talker: rec.talker,
          matchString: rec.matchString,
          sinkObj: args[0].toString(),
          row: rowInfo,
        });
      }
    } catch (e) {
      send({ kind: 'pager_row_error', tid, error: String(e) });
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
