#!/usr/bin/env python
import argparse
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

function classifyMessageKind(strings, ints) {
  const systemSignature =
    ints['0x120'] === 4 &&
    ints['0x128'] === 4 &&
    ints['0x138'] === 2 &&
    ints['0x1c0'] === 2 &&
    ints['0x1c4'] === 1;
  if (systemSignature) {
    return {
      message_kind: 'system',
      system_signature: '4/4/2/2/1',
    };
  }
  return {
    message_kind: 'user',
    system_signature: null,
  };
}

function dumpRows(beginPtr, endPtr, maxRows) {
  const rowSize = 0x290;
  const rows = [];
  const begin = ptr(beginPtr);
  const end = ptr(endPtr);
  if (begin.isNull() || end.isNull() || end.compare(begin) < 0) return rows;
  const totalBytes = parseInt(end.sub(begin).toString(), 16);
  const count = Math.min(Math.floor(totalBytes / rowSize), maxRows);
  for (let i = 0; i < count; i++) {
    const row = begin.add(i * rowSize);
    const strings = readStringFields(row, [0x18, 0x38, 0x58, 0x78, 0x98, 0xc0, 0xe0, 0x140, 0x160, 0x180, 0x270]);
    const ints = readIntFields(row, [0x10, 0x120, 0x124, 0x128, 0x12c, 0x130, 0x134, 0x138, 0x194, 0x198, 0x19c, 0x1a0, 0x1a4, 0x1a8, 0x1ac, 0x1c0, 0x1c4]);
    const kindInfo = classifyMessageKind(strings, ints);
    rows.push({
      index: i,
      row: row.toString(),
      strings,
      ints,
      message_kind: kindInfo.message_kind,
      system_signature: kindInfo.system_signature,
    });
  }
  return rows;
}

function readQueryObj(objPtr) {
  const out = {};
  for (const off of [0x0, 0x8, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48]) {
    try {
      const ptrValue = objPtr.add(off).readPointer();
      out['0x' + off.toString(16)] = ptrValue.toString();
    } catch (e) {}
  }
  try {
    const nested = objPtr.add(0x20).readPointer();
    if (!nested.isNull()) {
      out['0x20_string_0x18'] = readStdString(nested.add(0x18));
    }
  } catch (e) {}
  return out;
}

function readVectorInfo(vecPtr, maxRows) {
  try {
    const begin = vecPtr.readPointer();
    const end = vecPtr.add(Process.pointerSize).readPointer();
    const cap = vecPtr.add(Process.pointerSize * 2).readPointer();
    const totalBytes = begin.isNull() || end.isNull() || end.compare(begin) < 0 ? 0 : parseInt(end.sub(begin).toString(), 16);
    const count = Math.floor(totalBytes / 0x290);
    return { vecPtr: vecPtr.toString(), begin: begin.toString(), end: end.toString(), cap: cap.toString(), count, rows: dumpRows(begin, end, maxRows) };
  } catch (e) {
    return { error: String(e) };
  }
}

const mod = Process.getModuleByName('Weixin.dll');
const fn = mod.base.add(0x13ff7c0);
send({ kind: 'status', msg: 'hooking', fn: fn.toString() });

Interceptor.attach(fn, {
  onEnter(args) {
    this.param1 = args[0];
    this.param2 = args[1];
    try {
      this.talker = readStdString(args[0]);
    } catch (e) {
      this.talker = null;
    }
    try {
      this.filterFlags = args[0].add(0x30).readU32();
    } catch (e) {
      this.filterFlags = null;
    }
  },
  onLeave(retval) {
    try {
      const talker = this.talker || '';
      const outVecPtr = this.param1.add(0x38).readPointer();
      const queryObjInfo = readQueryObj(this.param1);
      const zumaTalker =
        talker === '27208021116@chatroom' ||
        queryObjInfo['0x20_string_0x18'] === '27208021116@chatroom';
      const maxRows = zumaTalker ? 30 : 8;
      const info = readVectorInfo(outVecPtr, maxRows);
      const interesting =
        talker === 'wxid_3a40v7q8y4kk12' ||
        talker === 'Glenn' ||
        zumaTalker ||
        (info.count && info.count > 0) ||
        info.rows.some(r => Object.values(r.strings).some(v => v.indexOf('howdy') >= 0 || v.indexOf('test123') >= 0 || v.indexOf('latest message 20260408') >= 0 || v.indexOf('message probe 20260408') >= 0));
      if (!interesting) return;
      send({
        kind: 'message_iterator',
        retval: retval.toString(),
        talker,
        filterFlags: this.filterFlags,
        queryObj: this.param1.toString(),
        queryObjInfo,
        dbCtx: this.param2.toString(),
        vector: info,
      });
    } catch (e) {
      send({ kind: 'error', where: 'FUN_1813ff7c0', error: String(e) });
    }
  }
});

setInterval(() => send({ kind: 'heartbeat' }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="Exact Weixin.exe PID to attach to")
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
