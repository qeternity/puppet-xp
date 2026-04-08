#!/usr/bin/env python
import sys
import threading

import frida


SCRIPT = r"""
const WATCH_TALKERS = [
  'wxid_3a40v7q8y4kk12',   // Glenn
  'wxid_cdxvsfdqlbqw22',   // Adam
  '27208021116@chatroom',  // Zuma Internal
];

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
  try { return addr.readPointer(); } catch (e) { return null; }
}

function tryReadU32(addr) {
  try { return addr.readU32(); } catch (e) { return null; }
}

function tryReadU64(addr) {
  try { return addr.readU64().toString(); } catch (e) { return null; }
}

function tryReadPtrU32(addr) {
  try {
    const p = addr.readPointer();
    if (p.isNull()) return null;
    return p.readU32();
  } catch (e) {
    return null;
  }
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
    rows.push({
      index: i,
      row: row.toString(),
      talker38: readStdString(row.add(0x38)),
      sender18: readStdString(row.add(0x18)),
      body180: readStdString(row.add(0x180)),
      ts124: tryReadU32(row.add(0x124)),
      type120: tryReadU32(row.add(0x120)),
      status128: tryReadU32(row.add(0x128)),
    });
  }
  return rows;
}

function readVectorInfo(vecPtr) {
  try {
    const begin = vecPtr.readPointer();
    const end = vecPtr.add(Process.pointerSize).readPointer();
    const cap = vecPtr.add(Process.pointerSize * 2).readPointer();
    const totalBytes = begin.isNull() || end.isNull() || end.compare(begin) < 0
      ? 0
      : parseInt(end.sub(begin).toString(), 16);
    const count = Math.floor(totalBytes / 0x290);
    return {
      vecPtr: vecPtr.toString(),
      begin: begin.toString(),
      end: end.toString(),
      cap: cap.toString(),
      count,
      rows: dumpRows(begin, end, 16),
    };
  } catch (e) {
    return { error: String(e) };
  }
}

function decodeWrapper(obj) {
  const slot0Ptr = tryReadPtr(obj.add(0x0));
  const slot3Ptr = tryReadPtr(obj.add(0x18));
  const slot4Ptr = tryReadPtr(obj.add(0x20));
  const slot5Ptr = tryReadPtr(obj.add(0x28));
  const slot6Ptr = tryReadPtr(obj.add(0x30));
  const output8Ptr = tryReadPtr(obj.add(0x40));
  const output16Ptr = tryReadPtr(obj.add(0x80));
  const bool40Ptr = tryReadPtr(obj.add(0x140));
  const talker100 = readStdString(obj.add(0x100));
  const talker0 = slot0Ptr ? readStdString(slot0Ptr) : null;
  const talker20 = slot4Ptr ? readStdString(slot4Ptr.add(0x18)) : null;
  return {
    obj: obj.toString(),
    slot0Ptr: slot0Ptr ? slot0Ptr.toString() : null,
    talker0,
    talker100,
    talker20,
    slot3Ptr: slot3Ptr ? slot3Ptr.toString() : null,
    slot3HeadQword: slot3Ptr ? tryReadU64(slot3Ptr) : null,
    slot4Ptr: slot4Ptr ? slot4Ptr.toString() : null,
    slot4HeadQword: slot4Ptr ? tryReadU64(slot4Ptr) : null,
    slot5Ptr: slot5Ptr ? slot5Ptr.toString() : null,
    slot5Value: tryReadPtrU32(obj.add(0x28)),
    slot6Ptr: slot6Ptr ? slot6Ptr.toString() : null,
    slot6Value: tryReadPtrU32(obj.add(0x30)),
    output8Ptr: output8Ptr ? output8Ptr.toString() : null,
    output8Value: output8Ptr ? tryReadU64(output8Ptr) : null,
    output16Ptr: output16Ptr ? output16Ptr.toString() : null,
    output16Value: output16Ptr ? tryReadU32(output16Ptr) : null,
    bool40Ptr: bool40Ptr ? bool40Ptr.toString() : null,
    bool40Value: bool40Ptr ? tryReadU32(bool40Ptr) : null,
    rawSlots: {
      '0x0': tryReadU64(obj.add(0x0)),
      '0x18': tryReadU64(obj.add(0x18)),
      '0x20': tryReadU64(obj.add(0x20)),
      '0x28': tryReadU64(obj.add(0x28)),
      '0x30': tryReadU64(obj.add(0x30)),
      '0x40': tryReadU64(obj.add(0x40)),
      '0x80': tryReadU64(obj.add(0x80)),
      '0x100_inline': talker100,
      '0x140': tryReadU64(obj.add(0x140)),
    },
  };
}

function wrapperTalker(info) {
  return info.talker100 || info.talker20 || info.talker0 || '';
}

const activeByThread = {};
const activeIterByThread = {};

const mod = Process.getModuleByName('Weixin.dll');
const fWrapA = mod.base.add(0x1405470);
const fIter = mod.base.add(0x13ff7c0);

send({
  kind: 'status',
  wrapA: fWrapA.toString(),
  iter: fIter.toString(),
  watchTalkers: WATCH_TALKERS,
});

Interceptor.attach(fWrapA, {
  onEnter(args) {
    const info = decodeWrapper(args[0]);
    const talker = wrapperTalker(info);
    if (WATCH_TALKERS.indexOf(talker) < 0) return;
    const threadId = Process.getCurrentThreadId();
    activeByThread[threadId] = {
      wrapper: info,
      iterEvents: [],
    };
    send({
      kind: 'wrapA_enter',
      threadId,
      talker,
      wrapper: info,
    });
  },
  onLeave(retval) {
    const threadId = Process.getCurrentThreadId();
    const state = activeByThread[threadId];
    if (!state) return;
    const finalInfo = decodeWrapper(ptr(state.wrapper.obj));
    send({
      kind: 'wrapA_leave',
      threadId,
      retval: retval.toString(),
      talker: wrapperTalker(finalInfo),
      wrapper: finalInfo,
      iterEvents: state ? state.iterEvents : [],
    });
    delete activeByThread[threadId];
  },
});

Interceptor.attach(fIter, {
  onEnter(args) {
    const threadId = Process.getCurrentThreadId();
    activeIterByThread[threadId] = {
      queryObj: args[0].toString(),
    };
  },
  onLeave(retval) {
    const threadId = Process.getCurrentThreadId();
    const state = activeByThread[threadId];
    const iterState = activeIterByThread[threadId];
    if (!state) return;
    try {
      const queryObj = ptr(iterState.queryObj);
      const outVecPtr = queryObj.add(0x38).readPointer();
      const iterInfo = {
        retval: retval.toString(),
        queryObj: queryObj.toString(),
        vector: readVectorInfo(outVecPtr),
      };
      state.iterEvents.push(iterInfo);
      send({
        kind: 'iter_under_wrapA',
        threadId,
        talker: wrapperTalker(state.wrapper),
        wrapper: state.wrapper,
        iter: iterInfo,
      });
    } catch (e) {
      send({
        kind: 'iter_under_wrapA_error',
        threadId,
        error: String(e),
      });
    } finally {
      delete activeIterByThread[threadId];
    }
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
