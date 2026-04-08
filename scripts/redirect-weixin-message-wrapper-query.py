#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT_TEMPLATE = r"""
const SOURCE_TALKER = %(source_talker)r;
const TARGET_TALKER = %(target_talker)r;

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

function overwriteStdString(obj, value) {
  const cap = obj.add(0x18).readU32();
  if (cap <= 15) {
    if (value.length > 15) {
      throw new Error('target too long for inline std::string');
    }
    obj.writeUtf8String(value);
    obj.add(0x10).writeU32(value.length);
    obj.add(0x18).writeU32(15);
    return;
  }
  const dataPtr = obj.readPointer();
  if (dataPtr.isNull()) {
    throw new Error('std::string data pointer was null');
  }
  if (value.length > cap) {
    throw new Error('target length exceeds existing capacity');
  }
  dataPtr.writeUtf8String(value);
  obj.add(0x10).writeU32(value.length);
}

function tryReadU64(addr) {
  try { return addr.readU64().toString(); } catch (e) { return null; }
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
      sender18: readStdString(row.add(0x18)),
      talker38: readStdString(row.add(0x38)),
      body180: readStdString(row.add(0x180)),
      ts124: (function () { try { return row.add(0x124).readU32(); } catch (e) { return null; } })(),
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

const mod = Process.getModuleByName('Weixin.dll');
const fWrap = mod.base.add(0x1411990);
const fIter = mod.base.add(0x13ff7c0);

send({ kind: 'status', wrap: fWrap.toString(), iter: fIter.toString(), source: SOURCE_TALKER, target: TARGET_TALKER });

let redirected = false;
const activeThreads = {};

Interceptor.attach(fWrap, {
  onEnter(args) {
    const threadId = Process.getCurrentThreadId();
    const obj = args[0];
    const talkerObj = obj.add(0x20);
    const originalTalker = readStdString(talkerObj) || '';
    if (redirected || originalTalker !== SOURCE_TALKER) {
      return;
    }
    try {
      overwriteStdString(talkerObj, TARGET_TALKER);
      redirected = true;
      activeThreads[threadId] = {
        wrapperObj: obj.toString(),
        originalTalker,
        rewrittenTalker: readStdString(talkerObj),
      };
      send({
        kind: 'wrapper_redirected',
        threadId,
        wrapperObj: obj.toString(),
        originalTalker,
        rewrittenTalker: readStdString(talkerObj),
        slot8: tryReadU64(obj.add(0x8)),
        slot10: tryReadU64(obj.add(0x10)),
        slot18: tryReadU64(obj.add(0x18)),
        slot28: tryReadU64(obj.add(0x28)),
      });
    } catch (e) {
      send({
        kind: 'wrapper_redirect_error',
        threadId,
        originalTalker,
        error: String(e),
      });
    }
  },
  onLeave(retval) {
    const threadId = Process.getCurrentThreadId();
    const state = activeThreads[threadId];
    if (!state) return;
    send({
      kind: 'wrapper_leave',
      threadId,
      retval: retval.toString(),
      wrapperObj: state.wrapperObj,
      originalTalker: state.originalTalker,
      rewrittenTalker: state.rewrittenTalker,
    });
    delete activeThreads[threadId];
  },
});

Interceptor.attach(fIter, {
  onEnter(args) {
    const threadId = Process.getCurrentThreadId();
    if (!activeThreads[threadId]) return;
    activeThreads[threadId].iterQueryObj = args[0].toString();
  },
  onLeave(retval) {
    const threadId = Process.getCurrentThreadId();
    const state = activeThreads[threadId];
    if (!state || !state.iterQueryObj) return;
    try {
      const queryObj = ptr(state.iterQueryObj);
      const outVecPtr = queryObj.add(0x38).readPointer();
      send({
        kind: 'wrapper_redirect_iter',
        threadId,
        retval: retval.toString(),
        originalTalker: state.originalTalker,
        rewrittenTalker: state.rewrittenTalker,
        queryObj: state.iterQueryObj,
        vector: readVectorInfo(outVecPtr),
      });
    } catch (e) {
      send({
        kind: 'wrapper_redirect_iter_error',
        threadId,
        originalTalker: state.originalTalker,
        rewrittenTalker: state.rewrittenTalker,
        error: String(e),
      });
    }
  },
});

setInterval(() => send({ kind: 'heartbeat' }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    device = frida.get_local_device()
    matches = [p for p in device.enumerate_processes() if p.name.lower() == "weixin.exe"]
    if not matches:
        raise SystemExit("Weixin.exe not found")
    pid = sorted(matches, key=lambda p: p.pid)[0].pid
    session = device.attach(pid)
    script = session.create_script(
        SCRIPT_TEMPLATE
        % {
            "source_talker": args.source,
            "target_talker": args.target,
        }
    )

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
