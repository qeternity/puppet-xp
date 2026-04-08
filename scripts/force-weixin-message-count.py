#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT_TEMPLATE = r"""
const TARGET_TALKER = %(target_talker)r;
const FORCE_COUNT = %(force_count)d;

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
    const strings = readStringFields(row, [0x18, 0x38, 0x58, 0x140, 0x180]);
    const ints = readIntFields(row, [0x120, 0x124, 0x128, 0x138, 0x1c0, 0x1c4]);
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

function readVectorInfo(vecPtr, maxRows) {
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
      rows: dumpRows(begin, end, maxRows),
    };
  } catch (e) {
    return { error: String(e) };
  }
}

function readQueryInfo(queryObj) {
  const out = {};
  try { out['0x0'] = queryObj.readPointer().toString(); } catch (e) {}
  try { out['0x8'] = queryObj.add(0x8).readPointer().toString(); } catch (e) {}
  try { out['0x20'] = queryObj.add(0x20).readPointer().toString(); } catch (e) {}
  try { out['0x38'] = queryObj.add(0x38).readPointer().toString(); } catch (e) {}
  try { out['0x48_u64'] = queryObj.add(0x48).readU64().toString(); } catch (e) {}
  try {
    const nested = queryObj.add(0x20).readPointer();
    if (!nested.isNull()) {
      out['0x20_string_0x18'] = readStdString(nested.add(0x18));
    }
  } catch (e) {}
  return out;
}

const mod = Process.getModuleByName('Weixin.dll');
const fnBuilder = mod.base.add(0x13b1b40);
const fnIter = mod.base.add(0x13ff7c0);

send({
  kind: 'status',
  fnBuilder: fnBuilder.toString(),
  fnIter: fnIter.toString(),
  targetTalker: TARGET_TALKER,
  forceCount: FORCE_COUNT,
});

const activeThreads = {};

Interceptor.attach(fnBuilder, {
  onEnter(args) {
    let talker = null;
    try { talker = readStdString(args[2]); } catch (e) {}
    if (talker !== TARGET_TALKER) return;
    const threadId = Process.getCurrentThreadId();
    let originalCount = null;
    try { originalCount = args[4].toUInt32(); } catch (e) {}
    try {
      args[4] = ptr(FORCE_COUNT);
    } catch (e) {
      send({ kind: 'builder_force_error', threadId, talker, error: String(e) });
      return;
    }
    activeThreads[threadId] = {
      talker,
      originalCount,
      forcedCount: FORCE_COUNT,
    };
    send({
      kind: 'builder_forced',
      threadId,
      talker,
      originalCount,
      forcedCount: FORCE_COUNT,
      param6: args[5].toString(),
      param9: args[8].toString(),
    });
  },
  onLeave(retval) {
    const threadId = Process.getCurrentThreadId();
    const state = activeThreads[threadId];
    if (!state) return;
    state.builderRetval = retval.toString();
  }
});

Interceptor.attach(fnIter, {
  onEnter(args) {
    const threadId = Process.getCurrentThreadId();
    const state = activeThreads[threadId];
    if (!state) return;
    state.queryObj = args[0].toString();
    state.dbCtx = args[1].toString();
  },
  onLeave(retval) {
    const threadId = Process.getCurrentThreadId();
    const state = activeThreads[threadId];
    if (!state) return;
    try {
      const queryObj = ptr(state.queryObj);
      const outVecPtr = queryObj.add(0x38).readPointer();
      send({
        kind: 'forced_iterator_result',
        threadId,
        talker: state.talker,
        originalCount: state.originalCount,
        forcedCount: state.forcedCount,
        builderRetval: state.builderRetval || null,
        iterRetval: retval.toString(),
        queryObj: state.queryObj,
        queryInfo: readQueryInfo(queryObj),
        dbCtx: state.dbCtx,
        vector: readVectorInfo(outVecPtr, 120),
      });
    } catch (e) {
      send({ kind: 'forced_iterator_error', threadId, talker: state.talker, error: String(e) });
    } finally {
      delete activeThreads[threadId];
    }
  }
});

setInterval(() => send({ kind: 'heartbeat' }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="Exact Weixin.exe PID to attach to")
    parser.add_argument("--target", required=True, help="Talker id whose request count should be forced")
    parser.add_argument("--count", type=int, required=True, help="Forced request size")
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
    script = session.create_script(
        SCRIPT_TEMPLATE
        % {
            "target_talker": args.target,
            "force_count": args.count,
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
