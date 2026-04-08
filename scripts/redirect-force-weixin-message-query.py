#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT_TEMPLATE = r"""
const SOURCE_TALKER = %(source_talker)r;
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

function rewriteQueryTalker(queryObj, targetTalker) {
  const rewritten = [];

  const primaryTalkerObj = queryObj.readPointer();
  overwriteStdString(primaryTalkerObj, targetTalker);
  rewritten.push({ where: 'slot0', value: readStdString(primaryTalkerObj) });

  try {
    const nested20 = queryObj.add(0x20).readPointer();
    if (!nested20.isNull()) {
      const nested20Talker = nested20.add(0x18);
      const current = readStdString(nested20Talker);
      if (current !== null) {
        overwriteStdString(nested20Talker, targetTalker);
        rewritten.push({ where: 'slot20+0x18', value: readStdString(nested20Talker) });
      }
    }
  } catch (e) {
    rewritten.push({ where: 'slot20+0x18', error: String(e) });
  }

  return rewritten;
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
  for (const off of [0x0, 0x8, 0x20, 0x28, 0x30, 0x38, 0x40]) {
    try {
      out['0x' + off.toString(16)] = queryObj.add(off).readPointer().toString();
    } catch (e) {}
  }
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
  sourceTalker: SOURCE_TALKER,
  targetTalker: TARGET_TALKER,
  forceCount: FORCE_COUNT,
});

const activeThreads = {};
let finished = false;

Interceptor.attach(fnBuilder, {
  onEnter(args) {
    if (finished) return;
    let talker = null;
    try { talker = readStdString(args[2]); } catch (e) {}
    if (talker !== SOURCE_TALKER) return;
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
      sourceTalker: talker,
      targetTalker: TARGET_TALKER,
      originalCount,
      forcedCount: FORCE_COUNT,
    };
    send({
      kind: 'builder_forced',
      threadId,
      sourceTalker: talker,
      targetTalker: TARGET_TALKER,
      originalCount,
      forcedCount: FORCE_COUNT,
    });
  }
});

Interceptor.attach(fnIter, {
  onEnter(args) {
    if (finished) return;
    const threadId = Process.getCurrentThreadId();
    const state = activeThreads[threadId];
    if (!state) return;
    state.queryObj = args[0].toString();
    state.dbCtx = args[1].toString();
    state.rewrites = [];
    try {
      const originalPrimary = readStdString(args[0].readPointer()) || '';
      const nested20 = args[0].add(0x20).readPointer();
      const originalNested = nested20.isNull() ? null : readStdString(nested20.add(0x18));
      state.rewrites = rewriteQueryTalker(args[0], TARGET_TALKER);
      state.originalPrimary = originalPrimary;
      state.originalNested = originalNested;
      send({
        kind: 'iter_redirected',
        threadId,
        sourceTalker: state.sourceTalker,
        targetTalker: state.targetTalker,
        queryObj: args[0].toString(),
        rewrites: state.rewrites,
      });
    } catch (e) {
      state.redirectError = String(e);
      send({
        kind: 'iter_redirect_error',
        threadId,
        sourceTalker: state.sourceTalker,
        targetTalker: state.targetTalker,
        queryObj: args[0].toString(),
        error: String(e),
      });
    }
  },
  onLeave(retval) {
    if (finished) return;
    const threadId = Process.getCurrentThreadId();
    const state = activeThreads[threadId];
    if (!state) return;
    try {
      if (!state.queryObj) {
        throw new Error('missing queryObj');
      }
      const queryObj = ptr(state.queryObj);
      const outVecPtr = queryObj.add(0x38).readPointer();
      send({
        kind: 'redirected_forced_result',
        threadId,
        sourceTalker: state.sourceTalker,
        targetTalker: state.targetTalker,
        originalCount: state.originalCount,
        forcedCount: state.forcedCount,
        iterRetval: retval.toString(),
        queryObj: queryObj.toString(),
        queryInfo: readQueryInfo(queryObj),
        dbCtx: state.dbCtx || null,
        vector: readVectorInfo(outVecPtr, 120),
      });
      finished = true;
    } catch (e) {
      send({
        kind: 'redirected_forced_result_error',
        threadId,
        sourceTalker: state.sourceTalker,
        targetTalker: state.targetTalker,
        error: String(e),
      });
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
    parser.add_argument("--source", required=True, help="Talker id expected from the UI-selected source conversation")
    parser.add_argument("--target", required=True, help="Talker id to substitute at the iterator")
    parser.add_argument("--count", type=int, default=100, help="Forced builder request size")
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
          "source_talker": args.source,
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
