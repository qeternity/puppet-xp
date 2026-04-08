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

function tryRewriteTalkerCopies(queryObj, targetTalker) {
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
      strings: readStringFields(row, [0x18, 0x38, 0x58, 0x140, 0x180]),
      ints: readIntFields(row, [0x10, 0x118, 0x120, 0x124, 0x128, 0x138, 0x1c0, 0x1c4]),
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
      rows: dumpRows(begin, end, 64),
    };
  } catch (e) {
    return { error: String(e) };
  }
}

const mod = Process.getModuleByName('Weixin.dll');
const fn = mod.base.add(0x13ff7c0);

send({ kind: 'status', fn: fn.toString(), source: SOURCE_TALKER, target: TARGET_TALKER });

let redirected = false;

Interceptor.attach(fn, {
  onEnter(args) {
    this.queryObj = args[0];
    this.dbCtx = args[1];
    this.talkerObj = args[0].readPointer();
    this.originalTalker = readStdString(this.talkerObj) || '';
    this.didRedirect = false;
    if (redirected) return;
    if (this.originalTalker !== SOURCE_TALKER) return;
    try {
      const rewrites = tryRewriteTalkerCopies(this.queryObj, TARGET_TALKER);
      redirected = true;
      this.didRedirect = true;
      send({
        kind: 'redirected',
        queryObj: this.queryObj.toString(),
        dbCtx: this.dbCtx.toString(),
        originalTalker: this.originalTalker,
        rewrittenTalker: readStdString(this.talkerObj),
        rewrites,
      });
    } catch (e) {
      send({ kind: 'redirect_error', error: String(e), originalTalker: this.originalTalker });
    }
  },
  onLeave(retval) {
    if (!this.didRedirect) return;
    try {
      const outVecPtr = this.queryObj.add(0x38).readPointer();
      send({
        kind: 'message_iterator_redirected',
        retval: retval.toString(),
        talker: readStdString(this.talkerObj),
        originalTalker: this.originalTalker,
        queryObj: this.queryObj.toString(),
        dbCtx: this.dbCtx.toString(),
        vector: readVectorInfo(outVecPtr),
      });
    } catch (e) {
      send({ kind: 'redirect_leave_error', error: String(e) });
    }
  },
});

setInterval(() => send({ kind: 'heartbeat' }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, help="Talker id expected from the real UI query")
    parser.add_argument("--target", required=True, help="Talker id to substitute in-flight")
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
