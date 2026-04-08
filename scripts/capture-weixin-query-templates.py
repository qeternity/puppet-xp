#!/usr/bin/env python
import sys
import threading

import frida


SCRIPT = r"""
const WATCH_TALKERS = [
  'wxid_3a40v7q8y4kk12',   // Glenn
  'wxid_cdxvsfdqlbqw22',   // Adam - Arrow FFAs
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

function tryReadPointer(addr) {
  try { return addr.readPointer(); } catch (e) { return null; }
}

function tryReadU32(addr) {
  try { return addr.readU32(); } catch (e) { return null; }
}

function tryReadU64(addr) {
  try { return addr.readU64().toString(); } catch (e) { return null; }
}

function hexdumpWords(addr, countQwords) {
  const out = [];
  for (let i = 0; i < countQwords; i++) {
    const slot = addr.add(i * 8);
    out.push({
      off: '0x' + (i * 8).toString(16),
      qword: tryReadU64(slot),
      u32: tryReadU32(slot),
      ptr: (function () { const p = tryReadPointer(slot); return p ? p.toString() : null; })(),
      std: readStdString(slot),
    });
  }
  return out;
}

function dumpRangePair(ptrValue, maxRows) {
  if (!ptrValue || ptrValue.isNull()) return null;
  try {
    const begin = ptrValue.readPointer();
    const end = ptrValue.add(Process.pointerSize).readPointer();
    const out = {
      base: ptrValue.toString(),
      begin: begin.toString(),
      end: end.toString(),
      rows: [],
    };
    if (begin.isNull() || end.isNull() || end.compare(begin) < 0) return out;
    const totalBytes = parseInt(end.sub(begin).toString(), 16);
    const count = Math.min(Math.floor(totalBytes / 0x290), maxRows);
    for (let i = 0; i < count; i++) {
      const row = begin.add(i * 0x290);
      out.rows.push({
        index: i,
        row: row.toString(),
        talker38: readStdString(row.add(0x38)),
        sender18: readStdString(row.add(0x18)),
        body180: readStdString(row.add(0x180)),
        ts124: tryReadU32(row.add(0x124)),
      });
    }
    return out;
  } catch (e) {
    return { error: String(e) };
  }
}

function dumpNestedObject(ptrValue) {
  if (!ptrValue || ptrValue.isNull()) return null;
  const out = {
    ptr: ptrValue.toString(),
    inlineStd: readStdString(ptrValue),
    derefStd: null,
    words: hexdumpWords(ptrValue, 12),
    maybeRange: null,
  };
  try { out.derefStd = readStdString(ptrValue.readPointer()); } catch (e) {}
  try { out.maybeRange = dumpRangePair(ptrValue, 4); } catch (e) {}
  return out;
}

function dumpQueryTemplate(queryObj) {
  const slots = [];
  for (let off = 0; off <= 0x60; off += 8) {
    const slot = queryObj.add(off);
    const ptrValue = tryReadPointer(slot);
    slots.push({
      off: '0x' + off.toString(16),
      rawQword: tryReadU64(slot),
      u32: tryReadU32(slot),
      ptr: ptrValue ? ptrValue.toString() : null,
      inlineStd: readStdString(slot),
      nested: (off >= 0x18 && off <= 0x30) || off === 0x0 || off === 0x38 || off === 0x40
        ? dumpNestedObject(ptrValue)
        : null,
    });
  }
  return slots;
}

const mod = Process.getModuleByName('Weixin.dll');
const fn = mod.base.add(0x13ff7c0);
send({ kind: 'status', fn: fn.toString(), watchTalkers: WATCH_TALKERS });

Interceptor.attach(fn, {
  onEnter(args) {
    const queryObj = args[0];
    const dbCtx = args[1];
    const talkerObj = queryObj.readPointer();
    const talker = readStdString(talkerObj) || '';
    if (WATCH_TALKERS.indexOf(talker) < 0) return;
    send({
      kind: 'query_template',
      talker,
      queryObj: queryObj.toString(),
      dbCtx: dbCtx.toString(),
      slots: dumpQueryTemplate(queryObj),
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
