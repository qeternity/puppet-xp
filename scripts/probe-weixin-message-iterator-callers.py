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

function tryReadTalkerFromQuery(queryObj) {
  const result = {};
  try {
    const slot0 = queryObj.readPointer();
    result.slot0Ptr = slot0.toString();
    result.slot0 = readStdString(slot0);
  } catch (e) {}
  try {
    const nested20 = queryObj.add(0x20).readPointer();
    result.slot20Ptr = nested20.toString();
    if (!nested20.isNull()) {
      result.slot20_18 = readStdString(nested20.add(0x18));
    }
  } catch (e) {}
  return result;
}

function dumpQwords(base, count) {
  const out = [];
  for (let i = 0; i < count; i++) {
    try {
      const off = i * Process.pointerSize;
      const val = base.add(off).readPointer();
      out.push({ off: '0x' + off.toString(16), ptr: val.toString() });
    } catch (e) {
      out.push({ off: '0x' + (i * Process.pointerSize).toString(16), error: String(e) });
    }
  }
  return out;
}

const mod = Process.getModuleByName('Weixin.dll');
const fn = mod.base.add(0x13ff7c0);
send({ kind: 'status', fn: fn.toString(), moduleBase: mod.base.toString() });

Interceptor.attach(fn, {
  onEnter(args) {
    try {
      const queryObj = args[0];
      const dbCtx = args[1];
      const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(addr => {
          const modInfo = Process.findModuleByAddress(addr);
          return {
            address: addr.toString(),
            module: modInfo ? modInfo.name : null,
            relative: modInfo ? ptr(addr).sub(modInfo.base).toString() : null,
          };
        });
      send({
        kind: 'iterator_enter_bt',
        queryObj: queryObj.toString(),
        dbCtx: dbCtx.toString(),
        queryTalkers: tryReadTalkerFromQuery(queryObj),
        qwords: dumpQwords(queryObj, 12),
        backtrace,
      });
    } catch (e) {
      send({ kind: 'iterator_enter_bt_error', error: String(e) });
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
