#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT = r"""
const BASELINE_SECONDS = {{BASELINE_SECONDS}};

function readStdString(addr) {
  try {
    const len = addr.add(0x10).readU32();
    const cap = addr.add(0x18).readU32();
    if (len === 0) return '';
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

function safePtrString(p) {
  try {
    if (p === null || p.isNull()) return '0x0';
    return p.toString();
  } catch (e) {
    return '0x0';
  }
}

function scanStdStrings(base, sizeBytes) {
  const out = [];
  const seen = {};
  for (let off = 0; off <= sizeBytes; off += 0x8) {
    const s = readStdString(base.add(off));
    if (!s) continue;
    if (s.length < 1 || s.length > 512) continue;
    const key = off.toString(16) + '|' + s;
    if (seen[key]) continue;
    seen[key] = true;
    out.push({ offset: '0x' + off.toString(16), value: s });
    if (out.length >= 24) break;
  }
  return out;
}

const mod = Process.getModuleByName('Weixin.dll');
const extractor = mod.base.add(0x15eb0d0);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
const seen = {};

send({
  kind: 'status',
  baseline_seconds: BASELINE_SECONDS,
  extractor: extractor.toString(),
});

Interceptor.attach(extractor, {
  onEnter(args) {
    this.outPtr = args[1];
    this.srcPtr = args[2];
    this.ret = this.returnAddress;
  },
  onLeave(retval) {
    try {
      const outStr = readStdString(this.outPtr.add(0x8));
      const outStrings = scanStdStrings(this.outPtr, 0x60);
      const srcStrings = scanStdStrings(this.srcPtr, 0x80);
      const key = JSON.stringify([safePtrString(this.ret), outStr, outStrings, srcStrings]);
      if (seen[key]) return;
      seen[key] = true;
      if (Date.now() < baselineUntil) return;
      send({
        kind: 'send_content_extract',
        return_address: safePtrString(this.ret),
        out_ptr: safePtrString(this.outPtr),
        src_ptr: safePtrString(this.srcPtr),
        out_string_guess: outStr,
        out_strings: outStrings,
        src_strings: srcStrings,
      });
    } catch (e) {
      send({ kind: 'error', where: 'extractor', error: String(e) });
    }
  }
});

setTimeout(() => send({ kind: 'armed', seen_count: Object.keys(seen).length }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat', seen_count: Object.keys(seen).length }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="Exact Weixin.exe PID to attach to")
    parser.add_argument("--baseline-seconds", type=int, default=3)
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
    rendered = SCRIPT.replace("{{BASELINE_SECONDS}}", str(args.baseline_seconds))
    script = session.create_script(rendered)

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
