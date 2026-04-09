#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT = r"""
const BASELINE_SECONDS = {{BASELINE_SECONDS}};

function safePtrString(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (e) {
    return '0x0';
  }
}

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

function plausible(s) {
  if (!s) return false;
  if (s.length < 1 || s.length > 4096) return false;
  return /^[\x20-\x7e\u00a0-\uffff\r\n\t]+$/.test(s);
}

function scanInterestingStd(base, offsets) {
  const out = [];
  for (const off of offsets) {
    try {
      const s = readStdString(base.add(off));
      if (!plausible(s)) continue;
      out.push({ offset: '0x' + off.toString(16), value: s });
    } catch (e) {
    }
  }
  return out;
}

function scanUtf16(base, offsets) {
  const out = [];
  for (const off of offsets) {
    try {
      const s = base.add(off).readUtf16String(128);
      if (!s) continue;
      if (s.length < 2 || s.length > 512) continue;
      if (!/[A-Za-z0-9]/.test(s)) continue;
      out.push({ offset: '0x' + off.toString(16), value: s });
    } catch (e) {
    }
  }
  return out;
}

function readU32(base, off) {
  try {
    return base.add(off).readU32();
  } catch (e) {
    return null;
  }
}

function scanInts(base, offsets) {
  const out = [];
  for (const off of offsets) {
    const v = readU32(base, off);
    if (v === null) continue;
    out.push({ offset: '0x' + off.toString(16), value: v });
  }
  return out;
}

function callerFrames(context, mod) {
  try {
    return Thread.backtrace(context, Backtracer.ACCURATE)
      .map(p => {
        const rel = p.sub(mod.base);
        return {
          address: p.toString(),
          relative: '0x' + rel.toString(16),
          symbol: DebugSymbol.fromAddress(p).toString(),
        };
      })
      .slice(0, 8);
  } catch (e) {
    return [{ error: String(e) }];
  }
}

const mod = Process.getModuleByName('Weixin.dll');
const targetFn = mod.base.add(0x15e8200);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
let seen = {};

const stdOffsets = [
  0x18,0x38,0x58,0x78,0x98,0xb0,0xd0,0xf0,0x110,0x130,0x150,0x170,0x190,0x1b0,
  0x200,0x220,0x240,0x260,0x280,0x2a0,0x2c0,0x300,0x380,0x400,0x480,0x500,
  0x580,0x600,0x620,0x640,0x660,0x680,0x6a0,0x6c0
];
const utf16Offsets = [
  0x18,0x38,0x58,0x78,0x98,0xb0,0xd0,0xf0,0x110,0x130,0x150,0x170,0x190,0x1b0,
  0x200,0x220,0x240,0x260,0x280,0x2a0,0x2c0,0x300,0x380,0x400,0x480,0x500,
  0x580,0x600,0x620,0x640,0x660,0x680
];
const intOffsets = [
  0x8,0xc,0x10,0x14,0x18,0x1c,0x20,0x24,0x28,0x2c,
  0x98,0x9c,0xa0,0xa4,0xa8,0xac,0xb8,0xbc,0xc0,0xc4,0xc8,0xcc,
  0xd8,0xdc,0xe0,0xe4,0xe8,0xec,
  0x658,0x65c,0x660,0x664,0x668,0x66c,0x670,0x674
];

send({
  kind: 'status',
  target_fn: targetFn.toString(),
  baseline_seconds: BASELINE_SECONDS,
});

Interceptor.attach(targetFn, {
  onEnter(args) {
    try {
      const sourcePair = args[2];
      const sourceObj = sourcePair.readPointer();
      if (sourceObj.isNull()) return;
      const payload = {
        param4: args[3].toInt32(),
        source_pair: safePtrString(sourcePair),
        source_obj: safePtrString(sourceObj),
        source_vtable: safePtrString(sourceObj.readPointer()),
        interesting_std: scanInterestingStd(sourceObj, stdOffsets),
        interesting_utf16: scanUtf16(sourceObj, utf16Offsets),
        interesting_ints: scanInts(sourceObj, intOffsets),
        callers: callerFrames(this.context, mod),
      };
      const key = JSON.stringify([
        payload.param4,
        payload.interesting_std.map(x => x.value),
        payload.interesting_utf16.map(x => x.value),
      ]);
      if (seen[key]) return;
      seen[key] = true;
      if (Date.now() < baselineUntil) return;
      send({ kind: 'send_request_source', payload });
    } catch (e) {
      send({ kind: 'error', where: 'targetFn', error: String(e) });
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
        payload = message.get("payload", message)
        sys.stdout.buffer.write((str(payload) + "\n").encode("utf-8", errors="replace"))
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    sys.stdout.buffer.write((f"attached pid={pid}\n").encode("utf-8"))
    sys.stdout.flush()
    threading.Event().wait()


if __name__ == "__main__":
    main()
