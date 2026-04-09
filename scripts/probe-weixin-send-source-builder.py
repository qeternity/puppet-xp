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
  if (s.length < 1 || s.length > 1024) return false;
  return /^[\x20-\x7e\u00a0-\uffff\r\n\t]+$/.test(s);
}

function scanStdStrings(base, sizeBytes) {
  const out = [];
  for (let off = 0; off <= sizeBytes; off += 0x8) {
    const s = readStdString(base.add(off));
    if (!plausible(s)) continue;
    out.push({ offset: '0x' + off.toString(16), value: s });
    if (out.length >= 48) break;
  }
  return out;
}

function scanUtf16Strings(base, sizeBytes) {
  const out = [];
  for (let off = 0; off <= sizeBytes; off += 0x8) {
    try {
      const s = base.add(off).readUtf16String(128);
      if (!s) continue;
      if (s.length < 2 || s.length > 512) continue;
      if (!/[A-Za-z0-9]/.test(s)) continue;
      out.push({ offset: '0x' + off.toString(16), value: s });
      if (out.length >= 32) break;
    } catch (e) {
    }
  }
  return out;
}

function scanInts(base, sizeBytes) {
  const out = [];
  for (let off = 0; off <= sizeBytes; off += 0x4) {
    try {
      const v = base.add(off).readU32();
      if (v === 0) continue;
      if (v > 0xffffffff) continue;
      out.push({ offset: '0x' + off.toString(16), value: v });
      if (out.length >= 48) break;
    } catch (e) {
    }
  }
  return out;
}

function scanPointerChildren(base, sizeBytes) {
  const out = [];
  for (let off = 0; off <= sizeBytes; off += Process.pointerSize) {
    try {
      const p = base.add(off).readPointer();
      if (p.isNull()) continue;
      if (p.compare(ptr('0x10000')) < 0) continue;
      const std = scanStdStrings(p, 0x100);
      const utf16 = scanUtf16Strings(p, 0x100);
      const ints = scanInts(p, 0x80);
      if (std.length === 0 && utf16.length === 0 && ints.length === 0) continue;
      out.push({
        offset: '0x' + off.toString(16),
        ptr: safePtrString(p),
        child_vtable: safePtrString(p.readPointer()),
        std,
        utf16,
        ints,
      });
      if (out.length >= 24) break;
    } catch (e) {
    }
  }
  return out;
}

function profilePtr(p, label) {
  if (!p || p.isNull()) {
    return {
      label,
      ptr: safePtrString(p),
      vtable: '0x0',
      std: [],
      utf16: [],
      ints: [],
      children: [],
    };
  }
  return {
    label,
    ptr: safePtrString(p),
    vtable: safePtrString(p.readPointer()),
    std: scanStdStrings(p, 0x180),
    utf16: scanUtf16Strings(p, 0x180),
    ints: scanInts(p, 0xc0),
    children: scanPointerChildren(p, 0x180),
  };
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
      .slice(0, 10);
  } catch (e) {
    return [{ error: String(e) }];
  }
}

const mod = Process.getModuleByName('Weixin.dll');
const targetFn = mod.base.add(0x1638130);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
let seen = {};

send({
  kind: 'status',
  target_fn: targetFn.toString(),
  baseline_seconds: BASELINE_SECONDS,
});

Interceptor.attach(targetFn, {
  onEnter(args) {
    try {
      const p1 = args[0];
      const p2 = args[1];
      const p3 = args[2];
      const payload = {
        p1: profilePtr(p1, 'param1'),
        p2: profilePtr(p2, 'param2'),
        p3: profilePtr(p3, 'param3'),
        callers: callerFrames(this.context, mod),
      };
      const strings = []
        .concat(payload.p1.std.map(x => x.value))
        .concat(payload.p2.std.map(x => x.value))
        .concat(payload.p3.std.map(x => x.value))
        .concat(payload.p1.children.flatMap(x => x.std.map(y => y.value)))
        .concat(payload.p2.children.flatMap(x => x.std.map(y => y.value)))
        .concat(payload.p3.children.flatMap(x => x.std.map(y => y.value)));
      const key = JSON.stringify(strings.sort().slice(0, 24));
      if (seen[key]) return;
      seen[key] = true;
      if (Date.now() < baselineUntil) return;
      send({ kind: 'send_source_builder', payload });
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
