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

function readVector(base) {
  try {
    const begin = base.readPointer();
    const end = base.add(Process.pointerSize).readPointer();
    const cap = base.add(Process.pointerSize * 2).readPointer();
    const count = end.sub(begin).toInt32() / 0x10;
    return {
      begin: safePtrString(begin),
      end: safePtrString(end),
      cap: safePtrString(cap),
      count,
    };
  } catch (e) {
    return null;
  }
}

function readPair(base) {
  try {
    return {
      pair_ptr: safePtrString(base),
      first_ptr: safePtrString(base.readPointer()),
      second_ptr: safePtrString(base.add(Process.pointerSize).readPointer()),
    };
  } catch (e) {
    return null;
  }
}

function scanTopStrings(base, offsets) {
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
const targetFn = mod.base.add(0x15af8e0);
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
      const wrapper = args[0];
      const vec = readVector(wrapper.add(0x8));
      let firstPair = null;
      let sourceObj = ptr(0);
      let sourceStrings = [];
      if (vec && vec.count > 0) {
        firstPair = readPair(ptr(vec.begin));
        if (firstPair && firstPair.first_ptr !== '0x0') {
          sourceObj = ptr(firstPair.first_ptr);
          sourceStrings = scanTopStrings(sourceObj, [0xb0, 0x600, 0x660]);
        }
      }

      const payload = {
        wrapper_ptr: safePtrString(wrapper),
        wrapper_vtable: safePtrString(wrapper.readPointer()),
        recipient_vector: vec,
        first_pair: firstPair,
        source_obj: safePtrString(sourceObj),
        source_strings: sourceStrings,
        metadata_strings: scanTopStrings(wrapper.add(0x20), [0x0, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0]),
        callers: callerFrames(this.context, mod),
      };
      const key = JSON.stringify([
        payload.source_strings.map(x => x.value),
        payload.metadata_strings.map(x => x.value),
      ]);
      if (seen[key]) return;
      seen[key] = true;
      if (Date.now() < baselineUntil) return;
      send({ kind: 'send_top_wrapper', payload });
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
