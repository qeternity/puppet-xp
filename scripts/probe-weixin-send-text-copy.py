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

function readUtf16Maybe(ptrValue, maxChars) {
  try {
    if (ptrValue.isNull()) return null;
    return ptrValue.readUtf16String(maxChars);
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

function scanPointersForUtf16(base, sizeBytes) {
  const out = [];
  const seen = {};
  for (let off = 0; off <= sizeBytes; off += Process.pointerSize) {
    try {
      const p = base.add(off).readPointer();
      const s = readUtf16Maybe(p, 128);
      if (!s) continue;
      if (s.length < 1 || s.length > 128) continue;
      if (!/^[\x20-\x7e\u00a0-\uffff]+$/.test(s)) continue;
      const key = off.toString(16) + '|' + s;
      if (seen[key]) continue;
      seen[key] = true;
      out.push({ offset: '0x' + off.toString(16), ptr: safePtrString(p), value: s });
      if (out.length >= 24) break;
    } catch (e) {
    }
  }
  return out;
}

const mod = Process.getModuleByName('Weixin.dll');
const copyFn = mod.base.add(0x38880);
const ownerFn = mod.base.add(0x15af8e0);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
const seen = {};

send({
  kind: 'status',
  baseline_seconds: BASELINE_SECONDS,
  copy_function: copyFn.toString(),
  owner_function: ownerFn.toString(),
});

Interceptor.attach(copyFn, {
  onEnter(args) {
    try {
      const ret = this.returnAddress;
      const rel = ptr(ret).sub(mod.base);
      if (rel.compare(ptr('0x15af8e0')) < 0 || rel.compare(ptr('0x15afcd0')) >= 0) {
        this.skip = true;
        return;
      }
      this.skip = false;
      this.dst = args[0];
      this.src = args[1];
      this.ret = ret;
    } catch (e) {
      this.skip = true;
    }
  },
  onLeave(retval) {
    try {
      if (this.skip) return;
      const payload = {
        return_address: safePtrString(this.ret),
        dst_ptr: safePtrString(this.dst),
        src_ptr: safePtrString(this.src),
        dst_std: readStdString(this.dst),
        src_std: readStdString(this.src),
        dst_strings: scanStdStrings(this.dst, 0x60),
        src_strings: scanStdStrings(this.src, 0x60),
        dst_utf16_ptrs: scanPointersForUtf16(this.dst, 0x60),
        src_utf16_ptrs: scanPointersForUtf16(this.src, 0x60),
      };
      const key = JSON.stringify(payload);
      if (seen[key]) return;
      seen[key] = true;
      if (Date.now() < baselineUntil) return;
      send({
        kind: 'send_text_copy',
        payload,
      });
    } catch (e) {
      send({ kind: 'error', where: 'copyFn', error: String(e) });
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
