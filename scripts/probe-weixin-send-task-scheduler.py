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

function plausibleText(s) {
  if (!s) return false;
  if (s.length < 1 || s.length > 256) return false;
  if (!/^[\x20-\x7e\u00a0-\uffff]+$/.test(s)) return false;
  return true;
}

function scanStdStrings(base, sizeBytes) {
  const out = [];
  const seen = {};
  for (let off = 0; off <= sizeBytes; off += 0x8) {
    const s = readStdString(base.add(off));
    if (!plausibleText(s)) continue;
    const key = off.toString(16) + '|' + s;
    if (seen[key]) continue;
    seen[key] = true;
    out.push({ offset: '0x' + off.toString(16), value: s });
    if (out.length >= 32) break;
  }
  return out;
}

function scanPointers(base, sizeBytes) {
  const out = [];
  const seen = {};
  for (let off = 0; off <= sizeBytes; off += Process.pointerSize) {
    try {
      const p = base.add(off).readPointer();
      if (p.isNull()) continue;
      const utf16 = readUtf16Maybe(p, 128);
      const std = readStdString(p);
      const around = scanStdStrings(p, 0x40);
      if (!plausibleText(utf16) && !plausibleText(std) && around.length === 0) continue;
      const key = off.toString(16) + '|' + p.toString();
      if (seen[key]) continue;
      seen[key] = true;
      out.push({
        offset: '0x' + off.toString(16),
        ptr: safePtrString(p),
        utf16,
        std,
        around,
      });
      if (out.length >= 40) break;
    } catch (e) {
    }
  }
  return out;
}

function scanVector(vecPtr) {
  const out = [];
  try {
    const begin = vecPtr.readPointer();
    const end = vecPtr.add(Process.pointerSize).readPointer();
    const stride = Process.pointerSize * 2;
    let cur = begin;
    let count = 0;
    while (cur.compare(end) < 0 && count < 8) {
      out.push({
        element_ptr: safePtrString(cur),
        std_value: readStdString(cur),
        strings: scanStdStrings(cur, 0x60),
      });
      cur = cur.add(stride);
      count++;
    }
  } catch (e) {
  }
  return out;
}

const mod = Process.getModuleByName('Weixin.dll');
const scheduleFn = mod.base.add(0x314950);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
const seen = {};

send({
  kind: 'status',
  baseline_seconds: BASELINE_SECONDS,
  schedule_function: scheduleFn.toString(),
});

Interceptor.attach(scheduleFn, {
  onEnter(args) {
    try {
      const taskHolder = args[1];
      const taskPtr = taskHolder.readPointer();
      if (taskPtr.isNull()) return;
      const payload = {
        task_ptr: safePtrString(taskPtr),
        task_strings: scanStdStrings(taskPtr, 0x158),
        task_pointers: scanPointers(taskPtr, 0x158),
        payload_at_28_strings: scanStdStrings(taskPtr.add(0x28), 0x80),
        payload_at_28_pointers: scanPointers(taskPtr.add(0x28), 0x80),
        payload_at_110_strings: scanStdStrings(taskPtr.add(0x110), 0x48),
        payload_at_110_pointers: scanPointers(taskPtr.add(0x110), 0x48),
        vector_at_138: scanVector(taskPtr.add(0x138)),
      };
      const key = JSON.stringify(payload);
      if (seen[key]) return;
      seen[key] = true;
      if (Date.now() < baselineUntil) return;
      send({
        kind: 'send_task_schedule',
        payload,
      });
    } catch (e) {
      send({ kind: 'error', where: 'scheduleFn', error: String(e) });
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
            sys.stdout.buffer.write((str(message["payload"] if "payload" in message else message) + "\n").encode("utf-8", errors="replace"))
            sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    sys.stdout.buffer.write((f"attached pid={pid}\n").encode("utf-8"))
    sys.stdout.flush()
    threading.Event().wait()


if __name__ == "__main__":
    main()
