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

function plausible(s) {
  if (!s) return false;
  if (s.length < 1 || s.length > 1024) return false;
  return /^[\x20-\x7e\u00a0-\uffff\r\n\t]+$/.test(s);
}

function safePtrString(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (e) {
    return '0x0';
  }
}

function scanStdStrings(base, sizeBytes) {
  const out = [];
  for (let off = 0; off <= sizeBytes; off += 0x8) {
    const s = readStdString(base.add(off));
    if (!plausible(s)) continue;
    out.push({ offset: '0x' + off.toString(16), value: s });
    if (out.length >= 32) break;
  }
  return out;
}

function scanUtf16Strings(base, sizeBytes) {
  const out = [];
  for (let off = 0; off <= sizeBytes; off += 0x8) {
    try {
      const s = base.add(off).readUtf16String(96);
      if (!s) continue;
      if (s.length < 2 || s.length > 256) continue;
      if (!/[A-Za-z0-9]/.test(s)) continue;
      out.push({ offset: '0x' + off.toString(16), value: s });
      if (out.length >= 24) break;
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
      const std = scanStdStrings(p, 0x80);
      const utf16 = scanUtf16Strings(p, 0x80);
      if (std.length === 0 && utf16.length === 0) continue;
      out.push({
        offset: '0x' + off.toString(16),
        ptr: safePtrString(p),
        child_vtable: safePtrString(p.readPointer()),
        std,
        utf16,
      });
      if (out.length >= 24) break;
    } catch (e) {
    }
  }
  return out;
}

function callerFrames(context, mod) {
  try {
    const bt = Thread.backtrace(context, Backtracer.ACCURATE)
      .map(p => {
        const rel = p.sub(mod.base);
        return {
          address: p.toString(),
          relative: '0x' + rel.toString(16),
          symbol: DebugSymbol.fromAddress(p).toString(),
        };
      });
    return bt.slice(0, 10);
  } catch (e) {
    return [{ error: String(e) }];
  }
}

const mod = Process.getModuleByName('Weixin.dll');
const targetFn = mod.base.add(0x15eb0d0);
const normalizeTypeName = new NativeFunction(mod.base.add(0x64afaac), 'pointer', ['pointer', 'pointer']);
const targetTypeDesc = mod.base.add(0xa301680);
const targetNamespace = mod.base.add(0x9d702f8);
const copyRef = new NativeFunction(mod.base.add(0x316b50), 'void', ['pointer']);
const getInner = new NativeFunction(mod.base.add(0x319290), 'pointer', ['pointer']);

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
      const outPtr = args[1];
      const inRef = args[2];

      const tmp = Memory.alloc(0x20);
      tmp.writeByteArray(new Uint8Array(0x20));
      tmp.writePointer(inRef.readPointer());
      tmp.add(Process.pointerSize).writePointer(inRef.add(Process.pointerSize).readPointer());

      copyRef(tmp);
      const innerSlot = getInner(tmp.readPointer());
      let actualTypeName = null;
      let targetTypeName = null;
      let innerObj = ptr(0);

      try {
        const targetTypePtr = normalizeTypeName(targetNamespace, targetTypeDesc);
        targetTypeName = targetTypePtr.readUtf8String();
      } catch (e) {}

      if (!innerSlot.isNull()) {
        innerObj = innerSlot.readPointer();
        if (!innerObj.isNull()) {
          let typeDescPtr = ptr(0);
          try {
            typeDescPtr = new NativeFunction(innerObj.readPointer().add(0x10).readPointer(), 'pointer', [])();
          } catch (e) {}
          if (!typeDescPtr.isNull()) {
            try {
              const actualTypePtr = normalizeTypeName(typeDescPtr.add(Process.pointerSize * 2), targetTypeDesc);
              actualTypeName = actualTypePtr.readUtf8String();
            } catch (e) {}
          }
        }
      }

      const payload = {
        out_ptr: safePtrString(outPtr),
        in_ref_ptr: safePtrString(inRef),
        inner_slot_ptr: safePtrString(innerSlot),
        inner_obj_ptr: safePtrString(innerObj),
        inner_obj_vtable: innerObj.isNull() ? '0x0' : safePtrString(innerObj.readPointer()),
        actual_type_name: actualTypeName,
        target_type_name: targetTypeName,
        inner_strings: innerObj.isNull() ? [] : scanStdStrings(innerObj, 0x100),
        inner_utf16: innerObj.isNull() ? [] : scanUtf16Strings(innerObj, 0x100),
        inner_pointer_children: innerObj.isNull() ? [] : scanPointerChildren(innerObj, 0x100),
        inref_strings: scanStdStrings(inRef, 0x40),
        inref_pointer_children: scanPointerChildren(inRef, 0x40),
        out_strings_before: scanStdStrings(outPtr, 0x50),
        callers: callerFrames(this.context, mod),
      };

      const key = JSON.stringify([payload.actual_type_name, payload.inner_strings]);
      if (seen[key]) return;
      seen[key] = true;
      if (Date.now() < baselineUntil) return;
      send({ kind: 'send_payload_type', payload });
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
