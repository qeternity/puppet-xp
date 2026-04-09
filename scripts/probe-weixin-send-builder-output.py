#!/usr/bin/env python
import ctypes
import json
import sys
import time
from ctypes import wintypes

import frida


SCRIPT = r"""
const mod = Process.getModuleByName('Weixin.dll');

function safe(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (_) {
    return '0x0';
  }
}

function readU32(base, off) {
  try { return base.add(off).readU32(); } catch (_) { return null; }
}

function readU64(base, off) {
  try { return base.add(off).readPointer().toString(); } catch (_) { return null; }
}

function readHex(base, size) {
  try {
    return hexdump(base, { offset: 0, length: size, header: false, ansi: false });
  } catch (_) {
    return null;
  }
}

function readStdString(addr) {
  try {
    const len = addr.add(0x10).readU32();
    const cap = addr.add(0x18).readU32();
    if (len === 0) return '';
    if (len > 0x4000 || cap > 0x100000) return null;
    let dataPtr = addr;
    if (cap > 15) dataPtr = addr.readPointer();
    if (!dataPtr || dataPtr.isNull()) return null;
    return dataPtr.readUtf8String(len);
  } catch (_) {
    return null;
  }
}

function dumpStd(base, off) {
  return {
    off: '0x' + off.toString(16),
    ptr: safe(base.add(off)),
    text: readStdString(base.add(off)),
    len: readU32(base, off + 0x10),
    cap: readU32(base, off + 0x18),
  };
}

function dumpQwords(base, count) {
  const out = {};
  for (let i = 0; i < count; i++) {
    const off = i * Process.pointerSize;
    out['0x' + off.toString(16)] = readU64(base, off);
  }
  return out;
}

let seq = 0;
let calls = {};

Interceptor.attach(mod.base.add(0x15e8200), {
  onEnter(args) {
    try {
      const pairPtr = args[2];
      if (pairPtr.isNull()) return;
      const sourcePtr = pairPtr.readPointer();
      const ownerPtr = pairPtr.add(Process.pointerSize).readPointer();
      if (sourcePtr.isNull() || ownerPtr.isNull()) return;

      const conversation = readStdString(sourcePtr.add(0xb0));
      const body = readStdString(sourcePtr.add(0x660));
      if (!conversation || !body) return;

      const id = ++seq;
      this.__probeId = id;
      calls[id] = {
        id,
        thread_id: Process.getCurrentThreadId(),
        caller_rva: safe(this.returnAddress.sub(mod.base)),
        send_ctx: safe(args[0]),
        result_buf: safe(args[1]),
        pair_ptr: safe(pairPtr),
        source_ptr: safe(sourcePtr),
        owner_ptr: safe(ownerPtr),
        mode: args[3].toUInt32(),
        conversation,
        body,
        source_fields: {
          convo: dumpStd(sourcePtr, 0xb0),
          uuid: dumpStd(sourcePtr, 0x600),
          body: dumpStd(sourcePtr, 0x660),
          aux_680: dumpStd(sourcePtr, 0x680),
        },
        owner_fields: {
          vtable: readU64(ownerPtr, 0x0),
          ref_a: readU32(ownerPtr, 0x8),
          ref_b: readU32(ownerPtr, 0xc),
          backref_18: readU64(ownerPtr, 0x18),
        },
      };

      send({ kind: 'build_enter', call: calls[id] });
    } catch (e) {
      send({ kind: 'error', where: '1815e8200_enter', error: String(e) });
    }
  },
  onLeave(retval) {
    try {
      const id = this.__probeId;
      if (!id || !calls[id]) return;
      const call = calls[id];
      const resultPtr = ptr(call.result_buf);
      call.retval = safe(retval);
      call.result_qwords = dumpQwords(resultPtr, 12);
      call.result_hex = readHex(resultPtr, 0x60);
      send({ kind: 'build_leave', call });
      delete calls[id];
    } catch (e) {
      send({ kind: 'error', where: '1815e8200_leave', error: String(e) });
    }
  }
});

Interceptor.attach(mod.base.add(0x15eb0d0), {
  onEnter(args) {
    try {
      const outPtr = args[1];
      const inObj = args[2];
      if (outPtr.isNull() || inObj.isNull()) return;

      const maybeText = [];
      [0x0, 0x10, 0x20, 0x30, 0x40, 0x50].forEach((off) => {
        maybeText.push(dumpStd(inObj, off));
      });

      send({
        kind: 'eb0d0_enter',
        thread_id: Process.getCurrentThreadId(),
        out_ptr: safe(outPtr),
        in_ptr: safe(inObj),
        in_qwords: dumpQwords(inObj, 10),
        in_strings: maybeText,
        out_pre_qwords: dumpQwords(outPtr, 8),
        out_pre_hex: readHex(outPtr, 0x40),
      });
    } catch (e) {
      send({ kind: 'error', where: '1815eb0d0_enter', error: String(e) });
    }
  },
  onLeave(retval) {
    try {
      send({
        kind: 'eb0d0_leave',
        thread_id: Process.getCurrentThreadId(),
        retval: safe(retval),
      });
    } catch (e) {
      send({ kind: 'error', where: '1815eb0d0_leave', error: String(e) });
    }
  }
});
"""


EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.EnumWindows.argtypes = [EnumWindowsProc, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD


def find_weixin_main_window():
    results = []

    @EnumWindowsProc
    def callback(hwnd, lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, len(buf))
        title = buf.value
        if not title:
            return True
        pid_out = wintypes.DWORD(0)
        tid = user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_out))
        results.append({"pid": pid_out.value, "thread_id": tid, "title": title})
        return True

    user32.EnumWindows(callback, 0)
    for item in results:
        if item["title"] == "WeChat":
            return item
    raise RuntimeError("No visible WeChat window found")


def main() -> None:
    window = find_weixin_main_window()
    device = frida.get_local_device()
    session = device.attach(window["pid"])
    script = session.create_script(SCRIPT)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    print(json.dumps({"kind": "host_meta", "pid": window["pid"], "thread_id": window["thread_id"], "title": window["title"]}, ensure_ascii=False), flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
