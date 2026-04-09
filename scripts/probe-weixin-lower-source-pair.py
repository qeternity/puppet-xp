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
  } catch (e) {
    return '0x0';
  }
}

function readU32(base, off) {
  try { return base.add(off).readU32(); } catch (_) { return null; }
}

function readU64(base, off) {
  try { return safe(base.add(off).readPointer()); } catch (_) { return null; }
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
  } catch (e) {
    return null;
  }
}

function dumpStringAt(base, off) {
  return {
    off: '0x' + off.toString(16),
    text: readStdString(base.add(off)),
    len: readU32(base, off + 0x10),
    cap: readU32(base, off + 0x18),
  };
}

function dumpSource(sourcePtr, ownerPtr, mode, callerRva) {
  const interestingStrings = [0x48, 0x88, 0xb0, 0x180, 0x240, 0x270, 0x600, 0x660, 0x680];
  const strings = {};
  interestingStrings.forEach((off) => {
    strings['0x' + off.toString(16)] = dumpStringAt(sourcePtr, off);
  });
  const ptrs = {};
  [0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x98, 0x100, 0x150, 0x1b0, 0x220, 0x2a0, 0x5f0].forEach((off) => {
    ptrs['0x' + off.toString(16)] = readU64(sourcePtr, off);
  });
  const ints = {};
  [0x9c, 0xa0, 0xd8, 0x134, 0x138].forEach((off) => {
    ints['0x' + off.toString(16)] = readU32(sourcePtr, off);
  });
  const owner = ownerPtr.isNull() ? null : {
    ptr: safe(ownerPtr),
    vtable: readU64(ownerPtr, 0x0),
    ref_a: readU32(ownerPtr, 0x8),
    ref_b: readU32(ownerPtr, 0xc),
    builder_backref_18: readU64(ownerPtr, 0x18),
  };
  return {
    caller_rva: callerRva,
    mode,
    source: safe(sourcePtr),
    owner: owner,
    strings,
    ptrs,
    ints,
  };
}

let seen = {};

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
      const mode = args[3].toUInt32();
      if (!conversation || !body) return;
      const key = [conversation, body, mode, safe(this.returnAddress)].join('|');
      if (seen[key]) return;
      seen[key] = true;
      send({
        kind: 'lower_source_pair',
        dump: dumpSource(sourcePtr, ownerPtr, mode, safe(this.returnAddress.sub(mod.base))),
      });
    } catch (e) {
      send({ kind: 'error', where: 'lower_source_pair', error: String(e) });
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
    print(json.dumps({"kind": "host_meta", "pid": window["pid"], "thread_id": window["thread_id"], "title": window["title"]}, ensure_ascii=False))
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
