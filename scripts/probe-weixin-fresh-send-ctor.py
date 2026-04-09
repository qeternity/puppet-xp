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

function dumpEntry(entryPtr) {
  try {
    return {
      ptr: safe(entryPtr),
      s0: readStdString(entryPtr),
      q10: safe(entryPtr.add(0x10).readPointer()),
      q18: safe(entryPtr.add(0x18).readPointer()),
      type20: entryPtr.add(0x20).readU32(),
      u24: entryPtr.add(0x24).readU32(),
    };
  } catch (e) {
    return {
      ptr: safe(entryPtr),
      error: String(e),
    };
  }
}

Interceptor.attach(mod.base.add(0x1664250), {
  onEnter(args) {
    try {
      const param1 = args[0];
      const target = args[1];
      const vec = args[2];
      const start = vec.readPointer();
      const end = vec.add(Process.pointerSize).readPointer();
      const cap = vec.add(Process.pointerSize * 2).readPointer();
      const bytes = end.sub(start).toInt32();
      const count = bytes / 0x28;
      const entries = [];
      for (let i = 0; i < count && i < 8; i++) {
        entries.push(dumpEntry(start.add(i * 0x28)));
      }
      send({
        kind: 'fresh_send_ctor',
        caller_rva: safe(this.returnAddress.sub(mod.base)),
        param1: safe(param1),
        target_ptr: safe(target),
        target: readStdString(target),
        vec_ptr: safe(vec),
        start: safe(start),
        end: safe(end),
        cap: safe(cap),
        count,
        entries,
      });
    } catch (e) {
      send({ kind: 'error', where: 'fresh_send_ctor', error: String(e) });
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
