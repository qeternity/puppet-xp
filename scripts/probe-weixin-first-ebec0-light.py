#!/usr/bin/env python
import argparse
import ctypes
import json
import sys
import time
from ctypes import wintypes

import frida


SCRIPT = r"""
const TARGET_BODY = {{TARGET_BODY_JSON}};
const mod = Process.getModuleByName('Weixin.dll');

function safe(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (_) {
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
  } catch (_) {
    return null;
  }
}

function dumpBytesHex(base, size) {
  try {
    if (!base || base.isNull()) return null;
    const bytes = base.readByteArray(size);
    if (!bytes) return null;
    return Array.from(new Uint8Array(bytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch (_) {
    return null;
  }
}

let activeThread = 0;
let seenFirst = false;

Interceptor.attach(mod.base.add(0x15e8200), {
  onEnter(args) {
    try {
      const pairPtr = args[2];
      if (pairPtr.isNull()) return;
      const sourcePtr = pairPtr.readPointer();
      if (sourcePtr.isNull()) return;
      const body = readStdString(sourcePtr.add(0x660));
      if (body !== TARGET_BODY) return;
      activeThread = Process.getCurrentThreadId();
      seenFirst = false;
      send({
        kind: 'build_enter',
        thread_id: activeThread,
        conversation: readStdString(sourcePtr.add(0xb0)),
        body,
        source_ptr: safe(sourcePtr),
        owner_ptr: safe(pairPtr.add(Process.pointerSize).readPointer()),
      });
    } catch (e) {
      send({ kind: 'error', where: 'build_enter', error: String(e) });
    }
  },
  onLeave(_) {
    activeThread = 0;
    seenFirst = false;
  }
});

Interceptor.attach(mod.base.add(0x15ebec0), {
  onEnter(args) {
    try {
      const tid = Process.getCurrentThreadId();
      if (!activeThread || tid !== activeThread || seenFirst) return;
      seenFirst = true;
      const keyPtr = args[1];
      const q0 = keyPtr.isNull() ? ptr('0x0') : keyPtr.readPointer();
      send({
        kind: 'first_ebec0',
        thread_id: tid,
        r8: safe(args[2]),
        r9: safe(args[3]),
        key_ptr: safe(keyPtr),
        key_bytes_40: dumpBytesHex(keyPtr, 0x40),
        q0_ptr: safe(q0),
        q0_bytes_50: q0.isNull() ? null : dumpBytesHex(q0, 0x50),
      });
    } catch (e) {
      send({ kind: 'error', where: 'first_ebec0', error: String(e) });
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

    if not user32.EnumWindows(callback, 0):
        raise OSError(ctypes.get_last_error())
    for item in results:
        if item["title"] == "WeChat":
            return item
    if results:
        return results[0]
    raise RuntimeError("No visible WeChat window found")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int)
    parser.add_argument("--body", required=True)
    parser.add_argument("--wait-ms", type=int, default=30000)
    args = parser.parse_args()

    window = find_weixin_main_window()
    pid = args.pid or window["pid"]

    device = frida.get_local_device()
    session = device.attach(pid)
    rendered = SCRIPT.replace("{{TARGET_BODY_JSON}}", json.dumps(args.body))
    script = session.create_script(rendered)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    print(json.dumps({"kind": "host_meta", "pid": pid, "title": window["title"], "body": args.body}, ensure_ascii=False), flush=True)
    time.sleep(args.wait_ms / 1000.0)


if __name__ == "__main__":
    main()
