#!/usr/bin/env python
import argparse
import ctypes
import json
import sys
import time
from ctypes import wintypes

import frida


SCRIPT = r"""
const mod = Process.getModuleByName('Weixin.dll');
const TARGET_BODY = {{TARGET_BODY_JSON}};

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

let activeThreads = {};
let activeCalls = {};
let seq = 0;

Interceptor.attach(mod.base.add(0x15e8200), {
  onEnter(args) {
    try {
      const pairPtr = args[2];
      if (pairPtr.isNull()) return;
      const sourcePtr = pairPtr.readPointer();
      if (sourcePtr.isNull()) return;
      const conversation = readStdString(sourcePtr.add(0xb0));
      const body = readStdString(sourcePtr.add(0x660));
      if (body !== TARGET_BODY) return;
      const tid = Process.getCurrentThreadId();
      const id = ++seq;
      activeThreads[tid] = id;
      activeCalls[id] = {
        id,
        thread_id: tid,
        conversation,
        body,
        source_ptr: safe(sourcePtr),
        pair_ptr: safe(pairPtr),
        mode: args[3].toUInt32(),
        ebec0_count: 0,
      };
      send({ kind: 'build_enter', call: activeCalls[id] });
    } catch (e) {
      send({ kind: 'error', where: 'build_enter', error: String(e) });
    }
  },
  onLeave(retval) {
    try {
      const tid = Process.getCurrentThreadId();
      const id = activeThreads[tid];
      if (!id || !activeCalls[id]) return;
      activeCalls[id].retval = safe(retval);
      send({ kind: 'build_leave', call: activeCalls[id] });
      delete activeThreads[tid];
      delete activeCalls[id];
    } catch (e) {
      send({ kind: 'error', where: 'build_leave', error: String(e) });
    }
  }
});

Interceptor.attach(mod.base.add(0x15ebec0), {
  onEnter(args) {
    try {
      const tid = Process.getCurrentThreadId();
      const id = activeThreads[tid];
      if (!id || !activeCalls[id]) return;
      const ebec0Index = activeCalls[id].ebec0_count++;
      if (ebec0Index >= 3) return;
      const keyPtr = args[1];
      const q0 = keyPtr.isNull() ? ptr('0x0') : keyPtr.readPointer();
      send({
        kind: 'ebec0_enter',
        id,
        index: ebec0Index,
        thread_id: tid,
        r8: safe(args[2]),
        r9: safe(args[3]),
        key_ptr: safe(keyPtr),
        key_qwords: {
          q0: readU64(keyPtr, 0x0),
          q8: readU64(keyPtr, 0x8),
          q10: readU64(keyPtr, 0x10),
          q18: readU64(keyPtr, 0x18),
        },
        key_bytes_40: dumpBytesHex(keyPtr, 0x40),
        q0_bytes_50: q0.isNull() ? null : dumpBytesHex(q0, 0x50),
        q0_bytes_100: q0.isNull() ? null : dumpBytesHex(q0, 0x100),
      });
    } catch (e) {
      send({ kind: 'error', where: 'ebec0_enter', error: String(e) });
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int)
    parser.add_argument("--body", required=True)
    args = parser.parse_args()

    window = find_weixin_main_window()
    target_pid = args.pid or window["pid"]
    device = frida.get_local_device()
    session = device.attach(target_pid)
    script = session.create_script(SCRIPT.replace("{{TARGET_BODY_JSON}}", json.dumps(args.body)))

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    print(json.dumps({"kind": "host_meta", "pid": target_pid, "thread_id": window["thread_id"], "title": window["title"], "body": args.body}, ensure_ascii=False), flush=True)
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
