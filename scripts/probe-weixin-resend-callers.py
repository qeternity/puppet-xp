#!/usr/bin/env python
import argparse
import ctypes
import json
import sys
import threading
from ctypes import wintypes

import frida


SCRIPT = r"""
const TARGET_CONVERSATION = {{TARGET_CONVERSATION}};
const TARGET_BODY = {{TARGET_BODY}};
const BASELINE_SECONDS = {{BASELINE_SECONDS}};

const mod = Process.getModuleByName('Weixin.dll');
const seen = new Set();
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);

function safePtrString(p) {
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

function frameInfo(addr) {
  try {
    const symbol = DebugSymbol.fromAddress(addr);
    let rel = null;
    try {
      rel = ptr(addr).sub(mod.base).toString();
    } catch (_) {
    }
    return {
      address: safePtrString(addr),
      relative: rel,
      module: symbol && symbol.moduleName ? symbol.moduleName : null,
      name: symbol && symbol.name ? symbol.name : null,
    };
  } catch (_) {
    return {
      address: safePtrString(addr),
      relative: null,
      module: null,
      name: null,
    };
  }
}

send({
  kind: 'status',
  build_function: safePtrString(mod.base.add(0x15e8200)),
  baseline_seconds: BASELINE_SECONDS,
  target_conversation: TARGET_CONVERSATION,
  target_body: TARGET_BODY,
});

Interceptor.attach(mod.base.add(0x15e8200), {
  onEnter(args) {
    try {
      const pairPtr = args[2];
      if (!pairPtr || pairPtr.isNull()) return;
      const sourcePtr = pairPtr.readPointer();
      if (!sourcePtr || sourcePtr.isNull()) return;

      const conversation = readStdString(sourcePtr.add(0xb0));
      const body = readStdString(sourcePtr.add(0x660));
      if (conversation !== TARGET_CONVERSATION || body !== TARGET_BODY) return;

      const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .slice(0, 20)
        .map(frameInfo);
      const key = JSON.stringify(bt.map((x) => x.relative || x.address));
      if (seen.has(key)) return;
      seen.add(key);
      if (Date.now() < baselineUntil) return;

      send({
        kind: 'resend_builder_caller',
        thread_id: Process.getCurrentThreadId(),
        mode: args[3].toUInt32(),
        return_address: frameInfo(this.returnAddress),
        source_ptr: safePtrString(sourcePtr),
        pair_ptr: safePtrString(pairPtr),
        convo_len: readU32(sourcePtr, 0xb0 + 0x10),
        body_len: readU32(sourcePtr, 0x660 + 0x10),
        backtrace: bt,
      });
    } catch (e) {
      send({ kind: 'error', where: 'build_enter', error: String(e) });
    }
  }
});

setTimeout(() => send({ kind: 'armed', seen_count: seen.size }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat', seen_count: seen.size }), 30000);
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


def find_wechat_main_window_pid() -> int:
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
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_out))
        results.append({"pid": pid_out.value, "title": title})
        return True

    user32.EnumWindows(callback, 0)
    for item in results:
        if item["title"] == "WeChat":
            return item["pid"]
    raise RuntimeError("No visible WeChat window found")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="Exact Weixin.exe PID to attach to")
    parser.add_argument("--conversation", default="27208021116@chatroom")
    parser.add_argument("--body", default="skynet")
    parser.add_argument("--baseline-seconds", type=int, default=1)
    args = parser.parse_args()

    pid = args.pid if args.pid is not None else find_wechat_main_window_pid()
    rendered = (
        SCRIPT.replace("{{TARGET_CONVERSATION}}", json.dumps(args.conversation))
        .replace("{{TARGET_BODY}}", json.dumps(args.body))
        .replace("{{BASELINE_SECONDS}}", str(args.baseline_seconds))
    )

    device = frida.get_local_device()
    session = device.attach(pid)
    script = session.create_script(rendered)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    print(json.dumps({"kind": "attached", "pid": pid}, ensure_ascii=False), flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
