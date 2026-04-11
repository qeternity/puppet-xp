#!/usr/bin/env python
import ctypes
import json
import sys
import time
from ctypes import wintypes

import frida


SCRIPT = r"""
const TARGET_CONVERSATION = {{TARGET_CONVERSATION_JSON}};
const FILTER_BODIES = {{FILTER_BODIES_JSON}};

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

function readPointerAt(base, off) {
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
  } catch (_) {
    return null;
  }
}

function dumpStd(addr) {
  try {
    return {
      text: readStdString(addr),
      len: readU32(addr, 0x10),
      cap: readU32(addr, 0x18),
      ptr: readPointerAt(addr, 0x0),
    };
  } catch (_) {
    return null;
  }
}

function dumpQwords(base, size) {
  const out = {};
  for (let off = 0; off < size; off += 8) {
    out['0x' + off.toString(16)] = readPointerAt(base, off);
  }
  return out;
}

function dumpRegs(ctx) {
  const names = ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15','rip'];
  const out = {};
  names.forEach((name) => {
    try { out[name] = safe(ctx[name]); } catch (_) {}
  });
  return out;
}

function shouldCapture(conversation, body) {
  if (!conversation || !body) return false;
  if (TARGET_CONVERSATION && conversation !== TARGET_CONVERSATION) return false;
  if (!FILTER_BODIES || FILTER_BODIES.length === 0) return true;
  return FILTER_BODIES.indexOf(body) >= 0;
}

let seq = 0;
let active = {};

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
      if (!shouldCapture(conversation, body)) return;

      const id = ++seq;
      this.__id = id;
      active[id] = {
        id,
        thread_id: Process.getCurrentThreadId(),
        caller_rva: safe(this.returnAddress.sub(mod.base)),
        return_address: safe(this.returnAddress),
        mode: args[3].toUInt32(),
        send_ctx: safe(args[0]),
        result_buf: safe(args[1]),
        pair_ptr: safe(pairPtr),
        source_ptr: safe(sourcePtr),
        owner_ptr: safe(ownerPtr),
        conversation,
        body,
        uuid: readStdString(sourcePtr.add(0x600)),
        source_fields: {
          f9c: readU32(sourcePtr, 0x9c),
          fd8: readU32(sourcePtr, 0xd8),
          b0: dumpStd(sourcePtr.add(0xb0)),
          600: dumpStd(sourcePtr.add(0x600)),
          660: dumpStd(sourcePtr.add(0x660)),
          680: dumpStd(sourcePtr.add(0x680)),
        },
        owner_qwords: dumpQwords(ownerPtr, 0x60),
        result_pre_qwords: dumpQwords(args[1], 0x40),
        regs: dumpRegs(this.context),
        stack_qwords: dumpQwords(this.context.rsp, 0x80),
      };
      send({ kind: 'builder_context_enter', call: active[id] });
    } catch (e) {
      send({ kind: 'error', where: 'builder_context_enter', error: String(e) });
    }
  },
  onLeave(retval) {
    try {
      const id = this.__id;
      if (!id || !active[id]) return;
      const record = active[id];
      record.retval = safe(retval);
      try {
        record.result_post_qwords = dumpQwords(ptr(record.result_buf), 0x40);
      } catch (_) {}
      send({ kind: 'builder_context_leave', call: record });
      delete active[id];
    } catch (e) {
      send({ kind: 'error', where: 'builder_context_leave', error: String(e) });
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
    conversation = sys.argv[1] if len(sys.argv) > 1 else "27208021116@chatroom"
    bodies = sys.argv[2:] if len(sys.argv) > 2 else []
    window = find_weixin_main_window()
    device = frida.get_local_device()
    session = device.attach(window["pid"])
    script_source = (
        SCRIPT
        .replace("{{TARGET_CONVERSATION_JSON}}", json.dumps(conversation))
        .replace("{{FILTER_BODIES_JSON}}", json.dumps(bodies))
    )
    script = session.create_script(script_source)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    print(json.dumps({"kind": "host_meta", "pid": window["pid"], "thread_id": window["thread_id"], "title": window["title"], "conversation": conversation, "bodies": bodies}, ensure_ascii=False), flush=True)
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
