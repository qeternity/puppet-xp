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
    text: readStdString(base.add(off)),
    len: readU32(base, off + 0x10),
    cap: readU32(base, off + 0x18),
  };
}

function dumpQwords(base, offs) {
  const out = {};
  offs.forEach((off) => {
    out['0x' + off.toString(16)] = readU64(base, off);
  });
  return out;
}

let seq = 0;
let active = {};
let innerActiveThreads = {};

Interceptor.attach(mod.base.add(0x15e8200), {
  onEnter(args) {
    try {
      const pairPtr = args[2];
      if (pairPtr.isNull()) return;
      const sourcePtr = pairPtr.readPointer();
      if (sourcePtr.isNull()) return;
      const conversation = readStdString(sourcePtr.add(0xb0));
      const body = readStdString(sourcePtr.add(0x660));
      if (!conversation || !body) return;
      const id = ++seq;
      this.__id = id;
      innerActiveThreads[Process.getCurrentThreadId()] = id;
      active[id] = {
        id,
        thread_id: Process.getCurrentThreadId(),
        caller_rva: safe(this.returnAddress.sub(mod.base)),
        result_buf: safe(args[1]),
        pair_ptr: safe(pairPtr),
        source_ptr: safe(sourcePtr),
        mode: args[3].toUInt32(),
        conversation,
        body,
      };
      send({ kind: 'build_enter', call: active[id] });
    } catch (e) {
      send({ kind: 'error', where: 'build_enter', error: String(e) });
    }
  },
  onLeave(retval) {
    try {
      const id = this.__id;
      if (!id || !active[id]) return;
      active[id].retval = safe(retval);
      send({ kind: 'build_leave', call: active[id] });
      delete innerActiveThreads[active[id].thread_id];
      delete active[id];
    } catch (e) {
      send({ kind: 'error', where: 'build_leave', error: String(e) });
    }
  }
});

Interceptor.attach(mod.base.add(0x15eb320), {
  onEnter(args) {
    try {
      send({
        kind: 'eb320_enter',
        thread_id: Process.getCurrentThreadId(),
        p1: safe(args[0]),
        map_base: safe(args[1]),
        pair_copy: safe(args[2]),
        out_ptr: safe(args[3]),
        out_pre_q0: readU64(args[3], 0x0),
        out_pre_q8: readU64(args[3], 0x8),
        out_qwords: dumpQwords(args[3], [0x0, 0x8, 0x10, 0x18, 0x20, 0x28]),
      });
    } catch (e) {
      send({ kind: 'error', where: 'eb320_enter', error: String(e) });
    }
  },
  onLeave(retval) {
    try {
      send({ kind: 'eb320_leave', thread_id: Process.getCurrentThreadId(), retval: safe(retval) });
    } catch (e) {
      send({ kind: 'error', where: 'eb320_leave', error: String(e) });
    }
  }
});

function emitInner(name, rva) {
  Interceptor.attach(mod.base.add(rva), {
    onEnter(args) {
      try {
        const tid = Process.getCurrentThreadId();
        const id = innerActiveThreads[tid];
        if (!id || !active[id]) return;
        send({
          kind: 'inner',
          id,
          thread_id: tid,
          name,
          rva: '0x' + rva.toString(16),
        });
      } catch (e) {
        send({ kind: 'error', where: 'inner_' + name, error: String(e) });
      }
    }
  });
}

[
  [0x01d1d40, 'mk_pair_copy'],
  [0x1685ad0, 'emit_builder_record'],
  [0x1636a20, 'link_builder_a'],
  [0x1632f00, 'link_builder_b'],
  [0x2102270, 'finalize_builder_branch'],
  [0x3400c20, 'msg_kind_get'],
  [0x3400c40, 'msg_flag_check'],
  [0x3400c30, 'msg_flag_set'],
  [0x3400c00, 'msg_aux_dump'],
].forEach(([rva, name]) => emitInner(name, rva));

Interceptor.attach(mod.base.add(0x15ebec0), {
  onEnter(args) {
    try {
      const keyPtr = args[1];
      const q0 = keyPtr.isNull() ? ptr('0x0') : keyPtr.readPointer();
      send({
        kind: 'ebec0_enter',
        thread_id: Process.getCurrentThreadId(),
        builder: safe(args[0]),
        key_ptr: safe(keyPtr),
        key_qwords: {
          q0: readU64(keyPtr, 0x0),
          q8: readU64(keyPtr, 0x8),
          q10: readU64(keyPtr, 0x10),
          q18: readU64(keyPtr, 0x18),
        },
        key_strings: {
          s0: dumpStd(keyPtr, 0x0),
          s20: dumpStd(keyPtr, 0x20),
        },
        key_node: q0.isNull() ? null : {
          ptr: safe(q0),
          qwords: dumpQwords(q0, [0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48]),
          s10: dumpStd(q0, 0x10),
          s30: dumpStd(q0, 0x30),
        },
        builder_state: dumpQwords(args[0].add(0xb78), [0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8, 0xc0]),
      });
    } catch (e) {
      send({ kind: 'error', where: 'ebec0_enter', error: String(e) });
    }
  },
  onLeave(retval) {
    try {
      send({ kind: 'ebec0_leave', thread_id: Process.getCurrentThreadId(), retval: safe(retval) });
    } catch (e) {
      send({ kind: 'error', where: 'ebec0_leave', error: String(e) });
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
