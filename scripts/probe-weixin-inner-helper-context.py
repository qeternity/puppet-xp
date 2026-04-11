#!/usr/bin/env python
import argparse
import json
import sys
import threading

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
  return {
    text: readStdString(addr),
    len: readU32(addr, 0x10),
    cap: readU32(addr, 0x18),
    ptr: safe(addr.readPointer()),
  };
}

function dumpQwords(base, size) {
  const out = {};
  for (let off = 0; off < size; off += 8) {
    try {
      out['0x' + off.toString(16)] = safe(base.add(off).readPointer());
    } catch (_) {
      out['0x' + off.toString(16)] = null;
    }
  }
  return out;
}

function bytesToHex(arrbuf) {
  try {
    const bytes = new Uint8Array(arrbuf);
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i].toString(16);
      out += b.length === 1 ? ('0' + b) : b;
    }
    return out;
  } catch (_) {
    return null;
  }
}

function dumpBytes(base, size) {
  try {
    if (!base || base.isNull()) return null;
    return bytesToHex(base.readByteArray(size));
  } catch (_) {
    return null;
  }
}

function readPtr(base) {
  try {
    if (!base || base.isNull()) return ptr('0x0');
    return base.readPointer();
  } catch (_) {
    return ptr('0x0');
  }
}

function shouldCapture(conversation, body) {
  if (conversation !== TARGET_CONVERSATION) return false;
  if (!body) return false;
  if (FILTER_BODIES.length === 0) return true;
  return FILTER_BODIES.indexOf(body) >= 0;
}

let current = null;
let nextId = 1;

Interceptor.attach(mod.base.add(0x15e8200), {
  onEnter(args) {
    try {
      const sourcePtr = args[2].readPointer();
      const ownerPtr = args[2].add(Process.pointerSize).readPointer();
      const conversation = readStdString(sourcePtr.add(0xb0));
      const body = readStdString(sourcePtr.add(0x660));
      if (!shouldCapture(conversation, body)) return;
      const id = nextId++;
      current = {
        id,
        thread_id: Process.getCurrentThreadId(),
        source_ptr: safe(sourcePtr),
        owner_ptr: safe(ownerPtr),
        send_ctx: safe(args[0]),
        result_buf: safe(args[1]),
        pair_ptr: safe(args[2]),
        mode: args[3].toUInt32(),
        conversation,
        body,
        uuid: readStdString(sourcePtr.add(0x600)),
      };
      send({ kind: 'builder_enter', call: current });
    } catch (e) {
      send({ kind: 'error', where: 'builder_enter', error: String(e) });
    }
  },
  onLeave(retval) {
    if (!current) return;
    send({
      kind: 'builder_leave',
      call: current,
      retval: safe(retval),
      result_post_qwords: dumpQwords(ptr(current.result_buf), 0x40),
    });
    current = null;
  }
});

function helperHook(name, rva) {
  Interceptor.attach(mod.base.add(rva), {
    onEnter(args) {
      if (!current) return;
      if (Process.getCurrentThreadId() !== current.thread_id) return;
      send({
        kind: name + '_enter',
        call: current,
        q0_ptr: safe(readPtr(args[1])),
        args: {
          rcx: safe(args[0]),
          rdx: safe(args[1]),
          r8: safe(args[2]),
          r9: safe(args[3]),
        },
        rcx_qwords: args[0] && !args[0].isNull() ? dumpQwords(args[0], 0x40) : null,
        rdx_qwords: args[1] && !args[1].isNull() ? dumpQwords(args[1], 0x40) : null,
        rdx_bytes_40: args[1] && !args[1].isNull() ? dumpBytes(args[1], 0x40) : null,
        rdx_q0_qwords: args[1] && !args[1].isNull() ? dumpQwords(readPtr(args[1]), 0x50) : null,
        rdx_q0_bytes_50: args[1] && !args[1].isNull() ? dumpBytes(readPtr(args[1]), 0x50) : null,
      });
    },
    onLeave(retval) {
      if (!current) return;
      if (Process.getCurrentThreadId() !== current.thread_id) return;
      send({
        kind: name + '_leave',
        call: current,
        retval: safe(retval),
      });
    }
  });
}

helperHook('eb320', 0x15eb320);
helperHook('ebec0', 0x15ebec0);

send({
  kind: 'host_meta',
  pid: Process.id,
  conversation: TARGET_CONVERSATION,
  bodies: FILTER_BODIES,
});
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("conversation", nargs="?", default="27208021116@chatroom")
    parser.add_argument("bodies", nargs="*")
    parser.add_argument("--pid", type=int, required=True)
    args = parser.parse_args()

    device = frida.get_local_device()
    session = device.attach(args.pid)
    script_source = (
        SCRIPT
        .replace("{{TARGET_CONVERSATION_JSON}}", json.dumps(args.conversation))
        .replace("{{FILTER_BODIES_JSON}}", json.dumps(args.bodies))
    )
    script = session.create_script(script_source)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
