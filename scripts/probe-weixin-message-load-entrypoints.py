#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT = r"""
function readStdString(addr) {
  try {
    const len = addr.add(0x10).readU32();
    const cap = addr.add(0x18).readU32();
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

function sniffConversation(obj) {
  const out = { self: obj.toString() };
  try {
    out.cc = obj.add(0xcc).readU32();
  } catch (e) {}
  try {
    const p18 = obj.add(0x18).readPointer();
    out.p18 = p18.toString();
    if (!p18.isNull()) {
      out.p18_50 = readStdString(p18.add(0x50));
    }
  } catch (e) {}
  try {
    const p20 = obj.add(0x20).readPointer();
    out.p20 = p20.toString();
  } catch (e) {}
  try {
    const p50 = obj.add(0x50).readPointer();
    out.p50 = p50.toString();
  } catch (e) {}
  try {
    const p60 = obj.add(0x60).readPointer();
    out.p60 = p60.toString();
  } catch (e) {}
  try {
    const p78 = obj.add(0x78).readPointer();
    out.p78 = p78.toString();
  } catch (e) {}
  return out;
}

function bt() {
  return Thread.backtrace(this.context, Backtracer.ACCURATE).map(addr => {
    const modInfo = Process.findModuleByAddress(addr);
    return {
      address: addr.toString(),
      module: modInfo ? modInfo.name : null,
      relative: modInfo ? ptr(addr).sub(modInfo.base).toString() : null,
    };
  });
}

const mod = Process.getModuleByName('Weixin.dll');
const fnA = mod.base.add(0x9c77c0);
const fnB = mod.base.add(0x9c3b20);
send({ kind: 'status', fnA: fnA.toString(), fnB: fnB.toString() });

Interceptor.attach(fnA, {
  onEnter(args) {
    send({
      kind: 'load_entry_9c77c0',
      obj: args[0].toString(),
      requestedCount: args[1].toUInt32(),
      convo: sniffConversation(args[0]),
      backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE).map(addr => {
        const modInfo = Process.findModuleByAddress(addr);
        return {
          address: addr.toString(),
          module: modInfo ? modInfo.name : null,
          relative: modInfo ? ptr(addr).sub(modInfo.base).toString() : null,
        };
      }),
    });
  }
});

Interceptor.attach(fnB, {
  onEnter(args) {
    const pair = args[1];
    let pairInfo = null;
    try {
      pairInfo = {
        ptr: pair.toString(),
        slot0: pair.readPointer().toString(),
        slot8: pair.add(Process.pointerSize).readPointer().toString(),
      };
    } catch (e) {}
    send({
      kind: 'load_entry_9c3b20',
      obj: args[0].toString(),
      convo: sniffConversation(args[0]),
      pair: pairInfo,
      backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE).map(addr => {
        const modInfo = Process.findModuleByAddress(addr);
        return {
          address: addr.toString(),
          module: modInfo ? modInfo.name : null,
          relative: modInfo ? ptr(addr).sub(modInfo.base).toString() : null,
        };
      }),
    });
  }
});

setInterval(() => send({ kind: 'heartbeat' }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="Exact Weixin.exe PID to attach to")
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
    script = session.create_script(SCRIPT)

    def on_message(message, data):
        if message["type"] == "send":
            sys.stdout.buffer.write((str(message["payload"]) + "\n").encode("utf-8", errors="replace"))
            sys.stdout.flush()
        else:
            sys.stdout.buffer.write((str(message) + "\n").encode("utf-8", errors="replace"))
            sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    sys.stdout.buffer.write((f"attached pid={pid}\n").encode("utf-8"))
    sys.stdout.flush()
    threading.Event().wait()


if __name__ == "__main__":
    main()
