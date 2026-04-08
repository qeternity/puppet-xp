#!/usr/bin/env python
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

function sniffStringAt(ptrValue) {
  try {
    const p = ptr(ptrValue);
    if (p.isNull()) return null;
    const direct = readStdString(p);
    if (direct) return { where: p.toString(), value: direct, mode: 'direct' };
    const first = p.readPointer();
    if (!first.isNull()) {
      const indirect = readStdString(first);
      if (indirect) return { where: first.toString(), value: indirect, mode: 'indirect' };
    }
  } catch (e) {}
  return null;
}

function readVec3(addr) {
  try {
    const p = ptr(addr);
    return {
      self: p.toString(),
      a: p.readPointer().toString(),
      b: p.add(Process.pointerSize).readPointer().toString(),
      c: p.add(Process.pointerSize * 2).readPointer().toString(),
    };
  } catch (e) {
    return { self: ptr(addr).toString(), error: String(e) };
  }
}

const mod = Process.getModuleByName('Weixin.dll');
const fn = mod.base.add(0x13ef9c0);
send({ kind: 'status', fn: fn.toString() });

Interceptor.attach(fn, {
  onEnter(args) {
    this.args = [];
    for (let i = 0; i < 7; i++) this.args.push(args[i]);
    const strings = {};
    for (let i = 0; i < 7; i++) {
      const s = sniffStringAt(args[i]);
      if (s) strings['arg' + i] = s;
    }
    send({
      kind: 'shared_enter',
      tid: Process.getCurrentThreadId(),
      args: this.args.map(a => a.toString()),
      strings,
      arg1Vec: readVec3(args[1]),
      arg4Vec: readVec3(args[4]),
      arg5Vec: readVec3(args[5]),
      arg6Vec: readVec3(args[6]),
    });
  },
  onLeave(retval) {
    send({
      kind: 'shared_leave',
      tid: Process.getCurrentThreadId(),
      retval: retval.toString(),
      arg1Vec: readVec3(this.args[1]),
      arg4Vec: readVec3(this.args[4]),
      arg5Vec: readVec3(this.args[5]),
      arg6Vec: readVec3(this.args[6]),
    });
  }
});

setInterval(() => send({ kind: 'heartbeat' }), 30000);
"""


def main() -> None:
    device = frida.get_local_device()
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
