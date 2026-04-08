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

function dumpQwords(base, count) {
  const out = [];
  for (let i = 0; i < count; i++) {
    try {
      const off = i * Process.pointerSize;
      out.push({
        off: '0x' + off.toString(16),
        ptr: base.add(off).readPointer().toString(),
      });
    } catch (e) {
      out.push({
        off: '0x' + (i * Process.pointerSize).toString(16),
        error: String(e),
      });
    }
  }
  return out;
}

function describeBuilderObj(obj) {
  const out = { self: obj.toString() };
  try { out.talker = readStdString(obj.add(0x88)); } catch (e) {}
  try { out.flags38 = obj.add(0x38).readU32(); } catch (e) {}
  try { out.count60 = obj.add(0x60).readU32(); } catch (e) {}
  try { out.mode68 = obj.add(0x68).readU32(); } catch (e) {}
  try { out.slot40 = readStdString(obj.add(0x40)); } catch (e) {}
  try { out.sharedC0 = obj.add(0xc0).readPointer().toString(); } catch (e) {}
  try { out.region70 = dumpQwords(obj.add(0x70), 6); } catch (e) {}
  return out;
}

function describeArgs(args) {
  const out = {};
  try { out.param1 = args[0].toString(); } catch (e) {}
  try { out.param2 = args[1].toString(); } catch (e) {}
  try {
    out.param3 = args[2].toString();
    out.talker = readStdString(args[2]);
  } catch (e) {}
  try { out.param4 = args[3].toInt32(); } catch (e) {}
  try { out.param5 = args[4].toUInt32(); } catch (e) {}
  try {
    out.param6 = args[5].toString();
    out.param6_qwords = dumpQwords(args[5], 6);
  } catch (e) {}
  try {
    out.param7 = args[6].toString();
    out.param7_string = readStdString(args[6]);
  } catch (e) {}
  try { out.param8 = args[7].toString(); } catch (e) {}
  try { out.param9 = args[8].toString(); } catch (e) {}
  return out;
}

function backtrace(context) {
  return Thread.backtrace(context, Backtracer.ACCURATE).map(addr => {
    const modInfo = Process.findModuleByAddress(addr);
    return {
      address: addr.toString(),
      module: modInfo ? modInfo.name : null,
      relative: modInfo ? ptr(addr).sub(modInfo.base).toString() : null,
    };
  });
}

const mod = Process.getModuleByName('Weixin.dll');
const fnRequestOwner = mod.base.add(0x33c5b00);
const fnRequestBuilder = mod.base.add(0x13b1b40);
send({
  kind: 'status',
  fnRequestOwner: fnRequestOwner.toString(),
  fnRequestBuilder: fnRequestBuilder.toString(),
  moduleBase: mod.base.toString(),
});

Interceptor.attach(fnRequestOwner, {
  onEnter(args) {
    try {
      this.obj = args[0];
      send({
        kind: 'request_owner_enter',
        obj: describeBuilderObj(args[0]),
        backtrace: backtrace(this.context),
      });
    } catch (e) {
      send({ kind: 'request_owner_enter_error', error: String(e) });
    }
  },
  onLeave(retval) {
    try {
      send({
        kind: 'request_owner_leave',
        obj: this.obj ? this.obj.toString() : null,
        retval: retval.toString(),
      });
    } catch (e) {
      send({ kind: 'request_owner_leave_error', error: String(e) });
    }
  }
});

Interceptor.attach(fnRequestBuilder, {
  onEnter(args) {
    try {
      send({
        kind: 'request_builder_enter',
        args: describeArgs(args),
        backtrace: backtrace(this.context),
      });
    } catch (e) {
      send({ kind: 'request_builder_enter_error', error: String(e) });
    }
  },
  onLeave(retval) {
    try {
      send({
        kind: 'request_builder_leave',
        retval: retval.toString(),
      });
    } catch (e) {
      send({ kind: 'request_builder_leave_error', error: String(e) });
    }
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
