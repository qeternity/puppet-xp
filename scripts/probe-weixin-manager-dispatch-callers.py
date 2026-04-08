#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT = r"""
const BASELINE_SECONDS = {{BASELINE_SECONDS}};

function readStdString(addr) {
  try {
    const len = addr.add(0x10).readU32();
    const cap = addr.add(0x18).readU32();
    if (len === 0) return '';
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

function readU32(base, off) {
  try {
    return base.add(off).readU32();
  } catch (e) {
    return null;
  }
}

function safePtrString(p) {
  try {
    if (p === null || p.isNull()) return '0x0';
    return p.toString();
  } catch (e) {
    return '0x0';
  }
}

function getSelfUsername(mod) {
  try {
    const getSnapshotMgr = new NativeFunction(mod.base.add(0x1f540), 'pointer', []);
    const buildSnapshot = new NativeFunction(mod.base.add(0x20aa0), 'pointer', ['pointer', 'pointer', 'uchar']);
    const snapshotMgr = getSnapshotMgr();
    const snapshotBuf = Memory.alloc(0x200);
    snapshotBuf.writeByteArray(new Uint8Array(0x200));
    buildSnapshot(snapshotMgr, snapshotBuf, 1);
    return readStdString(snapshotBuf.add(0x0));
  } catch (e) {
    return null;
  }
}

function extractCompactDispatchEvent(objPtr, selfUsername) {
  const conversationId = readStdString(objPtr.add(0x0));
  const content = readStdString(objPtr.add(0x48));
  const sender = readStdString(objPtr.add(0xa8));
  const title = readStdString(objPtr.add(0x160));
  let direction = 'unknown';
  if (selfUsername && sender === selfUsername) direction = 'sent';
  else if (sender) direction = 'received';

  return {
    conversation_id: conversationId,
    title,
    sender_username: sender,
    direction,
    timestamp_candidate: readU32(objPtr, 0x90),
    content,
  };
}

function eventKey(event) {
  return [
    event.conversation_id || '',
    event.sender_username || '',
    event.content || '',
  ].join('|');
}

const mod = Process.getModuleByName('Weixin.dll');
const selfUsername = getSelfUsername(mod);
const dispatchCb = mod.base.add(0x154bb80);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
const seen = {};

function frameInfo(addr) {
  try {
    const symbol = DebugSymbol.fromAddress(addr);
    let rel = null;
    try {
      rel = ptr(addr).sub(mod.base).toString();
    } catch (e) {
    }
    return {
      address: safePtrString(addr),
      relative: rel,
      name: symbol && symbol.name ? symbol.name : null,
      module: symbol && symbol.moduleName ? symbol.moduleName : null,
    };
  } catch (e) {
    return {
      address: safePtrString(addr),
      relative: null,
      name: null,
      module: null,
    };
  }
}

send({
  kind: 'status',
  self_username: selfUsername,
  baseline_seconds: BASELINE_SECONDS,
  dispatch_callback: dispatchCb.toString(),
});

Interceptor.attach(dispatchCb, {
  onEnter(args) {
    try {
      const event = extractCompactDispatchEvent(args[1], selfUsername);
      if (!event.conversation_id && !event.content) return;
      const key = eventKey(event);
      if (Date.now() < baselineUntil) {
        seen[key] = true;
        return;
      }
      if (seen[key]) return;
      seen[key] = true;
      const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .slice(0, 8)
        .map(frameInfo);
      send({
        kind: 'manager_dispatch_caller',
        event,
        flag: args[3].toInt32(),
        return_address: frameInfo(this.returnAddress),
        backtrace,
      });
    } catch (e) {
      send({ kind: 'error', where: 'dispatchCb', error: String(e) });
    }
  }
});

setTimeout(() => send({ kind: 'armed', seen_count: Object.keys(seen).length }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat', seen_count: Object.keys(seen).length }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="Exact Weixin.exe PID to attach to")
    parser.add_argument("--baseline-seconds", type=int, default=3)
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
    rendered = SCRIPT.replace("{{BASELINE_SECONDS}}", str(args.baseline_seconds))
    script = session.create_script(rendered)

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
