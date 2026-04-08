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

function classifyMessageKind(ints) {
  const systemSignature =
    ints.i120 === 4 &&
    ints.i128 === 4 &&
    ints.i138 === 2 &&
    ints.i1c0 === 2 &&
    ints.i1c4 === 1;
  if (systemSignature) {
    return {
      message_kind: 'system',
      system_signature: '4/4/2/2/1',
    };
  }
  return {
    message_kind: 'user',
    system_signature: null,
  };
}

function extractRow(rowPtr, selfUsername) {
  const s18 = readStdString(rowPtr.add(0x18));
  const s38 = readStdString(rowPtr.add(0x38));
  const s58 = readStdString(rowPtr.add(0x58));
  const msgsource = readStdString(rowPtr.add(0x140));
  const content = readStdString(rowPtr.add(0x180));
  const ints = {
    i120: readU32(rowPtr, 0x120),
    i124: readU32(rowPtr, 0x124),
    i128: readU32(rowPtr, 0x128),
    i138: readU32(rowPtr, 0x138),
    i1c0: readU32(rowPtr, 0x1c0),
    i1c4: readU32(rowPtr, 0x1c4),
  };
  const kindInfo = classifyMessageKind(ints);

  let conversationId = null;
  let sender = null;
  let direction = 'unknown';

  if (kindInfo.message_kind === 'system') {
    conversationId = s18;
    sender = s38;
    if (selfUsername && sender === selfUsername) direction = 'sent';
  } else if (s38 && s38.indexOf('@chatroom') >= 0) {
    conversationId = s38;
    sender = s58 || s18;
    if (selfUsername && sender === selfUsername) direction = 'sent';
    else if (sender) direction = 'received';
  } else {
    conversationId = s38 || s18;
    sender = s58 || s18;
    if (selfUsername && sender === selfUsername) direction = 'sent';
    else if (sender) direction = 'received';
  }

  return {
    row_ptr: rowPtr.toString(),
    conversation_id: conversationId,
    sender_username: sender,
    self_username: selfUsername,
    direction,
    message_kind: kindInfo.message_kind,
    system_signature: kindInfo.system_signature,
    timestamp: ints.i124,
    content,
    msgsource,
  };
}

function eventKey(event) {
  return [
    event.conversation_id || '',
    event.sender_username || '',
    String(event.timestamp || 0),
    event.content || '',
    event.message_kind || '',
  ].join('|');
}

const mod = Process.getModuleByName('Weixin.dll');
const selfUsername = getSelfUsername(mod);
const rowTransform = mod.base.add(0x1419100);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
const seen = {};

send({
  kind: 'status',
  self_username: selfUsername,
  baseline_seconds: BASELINE_SECONDS,
  row_transform: rowTransform.toString(),
});

Interceptor.attach(rowTransform, {
  onEnter(args) {
    this.rowPtr = args[1];
  },
  onLeave(retval) {
    try {
      const event = extractRow(this.rowPtr, selfUsername);
      if (!event.conversation_id && !event.content) return;
      const key = eventKey(event);
      if (seen[key]) return;
      seen[key] = true;
      if (Date.now() < baselineUntil) {
        send({ kind: 'baseline_row', event });
        return;
      }
      send({ kind: 'row_transform_event', event });
    } catch (e) {
      send({ kind: 'error', where: 'rowTransform', error: String(e) });
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
