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

function extractMessage(msgObj, selfUsername) {
  const s18 = readStdString(msgObj.add(0x18));
  const s38 = readStdString(msgObj.add(0x38));
  const s58 = readStdString(msgObj.add(0x58));
  const msgsource = readStdString(msgObj.add(0x140));
  const content = readStdString(msgObj.add(0x180));
  const ints = {
    i120: readU32(msgObj, 0x120),
    i124: readU32(msgObj, 0x124),
    i128: readU32(msgObj, 0x128),
    i138: readU32(msgObj, 0x138),
    i1c0: readU32(msgObj, 0x1c0),
    i1c4: readU32(msgObj, 0x1c4),
  };
  const kindInfo = classifyMessageKind(ints);

  let conversationId = null;
  let sender = null;
  let direction = 'unknown';

  if (kindInfo.message_kind === 'system') {
    conversationId = s18;
    sender = s38;
    if (selfUsername && sender === selfUsername) {
      direction = 'sent';
    }
  } else if (s38 && s38.indexOf('@chatroom') >= 0) {
    conversationId = s38;
    sender = s58 || s18;
    if (selfUsername && sender === selfUsername) {
      direction = 'sent';
    } else if (sender) {
      direction = 'received';
    }
  } else {
    conversationId = s38 || s18;
    sender = s58 || s18;
    if (selfUsername && sender === selfUsername) {
      direction = 'sent';
    } else if (sender) {
      direction = 'received';
    }
  }

  return {
    message_ptr: msgObj.toString(),
    conversation_id: conversationId,
    sender_username: sender,
    self_username: selfUsername,
    direction,
    message_kind: kindInfo.message_kind,
    system_signature: kindInfo.system_signature,
    timestamp: ints.i124,
    content,
    msgsource,
    raw_strings: { s18, s38, s58 },
    raw_ints: ints,
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
const parseIfNeeded = mod.base.add(0x9b17c0);
const parseCore = mod.base.add(0x212a5c0);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
const seen = {};

function handleEvent(source, msgObj) {
  const event = extractMessage(msgObj, selfUsername);
  if (!event.conversation_id && !event.content) return;
  const key = eventKey(event);
  if (seen[key]) return;
  seen[key] = true;

  if (Date.now() < baselineUntil) {
    send({
      kind: 'baseline_row',
      source,
      event,
    });
    return;
  }

  send({
    kind: 'live_message_event',
    source,
    event,
  });
}

send({
  kind: 'status',
  self_username: selfUsername,
  baseline_seconds: BASELINE_SECONDS,
  baseline_until_epoch_ms: baselineUntil,
  parse_if_needed: parseIfNeeded.toString(),
  parse_core: parseCore.toString(),
});

Interceptor.attach(parseIfNeeded, {
  onEnter(args) {
    this.msgObj = args[0];
  },
  onLeave(retval) {
    try {
      handleEvent('parseIfNeeded', this.msgObj);
    } catch (e) {
      send({ kind: 'error', where: 'parseIfNeeded', error: String(e) });
    }
  }
});

Interceptor.attach(parseCore, {
  onEnter(args) {
    this.msgObj = args[0];
  },
  onLeave(retval) {
    try {
      handleEvent('parseCore', this.msgObj);
    } catch (e) {
      send({ kind: 'error', where: 'parseCore', error: String(e) });
    }
  }
});

setTimeout(() => {
  send({
    kind: 'armed',
    seen_count: Object.keys(seen).length,
  });
}, BASELINE_SECONDS * 1000);

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
