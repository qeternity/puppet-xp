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

function readU64(base, off) {
  try {
    return base.add(off).readU64().toString();
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

function extractCompactDispatchEvent(objPtr, selfUsername) {
  const conversationId = readStdString(objPtr.add(0x0));
  const content = readStdString(objPtr.add(0x48));
  const sender = readStdString(objPtr.add(0xa8));
  const avatarUrl = readStdString(objPtr.add(0x140));
  const title = readStdString(objPtr.add(0x160));
  let direction = 'unknown';
  if (selfUsername && sender === selfUsername) direction = 'sent';
  else if (sender) direction = 'received';

  const ints = {
    i30: readU32(objPtr, 0x30),
    i40: readU32(objPtr, 0x40),
    i78: readU32(objPtr, 0x78),
    i88: readU32(objPtr, 0x88),
    i90: readU32(objPtr, 0x90),
    i98: readU32(objPtr, 0x98),
    i100: readU32(objPtr, 0x100),
    i110: readU32(objPtr, 0x110),
    i120: readU32(objPtr, 0x120),
    i130: readU32(objPtr, 0x130),
    i138: readU32(objPtr, 0x138),
    i1d0: readU32(objPtr, 0x1d0),
    i1d8: readU32(objPtr, 0x1d8),
    i1e0: readU32(objPtr, 0x1e0),
    i1e8: readU32(objPtr, 0x1e8),
  };
  const wide = {
    q1d0: readU64(objPtr, 0x1d0),
    q1d8: readU64(objPtr, 0x1d8),
    q1e0: readU64(objPtr, 0x1e0),
    q1e8: readU64(objPtr, 0x1e8),
  };

  return {
    event_ptr: objPtr.toString(),
    conversation_id: conversationId,
    title,
    sender_username: sender,
    self_username: selfUsername,
    direction,
    content,
    avatar_url: avatarUrl,
    raw_ints: ints,
    raw_u64: wide,
  };
}

function extractMessageLike(objPtr, selfUsername) {
  const s18 = readStdString(objPtr.add(0x18));
  const s38 = readStdString(objPtr.add(0x38));
  const s58 = readStdString(objPtr.add(0x58));
  const msgsource = readStdString(objPtr.add(0x140));
  const content = readStdString(objPtr.add(0x180));
  const ints = {
    i120: readU32(objPtr, 0x120),
    i124: readU32(objPtr, 0x124),
    i128: readU32(objPtr, 0x128),
    i138: readU32(objPtr, 0x138),
    i1c0: readU32(objPtr, 0x1c0),
    i1c4: readU32(objPtr, 0x1c4),
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
    message_ptr: objPtr.toString(),
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

function isInterestingString(s) {
  if (!s) return false;
  if (s.length < 2 || s.length > 512) return false;
  if (s.indexOf('wxid_') >= 0) return true;
  if (s.indexOf('@chatroom') >= 0) return true;
  if (s.indexOf('<msgsource') >= 0) return true;
  if (s === 'filehelper' || s === 'weixin') return true;
  if (/^[\x20-\x7e\u00a0-\uffff]+$/.test(s)) return true;
  return false;
}

function scanStdStrings(base, sizeBytes) {
  const out = [];
  const seen = {};
  for (let off = 0; off <= sizeBytes; off += 0x8) {
    const s = readStdString(base.add(off));
    if (!isInterestingString(s)) continue;
    const key = off.toString(16) + '|' + s;
    if (seen[key]) continue;
    seen[key] = true;
    out.push({ offset: '0x' + off.toString(16), value: s });
    if (out.length >= 16) break;
  }
  return out;
}

function eventKey(source, event, extras) {
  const messagePart = event ? [
    event.conversation_id || '',
    event.sender_username || '',
    String(event.timestamp || 0),
    event.content || '',
    event.message_kind || '',
  ].join('|') : '';
  const extraPart = extras ? JSON.stringify(extras) : '';
  return [source, messagePart, extraPart].join('|');
}

function dispatchDedupKey(event) {
  return [
    event.conversation_id || '',
    event.sender_username || '',
    event.content || '',
  ].join('|');
}

const mod = Process.getModuleByName('Weixin.dll');
const selfUsername = getSelfUsername(mod);
const batchCb = mod.base.add(0x154fb60);
const singleCb = mod.base.add(0x154c6e0);
const dispatchCb = mod.base.add(0x154bb80);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
const seen = {};
const recentDispatch = {};

function emit(source, event, extras) {
  const key = eventKey(source, event, extras);
  if (seen[key]) return;
  seen[key] = true;

  if (Date.now() < baselineUntil) {
    return;
  }

  send({
    kind: 'manager_message_event',
    source,
    event,
    extras,
  });
}

send({
  kind: 'status',
  self_username: selfUsername,
  baseline_seconds: BASELINE_SECONDS,
  batch_callback: batchCb.toString(),
  single_callback: singleCb.toString(),
  dispatch_callback: dispatchCb.toString(),
});

Interceptor.attach(batchCb, {
  onEnter(args) {
    try {
      const rangePtr = args[2];
      const begin = rangePtr.readPointer();
      const end = rangePtr.add(Process.pointerSize).readPointer();
      let count = null;
      try {
        const delta = end.sub(begin).toInt32();
        if (delta >= 0 && (delta % 0x140) === 0) {
          count = delta / 0x140;
        }
      } catch (e) {
      }
      emit('batch_callback', null, {
        param2: args[1].toInt32(),
        range_ptr: safePtrString(rangePtr),
        begin: safePtrString(begin),
        end: safePtrString(end),
        count,
      });
    } catch (e) {
      send({ kind: 'error', where: 'batchCb', error: String(e) });
    }
  }
});

Interceptor.attach(singleCb, {
  onEnter(args) {
    try {
      const itemPtr = args[1];
      const strings = scanStdStrings(itemPtr, 0x140);
      emit('single_callback', null, {
        item_ptr: safePtrString(itemPtr),
        strings,
      });
    } catch (e) {
      send({ kind: 'error', where: 'singleCb', error: String(e) });
    }
  }
});

Interceptor.attach(dispatchCb, {
  onEnter(args) {
    try {
      const msgPtr = args[1];
      const compactEvent = extractCompactDispatchEvent(msgPtr, selfUsername);
      const dedupKey = dispatchDedupKey(compactEvent);
      const now = Date.now();
      if (dedupKey !== '||') {
        const prev = recentDispatch[dedupKey];
        if (prev && (now - prev) < 1500) {
          return;
        }
        recentDispatch[dedupKey] = now;
      }
      const fallbackEvent = extractMessageLike(msgPtr, selfUsername);
      const strings = scanStdStrings(msgPtr, 0x268);
      if (
        compactEvent.conversation_id ||
        compactEvent.content ||
        compactEvent.title ||
        compactEvent.avatar_url ||
        fallbackEvent.msgsource ||
        strings.length > 0
      ) {
        emit('dispatch_callback', compactEvent, {
          msg_ptr: safePtrString(msgPtr),
          flag: args[3].toInt32(),
          fallback_event: fallbackEvent,
          strings,
        });
      }
    } catch (e) {
      send({ kind: 'error', where: 'dispatchCb', error: String(e) });
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
