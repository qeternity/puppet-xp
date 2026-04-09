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

function isConversationId(s) {
  if (!s) return false;
  return s.indexOf('@chatroom') >= 0 || s.indexOf('wxid_') === 0 || s === 'filehelper' || s === 'weixin';
}

function looksLikeMsgsource(s) {
  return !!s && s.indexOf('<msgsource') === 0;
}

function plausibleBody(s) {
  if (!s) return false;
  if (s.length < 1 || s.length > 4096) return false;
  if (looksLikeMsgsource(s)) return false;
  if (isConversationId(s)) return false;
  return /^[\x20-\x7e\u00a0-\uffff\r\n\t]+$/.test(s);
}

function parseSendTask(taskPtr, selfUsername) {
  const sender38 = readStdString(taskPtr.add(0x38));
  const convo58 = readStdString(taskPtr.add(0x58));
  const sender78 = readStdString(taskPtr.add(0x78));
  const convo98 = readStdString(taskPtr.add(0x98));
  const bodyE0 = readStdString(taskPtr.add(0xe0));
  const msgsource100 = readStdString(taskPtr.add(0x100));

  const nestedSender10 = readStdString(taskPtr.add(0x28).add(0x10));
  const nestedConvo30 = readStdString(taskPtr.add(0x28).add(0x30));
  const nestedSender50 = readStdString(taskPtr.add(0x28).add(0x50));
  const nestedConvo70 = readStdString(taskPtr.add(0x28).add(0x70));

  const nestedBody0 = readStdString(taskPtr.add(0x110).add(0x0));
  const nestedBody20 = readStdString(taskPtr.add(0x110).add(0x20));

  const conversationId = isConversationId(convo58) ? convo58 :
    (isConversationId(convo98) ? convo98 :
      (isConversationId(nestedConvo30) ? nestedConvo30 :
        (isConversationId(nestedConvo70) ? nestedConvo70 : null)));

  const senderUsername = sender38 || sender78 || nestedSender10 || nestedSender50 || null;
  const msgsource = looksLikeMsgsource(msgsource100) ? msgsource100 : null;
  const body = plausibleBody(bodyE0) ? bodyE0 :
    (plausibleBody(nestedBody0) ? nestedBody0 :
      (plausibleBody(nestedBody20) ? nestedBody20 : null));

  if (!conversationId || !senderUsername || !body) {
    return null;
  }

  let direction = 'unknown';
  if (selfUsername && senderUsername === selfUsername) direction = 'sent';
  else direction = 'received';

  return {
    task_ptr: safePtrString(taskPtr),
    conversation_id: conversationId,
    sender_username: senderUsername,
    self_username: selfUsername,
    direction,
    content: body,
    msgsource,
    raw_strings: {
      sender38,
      convo58,
      sender78,
      convo98,
      bodyE0,
      msgsource100,
      nestedSender10,
      nestedConvo30,
      nestedSender50,
      nestedConvo70,
      nestedBody0,
      nestedBody20,
    },
    raw_ints: {
      i8: readU32(taskPtr, 0x8),
      i10: readU32(taskPtr, 0x10),
      i18: readU32(taskPtr, 0x18),
      i20: readU32(taskPtr, 0x20),
      i28: readU32(taskPtr, 0x28),
      i30: readU32(taskPtr, 0x30),
      i108: readU32(taskPtr, 0x108),
      i110: readU32(taskPtr, 0x110),
      i118: readU32(taskPtr, 0x118),
      i120: readU32(taskPtr, 0x120),
      i128: readU32(taskPtr, 0x128),
      i130: readU32(taskPtr, 0x130),
      i138: readU32(taskPtr, 0x138),
      i140: readU32(taskPtr, 0x140),
      i148: readU32(taskPtr, 0x148),
      i150: readU32(taskPtr, 0x150),
    },
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
const scheduleFn = mod.base.add(0x314950);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
const seen = {};

send({
  kind: 'status',
  self_username: selfUsername,
  baseline_seconds: BASELINE_SECONDS,
  schedule_function: scheduleFn.toString(),
});

Interceptor.attach(scheduleFn, {
  onEnter(args) {
    try {
      const taskHolder = args[1];
      const taskPtr = taskHolder.readPointer();
      if (taskPtr.isNull()) return;
      const event = parseSendTask(taskPtr, selfUsername);
      if (!event) return;
      const key = eventKey(event);
      if (seen[key]) return;
      seen[key] = true;
      if (Date.now() < baselineUntil) return;
      send({
        kind: 'send_task_event',
        event,
      });
    } catch (e) {
      send({ kind: 'error', where: 'scheduleFn', error: String(e) });
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
            sys.stdout.buffer.write((str(message["payload"] if "payload" in message else message) + "\n").encode("utf-8", errors="replace"))
            sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    sys.stdout.buffer.write((f"attached pid={pid}\n").encode("utf-8"))
    sys.stdout.flush()
    threading.Event().wait()


if __name__ == "__main__":
    main()
