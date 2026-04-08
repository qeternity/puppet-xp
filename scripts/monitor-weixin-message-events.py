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

function extractRow(row, selfUsername) {
  const s18 = readStdString(row.add(0x18));
  const s38 = readStdString(row.add(0x38));
  const s58 = readStdString(row.add(0x58));
  const msgSource = readStdString(row.add(0x140));
  const content = readStdString(row.add(0x180));
  const ints = {
    i120: readU32(row, 0x120),
    i124: readU32(row, 0x124),
    i128: readU32(row, 0x128),
    i138: readU32(row, 0x138),
    i1c0: readU32(row, 0x1c0),
    i1c4: readU32(row, 0x1c4),
  };
  const kindInfo = classifyMessageKind(ints);

  let conversationId = null;
  let sender = null;
  let direction = 'unknown';

  if (kindInfo.message_kind === 'system') {
    conversationId = s18;
    sender = s38;
    if (selfUsername && sender === selfUsername) direction = 'sent';
  } else {
    const looksChatroom = s38 && s38.indexOf('@chatroom') >= 0;
    if (looksChatroom) {
      conversationId = s38;
      sender = s58 || s18;
    } else {
      conversationId = s38 || s18;
      sender = s58 || s18;
    }
    if (selfUsername && sender === selfUsername) {
      direction = 'sent';
    } else if (sender) {
      direction = 'received';
    }
  }

  return {
    conversation_id: conversationId,
    sender_username: sender,
    self_username: selfUsername,
    direction,
    message_kind: kindInfo.message_kind,
    system_signature: kindInfo.system_signature,
    timestamp: ints.i124,
    content,
    msgsource: msgSource,
    raw_strings: {
      s18,
      s38,
      s58,
    },
    raw_ints: ints,
  };
}

function readVectorRows(vecPtr, selfUsername, maxRows) {
  const rows = [];
  try {
    const begin = vecPtr.readPointer();
    const end = vecPtr.add(Process.pointerSize).readPointer();
    if (begin.isNull() || end.isNull() || end.compare(begin) < 0) return rows;
    const rowSize = 0x290;
    const totalBytes = parseInt(end.sub(begin).toString(), 16);
    const count = Math.min(Math.floor(totalBytes / rowSize), maxRows);
    for (let i = 0; i < count; i++) {
      rows.push(extractRow(begin.add(i * rowSize), selfUsername));
    }
  } catch (e) {}
  return rows;
}

const mod = Process.getModuleByName('Weixin.dll');
const selfUsername = getSelfUsername(mod);
const iteratorFn = mod.base.add(0x13ff7c0);
const sessionLastMapFn = mod.base.add(0x13e9460);
const seen = {};

function rowKey(row) {
  return [
    row.conversation_id || '',
    row.sender_username || '',
    String(row.timestamp || 0),
    row.content || '',
    row.message_kind || '',
  ].join('|');
}

function maybeEmitRows(source, rows) {
  for (const row of rows) {
    const content = row.content || '';
    const conv = row.conversation_id || '';
    if (!content && row.message_kind !== 'system') continue;
    if (!conv) continue;
    const key = rowKey(row);
    if (seen[key]) continue;
    seen[key] = true;
    send({
      kind: 'message_event',
      source,
      event: row,
    });
  }
}

send({
  kind: 'status',
  self_username: selfUsername,
  iterator_fn: iteratorFn.toString(),
  session_last_map_fn: sessionLastMapFn.toString(),
});

Interceptor.attach(iteratorFn, {
  onEnter(args) {
    this.queryObj = args[0];
  },
  onLeave(retval) {
    try {
      const outVecPtr = this.queryObj.add(0x38).readPointer();
      const rows = readVectorRows(outVecPtr, selfUsername, 100);
      maybeEmitRows('iterator', rows);
    } catch (e) {
      send({ kind: 'error', where: 'iterator', error: String(e) });
    }
  }
});

Interceptor.attach(sessionLastMapFn, {
  onEnter(args) {
    try {
      send({
        kind: 'session_last_message_map_trigger',
        arg0: args[0].toString(),
        arg1: args[1].toString(),
      });
    } catch (e) {}
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
