#!/usr/bin/env python
import argparse
import json
import sys
import time

import frida


SCRIPT = r"""
const TEMPLATE_SOURCE = ptr({{TEMPLATE_SOURCE_JSON}});
const TEMPLATE_OWNER = ptr({{TEMPLATE_OWNER_JSON}});
const TARGET_CONVERSATION = {{TARGET_CONVERSATION_JSON}};
const TARGET_BODY = {{TARGET_BODY_JSON}};
const WAIT_MS = {{WAIT_MS}};

function safePtrString(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (e) {
    return '0x0';
  }
}

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

function writeHeapStdString(addr, value, wxAlloc) {
  const utf8 = Array.from(value).map(ch => ch.charCodeAt(0));
  if (utf8.length <= 15) {
    addr.writeByteArray(new Uint8Array(16));
    for (let i = 0; i < utf8.length; i++) {
      addr.add(i).writeU8(utf8[i]);
    }
    addr.add(utf8.length).writeU8(0);
    addr.add(0x10).writeU32(utf8.length);
    addr.add(0x14).writeU32(0);
    addr.add(0x18).writeU32(15);
    addr.add(0x1c).writeU32(0);
    return;
  }
  const buf = wxAlloc(utf8.length + 1);
  for (let i = 0; i < utf8.length; i++) {
    buf.add(i).writeU8(utf8[i]);
  }
  buf.add(utf8.length).writeU8(0);
  addr.writeByteArray(new Uint8Array(16));
  addr.writePointer(buf);
  addr.add(0x10).writeU32(utf8.length);
  addr.add(0x14).writeU32(0);
  addr.add(0x18).writeU32(utf8.length);
  addr.add(0x1c).writeU32(0);
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
  const body = plausibleBody(bodyE0) ? bodyE0 :
    (plausibleBody(nestedBody0) ? nestedBody0 :
      (plausibleBody(nestedBody20) ? nestedBody20 : null));
  const msgsource = looksLikeMsgsource(msgsource100) ? msgsource100 : null;
  if (!conversationId || !senderUsername || !body) return null;

  return {
    task_ptr: safePtrString(taskPtr),
    conversation_id: conversationId,
    sender_username: senderUsername,
    direction: selfUsername && senderUsername === selfUsername ? 'sent' : 'received',
    content: body,
    msgsource,
    raw_ints: {
      i98: readU32(taskPtr, 0x98),
      i9c: readU32(taskPtr, 0x9c),
      i108: readU32(taskPtr, 0x108),
      i120: readU32(taskPtr, 0x120),
      i128: readU32(taskPtr, 0x128),
      i138: readU32(taskPtr, 0x138),
    },
  };
}

function extractCompactDispatchEvent(objPtr, selfUsername) {
  const conversationId = readStdString(objPtr.add(0x0));
  const content = readStdString(objPtr.add(0x48));
  const sender = readStdString(objPtr.add(0xa8));
  const title = readStdString(objPtr.add(0x160));
  if (!conversationId || !sender || !content) return null;
  return {
    event_ptr: safePtrString(objPtr),
    conversation_id: conversationId,
    title,
    sender_username: sender,
    direction: selfUsername && sender === selfUsername ? 'sent' : 'received',
    content,
    timestamp_candidate: readU32(objPtr, 0x90),
  };
}

function rebasePointersInOwnerBlock(originalOwner, clonedOwner, sizeBytes) {
  const end = originalOwner.add(sizeBytes);
  for (let off = 0; off < sizeBytes; off += Process.pointerSize) {
    try {
      const value = originalOwner.add(off).readPointer();
      if (value.isNull()) continue;
      if (value.compare(originalOwner) >= 0 && value.compare(end) < 0) {
        const delta = value.sub(originalOwner).toInt32();
        clonedOwner.add(off).writePointer(clonedOwner.add(delta));
      }
    } catch (e) {
    }
  }
}

const mod = Process.getModuleByName('Weixin.dll');
const selfUsername = getSelfUsername(mod);
const wxAlloc = new NativeFunction(mod.base.add(0x6309d1c), 'pointer', ['ulong']);
const getRoot = new NativeFunction(mod.base.add(0x20800), 'pointer', ['pointer']);
const getSvc = new NativeFunction(mod.base.add(0x2fbff0), 'void', ['pointer', 'pointer']);
const getSendCtx = new NativeFunction(mod.base.add(0x633270), 'pointer', ['pointer', 'pointer']);
const buildOnePairRequest = new NativeFunction(mod.base.add(0x15e8200), 'pointer', ['pointer', 'pointer', 'pointer', 'uint']);
const initTask = new NativeFunction(mod.base.add(0x0f7b40), 'void', ['pointer', 'pointer', 'pointer']);
const copyMeta = new NativeFunction(mod.base.add(0x38880), 'pointer', ['pointer', 'pointer']);
const copyTaskPayload = new NativeFunction(mod.base.add(0x15affc0), 'pointer', ['pointer', 'pointer']);
const initScheduleCtx = new NativeFunction(mod.base.add(0x182c10), 'void', ['pointer', 'pointer', 'pointer', 'uint']);
const scheduleTask = new NativeFunction(mod.base.add(0x314950), 'uint', ['pointer', 'pointer', 'pointer', 'uchar']);

let capturedTaskEvent = null;
let capturedManagerEvent = null;
let seenTaskKeys = {};
let seenMgrKeys = {};

Interceptor.attach(mod.base.add(0x314950), {
  onEnter(args) {
    try {
      const holder = args[1];
      const taskPtr = holder.readPointer();
      if (taskPtr.isNull()) return;
      const event = parseSendTask(taskPtr, selfUsername);
      if (!event) return;
      const key = [event.conversation_id, event.sender_username, event.content].join('|');
      if (seenTaskKeys[key]) return;
      seenTaskKeys[key] = true;
      if (event.conversation_id === TARGET_CONVERSATION && event.content === TARGET_BODY) {
        capturedTaskEvent = event;
      }
      send({ kind: 'send_task_event', event });
    } catch (e) {
      send({ kind: 'error', where: 'schedule_hook', error: String(e) });
    }
  }
});

Interceptor.attach(mod.base.add(0x154bb80), {
  onEnter(args) {
    try {
      const event = extractCompactDispatchEvent(args[1], selfUsername);
      if (!event) return;
      const key = [event.conversation_id, event.sender_username, event.content].join('|');
      if (seenMgrKeys[key]) return;
      seenMgrKeys[key] = true;
      if (event.conversation_id === TARGET_CONVERSATION && event.content === TARGET_BODY) {
        capturedManagerEvent = event;
      }
      send({ kind: 'manager_message_event', event });
    } catch (e) {
      send({ kind: 'error', where: 'manager_hook', error: String(e) });
    }
  }
});

rpc.exports.run = () => {
  let stage = 'start';
  try {
    send({ kind: 'stage', stage });
    stage = 'validate_template';
    send({ kind: 'stage', stage });
    if (TEMPLATE_SOURCE.isNull() || TEMPLATE_OWNER.isNull()) {
      throw new Error('template source/owner is null');
    }

    stage = 'clone_owner';
    send({ kind: 'stage', stage });
    const ownerSize = 0x710;
    const ownerClone = wxAlloc(ownerSize);
    Memory.copy(ownerClone, TEMPLATE_OWNER, ownerSize);
    rebasePointersInOwnerBlock(TEMPLATE_OWNER, ownerClone, ownerSize);

    stage = 'clone_source';
    send({ kind: 'stage', stage });
    const sourceOffset = TEMPLATE_SOURCE.sub(TEMPLATE_OWNER).toInt32();
    const sourceClone = ownerClone.add(sourceOffset);
    sourceClone.add(0x8).writePointer(sourceClone);
    sourceClone.add(0x10).writePointer(ownerClone);

    stage = 'rewrite_strings';
    send({ kind: 'stage', stage });
    writeHeapStdString(sourceClone.add(0xb0), TARGET_CONVERSATION, wxAlloc);
    writeHeapStdString(sourceClone.add(0x660), TARGET_BODY, wxAlloc);

    stage = 'build_pair';
    send({ kind: 'stage', stage });
    const pairBuf = wxAlloc(0x10);
    pairBuf.writePointer(sourceClone);
    pairBuf.add(Process.pointerSize).writePointer(ownerClone);

    stage = 'build_result';
    send({ kind: 'stage', stage });
    const resultBuf = Memory.alloc(0x60);
    resultBuf.writeByteArray(new Uint8Array(0x60));

    stage = 'get_root';
    send({ kind: 'stage', stage });
    const rootBuf = Memory.alloc(0x20);
    rootBuf.writeByteArray(new Uint8Array(0x20));
    getRoot(rootBuf);

    stage = 'get_service';
    send({ kind: 'stage', stage });
    const svcBuf = Memory.alloc(0x20);
    svcBuf.writeByteArray(new Uint8Array(0x20));
    getSvc(rootBuf.readPointer(), svcBuf);

    stage = 'get_send_ctx';
    send({ kind: 'stage', stage });
    const sendCtxBuf = Memory.alloc(0x20);
    sendCtxBuf.writeByteArray(new Uint8Array(0x20));
    getSendCtx(svcBuf.readPointer(), sendCtxBuf);

    stage = 'call_builder';
    send({ kind: 'stage', stage });
    buildOnePairRequest(sendCtxBuf.readPointer(), resultBuf, pairBuf, 1);

    stage = 'alloc_task';
    send({ kind: 'stage', stage });
    const taskObj = wxAlloc(0x158);
    taskObj.writeByteArray(new Uint8Array(0x158));
    stage = 'init_task';
    send({ kind: 'stage', stage });
    initTask(taskObj, mod.base.add(0x15afcd0), mod.base.add(0x15afe50));

    stage = 'copy_meta';
    send({ kind: 'stage', stage });
    const emptyMeta = Memory.alloc(0xd0);
    emptyMeta.writeByteArray(new Uint8Array(0xd0));
    copyMeta(taskObj.add(0x28), emptyMeta);
    stage = 'copy_payload';
    send({ kind: 'stage', stage });
    copyTaskPayload(taskObj.add(0x110), resultBuf);

    stage = 'init_sched_ctx';
    send({ kind: 'stage', stage });
    const scheduleCtx = Memory.alloc(0x20);
    scheduleCtx.writeByteArray(new Uint8Array(0x20));
    initScheduleCtx(scheduleCtx, mod.base.add(0x7dc727f), mod.base.add(0x81207c4), 0x1f9);

    stage = 'schedule';
    send({ kind: 'stage', stage });
    const holder = Memory.alloc(Process.pointerSize);
    holder.writePointer(taskObj);
    const scheduleResult = scheduleTask(scheduleCtx, holder, ptr('0x0'), 0);

    stage = 'return';
    send({ kind: 'stage', stage });
    return {
      ok: true,
      stage,
      schedule_result: scheduleResult,
      self_username: selfUsername,
      template_source: safePtrString(TEMPLATE_SOURCE),
      template_owner: safePtrString(TEMPLATE_OWNER),
      owner_clone: safePtrString(ownerClone),
      source_clone: safePtrString(sourceClone),
      source_offset: sourceOffset,
      source_strings: {
        conversation: readStdString(sourceClone.add(0xb0)),
        uuid: readStdString(sourceClone.add(0x600)),
        body: readStdString(sourceClone.add(0x660)),
      },
      global_ctx: {
        root: safePtrString(rootBuf.readPointer()),
        service: safePtrString(svcBuf.readPointer()),
        send_ctx: safePtrString(sendCtxBuf.readPointer()),
      },
      result_strings: {
        r0: readStdString(resultBuf.add(0x0)),
        r20: readStdString(resultBuf.add(0x20)),
      },
    };
  } catch (e) {
    return {
      ok: false,
      stage,
      error: String(e),
      self_username: selfUsername,
      task_event: capturedTaskEvent,
      manager_event: capturedManagerEvent,
    };
  }
};

rpc.exports.getstate = () => {
  return {
    ok: capturedManagerEvent !== null,
    self_username: selfUsername,
    task_event: capturedTaskEvent,
    manager_event: capturedManagerEvent,
  };
};
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--template-source", required=True)
    parser.add_argument("--template-owner", required=True)
    parser.add_argument("--conversation-id", required=True)
    parser.add_argument("--body", required=True)
    parser.add_argument("--wait-ms", type=int, default=5000)
    args = parser.parse_args()

    device = frida.get_local_device()
    session = device.attach(args.pid)
    rendered = (
        SCRIPT
        .replace("{{TEMPLATE_SOURCE_JSON}}", json.dumps(args.template_source))
        .replace("{{TEMPLATE_OWNER_JSON}}", json.dumps(args.template_owner))
        .replace("{{TARGET_CONVERSATION_JSON}}", json.dumps(args.conversation_id))
        .replace("{{TARGET_BODY_JSON}}", json.dumps(args.body))
        .replace("{{WAIT_MS}}", str(args.wait_ms))
    )
    script = session.create_script(rendered)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(str(payload) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    initial = script.exports_sync.run()
    print(json.dumps(initial, ensure_ascii=False, indent=2))
    time.sleep(args.wait_ms / 1000.0)
    final_state = script.exports_sync.getstate()
    print(json.dumps({"final_state": final_state}, ensure_ascii=False, indent=2))
    session.detach()


if __name__ == "__main__":
    main()
