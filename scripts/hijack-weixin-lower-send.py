#!/usr/bin/env python
import argparse
import json
import sys
import threading

import frida


SCRIPT = r"""
const TRIGGER_BODY = {{TRIGGER_BODY_JSON}};
const TARGET_CONVERSATION = {{TARGET_CONVERSATION_JSON}};
const TARGET_BODY = {{TARGET_BODY_JSON}};
const BASELINE_SECONDS = {{BASELINE_SECONDS}};
const BUILDER_ONLY = {{BUILDER_ONLY}};

function safePtrString(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (e) {
    return '0x0';
  }
}

function bytesToHex(arrbuf) {
  try {
    const bytes = new Uint8Array(arrbuf);
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i].toString(16);
      out += b.length === 1 ? ('0' + b) : b;
    }
    return out;
  } catch (e) {
    return null;
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

function readVector(base) {
  try {
    const begin = base.readPointer();
    const end = base.add(Process.pointerSize).readPointer();
    const cap = base.add(Process.pointerSize * 2).readPointer();
    const count = end.sub(begin).toInt32() / 0x10;
    return { begin, end, cap, count };
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

function readU32(base, off) {
  try {
    return base.add(off).readU32();
  } catch (e) {
    return null;
  }
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

function dumpQwords(base, size) {
  const out = {};
  try {
    if (!base || base.isNull()) return null;
    for (let off = 0; off < size; off += 8) {
      try {
        out['0x' + off.toString(16)] = safePtrString(base.add(off).readPointer());
      } catch (_) {
        out['0x' + off.toString(16)] = null;
      }
    }
    return out;
  } catch (_) {
    return null;
  }
}

function dumpBytes(base, size) {
  try {
    if (!base || base.isNull()) return null;
    return bytesToHex(base.readByteArray(size));
  } catch (_) {
    return null;
  }
}

function readPtr(base) {
  try {
    if (!base || base.isNull()) return ptr('0x0');
    return base.readPointer();
  } catch (_) {
    return ptr('0x0');
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

const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
let fired = false;
let invokingSynthetic = false;
let lastStage = null;
let seenTaskKeys = {};
let seenManagerKeys = {};
let currentSyntheticTaskPtr = null;
let helperTraceActive = false;
let helperTraceThreadId = 0;
let helperTraceLabel = null;

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
      event.synthetic_task_match = !!(currentSyntheticTaskPtr && taskPtr.equals(currentSyntheticTaskPtr));
      event.synthetic_task_ptr = currentSyntheticTaskPtr ? safePtrString(currentSyntheticTaskPtr) : null;
      send({ kind: 'send_task_event', event });
    } catch (e) {
      send({ kind: 'error', where: 'schedule_hook', error: String(e), stage: lastStage });
    }
  }
});

Interceptor.attach(mod.base.add(0x154bb80), {
  onEnter(args) {
    try {
      const event = extractCompactDispatchEvent(args[1], selfUsername);
      if (!event) return;
      const key = [event.conversation_id, event.sender_username, event.content].join('|');
      if (seenManagerKeys[key]) return;
      seenManagerKeys[key] = true;
      send({ kind: 'manager_message_event', event });
    } catch (e) {
      send({ kind: 'error', where: 'manager_hook', error: String(e), stage: lastStage });
    }
  }
});

Interceptor.attach(mod.base.add(0x15e8200), {
  onEnter(args) {
    try {
      const pairPtr = args[2];
      if (pairPtr.isNull()) return;
      const sourcePtr = pairPtr.readPointer();
      if (sourcePtr.isNull()) return;
      const conversation = readStdString(sourcePtr.add(0xb0));
      const body = readStdString(sourcePtr.add(0x660));
      if (conversation !== TARGET_CONVERSATION) return;
      if (body !== TRIGGER_BODY && body !== TARGET_BODY) return;
      helperTraceActive = true;
      helperTraceThreadId = Process.getCurrentThreadId();
      helperTraceLabel = body;
      send({
        kind: 'helper_builder_enter',
        label: body,
        thread_id: helperTraceThreadId,
        send_ctx: safePtrString(args[0]),
        result_buf: safePtrString(args[1]),
        pair_ptr: safePtrString(pairPtr),
        source_ptr: safePtrString(sourcePtr),
        owner_ptr: safePtrString(pairPtr.add(Process.pointerSize).readPointer()),
        mode: args[3].toUInt32(),
        conversation,
        body,
        uuid: readStdString(sourcePtr.add(0x600)),
      });
    } catch (e) {
      send({ kind: 'error', where: 'helper_builder_enter', error: String(e), stage: lastStage });
    }
  },
  onLeave(retval) {
    try {
      if (!helperTraceActive) return;
      if (Process.getCurrentThreadId() !== helperTraceThreadId) return;
      send({
        kind: 'helper_builder_leave',
        label: helperTraceLabel,
        thread_id: helperTraceThreadId,
        retval: safePtrString(retval),
      });
    } catch (e) {
      send({ kind: 'error', where: 'helper_builder_leave', error: String(e), stage: lastStage });
    } finally {
      helperTraceActive = false;
      helperTraceThreadId = 0;
      helperTraceLabel = null;
    }
  }
});

function helperHook(name, rva) {
  Interceptor.attach(mod.base.add(rva), {
    onEnter(args) {
      try {
        if (!helperTraceActive) return;
        if (Process.getCurrentThreadId() !== helperTraceThreadId) return;
        const q0 = readPtr(args[1]);
        send({
          kind: 'helper_' + name + '_enter',
          label: helperTraceLabel,
          thread_id: helperTraceThreadId,
          args: {
            rcx: safePtrString(args[0]),
            rdx: safePtrString(args[1]),
            r8: safePtrString(args[2]),
            r9: safePtrString(args[3]),
          },
          q0_ptr: safePtrString(q0),
          rdx_qwords: args[1] && !args[1].isNull() ? dumpQwords(args[1], 0x40) : null,
          rdx_bytes_40: args[1] && !args[1].isNull() ? dumpBytes(args[1], 0x40) : null,
          rdx_q0_qwords: !q0.isNull() ? dumpQwords(q0, 0x50) : null,
          rdx_q0_bytes_50: !q0.isNull() ? dumpBytes(q0, 0x50) : null,
        });
      } catch (e) {
        send({ kind: 'error', where: 'helper_' + name + '_enter', error: String(e), stage: lastStage });
      }
    },
    onLeave(retval) {
      try {
        if (!helperTraceActive) return;
        if (Process.getCurrentThreadId() !== helperTraceThreadId) return;
        send({
          kind: 'helper_' + name + '_leave',
          label: helperTraceLabel,
          thread_id: helperTraceThreadId,
          retval: safePtrString(retval),
        });
      } catch (e) {
        send({ kind: 'error', where: 'helper_' + name + '_leave', error: String(e), stage: lastStage });
      }
    }
  });
}

helperHook('eb320', 0x15eb320);
helperHook('ebec0', 0x15ebec0);

Interceptor.attach(mod.base.add(0x15af8e0), {
  onEnter(args) {
    try {
      if (invokingSynthetic) return;
      if (Date.now() < baselineUntil) return;
      if (fired) return;

      const wrapper = args[0];
      const vec = readVector(wrapper.add(0x8));
      if (!vec || vec.count < 1) return;
      const pair = vec.begin;
      const sourceObj = pair.readPointer();
      const ownerBase = pair.add(Process.pointerSize).readPointer();
      if (sourceObj.isNull() || ownerBase.isNull()) return;

      const currentBody = readStdString(sourceObj.add(0x660));
      if (currentBody !== TRIGGER_BODY) return;

      this.pending = {
        thread_id: Process.getCurrentThreadId(),
        wrapper: wrapper,
        sourceObj: sourceObj,
        ownerBase: ownerBase,
        conversation: readStdString(sourceObj.add(0xb0)),
        body: currentBody,
        uuid: readStdString(sourceObj.add(0x600)),
        sourceOffset: sourceObj.sub(ownerBase).toInt32(),
        conversationCap: readU32(sourceObj.add(0xb0), 0x18),
        ownerRefA: readU32(ownerBase, 0x8),
        ownerRefB: readU32(ownerBase, 0xc),
        ownerSnapshotHex: bytesToHex(ownerBase.readByteArray(0x710)),
      };
      send({ kind: 'seed_captured', pending: this.pending });
    } catch (e) {
      send({ kind: 'error', where: 'top_send_enter', error: String(e), stage: lastStage });
    }
  },
  onLeave(retval) {
    let stageTrail = [];
    try {
      if (!this.pending) return;
      if (fired) return;
      fired = true;
      invokingSynthetic = true;
      const mark = (stage, extra) => {
        lastStage = stage;
        stageTrail.push({ stage, extra: extra || null });
      };

      mark('clone_owner_prepare', this.pending);
      const ownerClone = wxAlloc(0x710);
      mark('clone_owner_copy');
      Memory.copy(ownerClone, this.pending.ownerBase, 0x710);
      mark('clone_owner_rebase');
      rebasePointersInOwnerBlock(this.pending.ownerBase, ownerClone, 0x710);

      mark('clone_source_locate');
      const sourceOffset = this.pending.sourceObj.sub(this.pending.ownerBase).toInt32();
      const sourceClone = ownerClone.add(sourceOffset);
      mark('clone_source_fix_backrefs');
      sourceClone.add(0x8).writePointer(sourceClone);
      sourceClone.add(0x10).writePointer(ownerClone);
      send({
        kind: 'synthetic_clone_ready',
        thread_id: Process.getCurrentThreadId(),
        owner_clone: safePtrString(ownerClone),
        source_clone: safePtrString(sourceClone),
        original_owner: safePtrString(this.pending.ownerBase),
        original_source: safePtrString(this.pending.sourceObj),
        trigger_body: this.pending.body,
      });

      mark('rewrite_strings_conversation');
      writeHeapStdString(sourceClone.add(0xb0), TARGET_CONVERSATION, wxAlloc);
      mark('rewrite_strings_body');
      writeHeapStdString(sourceClone.add(0x660), TARGET_BODY, wxAlloc);

      mark('build_pair');
      const pairBuf = wxAlloc(0x10);
      pairBuf.writePointer(sourceClone);
      pairBuf.add(Process.pointerSize).writePointer(ownerClone);

      mark('get_root_prepare');
      const rootBuf = Memory.alloc(0x20);
      rootBuf.writeByteArray(new Uint8Array(0x20));
      mark('get_root_call');
      getRoot(rootBuf);

      mark('get_service_prepare');
      const svcBuf = Memory.alloc(0x20);
      svcBuf.writeByteArray(new Uint8Array(0x20));
      mark('get_service_call');
      getSvc(rootBuf.readPointer(), svcBuf);

      mark('get_send_ctx_prepare');
      const sendCtxBuf = Memory.alloc(0x20);
      sendCtxBuf.writeByteArray(new Uint8Array(0x20));
      mark('get_send_ctx_call');
      getSendCtx(svcBuf.readPointer(), sendCtxBuf);
      const sendCtx = sendCtxBuf.readPointer();

      mark('call_builder_prepare', {
        send_ctx: safePtrString(sendCtx),
        b78: safePtrString(sendCtx.add(0xb78).readPointer()),
      });
      const resultBuf = Memory.alloc(0x60);
      resultBuf.writeByteArray(new Uint8Array(0x60));
      mark('call_builder_call');
      buildOnePairRequest(sendCtx, resultBuf, pairBuf, 1);
      if (BUILDER_ONLY) {
        mark('builder_only_done', {
          owner_clone: safePtrString(ownerClone),
          source_clone: safePtrString(sourceClone),
          pair_buf: safePtrString(pairBuf),
          conversation: readStdString(sourceClone.add(0xb0)),
          body: readStdString(sourceClone.add(0x660)),
          uuid: readStdString(sourceClone.add(0x600)),
        });
        send({ kind: 'synthetic_done', trail: stageTrail, pending: this.pending, builder_only: true });
        invokingSynthetic = false;
        return;
      }

      mark('alloc_task');
      const taskObj = wxAlloc(0x158);
      taskObj.writeByteArray(new Uint8Array(0x158));
      currentSyntheticTaskPtr = taskObj;

      mark('init_task_call');
      initTask(taskObj, mod.base.add(0x15afcd0), mod.base.add(0x15afe50));

      mark('copy_meta_prepare');
      const emptyMeta = Memory.alloc(0xd0);
      emptyMeta.writeByteArray(new Uint8Array(0xd0));
      mark('copy_meta_call');
      copyMeta(taskObj.add(0x28), emptyMeta);

      mark('copy_payload_call');
      copyTaskPayload(taskObj.add(0x110), resultBuf);
      mark('copy_payload_done');

      mark('init_sched_ctx_alloc');
      const schedCtx = Memory.alloc(0x20);
      schedCtx.writeByteArray(new Uint8Array(0x20));
      mark('init_sched_ctx_call');
      initScheduleCtx(schedCtx, mod.base.add(0x7dc727f), mod.base.add(0x81207c4), 0x1f9);

      mark('schedule_holder_alloc');
      const holder = Memory.alloc(Process.pointerSize);
      holder.writePointer(taskObj);
      mark('schedule_call');
      const scheduleResult = scheduleTask(schedCtx, holder, ptr('0x0'), 0);

      mark('done', {
        schedule_result: scheduleResult,
        task_obj: safePtrString(taskObj),
        conversation: readStdString(sourceClone.add(0xb0)),
        body: readStdString(sourceClone.add(0x660)),
        uuid: readStdString(sourceClone.add(0x600)),
      });
      send({ kind: 'synthetic_done', trail: stageTrail, pending: this.pending });
      invokingSynthetic = false;
    } catch (e) {
      invokingSynthetic = false;
      send({ kind: 'error', where: 'top_send_leave', error: String(e), stage: lastStage, trail: stageTrail, synthetic_task_ptr: currentSyntheticTaskPtr ? safePtrString(currentSyntheticTaskPtr) : null, pending: this.pending || null });
    }
  }
});

send({
  kind: 'status',
  self_username: selfUsername,
  trigger_body: TRIGGER_BODY,
  target_conversation: TARGET_CONVERSATION,
  target_body: TARGET_BODY,
  baseline_seconds: BASELINE_SECONDS,
});

setTimeout(() => send({ kind: 'armed' }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat', fired, stage: lastStage }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--trigger-body", required=True)
    parser.add_argument("--conversation-id", required=True)
    parser.add_argument("--body", required=True)
    parser.add_argument("--baseline-seconds", type=int, default=2)
    parser.add_argument("--builder-only", action="store_true")
    args = parser.parse_args()

    device = frida.get_local_device()
    session = device.attach(args.pid)
    rendered = (
        SCRIPT
        .replace("{{TRIGGER_BODY_JSON}}", json.dumps(args.trigger_body))
        .replace("{{TARGET_CONVERSATION_JSON}}", json.dumps(args.conversation_id))
        .replace("{{TARGET_BODY_JSON}}", json.dumps(args.body))
        .replace("{{BASELINE_SECONDS}}", str(args.baseline_seconds))
        .replace("{{BUILDER_ONLY}}", "true" if args.builder_only else "false")
    )
    script = session.create_script(rendered)

    def on_message(message, data):
      payload = message.get("payload", message)
      sys.stdout.write(str(payload) + "\n")
      sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    sys.stdout.write(f"attached pid={args.pid}\n")
    sys.stdout.flush()
    threading.Event().wait()


if __name__ == "__main__":
    main()
