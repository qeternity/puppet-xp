#!/usr/bin/env python
import argparse
import ast
import ctypes
import json
import os
import sys
import time
from ctypes import wintypes
from pathlib import Path

import frida


SCRIPT = r"""
const MODE = {{MODE_JSON}};
const TEMPLATE_WRAPPER = {{TEMPLATE_WRAPPER_EXPR}};
const TEMPLATE_SOURCE = ptr({{TEMPLATE_SOURCE_JSON}});
const TEMPLATE_OWNER = ptr({{TEMPLATE_OWNER_JSON}});
const TARGET_CONVERSATION = {{TARGET_CONVERSATION_JSON}};
const TARGET_BODY = {{TARGET_BODY_JSON}};
const TARGET_THREAD_ID = {{TARGET_THREAD_ID}};
const PAIR_MODE = {{PAIR_MODE}};
const EBECO_FIX = {{EBECO_FIX_JSON}};
const OWNER_REF_A_OVERRIDE = {{OWNER_REF_A_JSON}};
const OWNER_REF_B_OVERRIDE = {{OWNER_REF_B_JSON}};

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

function writeHeapStdString(addr, value, wxAlloc, forcedCap) {
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
  let cap = forcedCap !== undefined && forcedCap !== null ? forcedCap : utf8.length;
  if (cap < utf8.length) cap = utf8.length;
  const buf = wxAlloc(cap + 1);
  for (let i = 0; i < utf8.length; i++) {
    buf.add(i).writeU8(utf8[i]);
  }
  buf.add(utf8.length).writeU8(0);
  addr.writeByteArray(new Uint8Array(16));
  addr.writePointer(buf);
  addr.add(0x10).writeU32(utf8.length);
  addr.add(0x14).writeU32(0);
  addr.add(0x18).writeU32(cap);
  addr.add(0x1c).writeU32(0);
}

function randomHex(n) {
  const alphabet = '0123456789abcdef';
  let out = '';
  for (let i = 0; i < n; i++) {
    out += alphabet[Math.floor(Math.random() * 16)];
  }
  return out;
}

function randomUuid() {
  return [
    randomHex(8),
    randomHex(4),
    '4' + randomHex(3),
    '8' + randomHex(3),
    randomHex(12),
  ].join('-');
}

function hexToByteArray(hex) {
  if (!hex) return null;
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length === 0 || (clean.length % 2) !== 0) return null;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

function readBytesHex(addr, size) {
  try {
    if (!addr || addr.isNull()) return null;
    const bytes = addr.readByteArray(size);
    if (!bytes) return null;
    return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, '0')).join('');
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

const mod = Process.getModuleByName('Weixin.dll');
const selfUsername = getSelfUsername(mod);
const wxAlloc = new NativeFunction(mod.base.add(0x6309d1c), 'pointer', ['ulong']);
const getRoot = new NativeFunction(mod.base.add(0x20800), 'pointer', ['pointer']);
const getSvc = new NativeFunction(mod.base.add(0x2fbff0), 'void', ['pointer', 'pointer']);
const getSendCtx = new NativeFunction(mod.base.add(0x633270), 'pointer', ['pointer', 'pointer']);
const freshPairCtor = new NativeFunction(mod.base.add(0x633150), 'pointer', ['pointer']);
const buildOnePairRequest = new NativeFunction(mod.base.add(0x15e8200), 'pointer', ['pointer', 'pointer', 'pointer', 'uint']);
const buildBatchRequest = new NativeFunction(mod.base.add(0x15e9960), 'pointer', ['pointer', 'pointer', 'pointer', 'ulong']);
const topSendFn = new NativeFunction(mod.base.add(0x15af8e0), 'void', ['pointer']);
const freshSendCtor = new NativeFunction(mod.base.add(0x1664250), 'void', ['pointer', 'pointer', 'pointer']);
const initTask = new NativeFunction(mod.base.add(0x0f7b40), 'void', ['pointer', 'pointer', 'pointer']);
const copyMeta = new NativeFunction(mod.base.add(0x38880), 'pointer', ['pointer', 'pointer']);
const copyTaskPayload = new NativeFunction(mod.base.add(0x15affc0), 'pointer', ['pointer', 'pointer']);
const initScheduleCtx = new NativeFunction(mod.base.add(0x182c10), 'void', ['pointer', 'pointer', 'pointer', 'uint']);
const scheduleTask = new NativeFunction(mod.base.add(0x314950), 'uint', ['pointer', 'pointer', 'pointer', 'uchar']);

let capturedTaskEvent = null;
let capturedManagerEvent = null;
let seenTaskKeys = {};
let seenMgrKeys = {};
let freshHijackActive = false;
let freshHijackTriggered = false;
let freshHijackCapture = null;
let freshTraceActive = false;
let freshTraceCounts = {};
let freshPairBuildTrace = [];
let freshPairBuildActive = false;
let freshPairBuildCurrent = null;
let freshPairEbec0Index = 0;

function readQwords(base, count) {
  try {
    if (!base || base.isNull()) return null;
    const out = {};
    for (let i = 0; i < count; i++) {
      const off = i * Process.pointerSize;
      out['0x' + off.toString(16)] = safePtrString(base.add(off).readPointer());
    }
    return out;
  } catch (e) {
    return null;
  }
}

function getEbec0FixForIndex(index) {
  if (!EBECO_FIX) return null;
  if (Array.isArray(EBECO_FIX)) {
    return index < EBECO_FIX.length ? EBECO_FIX[index] : null;
  }
  if (Array.isArray(EBECO_FIX.sequence)) {
    return index < EBECO_FIX.sequence.length ? EBECO_FIX.sequence[index] : null;
  }
  return EBECO_FIX;
}

Process.setExceptionHandler(function (details) {
  try {
    if (!freshPairBuildActive) return false;
    const currentThread = Process.getCurrentThreadId();
    if (currentThread !== TARGET_THREAD_ID) return false;
    const ctx = details.context || {};
    send({
      kind: 'fresh_pair_exception',
      thread_id: currentThread,
      type: details.type || null,
      address: details.address ? safePtrString(details.address) : null,
      memory_operation: details.memory ? details.memory.operation : null,
      memory_address: details.memory ? safePtrString(details.memory.address) : null,
      stage_call: freshPairBuildCurrent,
      registers: {
        rip: ctx.rip ? safePtrString(ctx.rip) : null,
        rsp: ctx.rsp ? safePtrString(ctx.rsp) : null,
        rbp: ctx.rbp ? safePtrString(ctx.rbp) : null,
        rcx: ctx.rcx ? safePtrString(ctx.rcx) : null,
        rdx: ctx.rdx ? safePtrString(ctx.rdx) : null,
        r8: ctx.r8 ? safePtrString(ctx.r8) : null,
        r9: ctx.r9 ? safePtrString(ctx.r9) : null,
        rax: ctx.rax ? safePtrString(ctx.rax) : null,
      },
      rsp_qwords: ctx.rsp ? readQwords(ctx.rsp, 8) : null,
    });
  } catch (e) {
    send({ kind: 'error', where: 'fresh_pair_exception_handler', error: String(e) });
  }
  return false;
});

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

Interceptor.attach(mod.base.add(0x15e8200), {
  onEnter(args) {
    try {
      if (Process.getCurrentThreadId() === TARGET_THREAD_ID) {
        const pairPtr = args[2];
        if (!pairPtr.isNull()) {
          const sourcePtr = pairPtr.readPointer();
          if (!sourcePtr.isNull()) {
            const conversation = readStdString(sourcePtr.add(0xb0));
            const body = readStdString(sourcePtr.add(0x660));
            if (conversation === TARGET_CONVERSATION && body === TARGET_BODY) {
              const ownerPtr = pairPtr.add(Process.pointerSize).readPointer();
              freshPairBuildActive = true;
              freshPairBuildCurrent = {
                kind: 'pair_build_enter',
                thread_id: Process.getCurrentThreadId(),
                caller_rva: safePtrString(this.returnAddress.sub(mod.base)),
                send_ctx: safePtrString(args[0]),
                result_buf: safePtrString(args[1]),
                pair_ptr: safePtrString(pairPtr),
                source_ptr: safePtrString(sourcePtr),
                owner_ptr: safePtrString(ownerPtr),
                mode: args[3].toUInt32(),
                conversation,
                body,
                script_mode: MODE,
                owner_refs: ownerPtr.isNull() ? null : {
                  ref_a: readU32(ownerPtr, 0x8),
                  ref_b: readU32(ownerPtr, 0xc),
                },
              };
              freshPairBuildTrace.push(freshPairBuildCurrent);
              freshPairEbec0Index = 0;
              send(freshPairBuildCurrent);
            }
          }
        }
      }
      if (!freshHijackActive) return;
      if (Process.getCurrentThreadId() !== TARGET_THREAD_ID) return;
      const pairPtr = args[2];
      if (pairPtr.isNull()) return;
      const sourcePtr = pairPtr.readPointer();
      const ownerPtr = pairPtr.add(Process.pointerSize).readPointer();
      if (sourcePtr.isNull() || ownerPtr.isNull()) return;
      const incomingMode = args[3].toUInt32();
      const capture = {
        pair: safePtrString(pairPtr),
        source: safePtrString(sourcePtr),
        owner: safePtrString(ownerPtr),
        caller_rva: safePtrString(this.returnAddress.sub(mod.base)),
        incoming_mode: incomingMode,
        conversation: readStdString(sourcePtr.add(0xb0)),
        body: readStdString(sourcePtr.add(0x660)),
        uuid: readStdString(sourcePtr.add(0x600)),
        flags: {
          f9c: readU32(sourcePtr, 0x9c),
          fd8: readU32(sourcePtr, 0xd8),
        },
      };
      freshHijackCapture = capture;
      send({ kind: 'fresh_pair_captured', capture });
      if (MODE === 'fresh-hijack1' && !freshHijackTriggered && incomingMode === 0) {
        args[3] = ptr(1);
        freshHijackTriggered = true;
        send({
          kind: 'fresh_mode_flip',
          from_mode: incomingMode,
          to_mode: 1,
          caller_rva: capture.caller_rva,
          conversation: capture.conversation,
          body: capture.body,
        });
      }
    } catch (e) {
      send({ kind: 'error', where: 'fresh_hijack_builder', error: String(e) });
    }
  },
  onLeave(retval) {
    try {
      if (!freshPairBuildActive || Process.getCurrentThreadId() !== TARGET_THREAD_ID) return;
      const payload = {
        kind: 'fresh_pair_build_leave',
        thread_id: Process.getCurrentThreadId(),
        retval: safePtrString(retval),
      };
      freshPairBuildTrace.push(payload);
      send(payload);
      freshPairBuildActive = false;
      freshPairBuildCurrent = null;
    } catch (e) {
      send({ kind: 'error', where: 'fresh_pair_build_leave', error: String(e) });
    }
  }
});

Interceptor.attach(mod.base.add(0x15eb320), {
  onEnter(args) {
    try {
      if (!freshPairBuildActive || Process.getCurrentThreadId() !== TARGET_THREAD_ID) return;
      const payload = {
        kind: 'fresh_pair_eb320_enter',
        thread_id: Process.getCurrentThreadId(),
        p1: safePtrString(args[0]),
        map_base: safePtrString(args[1]),
        pair_copy: safePtrString(args[2]),
        out_ptr: safePtrString(args[3]),
      };
      freshPairBuildTrace.push(payload);
      send(payload);
    } catch (e) {
      send({ kind: 'error', where: 'fresh_pair_eb320_enter', error: String(e) });
    }
  },
  onLeave(retval) {
    try {
      if (!freshPairBuildActive || Process.getCurrentThreadId() !== TARGET_THREAD_ID) return;
      const payload = {
        kind: 'fresh_pair_eb320_leave',
        thread_id: Process.getCurrentThreadId(),
        retval: safePtrString(retval),
      };
      freshPairBuildTrace.push(payload);
      send(payload);
    } catch (e) {
      send({ kind: 'error', where: 'fresh_pair_eb320_leave', error: String(e) });
    }
  }
});

Interceptor.attach(mod.base.add(0x15ebec0), {
  onEnter(args) {
    try {
      if (!freshPairBuildActive || Process.getCurrentThreadId() !== TARGET_THREAD_ID) return;
      const keyPtr = args[1];
      const ebec0Index = freshPairEbec0Index++;
      const payload = {
        kind: 'fresh_pair_ebec0_enter',
        index: ebec0Index,
        thread_id: Process.getCurrentThreadId(),
        builder: safePtrString(args[0]),
        key_ptr: safePtrString(keyPtr),
        key_s0: keyPtr.isNull() ? null : readStdString(keyPtr.add(0x0)),
        key_s20: keyPtr.isNull() ? null : readStdString(keyPtr.add(0x20)),
      };
      const ebec0Fix = getEbec0FixForIndex(ebec0Index);
      if (ebec0Fix && !keyPtr.isNull()) {
        try {
          if (ebec0Fix.replace_key_ptr) {
            args[1] = ptr(ebec0Fix.replace_key_ptr);
            payload.replaced_key_ptr = ebec0Fix.replace_key_ptr;
          }
          if (ebec0Fix.replace_r8) {
            args[2] = ptr(ebec0Fix.replace_r8);
            payload.replaced_r8 = ebec0Fix.replace_r8;
          }
          if (ebec0Fix.replace_r9) {
            args[3] = ptr(ebec0Fix.replace_r9);
            payload.replaced_r9 = ebec0Fix.replace_r9;
          }
          let q0Hex = null;
          if (ebec0Fix.key_bytes_40 || ebec0Fix.q0_bytes_50 || ebec0Fix.q0_bytes_hex) {
            const keyClone = Memory.alloc(0x40);
            keyClone.writeByteArray(new Uint8Array(0x40));
            if (ebec0Fix.key_bytes_40) {
              const keyBytes = hexToByteArray(ebec0Fix.key_bytes_40);
              if (!keyBytes || keyBytes.length !== 0x40) {
                throw new Error('key_bytes_40 must decode to 0x40 bytes');
              }
              keyClone.writeByteArray(keyBytes);
            }
            let q0Clone = NULL;
            q0Hex = ebec0Fix.q0_bytes_hex || ebec0Fix.q0_bytes_50 || null;
            if (q0Hex) {
              const q0Bytes = hexToByteArray(q0Hex);
              if (!q0Bytes || q0Bytes.length === 0) {
                throw new Error('q0_bytes_hex must decode to non-empty bytes');
              }
              q0Clone = Memory.alloc(q0Bytes.length);
              q0Clone.writeByteArray(q0Bytes);
              keyClone.writePointer(q0Clone);
            }
            args[1] = keyClone;
            payload.allocated_key_clone = safePtrString(keyClone);
            payload.allocated_q0_clone = safePtrString(q0Clone);
          }
          const effectiveKeyPtr = args[1];
          payload.effective_key_ptr = safePtrString(effectiveKeyPtr);
          payload.effective_key_qwords = readQwords(effectiveKeyPtr, 8);
          if (q0Hex) {
            const node = effectiveKeyPtr.readPointer();
            if (!node.isNull()) {
            if (ebec0Fix.q18) node.add(0x18).writePointer(ptr(ebec0Fix.q18));
            if (ebec0Fix.q20) node.add(0x20).writePointer(ptr(ebec0Fix.q20));
            if (Object.prototype.hasOwnProperty.call(ebec0Fix, 'q28')) {
              node.add(0x28).writePointer(ptr(ebec0Fix.q28));
            }
            if (Object.prototype.hasOwnProperty.call(ebec0Fix, 'q30')) {
              node.add(0x30).writePointer(ptr(ebec0Fix.q30));
            }
            if (ebec0Fix.q38) node.add(0x38).writePointer(ptr(ebec0Fix.q38));
            if (ebec0Fix.q40) node.add(0x40).writePointer(ptr(ebec0Fix.q40));
            if (ebec0Fix.q48) node.add(0x48).writePointer(ptr(ebec0Fix.q48));
            payload.fixed_node = {
              node: safePtrString(node),
              q18: ebec0Fix.q18 || null,
              q20: ebec0Fix.q20 || null,
              q28: Object.prototype.hasOwnProperty.call(ebec0Fix, 'q28') ? ebec0Fix.q28 : null,
              q30: Object.prototype.hasOwnProperty.call(ebec0Fix, 'q30') ? ebec0Fix.q30 : null,
              q38: ebec0Fix.q38 || null,
              q40: ebec0Fix.q40 || null,
              q48: ebec0Fix.q48 || null,
            };
          }
          }
        } catch (fixErr) {
          payload.fix_error = String(fixErr);
        }
      }
      freshPairBuildTrace.push(payload);
      send(payload);
    } catch (e) {
      send({ kind: 'error', where: 'fresh_pair_ebec0_enter', error: String(e) });
    }
  },
  onLeave(retval) {
    try {
      if (!freshPairBuildActive || Process.getCurrentThreadId() !== TARGET_THREAD_ID) return;
      const payload = {
        kind: 'fresh_pair_ebec0_leave',
        thread_id: Process.getCurrentThreadId(),
        retval: safePtrString(retval),
      };
      freshPairBuildTrace.push(payload);
      send(payload);
    } catch (e) {
      send({ kind: 'error', where: 'fresh_pair_ebec0_leave', error: String(e) });
    }
  }
});

function installFreshPairInnerTrace(rva, name) {
  Interceptor.attach(mod.base.add(rva), {
    onEnter(args) {
      try {
        if (!freshPairBuildActive || Process.getCurrentThreadId() !== TARGET_THREAD_ID) return;
        const payload = {
          kind: 'fresh_pair_inner',
          name,
          rva: '0x' + rva.toString(16),
          thread_id: Process.getCurrentThreadId(),
        };
        freshPairBuildTrace.push(payload);
        send(payload);
      } catch (e) {
        send({ kind: 'error', where: 'fresh_pair_inner_' + name, error: String(e) });
      }
    }
  });
}

[
  [0x01d1d40, 'mk_pair_copy'],
  [0x1685ad0, 'emit_builder_record'],
  [0x1636a20, 'link_builder_a'],
  [0x1632f00, 'link_builder_b'],
  [0x2102270, 'finalize_builder_branch'],
  [0x3400c20, 'msg_kind_get'],
  [0x3400c40, 'msg_flag_check'],
  [0x3400c30, 'msg_flag_set'],
  [0x3400c00, 'msg_aux_dump'],
].forEach(([rva, name]) => installFreshPairInnerTrace(rva, name));

function installFreshTraceHook(rva, name) {
  Interceptor.attach(mod.base.add(rva), {
    onEnter(args) {
      try {
        if (!freshTraceActive) return;
        if (Process.getCurrentThreadId() !== TARGET_THREAD_ID) return;
        const count = (freshTraceCounts[name] || 0) + 1;
        freshTraceCounts[name] = count;
        send({ kind: 'fresh_trace', name, rva: '0x' + rva.toString(16), count });
      } catch (e) {
        send({ kind: 'error', where: 'fresh_trace_' + name, error: String(e) });
      }
    }
  });
}

[
  [0x0a80660, 'validate_target'],
  [0x03da70, 'alloc_filtered_vec'],
  [0x03dc60, 'grow_filtered_vec'],
  [0x00c800, 'prepare_msg_map'],
  [0x1d1170, 'insert_msg_map_entry'],
  [0x1d1650, 'make_msg_map_node'],
  [0x020800, 'get_root'],
  [0x2fbff0, 'get_service'],
  [0x36a860, 'resolve_msg_service'],
  [0xe64a70, 'enrich_msg_entries'],
  [0x6a5990, 'append_caption'],
  [0x0b44a0, 'make_aux_token'],
  [0x4c9820, 'copy_body_aux'],
  [0x00cb30, 'free_msg_map'],
  [0x0ab1e0, 'free_msg_node'],
  [0x633150, 'fresh_pair_ctor'],
  [0x633270, 'get_send_ctx'],
  [0x15e8200, 'build_one_pair_request'],
].forEach(([rva, name]) => installFreshTraceHook(rva, name));

rpc.exports.run = () => {
  Process.runOnThread(TARGET_THREAD_ID, function () {
    let stage = 'start';
    try {
      send({ kind: 'stage', stage, mode: MODE, thread_id: TARGET_THREAD_ID });

      if (MODE === 'fresh' || MODE === 'fresh-hijack1' || MODE === 'fresh-trace') {
        Process.runOnThread(TARGET_THREAD_ID, () => {
          try {
            stage = 'fresh_build_target';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const targetBuf = Memory.alloc(0x20);
            targetBuf.writeByteArray(new Uint8Array(0x20));
            writeHeapStdString(targetBuf, TARGET_CONVERSATION, wxAlloc);

            stage = 'fresh_build_entry';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const entry = Memory.alloc(0x28);
            entry.writeByteArray(new Uint8Array(0x28));
            writeHeapStdString(entry, TARGET_BODY, wxAlloc);
            entry.add(0x20).writeU32(4);
            entry.add(0x24).writeU32(0);

            stage = 'fresh_build_vector';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const vec = Memory.alloc(Process.pointerSize * 3);
            vec.writePointer(entry);
            vec.add(Process.pointerSize).writePointer(entry.add(0x28));
            vec.add(Process.pointerSize * 2).writePointer(entry.add(0x28));

            stage = 'fresh_call_ctor';
            send({
              kind: 'stage',
              stage,
              mode: MODE,
              current_thread: Process.getCurrentThreadId(),
              target_conversation: readStdString(targetBuf),
              body: readStdString(entry),
              entry_type: entry.add(0x20).readU32(),
            });
            freshHijackCapture = null;
            freshHijackTriggered = false;
            freshHijackActive = MODE === 'fresh-hijack1';
            freshTraceCounts = {};
            freshTraceActive = MODE === 'fresh-trace';
            freshSendCtor(ptr('0x0'), targetBuf, vec);
            freshHijackActive = false;
            freshTraceActive = false;

            stage = 'done';
            send({
              kind: 'autonomous_send_invoked',
              mode: MODE,
              stage,
              thread_id: TARGET_THREAD_ID,
              current_thread: Process.getCurrentThreadId(),
              rewritten: {
                conversation: readStdString(targetBuf),
                body: readStdString(entry),
              },
              fresh_hijack: freshHijackCapture,
              fresh_hijack_triggered: freshHijackTriggered,
              fresh_trace_counts: freshTraceCounts,
            });
          } catch (e) {
            freshHijackActive = false;
            freshTraceActive = false;
            send({ kind: 'invoke_error', stage, error: String(e), thread_id: TARGET_THREAD_ID, current_thread: Process.getCurrentThreadId(), mode: MODE });
          }
        });
        return { queued_threaded: true, mode: MODE, target_thread_id: TARGET_THREAD_ID, self_username: selfUsername };
      }

      if (MODE === 'fresh-pair1') {
        Process.runOnThread(TARGET_THREAD_ID, () => {
          try {
            stage = 'fresh_pair_ctor';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const pairBuf = Memory.alloc(0x10);
            pairBuf.writeByteArray(new Uint8Array(0x10));
            freshPairCtor(pairBuf);

            const sourceClone = pairBuf.readPointer();
            const ownerClone = pairBuf.add(Process.pointerSize).readPointer();
            if (sourceClone.isNull() || ownerClone.isNull()) {
              throw new Error('fresh pair ctor returned null source/owner');
            }

            stage = 'fresh_pair_rewrite';
            send({
              kind: 'stage',
              stage,
              current_thread: Process.getCurrentThreadId(),
              source: safePtrString(sourceClone),
              owner: safePtrString(ownerClone),
              field_lengths: {
                convo_len: readU32(sourceClone, 0xc0),
                body_len: readU32(sourceClone, 0x670),
                aux1_len: readU32(sourceClone, 0x48),
                aux2_len: readU32(sourceClone, 0x88),
              },
            });
            writeHeapStdString(sourceClone.add(0xb0), TARGET_CONVERSATION, wxAlloc, 31);
            writeHeapStdString(sourceClone.add(0x600), randomUuid(), wxAlloc, 47);
            writeHeapStdString(sourceClone.add(0x660), TARGET_BODY, wxAlloc);
            ownerClone.add(0x8).writeU32(7);
            ownerClone.add(0xc).writeU32(2);
            sourceClone.add(0x9c).writeU32(1);
            sourceClone.add(0xd8).writeU32(1);

            stage = 'fresh_pair_get_root';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const rootBuf = Memory.alloc(0x20);
            rootBuf.writeByteArray(new Uint8Array(0x20));
            getRoot(rootBuf);

            stage = 'fresh_pair_get_service';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const svcBuf = Memory.alloc(0x20);
            svcBuf.writeByteArray(new Uint8Array(0x20));
            getSvc(rootBuf.readPointer(), svcBuf);

            stage = 'fresh_pair_get_send_ctx';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const sendCtxBuf = Memory.alloc(0x20);
            sendCtxBuf.writeByteArray(new Uint8Array(0x20));
            getSendCtx(svcBuf.readPointer(), sendCtxBuf);
            const sendCtx = sendCtxBuf.readPointer();

            stage = 'fresh_pair_build';
            freshPairBuildTrace = [];
            freshPairBuildActive = false;
            freshPairBuildCurrent = null;
            send({
              kind: 'stage',
              stage,
              current_thread: Process.getCurrentThreadId(),
              send_ctx: safePtrString(sendCtx),
              b78: sendCtx.isNull() ? '0x0' : safePtrString(sendCtx.add(0xb78).readPointer()),
              rewritten: {
                conversation: readStdString(sourceClone.add(0xb0)),
                uuid: readStdString(sourceClone.add(0x600)),
                body: readStdString(sourceClone.add(0x660)),
              },
            });
            const resultBuf = Memory.alloc(0x60);
            resultBuf.writeByteArray(new Uint8Array(0x60));
            buildOnePairRequest(sendCtx, resultBuf, pairBuf, PAIR_MODE);

            stage = 'done';
            send({
              kind: 'autonomous_send_invoked',
              mode: MODE,
              stage,
              thread_id: TARGET_THREAD_ID,
              current_thread: Process.getCurrentThreadId(),
              fresh_pair: {
                source: safePtrString(sourceClone),
                owner: safePtrString(ownerClone),
              },
              rewritten: {
                conversation: readStdString(sourceClone.add(0xb0)),
                uuid: readStdString(sourceClone.add(0x600)),
                body: readStdString(sourceClone.add(0x660)),
              },
              build_trace: freshPairBuildTrace,
            });
          } catch (e) {
            send({ kind: 'invoke_error', stage, error: String(e), thread_id: TARGET_THREAD_ID, current_thread: Process.getCurrentThreadId(), mode: MODE });
          }
        });
        return { queued_threaded: true, mode: MODE, target_thread_id: TARGET_THREAD_ID, self_username: selfUsername };
      }

      if (MODE === 'fresh-batch1' || MODE === 'fresh-batch0') {
        Process.runOnThread(TARGET_THREAD_ID, () => {
          try {
            stage = 'fresh_batch_ctor';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const pairBuf = Memory.alloc(0x10);
            pairBuf.writeByteArray(new Uint8Array(0x10));
            freshPairCtor(pairBuf);

            const sourceClone = pairBuf.readPointer();
            const ownerClone = pairBuf.add(Process.pointerSize).readPointer();
            if (sourceClone.isNull() || ownerClone.isNull()) {
              throw new Error('fresh pair ctor returned null source/owner');
            }

            stage = 'fresh_batch_rewrite';
            send({
              kind: 'stage',
              stage,
              current_thread: Process.getCurrentThreadId(),
              source: safePtrString(sourceClone),
              owner: safePtrString(ownerClone),
            });
            writeHeapStdString(sourceClone.add(0xb0), TARGET_CONVERSATION, wxAlloc, 31);
            writeHeapStdString(sourceClone.add(0x600), randomUuid(), wxAlloc, 47);
            writeHeapStdString(sourceClone.add(0x660), TARGET_BODY, wxAlloc);
            ownerClone.add(0x8).writeU32(7);
            ownerClone.add(0xc).writeU32(2);
            sourceClone.add(0x9c).writeU32(1);
            sourceClone.add(0xd8).writeU32(MODE === 'fresh-batch0' ? 10000 : 1);

            stage = 'fresh_batch_build_vector';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const pairElem = Memory.alloc(0x10);
            pairElem.writePointer(sourceClone);
            pairElem.add(Process.pointerSize).writePointer(ownerClone);
            const vec = Memory.alloc(Process.pointerSize * 3);
            vec.writePointer(pairElem);
            vec.add(Process.pointerSize).writePointer(pairElem.add(0x10));
            vec.add(Process.pointerSize * 2).writePointer(pairElem.add(0x10));

            stage = 'fresh_batch_get_root';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const rootBuf = Memory.alloc(0x20);
            rootBuf.writeByteArray(new Uint8Array(0x20));
            getRoot(rootBuf);

            stage = 'fresh_batch_get_service';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const svcBuf = Memory.alloc(0x20);
            svcBuf.writeByteArray(new Uint8Array(0x20));
            getSvc(rootBuf.readPointer(), svcBuf);

            stage = 'fresh_batch_get_send_ctx';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const sendCtxBuf = Memory.alloc(0x20);
            sendCtxBuf.writeByteArray(new Uint8Array(0x20));
            getSendCtx(svcBuf.readPointer(), sendCtxBuf);
            const sendCtx = sendCtxBuf.readPointer();

            stage = 'fresh_batch_call';
            send({
              kind: 'stage',
              stage,
              current_thread: Process.getCurrentThreadId(),
              send_ctx: safePtrString(sendCtx),
              rewritten: {
                conversation: readStdString(sourceClone.add(0xb0)),
                uuid: readStdString(sourceClone.add(0x600)),
                body: readStdString(sourceClone.add(0x660)),
              },
            });
            const resultBuf = Memory.alloc(0x200);
            resultBuf.writeByteArray(new Uint8Array(0x200));
            buildBatchRequest(sendCtx, resultBuf, vec, MODE === 'fresh-batch0' ? 0 : 1);

            stage = 'done';
            send({
              kind: 'autonomous_send_invoked',
              mode: MODE,
              stage,
              thread_id: TARGET_THREAD_ID,
              current_thread: Process.getCurrentThreadId(),
              fresh_pair: {
                source: safePtrString(sourceClone),
                owner: safePtrString(ownerClone),
              },
              rewritten: {
                conversation: readStdString(sourceClone.add(0xb0)),
                uuid: readStdString(sourceClone.add(0x600)),
                body: readStdString(sourceClone.add(0x660)),
              },
            });
          } catch (e) {
            send({ kind: 'invoke_error', stage, error: String(e), thread_id: TARGET_THREAD_ID, current_thread: Process.getCurrentThreadId(), mode: MODE });
          }
        });
        return { queued_threaded: true, mode: MODE, target_thread_id: TARGET_THREAD_ID, self_username: selfUsername };
      }

      if (MODE === 'batch-template') {
        Process.runOnThread(TARGET_THREAD_ID, () => {
          try {
            stage = 'batch_template_clone_owner';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const ownerClone = wxAlloc(0x710);
            Memory.copy(ownerClone, TEMPLATE_OWNER, 0x710);
            rebasePointersInOwnerBlock(TEMPLATE_OWNER, ownerClone, 0x710);

            stage = 'batch_template_clone_source';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const sourceOffset = TEMPLATE_SOURCE.sub(TEMPLATE_OWNER).toInt32();
            const sourceClone = ownerClone.add(sourceOffset);
            sourceClone.add(0x8).writePointer(sourceClone);
            sourceClone.add(0x10).writePointer(ownerClone);

            stage = 'batch_template_rewrite';
            send({
              kind: 'stage',
              stage,
              current_thread: Process.getCurrentThreadId(),
              source: safePtrString(sourceClone),
              owner: safePtrString(ownerClone),
            });
            writeHeapStdString(sourceClone.add(0xb0), TARGET_CONVERSATION, wxAlloc);
            writeHeapStdString(sourceClone.add(0x660), TARGET_BODY, wxAlloc);

            stage = 'batch_template_build_vector';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const pairElem = Memory.alloc(0x10);
            pairElem.writePointer(sourceClone);
            pairElem.add(Process.pointerSize).writePointer(ownerClone);
            const vec = Memory.alloc(Process.pointerSize * 3);
            vec.writePointer(pairElem);
            vec.add(Process.pointerSize).writePointer(pairElem.add(0x10));
            vec.add(Process.pointerSize * 2).writePointer(pairElem.add(0x10));

            stage = 'batch_template_get_root';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const rootBuf = Memory.alloc(0x20);
            rootBuf.writeByteArray(new Uint8Array(0x20));
            getRoot(rootBuf);

            stage = 'batch_template_get_service';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const svcBuf = Memory.alloc(0x20);
            svcBuf.writeByteArray(new Uint8Array(0x20));
            getSvc(rootBuf.readPointer(), svcBuf);

            stage = 'batch_template_get_send_ctx';
            send({ kind: 'stage', stage, current_thread: Process.getCurrentThreadId() });
            const sendCtxBuf = Memory.alloc(0x20);
            sendCtxBuf.writeByteArray(new Uint8Array(0x20));
            getSendCtx(svcBuf.readPointer(), sendCtxBuf);
            const sendCtx = sendCtxBuf.readPointer();

            stage = 'batch_template_call';
            send({
              kind: 'stage',
              stage,
              current_thread: Process.getCurrentThreadId(),
              send_ctx: safePtrString(sendCtx),
              rewritten: {
                conversation: readStdString(sourceClone.add(0xb0)),
                uuid: readStdString(sourceClone.add(0x600)),
                body: readStdString(sourceClone.add(0x660)),
              },
            });
            const resultBuf = Memory.alloc(0x200);
            resultBuf.writeByteArray(new Uint8Array(0x200));
            buildBatchRequest(sendCtx, resultBuf, vec, 1);

            stage = 'done';
            send({
              kind: 'autonomous_send_invoked',
              mode: MODE,
              stage,
              thread_id: TARGET_THREAD_ID,
              current_thread: Process.getCurrentThreadId(),
              template_pair: {
                source: safePtrString(sourceClone),
                owner: safePtrString(ownerClone),
              },
              rewritten: {
                conversation: readStdString(sourceClone.add(0xb0)),
                uuid: readStdString(sourceClone.add(0x600)),
                body: readStdString(sourceClone.add(0x660)),
              },
            });
          } catch (e) {
            send({ kind: 'invoke_error', stage, error: String(e), thread_id: TARGET_THREAD_ID, current_thread: Process.getCurrentThreadId(), mode: MODE });
          }
        });
        return { queued_threaded: true, mode: MODE, target_thread_id: TARGET_THREAD_ID, self_username: selfUsername };
      }

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
      const originalConversation = readStdString(sourceClone.add(0xb0));
      const originalConvCap = readU32(sourceClone.add(0xb0), 0x18);
      const originalUuid = readStdString(sourceClone.add(0x600));
      const originalUuidCap = readU32(sourceClone.add(0x600), 0x18);
      const originalRefA = readU32(ownerClone, 0x8);
      const originalRefB = readU32(ownerClone, 0xc);

      if (MODE === 'builder-minimal') {
        if (TARGET_CONVERSATION !== originalConversation) {
          writeHeapStdString(sourceClone.add(0xb0), TARGET_CONVERSATION, wxAlloc, originalConvCap || 31);
        }
        writeHeapStdString(sourceClone.add(0x660), TARGET_BODY, wxAlloc);
        if (!originalUuid) {
          writeHeapStdString(sourceClone.add(0x600), randomUuid(), wxAlloc, originalUuidCap || 47);
        }
        ownerClone.add(0x8).writeU32(OWNER_REF_A_OVERRIDE !== null ? OWNER_REF_A_OVERRIDE : (originalRefA || 3));
        ownerClone.add(0xc).writeU32(OWNER_REF_B_OVERRIDE !== null ? OWNER_REF_B_OVERRIDE : (originalRefB || 2));
      } else {
        writeHeapStdString(sourceClone.add(0xb0), TARGET_CONVERSATION, wxAlloc, 31);
        writeHeapStdString(sourceClone.add(0x600), randomUuid(), wxAlloc, 47);
        writeHeapStdString(sourceClone.add(0x660), TARGET_BODY, wxAlloc);
        ownerClone.add(0x8).writeU32(OWNER_REF_A_OVERRIDE !== null ? OWNER_REF_A_OVERRIDE : 7);
        ownerClone.add(0xc).writeU32(OWNER_REF_B_OVERRIDE !== null ? OWNER_REF_B_OVERRIDE : 2);
      }
      sourceClone.add(0x9c).writeU32(1);
      sourceClone.add(0xd8).writeU32(1);

      if (MODE === 'wrapper' || MODE === 'wrapper-inplace' || MODE === 'wrapper-inplace-no-restore') {
        stage = 'clone_wrapper';
        send({ kind: 'stage', stage });
        if (TEMPLATE_WRAPPER.isNull()) {
          throw new Error('template wrapper is null');
        }
        let wrapperTarget = TEMPLATE_WRAPPER;
        let pairClone = null;
        let wrapperClone = null;
        let originalConversation = null;
        let originalBody = null;
        let originalUuid = null;
        let originalConversationCap = null;
        let originalBodyCap = null;
        let originalUuidCap = null;

        if (MODE === 'wrapper') {
          wrapperClone = wxAlloc(0x120);
          Memory.copy(wrapperClone, TEMPLATE_WRAPPER, 0x120);

          stage = 'clone_pair';
          send({ kind: 'stage', stage });
          const pairPtr = TEMPLATE_WRAPPER.add(0x8).readPointer();
          if (pairPtr.isNull()) {
            throw new Error('template wrapper pair is null');
          }
          pairClone = wxAlloc(0x10);
          Memory.copy(pairClone, pairPtr, 0x10);
          pairClone.writePointer(sourceClone);
          pairClone.add(Process.pointerSize).writePointer(ownerClone);
          wrapperClone.add(0x8).writePointer(pairClone);
          wrapperClone.add(0x10).writePointer(pairClone.add(0x10));
          wrapperClone.add(0x18).writePointer(pairClone.add(0x10));
          wrapperTarget = wrapperClone;
        } else {
          stage = 'capture_inplace_originals';
          send({ kind: 'stage', stage });
          originalConversation = readStdString(TEMPLATE_SOURCE.add(0xb0));
          originalBody = readStdString(TEMPLATE_SOURCE.add(0x660));
          originalUuid = readStdString(TEMPLATE_SOURCE.add(0x600));
          originalConversationCap = readU32(TEMPLATE_SOURCE.add(0xb0), 0x18);
          originalBodyCap = readU32(TEMPLATE_SOURCE.add(0x660), 0x18);
          originalUuidCap = readU32(TEMPLATE_SOURCE.add(0x600), 0x18);
          writeHeapStdString(TEMPLATE_SOURCE.add(0xb0), TARGET_CONVERSATION, wxAlloc, originalConversationCap || 31);
          writeHeapStdString(TEMPLATE_SOURCE.add(0x660), TARGET_BODY, wxAlloc, originalBodyCap || 15);
          writeHeapStdString(TEMPLATE_SOURCE.add(0x600), originalUuid || randomUuid(), wxAlloc, originalUuidCap || 47);
        }

        stage = 'call_top_send';
        send({ kind: 'stage', stage, wrapper_target: safePtrString(wrapperTarget), inplace: MODE !== 'wrapper' });
        try {
          topSendFn(wrapperTarget);
        } finally {
          if (MODE === 'wrapper-inplace') {
            stage = 'restore_inplace_originals';
            send({ kind: 'stage', stage });
            writeHeapStdString(TEMPLATE_SOURCE.add(0xb0), originalConversation || '', wxAlloc, originalConversationCap || 31);
            writeHeapStdString(TEMPLATE_SOURCE.add(0x660), originalBody || '', wxAlloc, originalBodyCap || 15);
            writeHeapStdString(TEMPLATE_SOURCE.add(0x600), originalUuid || '', wxAlloc, originalUuidCap || 47);
          }
        }

        stage = 'done';
        send({
          kind: 'autonomous_send_invoked',
          mode: MODE,
          stage,
          thread_id: TARGET_THREAD_ID,
          source_offset: sourceOffset,
          rewritten: {
            conversation: readStdString(sourceClone.add(0xb0)),
            uuid: readStdString(sourceClone.add(0x600)),
            body: readStdString(sourceClone.add(0x660)),
          },
          wrapper_clone: safePtrString(wrapperClone),
          wrapper_target: safePtrString(wrapperTarget),
        });
        return;
      }

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
      const sendCtx = sendCtxBuf.readPointer();

      stage = 'call_builder';
      send({ kind: 'stage', stage, send_ctx: safePtrString(sendCtx), b78: safePtrString(sendCtx.add(0xb78).readPointer()) });
      freshPairBuildTrace = [];
      freshPairBuildActive = false;
      freshPairBuildCurrent = null;
      freshPairEbec0Index = 0;
      buildOnePairRequest(sendCtx, resultBuf, pairBuf, PAIR_MODE);

      if (MODE === 'tail-schedule') {
        stage = 'alloc_task';
        send({ kind: 'stage', stage });
        const taskObj = wxAlloc(0x158);
        taskObj.writeByteArray(new Uint8Array(0x158));

        stage = 'init_task_call';
        send({ kind: 'stage', stage });
        initTask(taskObj, mod.base.add(0x15afcd0), mod.base.add(0x15afe50));

        stage = 'copy_meta_prepare';
        send({ kind: 'stage', stage });
        const emptyMeta = Memory.alloc(0xd0);
        emptyMeta.writeByteArray(new Uint8Array(0xd0));

        stage = 'copy_meta_call';
        send({ kind: 'stage', stage });
        copyMeta(taskObj.add(0x28), emptyMeta);

        stage = 'copy_payload_call';
        send({ kind: 'stage', stage });
        copyTaskPayload(taskObj.add(0x110), resultBuf);

        stage = 'init_sched_ctx_alloc';
        send({ kind: 'stage', stage });
        const schedCtx = Memory.alloc(0x20);
        schedCtx.writeByteArray(new Uint8Array(0x20));

        stage = 'init_sched_ctx_call';
        send({ kind: 'stage', stage });
        initScheduleCtx(schedCtx, mod.base.add(0x7dc727f), mod.base.add(0x81207c4), 0x1f9);

        stage = 'schedule_holder_alloc';
        send({ kind: 'stage', stage });
        const holder = Memory.alloc(Process.pointerSize);
        holder.writePointer(taskObj);

        stage = 'schedule_call';
        send({ kind: 'stage', stage });
        const scheduleResult = scheduleTask(schedCtx, holder, ptr('0x0'), 0);

        stage = 'done';
        send({
          kind: 'autonomous_send_invoked',
          mode: MODE,
          stage,
          thread_id: TARGET_THREAD_ID,
          source_offset: sourceOffset,
          schedule_result: scheduleResult,
          task_obj: safePtrString(taskObj),
          rewritten: {
            conversation: readStdString(sourceClone.add(0xb0)),
            uuid: readStdString(sourceClone.add(0x600)),
            body: readStdString(sourceClone.add(0x660)),
          },
        });
        return;
      }

      stage = 'done';
      send({
        kind: 'autonomous_send_invoked',
        mode: MODE,
        stage,
        thread_id: TARGET_THREAD_ID,
        source_offset: sourceOffset,
        rewritten: {
          conversation: readStdString(sourceClone.add(0xb0)),
          uuid: readStdString(sourceClone.add(0x600)),
          body: readStdString(sourceClone.add(0x660)),
        },
      });
    } catch (e) {
      send({ kind: 'invoke_error', stage, error: String(e), thread_id: TARGET_THREAD_ID, mode: MODE });
    }
  });
  return { queued: true, mode: MODE, target_thread_id: TARGET_THREAD_ID, self_username: selfUsername };
};

rpc.exports.getstate = () => {
  return {
    self_username: selfUsername,
    fresh_hijack_capture: freshHijackCapture,
    fresh_trace_counts: freshTraceCounts,
    fresh_pair_build_trace: freshPairBuildTrace,
    task_event: capturedTaskEvent,
    manager_event: capturedManagerEvent,
  };
};
"""


EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.EnumWindows.argtypes = [EnumWindowsProc, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD


def find_weixin_main_window():
    results = []

    @EnumWindowsProc
    def callback(hwnd, lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, len(buf))
        title = buf.value
        if not title:
            return True
        pid_out = wintypes.DWORD(0)
        tid = user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_out))
        results.append({
            "hwnd": hwnd,
            "pid": pid_out.value,
            "thread_id": tid,
            "title": title,
        })
        return True

    if not user32.EnumWindows(callback, 0):
        raise OSError(ctypes.get_last_error())

    for item in results:
        if item["title"] == "WeChat":
            return item
    if results:
        return results[0]
    raise RuntimeError("No visible WeChat window found")


def parse_seed_from_log(path: Path):
    if not path.exists():
        raise FileNotFoundError(str(path))
    last_seed = None
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if "seed_captured" not in line:
                continue
            try:
                payload = ast.literal_eval(line)
            except Exception:
                continue
            if isinstance(payload, dict) and payload.get("kind") == "seed_captured":
                last_seed = payload.get("pending")
    if not last_seed:
        raise RuntimeError(f"No seed_captured entry found in {path}")
    return last_seed


def default_seed_log() -> Path:
    temp = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "Temp"
    candidates = [
        temp / "weixin_hijack_lower_send_builder_only_out.txt",
        temp / "weixin_hijack_lower_send_out4.txt",
        temp / "weixin_hijack_lower_send_out3.txt",
        temp / "weixin_hijack_lower_send_out2.txt",
        temp / "weixin_hijack_lower_send_out.txt",
    ]
    for path in candidates:
        if path.exists():
            return path
    raise RuntimeError("No lower-send log file found in temp directory")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int)
    parser.add_argument("--thread-id", type=int)
    parser.add_argument("--mode", choices=["builder", "builder-minimal", "tail-schedule", "wrapper", "wrapper-inplace", "wrapper-inplace-no-restore", "fresh", "fresh-hijack1", "fresh-trace", "fresh-pair1", "fresh-batch1", "fresh-batch0", "batch-template"], default="fresh")
    parser.add_argument("--template-wrapper")
    parser.add_argument("--template-source")
    parser.add_argument("--template-owner")
    parser.add_argument("--seed-log")
    parser.add_argument("--conversation-id", default="27208021116@chatroom")
    parser.add_argument("--body", default="skynet")
    parser.add_argument("--wait-ms", type=int, default=5000)
    parser.add_argument("--pair-mode", type=int, default=1)
    parser.add_argument("--ebec0-fix-json")
    parser.add_argument("--ebec0-fix-file")
    parser.add_argument("--owner-ref-a", type=int)
    parser.add_argument("--owner-ref-b", type=int)
    args = parser.parse_args()

    window = find_weixin_main_window()
    pid = args.pid or window["pid"]
    thread_id = args.thread_id or window["thread_id"]

    template_wrapper = args.template_wrapper
    template_source = args.template_source
    template_owner = args.template_owner
    seed = None
    if args.mode in ("builder", "builder-minimal", "wrapper", "wrapper-inplace", "wrapper-inplace-no-restore"):
      if not template_wrapper or not template_source or not template_owner:
        seed_log = Path(args.seed_log) if args.seed_log else default_seed_log()
        seed = parse_seed_from_log(seed_log)
        template_wrapper = template_wrapper or seed.get("wrapper")
        template_source = template_source or seed["sourceObj"]
        template_owner = template_owner or seed["ownerBase"]

    ebec0_fix_json = None
    ebec0_fix_source = None
    if args.ebec0_fix_file:
        ebec0_fix_source = Path(args.ebec0_fix_file).read_text(encoding="utf-8")
    elif args.ebec0_fix_json:
        ebec0_fix_source = args.ebec0_fix_json

    if ebec0_fix_source:
        try:
            ebec0_fix_json = json.loads(ebec0_fix_source)
        except json.JSONDecodeError:
            ebec0_fix_json = ast.literal_eval(ebec0_fix_source)

    device = frida.get_local_device()
    session = device.attach(pid)
    rendered = (
        SCRIPT
        .replace("{{MODE_JSON}}", json.dumps(args.mode))
        .replace("{{TEMPLATE_WRAPPER_EXPR}}", f"ptr({json.dumps(template_wrapper)})" if template_wrapper else "ptr('0x0')")
        .replace("{{TEMPLATE_SOURCE_JSON}}", json.dumps(template_source or "0x0"))
        .replace("{{TEMPLATE_OWNER_JSON}}", json.dumps(template_owner or "0x0"))
        .replace("{{TARGET_CONVERSATION_JSON}}", json.dumps(args.conversation_id))
        .replace("{{TARGET_BODY_JSON}}", json.dumps(args.body))
        .replace("{{TARGET_THREAD_ID}}", str(thread_id))
        .replace("{{PAIR_MODE}}", str(args.pair_mode))
        .replace("{{EBECO_FIX_JSON}}", json.dumps(ebec0_fix_json) if ebec0_fix_json is not None else "null")
        .replace("{{OWNER_REF_A_JSON}}", json.dumps(args.owner_ref_a))
        .replace("{{OWNER_REF_B_JSON}}", json.dumps(args.owner_ref_b))
    )
    script = session.create_script(rendered)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()

    meta = {
        "pid": pid,
        "thread_id": thread_id,
        "mode": args.mode,
        "window_title": window["title"],
        "template_wrapper": template_wrapper,
        "template_source": template_source,
        "template_owner": template_owner,
        "seed": seed,
        "target_conversation": args.conversation_id,
        "target_body": args.body,
        "pair_mode": args.pair_mode,
        "ebec0_fix_json": ebec0_fix_json,
        "owner_ref_a": args.owner_ref_a,
        "owner_ref_b": args.owner_ref_b,
    }
    print(json.dumps({"kind": "host_meta", "meta": meta}, ensure_ascii=False))
    result = script.exports_sync.run()
    print(json.dumps({"kind": "run_result", "result": result}, ensure_ascii=False))
    time.sleep(args.wait_ms / 1000.0)
    try:
        final_state = script.exports_sync.getstate()
        print(json.dumps({"kind": "final_state", "state": final_state}, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({"kind": "final_state_error", "error": str(e)}, ensure_ascii=False))
    try:
        session.detach()
    except Exception as e:
        print(json.dumps({"kind": "detach_error", "error": str(e)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
