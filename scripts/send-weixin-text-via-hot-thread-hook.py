#!/usr/bin/env python
import argparse
import json
import sys
import time

import frida


SCRIPT = r"""
const TARGET_RVA = {{TARGET_RVA}};
const TARGET_CONVERSATION = {{TARGET_CONVERSATION_JSON}};
const TARGET_BODY = {{TARGET_BODY_JSON}};
const TEMPLATE_SOURCE = ptr({{TEMPLATE_SOURCE_JSON}});
const TEMPLATE_OWNER = ptr({{TEMPLATE_OWNER_JSON}});
const OWNER_BLOCK_SIZE = 0x710;
const SNAPSHOT_HEX = {{SNAPSHOT_HEX_JSON}};
const SNAPSHOT_SOURCE_OFFSET = {{SNAPSHOT_SOURCE_OFFSET_JSON}};
const SNAPSHOT_CONVERSATION = {{SNAPSHOT_CONVERSATION_JSON}};
const SNAPSHOT_UUID = {{SNAPSHOT_UUID_JSON}};
const SNAPSHOT_CONV_CAP = {{SNAPSHOT_CONV_CAP_JSON}};
const SNAPSHOT_REF_A = {{SNAPSHOT_REF_A_JSON}};
const SNAPSHOT_REF_B = {{SNAPSHOT_REF_B_JSON}};

const mod = Process.getModuleByName('Weixin.dll');

function safe(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (_) {
    return '0x0';
  }
}

function readU32(base, off) {
  try { return base.add(off).readU32(); } catch (_) { return null; }
}

function readStdString(addr) {
  try {
    const len = addr.add(0x10).readU32();
    const cap = addr.add(0x18).readU32();
    if (len === 0) return '';
    if (len > 0x4000 || cap > 0x100000) return null;
    let dataPtr = addr;
    if (cap > 15) dataPtr = addr.readPointer();
    if (!dataPtr || dataPtr.isNull()) return null;
    return dataPtr.readUtf8String(len);
  } catch (_) {
    return null;
  }
}

function writeHeapStdString(addr, value, wxAlloc, forcedCap) {
  const utf8 = Array.from(value).map(ch => ch.charCodeAt(0));
  if (utf8.length <= 15) {
    addr.writeByteArray(new Uint8Array(16));
    for (let i = 0; i < utf8.length; i++) addr.add(i).writeU8(utf8[i]);
    addr.add(utf8.length).writeU8(0);
    addr.add(0x10).writeU32(utf8.length);
    addr.add(0x14).writeU32(0);
    addr.add(0x18).writeU32(15);
    addr.add(0x1c).writeU32(0);
    return;
  }
  const cap = forcedCap || utf8.length;
  const buf = wxAlloc(cap + 1);
  for (let i = 0; i < utf8.length; i++) buf.add(i).writeU8(utf8[i]);
  buf.add(utf8.length).writeU8(0);
  addr.writeByteArray(new Uint8Array(16));
  addr.writePointer(buf);
  addr.add(0x10).writeU32(utf8.length);
  addr.add(0x14).writeU32(0);
  addr.add(0x18).writeU32(cap);
  addr.add(0x1c).writeU32(0);
}

function hexToBytes(hex) {
  if (!hex) return null;
  const len = hex.length / 2;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
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
    } catch (_) {}
  }
}

const wxAlloc = new NativeFunction(mod.base.add(0x6309d1c), 'pointer', ['ulong']);
const getRoot = new NativeFunction(mod.base.add(0x20800), 'pointer', ['pointer']);
const getSvc = new NativeFunction(mod.base.add(0x2fbff0), 'void', ['pointer', 'pointer']);
const getSendCtx = new NativeFunction(mod.base.add(0x633270), 'pointer', ['pointer', 'pointer']);
const buildOnePairRequest = new NativeFunction(mod.base.add(0x15e8200), 'pointer', ['pointer', 'pointer', 'pointer', 'uint']);

const TEMPLATE_SOURCE_OFFSET = SNAPSHOT_SOURCE_OFFSET !== null ? SNAPSHOT_SOURCE_OFFSET : TEMPLATE_SOURCE.sub(TEMPLATE_OWNER).toInt32();
const SNAPSHOT_BYTES = SNAPSHOT_HEX ? hexToBytes(SNAPSHOT_HEX) : new Uint8Array(TEMPLATE_OWNER.readByteArray(OWNER_BLOCK_SIZE));
const LIVE_UUID = readStdString(TEMPLATE_SOURCE.add(0x600));
const LIVE_CONVERSATION = readStdString(TEMPLATE_SOURCE.add(0xb0));
const LIVE_CONV_CAP = readU32(TEMPLATE_SOURCE.add(0xb0), 0x18);
const LIVE_REF_A = readU32(TEMPLATE_OWNER, 0x8);
const LIVE_REF_B = readU32(TEMPLATE_OWNER, 0xc);
const EFFECTIVE_UUID = SNAPSHOT_UUID !== null ? SNAPSHOT_UUID : LIVE_UUID;
const EFFECTIVE_CONVERSATION = SNAPSHOT_CONVERSATION !== null ? SNAPSHOT_CONVERSATION : LIVE_CONVERSATION;
const EFFECTIVE_CONV_CAP = SNAPSHOT_CONV_CAP !== null ? SNAPSHOT_CONV_CAP : LIVE_CONV_CAP;
const EFFECTIVE_REF_A = SNAPSHOT_REF_A !== null ? SNAPSHOT_REF_A : LIVE_REF_A;
const EFFECTIVE_REF_B = SNAPSHOT_REF_B !== null ? SNAPSHOT_REF_B : LIVE_REF_B;

let fired = false;
let invoking = false;

Interceptor.attach(mod.base.add(TARGET_RVA), {
  onEnter(args) {
    if (fired || invoking) return;
    invoking = true;
    try {
      const ownerClone = wxAlloc(0x710);
      ownerClone.writeByteArray(SNAPSHOT_BYTES);
      rebasePointersInOwnerBlock(TEMPLATE_OWNER, ownerClone, OWNER_BLOCK_SIZE);
      const sourceClone = ownerClone.add(TEMPLATE_SOURCE_OFFSET);
      sourceClone.add(0x8).writePointer(sourceClone);
      sourceClone.add(0x10).writePointer(ownerClone);
      if (EFFECTIVE_REF_A !== null) ownerClone.add(0x8).writeU32(EFFECTIVE_REF_A);
      if (EFFECTIVE_REF_B !== null) ownerClone.add(0xc).writeU32(EFFECTIVE_REF_B);

      const originalConversation = EFFECTIVE_CONVERSATION;
      const originalConvCap = EFFECTIVE_CONV_CAP;
      if (TARGET_CONVERSATION !== originalConversation) {
        writeHeapStdString(sourceClone.add(0xb0), TARGET_CONVERSATION, wxAlloc, originalConvCap || 31);
      } else if (originalConversation) {
        writeHeapStdString(sourceClone.add(0xb0), originalConversation, wxAlloc, originalConvCap || 31);
      }
      if (EFFECTIVE_UUID) {
        writeHeapStdString(sourceClone.add(0x600), EFFECTIVE_UUID, wxAlloc, 47);
      }
      writeHeapStdString(sourceClone.add(0x660), TARGET_BODY, wxAlloc);
      sourceClone.add(0x9c).writeU32(1);
      sourceClone.add(0xd8).writeU32(1);

      const pairBuf = wxAlloc(0x10);
      pairBuf.writePointer(sourceClone);
      pairBuf.add(Process.pointerSize).writePointer(ownerClone);

      const resultBuf = Memory.alloc(0x60);
      resultBuf.writeByteArray(new Uint8Array(0x60));

      const rootBuf = Memory.alloc(0x20);
      rootBuf.writeByteArray(new Uint8Array(0x20));
      getRoot(rootBuf);

      const svcBuf = Memory.alloc(0x20);
      svcBuf.writeByteArray(new Uint8Array(0x20));
      getSvc(rootBuf.readPointer(), svcBuf);

      const sendCtxBuf = Memory.alloc(0x20);
      sendCtxBuf.writeByteArray(new Uint8Array(0x20));
      getSendCtx(svcBuf.readPointer(), sendCtxBuf);
      const sendCtx = sendCtxBuf.readPointer();

      send({
        kind: 'hot_hook_before',
        thread_id: Process.getCurrentThreadId(),
        hook_rva: '0x' + TARGET_RVA.toString(16),
        send_ctx: safe(sendCtx),
        pair_ptr: safe(pairBuf),
        source_ptr: safe(sourceClone),
        owner_ptr: safe(ownerClone),
        conversation: readStdString(sourceClone.add(0xb0)),
        body: readStdString(sourceClone.add(0x660)),
        uuid: readStdString(sourceClone.add(0x600)),
        owner_ref_a: readU32(ownerClone, 0x8),
        owner_ref_b: readU32(ownerClone, 0xc),
      });

      buildOnePairRequest(sendCtx, resultBuf, pairBuf, 1);

      send({
        kind: 'hot_hook_after',
        thread_id: Process.getCurrentThreadId(),
        result_buf: safe(resultBuf),
        result_q20: readU32(resultBuf, 0x20),
        result_q28: safe(resultBuf.add(0x28).readPointer()),
        result_q30: safe(resultBuf.add(0x30).readPointer()),
        result_q38: safe(resultBuf.add(0x38).readPointer()),
      });
      fired = true;
    } catch (e) {
      send({ kind: 'hot_hook_error', thread_id: Process.getCurrentThreadId(), error: String(e) });
    } finally {
      invoking = false;
    }
  }
});

send({ kind: 'armed', hook_rva: '0x' + TARGET_RVA.toString(16) });
send({
  kind: 'template_snapshot',
  source_offset: TEMPLATE_SOURCE_OFFSET,
  conversation: EFFECTIVE_CONVERSATION,
  uuid: EFFECTIVE_UUID,
  ref_a: EFFECTIVE_REF_A,
  ref_b: EFFECTIVE_REF_B,
});
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--hook-rva", required=True, help="Hex RVA like 0xbd3ad0")
    parser.add_argument("--template-source", required=True)
    parser.add_argument("--template-owner", required=True)
    parser.add_argument("--conversation-id", required=True)
    parser.add_argument("--body", required=True)
    parser.add_argument("--snapshot-hex")
    parser.add_argument("--snapshot-source-offset", type=int)
    parser.add_argument("--snapshot-conversation")
    parser.add_argument("--snapshot-uuid")
    parser.add_argument("--snapshot-conv-cap", type=int)
    parser.add_argument("--snapshot-ref-a", type=int)
    parser.add_argument("--snapshot-ref-b", type=int)
    parser.add_argument("--wait-ms", type=int, default=12000)
    args = parser.parse_args()

    hook_rva = int(args.hook_rva, 16)

    device = frida.get_local_device()
    session = device.attach(args.pid)
    source = (
        SCRIPT
        .replace("{{TARGET_RVA}}", str(hook_rva))
        .replace("{{TARGET_CONVERSATION_JSON}}", json.dumps(args.conversation_id))
        .replace("{{TARGET_BODY_JSON}}", json.dumps(args.body))
        .replace("{{TEMPLATE_SOURCE_JSON}}", json.dumps(args.template_source))
        .replace("{{TEMPLATE_OWNER_JSON}}", json.dumps(args.template_owner))
        .replace("{{SNAPSHOT_HEX_JSON}}", json.dumps(args.snapshot_hex))
        .replace("{{SNAPSHOT_SOURCE_OFFSET_JSON}}", json.dumps(args.snapshot_source_offset))
        .replace("{{SNAPSHOT_CONVERSATION_JSON}}", json.dumps(args.snapshot_conversation))
        .replace("{{SNAPSHOT_UUID_JSON}}", json.dumps(args.snapshot_uuid))
        .replace("{{SNAPSHOT_CONV_CAP_JSON}}", json.dumps(args.snapshot_conv_cap))
        .replace("{{SNAPSHOT_REF_A_JSON}}", json.dumps(args.snapshot_ref_a))
        .replace("{{SNAPSHOT_REF_B_JSON}}", json.dumps(args.snapshot_ref_b))
    )
    script = session.create_script(source)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    print(json.dumps({"kind": "host_meta", "pid": args.pid, "hook_rva": hex(hook_rva), "conversation": args.conversation_id, "body": args.body}, ensure_ascii=False), flush=True)
    time.sleep(args.wait_ms / 1000.0)
    try:
        session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
