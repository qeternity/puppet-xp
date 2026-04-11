#!/usr/bin/env python
import argparse
import json
import sys
import threading

import frida


SCRIPT = r"""
const TARGET_THREAD_ID = {{TARGET_THREAD_ID}};
const TEMPLATE_SOURCE = ptr({{TEMPLATE_SOURCE_JSON}});
const TEMPLATE_OWNER = ptr({{TEMPLATE_OWNER_JSON}});
const TARGET_CONVERSATION = {{TARGET_CONVERSATION_JSON}};
const TARGET_BODY = {{TARGET_BODY_JSON}};
const BASELINE_MS = {{BASELINE_MS}};

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
const user32 = Process.getModuleByName('user32.dll');
const wxAlloc = new NativeFunction(mod.base.add(0x6309d1c), 'pointer', ['ulong']);
const getRoot = new NativeFunction(mod.base.add(0x20800), 'pointer', ['pointer']);
const getSvc = new NativeFunction(mod.base.add(0x2fbff0), 'void', ['pointer', 'pointer']);
const getSendCtx = new NativeFunction(mod.base.add(0x633270), 'pointer', ['pointer', 'pointer']);
const buildOnePairRequest = new NativeFunction(mod.base.add(0x15e8200), 'pointer', ['pointer', 'pointer', 'pointer', 'uint']);

const dispatchMessage = user32.getExportByName('DispatchMessageW');
const baselineUntil = Date.now() + BASELINE_MS;
let fired = false;
let invoking = false;
let lastStage = null;

Interceptor.attach(dispatchMessage, {
  onEnter(args) {
    try {
      if (invoking || fired) return;
      if (Date.now() < baselineUntil) return;
      if (Process.getCurrentThreadId() !== TARGET_THREAD_ID) return;

      invoking = true;
      const trail = [];
      const mark = (stage, extra) => {
        lastStage = stage;
        trail.push({ stage, extra: extra || null });
      };

      mark('clone_owner');
      const ownerClone = wxAlloc(0x710);
      Memory.copy(ownerClone, TEMPLATE_OWNER, 0x710);
      rebasePointersInOwnerBlock(TEMPLATE_OWNER, ownerClone, 0x710);

      mark('clone_source');
      const sourceOffset = TEMPLATE_SOURCE.sub(TEMPLATE_OWNER).toInt32();
      const sourceClone = ownerClone.add(sourceOffset);
      sourceClone.add(0x8).writePointer(sourceClone);
      sourceClone.add(0x10).writePointer(ownerClone);

      mark('rewrite');
      writeHeapStdString(sourceClone.add(0xb0), TARGET_CONVERSATION, wxAlloc);
      writeHeapStdString(sourceClone.add(0x660), TARGET_BODY, wxAlloc);

      mark('build_pair');
      const pairBuf = wxAlloc(0x10);
      pairBuf.writePointer(sourceClone);
      pairBuf.add(Process.pointerSize).writePointer(ownerClone);

      mark('get_root');
      const rootBuf = Memory.alloc(0x20);
      rootBuf.writeByteArray(new Uint8Array(0x20));
      getRoot(rootBuf);

      mark('get_service');
      const svcBuf = Memory.alloc(0x20);
      svcBuf.writeByteArray(new Uint8Array(0x20));
      getSvc(rootBuf.readPointer(), svcBuf);

      mark('get_send_ctx');
      const sendCtxBuf = Memory.alloc(0x20);
      sendCtxBuf.writeByteArray(new Uint8Array(0x20));
      getSendCtx(svcBuf.readPointer(), sendCtxBuf);
      const sendCtx = sendCtxBuf.readPointer();

      mark('call_builder_prepare', {
        send_ctx: safePtrString(sendCtx),
        b78: safePtrString(sendCtx.add(0xb78).readPointer()),
        conversation: readStdString(sourceClone.add(0xb0)),
        body: readStdString(sourceClone.add(0x660)),
      });
      const resultBuf = Memory.alloc(0x60);
      resultBuf.writeByteArray(new Uint8Array(0x60));

      mark('call_builder');
      buildOnePairRequest(sendCtx, resultBuf, pairBuf, 1);
      fired = true;
      send({ kind: 'autonomous_done', trail });
    } catch (e) {
      send({ kind: 'invoke_error', stage: lastStage, error: String(e) });
    } finally {
      invoking = false;
    }
  }
});

send({
  kind: 'status',
  target_thread_id: TARGET_THREAD_ID,
  target_conversation: TARGET_CONVERSATION,
  target_body: TARGET_BODY,
  template_source: safePtrString(TEMPLATE_SOURCE),
  template_owner: safePtrString(TEMPLATE_OWNER),
});
setTimeout(() => send({ kind: 'armed' }), BASELINE_MS);
setInterval(() => send({ kind: 'heartbeat', fired, stage: lastStage }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--thread-id", type=int, required=True)
    parser.add_argument("--template-source", required=True)
    parser.add_argument("--template-owner", required=True)
    parser.add_argument("--conversation-id", required=True)
    parser.add_argument("--body", required=True)
    parser.add_argument("--baseline-ms", type=int, default=1500)
    args = parser.parse_args()

    device = frida.get_local_device()
    session = device.attach(args.pid)
    rendered = (
        SCRIPT
        .replace("{{TARGET_THREAD_ID}}", str(args.thread_id))
        .replace("{{TEMPLATE_SOURCE_JSON}}", json.dumps(args.template_source))
        .replace("{{TEMPLATE_OWNER_JSON}}", json.dumps(args.template_owner))
        .replace("{{TARGET_CONVERSATION_JSON}}", json.dumps(args.conversation_id))
        .replace("{{TARGET_BODY_JSON}}", json.dumps(args.body))
        .replace("{{BASELINE_MS}}", str(args.baseline_ms))
    )
    script = session.create_script(rendered)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    print(json.dumps({"kind": "host_meta", "pid": args.pid, "thread_id": args.thread_id}, ensure_ascii=False), flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
