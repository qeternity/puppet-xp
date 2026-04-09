#!/usr/bin/env python
import argparse
import json
import sys
import threading
import time

import frida


SCRIPT = r"""
const BASELINE_SECONDS = {{BASELINE_SECONDS}};

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

const mod = Process.getModuleByName('Weixin.dll');
const topSendFn = new NativeFunction(mod.base.add(0x15af8e0), 'void', ['pointer']);
const wxAlloc = new NativeFunction(mod.base.add(0x6309d1c), 'pointer', ['ulong']);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);

let templateState = null;
let listener = null;

function cloneLiveWrapper(wrapper, sourceObj, ownerBase) {
  const wrapperClone = wxAlloc(0x120);
  Memory.copy(wrapperClone, wrapper, 0x120);

  const pairClone = wxAlloc(0x10);
  Memory.copy(pairClone, wrapper.add(0x8).readPointer(), 0x10);

  const ownedClone = wxAlloc(0x710);
  Memory.copy(ownedClone, ownerBase, 0x710);

  const sourceOffset = sourceObj.sub(ownerBase).toInt32();
  const sourceClone = ownedClone.add(sourceOffset);
  sourceClone.add(0x8).writePointer(sourceClone);
  sourceClone.add(0x10).writePointer(ownedClone);

  pairClone.writePointer(sourceClone);
  pairClone.add(Process.pointerSize).writePointer(ownedClone);

  wrapperClone.add(0x8).writePointer(pairClone);
  wrapperClone.add(0x10).writePointer(pairClone.add(0x10));
  wrapperClone.add(0x18).writePointer(pairClone.add(0x10));

  return { wrapperClone, pairClone, ownedClone, sourceClone, sourceOffset };
}

function cloneTemplate(template) {
  const wrapperClone = wxAlloc(0x120);
  Memory.copy(wrapperClone, ptr(template.wrapper), 0x120);

  const pairClone = wxAlloc(0x10);
  Memory.copy(pairClone, ptr(template.pair), 0x10);

  const ownedClone = wxAlloc(0x710);
  Memory.copy(ownedClone, ptr(template.owner), 0x710);

  const sourceClone = ownedClone.add(template.source_offset);
  sourceClone.add(0x8).writePointer(sourceClone);
  sourceClone.add(0x10).writePointer(ownedClone);

  pairClone.writePointer(sourceClone);
  pairClone.add(Process.pointerSize).writePointer(ownedClone);

  wrapperClone.add(0x8).writePointer(pairClone);
  wrapperClone.add(0x10).writePointer(pairClone.add(0x10));
  wrapperClone.add(0x18).writePointer(pairClone.add(0x10));

  return { wrapperClone, pairClone, ownedClone, sourceClone };
}

listener = Interceptor.attach(mod.base.add(0x15af8e0), {
  onEnter(args) {
    try {
      if (Date.now() < baselineUntil) return;
      const wrapper = args[0];
      const vec = readVector(wrapper.add(0x8));
      if (!vec || vec.count < 1) return;

      const pair = vec.begin;
      const sourceObj = pair.readPointer();
      const ownerBase = pair.add(Process.pointerSize).readPointer();
      if (sourceObj.isNull() || ownerBase.isNull()) return;

      const captured = cloneLiveWrapper(wrapper, sourceObj, ownerBase);
      templateState = {
        wrapper: safePtrString(captured.wrapperClone),
        pair: safePtrString(captured.pairClone),
        owner: safePtrString(captured.ownedClone),
        source: safePtrString(captured.sourceClone),
        source_offset: captured.sourceOffset,
        seed_conversation: readStdString(sourceObj.add(0xb0)),
        seed_body: readStdString(sourceObj.add(0x660)),
        seed_uuid: readStdString(sourceObj.add(0x600)),
      };

      send({
        kind: 'template_captured',
        template: templateState,
      });

      if (listener !== null) {
        listener.detach();
        listener = null;
        send({ kind: 'template_listener_detached' });
      }
    } catch (e) {
      send({ kind: 'error', where: 'capture_hook', error: String(e) });
    }
  }
});

rpc.exports = {
  hastemplate() {
    return templateState !== null;
  },
  gettemplate() {
    if (templateState === null) return null;
    return templateState;
  },
  sendtext(conversationId, body) {
    if (templateState === null) {
      throw new Error('template not captured');
    }
    const fresh = cloneTemplate(templateState);
    writeHeapStdString(fresh.sourceClone.add(0xb0), conversationId, wxAlloc);
    writeHeapStdString(fresh.sourceClone.add(0x660), body, wxAlloc);

    const result = {
      wrapper: safePtrString(fresh.wrapperClone),
      source: safePtrString(fresh.sourceClone),
      conversation: readStdString(fresh.sourceClone.add(0xb0)),
      body: readStdString(fresh.sourceClone.add(0x660)),
      uuid: readStdString(fresh.sourceClone.add(0x600)),
    };

    send({ kind: 'template_send_invoking', payload: result });
    topSendFn(fresh.wrapperClone);
    return result;
  }
};

send({
  kind: 'status',
  target_fn: mod.base.add(0x15af8e0).toString(),
  baseline_seconds: BASELINE_SECONDS,
});
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--conversation-id", required=True)
    parser.add_argument("--body", required=True)
    parser.add_argument("--baseline-seconds", type=int, default=2)
    parser.add_argument("--wait-seed-seconds", type=int, default=120)
    args = parser.parse_args()

    device = frida.get_local_device()
    session = device.attach(args.pid)
    rendered = SCRIPT.replace("{{BASELINE_SECONDS}}", str(args.baseline_seconds))
    script = session.create_script(rendered)

    template_captured = threading.Event()

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.buffer.write((str(payload) + "\n").encode("utf-8", errors="replace"))
        sys.stdout.flush()
        if isinstance(payload, dict) and payload.get("kind") == "template_captured":
            template_captured.set()

    script.on("message", on_message)
    script.load()
    sys.stdout.buffer.write((f"attached pid={args.pid}\n").encode("utf-8"))
    sys.stdout.flush()

    if not template_captured.wait(args.wait_seed_seconds):
        raise SystemExit("timed out waiting for seed send / template capture")

    result = script.exports_sync.sendtext(args.conversation_id, args.body)
    sys.stdout.buffer.write((f"sendtext_result={json.dumps(result)}\n").encode("utf-8", errors="replace"))
    sys.stdout.flush()

    time.sleep(5)


if __name__ == "__main__":
    main()
