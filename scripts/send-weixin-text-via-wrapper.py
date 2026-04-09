#!/usr/bin/env python
import argparse
import json
import sys

import frida


SCRIPT = r"""
const TARGET_USERNAME = {{TARGET_USERNAME_JSON}};
const BODY = {{BODY_JSON}};
const MODE = {{MODE_JSON}};
const WAIT_MS = {{WAIT_MS}};

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
  const data = Memory.allocUtf8String(value);
  const len = Array.from(value).length;
  if (len <= 15) {
    addr.writeByteArray(new Uint8Array(16));
    Memory.copy(addr, data, len + 1);
    addr.add(0x10).writeU32(len);
    addr.add(0x14).writeU32(0);
    addr.add(0x18).writeU32(15);
    addr.add(0x1c).writeU32(0);
    return;
  }

  const buf = wxAlloc(len + 1);
  Memory.copy(buf, data, len + 1);
  addr.writeByteArray(new Uint8Array(16));
  addr.writePointer(buf);
  addr.add(0x10).writeU32(len);
  addr.add(0x14).writeU32(0);
  addr.add(0x18).writeU32(len);
  addr.add(0x1c).writeU32(0);
}

function looksLikeMsgsource(s) {
  return !!s && s.indexOf('<msgsource') === 0;
}

function isConversationId(s) {
  if (!s) return false;
  return s.indexOf('@chatroom') >= 0 || s.indexOf('wxid_') === 0 || s === 'filehelper' || s === 'weixin';
}

function plausibleBody(s) {
  if (!s) return false;
  if (s.length < 1 || s.length > 4096) return false;
  if (looksLikeMsgsource(s)) return false;
  if (isConversationId(s)) return false;
  return /^[\x20-\x7e\u00a0-\uffff\r\n\t]+$/.test(s);
}

function safePtrString(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (e) {
    return '0x0';
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

const mod = Process.getModuleByName('Weixin.dll');
const selfUsername = getSelfUsername(mod);

const wxAlloc = new NativeFunction(mod.base.add(0x6309d1c), 'pointer', ['ulong']);
const ctorWrapper = new NativeFunction(mod.base.add(0x633150), 'pointer', ['pointer']);
const getRoot = new NativeFunction(mod.base.add(0x20800), 'void', ['pointer']);
const getSvc = new NativeFunction(mod.base.add(0x2fbff0), 'void', ['pointer', 'pointer']);
const getSchedCtx = new NativeFunction(mod.base.add(0x633270), 'void', ['pointer', 'pointer']);
const sendMode0 = new NativeFunction(mod.base.add(0x15e8a80), 'pointer', ['pointer', 'pointer', 'pointer']);
const sendMode1 = new NativeFunction(mod.base.add(0x15ea920), 'pointer', ['pointer', 'pointer', 'pointer']);
const scheduleFn = mod.base.add(0x314950);

let captured = null;
let firedCount = 0;

Interceptor.attach(scheduleFn, {
  onEnter(args) {
    try {
      const holder = args[1];
      const taskPtr = holder.readPointer();
      if (taskPtr.isNull()) return;
      const event = parseSendTask(taskPtr, selfUsername);
      if (!event) return;
      firedCount += 1;
      if (event.conversation_id === TARGET_USERNAME && event.content === BODY && !captured) {
        captured = event;
      }
      send({ kind: 'schedule_probe', count: firedCount, event });
    } catch (e) {
      send({ kind: 'error', where: 'scheduleFn', error: String(e) });
    }
  }
});

function buildWrapper(targetUsername, body) {
  const holder = Memory.alloc(Process.pointerSize * 2);
  holder.writeByteArray(new Uint8Array(Process.pointerSize * 2));
  ctorWrapper(holder);
  const obj = holder.readPointer();
  if (obj.isNull()) throw new Error('wrapper constructor returned null object');

  writeHeapStdString(obj.add(0xb0), targetUsername, wxAlloc);
  writeHeapStdString(obj.add(0x660), body, wxAlloc);
  obj.add(0x9c).writeU32(1);
  obj.add(0xd8).writeU32(10000);

  return { holder, obj };
}

function buildServiceCtx() {
  const rootOut = Memory.alloc(0x20);
  rootOut.writeByteArray(new Uint8Array(0x20));
  getRoot(rootOut);
  const root = rootOut.readPointer();

  const svcOut = Memory.alloc(0x20);
  svcOut.writeByteArray(new Uint8Array(0x20));
  getSvc(root, svcOut);
  const svc = svcOut.readPointer();

  const schedOut = Memory.alloc(0x20);
  schedOut.writeByteArray(new Uint8Array(0x20));
  getSchedCtx(svc, schedOut);

  return { root, svc, schedOut };
}

rpc.exports.run = () => {
  try {
    const wrapper = buildWrapper(TARGET_USERNAME, BODY);
    const ctx = buildServiceCtx();
    const resultOut = Memory.alloc(0x40);
    resultOut.writeByteArray(new Uint8Array(0x40));

    send({
      kind: 'pre_call',
      mode: MODE,
      self_username: selfUsername,
      wrapper_obj: safePtrString(wrapper.obj),
      target_at_b0: readStdString(wrapper.obj.add(0xb0)),
      body_at_660: readStdString(wrapper.obj.add(0x660)),
      flag_9c: readU32(wrapper.obj, 0x9c),
      timeout_d8: readU32(wrapper.obj, 0xd8),
      root: safePtrString(ctx.root),
      svc: safePtrString(ctx.svc),
    });

    if (MODE === 'mode1') {
      sendMode1(ctx.schedOut, resultOut, wrapper.holder);
    } else {
      sendMode0(ctx.schedOut, resultOut, wrapper.holder);
    }

    const started = Date.now();
    while ((Date.now() - started) < WAIT_MS) {
      if (captured) break;
      Thread.sleep(0.05);
    }

    return {
      ok: captured !== null,
      mode: MODE,
      fired_count: firedCount,
      captured,
      self_username: selfUsername,
      wrapper_obj: safePtrString(wrapper.obj),
      target_at_b0: readStdString(wrapper.obj.add(0xb0)),
      body_at_660: readStdString(wrapper.obj.add(0x660)),
      result_strings: {
        r0: readStdString(resultOut.add(0x0)),
        r20: readStdString(resultOut.add(0x20)),
      },
    };
  } catch (e) {
    return {
      ok: false,
      error: String(e),
      mode: MODE,
      fired_count: firedCount,
      captured,
      self_username: selfUsername,
    };
  }
};
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="Exact Weixin.exe PID to attach to")
    parser.add_argument("--target", required=True, help="Target conversation username, wxid, or @chatroom")
    parser.add_argument("--body", required=True, help="Text body to send")
    parser.add_argument("--mode", choices=["mode0", "mode1"], default="mode0")
    parser.add_argument("--wait-ms", type=int, default=3000)
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
    rendered = (
        SCRIPT
        .replace("{{TARGET_USERNAME_JSON}}", json.dumps(args.target))
        .replace("{{BODY_JSON}}", json.dumps(args.body))
        .replace("{{MODE_JSON}}", json.dumps(args.mode))
        .replace("{{WAIT_MS}}", str(args.wait_ms))
    )
    script = session.create_script(rendered)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(str(payload) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    result = script.exports_sync.run()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    session.detach()


if __name__ == "__main__":
    main()
