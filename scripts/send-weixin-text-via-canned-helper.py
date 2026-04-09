#!/usr/bin/env python
import argparse
import ctypes
import json
import sys
import time
from ctypes import wintypes

import frida


SCRIPT = r"""
const TARGET_CONVERSATION = {{TARGET_CONVERSATION_JSON}};
const TARGET_BODY = {{TARGET_BODY_JSON}};
const TARGET_THREAD_ID = {{TARGET_THREAD_ID}};

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

function isConversationId(s) {
  if (!s) return false;
  return s.indexOf('@chatroom') >= 0 || s.indexOf('wxid_') === 0 || s === 'filehelper' || s === 'weixin';
}

function plausibleBody(s) {
  if (!s) return false;
  if (s.length < 1 || s.length > 4096) return false;
  if (s.indexOf('<msgsource') === 0) return false;
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

  if (!conversationId || !senderUsername || !body) return null;

  return {
    task_ptr: safePtrString(taskPtr),
    conversation_id: conversationId,
    sender_username: senderUsername,
    direction: selfUsername && senderUsername === selfUsername ? 'sent' : 'received',
    content: body,
    msgsource: msgsource100 && msgsource100.indexOf('<msgsource') === 0 ? msgsource100 : null,
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

const mod = Process.getModuleByName('Weixin.dll');
const wxAlloc = new NativeFunction(mod.base.add(0x6309d1c), 'pointer', ['ulong']);
const getRoot = new NativeFunction(mod.base.add(0x20800), 'pointer', ['pointer']);
const getSvc = new NativeFunction(mod.base.add(0x2fbff0), 'void', ['pointer', 'pointer']);
const getHelperCtx = new NativeFunction(mod.base.add(0x61d050), 'pointer', ['pointer', 'pointer']);
const helperSend = new NativeFunction(mod.base.add(0x64a180), 'void', ['pointer', 'pointer']);
const getSnapshotMgr = new NativeFunction(mod.base.add(0x1f540), 'pointer', []);
const buildSnapshot = new NativeFunction(mod.base.add(0x20aa0), 'pointer', ['pointer', 'pointer', 'uchar']);

function getSelfUsername() {
  try {
    const snapshotMgr = getSnapshotMgr();
    const snapshotBuf = Memory.alloc(0x200);
    snapshotBuf.writeByteArray(new Uint8Array(0x200));
    buildSnapshot(snapshotMgr, snapshotBuf, 1);
    return readStdString(snapshotBuf.add(0x0));
  } catch (e) {
    return null;
  }
}

const selfUsername = getSelfUsername();
let armed = true;
let taskEvent = null;
let managerEvent = null;

Interceptor.attach(mod.base.add(0x15e8200), {
  onEnter(args) {
    try {
      if (!armed) return;
      if (this.threadId !== TARGET_THREAD_ID) return;
      if (args[3].toInt32() !== 0) return;
      const pair = args[2];
      const source = pair.readPointer();
      if (source.isNull()) return;
      const currentConversation = readStdString(source.add(0xb0));
      const currentBody = readStdString(source.add(0x660));
      if (!currentConversation || !currentBody) return;
      if (currentBody !== "You've left the group chat") return;
      writeHeapStdString(source.add(0xb0), TARGET_CONVERSATION, wxAlloc);
      writeHeapStdString(source.add(0x600), "autonomous-" + Date.now().toString(16), wxAlloc);
      writeHeapStdString(source.add(0x660), TARGET_BODY, wxAlloc);
      source.add(0x9c).writeU32(1);
      source.add(0xd8).writeU32(10000);
      send({
        kind: 'builder_rewrite',
        source: safePtrString(source),
        old_conversation: currentConversation,
        old_body: currentBody,
        new_conversation: readStdString(source.add(0xb0)),
        new_body: readStdString(source.add(0x660)),
      });
      armed = false;
    } catch (e) {
      send({ kind: 'error', where: 'builder_rewrite', error: String(e) });
    }
  }
});

Interceptor.attach(mod.base.add(0x314950), {
  onEnter(args) {
    try {
      const holder = args[1];
      const taskPtr = holder.readPointer();
      if (taskPtr.isNull()) return;
      const event = parseSendTask(taskPtr, selfUsername);
      if (!event) return;
      if (event.conversation_id === TARGET_CONVERSATION && event.content === TARGET_BODY) {
        taskEvent = event;
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
      if (event.conversation_id === TARGET_CONVERSATION && event.content === TARGET_BODY) {
        managerEvent = event;
      }
      send({ kind: 'manager_message_event', event });
    } catch (e) {
      send({ kind: 'error', where: 'manager_hook', error: String(e) });
    }
  }
});

rpc.exports.run = () => {
  Process.runOnThread(TARGET_THREAD_ID, function () {
    try {
      const target = Memory.alloc(0x20);
      target.writeByteArray(new Uint8Array(0x20));
      writeHeapStdString(target, TARGET_CONVERSATION, wxAlloc);
      const rootBuf = Memory.alloc(0x20);
      rootBuf.writeByteArray(new Uint8Array(0x20));
      getRoot(rootBuf);
      const svcBuf = Memory.alloc(0x20);
      svcBuf.writeByteArray(new Uint8Array(0x20));
      getSvc(rootBuf.readPointer(), svcBuf);
      const helperCtxBuf = Memory.alloc(0x20);
      helperCtxBuf.writeByteArray(new Uint8Array(0x20));
      getHelperCtx(svcBuf.readPointer(), helperCtxBuf);
      const helperCtx = helperCtxBuf.readPointer();
      send({
        kind: 'helper_invoke',
        helper: 'FUN_18064a180',
        helper_ctx: safePtrString(helperCtx),
        target_conversation: readStdString(target),
        thread_id: TARGET_THREAD_ID,
      });
      helperSend(helperCtx, target);
      send({ kind: 'helper_returned' });
    } catch (e) {
      send({ kind: 'invoke_error', error: String(e) });
    }
  });
  return { queued: true, self_username: selfUsername };
};

rpc.exports.getstate = () => {
  return {
    self_username: selfUsername,
    task_event: taskEvent,
    manager_event: managerEvent,
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int)
    parser.add_argument("--thread-id", type=int)
    parser.add_argument("--conversation-id", default="27208021116@chatroom")
    parser.add_argument("--body", default="skynet")
    parser.add_argument("--wait-ms", type=int, default=5000)
    args = parser.parse_args()

    window = find_weixin_main_window()
    pid = args.pid or window["pid"]
    thread_id = args.thread_id or window["thread_id"]

    device = frida.get_local_device()
    session = device.attach(pid)
    rendered = (
        SCRIPT
        .replace("{{TARGET_CONVERSATION_JSON}}", json.dumps(args.conversation_id))
        .replace("{{TARGET_BODY_JSON}}", json.dumps(args.body))
        .replace("{{TARGET_THREAD_ID}}", str(thread_id))
    )
    script = session.create_script(rendered)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    print(json.dumps({
        "kind": "host_meta",
        "meta": {
            "pid": pid,
            "thread_id": thread_id,
            "window_title": window["title"],
            "target_conversation": args.conversation_id,
            "target_body": args.body,
        },
    }, ensure_ascii=False))
    result = script.exports_sync.run()
    print(json.dumps({"kind": "run_result", "result": result}, ensure_ascii=False))
    time.sleep(args.wait_ms / 1000.0)
    final_state = script.exports_sync.getstate()
    print(json.dumps({"kind": "final_state", "state": final_state}, ensure_ascii=False))
    session.detach()


if __name__ == "__main__":
    main()
