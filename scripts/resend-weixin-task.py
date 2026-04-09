#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT = r"""
const TASK_PTR = ptr('{{TASK_PTR}}');
const NEW_BODY = {{NEW_BODY_JSON}};

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

function writeInlineStdString(addr, value) {
  const bytes = Array.from(value).map(ch => ch.charCodeAt(0));
  if (bytes.length > 15) {
    throw new Error('inline std::string write only supports <= 15 chars');
  }
  addr.writeByteArray(new Uint8Array(16));
  for (let i = 0; i < bytes.length; i++) {
    addr.add(i).writeU8(bytes[i]);
  }
  addr.add(bytes.length).writeU8(0);
  addr.add(0x10).writeU32(bytes.length);
  addr.add(0x14).writeU32(0);
  addr.add(0x18).writeU32(15);
  addr.add(0x1c).writeU32(0);
}

function safePtrString(p) {
  try {
    if (p === null || p.isNull()) return '0x0';
    return p.toString();
  } catch (e) {
    return '0x0';
  }
}

const mod = Process.getModuleByName('Weixin.dll');
const wxAlloc = new NativeFunction(mod.base.add(0x6309d1c), 'pointer', ['ulong']);
const getRoot = new NativeFunction(mod.base.add(0x20800), 'pointer', ['pointer']);
const getSvc = new NativeFunction(mod.base.add(0x2fbff0), 'void', ['pointer', 'pointer']);
const getSchedCtx = new NativeFunction(mod.base.add(0x633270), 'void', ['pointer', 'pointer']);
const scheduleTask = new NativeFunction(mod.base.add(0x314950), 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

function writeHeapStdString(addr, value) {
  const utf8 = Array.from(value).map(ch => ch.charCodeAt(0));
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

function cloneTaskWithOwnedStrings(srcPtr) {
  const clone = wxAlloc(0x158);
  Memory.copy(clone, srcPtr, 0x158);

  const sender38 = readStdString(srcPtr.add(0x38));
  const convo58 = readStdString(srcPtr.add(0x58));
  const sender78 = readStdString(srcPtr.add(0x78));
  const convo98 = readStdString(srcPtr.add(0x98));
  const msgsource100 = readStdString(srcPtr.add(0x100));
  const nestedSender10 = readStdString(srcPtr.add(0x28).add(0x10));
  const nestedConvo30 = readStdString(srcPtr.add(0x28).add(0x30));
  const nestedSender50 = readStdString(srcPtr.add(0x28).add(0x50));
  const nestedConvo70 = readStdString(srcPtr.add(0x28).add(0x70));

  if (sender38) writeHeapStdString(clone.add(0x38), sender38);
  if (convo58) writeHeapStdString(clone.add(0x58), convo58);
  if (sender78) writeHeapStdString(clone.add(0x78), sender78);
  if (convo98) writeHeapStdString(clone.add(0x98), convo98);
  if (msgsource100) writeHeapStdString(clone.add(0x100), msgsource100);
  if (nestedSender10) writeHeapStdString(clone.add(0x28).add(0x10), nestedSender10);
  if (nestedConvo30) writeHeapStdString(clone.add(0x28).add(0x30), nestedConvo30);
  if (nestedSender50) writeHeapStdString(clone.add(0x28).add(0x50), nestedSender50);
  if (nestedConvo70) writeHeapStdString(clone.add(0x28).add(0x70), nestedConvo70);

  writeInlineStdString(clone.add(0xe0), NEW_BODY);
  return clone;
}

rpc.exports.run = () => {
  try {
    const before = {
      sender38: readStdString(TASK_PTR.add(0x38)),
      convo58: readStdString(TASK_PTR.add(0x58)),
      sender78: readStdString(TASK_PTR.add(0x78)),
      convo98: readStdString(TASK_PTR.add(0x98)),
      bodyE0: readStdString(TASK_PTR.add(0xe0)),
      msgsource100: readStdString(TASK_PTR.add(0x100)),
    };

    if (before.bodyE0 === null) {
      throw new Error('task body at +0xe0 is not readable');
    }

    const clonedTask = cloneTaskWithOwnedStrings(TASK_PTR);

    const after = {
      cloned_task_ptr: safePtrString(clonedTask),
      bodyE0: readStdString(clonedTask.add(0xe0)),
      convo58: readStdString(clonedTask.add(0x58)),
    };

    const out58 = Memory.alloc(0x20);
    out58.writeByteArray(new Uint8Array(0x20));
    getRoot(out58);
    const v58 = out58.readPointer();

    const out40 = Memory.alloc(0x20);
    out40.writeByteArray(new Uint8Array(0x20));
    getSvc(v58, out40);
    const v40 = out40.readPointer();

    const out78 = Memory.alloc(0x20);
    out78.writeByteArray(new Uint8Array(0x20));
    getSchedCtx(v40, out78);

    const holder = Memory.alloc(Process.pointerSize);
    holder.writePointer(clonedTask);

    scheduleTask(out78, holder, ptr(0), ptr(0));

    return {
      ok: true,
      task_ptr: safePtrString(TASK_PTR),
      before,
      after,
      root_ctx: safePtrString(v58),
      svc_ctx: safePtrString(v40),
    };
  } catch (e) {
    return {
      ok: false,
      error: String(e),
    };
  }
};
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="Exact Weixin.exe PID to attach to")
    parser.add_argument("--task-ptr", required=True, help="Existing live task pointer, e.g. 0x183c32a2cf0")
    parser.add_argument("--body", required=True, help="New inline body text (<= 15 chars)")
    args = parser.parse_args()

    if len(args.body.encode("utf-8")) > 15:
      raise SystemExit("Body must be <= 15 UTF-8 bytes for this inline resend probe")

    device = frida.get_local_device()
    if args.pid is not None:
        pid = args.pid
    else:
        matches = [p for p in device.enumerate_processes() if p.name.lower() == "weixin.exe"]
        if not matches:
            raise SystemExit("Weixin.exe not found")
        pid = sorted(matches, key=lambda p: p.pid)[0].pid

    session = device.attach(pid)
    rendered = SCRIPT.replace("{{TASK_PTR}}", args.task_ptr).replace("{{NEW_BODY_JSON}}", repr(args.body))
    script = session.create_script(rendered)

    done = threading.Event()
    result_holder = {"result": None}

    def on_message(message, data):
        if message["type"] == "send":
            sys.stdout.write(str(message["payload"]) + "\n")
            sys.stdout.flush()
        else:
            sys.stdout.write(str(message) + "\n")
            sys.stdout.flush()

    script.on("message", on_message)
    script.load()

    result_holder["result"] = script.exports_sync.run()
    print(result_holder["result"])

    session.detach()


if __name__ == "__main__":
    main()
