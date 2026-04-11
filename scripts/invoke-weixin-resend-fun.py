#!/usr/bin/env python
import argparse
import json
import sys
import time

import frida


SCRIPT = r"""
const THREAD_ID = {{THREAD_ID}};
const ARG0 = ptr({{ARG0}});
const ARG1 = ptr({{ARG1}});
const WAIT_MS = {{WAIT_MS}};

function safe(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (_) {
    return '0x0';
  }
}

function readStdString(addr) {
  try {
    const len = addr.add(0x10).readU32();
    const cap = addr.add(0x18).readU32();
    if (len === 0) return '';
    if (len > 0x2000 || cap > 0x100000) return null;
    let dataPtr = addr;
    if (cap > 15) dataPtr = addr.readPointer();
    if (!dataPtr || dataPtr.isNull()) return null;
    return dataPtr.readUtf8String(len);
  } catch (_) {
    return null;
  }
}

rpc.exports = {
  run() {
    const mod = Process.getModuleByName('Weixin.dll');
    const resend = new NativeFunction(mod.base.add(0x159ef90), 'void', ['pointer', 'pointer']);
    send({
      kind: 'status',
      function: safe(mod.base.add(0x159ef90)),
      thread_id: THREAD_ID,
      arg0: safe(ARG0),
      arg1: safe(ARG1),
      arg1_fields: {
        s38: readStdString(ARG1.add(0x38)),
        s58: readStdString(ARG1.add(0x58)),
        s140: readStdString(ARG1.add(0x140)),
        s180: readStdString(ARG1.add(0x180)),
      },
    });
    Process.runOnThread(THREAD_ID, () => {
      try {
        send({ kind: 'invoke_enter', thread_id: Process.getCurrentThreadId() });
        resend(ARG0, ARG1);
        send({ kind: 'invoke_leave', thread_id: Process.getCurrentThreadId() });
      } catch (e) {
        send({ kind: 'invoke_error', thread_id: Process.getCurrentThreadId(), error: String(e) });
      }
    });
    return { queued: true };
  }
};
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--thread-id", type=int, required=True)
    parser.add_argument("--arg0", required=True)
    parser.add_argument("--arg1", required=True)
    parser.add_argument("--wait-ms", type=int, default=5000)
    args = parser.parse_args()

    rendered = (
        SCRIPT.replace("{{THREAD_ID}}", str(args.thread_id))
        .replace("{{ARG0}}", json.dumps(args.arg0))
        .replace("{{ARG1}}", json.dumps(args.arg1))
        .replace("{{WAIT_MS}}", str(args.wait_ms))
    )

    device = frida.get_local_device()
    session = device.attach(args.pid)
    script = session.create_script(rendered)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    print(json.dumps({"kind": "host_meta", "pid": args.pid, "thread_id": args.thread_id, "arg0": args.arg0, "arg1": args.arg1}), flush=True)
    result = script.exports_sync.run()
    print(json.dumps({"kind": "run_result", "result": result}, ensure_ascii=False), flush=True)
    time.sleep(args.wait_ms / 1000.0)
    try:
      session.detach()
    except Exception:
      pass


if __name__ == "__main__":
    main()
