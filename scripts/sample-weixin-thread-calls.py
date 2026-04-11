#!/usr/bin/env python
import argparse
import json
import sys
import time

import frida


SCRIPT = r"""
const TARGET_THREAD = {{TARGET_THREAD}};
const DURATION_MS = {{DURATION_MS}};
const MAX_ROWS = {{MAX_ROWS}};
const mod = Process.getModuleByName('Weixin.dll');

function safe(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (_) {
    return '0x0';
  }
}

const start = Date.now();
let active = false;

Stalker.exclude(Process.getModuleByName('ntdll.dll'));
Stalker.exclude(Process.getModuleByName('kernel32.dll'));
Stalker.exclude(Process.getModuleByName('KERNELBASE.dll'));
Stalker.exclude(Process.getModuleByName('user32.dll'));

Process.runOnThread(TARGET_THREAD, function () {
  active = true;
  Stalker.follow(TARGET_THREAD, {
    events: {
      call: true,
      ret: false,
      exec: false,
      block: false,
      compile: false,
    },
    onCallSummary(summary) {
      const rows = [];
      Object.keys(summary).forEach((addr) => {
        try {
          const ptrAddr = ptr(addr);
          if (ptrAddr.compare(mod.base) < 0 || ptrAddr.compare(mod.base.add(mod.size)) >= 0) return;
          rows.push({
            addr: safe(ptrAddr),
            rva: safe(ptrAddr.sub(mod.base)),
            count: summary[addr],
          });
        } catch (_) {
        }
      });
      rows.sort((a, b) => b.count - a.count);
      send({ kind: 'call_summary', thread_id: TARGET_THREAD, rows: rows.slice(0, MAX_ROWS) });
    },
  });
});

setTimeout(function () {
  try {
    if (active) {
      Stalker.unfollow(TARGET_THREAD);
      Stalker.garbageCollect();
    }
  } catch (_) {
  }
  send({ kind: 'done', thread_id: TARGET_THREAD, duration_ms: DURATION_MS });
}, DURATION_MS);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--thread-id", type=int, required=True)
    parser.add_argument("--duration-ms", type=int, default=4000)
    parser.add_argument("--max-rows", type=int, default=40)
    args = parser.parse_args()

    device = frida.get_local_device()
    session = device.attach(args.pid)
    source = (
        SCRIPT
        .replace("{{TARGET_THREAD}}", str(args.thread_id))
        .replace("{{DURATION_MS}}", str(args.duration_ms))
        .replace("{{MAX_ROWS}}", str(args.max_rows))
    )
    script = session.create_script(source)

    def on_message(message, data):
        payload = message.get("payload", message)
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    print(json.dumps({"kind": "host_meta", "pid": args.pid, "thread_id": args.thread_id, "duration_ms": args.duration_ms}, ensure_ascii=False), flush=True)
    time.sleep((args.duration_ms / 1000.0) + 2)
    try:
        session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
