#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT = r"""
const TARGET_CONVERSATION = {{TARGET_CONVERSATION}};
const BASELINE_SECONDS = {{BASELINE_SECONDS}};
const mod = Process.getModuleByName('Weixin.dll');
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
const seen = new Set();

function safe(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (_) {
    return '0x0';
  }
}

function emit(kind, payload) {
  const key = kind + '|' + JSON.stringify(payload);
  if (seen.has(key)) return;
  seen.add(key);
  if (Date.now() < baselineUntil) return;
  send({ kind, payload });
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

function looksInteresting(s) {
  if (!s) return false;
  if (s.indexOf(TARGET_CONVERSATION) >= 0) return true;
  if (s.indexOf('wxid_') >= 0) return true;
  if (s.indexOf('@chatroom') >= 0) return true;
  if (s.indexOf('<msgsource') >= 0) return true;
  if (s.length > 0 && s.length < 80) return true;
  return false;
}

function scanStd(base, label, offs) {
  const hits = [];
  offs.forEach((off) => {
    try {
      const s = readStdString(base.add(off));
      if (looksInteresting(s)) {
        hits.push({ label, offset: '0x' + off.toString(16), value: s });
      }
    } catch (_) {}
  });
  return hits;
}

function tryReadPtr(base, off) {
  try {
    const p = base.add(off).readPointer();
    if (!p || p.isNull()) return null;
    return p;
  } catch (_) {
    return null;
  }
}

Interceptor.attach(mod.base.add(0x159ec20), {
  onEnter(args) {
    try {
      const tid = Process.getCurrentThreadId();
      const task = args[0];
      const strings = [];
      strings.push(...scanStd(task.add(0x28), 'task28', [
        0x38,0x58,0x78,0x98,0xb8,0xd8,0xf8,0x118,0x140,0x160,0x180,0x1a0,0x1c0,0x1e0,0x200,0x220,0x240,0x260,0x280,0x2a0,0x2c0,0x2e0,0x300,0x320,0x340
      ]));

      const task3b0 = task.add(0x3b0).readU32();
      const owner = task.add(0x3b8).readPointer();
      const ownerE0 = owner && !owner.isNull() ? tryReadPtr(owner, 0xe0) : null;
      if (ownerE0) {
        strings.push(...scanStd(ownerE0, 'owner_e0', [
          0x0,0x20,0x40,0x60,0x80,0xa0,0xc0,0xe0,0x100,0x120,0x140,0x160,0x180,0x1a0,0x1c0,0x1e0,0x200,0x220,0x240,0x260
        ]));
      }
      emit('resend_worker_enter', {
        thread_id: tid,
        task: safe(task),
        task3b0,
        owner: safe(owner),
        owner_e0: safe(ownerE0),
        strings,
      });
    } catch (e) {
      send({ kind: 'error', where: 'FUN_18159ec20', error: String(e) });
    }
  }
});

send({
  kind: 'status',
  function: safe(mod.base.add(0x159ec20)),
  baseline_seconds: BASELINE_SECONDS,
  target_conversation: TARGET_CONVERSATION,
});

setTimeout(() => send({ kind: 'armed' }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat' }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--conversation", default="27208021116@chatroom")
    parser.add_argument("--baseline-seconds", type=int, default=0)
    args = parser.parse_args()

    rendered = (
        SCRIPT.replace("{{TARGET_CONVERSATION}}", repr(args.conversation))
        .replace("{{BASELINE_SECONDS}}", str(args.baseline_seconds))
    )

    device = frida.get_local_device()
    session = device.attach(args.pid)
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
