#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT = r"""
const BASELINE_SECONDS = {{BASELINE_SECONDS}};
const TARGET_BODY = {{TARGET_BODY}};

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
  } catch (_) {
    return null;
  }
}

function safePtrString(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (_) {
    return '0x0';
  }
}

function frameInfo(mod, addr) {
  try {
    const symbol = DebugSymbol.fromAddress(addr);
    let rel = null;
    try {
      rel = ptr(addr).sub(mod.base).toString();
    } catch (_) {
    }
    return {
      address: safePtrString(addr),
      relative: rel,
      module: symbol && symbol.moduleName ? symbol.moduleName : null,
      name: symbol && symbol.name ? symbol.name : null,
    };
  } catch (_) {
    return {
      address: safePtrString(addr),
      relative: null,
      module: null,
      name: null,
    };
  }
}

function looksLikeTargetArg(p) {
  try {
    if (!p || p.isNull()) return false;
    const s = readStdString(p);
    return s === TARGET_BODY;
  } catch (_) {
    return false;
  }
}

const exe = Process.enumerateModules()[0];
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
const seen = new Set();

const frames = [
  ['frame_159eb1a_func', 0x159eb1a - 0x1a],
  ['frame_159f624_func', 0x159f624 - 0x24],
  ['frame_61289b_func', 0x61289b - 0x1b],
  ['frame_3e48ea_func', 0x3e48ea - 0x1a],
  ['frame_3e388a_func', 0x3e388a - 0x1a],
];

send({
  kind: 'status',
  exe_base: safePtrString(exe.base),
  exe_name: exe.name,
  baseline_seconds: BASELINE_SECONDS,
  target_body: TARGET_BODY,
  frames: frames.map(([name, rva]) => ({ name, rva: '0x' + rva.toString(16), addr: safePtrString(exe.base.add(rva)) })),
});

frames.forEach(([name, rva]) => {
  Interceptor.attach(exe.base.add(rva), {
    onEnter(args) {
      try {
        const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
          .slice(0, 12)
          .map((addr) => frameInfo(exe, addr));
        const interestingArgs = [];
        for (let i = 0; i < 6; i++) {
          const p = args[i];
          interestingArgs.push({
            index: i,
            ptr: safePtrString(p),
            std: (() => { try { return readStdString(p); } catch (_) { return null; } })(),
          });
        }
        const hasTarget = interestingArgs.some((x) => x.std === TARGET_BODY) || bt.some((x) => (x.relative || '') === '0x159eb1a' || (x.relative || '') === '0x159f624');
        const key = name + '|' + JSON.stringify(bt.map((x) => x.relative || x.address));
        if (seen.has(key)) return;
        seen.add(key);
        if (Date.now() < baselineUntil) return;
        send({
          kind: 'frame_enter',
          frame: name,
          rva: '0x' + rva.toString(16),
          thread_id: Process.getCurrentThreadId(),
          return_address: frameInfo(exe, this.returnAddress),
          has_target: hasTarget,
          args: interestingArgs,
          backtrace: bt,
        });
      } catch (e) {
        send({ kind: 'error', where: name, error: String(e) });
      }
    }
  });
});

setTimeout(() => send({ kind: 'armed', seen_count: seen.size }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat', seen_count: seen.size }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--baseline-seconds", type=int, default=0)
    parser.add_argument("--body", default="skynet")
    args = parser.parse_args()

    rendered = (
        SCRIPT.replace("{{BASELINE_SECONDS}}", str(args.baseline_seconds))
        .replace("{{TARGET_BODY}}", repr(args.body))
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
