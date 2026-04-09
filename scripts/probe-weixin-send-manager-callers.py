#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT = r"""
const BASELINE_SECONDS = {{BASELINE_SECONDS}};

function safePtrString(p) {
  try {
    if (p === null || p.isNull()) return '0x0';
    return p.toString();
  } catch (e) {
    return '0x0';
  }
}

function frameInfo(mod, addr) {
  try {
    const symbol = DebugSymbol.fromAddress(addr);
    let rel = null;
    try {
      rel = ptr(addr).sub(mod.base).toString();
    } catch (e) {
    }
    return {
      address: safePtrString(addr),
      relative: rel,
      name: symbol && symbol.name ? symbol.name : null,
      module: symbol && symbol.moduleName ? symbol.moduleName : null,
    };
  } catch (e) {
    return {
      address: safePtrString(addr),
      relative: null,
      name: null,
      module: null,
    };
  }
}

const mod = Process.getModuleByName('Weixin.dll');
const resolver = mod.base.add(0xd0a840);
const baselineUntil = Date.now() + (BASELINE_SECONDS * 1000);
const seen = {};

send({
  kind: 'status',
  baseline_seconds: BASELINE_SECONDS,
  resolver: resolver.toString(),
});

Interceptor.attach(resolver, {
  onEnter(args) {
    try {
      const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .slice(0, 12)
        .map((a) => frameInfo(mod, a));
      const key = JSON.stringify(bt.map((x) => x.relative || x.address));
      if (seen[key]) return;
      seen[key] = true;
      if (Date.now() < baselineUntil) return;
      send({
        kind: 'send_manager_caller',
        return_address: frameInfo(mod, this.returnAddress),
        backtrace: bt,
      });
    } catch (e) {
      send({ kind: 'error', where: 'resolver', error: String(e) });
    }
  }
});

setTimeout(() => send({ kind: 'armed', seen_count: Object.keys(seen).length }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat', seen_count: Object.keys(seen).length }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="Exact Weixin.exe PID to attach to")
    parser.add_argument("--baseline-seconds", type=int, default=3)
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
    rendered = SCRIPT.replace("{{BASELINE_SECONDS}}", str(args.baseline_seconds))
    script = session.create_script(rendered)

    def on_message(message, data):
        if message["type"] == "send":
            sys.stdout.buffer.write((str(message["payload"]) + "\n").encode("utf-8", errors="replace"))
            sys.stdout.flush()
        else:
            sys.stdout.buffer.write((str(message) + "\n").encode("utf-8", errors="replace"))
            sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    sys.stdout.buffer.write((f"attached pid={pid}\n").encode("utf-8"))
    sys.stdout.flush()
    threading.Event().wait()


if __name__ == "__main__":
    main()
