#!/usr/bin/env python
import argparse
import sys
import threading

import frida


SCRIPT = r"""
const TARGET_BODY = {{TARGET_BODY}};
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

function frameInfo(addr) {
  try {
    const owner = Process.findModuleByAddress(addr);
    const sym = DebugSymbol.fromAddress(addr);
    let rel = null;
    try {
      if (owner) rel = ptr(addr).sub(owner.base).toString();
    } catch (_) {}
    return {
      address: safe(addr),
      relative: rel,
      owner_name: owner ? owner.name : null,
      owner_base: owner ? safe(owner.base) : null,
      name: sym && sym.name ? sym.name : null,
      module: sym && sym.moduleName ? sym.moduleName : null,
    };
  } catch (_) {
    return { address: safe(addr), relative: null, owner_name: null, owner_base: null, name: null, module: null };
  }
}

function readU32(base, off) {
  try { return base.add(off).readU32(); } catch (_) { return null; }
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

function looksInteresting(s) {
  if (!s) return false;
  if (s.indexOf(TARGET_BODY) >= 0) return true;
  if (s.indexOf('wxid_') >= 0) return true;
  if (s.indexOf('@chatroom') >= 0) return true;
  if (s.indexOf('<msgsource') >= 0) return true;
  return false;
}

function scanStd(base, label) {
  const hits = [];
  const offs = [
    0x0,0x10,0x20,0x30,0x38,0x40,0x48,0x50,0x58,0x60,0x68,0x70,0x78,0x80,0x88,0x90,
    0xa0,0xb0,0xc0,0xd0,0xe0,0xf0,0x100,0x110,0x120,0x130,0x140,0x150,0x160,0x170,0x180,
    0x1a0,0x1c0,0x1e0,0x200,0x220,0x240,0x260,0x280,0x2a0,0x2c0,0x2e0,0x300,0x320,0x340,
    0x360,0x380,0x3a0
  ];
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

function emit(kind, payload) {
  const key = kind + '|' + JSON.stringify(payload);
  if (seen.has(key)) return;
  seen.add(key);
  if (Date.now() < baselineUntil) return;
  send({ kind, payload });
}

function hook(name, rva, argc) {
  Interceptor.attach(mod.base.add(rva), {
    onEnter(args) {
      try {
        const tid = Process.getCurrentThreadId();
        const argDump = [];
        const stringHits = [];
        for (let i = 0; i < argc; i++) {
          const p = args[i];
          argDump.push({ index: i, ptr: safe(p) });
          if (p && !p.isNull()) {
            try {
              const direct = readStdString(p);
              if (looksInteresting(direct)) {
                stringHits.push({ label: 'arg' + i + '_direct', offset: '0x0', value: direct });
              }
            } catch (_) {}
            scanStd(p, 'arg' + i).forEach((x) => stringHits.push(x));
          }
        }
        const bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 12).map(frameInfo);
        emit('wrapper_enter', {
          name,
          rva: '0x' + rva.toString(16),
          thread_id: tid,
          return_address: frameInfo(this.returnAddress),
          args: argDump,
          string_hits: stringHits,
          backtrace: bt,
        });
      } catch (e) {
        send({ kind: 'error', where: name, error: String(e) });
      }
    }
  });
}

send({
  kind: 'status',
  baseline_seconds: BASELINE_SECONDS,
  target_body: TARGET_BODY,
  wrappers: [
    { name: 'FUN_18159e480', address: safe(mod.base.add(0x159e480)) },
    { name: 'FUN_18159ef90', address: safe(mod.base.add(0x159ef90)) },
    { name: 'FUN_180612870', address: safe(mod.base.add(0x612870)) },
  ],
});

hook('FUN_18159e480', 0x159e480, 3);
hook('FUN_18159ef90', 0x159ef90, 2);
hook('FUN_180612870', 0x612870, 2);

setTimeout(() => send({ kind: 'armed', seen_count: seen.size }), BASELINE_SECONDS * 1000);
setInterval(() => send({ kind: 'heartbeat', seen_count: seen.size }), 30000);
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--body", default="skynet")
    parser.add_argument("--baseline-seconds", type=int, default=0)
    args = parser.parse_args()

    rendered = (
        SCRIPT.replace("{{TARGET_BODY}}", repr(args.body))
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
