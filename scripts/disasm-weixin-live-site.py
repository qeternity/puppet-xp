#!/usr/bin/env python
import argparse
import json
import sys
import threading

import frida


SCRIPT = r"""
const TARGETS = {{TARGETS_JSON}};

function safe(p) {
  try {
    if (!p || p.isNull()) return '0x0';
    return p.toString();
  } catch (_) {
    return '0x0';
  }
}

function sym(addr) {
  try {
    const s = DebugSymbol.fromAddress(addr);
    return {
      text: s ? s.toString() : null,
      name: s && s.name ? s.name : null,
      module: s && s.moduleName ? s.moduleName : null,
    };
  } catch (_) {
    return { text: null, name: null, module: null };
  }
}

function parseOne(addr) {
  const ins = Instruction.parse(addr);
  const out = {
    address: safe(addr),
    mnemonic: ins.mnemonic,
    opStr: ins.opStr,
    size: ins.size,
    next: safe(ins.next),
  };
  try {
    out.text = ins.toString();
  } catch (_) {
  }
  return out;
}

function findPrecedingSequence(targetAddr) {
  const results = [];
  for (let back = 1; back <= 15; back++) {
    const start = targetAddr.sub(back);
    const seq = [];
    let cur = start;
    let ok = true;
    for (let i = 0; i < 8; i++) {
      try {
        const ins = Instruction.parse(cur);
        seq.push({
          address: safe(cur),
          mnemonic: ins.mnemonic,
          opStr: ins.opStr,
          size: ins.size,
          text: ins.toString(),
        });
        cur = ins.next;
        if (cur.equals(targetAddr)) {
          results.push({ start: safe(start), sequence: seq });
          break;
        }
        if (cur.compare(targetAddr) > 0) break;
      } catch (_) {
        ok = false;
        break;
      }
    }
    if (!ok) continue;
  }
  return results;
}

send({ kind: 'status', targets: TARGETS });

for (const target of TARGETS) {
  const addr = ptr(target);
  const before = findPrecedingSequence(addr);
  const after = [];
  let cur = addr;
  for (let i = 0; i < 8; i++) {
    try {
      const ins = Instruction.parse(cur);
      after.push({
        address: safe(cur),
        mnemonic: ins.mnemonic,
        opStr: ins.opStr,
        size: ins.size,
        text: ins.toString(),
      });
      cur = ins.next;
    } catch (e) {
      after.push({ address: safe(cur), error: String(e) });
      break;
    }
  }
  send({
    kind: 'site',
    target: safe(addr),
    symbol: sym(addr),
    preceding_candidates: before,
    following: after,
  });
}
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("addresses", nargs="+", help="Absolute addresses, e.g. 0x7ff62c9ff624")
    args = parser.parse_args()

    rendered = SCRIPT.replace("{{TARGETS_JSON}}", json.dumps(args.addresses))
    device = frida.get_local_device()
    session = device.attach(args.pid)
    script = session.create_script(rendered)

    done = threading.Event()

    def on_message(message, data):
      payload = message.get("payload", message)
      sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
      sys.stdout.flush()
      if isinstance(payload, dict) and payload.get("kind") == "site" and payload.get("target") == args.addresses[-1]:
        pass

    script.on("message", on_message)
    script.load()
    threading.Event().wait(2)
    try:
      session.detach()
    except Exception:
      pass


if __name__ == "__main__":
    main()
