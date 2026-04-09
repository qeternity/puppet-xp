#!/usr/bin/env python
import argparse
import json
import sys
import time

import frida


SCRIPT = r"""
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
    if (len > 0x4000 || cap > 0x100000) return null;
    if (len === 0) return '';
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

function isConversationId(s) {
  if (!s) return false;
  return s.indexOf('@chatroom') >= 0 || s.indexOf('wxid_') === 0 || s === 'filehelper' || s === 'weixin';
}

function looksUuid(s) {
  return !!s && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
}

function plausibleBody(s) {
  if (s === null) return false;
  if (s.length === 0) return true;
  if (s.length > 4096) return false;
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

function ptrInModule(mod, p) {
  try {
    return p.compare(mod.base) >= 0 && p.compare(mod.base.add(mod.size)) < 0;
  } catch (e) {
    return false;
  }
}

function validateCandidate(mod, ownerBase, sourceObj) {
  try {
    if (!sourceObj.add(0x8).readPointer().equals(sourceObj)) return null;
    if (!sourceObj.add(0x10).readPointer().equals(ownerBase)) return null;
    if (!ownerBase.add(0x10).readPointer().equals(sourceObj)) return null;

    const vtable = sourceObj.readPointer();
    if (vtable.isNull()) return null;
    if (!ptrInModule(mod, vtable)) return null;

    const ref1 = ownerBase.add(0x8).readU32();
    const ref2 = ownerBase.add(0xc).readU32();
    if (ref1 > 0x1000 || ref2 > 0x1000) return null;

    const conversation = readStdString(sourceObj.add(0xb0));
    const uuid = readStdString(sourceObj.add(0x600));
    const body = readStdString(sourceObj.add(0x660));

    const f9c = readU32(sourceObj, 0x9c);
    const fa4 = readU32(sourceObj, 0xa4);
    const fc0 = readU32(sourceObj, 0xc0);
    const fc8 = readU32(sourceObj, 0xc8);
    const fd8 = readU32(sourceObj, 0xd8);
    const f670 = readU32(sourceObj, 0x670);

    const convoOk = conversation === '' || isConversationId(conversation);
    const uuidOk = uuid === '' || looksUuid(uuid);
    const bodyOk = plausibleBody(body);
    const fieldOk = (f9c === 1 || f9c === 0) && (fa4 === 7 || fa4 === 0) && (fd8 === 1 || fd8 === 0 || fd8 === 10000);
    const lenOk = (conversation === null || fc0 === conversation.length) && (body === null || f670 === body.length);

    if (!convoOk || !uuidOk || !bodyOk || !fieldOk || !lenOk) return null;

    return {
      owner_base: safePtrString(ownerBase),
      source_obj: safePtrString(sourceObj),
      vtable: safePtrString(vtable),
      refs: { ref1, ref2 },
      conversation,
      uuid,
      body,
      ints: {
        i9c: f9c,
        ia4: fa4,
        ic0: fc0,
        ic8: fc8,
        id8: fd8,
        i670: f670,
      },
    };
  } catch (e) {
    return null;
  }
}

rpc.exports.scan = async () => {
  const mod = Process.getModuleByName('Weixin.dll');
  const results = [];
  const seen = {};
  const ranges = (await Process.enumerateRanges('rw-'))
    .filter(r => !r.file || !r.file.path);

  for (const range of ranges) {
    const maxChunk = 0x200000;
    for (let offset = 0; offset < range.size; offset += maxChunk) {
      const remaining = range.size - offset;
      const chunkSize = remaining > maxChunk ? maxChunk : remaining;
      if (chunkSize < 0x20) continue;
      const chunkBase = range.base.add(offset);
      let bytes;
      try {
        bytes = chunkBase.readByteArray(chunkSize);
      } catch (e) {
        continue;
      }
      if (bytes === null) continue;
      const view = new DataView(bytes);
      const baseBig = BigInt(chunkBase.toString());
      const limit = chunkSize - 0x20;
      for (let off = 0; off <= limit; off += 8) {
        const abs = baseBig + BigInt(off);
        const expect0 = abs - 8n;
        const expect1 = abs - 24n;
        const q0lo = view.getUint32(off, true);
        const q0hi = view.getUint32(off + 4, true);
        const q1lo = view.getUint32(off + 8, true);
        const q1hi = view.getUint32(off + 12, true);
        if (q0lo !== Number(expect0 & 0xffffffffn) || q0hi !== Number((expect0 >> 32n) & 0xffffffffn)) continue;
        if (q1lo !== Number(expect1 & 0xffffffffn) || q1hi !== Number((expect1 >> 32n) & 0xffffffffn)) continue;

        const ownerBase = ptr('0x' + (abs - 24n).toString(16));
        const sourceObj = ptr('0x' + (abs - 8n).toString(16));
        const candidate = validateCandidate(mod, ownerBase, sourceObj);
        if (!candidate) continue;

        const key = candidate.owner_base + '|' + candidate.source_obj;
        if (seen[key]) continue;
        seen[key] = true;
        results.push(candidate);
      }
    }
  }

  results.sort((a, b) => {
    const ax = a.conversation ? 1 : 0;
    const bx = b.conversation ? 1 : 0;
    if (ax !== bx) return bx - ax;
    const ab = a.body ? 1 : 0;
    const bb = b.body ? 1 : 0;
    if (ab !== bb) return bb - ab;
    return a.owner_base.localeCompare(b.owner_base);
  });

  return {
    count: results.length,
    results,
  };
};
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="Exact Weixin.exe PID to attach to")
    parser.add_argument("--limit", type=int, default=50, help="Max results to print")
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
    script = session.create_script(SCRIPT)

    def on_message(message, data):
      payload = message.get("payload", message)
      sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
      sys.stdout.flush()

    script.on("message", on_message)
    script.load()
    start = time.time()
    result = script.exports_sync.scan()
    elapsed = time.time() - start
    trimmed = {
      "pid": pid,
      "elapsed_seconds": round(elapsed, 3),
      "count": result.get("count", 0),
      "results": result.get("results", [])[:args.limit],
    }
    sys.stdout.write(json.dumps(trimmed, ensure_ascii=False, indent=2) + "\n")
    sys.stdout.flush()
    session.detach()


if __name__ == "__main__":
    main()
