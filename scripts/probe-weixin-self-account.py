#!/usr/bin/env python
import argparse
import json
import sys
import threading

import frida


SCRIPT = r"""
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

function readInterestingStdStrings(base, maxOffset) {
  const hits = [];
  for (let off = 0; off <= maxOffset; off += 0x8) {
    const value = readStdString(base.add(off));
    if (!value || value.length === 0) continue;
    if (/[^\x09\x0a\x0d\x20-\x7e\u0080-\uffff]/.test(value)) continue;
    hits.push({
      offset: '0x' + off.toString(16),
      value,
    });
  }
  return hits;
}

function readU32Fields(base, offsets) {
  const out = {};
  for (const off of offsets) {
    try {
      out['0x' + off.toString(16)] = base.add(off).readU32();
    } catch (e) {}
  }
  return out;
}

const mod = Process.getModuleByName('Weixin.dll');
const getSnapshotMgr = new NativeFunction(mod.base.add(0x1f540), 'pointer', []);
const buildSnapshot = new NativeFunction(mod.base.add(0x20aa0), 'pointer', ['pointer', 'pointer', 'uchar']);
const getCtxShared = new NativeFunction(mod.base.add(0x20800), 'pointer', ['pointer']);
const cloneStdString = new NativeFunction(mod.base.add(0x0f6cb0), 'pointer', ['pointer']);
const getLoginSid = new NativeFunction(mod.base.add(0x303ec0), 'uint64', ['pointer']);
const getLoginDiffBase = new NativeFunction(mod.base.add(0x303e70), 'uint64', ['pointer']);
const getIsAutoLogin = new NativeFunction(mod.base.add(0x303ea0), 'bool', ['pointer']);
const getIsSyncRecord = new NativeFunction(mod.base.add(0x303e80), 'uchar', ['pointer']);
const getPcLoginType = new NativeFunction(mod.base.add(0x303eb0), 'uint32', ['pointer']);

const sharedBuf = Memory.alloc(0x10);
sharedBuf.writeByteArray(new Uint8Array(0x10));
getCtxShared(sharedBuf);
const ctxPtr = sharedBuf.readPointer();
const ctxRef = sharedBuf.add(0x8).readPointer();

const snapshotMgr = getSnapshotMgr();
const snapshotVtable = snapshotMgr.readPointer();
const getAccountUsername = new NativeFunction(snapshotVtable.add(0x20).readPointer(), 'pointer', ['pointer']);
const snapshotBuf = Memory.alloc(0x200);
snapshotBuf.writeByteArray(new Uint8Array(0x200));
buildSnapshot(snapshotMgr, snapshotBuf, 1);
const accountUsernameObj = cloneStdString(getAccountUsername(snapshotMgr));
const accountUsername = readStdString(accountUsernameObj);

let ctxInfo = null;
if (!ctxPtr.isNull()) {
  const sid = getLoginSid(ctxPtr);
  const diffBase = getLoginDiffBase(ctxPtr);
  ctxInfo = {
    ctx_ptr: ctxPtr.toString(),
    ctx_ref: ctxRef.toString(),
    is_auto_login: !!getIsAutoLogin(ctxPtr),
    is_sync_record: getIsSyncRecord(ctxPtr),
    pc_login_type: getPcLoginType(ctxPtr),
    login_sid: sid.toString(),
    login_diff_base: diffBase.toString(),
    login_diff_ms: sid.sub(diffBase).toString(),
    raw_u32: readU32Fields(ctxPtr, [0x4f8, 0x4fc, 0x500, 0x504, 0x508, 0x50c]),
  };
}

const snapshotStrings = readInterestingStdStrings(snapshotBuf, 0x180);
const snapshotFields = {
  user_name: readStdString(snapshotBuf.add(0x0)),
  nick_name: readStdString(snapshotBuf.add(0x28)),
  auto_auth_key: readStdString(snapshotBuf.add(0x48)),
  head_img_url: readStdString(snapshotBuf.add(0x68)),
  pc_account_name: readStdString(snapshotBuf.add(0x88)),
  server_id_like: readStdString(snapshotBuf.add(0xa8)),
  extra_d0: readStdString(snapshotBuf.add(0xd0)),
  flags_0x20: readU32Fields(snapshotBuf, [0x20, 0x24]),
  tail_0xc8: readU32Fields(snapshotBuf, [0xc8, 0xcc, 0xe8, 0xec, 0xf0, 0xf4, 0xf8, 0xfc]),
};
const summary = {};
for (const hit of snapshotStrings) {
  if (hit.value.startsWith('wxid_')) summary.wxid = hit.value;
  if (hit.value === 'zumalabs' || /^[A-Za-z][A-Za-z0-9_\-]{2,}$/.test(hit.value)) {
    if (!summary.account_like || hit.value === 'zumalabs') summary.account_like = hit.value;
  }
  if (hit.value === 'Chase' || /[\u4e00-\u9fff]/.test(hit.value) || hit.value.includes(' ')) {
    if (!summary.display_like || hit.value === 'Chase') summary.display_like = hit.value;
  }
  if (hit.value.startsWith('http')) summary.avatar_like = hit.value;
}

send({
  kind: 'self_account_probe',
  pid: Process.id,
  module_base: mod.base.toString(),
  funcs: {
    getSnapshotMgr: mod.base.add(0x1f540).toString(),
    buildSnapshot: mod.base.add(0x20aa0).toString(),
    getCtxShared: mod.base.add(0x20800).toString(),
  },
  manager: {
    ptr: snapshotMgr.toString(),
    vtable: snapshotVtable.toString(),
    account_username: accountUsername,
  },
  ctx: ctxInfo,
  snapshot_buf: snapshotBuf.toString(),
  snapshot_fields: snapshotFields,
  snapshot_strings: snapshotStrings,
  summary,
});
"""


def on_message(message, _data):
    if message["type"] == "send":
        payload = message["payload"]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(message, ensure_ascii=False, indent=2), file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    args = parser.parse_args()

    session = frida.attach(args.pid)
    script = session.create_script(SCRIPT)
    script.on("message", on_message)
    script.load()

    done = threading.Event()
    done.wait(1.0)

    session.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
