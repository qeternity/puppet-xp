from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import frida


SCRIPT_SOURCE = r"""
const OFFSETS = {
  entryA: 0x15b3990,
  entryB: 0x15b1350,
  detachedSeedCtor: 0x15b1c80,
  detachedSeedCopy: 0x15b20b0,
  entryBPairNormalize: 0x633270,
  entryBPairNormalizeParse: 0x2ad6b0,
  entryBPairNormalizeBuild: 0x2ac4d0,
  entryBWorkerDispatch: 0x15ea920,
  threadPairFetch: 0x020800,
  pairCopyMaybe: 0x2fbff0,
  workerEntry: 0x15e8200,
  workerCtor: 0x33fc800,
  builderPopulate: 0x33fccd0,
  builderSession: 0x1f540,
  builderInitA: 0x9b12c0,
  builderInitB: 0x9b0e40,
  builderConversationPrep: 0xd0a840,
  builderMessagePrep: 0x2836500,
  builderMessagePrepAuxA: 0x332df80,
  builderMessagePrepAuxC: 0x1618040,
  builderMessagePrepLoopPrep: 0x36d5e0,
  builderMessagePrepLoopKey: 0x13cfcb0,
  builderMessagePrepLoopSourcePick: 0x9b3bd0,
  builderMessagePrepLoopKeyNewsappCheck: 0xa81bb0,
  builderMessagePrepLoopKeyNotificationCheck: 0xa82a10,
  builderMessagePrepLoopKeyChatCheck: 0xa802c0,
  builderMessagePrepLoopKeyBrandCustomerCheck: 0xa82df0,
  builderMessagePrepLoopKeyFallbackCheck: 0xa819a0,
  builderMessagePrepLoopSelect: 0xebe6f0,
  detachedPostSelectWalker: 0xce4dd0,
  builderMessagePrepLoopItem: 0xebe570,
  builderMessagePrepLoopFinalize: 0x968840,
  builderTailFormat: 0x2835d60,
  builderTailA: 0x17e5560,
  builderTailB: 0x288c030,
  builderTailC: 0x17e63a0,
  builderTailD: 0x1685370,
  builderWorkerFieldA: 0x9b14d0,
  builderWorkerFieldB: 0x9b1990,
  helperTableInsert: 0x15eb320,
  helperWalk: 0x15ebec0,
  workerFinalize: 0x15eb0d0,
  selfString: 0x0c3680,
  goodSourceVtable: 0x7ebe788,
  badSourceVtable: 0x811c028,
  goodSourcePairCtor: 0x633150,
};

const rawSend = send;

function sendHookError(hook, phase, error) {
  try {
    rawSend({
      kind: "hook-error",
      hook,
      phase,
      threadId: Process.getCurrentThreadId(),
      error: String(error),
    });
  } catch (_) {
  }
}

function guardHook(hook, phase, fn) {
  return function (...args) {
    try {
      return fn.apply(this, args);
    } catch (error) {
      sendHookError(hook, phase, error);
      return undefined;
    }
  };
}

const CALLER_SIZE = 0x478;
const REQUEST_REGION_SIZE = 0x3a0;
const TAIL_REGION_OFFSET = 0x390;
const TAIL_REGION_SIZE = CALLER_SIZE - TAIL_REGION_OFFSET;
const TEMPLATE_BLOCK_SIZE = 0x6b0;
const TEMPLATE_USER_OFFSET = 0x10;
const moduleBase = Process.getModuleByName("Weixin.dll").base;
const GOOD_SOURCE_VTABLE = moduleBase.add(OFFSETS.goodSourceVtable);
const BAD_SOURCE_VTABLE = moduleBase.add(OFFSETS.badSourceVtable);
const readSelfStringNative = new NativeFunction(moduleBase.add(OFFSETS.selfString), "pointer", [], {
  exceptions: "steal",
});
const buildDetachedSeedNative = new NativeFunction(
  moduleBase.add(OFFSETS.detachedSeedCtor),
  "pointer",
  ["pointer"],
  { exceptions: "steal" }
);
const buildGoodSourcePairNative = new NativeFunction(
  moduleBase.add(OFFSETS.goodSourcePairCtor),
  "pointer",
  ["pointer", "pointer", "pointer", "pointer"],
  { exceptions: "steal" }
);
globalThis.callStringAllocs = [];
globalThis.persistentStringAllocs = [];
globalThis.exceptionReportState = {
  recent: Object.create(null),
};

function safeContextRegister(context, name) {
  try {
    if (!context || context[name] === undefined || context[name] === null) {
      return null;
    }
    return ptr(context[name]).toString();
  } catch (_) {
    return null;
  }
}

function shouldEmitNativeException(details, threadId, pc, address, memoryOperation, memoryAddress) {
  if (!shouldTraceDetachedThread()) {
    return false;
  }

  const recent = globalThis.exceptionReportState.recent;
  const key = [
    threadId,
    details.type || "",
    pc || "",
    address || "",
    memoryOperation || "",
    memoryAddress || "",
  ].join("|");
  const now = Date.now();
  const lastSeen = recent[key] || 0;
  recent[key] = now;

  // Weixin throws many identical first-chance CoreUI/C++ exceptions on hot
  // paths. Logging every instance materially perturbs the run, so only emit
  // the first copy of a repeating signature inside a short window.
  if (lastSeen && now - lastSeen < 1000) {
    return false;
  }

  let recentCount = 0;
  for (const [recentKey, recentAt] of Object.entries(recent)) {
    if (now - recentAt > 10000) {
      delete recent[recentKey];
      continue;
    }
    recentCount += 1;
  }
  if (recentCount > 128) {
    for (const recentKey of Object.keys(recent).slice(0, recentCount - 128)) {
      delete recent[recentKey];
    }
  }

  return true;
}

Process.setExceptionHandler((details) => {
  try {
    const threadId = Process.getCurrentThreadId();
    const pc = safeContextRegister(details.context, "pc") || safeContextRegister(details.context, "rip");
    const sp = safeContextRegister(details.context, "sp") || safeContextRegister(details.context, "rsp");
    const fp = safeContextRegister(details.context, "fp") || safeContextRegister(details.context, "rbp");
    const address = details.address ? ptr(details.address).toString() : null;
    const memoryOperation = details.memory ? details.memory.operation || null : null;
    const memoryAddress =
      details.memory && details.memory.address ? ptr(details.memory.address).toString() : null;

    if (!shouldEmitNativeException(details, threadId, pc, address, memoryOperation, memoryAddress)) {
      return false;
    }
    rawSend({
      kind: "native-exception",
      threadId,
      type: details.type || null,
      pc,
      sp,
      fp,
      address,
      memory: details.memory
        ? {
            operation: memoryOperation,
            address: memoryAddress,
          }
        : null,
      registers: {
        rax: safeContextRegister(details.context, "rax"),
        rbx: safeContextRegister(details.context, "rbx"),
        rcx: safeContextRegister(details.context, "rcx"),
        rdx: safeContextRegister(details.context, "rdx"),
        rsi: safeContextRegister(details.context, "rsi"),
        rdi: safeContextRegister(details.context, "rdi"),
        r8: safeContextRegister(details.context, "r8"),
        r9: safeContextRegister(details.context, "r9"),
        r10: safeContextRegister(details.context, "r10"),
        r11: safeContextRegister(details.context, "r11"),
        r12: safeContextRegister(details.context, "r12"),
        r13: safeContextRegister(details.context, "r13"),
        r14: safeContextRegister(details.context, "r14"),
        r15: safeContextRegister(details.context, "r15"),
      },
      backtrace: details.context ? formatBacktrace(details.context).slice(0, 16) : [],
    });
  } catch (_) {
  }
  return false;
});

function hex(value) {
  return ptr(value).toString();
}

function safeReadPointer(address) {
  try {
    return ptr(address).readPointer();
  } catch (_) {
    return null;
  }
}

function safeReadU32(address) {
  try {
    return ptr(address).readU32();
  } catch (_) {
    return null;
  }
}

function safeReadU8(address) {
  try {
    return ptr(address).readU8();
  } catch (_) {
    return null;
  }
}

function safeReadAnsi(address, length) {
  try {
    if (length === 0) {
      return "";
    }
    return ptr(address).readUtf8String(Number(length));
  } catch (_) {
    return null;
  }
}

function safeReadCString(address) {
  try {
    return ptr(address).readUtf8String();
  } catch (_) {
    return null;
  }
}

function formatBacktrace(context) {
  try {
    return Thread.backtrace(context, Backtracer.ACCURATE).map((address) => ({
      address: ptr(address).toString(),
      symbol: DebugSymbol.fromAddress(address).toString(),
    }));
  } catch (_) {
    return [];
  }
}

function describeAddress(address) {
  const target = ptr(address);
  try {
    const module = Process.findModuleByAddress(target);
    const symbol = DebugSymbol.fromAddress(target);
    return {
      address: target.toString(),
      module: module ? module.name : null,
      base: module ? module.base.toString() : null,
      offset: module ? target.sub(module.base).toString() : null,
      symbol: symbol ? symbol.toString() : null,
    };
  } catch (_) {
    return {
      address: target.toString(),
      module: null,
      base: null,
      offset: null,
      symbol: null,
    };
  }
}

function readHex(address, size) {
  try {
    return hexdump(ptr(address), {
      offset: 0,
      length: size,
      header: false,
      ansi: false,
    });
  } catch (_) {
    return null;
  }
}

function readSmallString(address) {
  const base = ptr(address);
  try {
    const length = base.add(0x10).readU64();
    const capacity = base.add(0x18).readU64();
    const heap = capacity.compare(0x0f) > 0;
    const dataPtr = heap ? base.readPointer() : base;
    return {
      address: base.toString(),
      data: dataPtr.toString(),
      length: length.toString(),
      capacity: capacity.toString(),
      heap,
      text: safeReadAnsi(dataPtr, length),
    };
  } catch (error) {
    return {
      address: base.toString(),
      error: String(error),
    };
  }
}

function inspectOuter(outer) {
  const base = ptr(outer);
  return {
    outer: base.toString(),
    requestRegion: base.add(0x08).toString(),
    tailRegion: base.add(TAIL_REGION_OFFSET).toString(),
    talkerA: readSmallString(base.add(0x38)),
    talkerB: readSmallString(base.add(0x78)),
    body: readSmallString(base.add(0xc0)),
    msgsource: readSmallString(base.add(0xe0)),
    tailFields: inspectTailRegion(base.add(TAIL_REGION_OFFSET)),
  };
}

function inspectTailRegion(address) {
  const base = ptr(address);
  const qwordOffsets = [0x0, 0x8, 0x48, 0x88, 0xc8, 0xd0, 0xd8, 0xe0];
  const qwords = {};
  for (const offset of qwordOffsets) {
    try {
      qwords[`0x${offset.toString(16)}`] = base.add(offset).readPointer().toString();
    } catch (_) {
      qwords[`0x${offset.toString(16)}`] = null;
    }
  }
  return qwords;
}

function inspectPointerFields(address, offsets) {
  const object = ptr(address);
  const fields = {};
  offsets.forEach((offset) => {
    fields[`0x${offset.toString(16)}`] = hex(safeReadPointer(object.add(offset)));
  });
  return fields;
}

function inspectDwordFields(address, offsets) {
  const object = ptr(address);
  const fields = {};
  offsets.forEach((offset) => {
    fields[`0x${offset.toString(16)}`] = safeReadU32(object.add(offset));
  });
  return fields;
}

function inspectRequestRegion(address) {
  const base = ptr(address);
  return {
    address: base.toString(),
    s10: readSmallString(base.add(0x10)),
    s30: readSmallString(base.add(0x30)),
    s50: readSmallString(base.add(0x50)),
    s70: readSmallString(base.add(0x70)),
    sB8: readSmallString(base.add(0xb8)),
    sD8: readSmallString(base.add(0xd8)),
    s118: readSmallString(base.add(0x118)),
    s138: readSmallString(base.add(0x138)),
    s160: readSmallString(base.add(0x160)),
    s180: readSmallString(base.add(0x180)),
    s1A0: readSmallString(base.add(0x1a0)),
    s1C0: readSmallString(base.add(0x1c0)),
    s1E0: readSmallString(base.add(0x1e0)),
    s200: readSmallString(base.add(0x200)),
    s230: readSmallString(base.add(0x230)),
    s250: readSmallString(base.add(0x250)),
    s2A0: readSmallString(base.add(0x2a0)),
    s300: readSmallString(base.add(0x300)),
    dwords: inspectDwordFields(base, [0x270, 0x278, 0x280, 0x290, 0x380]),
    pointers: inspectPointerFields(base, [0x288, 0x290, 0x298]),
  };
}

function safeInspectRequestRegion(address) {
  try {
    return inspectRequestRegion(address);
  } catch (error) {
    return {
      address: ptr(address).toString(),
      error: String(error),
    };
  }
}

function inspectSyntheticSourceObject(address) {
  const base = ptr(address);
  return {
    address: base.toString(),
    vtable: base.readPointer().toString(),
    dword9c: base.add(0x9c).readU32(),
    dwordD8: base.add(0xd8).readU32(),
    talker: readSmallString(base.add(0xb0)),
    selfField: readSmallString(base.add(0x660)),
    rc240: readRcPair(base.add(0x240)),
    rc278: readRcPair(base.add(0x278)),
    rc288: readRcPair(base.add(0x288)),
    rc298: readRcPair(base.add(0x298)),
  };
}

function readRcPair(address) {
  const base = ptr(address);
  const object = base.readPointer();
  const ref = base.add(Process.pointerSize).readPointer();
  let vtable = null;
  try {
    if (!object.isNull()) {
      vtable = object.readPointer().toString();
    }
  } catch (_) {
    vtable = null;
  }
  return {
    address: base.toString(),
    object: object.toString(),
    ref: ref.toString(),
    vtable,
  };
}

function safeReadRcPair(address) {
  try {
    return readRcPair(address);
  } catch (error) {
    return {
      address: ptr(address).toString(),
      error: String(error),
    };
  }
}

function inspectDetachedSeedCopySource(address) {
  const base = ptr(address);
  return {
    address: base.toString(),
    headHex: readHex(base, 0x80),
    pointers: inspectPointerFields(base, [0x00, 0x08, 0x10, 0x18, 0x20, 0x28]),
    dwords: inspectDwordFields(base, [0x0c, 0x10, 0x14, 0x18, 0x1c]),
    requestLike: safeInspectRequestRegion(base),
  };
}

function inspectHelperNodeObject(address) {
  const object = ptr(address);
  return {
    address: object.toString(),
    vtable: hex(safeReadPointer(object)),
    strings: {
      s38: readSmallString(object.add(0x38)),
    },
    pointers: inspectPointerFields(object, [0x08, 0x10, 0x18, 0x20]),
    pairSlots: {
      slot0: readRcPair(object.add(0x78)),
      slot1: readRcPair(object.add(0x88)),
      slot2: readRcPair(object.add(0x98)),
    },
    headHex: readHex(object, 0xc0),
  };
}

function inspectFinalizeSourceObject(address) {
  const object = ptr(address);
  return {
    address: object.toString(),
    header: {
      qword0: hex(safeReadPointer(object)),
      qword8: hex(safeReadPointer(object.add(0x08))),
    },
    stage: {
      typePtr: hex(safeReadPointer(object.add(0x270))),
      ownerRefA: safeReadU32(object.add(0x278)),
      ownerRefB: safeReadU32(object.add(0x27c)),
      chainedPair: readRcPair(object.add(0x280)),
    },
    pointers: inspectPointerFields(object, [0x110, 0x120, 0x240, 0x248]),
    dwords: inspectDwordFields(object, [0x0c, 0x10, 0x118, 0x124, 0x128, 0x134, 0x138, 0x230]),
    headHex: readHex(object, 0x100),
    stageHex: readHex(object.add(0x270), 0x30),
  };
}

function inspectEntryBNormalizeSource(address) {
  const object = ptr(address);
  return {
    address: object.toString(),
    qwords: inspectPointerFields(object, [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78]),
    dwords: inspectDwordFields(object, [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x58, 0x70]),
    headHex: readHex(object, 0x80),
  };
}

function inspectEntryBNormalizeKeyProvider(address) {
  const object = ptr(address);
  return {
    address: object.toString(),
    qwords: inspectPointerFields(object, [0x00, 0x08, 0x10, 0x18, 0x20, 0x28]),
    dwords: inspectDwordFields(object, [0x00, 0x08, 0x10, 0x18, 0x20, 0x28]),
    headHex: readHex(object, 0x40),
  };
}

function readFinalizeResult(address) {
  const base = ptr(address);
  try {
    return {
      address: base.toString(),
      object: hex(base.readPointer()),
      text: readSmallString(base.add(0x08)),
      tailValue: hex(base.add(0x28).readPointer()),
      tailRef: hex(base.add(0x30).readPointer()),
    };
  } catch (error) {
    return {
      address: base.toString(),
      error: String(error),
    };
  }
}

function readTalkerFromSourceObject(address) {
  try {
    return readSmallString(ptr(address).add(0xb0));
  } catch (_) {
    return null;
  }
}

function shouldTraceDetachedThread() {
  return globalThis.swapState.enabled && Process.getCurrentThreadId() === globalThis.swapState.threadId;
}

function shouldTraceDetachedHotPath() {
  return shouldTraceDetachedThread() && !!(globalThis.swapState && globalThis.swapState.deepTrace);
}

function shouldTraceCapturedWorkerThread() {
  return (
    globalThis.captureState &&
    globalThis.captureState.status === "captured" &&
    Number(globalThis.captureState.capturedThreadId || 0) === Process.getCurrentThreadId()
  );
}

function shouldTraceFinalizeThread() {
  return shouldTraceDetachedThread() || shouldTraceCapturedWorkerThread();
}

function writeSmallString(address, text, persistent) {
  const base = ptr(address);
  const bytes = Memory.allocUtf8String(text);
  const length = text.length;
  if (length <= 15) {
    base.writeUtf8String(text);
    for (let i = length + 1; i < 16; i += 1) {
      base.add(i).writeU8(0);
    }
    base.add(0x10).writeU64(length);
    base.add(0x18).writeU64(15);
    return;
  }
  if (persistent) {
    globalThis.persistentStringAllocs.push(bytes);
  } else {
    globalThis.callStringAllocs.push(bytes);
  }
  base.writePointer(bytes);
  base.add(0x08).writeU64(0);
  base.add(0x10).writeU64(length);
  base.add(0x18).writeU64(Math.max(31, length | 0xf));
}

globalThis.captureState = {
  status: "idle",
  conversationId: null,
  capturedConversationId: null,
  capturedWrapper: null,
  capturedObject: null,
  capturedTemplateRegion: null,
  capturedThreadId: 0,
};
globalThis.autoDetachedConfig = null;
globalThis.swapState = {
  enabled: false,
  mode: "captured",
  threadId: 0,
  conversationId: null,
  deepTrace: false,
  selfUsername: null,
  liveWrapperAddress: null,
  preparedPairAddress: null,
  preparedWrapper: null,
  preparedObject: null,
  preparedTemplateRegion: null,
};
globalThis.capturedTemplateBlock = null;
globalThis.capturedTailTemplateBlock = null;
globalThis.liveCloneTemplateBlock = null;
globalThis.liveCloneTailTemplateBlock = null;
globalThis.syntheticPrepared = null;

function cloneTemplateBlock(templateBlock, conversationId) {
  if (templateBlock === null) {
    return null;
  }

  const cloneBase = Memory.alloc(TEMPLATE_BLOCK_SIZE);
  cloneBase.writeByteArray(templateBlock);

  const cloneObject = cloneBase.add(TEMPLATE_USER_OFFSET);
  cloneBase.add(0x08).writeU64(0x100000001);
  cloneObject.add(0x08).writePointer(cloneObject);
  cloneObject.add(0x10).writePointer(cloneBase);
  if (conversationId) {
    writeSmallString(cloneObject.add(0xb0), conversationId, true);
  }

  return {
    base: cloneBase,
    object: cloneObject,
  };
}

function cloneCapturedTemplate(conversationId) {
  return cloneTemplateBlock(globalThis.capturedTemplateBlock, conversationId);
}

function cloneTemplateFromLiveWrapper(wrapperAddress, conversationId) {
  const sourceBase = ptr(wrapperAddress);
  return cloneTemplateBlock(sourceBase.readByteArray(TEMPLATE_BLOCK_SIZE), conversationId);
}

function getPreparedSwapTailTemplate() {
  if (!globalThis.swapState || !globalThis.swapState.enabled) {
    return null;
  }
  if (globalThis.swapState.mode === "captured") {
    return globalThis.capturedTailTemplateBlock;
  }
  if (globalThis.swapState.mode === "liveclone" || globalThis.swapState.mode === "liveraw") {
    return globalThis.liveCloneTailTemplateBlock;
  }
  if (globalThis.swapState.mode === "synthetic" && globalThis.syntheticPrepared) {
    return ptr(globalThis.syntheticPrepared.base).readByteArray(TAIL_REGION_SIZE);
  }
  return null;
}

function readKnownSelfUsername() {
  const nativeSelf = safeReadCString(readSelfStringNative());
  if (nativeSelf && /^(wxid_|gh_|v1_)/.test(nativeSelf)) {
    return nativeSelf;
  }
  return null;
}

function patchSyntheticGoodSource(objectAddress, conversationId, selfUsername) {
  const base = ptr(objectAddress);
  const effectiveSelf = selfUsername || readKnownSelfUsername();
  if (conversationId) {
    writeSmallString(base.add(0xb0), conversationId, true);
  }
  if (effectiveSelf) {
    writeSmallString(base.add(0x660), effectiveSelf, true);
  }
  base.add(0x9c).writeU32(1);
  base.add(0xd8).writeU32(10000);
}

function buildSyntheticGoodPair(conversationId, selfUsername) {
  const pairAddress = Memory.alloc(Process.pointerSize * 2);
  pairAddress.writeByteArray(new Uint8Array(Process.pointerSize * 2));
  buildGoodSourcePairNative(pairAddress, ptr(0), ptr(0), ptr(0));

  const snapshot = readRcPair(pairAddress);
  if (snapshot.object === "0x0" || snapshot.vtable !== GOOD_SOURCE_VTABLE.toString()) {
    throw new Error("good source constructor returned unexpected pair: " + JSON.stringify(snapshot));
  }

  patchSyntheticGoodSource(snapshot.object, conversationId, selfUsername);
  const patched = readRcPair(pairAddress);
  return {
    pairAddress,
    base: ptr(patched.ref),
    object: ptr(patched.object),
    snapshot: patched,
    templateRegion: ptr(patched.object).add(0xd8),
  };
}

function buildSeedRequestTemplate() {
  const pairAddress = Memory.alloc(Process.pointerSize * 2);
  pairAddress.writeByteArray(new Uint8Array(Process.pointerSize * 2));
  buildDetachedSeedNative(pairAddress);
  const snapshot = readRcPair(pairAddress);
  if (snapshot.object === "0x0") {
    throw new Error("detached seed constructor returned null pair");
  }
  return {
    pairAddress,
    base: ptr(snapshot.ref),
    object: ptr(snapshot.object),
    snapshot,
    templateRegion: ptr(snapshot.object).add(0xd8),
    tailTemplate: ptr(snapshot.ref).readByteArray(TAIL_REGION_SIZE),
  };
}

function applyKnownSelfContextToRequestRegion(regionAddress, selfUsername, nickname, alias) {
  const base = ptr(regionAddress);
  const effectiveSelf = selfUsername || readKnownSelfUsername();
  if (effectiveSelf) {
    writeSmallString(base.add(0x10), effectiveSelf, false);
    writeSmallString(base.add(0x50), effectiveSelf, false);
  }
  if (nickname) {
    writeSmallString(base.add(0x2a0), nickname, false);
  }
  if (alias) {
    writeSmallString(base.add(0x300), alias, false);
  }
}

function maybeCaptureGoodTemplate(inputPair) {
  try {
    if (globalThis.captureState.status !== "armed") {
      return;
    }

    const snapshot = readRcPair(inputPair);
    if (snapshot.object === "0x0" || snapshot.vtable !== GOOD_SOURCE_VTABLE.toString()) {
      return;
    }

    const talker = readTalkerFromSourceObject(snapshot.object);
    if (talker === null || talker.text !== globalThis.captureState.conversationId) {
      return;
    }

    const wrapperBase = ptr(snapshot.object).sub(TEMPLATE_USER_OFFSET);
    globalThis.capturedTemplateBlock = wrapperBase.readByteArray(TEMPLATE_BLOCK_SIZE);
    globalThis.capturedTailTemplateBlock = wrapperBase.readByteArray(TAIL_REGION_SIZE);
    globalThis.captureState = {
      status: "captured",
      conversationId: globalThis.captureState.conversationId,
      capturedConversationId: talker.text,
      capturedWrapper: wrapperBase.toString(),
      capturedObject: snapshot.object,
      capturedTemplateRegion: ptr(snapshot.object).add(0xd8).toString(),
      capturedThreadId: Process.getCurrentThreadId(),
    };
    rawSend({
      kind: "good-template-captured",
      threadId: Process.getCurrentThreadId(),
      wrapper: wrapperBase.toString(),
      object: snapshot.object,
      templateRegion: ptr(snapshot.object).add(0xd8).toString(),
      talker,
    });
    if (globalThis.autoDetachedConfig && !globalThis.autoDetachedConfig.started) {
      globalThis.autoDetachedConfig.started = true;
      const config = Object.assign({}, globalThis.autoDetachedConfig, {
        templateRegion: ptr(snapshot.object).add(0xd8).toString(),
        threadId:
          Number(globalThis.autoDetachedConfig.threadId || 0) || Process.getCurrentThreadId(),
      });
      rawSend({
        kind: "auto-detached-launching",
        threadId: Process.getCurrentThreadId(),
        templateRegion: config.templateRegion,
        targetThreadId: config.threadId,
        entry: config.entryName,
        body: config.body,
      });
      globalThis.swapState = {
        enabled: true,
        mode: "captured",
        threadId: config.threadId,
        conversationId: config.conversationId,
        deepTrace: !!config.deepTrace,
        selfUsername: null,
        liveWrapperAddress: null,
        preparedPairAddress: null,
        preparedWrapper: wrapperBase.toString(),
        preparedObject: snapshot.object,
        preparedTemplateRegion: ptr(snapshot.object).add(0xd8).toString(),
      };
      setImmediate(function () {
        scheduleDetached(
          config.templateRegion,
          config.conversationId,
          config.body,
          config.msgsource,
          config.entryName,
          config.threadId,
          config.initRequestFromSeedCtor,
          config.seedTailFromSeedTemplate,
          config.seedTailFromSwapTemplate,
          config.requestSelfUsername,
          config.requestNickname,
          config.requestAlias
        );
      });
    }
  } catch (error) {
    rawSend({
      kind: "good-template-capture-error",
      threadId: Process.getCurrentThreadId(),
      error: String(error),
    });
  }
}

function maybeSwapDetachedPair(inputPair) {
  if (!globalThis.swapState.enabled) {
    return;
  }
  if (Process.getCurrentThreadId() !== globalThis.swapState.threadId) {
    return;
  }

  const snapshot = readRcPair(inputPair);
  rawSend({
    kind: "detached-swap-check",
    threadId: Process.getCurrentThreadId(),
    pair: snapshot,
    expectedBadVtable: BAD_SOURCE_VTABLE.toString(),
    mode: globalThis.swapState.mode,
  });
  if (snapshot.object === "0x0" || snapshot.vtable !== BAD_SOURCE_VTABLE.toString()) {
    rawSend({
      kind: "detached-swap-skipped",
      threadId: Process.getCurrentThreadId(),
      reason: snapshot.object === "0x0" ? "null-object" : "unexpected-vtable",
      pair: snapshot,
    });
    return;
  }

  let cloned = null;
  if (globalThis.swapState.mode === "captured") {
    if (globalThis.capturedTemplateBlock === null) {
      return;
    }
    cloned = cloneCapturedTemplate(globalThis.swapState.conversationId);
  } else if (globalThis.swapState.mode === "liveclone") {
    if (globalThis.liveCloneTemplateBlock === null) {
      return;
    }
    cloned = cloneTemplateBlock(globalThis.liveCloneTemplateBlock, globalThis.swapState.conversationId);
  } else if (globalThis.swapState.mode === "liveraw") {
    if (!globalThis.swapState.liveWrapperAddress) {
      return;
    }
    cloned = {
      base: ptr(globalThis.swapState.liveWrapperAddress),
      object: ptr(globalThis.swapState.liveWrapperAddress).add(TEMPLATE_USER_OFFSET),
    };
  } else if (globalThis.swapState.mode === "synthetic") {
    cloned =
      globalThis.syntheticPrepared ||
      buildSyntheticGoodPair(globalThis.swapState.conversationId, globalThis.swapState.selfUsername);
  }
  if (cloned === null) {
    rawSend({
      kind: "detached-swap-skipped",
      threadId: Process.getCurrentThreadId(),
      reason: "clone-null",
      mode: globalThis.swapState.mode,
    });
    return;
  }

  ptr(inputPair).writePointer(cloned.object);
  ptr(inputPair).add(Process.pointerSize).writePointer(cloned.base);

  rawSend({
    kind: globalThis.swapState.mode === "synthetic" ? "detached-pair-swapped-synthetic" : "detached-pair-swapped",
    threadId: Process.getCurrentThreadId(),
    oldPair: snapshot,
    newPair: readRcPair(inputPair),
  });
}

Interceptor.attach(moduleBase.add(OFFSETS.workerCtor), {
  onEnter(args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "worker-ctor-enter",
      threadId: Process.getCurrentThreadId(),
      out: ptr(args[0]).toString(),
      pair: readRcPair(args[1]),
      mode: Number(args[2]),
    });
  },
  onLeave(retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "worker-ctor-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  },
});

Interceptor.attach(moduleBase.add(OFFSETS.builderPopulate), {
  onEnter(args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "builder-populate-enter",
      threadId: Process.getCurrentThreadId(),
      out: ptr(args[0]).toString(),
      worker: ptr(args[1]).toString(),
    });
  },
  onLeave(retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "builder-populate-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  },
});

Interceptor.attach(moduleBase.add(OFFSETS.workerEntry), {
  onEnter(args) {
    if (globalThis.captureState.status === "armed") {
      const pair = safeReadRcPair(args[2]);
      rawSend({
        kind: "capture-worker-entry",
        threadId: Process.getCurrentThreadId(),
        pair,
        talker: pair.object === "0x0" ? null : readTalkerFromSourceObject(pair.object),
      });
    }
    if (shouldTraceDetachedThread()) {
      rawSend({
        kind: "worker-entry-enter",
        threadId: Process.getCurrentThreadId(),
        pair: readRcPair(args[2]),
      });
    }
    maybeCaptureGoodTemplate(args[2]);
    maybeSwapDetachedPair(args[2]);
    // Allow synthetic/live-cloned swaps to seed capture without a manual UI send.
    maybeCaptureGoodTemplate(args[2]);
  },
  onLeave(retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "worker-entry-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  },
});

Interceptor.attach(moduleBase.add(OFFSETS.entryB), {
  onEnter(args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "detached-caller-enter",
      threadId: Process.getCurrentThreadId(),
      outer: ptr(args[0]).toString(),
      state: inspectOuter(args[0]),
    });
  },
  onLeave(retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "detached-caller-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  },
});

Interceptor.attach(moduleBase.add(OFFSETS.detachedSeedCtor), {
  onEnter(args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    this.outPair = ptr(args[0]);
    rawSend({
      kind: "detached-seed-ctor-enter",
      threadId: Process.getCurrentThreadId(),
      outPair: ptr(args[0]).toString(),
    });
  },
  onLeave(retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "detached-seed-ctor-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      outPairState: safeReadRcPair(this.outPair),
    });
  },
});

Interceptor.attach(moduleBase.add(OFFSETS.detachedSeedCopy), {
  onEnter(args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    this.src = ptr(args[0]);
    this.dst = ptr(args[1]);
    rawSend({
      kind: "detached-seed-copy-enter",
      threadId: Process.getCurrentThreadId(),
      outer: this.src.toString(),
      outPair: this.dst.toString(),
      srcState: inspectDetachedSeedCopySource(this.src),
      dstBefore: safeInspectRequestRegion(this.dst),
      dstPairView: safeReadRcPair(this.dst),
    });
  },
  onLeave(retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "detached-seed-copy-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      dstAfter: safeInspectRequestRegion(this.dst),
      dstPairView: safeReadRcPair(this.dst),
    });
  },
});

Interceptor.attach(moduleBase.add(OFFSETS.threadPairFetch), {
  onEnter: guardHook("thread-pair-fetch", "enter", function (args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    this.out = ptr(args[0]);
    rawSend({
      kind: "thread-pair-fetch-enter",
      threadId: Process.getCurrentThreadId(),
      out: this.out.toString(),
      outBefore: safeReadRcPair(this.out),
    });
  }),
  onLeave: guardHook("thread-pair-fetch", "leave", function (retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "thread-pair-fetch-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      outAfter: safeReadRcPair(this.out),
      outRawPointers: inspectPointerFields(this.out, [0x0, 0x8]),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.pairCopyMaybe), {
  onEnter: guardHook("pair-copy-maybe", "enter", function (args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    this.src = ptr(args[0]);
    this.dst = ptr(args[1]);
    rawSend({
      kind: "pair-copy-maybe-enter",
      threadId: Process.getCurrentThreadId(),
      src: this.src.toString(),
      dst: this.dst.toString(),
      srcPointers: inspectPointerFields(this.src, [0x28, 0x30]),
      caller: this.returnAddress.toString(),
      callerInfo: describeAddress(this.returnAddress),
      backtrace: formatBacktrace(this.context).slice(0, 8),
    });
  }),
  onLeave: guardHook("pair-copy-maybe", "leave", function (retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "pair-copy-maybe-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      dstPair: safeReadRcPair(this.dst),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.entryBPairNormalize), {
  onEnter: guardHook("entryb-pair-normalize", "enter", function (args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    this.src = ptr(args[0]);
    this.dst = ptr(args[1]);
    rawSend({
      kind: "entryb-pair-normalize-enter",
      threadId: Process.getCurrentThreadId(),
      src: this.src.toString(),
      dst: this.dst.toString(),
      srcState: inspectEntryBNormalizeSource(this.src),
      caller: this.returnAddress.toString(),
    });
  }),
  onLeave: guardHook("entryb-pair-normalize", "leave", function (retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "entryb-pair-normalize-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      dstPair: safeReadRcPair(this.dst),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.entryBPairNormalizeParse), {
  onEnter: guardHook("entryb-pair-normalize-parse", "enter", function (args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    this.arg1 = ptr(args[1]);
    rawSend({
      kind: "entryb-pair-normalize-parse-enter",
      threadId: Process.getCurrentThreadId(),
      arg0: ptr(args[0]).toString(),
      arg1: ptr(args[1]).toString(),
      arg2: ptr(args[2]).toString(),
      arg0State: inspectEntryBNormalizeSource(args[0]),
      arg2State: inspectEntryBNormalizeKeyProvider(args[2]),
      caller: this.returnAddress.toString(),
    });
  }),
  onLeave: guardHook("entryb-pair-normalize-parse", "leave", function (retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "entryb-pair-normalize-parse-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      arg1Qwords: inspectPointerFields(this.arg1, [0x00, 0x08, 0x10, 0x18]),
      arg1Dwords: inspectDwordFields(this.arg1, [0x00, 0x08, 0x10, 0x18]),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.entryBPairNormalizeBuild), {
  onEnter: guardHook("entryb-pair-normalize-build", "enter", function (args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    this.dst = ptr(args[1]);
    rawSend({
      kind: "entryb-pair-normalize-build-enter",
      threadId: Process.getCurrentThreadId(),
      arg0: ptr(args[0]).toString(),
      arg1: ptr(args[1]).toString(),
      arg2: ptr(args[2]).toString(),
      caller: this.returnAddress.toString(),
    });
  }),
  onLeave: guardHook("entryb-pair-normalize-build", "leave", function (retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "entryb-pair-normalize-build-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      dstPair: safeReadRcPair(this.dst),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.entryBWorkerDispatch), {
  onEnter: guardHook("entryb-worker-dispatch", "enter", function (args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "entryb-worker-dispatch-enter",
      threadId: Process.getCurrentThreadId(),
      arg0: ptr(args[0]).toString(),
      arg1: ptr(args[1]).toString(),
      arg2: ptr(args[2]).toString(),
      pair: safeReadRcPair(args[2]),
    });
  }),
  onLeave: guardHook("entryb-worker-dispatch", "leave", function (retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "entryb-worker-dispatch-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.workerCtor), {
  onEnter: guardHook("worker-ctor", "enter", function (args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "worker-ctor-enter",
      threadId: Process.getCurrentThreadId(),
      pair: safeReadRcPair(args[1]),
      mode: args[2].toInt32(),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.builderPopulate), {
  onEnter: guardHook("builder-populate", "enter", function (args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    this.outPair = ptr(args[1]);
    rawSend({
      kind: "builder-populate-enter",
      threadId: Process.getCurrentThreadId(),
      worker: ptr(args[0]).toString(),
      outPair: ptr(args[1]).toString(),
      sourceState: inspectSyntheticSourceObject(safeReadPointer(ptr(args[0]).add(0x08)) || ptr(0)),
    });
  }),
  onLeave: guardHook("builder-populate", "leave", function (retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "builder-populate-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      outPair: safeReadRcPair(this.outPair),
    });
  }),
});

function attachBuilderStageHook(offset, kind, payloadFactory) {
  Interceptor.attach(moduleBase.add(offset), {
    onEnter(args) {
      if (!shouldTraceDetachedHotPath()) {
        return;
      }
      const payload = payloadFactory
        ? payloadFactory(args, {
            returnAddress: this.returnAddress,
            context: this.context,
          })
        : {};
      rawSend(
        Object.assign(
          {
            kind,
            threadId: Process.getCurrentThreadId(),
          },
          payload
        )
      );
    },
  });
}

attachBuilderStageHook(OFFSETS.builderSession, "builder-session-enter");
attachBuilderStageHook(OFFSETS.builderInitA, "builder-init-a-enter", (args) => ({
  dst: ptr(args[0]).toString(),
  src: ptr(args[1]).toString(),
}));
attachBuilderStageHook(OFFSETS.builderInitB, "builder-init-b-enter", (args) => ({
  dst: ptr(args[0]).toString(),
  src: ptr(args[1]).toString(),
}));
attachBuilderStageHook(OFFSETS.builderConversationPrep, "builder-conversation-prep-enter", (args) => ({
  src: ptr(args[0]).toString(),
  out: ptr(args[1]).toString(),
}));
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrep), {
  onEnter(args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "builder-message-prep-enter",
      threadId: Process.getCurrentThreadId(),
      src: ptr(args[0]).toString(),
      talker: ptr(args[1]).toString(),
      msgId: Number(args[2]),
    });
  },
  onLeave(retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "builder-message-prep-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  },
});
attachBuilderStageHook(OFFSETS.builderMessagePrepAuxA, "builder-message-prep-aux-a-enter", (args, meta) => ({
  arg0: ptr(args[0]).toString(),
  caller: meta.returnAddress.toString(),
}));
attachBuilderStageHook(OFFSETS.builderMessagePrepAuxC, "builder-message-prep-aux-c-enter", (args, meta) => ({
  arg0: ptr(args[0]).toString(),
  arg1: ptr(args[1]).toString(),
  arg2: ptr(args[2]).toString(),
  caller: meta.returnAddress.toString(),
}));
attachBuilderStageHook(OFFSETS.builderMessagePrepLoopPrep, "builder-message-prep-loop-prep-enter", (args, meta) => ({
  arg0: ptr(args[0]).toString(),
  arg1: ptr(args[1]).toString(),
  caller: meta.returnAddress.toString(),
}));
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepLoopKey), {
  onEnter(args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "builder-message-prep-loop-key-enter",
      threadId: Process.getCurrentThreadId(),
      arg0: ptr(args[0]).toString(),
      caller: this.returnAddress.toString(),
    });
  },
  onLeave(retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "builder-message-prep-loop-key-leave",
      threadId: Process.getCurrentThreadId(),
      retval: Number(retval),
    });
  },
});
attachBuilderStageHook(
  OFFSETS.builderMessagePrepLoopSourcePick,
  "builder-message-prep-loop-source-pick-enter",
  (args, meta) => ({
    arg0: ptr(args[0]).toString(),
    caller: meta.returnAddress.toString(),
  })
);
[
  [OFFSETS.builderMessagePrepLoopKeyNewsappCheck, "builder-message-prep-loop-key-newsapp-check"],
  [OFFSETS.builderMessagePrepLoopKeyNotificationCheck, "builder-message-prep-loop-key-notification-check"],
  [OFFSETS.builderMessagePrepLoopKeyChatCheck, "builder-message-prep-loop-key-chat-check"],
  [OFFSETS.builderMessagePrepLoopKeyBrandCustomerCheck, "builder-message-prep-loop-key-brand-customer-check"],
  [OFFSETS.builderMessagePrepLoopKeyFallbackCheck, "builder-message-prep-loop-key-fallback-check"],
].forEach(([offset, kind]) => {
  Interceptor.attach(moduleBase.add(offset), {
    onEnter(args) {
      if (!shouldTraceDetachedHotPath()) {
        return;
      }
      rawSend({
        kind: `${kind}-enter`,
        threadId: Process.getCurrentThreadId(),
        arg0: ptr(args[0]).toString(),
        caller: this.returnAddress.toString(),
      });
    },
    onLeave(retval) {
      if (!shouldTraceDetachedHotPath()) {
        return;
      }
      rawSend({
        kind: `${kind}-leave`,
        threadId: Process.getCurrentThreadId(),
        retval: Number(retval),
      });
    },
  });
});
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepLoopSelect), {
  onEnter: guardHook("builder-message-prep-loop-select", "enter", function (args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    this.outPair = ptr(args[1]);
    rawSend({
      kind: "builder-message-prep-loop-select-enter",
      threadId: Process.getCurrentThreadId(),
      arg0: ptr(args[0]).toString(),
      outPair: ptr(args[1]).toString(),
      selector: Number(args[2]),
      value124: Number(args[3]),
      caller: this.returnAddress.toString(),
    });
  }),
  onLeave: guardHook("builder-message-prep-loop-select", "leave", function (retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "builder-message-prep-loop-select-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      outPair: safeReadRcPair(this.outPair),
    });
  }),
});
Interceptor.attach(moduleBase.add(OFFSETS.detachedPostSelectWalker), {
  onEnter: guardHook("detached-post-select-walker", "enter", function (args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    this.arg0 = ptr(args[0]);
    const priorFlag = safeReadU8(this.arg0.add(0x278));
    this.arg0.add(0x278).writeU8(1);
    rawSend({
      kind: "detached-post-select-walker-enter",
      threadId: Process.getCurrentThreadId(),
      arg0: this.arg0.toString(),
      priorFlag,
      root: hex(safeReadPointer(this.arg0.add(0x08))),
    });
  }),
  onLeave: guardHook("detached-post-select-walker", "leave", function (retval) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "detached-post-select-walker-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  }),
});
attachBuilderStageHook(OFFSETS.builderMessagePrepLoopItem, "builder-message-prep-loop-item-enter", (args, meta) => ({
  arg0: ptr(args[0]).toString(),
  arg1: ptr(args[1]).toString(),
  arg2: ptr(args[2]).toString(),
  arg3: Number(args[3]),
  caller: meta.returnAddress.toString(),
}));
attachBuilderStageHook(
  OFFSETS.builderMessagePrepLoopFinalize,
  "builder-message-prep-loop-finalize-enter",
  (args, meta) => ({
    arg0: ptr(args[0]).toString(),
    arg1: ptr(args[1]).toString(),
    caller: meta.returnAddress.toString(),
  })
);
attachBuilderStageHook(OFFSETS.builderTailFormat, "builder-tail-format-enter", (args, meta) => ({
  arg0: ptr(args[0]).toString(),
  arg1: ptr(args[1]).toString(),
  arg2: ptr(args[2]).toString(),
  caller: meta.returnAddress.toString(),
}));
attachBuilderStageHook(OFFSETS.builderTailA, "builder-tail-a-enter", (args, meta) => ({
  arg0: ptr(args[0]).toString(),
  arg1: ptr(args[1]).toString(),
  arg2: ptr(args[2]).toString(),
  caller: meta.returnAddress.toString(),
}));
attachBuilderStageHook(OFFSETS.builderTailB, "builder-tail-b-enter", (args, meta) => ({
  arg0: ptr(args[0]).toString(),
  arg1: ptr(args[1]).toString(),
  arg2: ptr(args[2]).toString(),
  caller: meta.returnAddress.toString(),
}));
attachBuilderStageHook(OFFSETS.builderTailC, "builder-tail-c-enter", (args, meta) => ({
  arg0: ptr(args[0]).toString(),
  arg1: ptr(args[1]).toString(),
  arg2: ptr(args[2]).toString(),
  caller: meta.returnAddress.toString(),
}));
attachBuilderStageHook(OFFSETS.builderTailD, "builder-tail-d-enter", (args, meta) => ({
  arg0: ptr(args[0]).toString(),
  arg1: ptr(args[1]).toString(),
  arg2: ptr(args[2]).toString(),
  caller: meta.returnAddress.toString(),
}));
attachBuilderStageHook(OFFSETS.builderWorkerFieldA, "builder-worker-field-a-enter", (args) => ({
  worker: ptr(args[0]).toString(),
  value: Number(args[1]),
}));
attachBuilderStageHook(OFFSETS.builderWorkerFieldB, "builder-worker-field-b-enter", (args) => ({
  worker: ptr(args[0]).toString(),
  value: Number(args[1]),
}));

Interceptor.attach(moduleBase.add(OFFSETS.helperTableInsert), {
  onEnter: guardHook("helper-table-insert", "enter", function (args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    const pair = safeReadRcPair(args[2]);
    rawSend({
      kind: "helper-table-insert",
      threadId: Process.getCurrentThreadId(),
      manager: ptr(args[1]).toString(),
      pair,
      key: readSmallString(args[3]),
      pairObject: pair.object === "0x0" || pair.error ? null : inspectHelperNodeObject(pair.object),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.helperWalk), {
  onEnter: guardHook("helper-walk", "enter", function (args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    rawSend({
      kind: "helper-walk-enter",
      threadId: Process.getCurrentThreadId(),
      owner: ptr(args[0]).toString(),
      key: readSmallString(args[1]),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.workerFinalize), {
  onEnter: guardHook("worker-finalize", "enter", function (args) {
    if (!shouldTraceFinalizeThread()) {
      return;
    }
    this.out = args[1];
    const sourcePair = safeReadRcPair(args[2]);
    rawSend({
      kind: "worker-finalize-enter",
      threadId: Process.getCurrentThreadId(),
      out: ptr(args[1]).toString(),
      sourcePair,
      sourceObject: sourcePair.object === "0x0" || sourcePair.error ? null : inspectFinalizeSourceObject(sourcePair.object),
    });
  }),
  onLeave: guardHook("worker-finalize", "leave", function (retval) {
    if (!shouldTraceFinalizeThread() || !this.out) {
      return;
    }
    let retvalText = null;
    try {
      retvalText = retval ? retval.toString() : null;
    } catch (error) {
      retvalText = `<retval-error ${String(error)}>`;
    }
    rawSend({
      kind: "worker-finalize-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retvalText,
      result: readFinalizeResult(this.out),
    });
  }),
});

function callDetached(
  templateRegion,
  conversationId,
  body,
  msgsource,
  entryName,
  initRequestFromSeedCtor,
  seedTailFromSeedTemplate,
  seedTailFromSwapTemplate,
  requestSelfUsername,
  requestNickname,
  requestAlias
) {
  globalThis.callStringAllocs = [];
  const entryOffset = entryName === "entryB" ? OFFSETS.entryB : OFFSETS.entryA;
  const nativeEntry = new NativeFunction(moduleBase.add(entryOffset), "void", ["pointer"], {
    // Weixin raises internal C++/UIA exceptions on this path that appear to be
    // handled in-process. Let them propagate instead of converting them into a
    // JS-side fatal "system error" for the detached attempt.
    exceptions: "propagate",
  });

  // The detached entry consumes the copied request region plus a tail object
  // starting at caller+0x390. That tail extends past the 0x3a0-byte request
  // payload, so a request-sized allocation is too small.
  const outer = Memory.alloc(CALLER_SIZE);
  outer.writeByteArray(new Uint8Array(CALLER_SIZE));
  let seedTemplate = null;
  if (initRequestFromSeedCtor || seedTailFromSeedTemplate) {
    seedTemplate = buildSeedRequestTemplate();
  }
  if (initRequestFromSeedCtor) {
    Memory.copy(outer.add(0x08), seedTemplate.templateRegion, REQUEST_REGION_SIZE);
    rawSend({
      kind: "detached-seed-template-prepared",
      threadId: Process.getCurrentThreadId(),
      pair: seedTemplate.snapshot,
      templateRegion: seedTemplate.templateRegion.toString(),
      regionState: inspectRequestRegion(seedTemplate.templateRegion),
    });
  } else {
    Memory.copy(outer.add(0x08), ptr(templateRegion), REQUEST_REGION_SIZE);
  }

  let tailTemplate = null;
  let tailTemplateSource = null;
  if (seedTailFromSwapTemplate) {
    tailTemplate = getPreparedSwapTailTemplate();
    tailTemplateSource = "swap-template";
  } else if (seedTailFromSeedTemplate) {
    // FUN_1815b1350 later clones the caller tail block from outer+0x390 via
    // FUN_180038880. The detached seed wrapper prefix is also exactly 0xe8
    // bytes long, so use it as an opt-in tail template instead of all-zero
    // detached state.
    tailTemplate = seedTemplate.tailTemplate;
    tailTemplateSource = "seed-template";
  }

  if (tailTemplate !== null) {
    outer.add(TAIL_REGION_OFFSET).writeByteArray(tailTemplate);
    rawSend({
      kind: "detached-tail-template-prepared",
      threadId: Process.getCurrentThreadId(),
      tailRegion: hex(outer.add(TAIL_REGION_OFFSET)),
      tailFields: inspectTailRegion(outer.add(TAIL_REGION_OFFSET)),
      source: tailTemplateSource,
      seedBase: seedTemplate ? seedTemplate.base.toString() : null,
    });
  }

  writeSmallString(outer.add(0x38), conversationId, false);
  writeSmallString(outer.add(0x78), conversationId, false);
  writeSmallString(outer.add(0xc0), body, false);
  writeSmallString(outer.add(0xe0), msgsource, false);
  applyKnownSelfContextToRequestRegion(outer.add(0x08), requestSelfUsername, requestNickname, requestAlias);

  rawSend({
    kind: "detached-request-region-pre-entry",
    threadId: Process.getCurrentThreadId(),
    region: hex(outer.add(0x08)),
    state: inspectRequestRegion(outer.add(0x08)),
  });

  rawSend({
    kind: "detached-native-entry-call",
    threadId: Process.getCurrentThreadId(),
    entry: entryName,
    entryAddress: moduleBase.add(entryOffset).toString(),
    outer: hex(outer),
  });

  try {
    nativeEntry(outer);
  } catch (error) {
    rawSend({
      kind: "detached-native-entry-error",
      threadId: Process.getCurrentThreadId(),
      entry: entryName,
      error: String(error),
    });
    throw error;
  }

  rawSend({
    kind: "detached-native-entry-return",
    threadId: Process.getCurrentThreadId(),
    entry: entryName,
    outer: hex(outer),
  });

  return {
    entry: entryName,
    outer: hex(outer),
    region: hex(outer.add(0x08)),
    state: inspectOuter(outer),
  };
}

function scheduleDetached(
  templateRegion,
  conversationId,
  body,
  msgsource,
  entryName,
  threadId,
  initRequestFromSeedCtor,
  seedTailFromSeedTemplate,
  seedTailFromSwapTemplate,
  requestSelfUsername,
  requestNickname,
  requestAlias
) {
  globalThis.detachedStatus = {
    status: "pending",
    requestedThreadId: threadId,
    entry: entryName,
  };

  Process.runOnThread(threadId, function () {
    globalThis.detachedStatus = {
      status: "running",
      requestedThreadId: threadId,
      actualThreadId: Process.getCurrentThreadId(),
      entry: entryName,
    };
    rawSend({
      kind: "detached-runonthread-enter",
      threadId: Process.getCurrentThreadId(),
      requestedThreadId: threadId,
      entry: entryName,
    });

    try {
      const result = callDetached(
        templateRegion,
        conversationId,
        body,
        msgsource,
        entryName,
        initRequestFromSeedCtor,
        seedTailFromSeedTemplate,
        seedTailFromSwapTemplate,
        requestSelfUsername,
        requestNickname,
        requestAlias
      );
      globalThis.detachedStatus = {
        status: "done",
        requestedThreadId: threadId,
        actualThreadId: Process.getCurrentThreadId(),
        entry: entryName,
        result,
      };
    } catch (e) {
      globalThis.detachedStatus = {
        status: "error",
        requestedThreadId: threadId,
        actualThreadId: Process.getCurrentThreadId(),
        entry: entryName,
        error: e.toString(),
      };
    }
  });

  return globalThis.detachedStatus;
}

rpc.exports = {
  armcapture(conversationId) {
    globalThis.captureState = {
      status: "armed",
      conversationId,
      capturedConversationId: null,
      capturedWrapper: null,
      capturedObject: null,
      capturedTemplateRegion: null,
      capturedThreadId: 0,
    };
    globalThis.capturedTemplateBlock = null;
    globalThis.capturedTailTemplateBlock = null;
    globalThis.autoDetachedConfig = null;
    return globalThis.captureState;
  },
  armcaptureandsend(
    conversationId,
    body,
    msgsource,
    entryName,
    threadId,
    initRequestFromSeedCtor,
    seedTailFromSeedTemplate,
    seedTailFromSwapTemplate,
    requestSelfUsername,
    requestNickname,
    requestAlias,
    deepTrace
  ) {
    globalThis.captureState = {
      status: "armed",
      conversationId,
      capturedConversationId: null,
      capturedWrapper: null,
      capturedObject: null,
      capturedTemplateRegion: null,
      capturedThreadId: 0,
    };
    globalThis.capturedTemplateBlock = null;
    globalThis.capturedTailTemplateBlock = null;
    globalThis.autoDetachedConfig = {
      started: false,
      conversationId,
      body,
      msgsource,
      entryName,
      threadId,
      initRequestFromSeedCtor,
      seedTailFromSeedTemplate,
      seedTailFromSwapTemplate,
      requestSelfUsername,
      requestNickname,
      requestAlias,
      deepTrace: !!deepTrace,
    };
    return {
      captureState: globalThis.captureState,
      autoDetachedConfig: globalThis.autoDetachedConfig,
    };
  },
  getcapturestate() {
    return globalThis.captureState;
  },
  setswap(threadId, conversationId) {
    globalThis.swapState = {
      enabled: true,
      mode: "captured",
      threadId,
      conversationId,
      deepTrace: false,
      selfUsername: null,
      liveWrapperAddress: null,
      preparedPairAddress: null,
      preparedWrapper: null,
      preparedObject: null,
      preparedTemplateRegion: null,
    };
    return globalThis.swapState;
  },
  setliveclone(threadId, conversationId, wrapperAddress) {
    const prepared = cloneTemplateFromLiveWrapper(wrapperAddress, conversationId);
    globalThis.liveCloneTemplateBlock = ptr(prepared.base).readByteArray(TEMPLATE_BLOCK_SIZE);
    globalThis.liveCloneTailTemplateBlock = ptr(wrapperAddress).readByteArray(TAIL_REGION_SIZE);
    globalThis.swapState = {
      enabled: true,
      mode: "liveclone",
      threadId,
      conversationId,
      deepTrace: false,
      selfUsername: null,
      liveWrapperAddress: wrapperAddress,
      preparedPairAddress: null,
      preparedWrapper: prepared.base.toString(),
      preparedObject: prepared.object.toString(),
      preparedTemplateRegion: prepared.object.add(0xd8).toString(),
    };
    rawSend({
      kind: "liveclone-prepared",
      threadId: Process.getCurrentThreadId(),
      sourceWrapper: ptr(wrapperAddress).toString(),
      preparedWrapper: prepared.base.toString(),
      preparedObject: prepared.object.toString(),
      preparedTemplateRegion: prepared.object.add(0xd8).toString(),
    });
    return globalThis.swapState;
  },
  setliveraw(threadId, conversationId, wrapperAddress) {
    globalThis.liveCloneTailTemplateBlock = ptr(wrapperAddress).readByteArray(TAIL_REGION_SIZE);
    globalThis.swapState = {
      enabled: true,
      mode: "liveraw",
      threadId,
      conversationId,
      deepTrace: false,
      selfUsername: null,
      liveWrapperAddress: wrapperAddress,
      preparedPairAddress: null,
      preparedWrapper: wrapperAddress,
      preparedObject: ptr(wrapperAddress).add(TEMPLATE_USER_OFFSET).toString(),
      preparedTemplateRegion: ptr(wrapperAddress).add(TEMPLATE_USER_OFFSET).add(0xd8).toString(),
    };
    return globalThis.swapState;
  },
  preparesynthetic(threadId, conversationId, selfUsername) {
    const prepared = buildSyntheticGoodPair(conversationId, selfUsername);
    globalThis.syntheticPrepared = prepared;
    globalThis.swapState = {
      enabled: true,
      mode: "synthetic",
      threadId,
      conversationId,
      deepTrace: false,
      selfUsername: selfUsername || null,
      liveWrapperAddress: null,
      preparedPairAddress: prepared.pairAddress.toString(),
      preparedWrapper: prepared.base.toString(),
      preparedObject: prepared.object.toString(),
      preparedTemplateRegion: prepared.templateRegion.toString(),
    };
    rawSend({
      kind: "synthetic-good-pair-prepared",
      threadId: Process.getCurrentThreadId(),
      pair: prepared.snapshot,
      templateRegion: prepared.templateRegion.toString(),
      talker: readTalkerFromSourceObject(prepared.object),
      sourceState: inspectSyntheticSourceObject(prepared.object),
      embeddedRequestState: inspectRequestRegion(prepared.templateRegion),
    });
    return globalThis.swapState;
  },
  clearswap() {
    globalThis.swapState = {
      enabled: false,
      mode: "captured",
      threadId: 0,
      conversationId: null,
      deepTrace: false,
      selfUsername: null,
      liveWrapperAddress: null,
      preparedPairAddress: null,
      preparedWrapper: null,
      preparedObject: null,
      preparedTemplateRegion: null,
    };
    globalThis.liveCloneTemplateBlock = null;
    globalThis.capturedTailTemplateBlock = null;
    globalThis.liveCloneTailTemplateBlock = null;
    globalThis.syntheticPrepared = null;
    return globalThis.swapState;
  },
  setdeeptrace(enabled) {
    globalThis.swapState.deepTrace = !!enabled;
    return globalThis.swapState;
  },
  send(
    templateRegion,
    conversationId,
    body,
    msgsource,
    entryName,
    threadId,
    initRequestFromSeedCtor,
    seedTailFromSeedTemplate,
    seedTailFromSwapTemplate,
    requestSelfUsername,
    requestNickname,
    requestAlias
  ) {
    if (threadId && threadId !== 0) {
      return scheduleDetached(
        templateRegion,
        conversationId,
        body,
        msgsource,
        entryName,
        threadId,
        initRequestFromSeedCtor,
        seedTailFromSeedTemplate,
        seedTailFromSwapTemplate,
        requestSelfUsername,
        requestNickname,
        requestAlias
      );
    }
    return callDetached(
      templateRegion,
      conversationId,
      body,
      msgsource,
      entryName,
      initRequestFromSeedCtor,
      seedTailFromSeedTemplate,
      seedTailFromSwapTemplate,
      requestSelfUsername,
      requestNickname,
      requestAlias
    );
  },
  getstatus() {
    return globalThis.detachedStatus || null;
  },
};
"""


def resolve_weixin_dll_host_pid() -> int:
    command = r"""
    Get-Process Weixin | ForEach-Object {
      $procId = $_.Id
      $_.Modules |
        Where-Object { $_.ModuleName -eq 'Weixin.dll' } |
        ForEach-Object { $procId }
    } | Select-Object -First 1
    """
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    text = completed.stdout.strip()
    if not text:
        raise SystemExit("Could not find a live Weixin process hosting Weixin.dll")
    return int(text)


def main() -> int:
  parser = argparse.ArgumentParser(description="Attempt a detached Weixin text send from a live request template.")
  parser.add_argument("--pid", type=int, help="Target Weixin PID. Defaults to live Weixin.dll host.")
  parser.add_argument("--template-region", required=True, help="Pointer to a live request region captured from 15b20b0.")
  parser.add_argument("--conversation-id", required=True, help="Target conversation id.")
  parser.add_argument("--body", required=True, help="Detached body text.")
  parser.add_argument(
      "--msgsource",
      default="<msgsource><alnode><fr>1</fr></alnode></msgsource>",
      help="Msgsource XML to embed.",
  )
  parser.add_argument(
      "--entry",
      choices=("entryA", "entryB"),
      default="entryA",
      help="Detached entrypoint: entryA=0x1815b3990, entryB=0x1815b1350.",
  )
  parser.add_argument("--thread-id", type=int, default=0, help="Optional live WeChat thread id to invoke on.")
  parser.add_argument(
      "--wait-for-good-template",
      help="Capture a live-good worker source pair for this conversation before the detached attempt.",
  )
  parser.add_argument(
      "--auto-detach-after-capture",
      action="store_true",
      help="Schedule the detached replay inside the Frida script immediately after capture.",
  )
  parser.add_argument(
      "--capture-timeout-ms",
      type=int,
      default=30000,
      help="How long to wait for a live-good template capture.",
  )
  parser.add_argument(
      "--run-timeout-ms",
      type=int,
      default=30000,
      help="How long to wait for detached runOnThread completion.",
  )
  parser.add_argument(
      "--deep-trace",
      action="store_true",
      help="Temporarily re-enable the hotter detached entryB trace hooks for debugging.",
  )
  parser.add_argument(
      "--swap-with-captured-template",
      action="store_true",
      help="Replace the detached worker's bad source pair with the captured live-good template.",
  )
  parser.add_argument(
      "--use-captured-template-region",
      action="store_true",
      help="Use the captured live-good source object's embedded request region as --template-region.",
  )
  parser.add_argument(
      "--swap-with-synthetic-good-source",
      action="store_true",
      help="Build a good-family source pair in-process with FUN_180633150 and swap it in at workerEntry.",
  )
  parser.add_argument(
      "--swap-with-live-wrapper",
      help="Clone a previously captured live-good wrapper block at this address and swap it in at workerEntry.",
  )
  parser.add_argument(
      "--swap-with-live-wrapper-raw",
      help="Swap the original live-good wrapper block at this address directly, without cloning it first.",
  )
  parser.add_argument(
      "--use-synthetic-template-region",
      action="store_true",
      help="Use the synthetic good-family source object's embedded request region as --template-region.",
  )
  parser.add_argument(
      "--synthetic-self-username",
      help="Optional self username to write into the synthetic good source at +0x660.",
  )
  parser.add_argument(
      "--request-self-username",
      help="Optional self username to seed into the detached request region at +0x10 and +0x50.",
  )
  parser.add_argument(
      "--request-nickname",
      help="Optional nickname to seed into the detached request region at +0x2a0.",
  )
  parser.add_argument(
      "--request-alias",
      help="Optional alias to seed into the detached request region at +0x300.",
  )
  parser.add_argument(
      "--init-request-from-seed-ctor",
      action="store_true",
      help="Initialize the detached caller request region from FUN_1815b1c80 instead of --template-region.",
  )
  parser.add_argument(
      "--seed-tail-from-seed-template",
      action="store_true",
      help=(
          "Seed caller+0x390 from the detached seed wrapper prefix instead of leaving "
          "the late async tail fully zeroed."
      ),
  )
  parser.add_argument(
      "--seed-tail-from-swap-template",
      action="store_true",
      help=(
          "Seed caller+0x390 from the active swap template wrapper prefix instead of "
          "using the detached seed wrapper tail."
      ),
  )
  args = parser.parse_args()

  pid = args.pid or resolve_weixin_dll_host_pid()
  device = frida.get_local_device()
  session = device.attach(pid)
  script = session.create_script(SCRIPT_SOURCE)

  def on_message(message, data):
      if message["type"] == "send":
          print(json.dumps(message["payload"], ensure_ascii=True), file=sys.stderr, flush=True)
      else:
          print(json.dumps(message, ensure_ascii=True), file=sys.stderr, flush=True)

  script.on("message", on_message)
  script.load()

  try:
      if args.wait_for_good_template:
          if args.auto_detach_after_capture:
              script.exports_sync.armcaptureandsend(
                  args.wait_for_good_template,
                  args.body,
                  args.msgsource,
                  args.entry,
                  args.thread_id or 0,
                  args.init_request_from_seed_ctor,
                  args.seed_tail_from_seed_template,
                  args.seed_tail_from_swap_template,
                  args.request_self_username,
                  args.request_nickname,
                  args.request_alias,
                  args.deep_trace,
              )
          else:
              script.exports_sync.armcapture(args.wait_for_good_template)
          deadline = time.time() + (args.capture_timeout_ms / 1000.0)
          capture_state = None
          while time.time() < deadline:
              capture_state = script.exports_sync.getcapturestate()
              if capture_state and capture_state.get("status") == "captured":
                  break
              time.sleep(0.05)
          else:
              raise SystemExit(
                  json.dumps(
                      {
                          "ok": False,
                          "error": "timed out waiting for live-good template capture",
                          "capture_state": script.exports_sync.getcapturestate(),
                      },
                      ensure_ascii=True,
                  )
              )

      if args.auto_detach_after_capture:
          deadline = time.time() + (args.run_timeout_ms / 1000.0)
          result = None
          while time.time() < deadline:
              try:
                  result = script.exports_sync.getstatus()
              except frida.InvalidOperationError as exc:
                  raise SystemExit(
                      json.dumps(
                          {
                              "ok": False,
                              "error": "frida script destroyed while waiting for auto-detached completion",
                              "detail": str(exc),
                          },
                          ensure_ascii=True,
                      )
                  )
              if result and result.get("status") in {"done", "error"}:
                  break
              time.sleep(0.05)
          else:
              raise SystemExit(
                  json.dumps(
                      {
                          "ok": False,
                          "error": "timed out waiting for auto-detached completion",
                          "capture_state": capture_state,
                          "status": result,
                      },
                      ensure_ascii=True,
                  )
              )

          if result.get("status") == "error":
              raise SystemExit(json.dumps({"ok": False, "error": result["error"], "status": result}, ensure_ascii=True))

          print(json.dumps({"ok": True, "result": result, "capture_state": capture_state}, ensure_ascii=True))
          return 0

      if args.use_captured_template_region:
          args.template_region = capture_state["capturedTemplateRegion"]
      if args.swap_with_captured_template and not args.thread_id:
          captured_thread_id = int(capture_state.get("capturedThreadId") or 0)
          if not captured_thread_id:
              raise SystemExit(
                  json.dumps(
                      {
                          "ok": False,
                          "error": "captured template missing capturedThreadId",
                          "capture_state": capture_state,
                      },
                      ensure_ascii=True,
                  )
              )
          args.thread_id = captured_thread_id

      if (
          args.swap_with_captured_template
          or args.swap_with_synthetic_good_source
          or args.swap_with_live_wrapper
          or args.swap_with_live_wrapper_raw
      ):
          if not args.thread_id:
              raise SystemExit("source-pair swapping requires --thread-id")
      if args.swap_with_synthetic_good_source or args.use_synthetic_template_region:
          synthetic_state = script.exports_sync.preparesynthetic(
              args.thread_id,
              args.conversation_id,
              args.synthetic_self_username,
          )
          if args.use_synthetic_template_region:
              args.template_region = synthetic_state["preparedTemplateRegion"]
      elif args.swap_with_live_wrapper:
          script.exports_sync.setliveclone(
              args.thread_id,
              args.conversation_id,
              args.swap_with_live_wrapper,
          )
      elif args.swap_with_live_wrapper_raw:
          script.exports_sync.setliveraw(
              args.thread_id,
              args.conversation_id,
              args.swap_with_live_wrapper_raw,
          )
      elif args.swap_with_captured_template:
          script.exports_sync.setswap(args.thread_id, args.conversation_id)
      if args.deep_trace:
          script.exports_sync.setdeeptrace(True)

      result = script.exports_sync.send(
          args.template_region,
          args.conversation_id,
          args.body,
          args.msgsource,
          args.entry,
          args.thread_id,
          args.init_request_from_seed_ctor,
          args.seed_tail_from_seed_template,
          args.seed_tail_from_swap_template,
          args.request_self_username,
          args.request_nickname,
          args.request_alias,
      )
      if args.thread_id:
          deadline = time.time() + (args.run_timeout_ms / 1000.0)
          while time.time() < deadline:
              try:
                  status = script.exports_sync.getstatus()
              except frida.InvalidOperationError as exc:
                  raise SystemExit(
                      json.dumps(
                          {
                              "ok": False,
                              "error": "frida script destroyed while waiting for runOnThread completion",
                              "detail": str(exc),
                          },
                          ensure_ascii=True,
                      )
                  )
              if status and status.get("status") in {"done", "error"}:
                  result = status
                  break
              time.sleep(0.05)
          else:
              try:
                  result = script.exports_sync.getstatus()
              except frida.InvalidOperationError as exc:
                  raise SystemExit(
                      json.dumps(
                          {
                              "ok": False,
                              "error": "frida script destroyed while reading final runOnThread status",
                              "detail": str(exc),
                          },
                          ensure_ascii=True,
                      )
                  )
              raise SystemExit(
                  json.dumps(
                      {
                          "ok": False,
                          "error": "timed out waiting for runOnThread completion",
                          "status": result,
                      },
                      ensure_ascii=True,
                  )
              )

          if result.get("status") == "error":
              raise SystemExit(json.dumps({"ok": False, "error": result["error"], "status": result}, ensure_ascii=True))

      print(json.dumps({"ok": True, "result": result}, ensure_ascii=True))
      return 0
  finally:
      session.detach()


if __name__ == "__main__":
  raise SystemExit(main())
