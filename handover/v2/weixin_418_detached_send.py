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
  builderMessagePrepLoopFinalizeAwaitCheck: 0x316b50,
  builderMessagePrepLoopFinalizeAwaitResultSlot: 0x319290,
  builderMessagePrepLoopFinalizeTypeCompare: 0x64df380,
  builderMessagePrepLoopFinalizePairCtor: 0x034c40,
  builderMessagePrepLoopFinalizeItemBind: 0x2ab2fc0,
  builderMessagePrepPostFinalizeResolve: 0x33bafa0,
  postFinalizeResolveHelper: 0x33bb090,
  builderMessagePrepPostFinalizeReturnSite: 0x332f068,
  builderMessagePrepOuterWrapperInnerReturnSite: 0x1618078,
  builderMessagePrepOuterWrapperAwaitReturnSite: 0x1618087,
  builderMessagePrepOuterWrapperReturnSite: 0x1618283,
  builderMessagePrepUpstreamWrapperReturnSite: 0x2835f48,
  builderMessagePrepUpstreamWrapperReturnLoad: 0x28361bc,
  builderMessagePrepHigherWrapperAEntry: 0x2836500,
  builderMessagePrepHigherWrapperAReturnSite: 0x2836547,
  builderMessagePrepHigherWrapperAFastForward: 0x2836a8b,
  builderMessagePrepHigherWrapperARet: 0x2836a99,
  builderMessagePrepHigherWrapperBEntry: 0x2a11b90,
  builderMessagePrepHigherWrapperBReturnSite: 0x2a1208e,
  builderTailFormat: 0x2835d60,
  builderTailA: 0x17e5560,
  builderTailB: 0x288c030,
  builderTailC: 0x17e63a0,
  builderTailD: 0x1685370,
  cloneTail: 0x038880,
  asyncWorkerRun: 0x15afcd0,
  entryBAsyncWorkerRun: 0x15b3350,
  queueSubmit: 0x314950,
  queueEnvelopeRun: 0x314de0,
  queueEnvelopeInvoke: 0x314e40,
  tailErrorHelper: 0x1cf420,
  tailConsume: 0x038f70,
  builderWorkerFieldA: 0x9b14d0,
  builderWorkerFieldB: 0x9b1990,
  resolveTypeNameHelper: 0x64afaac,
  helperParseHitCast: 0x034290,
  helperTableInsert: 0x15eb320,
  helperWalk: 0x15ebec0,
  workerFinalize: 0x15eb0d0,
  crashStub: 0x0f16b0,
  watsonFailFast: 0x64c96c8,
  roamServerCrashSite: 0x364339,
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
const TEMPLATE_REQUEST_REGION_OFFSET = 0xd8;
const TEMPLATE_SOURCE_STRING_OFFSETS = [0xb0, 0x660];
const TEMPLATE_REQUEST_STRING_OFFSETS = [
  0x10,
  0x30,
  0x50,
  0x70,
  0xb8,
  0xd8,
  0x118,
  0x138,
  0x160,
  0x180,
  0x1a0,
  0x1c0,
  0x1e0,
  0x200,
  0x230,
  0x250,
  0x2a0,
  0x300,
];
const moduleBase = Process.getModuleByName("Weixin.dll").base;
const GOOD_SOURCE_VTABLE = moduleBase.add(OFFSETS.goodSourceVtable);
const BAD_SOURCE_VTABLE = moduleBase.add(OFFSETS.badSourceVtable);
function resolveExport(moduleName, exportName) {
  const mod = Process.getModuleByName(moduleName);
  const match = mod.enumerateExports().find((entry) => entry.name === exportName);
  if (!match) {
    throw new Error(`missing export ${moduleName}!${exportName}`);
  }
  return match.address;
}
const getProcessHeapNative = new NativeFunction(
  resolveExport("kernel32.dll", "GetProcessHeap"),
  "pointer",
  [],
  { exceptions: "steal" }
);
const heapAllocNative = new NativeFunction(
  resolveExport("ntdll.dll", "RtlAllocateHeap"),
  "pointer",
  ["pointer", "uint32", "size_t"],
  { exceptions: "steal" }
);
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
const threadPairFetchNative = new NativeFunction(
  moduleBase.add(OFFSETS.threadPairFetch),
  "pointer",
  ["pointer"],
  { exceptions: "steal" }
);
const pairCopyMaybeNative = new NativeFunction(
  moduleBase.add(OFFSETS.pairCopyMaybe),
  "void",
  ["pointer", "pointer"],
  { exceptions: "steal" }
);
const normalizeSourcePairNative = new NativeFunction(
  moduleBase.add(OFFSETS.entryBPairNormalize),
  "pointer",
  ["pointer", "pointer"],
  { exceptions: "steal" }
);
globalThis.callStringAllocs = [];
globalThis.persistentStringAllocs = [];
globalThis.exceptionReportState = {
  recent: Object.create(null),
};
globalThis.detachedTraceState = {
  workers: Object.create(null),
  tails: Object.create(null),
};
globalThis.tailErrorSentinel = null;
globalThis.lastDetachedRequest = null;
globalThis.contextWatchState = {
  enabled: false,
  conversationId: null,
  maxHits: 0,
  hits: [],
  reentrant: false,
  pendingByThread: Object.create(null),
};
const HEAP_ZERO_MEMORY = 0x00000008;

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

function safeReadUtf16(address, length) {
  try {
    if (length !== undefined && length !== null) {
      return ptr(address).readUtf16String(Number(length));
    }
    return ptr(address).readUtf16String();
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

function formatHookArg(args, index) {
  const value = args[index];
  if (value === undefined || value === null) {
    return "0x0";
  }
  try {
    return ptr(value).toString();
  } catch (_) {
    return "<invalid>";
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

function inspectDispatchStatus(address) {
  const base = ptr(address);
  return {
    address: base.toString(),
    codeA: safeReadU32(base),
    codeB: safeReadU32(base.add(0x04)),
    text: readSmallString(base.add(0x08)),
    headHex: readHex(base, 0x40),
  };
}

function inspectAsyncStatus(address) {
  const base = ptr(address);
  return {
    address: base.toString(),
    statusByte: safeReadU8(base),
    text: readSmallString(base.add(0x08)),
    vectorFields: inspectPointerFields(base, [0x28, 0x30, 0x38, 0x40]),
    dword44: safeReadU32(base.add(0x44)),
    headHex: readHex(base, 0x50),
  };
}

function inspectSyntheticSourceObject(address) {
  const base = ptr(address);
  return {
    address: base.toString(),
    vtable: base.readPointer().toString(),
    dword9c: base.add(0x9c).readU32(),
    dwordD8: base.add(0xd8).readU32(),
    talker: readSmallString(base.add(0xb0)),
    field48: readSmallString(base.add(0x48)),
    field88: readSmallString(base.add(0x88)),
    field190: readSmallString(base.add(0x190)),
    field600: readSmallString(base.add(0x600)),
    selfField: readSmallString(base.add(0x660)),
    rc240: readRcPair(base.add(0x240)),
    rc278: readRcPair(base.add(0x278)),
    rc288: readRcPair(base.add(0x288)),
    rc298: readRcPair(base.add(0x298)),
    headHex: readHex(base, 0x120),
    field600Hex: readHex(base.add(0x5f0), 0x90),
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

function inspectRuntimeTypeInfo(address) {
  const object = ptr(address);
  try {
    if (object.isNull()) {
      return {
        address: object.toString(),
        vtable: "0x0",
        module: null,
        col: null,
        typeDescriptor: null,
        typeName: null,
        signature: null,
      };
    }
    const vtable = safeReadPointer(object);
    const module = vtable ? Process.findModuleByAddress(vtable) : null;
    const info = {
      address: object.toString(),
      vtable: vtable ? vtable.toString() : "0x0",
      module: module ? module.name : null,
      col: null,
      typeDescriptor: null,
      typeName: null,
      signature: null,
    };
    if (!vtable || vtable.isNull()) {
      return info;
    }
    const col = safeReadPointer(vtable.sub(Process.pointerSize));
    if (!col || col.isNull()) {
      return info;
    }
    info.col = col.toString();
    info.signature = safeReadU32(col);
    const typeDescriptorRva = safeReadU32(col.add(0x0c));
    const selfRva = safeReadU32(col.add(0x14));
    info.typeDescriptorRva = typeDescriptorRva;
    info.selfRva = selfRva;
    if (typeDescriptorRva === null || typeDescriptorRva === 0) {
      return info;
    }
    let imageBase = module ? module.base : null;
    if (selfRva !== null && selfRva !== 0) {
      imageBase = col.sub(selfRva);
    }
    if (!imageBase) {
      return info;
    }
    info.imageBase = imageBase.toString();
    const typeDescriptor = imageBase.add(typeDescriptorRva);
    info.typeDescriptor = typeDescriptor.toString();
    info.typeName = safeReadCString(typeDescriptor.add(0x10));
    return info;
  } catch (error) {
    return {
      address: object.toString(),
      error: String(error),
    };
  }
}

function inspectFinalizePromiseResultSlot(address) {
  const object = ptr(address);
  try {
    const slot = object.add(0xb8);
    const resultObject = safeReadPointer(slot);
    const aux = safeReadPointer(slot.add(Process.pointerSize));
    return {
      slot: slot.toString(),
      object: resultObject ? resultObject.toString() : "0x0",
      aux: aux ? aux.toString() : "0x0",
      slotHex: readHex(slot, 0x20),
      objectType:
        resultObject && !resultObject.isNull() ? inspectRuntimeTypeInfo(resultObject) : null,
    };
  } catch (error) {
    return {
      address: object.toString(),
      error: String(error),
    };
  }
}

function inspectFinalizePromiseObject(address) {
  const object = ptr(address);
  return {
    address: object.toString(),
    runtimeType: inspectRuntimeTypeInfo(object),
    stateBytes: {
      b5c: safeReadU8(object.add(0x5c)),
      b5d: safeReadU8(object.add(0x5d)),
      b5e: safeReadU8(object.add(0x5e)),
      b5f: safeReadU8(object.add(0x5f)),
      bC4: safeReadU8(object.add(0xc4)),
      bC5: safeReadU8(object.add(0xc5)),
      bC6: safeReadU8(object.add(0xc6)),
      bC7: safeReadU8(object.add(0xc7)),
    },
    stateDwords: inspectDwordFields(object, [0x58, 0x5c, 0x60, 0xc0, 0xc4, 0xc8]),
    statePointers: inspectPointerFields(object, [0x58, 0x60, 0x68, 0xb8, 0xc0, 0xc8]),
    resultSlot: inspectFinalizePromiseResultSlot(object),
    headHex: readHex(object, 0xe0),
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

function inspectLiveContextObject(address) {
  const base = ptr(address);
  let selfField = null;
  try {
    selfField = readSmallString(base.add(0x660));
  } catch (_) {
    selfField = null;
  }
  return {
    address: base.toString(),
    vtable: hex(safeReadPointer(base)),
    talker: readTalkerFromSourceObject(base),
    selfField,
    requestRegion: safeInspectRequestRegion(base.add(0xd8)),
    pairAt28: safeReadRcPair(base.add(0x28)),
    pairAt240: safeReadRcPair(base.add(0x240)),
    pairAt278: safeReadRcPair(base.add(0x278)),
    pairAt288: safeReadRcPair(base.add(0x288)),
    pairAt298: safeReadRcPair(base.add(0x298)),
  };
}

function probeThreadContextCurrent(conversationId) {
  const fetchedOut = Memory.alloc(Process.pointerSize * 2);
  fetchedOut.writeByteArray(new Uint8Array(Process.pointerSize * 2));
  threadPairFetchNative(fetchedOut);

  const result = {
    threadId: Process.getCurrentThreadId(),
    conversationId: conversationId || null,
    fetchedPair: readRcPair(fetchedOut),
    fetchedObject: null,
    copiedPair: null,
    copiedObject: null,
    normalizedPair: null,
    normalizedObject: null,
    refCandidate: null,
  };

  const fetchedObject = ptr(result.fetchedPair.object);
  if (!fetchedObject.isNull()) {
    result.fetchedObject = inspectLiveContextObject(fetchedObject);

    const copiedOut = Memory.alloc(Process.pointerSize * 2);
    copiedOut.writeByteArray(new Uint8Array(Process.pointerSize * 2));
    pairCopyMaybeNative(fetchedObject, copiedOut);
    result.copiedPair = readRcPair(copiedOut);

    const copiedObject = ptr(result.copiedPair.object);
    if (!copiedObject.isNull()) {
      result.copiedObject = inspectLiveContextObject(copiedObject);

      const normalizedOut = Memory.alloc(Process.pointerSize * 2);
      normalizedOut.writeByteArray(new Uint8Array(Process.pointerSize * 2));
      normalizeSourcePairNative(copiedObject, normalizedOut);
      result.normalizedPair = readRcPair(normalizedOut);

      const normalizedObject = ptr(result.normalizedPair.object);
      if (!normalizedObject.isNull()) {
        result.normalizedObject = inspectLiveContextObject(normalizedObject);
      }
    }
  }

  const fetchedRef = ptr(result.fetchedPair.ref);
  if (!fetchedRef.isNull()) {
    const refCandidate = {
      wrapper: fetchedRef.toString(),
      copiedPair: null,
      copiedObject: null,
      normalizedPair: null,
      normalizedObject: null,
    };
    try {
      const copiedOut = Memory.alloc(Process.pointerSize * 2);
      copiedOut.writeByteArray(new Uint8Array(Process.pointerSize * 2));
      pairCopyMaybeNative(fetchedRef, copiedOut);
      refCandidate.copiedPair = readRcPair(copiedOut);

      const copiedObject = ptr(refCandidate.copiedPair.object);
      if (!copiedObject.isNull()) {
        refCandidate.copiedObject = inspectLiveContextObject(copiedObject);

        const normalizedOut = Memory.alloc(Process.pointerSize * 2);
        normalizedOut.writeByteArray(new Uint8Array(Process.pointerSize * 2));
        normalizeSourcePairNative(copiedObject, normalizedOut);
        refCandidate.normalizedPair = readRcPair(normalizedOut);

        const normalizedObject = ptr(refCandidate.normalizedPair.object);
        if (!normalizedObject.isNull()) {
          refCandidate.normalizedObject = inspectLiveContextObject(normalizedObject);
        }
      }
    } catch (error) {
      refCandidate.error = String(error);
    }
    result.refCandidate = refCandidate;
  }

  const normalizedTalker =
    result.normalizedObject &&
    result.normalizedObject.talker &&
    typeof result.normalizedObject.talker.text === "string"
      ? result.normalizedObject.talker.text
      : null;
  const copiedTalker =
    result.copiedObject &&
    result.copiedObject.talker &&
    typeof result.copiedObject.talker.text === "string"
      ? result.copiedObject.talker.text
      : null;

  result.matchesConversation = {
    copiedTalkerMatches: !!(conversationId && copiedTalker === conversationId),
    normalizedTalkerMatches: !!(conversationId && normalizedTalker === conversationId),
    refCopiedTalkerMatches: !!(
      conversationId &&
      result.refCandidate &&
      result.refCandidate.copiedObject &&
      result.refCandidate.copiedObject.talker &&
      result.refCandidate.copiedObject.talker.text === conversationId
    ),
    refNormalizedTalkerMatches: !!(
      conversationId &&
      result.refCandidate &&
      result.refCandidate.normalizedObject &&
      result.refCandidate.normalizedObject.talker &&
      result.refCandidate.normalizedObject.talker.text === conversationId
    ),
  };
  return result;
}

function probeThreadContext(threadId, conversationId) {
  let probeResult = null;
  Process.runOnThread(threadId, function () {
    probeResult = probeThreadContextCurrent(conversationId);
  });
  for (let i = 0; i < 100 && probeResult === null; i += 1) {
    Thread.sleep(0.01);
  }
  if (probeResult === null) {
    throw new Error("thread probe produced no result");
  }
  return probeResult;
}

function maybeStoreContextWatchEntry(entry) {
  if (!globalThis.contextWatchState.enabled) {
    return;
  }
  const filterConversation = globalThis.contextWatchState.conversationId;
  const copiedTalker =
    entry.copiedTalker && typeof entry.copiedTalker.text === "string" ? entry.copiedTalker.text : null;
  const normalizedTalker =
    entry.normalizedTalker && typeof entry.normalizedTalker.text === "string"
      ? entry.normalizedTalker.text
      : null;
  const matches =
    !filterConversation ||
    copiedTalker === filterConversation ||
    normalizedTalker === filterConversation;
  if (!matches) {
    return;
  }
  globalThis.contextWatchState.hits.push(entry);
  rawSend({
    kind: "context-watch-hit",
    threadId: Process.getCurrentThreadId(),
    entry,
  });
  if (
    globalThis.contextWatchState.maxHits > 0 &&
    globalThis.contextWatchState.hits.length >= globalThis.contextWatchState.maxHits
  ) {
    globalThis.contextWatchState.enabled = false;
  }
}

function shouldTraceDetachedThread() {
  return globalThis.swapState.enabled && Process.getCurrentThreadId() === globalThis.swapState.threadId;
}

function rememberDetachedWorker(worker, origin) {
  const workerPtr = ptr(worker);
  if (workerPtr.isNull()) {
    return;
  }
  const workerKey = workerPtr.toString();
  const tailKey = workerPtr.add(0x28).toString();
  globalThis.detachedTraceState.workers[workerKey] = {
    origin,
    threadId: Process.getCurrentThreadId(),
  };
  globalThis.detachedTraceState.tails[tailKey] = {
    worker: workerKey,
    origin,
    threadId: Process.getCurrentThreadId(),
  };
}

function shouldTraceDetachedWorker(worker) {
  const workerPtr = ptr(worker);
  if (workerPtr.isNull()) {
    return shouldTraceDetachedThread();
  }
  return (
    shouldTraceDetachedThread() ||
    !!globalThis.detachedTraceState.workers[workerPtr.toString()]
  );
}

function shouldTraceDetachedTail(tail) {
  const tailPtr = ptr(tail);
  if (tailPtr.isNull()) {
    return shouldTraceDetachedThread();
  }
  return shouldTraceDetachedThread() || !!globalThis.detachedTraceState.tails[tailPtr.toString()];
}

function shouldTraceDetachedHotPath() {
  return shouldTraceDetachedThread() && !!(globalThis.swapState && globalThis.swapState.deepTrace);
}

function shouldTraceDetachedFocusedPath() {
  return (
    shouldTraceDetachedThread() &&
    !!(
      globalThis.swapState &&
      (globalThis.swapState.deepTrace || globalThis.swapState.focusedTrace)
    )
  );
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

function allocProcessUtf8String(text) {
  const heap = getProcessHeapNative();
  const size = text.length + 1;
  const bytes = heapAllocNative(heap, HEAP_ZERO_MEMORY, size);
  if (bytes.isNull()) {
    throw new Error("HeapAlloc failed for size " + size);
  }
  bytes.writeUtf8String(text);
  return bytes;
}

function writeSmallString(address, text, persistent) {
  const base = ptr(address);
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
  const bytes = allocProcessUtf8String(text);
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

function relocateSmallString(address, persistent) {
  const snapshot = readSmallString(address);
  if (!snapshot || snapshot.heap !== true || typeof snapshot.text !== "string") {
    return;
  }
  writeSmallString(address, snapshot.text, persistent);
}

function relocateKnownTemplateStrings(cloneBase) {
  const wrapper = ptr(cloneBase);
  const object = wrapper.add(TEMPLATE_USER_OFFSET);
  TEMPLATE_SOURCE_STRING_OFFSETS.forEach((offset) => {
    relocateSmallString(object.add(offset), true);
  });

  const requestRegion = object.add(TEMPLATE_REQUEST_REGION_OFFSET);
  TEMPLATE_REQUEST_STRING_OFFSETS.forEach((offset) => {
    relocateSmallString(requestRegion.add(offset), true);
  });
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
globalThis.capturedPrepared = null;
globalThis.liveCloneTemplateBlock = null;
globalThis.liveCloneTailTemplateBlock = null;
globalThis.syntheticPrepared = null;
globalThis.syntheticEmbedSeedMode = "seed-template";
globalThis.tailCloneTraceCount = 0;
globalThis.helperNodeState = {
  byThread: Object.create(null),
};
globalThis.builderTailEntryState = {
  byThread: Object.create(null),
};
globalThis.builderAuxAEntryState = {
  byThread: Object.create(null),
};
globalThis.outerWrapperEntryState = {
  byThread: Object.create(null),
};
globalThis.higherWrapperEntryState = {
  byThread: Object.create(null),
};
globalThis.builderReturnSlotRepairState = {
  enabled: false,
};
globalThis.finalizeOverride = {
  slot: "keep",
};
globalThis.latePairCopySwapState = {
  enabled: true,
};
globalThis.latePairCopyPatchState = {
  enabled: false,
};
globalThis.latePairCopyRequestFieldPatchState = {
  enabled: false,
};
globalThis.crashStubBypassState = {
  enabled: false,
};
globalThis.watsonFailFastBypassState = {
  enabled: false,
};
globalThis.roamServerCrashProbeState = {
  enabled: false,
  installed: false,
  loadHookInstalled: false,
  pollTimer: null,
  target: null,
  moduleBase: null,
};
globalThis.roamServerCrashBypassState = {
  enabled: false,
  patched: false,
  target: null,
  moduleBase: null,
  originalBytes: null,
};
globalThis.loopFinalizeOverride = {
  sourcePair: "keep",
};
globalThis.loopFinalizeBindRestore = {
  sourcePair: "keep",
};
globalThis.loopFinalizeState = {
  byThread: Object.create(null),
};
globalThis.loopFinalizeCastBypassState = {
  enabled: false,
  installed: false,
  target: null,
  compareTarget: null,
  compareReturnSite: null,
};
globalThis.loopFinalizeAwaitBypassState = {
  enabled: false,
  installed: false,
  awaitCheckTarget: null,
  awaitResultSlotTarget: null,
  nativeCheckBudget: 3,
  nativeCheckCountByThread: Object.create(null),
  passThroughResultSlotByThread: Object.create(null),
};
globalThis.outerWrapperAwaitBypassState = {
  enabled: false,
};
globalThis.upstreamWrapperReturnBypassState = {
  enabled: false,
};
globalThis.postFinalizeResolveBypassState = {
  enabled: false,
  installed: false,
  target: null,
};
globalThis.processExitProbeState = {
  enabled: false,
  installed: false,
  targets: [],
};

function getHelperSlotOffset(slotName) {
  if (slotName === "slot0") {
    return 0x78;
  }
  if (slotName === "slot1") {
    return 0x88;
  }
  if (slotName === "slot2") {
    return 0x98;
  }
  return null;
}

function rememberHelperNodeObject(threadId, objectAddress, keySnapshot) {
  if (!threadId || !objectAddress) {
    return;
  }
  globalThis.helperNodeState.byThread[String(threadId)] = {
    object: ptr(objectAddress).toString(),
    key: keySnapshot || null,
  };
}

function getHelperNodeForThread(threadId) {
  return globalThis.helperNodeState.byThread[String(threadId)] || null;
}

function maybeRepairBuilderReturnSlot(frame, threadId, stage) {
  if (!globalThis.builderReturnSlotRepairState.enabled) {
    return null;
  }
  if (!frame || ptr(frame).isNull()) {
    return null;
  }
  const entryState = globalThis.builderAuxAEntryState.byThread[String(threadId)] || null;
  if (!entryState || !entryState.stackReturnAddress || entryState.stackReturnAddress === "0x0") {
    return null;
  }
  const slotAddress = ptr(frame).add(0x2a8);
  const before = safeReadPointer(slotAddress);
  const expected = ptr(entryState.stackReturnAddress);
  if (!before || before.equals(expected)) {
    return {
      stage,
      slotAddress: slotAddress.toString(),
      before: before ? before.toString() : "0x0",
      expected: expected.toString(),
      repaired: false,
    };
  }
  slotAddress.writePointer(expected);
  const after = safeReadPointer(slotAddress);
  return {
    stage,
    slotAddress: slotAddress.toString(),
    before: before.toString(),
    expected: expected.toString(),
    after: after ? after.toString() : "0x0",
    repaired: !!(after && after.equals(expected)),
  };
}

function readHelperNodeSlotPair(helperObject, slotName) {
  const offset = getHelperSlotOffset(slotName);
  if (offset === null) {
    return null;
  }
  return safeReadRcPair(ptr(helperObject).add(offset));
}

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
  relocateKnownTemplateStrings(cloneBase);
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

function readTailTemplateFromWrapper(wrapperBase) {
  return ptr(wrapperBase).add(TAIL_REGION_OFFSET).readByteArray(TAIL_REGION_SIZE);
}

function getPreparedSwapTailTemplate() {
  if (!globalThis.swapState || !globalThis.swapState.enabled) {
    return null;
  }
  if (globalThis.swapState.mode === "captured") {
    if (globalThis.capturedPrepared) {
      return readTailTemplateFromWrapper(globalThis.capturedPrepared.base);
    }
    return globalThis.capturedTailTemplateBlock;
  }
  if (globalThis.swapState.mode === "liveclone" || globalThis.swapState.mode === "liveraw") {
    return globalThis.liveCloneTailTemplateBlock;
  }
  if (globalThis.swapState.mode === "synthetic" && globalThis.syntheticPrepared) {
    return readTailTemplateFromWrapper(globalThis.syntheticPrepared.base);
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
  if (conversationId) {
    writeSmallString(base.add(0xb0), conversationId, true);
  }
  base.add(0x9c).writeU32(1);
}

function patchSourceBodyField(objectAddress, bodyText) {
  if (!objectAddress || !bodyText) {
    return null;
  }
  const base = ptr(objectAddress);
  const before = readSmallString(base.add(0x660));
  writeSmallString(base.add(0x660), bodyText, true);
  return {
    before,
    after: readSmallString(base.add(0x660)),
  };
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
    tailTemplate: readTailTemplateFromWrapper(snapshot.ref),
  };
}

function prepareSyntheticEmbeddedRequestRegion(
  prepared,
  conversationId,
  body,
  msgsource,
  requestSelfUsername,
  requestNickname,
  requestAlias
) {
  if (!prepared) {
    return null;
  }

  const region = ptr(prepared.templateRegion);
  let seedPair = null;
  if (globalThis.syntheticEmbedSeedMode === "seed-template") {
    const seedTemplate = buildSeedRequestTemplate();
    seedPair = seedTemplate.snapshot;
    Memory.copy(region, seedTemplate.templateRegion, REQUEST_REGION_SIZE);
    writeSmallString(region.add(0x30), conversationId, false);
    writeSmallString(region.add(0x70), conversationId, false);
    writeSmallString(region.add(0xb8), body, false);
    writeSmallString(region.add(0xd8), msgsource, false);
    applyKnownSelfContextToRequestRegion(region, requestSelfUsername, requestNickname, requestAlias);
  } else if (globalThis.syntheticEmbedSeedMode === "patch-only") {
    // The good-source object's embedded region is close to the detached request
    // layout, but not identical. Preserve the constructor-built header and only
    // patch the fields we understand instead of memcpy'ing the detached seed blob.
    region.writeU32(1);
    writeSmallString(region.add(0x30), conversationId, false);
    writeSmallString(region.add(0x70), conversationId, false);
    writeSmallString(region.add(0xb8), body, false);
    writeSmallString(region.add(0xd8), msgsource, false);
    applyKnownSelfContextToRequestRegion(region, requestSelfUsername, requestNickname, requestAlias);
  }

  return {
    region: region.toString(),
    seedMode: globalThis.syntheticEmbedSeedMode,
    seedPair,
    state: inspectRequestRegion(region),
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

function applyDetachedRequestSkeleton(regionAddress, request) {
  const base = ptr(regionAddress);
  const conversationId = request && request.conversationId ? request.conversationId : "";
  const body = request && request.body ? request.body : "";
  const msgsource = request && request.msgsource ? request.msgsource : "";

  writeSmallString(base.add(0x10), request && request.requestSelfUsername ? request.requestSelfUsername : "", false);
  writeSmallString(base.add(0x30), conversationId, false);
  writeSmallString(base.add(0x50), request && request.requestSelfUsername ? request.requestSelfUsername : "", false);
  writeSmallString(base.add(0x70), conversationId, false);
  writeSmallString(base.add(0xb8), body, false);
  writeSmallString(base.add(0xd8), msgsource, false);

  [
    0x118,
    0x138,
    0x160,
    0x180,
    0x1a0,
    0x1c0,
    0x1e0,
    0x200,
    0x230,
    0x250,
  ].forEach((offset) => {
    writeSmallString(base.add(offset), "", false);
  });

  applyKnownSelfContextToRequestRegion(
    base,
    request ? request.requestSelfUsername : null,
    request ? request.requestNickname : null,
    request ? request.requestAlias : null
  );

  [0x270, 0x278, 0x280, 0x380].forEach((offset) => {
    base.add(offset).writeU32(0);
  });
  [0x288, 0x290, 0x298].forEach((offset) => {
    base.add(offset).writePointer(ptr("0x0"));
  });
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
    globalThis.capturedTailTemplateBlock = readTailTemplateFromWrapper(wrapperBase);
    globalThis.capturedPrepared = null;
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
        directSchedule: !!globalThis.autoDetachedConfig.directSchedule,
      });
      const scheduleMode = config.directSchedule ? "direct" : "setImmediate";
      const selfPatch = patchSourceBodyField(snapshot.object, config.body);
      rawSend({
        kind: "auto-detached-launching",
        threadId: Process.getCurrentThreadId(),
        templateRegion: config.templateRegion,
        targetThreadId: config.threadId,
        entry: config.entryName,
        body: config.body,
        scheduleMode,
      });
      if (selfPatch) {
        rawSend({
          kind: "auto-detached-source-self-patched",
          threadId: Process.getCurrentThreadId(),
          object: snapshot.object,
          body: config.body,
          selfPatch,
        });
      }
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
      globalThis.detachedStatus = {
        status: "queued-from-capture",
        requestedThreadId: config.threadId,
        captureThreadId: Process.getCurrentThreadId(),
        entry: config.entryName,
        scheduleMode,
      };

      const launchAutoDetached = function (source) {
        rawSend({
          kind: "auto-detached-schedule-enter",
          threadId: Process.getCurrentThreadId(),
          targetThreadId: config.threadId,
          entry: config.entryName,
          body: config.body,
          scheduleMode,
          source,
        });
        try {
          const status = scheduleDetached(
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
          rawSend({
            kind: "auto-detached-schedule-return",
            threadId: Process.getCurrentThreadId(),
            targetThreadId: config.threadId,
            entry: config.entryName,
            scheduleMode,
            source,
            detachedStatus: status,
          });
        } catch (error) {
          globalThis.detachedStatus = {
            status: "schedule-error",
            requestedThreadId: config.threadId,
            actualThreadId: Process.getCurrentThreadId(),
            entry: config.entryName,
            scheduleMode,
            source,
            error: String(error),
          };
          rawSend({
            kind: "auto-detached-schedule-error",
            threadId: Process.getCurrentThreadId(),
            targetThreadId: config.threadId,
            entry: config.entryName,
            scheduleMode,
            source,
            error: String(error),
          });
        }
      };

      if (config.directSchedule) {
        rawSend({
          kind: "auto-detached-direct-dispatch",
          threadId: Process.getCurrentThreadId(),
          targetThreadId: config.threadId,
          entry: config.entryName,
          scheduleMode,
        });
        launchAutoDetached("direct");
      } else {
        rawSend({
          kind: "auto-detached-before-setimmediate",
          threadId: Process.getCurrentThreadId(),
          targetThreadId: config.threadId,
          entry: config.entryName,
          scheduleMode,
        });
        setImmediate(function () {
          rawSend({
            kind: "auto-detached-setimmediate-fired",
            threadId: Process.getCurrentThreadId(),
            targetThreadId: config.threadId,
            entry: config.entryName,
            scheduleMode,
          });
          launchAutoDetached("setImmediate");
        });
      }
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
    if (globalThis.swapState.preparedWrapper && globalThis.swapState.preparedObject) {
      cloned = {
        base: ptr(globalThis.swapState.preparedWrapper),
        object: ptr(globalThis.swapState.preparedObject),
      };
    } else if (globalThis.capturedTemplateBlock === null) {
      return;
    } else {
      cloned = cloneCapturedTemplate(globalThis.swapState.conversationId);
    }
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

const LATE_PAIR_COPY_SWAP_OFFSETS = [0x332e438];
const LATE_PAIR_COPY_PATCH_OFFSETS = [0x2835f2a, 0x332e438];

function shouldSwapLatePairCopy(returnAddress) {
  try {
    const offsetText = ptr(returnAddress).sub(moduleBase).toString();
    const offset = parseInt(offsetText, 16);
    return LATE_PAIR_COPY_SWAP_OFFSETS.indexOf(offset) !== -1;
  } catch (error) {
    return false;
  }
}

function shouldPatchLatePairCopy(returnAddress) {
  try {
    const offsetText = ptr(returnAddress).sub(moduleBase).toString();
    const offset = parseInt(offsetText, 16);
    return LATE_PAIR_COPY_PATCH_OFFSETS.indexOf(offset) !== -1;
  } catch (error) {
    return false;
  }
}

function patchKnownLateCopiedSource(outputPair, syntheticPair) {
  const currentPair = safeReadRcPair(outputPair);
  if (
    currentPair.object === "0x0" ||
    currentPair.error ||
    !syntheticPair ||
    !syntheticPair.object
  ) {
    return null;
  }

  const targetObject = ptr(currentPair.object);
  const syntheticObject = ptr(syntheticPair.object);
  const targetRegion = targetObject.add(TEMPLATE_REQUEST_REGION_OFFSET);
  const syntheticRegion = syntheticObject.add(TEMPLATE_REQUEST_REGION_OFFSET);
  const before = {
    talker: readSmallString(targetObject.add(0xb0)),
    selfField: readSmallString(targetObject.add(0x660)),
    request: inspectRequestRegion(targetRegion),
  };

  // Preserve the donor object's normalize/container state. The detached outer
  // request already carries the body/talker payload we want; overwriting the
  // donor's embedded request strings here has been correlated with early parse
  // crashes before the send reaches finalize.
  patchSyntheticGoodSource(targetObject, globalThis.swapState.conversationId, globalThis.swapState.selfUsername);
  const syntheticSelf = readSmallString(syntheticObject.add(0x660));
  if (syntheticSelf && typeof syntheticSelf.text === "string") {
    writeSmallString(targetObject.add(0x660), syntheticSelf.text, true);
  }
  if (globalThis.latePairCopyRequestFieldPatchState.enabled && globalThis.lastDetachedRequest) {
    applyDetachedRequestSkeleton(targetRegion, globalThis.lastDetachedRequest);
  }

  return {
    pair: safeReadRcPair(outputPair),
    patch: {
      before,
      after: {
        talker: readSmallString(targetObject.add(0xb0)),
        selfField: readSmallString(targetObject.add(0x660)),
        request: inspectRequestRegion(targetRegion),
      },
    },
  };
}

function maybePatchLatePairCopyResult(outputPair, returnAddress) {
  if (!globalThis.swapState || !globalThis.swapState.enabled) {
    return null;
  }
  if (!globalThis.latePairCopyPatchState.enabled) {
    return null;
  }
  if (globalThis.swapState.mode !== "synthetic") {
    return null;
  }
  if (Process.getCurrentThreadId() !== globalThis.swapState.threadId) {
    return null;
  }
  if (!shouldPatchLatePairCopy(returnAddress)) {
    return null;
  }

  let synthetic = globalThis.syntheticPrepared;
  if (!synthetic) {
    synthetic = buildSyntheticGoodPair(
      globalThis.swapState.conversationId,
      globalThis.swapState.selfUsername
    );
  }
  if (!synthetic) {
    return null;
  }

  const result = patchKnownLateCopiedSource(outputPair, synthetic);
  if (!result) {
    return null;
  }

  rawSend({
    kind: "pair-copy-maybe-patched-known-fields",
    threadId: Process.getCurrentThreadId(),
    pair: result.pair,
    patch: result.patch,
  });
  return result.pair;
}

function maybeSwapPairCopyResult(outputPair, returnAddress) {
  if (!globalThis.swapState || !globalThis.swapState.enabled) {
    return null;
  }
  if (!globalThis.latePairCopySwapState.enabled) {
    return null;
  }
  if (globalThis.swapState.mode !== "synthetic") {
    return null;
  }
  if (Process.getCurrentThreadId() !== globalThis.swapState.threadId) {
    return null;
  }
  if (!shouldSwapLatePairCopy(returnAddress)) {
    return null;
  }

  let synthetic = globalThis.syntheticPrepared;
  if (!synthetic) {
    synthetic = buildSyntheticGoodPair(
      globalThis.swapState.conversationId,
      globalThis.swapState.selfUsername
    );
  }
  if (!synthetic) {
    return null;
  }

  const before = safeReadRcPair(outputPair);
  if (before.object === "0x0" || before.error) {
    return null;
  }
  if (before.object === synthetic.object.toString() && before.ref === synthetic.base.toString()) {
    return null;
  }

  ptr(outputPair).writePointer(synthetic.object);
  ptr(outputPair).add(Process.pointerSize).writePointer(synthetic.base);

  const after = safeReadRcPair(outputPair);
  rawSend({
    kind: "pair-copy-maybe-swapped-synthetic",
    threadId: Process.getCurrentThreadId(),
    oldPair: before,
    newPair: after,
  });
  return after;
}

function ensureCrashStubBypass() {
  if (globalThis.crashStubBypassState.enabled) {
    return globalThis.crashStubBypassState;
  }
  const crashStubAddress = moduleBase.add(OFFSETS.crashStub);
  Interceptor.replace(
    crashStubAddress,
    new NativeCallback(function () {
      let backtrace = [];
      try {
        backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
      } catch (_) {
        backtrace = [];
      }
      rawSend({
        kind: "crash-stub-bypassed",
        threadId: Process.getCurrentThreadId(),
        address: crashStubAddress.toString(),
        backtrace: backtrace.map((entry) => entry.toString()).slice(0, 12),
      });
      return;
    }, "void", [])
  );
  globalThis.crashStubBypassState = {
    enabled: true,
  };
  return globalThis.crashStubBypassState;
}

function ensureWatsonFailFastBypass() {
  if (globalThis.watsonFailFastBypassState.enabled) {
    return globalThis.watsonFailFastBypassState;
  }
  const target = moduleBase.add(OFFSETS.watsonFailFast);
  let watsonExport = null;
  try {
    watsonExport = Module.getExportByName("ucrtbase.dll", "_invoke_watson");
  } catch (_) {
    watsonExport = null;
  }
  Interceptor.replace(
    target,
    new NativeCallback(function () {
      rawSend({
        kind: "watson-failfast-bypassed",
        threadId: Process.getCurrentThreadId(),
        target: target.toString(),
        backtrace: formatBacktrace(this.context).slice(0, 16),
      });
      return;
    }, "void", [])
  );
  if (watsonExport) {
    Interceptor.replace(
      watsonExport,
      new NativeCallback(function (_a0, _a1, _a2, _a3, _a4) {
        rawSend({
          kind: "invoke-watson-bypassed",
          threadId: Process.getCurrentThreadId(),
          target: watsonExport.toString(),
          backtrace: formatBacktrace(this.context).slice(0, 16),
        });
        return;
      }, "void", ["pointer", "pointer", "pointer", "uint", "uint64"])
    );
  }
  globalThis.watsonFailFastBypassState = {
    enabled: true,
    target: target.toString(),
    watsonExport: watsonExport ? watsonExport.toString() : null,
  };
  return globalThis.watsonFailFastBypassState;
}

function readHexWindow(address, beforeBytes, totalBytes) {
  try {
    const start = ptr(address).sub(beforeBytes);
    const parts = [];
    for (let i = 0; i < totalBytes; i += 1) {
      const value = start.add(i).readU8();
      parts.push(value.toString(16).padStart(2, "0"));
    }
    return parts.join(" ");
  } catch (_) {
    return null;
  }
}

function maybeInstallRoamServerCrashProbe(reason) {
  if (!globalThis.roamServerCrashProbeState.enabled) {
    return null;
  }

  const module = Process.findModuleByName("roam_server.dll");
  if (!module) {
    return null;
  }

  const target = module.base.add(OFFSETS.roamServerCrashSite);
  if (globalThis.roamServerCrashProbeState.installed) {
    return globalThis.roamServerCrashProbeState;
  }

  rawSend({
    kind: "roam-server-crash-site-ready",
    threadId: Process.getCurrentThreadId(),
    reason: reason || "unknown",
    moduleBase: module.base.toString(),
    target: target.toString(),
    bytes: readHexWindow(target, 16, 64),
  });

  if (globalThis.roamServerCrashBypassState.enabled) {
    maybeInstallRoamServerCrashBypass(reason || "probe");
  } else {
    Interceptor.attach(target, {
      onEnter() {
        rawSend({
          kind: "roam-server-crash-site-hit",
          threadId: Process.getCurrentThreadId(),
          moduleBase: module.base.toString(),
          target: target.toString(),
          bytes: readHexWindow(target, 16, 64),
          backtrace: formatBacktrace(this.context).slice(0, 16),
        });
      },
    });
  }

  globalThis.roamServerCrashProbeState = {
    enabled: true,
    installed: true,
    loadHookInstalled: globalThis.roamServerCrashProbeState.loadHookInstalled,
    pollTimer: globalThis.roamServerCrashProbeState.pollTimer || null,
    target: target.toString(),
    moduleBase: module.base.toString(),
  };
  return globalThis.roamServerCrashProbeState;
}

function ensureRoamServerCrashProbe() {
  globalThis.roamServerCrashProbeState.enabled = true;
  maybeInstallRoamServerCrashProbe("enable");
  if (globalThis.roamServerCrashProbeState.loadHookInstalled) {
    return globalThis.roamServerCrashProbeState;
  }

  globalThis.roamServerCrashProbeState.pollTimer = setInterval(() => {
    if (!globalThis.roamServerCrashProbeState.enabled || globalThis.roamServerCrashProbeState.installed) {
      return;
    }
    maybeInstallRoamServerCrashProbe("poll");
  }, 50);
  globalThis.roamServerCrashProbeState.loadHookInstalled = true;
  return globalThis.roamServerCrashProbeState;
}

function maybeInstallRoamServerCrashBypass(reason) {
  if (!globalThis.roamServerCrashBypassState.enabled) {
    return null;
  }

  const module = Process.findModuleByName("roam_server.dll");
  if (!module) {
    return null;
  }

  const target = module.base.add(OFFSETS.roamServerCrashSite);
  if (globalThis.roamServerCrashBypassState.patched) {
    return globalThis.roamServerCrashBypassState;
  }

  const originalBytes = readHexWindow(target, 0, 8);
  Memory.patchCode(target, 2, (code) => {
    const writer = new X86Writer(code, { pc: target });
    writer.putNop();
    writer.putNop();
    writer.flush();
  });

  globalThis.roamServerCrashBypassState = {
    enabled: true,
    patched: true,
    target: target.toString(),
    moduleBase: module.base.toString(),
    originalBytes,
  };
  rawSend({
    kind: "roam-server-crash-site-bypassed",
    threadId: Process.getCurrentThreadId(),
    reason: reason || "unknown",
    moduleBase: module.base.toString(),
    target: target.toString(),
    originalBytes,
    patchedBytes: readHexWindow(target, 0, 8),
  });
  return globalThis.roamServerCrashBypassState;
}

function ensureRoamServerCrashBypass() {
  globalThis.roamServerCrashBypassState.enabled = true;
  ensureRoamServerCrashProbe();
  maybeInstallRoamServerCrashBypass("enable");
  return globalThis.roamServerCrashBypassState;
}

function maybeOverrideLoopFinalizeSourcePair(pairAddress) {
  if (!pairAddress || !globalThis.loopFinalizeOverride) {
    return null;
  }
  const mode = globalThis.loopFinalizeOverride.sourcePair || "keep";
  if (mode === "keep") {
    return null;
  }

  let replacementPair = null;
  if (mode === "saved") {
    const saved = getSavedLoopFinalizeState(Process.getCurrentThreadId());
    if (saved && saved.sourcePair && saved.sourcePair.object !== "0x0" && !saved.sourcePair.error) {
      replacementPair = {
        object: saved.sourcePair.object,
        ref: saved.sourcePair.ref,
      };
    }
  } else if (mode === "synthetic") {
    if (!globalThis.swapState || globalThis.swapState.mode !== "synthetic") {
      return null;
    }
    let synthetic = globalThis.syntheticPrepared;
    if (!synthetic) {
      synthetic = buildSyntheticGoodPair(
        globalThis.swapState.conversationId,
        globalThis.swapState.selfUsername
      );
    }
    if (synthetic) {
      replacementPair = {
        object: synthetic.object.toString(),
        ref: synthetic.base.toString(),
      };
    }
  }
  if (!replacementPair) {
    return null;
  }
  const target = ptr(pairAddress);
  const before = safeReadRcPair(target);
  target.writePointer(ptr(replacementPair.object));
  target.add(Process.pointerSize).writePointer(ptr(replacementPair.ref));
  return {
    mode,
    before,
    after: safeReadRcPair(target),
  };
}

function getSavedLoopFinalizeState(threadId) {
  if (!globalThis.loopFinalizeState || !globalThis.loopFinalizeState.byThread) {
    return null;
  }
  return globalThis.loopFinalizeState.byThread[String(threadId)] || null;
}

function maybeRestoreLoopFinalizeBindPair(pairAddress) {
  if (!pairAddress || !globalThis.loopFinalizeBindRestore) {
    return null;
  }
  const mode = globalThis.loopFinalizeBindRestore.sourcePair || "keep";
  if (mode === "keep") {
    return null;
  }

  let replacementPair = null;
  if (mode === "saved") {
    const saved = getSavedLoopFinalizeState(Process.getCurrentThreadId());
    if (saved && saved.sourcePair && saved.sourcePair.object !== "0x0" && !saved.sourcePair.error) {
      replacementPair = {
        object: saved.sourcePair.object,
        ref: saved.sourcePair.ref,
      };
    }
  } else if (mode === "synthetic") {
    if (globalThis.swapState && globalThis.swapState.mode === "synthetic") {
      let synthetic = globalThis.syntheticPrepared;
      if (!synthetic) {
        synthetic = buildSyntheticGoodPair(
          globalThis.swapState.conversationId,
          globalThis.swapState.selfUsername
        );
      }
      if (synthetic) {
        replacementPair = {
          object: synthetic.object.toString(),
          ref: synthetic.base.toString(),
        };
      }
    }
  }

  if (!replacementPair) {
    return null;
  }

  const target = ptr(pairAddress);
  const before = safeReadRcPair(target);
  target.writePointer(ptr(replacementPair.object));
  target.add(Process.pointerSize).writePointer(ptr(replacementPair.ref));
  return {
    mode,
    before,
    after: safeReadRcPair(target),
  };
}

function extractForcedLoopFinalizeResult(pairAddress) {
  if (!pairAddress || ptr(pairAddress).isNull()) {
    return {
      pairAddress: pairAddress ? ptr(pairAddress).toString() : null,
      pair: null,
      promiseObject: null,
      resultObject: null,
      forcedResult: "0x0",
      error: "pairAddress is null",
    };
  }

  const pair = safeReadRcPair(pairAddress);
  if (!pair || pair.error || pair.object === "0x0") {
    return {
      pairAddress: ptr(pairAddress).toString(),
      pair,
      promiseObject: null,
      resultObject: null,
      forcedResult: "0x0",
      error: pair && pair.error ? pair.error : "pair object is null",
    };
  }

  try {
    const promiseObject = ptr(pair.object);
    const resultSlot = inspectFinalizePromiseResultSlot(promiseObject);
    const resultObject =
      resultSlot && resultSlot.object && resultSlot.object !== "0x0"
        ? ptr(resultSlot.object)
        : null;
    const forcedResultPointer =
      resultObject && !resultObject.isNull()
        ? safeReadPointer(resultObject.add(Process.pointerSize))
        : null;
    return {
      pairAddress: ptr(pairAddress).toString(),
      pair,
      promiseObject: promiseObject.toString(),
      resultSlot,
      resultObject: resultObject ? resultObject.toString() : null,
      forcedResult: forcedResultPointer ? forcedResultPointer.toString() : "0x0",
    };
  } catch (error) {
    return {
      pairAddress: ptr(pairAddress).toString(),
      pair,
      promiseObject: pair.object,
      resultObject: null,
      forcedResult: "0x0",
      error: error && error.stack ? String(error.stack) : String(error),
    };
  }
}

function ensureLoopFinalizeCastBypass() {
  if (globalThis.loopFinalizeCastBypassState.installed) {
    globalThis.loopFinalizeCastBypassState.enabled = true;
    return globalThis.loopFinalizeCastBypassState;
  }

  const target = moduleBase.add(OFFSETS.builderMessagePrepLoopFinalize);
  const compareTarget = moduleBase.add(OFFSETS.builderMessagePrepLoopFinalizeTypeCompare);
  const compareReturnSite = target.add(0xbd);
  const originalCompare = new NativeFunction(compareTarget, "int", ["pointer", "pointer"]);
  Interceptor.replace(
    compareTarget,
    new NativeCallback(function (left, right) {
      const forceCompare =
        globalThis.loopFinalizeCastBypassState.enabled &&
        shouldTraceDetachedFocusedPath() &&
        this.returnAddress &&
        this.returnAddress.equals(compareReturnSite);
      const threadId = Process.getCurrentThreadId();
      const leftAddress = left ? ptr(left).toString() : null;
      const rightAddress = right ? ptr(right).toString() : null;
      const leftText = left ? safeReadCString(left) : null;
      const rightText = right ? safeReadCString(right) : null;
      if (forceCompare) {
        rawSend({
          kind: "builder-message-prep-loop-finalize-compare-enter",
          threadId,
          left: leftAddress,
          right: rightAddress,
          leftText,
          rightText,
          returnAddress: this.returnAddress.toString(),
        });
        rawSend({
          kind: "builder-message-prep-loop-finalize-compare-forced",
          threadId,
          originalRetval: null,
          forcedRetval: 0,
          left: leftAddress,
          right: rightAddress,
          leftText,
          rightText,
          skippedNativeCall: true,
        });
        return 0;
      }
      return originalCompare(left, right);
    }, "int", ["pointer", "pointer"])
  );
  globalThis.loopFinalizeCastBypassState = {
    enabled: true,
    installed: true,
    target: target.toString(),
    compareTarget: compareTarget.toString(),
    compareReturnSite: compareReturnSite.toString(),
  };
  rawSend({
    kind: "builder-message-prep-loop-finalize-force-installed",
    threadId: Process.getCurrentThreadId(),
    target: target.toString(),
    compareTarget: compareTarget.toString(),
    compareReturnSite: compareReturnSite.toString(),
  });
  return globalThis.loopFinalizeCastBypassState;
}

function ensureLoopFinalizeAwaitBypass() {
  if (globalThis.loopFinalizeAwaitBypassState.installed) {
    globalThis.loopFinalizeAwaitBypassState.enabled = true;
    return globalThis.loopFinalizeAwaitBypassState;
  }

  const awaitCheckTarget = moduleBase.add(OFFSETS.builderMessagePrepLoopFinalizeAwaitCheck);
  const awaitResultSlotTarget = moduleBase.add(OFFSETS.builderMessagePrepLoopFinalizeAwaitResultSlot);
  const originalAwaitCheck = new NativeFunction(awaitCheckTarget, "void", ["pointer"]);
  const originalAwaitResultSlot = new NativeFunction(awaitResultSlotTarget, "pointer", ["pointer"]);
  Interceptor.replace(
    awaitCheckTarget,
    new NativeCallback(function (pairAddress) {
      const threadId = Process.getCurrentThreadId();
      const threadKey = String(threadId);
      const focused =
        globalThis.loopFinalizeAwaitBypassState.enabled &&
        shouldTraceDetachedFocusedPath();
      const promiseObject =
        pairAddress && !ptr(pairAddress).isNull() ? safeReadPointer(pairAddress) : null;
      if (!focused) {
        originalAwaitCheck(pairAddress);
        return;
      }
      const usedNativeChecks =
        globalThis.loopFinalizeAwaitBypassState.nativeCheckCountByThread[threadKey] || 0;
      const nativeCheckBudget = globalThis.loopFinalizeAwaitBypassState.nativeCheckBudget || 0;
      if (usedNativeChecks < nativeCheckBudget) {
        globalThis.loopFinalizeAwaitBypassState.nativeCheckCountByThread[threadKey] =
          usedNativeChecks + 1;
        globalThis.loopFinalizeAwaitBypassState.passThroughResultSlotByThread[threadKey] = true;
        rawSend({
          kind: "builder-message-prep-loop-finalize-await-check-native-pass-through",
          threadId,
          nativePassIndex: usedNativeChecks + 1,
          nativeCheckBudget,
        });
        originalAwaitCheck(pairAddress);
        let promiseStateAfter = null;
        let resultSlotAfter = null;
        try {
          if (promiseObject && !promiseObject.isNull()) {
            promiseStateAfter = safeReadU32(ptr(promiseObject).add(0xc4));
            resultSlotAfter = inspectFinalizePromiseResultSlot(ptr(promiseObject));
          }
        } catch (error) {
          resultSlotAfter = {
            error: String(error),
          };
        }
        rawSend({
          kind: "builder-message-prep-loop-finalize-await-check-native-pass-through-leave",
          threadId,
          nativePassIndex: usedNativeChecks + 1,
          pairAddress: pairAddress ? ptr(pairAddress).toString() : "0x0",
          promiseObject: promiseObject ? promiseObject.toString() : "0x0",
          promiseStateAfter,
          resultSlot: resultSlotAfter,
        });
        return;
      }
      rawSend({
        kind: "builder-message-prep-loop-finalize-await-check-bypassed",
        threadId,
        pairAddress: pairAddress ? ptr(pairAddress).toString() : "0x0",
        pair: safeReadRcPair(pairAddress),
        promiseObject: promiseObject ? promiseObject.toString() : "0x0",
        nativeChecksUsed: usedNativeChecks,
        returnAddress: this.returnAddress ? this.returnAddress.toString() : null,
      });
      return;
    }, "void", ["pointer"])
  );
  Interceptor.replace(
    awaitResultSlotTarget,
    new NativeCallback(function (promiseObject) {
      const threadId = Process.getCurrentThreadId();
      const threadKey = String(threadId);
      const focused =
        globalThis.loopFinalizeAwaitBypassState.enabled &&
        shouldTraceDetachedFocusedPath();
      if (!focused) {
        return originalAwaitResultSlot(promiseObject);
      }
      const consumeNativePass =
        !!globalThis.loopFinalizeAwaitBypassState.passThroughResultSlotByThread[threadKey];
      if (consumeNativePass) {
        delete globalThis.loopFinalizeAwaitBypassState.passThroughResultSlotByThread[threadKey];
        const retval = originalAwaitResultSlot(promiseObject);
        let promiseState = null;
        let resultSlot = null;
        try {
          if (promiseObject && !ptr(promiseObject).isNull()) {
            promiseState = safeReadU32(ptr(promiseObject).add(0xc4));
            resultSlot = inspectFinalizePromiseResultSlot(ptr(promiseObject));
          }
        } catch (error) {
          resultSlot = {
            error: String(error),
          };
        }
        try {
          rawSend({
            kind: "builder-message-prep-loop-finalize-await-result-slot-native-pass-through",
            threadId,
            promiseObject: promiseObject ? ptr(promiseObject).toString() : "0x0",
            retval: retval ? ptr(retval).toString() : "0x0",
            promiseState,
            resultSlot,
            returnAddress: this.returnAddress ? this.returnAddress.toString() : null,
          });
        } catch (error) {
          rawSend({
            kind: "builder-message-prep-loop-finalize-await-result-slot-native-pass-through-log-error",
            threadId,
            error: String(error),
          });
        }
        return retval;
      }
      let forcedRetval = ptr(0);
      if (promiseObject && !ptr(promiseObject).isNull()) {
        forcedRetval = ptr(promiseObject).add(0xb8);
        rawSend({
          kind: "builder-message-prep-loop-finalize-await-result-slot-bypassed",
          threadId,
          promiseObject: ptr(promiseObject).toString(),
          forcedRetval: forcedRetval.toString(),
          promiseState: safeReadU32(ptr(promiseObject).add(0xc4)),
          resultObject: safeReadPointer(ptr(promiseObject).add(0xb8))
            ? safeReadPointer(ptr(promiseObject).add(0xb8)).toString()
            : "0x0",
          returnAddress: this.returnAddress ? this.returnAddress.toString() : null,
        });
        return forcedRetval;
      }
      return forcedRetval;
    }, "pointer", ["pointer"])
  );
  globalThis.loopFinalizeAwaitBypassState = {
    enabled: true,
    installed: true,
    awaitCheckTarget: awaitCheckTarget.toString(),
    awaitResultSlotTarget: awaitResultSlotTarget.toString(),
    nativeCheckBudget: 2,
    nativeCheckCountByThread: Object.create(null),
    passThroughResultSlotByThread: Object.create(null),
  };
  rawSend({
    kind: "builder-message-prep-loop-finalize-await-bypass-installed",
    threadId: Process.getCurrentThreadId(),
    awaitCheckTarget: awaitCheckTarget.toString(),
    awaitResultSlotTarget: awaitResultSlotTarget.toString(),
  });
  return globalThis.loopFinalizeAwaitBypassState;
}

function ensurePostFinalizeResolveBypass() {
  if (globalThis.postFinalizeResolveBypassState.installed) {
    globalThis.postFinalizeResolveBypassState.enabled = true;
    return globalThis.postFinalizeResolveBypassState;
  }

  const target = moduleBase.add(OFFSETS.builderMessagePrepPostFinalizeResolve);
  const promisePairCtor = new NativeFunction(
    moduleBase.add(OFFSETS.builderMessagePrepLoopFinalizePairCtor),
    "pointer",
    ["pointer"]
  );
  const resolveHelper = new NativeFunction(
    moduleBase.add(OFFSETS.postFinalizeResolveHelper),
    "void",
    ["pointer", "pointer", "pointer", "pointer"]
  );
  Interceptor.replace(
    target,
    new NativeCallback(function (resolverObject, resultPairAddress) {
      if (
        globalThis.postFinalizeResolveBypassState.enabled &&
        shouldTraceDetachedFocusedPath()
      ) {
        let seededPromise = null;
        let inputPair = null;
        let promiseObject = null;
        let localPromisePair = null;
        let localCopyRef = null;
        let helperResultPair = null;
        let resolveError = null;
        if (resolverObject && !ptr(resolverObject).isNull()) {
          try {
            localPromisePair = Memory.alloc(Process.pointerSize * 2);
            promisePairCtor(localPromisePair);
            seededPromise = safeReadRcPair(localPromisePair);
            promiseObject =
              seededPromise && seededPromise.object && seededPromise.object !== "0x0"
                ? ptr(seededPromise.object)
                : null;
            inputPair = resultPairAddress ? safeReadRcPair(resultPairAddress) : null;
            if (
              promiseObject &&
              !promiseObject.isNull() &&
              inputPair &&
              inputPair.object &&
              inputPair.object !== "0x0"
            ) {
              resolveHelper(resultPairAddress, localPromisePair, ptr(0), ptr(0));
              helperResultPair = safeReadRcPair(localPromisePair);
            }
            ptr(resolverObject).writePointer(ptr(0));
            ptr(resolverObject).add(Process.pointerSize).writePointer(ptr(0));
            const copiedPair = helperResultPair || seededPromise;
            if (copiedPair && copiedPair.object && copiedPair.object !== "0x0") {
              ptr(resolverObject).writePointer(ptr(copiedPair.object));
            }
            if (copiedPair && copiedPair.ref && copiedPair.ref !== "0x0") {
              localCopyRef = ptr(copiedPair.ref);
              try {
                localCopyRef.add(0x08).writeU32(localCopyRef.add(0x08).readU32() + 1);
              } catch (_) {}
              ptr(resolverObject).add(Process.pointerSize).writePointer(localCopyRef);
            }
          } catch (error) {
            resolveError = String(error);
          }
        }
        rawSend({
          kind: "builder-message-prep-post-finalize-resolve-bypassed",
          threadId: Process.getCurrentThreadId(),
          resolverObject: resolverObject ? ptr(resolverObject).toString() : "0x0",
          resultPairAddress: resultPairAddress ? ptr(resultPairAddress).toString() : "0x0",
          resultPair: inputPair || safeReadRcPair(resultPairAddress),
          seededPromise,
          localPromisePair: localPromisePair ? safeReadRcPair(localPromisePair) : null,
          resolverPairAfter: resolverObject && !ptr(resolverObject).isNull()
            ? safeReadRcPair(resolverObject)
            : null,
          promiseObject: promiseObject ? promiseObject.toString() : null,
          helperResultPair,
          localCopyRef: localCopyRef ? localCopyRef.toString() : null,
          resolveError,
          returnAddress: this.returnAddress ? this.returnAddress.toString() : null,
        });
      }
      return resolverObject;
    }, "pointer", ["pointer", "pointer"])
  );
  globalThis.postFinalizeResolveBypassState = {
    enabled: true,
    installed: true,
    target: target.toString(),
  };
  rawSend({
    kind: "builder-message-prep-post-finalize-resolve-bypass-installed",
    threadId: Process.getCurrentThreadId(),
    target: target.toString(),
  });
  return globalThis.postFinalizeResolveBypassState;
}

function ensureProcessExitProbe() {
  if (globalThis.processExitProbeState.installed) {
    globalThis.processExitProbeState.enabled = true;
    return globalThis.processExitProbeState;
  }

  const targets = [
    ["kernel32.dll", "ExitProcess"],
    ["kernelbase.dll", "ExitProcess"],
    ["kernel32.dll", "TerminateProcess"],
    ["kernelbase.dll", "TerminateProcess"],
    ["ntdll.dll", "NtTerminateProcess"],
    ["ntdll.dll", "RtlFailFast2"],
    ["kernelbase.dll", "RaiseFailFastException"],
    ["ucrtbase.dll", "abort"],
    ["vcruntime140.dll", "abort"],
  ];
  const installedTargets = [];
  for (const [moduleName, exportName] of targets) {
    let address = null;
    try {
      address = Module.getExportByName(moduleName, exportName);
    } catch (_) {
      address = null;
    }
    if (!address) {
      continue;
    }
    Interceptor.attach(address, {
      onEnter(args) {
        if (
          !globalThis.processExitProbeState.enabled ||
          !shouldTraceDetachedFocusedPath()
        ) {
          return;
        }
        rawSend({
          kind: "process-exit-probe-hit",
          threadId: Process.getCurrentThreadId(),
          moduleName,
          exportName,
          address: address.toString(),
          returnAddress: this.returnAddress ? this.returnAddress.toString() : null,
          arg0: args[0] ? ptr(args[0]).toString() : "0x0",
          arg1: args[1] ? ptr(args[1]).toString() : "0x0",
          arg2: args[2] ? ptr(args[2]).toString() : "0x0",
        });
      },
    });
    installedTargets.push({
      moduleName,
      exportName,
      address: address.toString(),
    });
  }
  globalThis.processExitProbeState = {
    enabled: true,
    installed: true,
    targets: installedTargets,
  };
  rawSend({
    kind: "process-exit-probe-installed",
    threadId: Process.getCurrentThreadId(),
    targets: installedTargets,
  });
  return globalThis.processExitProbeState;
}

Interceptor.attach(moduleBase.add(OFFSETS.workerCtor), {
  onEnter(args) {
    if (!shouldTraceDetachedFocusedPath()) {
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
    if (!shouldTraceDetachedFocusedPath()) {
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
    if (!shouldTraceDetachedFocusedPath()) {
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
    if (!shouldTraceDetachedFocusedPath()) {
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

Interceptor.attach(moduleBase.add(OFFSETS.workerCtor), {
  onEnter(args) {
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
    const sourcePair = safeReadRcPair(args[1]);
    rawSend({
      kind: "worker-ctor-enter",
      threadId: Process.getCurrentThreadId(),
      worker: ptr(args[0]).toString(),
      sourcePair,
      modeFlag: Number(args[2]),
      caller: this.returnAddress.toString(),
      sourceObject: sourcePair.object === "0x0" || sourcePair.error ? null : inspectSyntheticSourceObject(sourcePair.object),
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
    this.src = ptr(args[0]);
    this.dst = ptr(args[1]);
    if (globalThis.contextWatchState.enabled) {
      this.watchThreadId = Process.getCurrentThreadId();
      this.watchSrc = this.src;
      this.watchDst = this.dst;
      this.watchSrcPair = safeReadRcPair(this.watchSrc.add(0x28));
    }
    if (!shouldTraceDetachedHotPath()) {
      return;
    }
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
    if (globalThis.contextWatchState.enabled && this.watchDst) {
      const copiedPair = safeReadRcPair(this.watchDst);
      let copiedTalker = null;
      if (copiedPair.object !== "0x0") {
        copiedTalker = readTalkerFromSourceObject(copiedPair.object);
      }
      globalThis.contextWatchState.pendingByThread[String(this.watchThreadId)] = {
        observedThreadId: this.watchThreadId,
        wrapper: this.watchSrc.toString(),
        srcPair: this.watchSrcPair,
        copiedPair,
        copiedTalker,
        normalizedPair: null,
        normalizedTalker: null,
      };
    }
    if (!shouldTraceDetachedHotPath()) {
      const patchedPair = maybePatchLatePairCopyResult(this.dst, this.returnAddress);
      if (!patchedPair) {
        maybeSwapPairCopyResult(this.dst, this.returnAddress);
      }
      return;
    }
    const patchedPair = maybePatchLatePairCopyResult(this.dst, this.returnAddress);
    const swappedPair = patchedPair ? null : maybeSwapPairCopyResult(this.dst, this.returnAddress);
    const dstPair = patchedPair || swappedPair || safeReadRcPair(this.dst);
    let dstObjectState = null;
    if (dstPair.object !== "0x0" && !dstPair.error) {
      try {
        dstObjectState = inspectSyntheticSourceObject(dstPair.object);
      } catch (error) {
        dstObjectState = {
          address: dstPair.object,
          inspectError: String(error),
        };
      }
    }
    rawSend({
      kind: "pair-copy-maybe-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      dstPair,
      dstObjectState,
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.entryBPairNormalize), {
  onEnter: guardHook("entryb-pair-normalize", "enter", function (args) {
    if (globalThis.contextWatchState.enabled) {
      this.watchThreadId = Process.getCurrentThreadId();
      this.watchDst = ptr(args[1]);
    }
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
    if (globalThis.contextWatchState.enabled && this.watchDst) {
      const pending = globalThis.contextWatchState.pendingByThread[String(this.watchThreadId)];
      if (pending) {
        pending.normalizedPair = safeReadRcPair(this.watchDst);
        if (pending.normalizedPair.object !== "0x0") {
          pending.normalizedTalker = readTalkerFromSourceObject(pending.normalizedPair.object);
        }
        maybeStoreContextWatchEntry(pending);
        delete globalThis.contextWatchState.pendingByThread[String(this.watchThreadId)];
      }
    }
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
    this.statusOut = ptr(args[1]);
    rawSend({
      kind: "entryb-worker-dispatch-enter",
      threadId: Process.getCurrentThreadId(),
      arg0: ptr(args[0]).toString(),
      arg1: ptr(args[1]).toString(),
      arg2: ptr(args[2]).toString(),
      pair: safeReadRcPair(args[2]),
      statusBefore: inspectDispatchStatus(args[1]),
      caller: this.returnAddress.toString(),
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
      statusAfter: inspectDispatchStatus(this.statusOut),
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
      let payload = {};
      if (payloadFactory) {
        try {
          payload =
            payloadFactory(args, {
              returnAddress: this.returnAddress,
              context: this.context,
            }) || {};
        } catch (error) {
          payload = {
            hookPayloadError: String(error),
          };
        }
      }
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

function attachFocusedBuilderStageHook(offset, kind, payloadFactory) {
  Interceptor.attach(moduleBase.add(offset), {
    onEnter(args) {
      if (!shouldTraceDetachedFocusedPath()) {
        return;
      }
      let payload = {};
      if (payloadFactory) {
        try {
          payload =
            payloadFactory(args, {
              returnAddress: this.returnAddress,
              context: this.context,
            }) || {};
        } catch (error) {
          payload = {
            hookPayloadError: String(error),
          };
        }
      }
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
attachFocusedBuilderStageHook(OFFSETS.builderMessagePrepAuxA, "builder-message-prep-aux-a-enter", (args, meta) => {
  const threadId = Process.getCurrentThreadId();
  const rsp = meta.context && meta.context.rsp ? ptr(meta.context.rsp) : null;
  const rbp = meta.context && meta.context.rbp ? ptr(meta.context.rbp) : null;
  const stackReturnAddress = rsp && !rsp.isNull() ? safeReadPointer(rsp) : null;
  const entryState = {
    caller: meta.returnAddress ? meta.returnAddress.toString() : "0x0",
    rsp: rsp ? rsp.toString() : "0x0",
    rbp: rbp ? rbp.toString() : "0x0",
    stackReturnAddress: stackReturnAddress ? stackReturnAddress.toString() : "0x0",
  };
  globalThis.builderAuxAEntryState.byThread[String(threadId)] = entryState;
  return {
    arg0: ptr(args[0]).toString(),
    caller: entryState.caller,
    entryRsp: entryState.rsp,
    entryRbp: entryState.rbp,
    entryStackReturnAddress: entryState.stackReturnAddress,
  };
});
attachBuilderStageHook(OFFSETS.builderMessagePrepAuxC, "builder-message-prep-aux-c-enter", (args, meta) => ({
  arg0: ptr(args[0]).toString(),
  arg1: ptr(args[1]).toString(),
  arg2: ptr(args[2]).toString(),
  caller: meta.returnAddress.toString(),
}));
attachFocusedBuilderStageHook(OFFSETS.builderMessagePrepLoopPrep, "builder-message-prep-loop-prep-enter", (args, meta) => {
  const rbp = meta.context && meta.context.rbp ? ptr(meta.context.rbp) : null;
  const frameReturnSlot =
    rbp && !rbp.isNull() ? safeReadPointer(rbp.add(0x2a8)) : null;
  const slotRepair = maybeRepairBuilderReturnSlot(rbp, Process.getCurrentThreadId(), "loop-prep-enter");
  return {
    arg0: ptr(args[0]).toString(),
    arg1: ptr(args[1]).toString(),
    caller: meta.returnAddress.toString(),
    rbp: rbp ? rbp.toString() : "0x0",
    frameReturnSlot: frameReturnSlot ? frameReturnSlot.toString() : "0x0",
    slotRepair,
  };
});
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepLoopKey), {
  onEnter(args) {
    if (!shouldTraceDetachedFocusedPath()) {
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
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    rawSend({
      kind: "builder-message-prep-loop-key-leave",
      threadId: Process.getCurrentThreadId(),
      retval: Number(retval),
    });
  },
});
attachFocusedBuilderStageHook(
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
      if (!shouldTraceDetachedFocusedPath()) {
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
      if (!shouldTraceDetachedFocusedPath()) {
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
    if (!shouldTraceDetachedFocusedPath()) {
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
    if (!shouldTraceDetachedFocusedPath()) {
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
attachFocusedBuilderStageHook(OFFSETS.builderMessagePrepLoopItem, "builder-message-prep-loop-item-enter", (args, meta) => ({
  arg0: ptr(args[0]).toString(),
  arg1: ptr(args[1]).toString(),
  arg2: ptr(args[2]).toString(),
  arg3: Number(args[3]),
  caller: meta.returnAddress.toString(),
}));
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepLoopFinalizePairCtor), {
  onEnter: guardHook("builder-message-prep-loop-finalize-pair-ctor", "enter", function (args) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    this.outPair = ptr(args[0]);
    rawSend({
      kind: "builder-message-prep-loop-finalize-pair-ctor-enter",
      threadId: Process.getCurrentThreadId(),
      outPair: this.outPair.toString(),
      before: safeReadRcPair(this.outPair),
      caller: this.returnAddress.toString(),
    });
  }),
  onLeave: guardHook("builder-message-prep-loop-finalize-pair-ctor", "leave", function (retval) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const outPair = this.outPair ? safeReadRcPair(this.outPair) : null;
    rawSend({
      kind: "builder-message-prep-loop-finalize-pair-ctor-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      outPair,
      outPairPromiseObject:
        outPair && outPair.object !== "0x0" && !outPair.error
          ? inspectFinalizePromiseObject(outPair.object)
          : null,
    });
  }),
});
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepLoopFinalizeItemBind), {
  onEnter: guardHook("builder-message-prep-loop-finalize-item-bind", "enter", function (args) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    this.arg0 = ptr(args[0]);
    this.arg1 = ptr(args[1]);
    const restoreApplied = maybeRestoreLoopFinalizeBindPair(this.arg0);
    rawSend({
      kind: "builder-message-prep-loop-finalize-item-bind-enter",
      threadId: Process.getCurrentThreadId(),
      arg0: this.arg0.toString(),
      arg1: this.arg1.toString(),
      pairBefore: safeReadRcPair(this.arg0),
      itemObject: hex(safeReadPointer(this.arg1)),
      restoreApplied,
      caller: this.returnAddress.toString(),
    });
  }),
  onLeave: guardHook("builder-message-prep-loop-finalize-item-bind", "leave", function (retval) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const pairAfter = this.arg0 ? safeReadRcPair(this.arg0) : null;
    rawSend({
      kind: "builder-message-prep-loop-finalize-item-bind-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      pairAfter,
      pairAfterObject:
        pairAfter && pairAfter.object !== "0x0" && !pairAfter.error
          ? inspectFinalizeSourceObject(pairAfter.object)
          : null,
      pairAfterPromiseObject:
        pairAfter && pairAfter.object !== "0x0" && !pairAfter.error
          ? inspectFinalizePromiseObject(pairAfter.object)
          : null,
    });
  }),
});
attachFocusedBuilderStageHook(
  OFFSETS.builderMessagePrepLoopFinalize,
  "builder-message-prep-loop-finalize-enter",
  (args, meta) => {
    const arg0Pair = safeReadRcPair(args[0]);
    const arg1Pair = safeReadRcPair(args[1]);
    return {
      arg0: ptr(args[0]).toString(),
      arg1: ptr(args[1]).toString(),
      arg0Pair,
      arg1Pair,
      arg0PromiseObject:
        arg0Pair.object !== "0x0" && !arg0Pair.error
          ? inspectFinalizePromiseObject(arg0Pair.object)
          : null,
      arg1PromiseObject:
        arg1Pair.object !== "0x0" && !arg1Pair.error
          ? inspectFinalizePromiseObject(arg1Pair.object)
          : null,
      arg1Object:
        arg1Pair.object !== "0x0" && !arg1Pair.error
          ? inspectFinalizeSourceObject(arg1Pair.object)
          : null,
      caller: meta.returnAddress.toString(),
    };
  }
);
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepLoopFinalize), {
  onEnter(args) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const overrideResult = maybeOverrideLoopFinalizeSourcePair(args[1]);
    if (!overrideResult) {
      return;
    }
    rawSend({
      kind: "builder-message-prep-loop-finalize-source-override",
      threadId: Process.getCurrentThreadId(),
      sourcePairAddress: ptr(args[1]).toString(),
      override: overrideResult,
    });
  },
  onLeave(retval) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    rawSend({
      kind: "builder-message-prep-loop-finalize-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  },
});

Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepLoopFinalizeAwaitCheck), {
  onEnter(args) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    rawSend({
      kind: "builder-message-prep-loop-finalize-await-check-enter",
      threadId: Process.getCurrentThreadId(),
      arg0: ptr(args[0]).toString(),
      pair: safeReadRcPair(args[0]),
      caller: this.returnAddress.toString(),
      callerInfo: describeAddress(this.returnAddress),
    });
  },
  onLeave(retval) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    rawSend({
      kind: "builder-message-prep-loop-finalize-await-check-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  },
});

Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepLoopFinalizeAwaitResultSlot), {
  onEnter(args) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    rawSend({
      kind: "builder-message-prep-loop-finalize-await-result-slot-enter",
      threadId: Process.getCurrentThreadId(),
      arg0: ptr(args[0]).toString(),
      promiseObject: inspectFinalizePromiseObject(args[0]),
      caller: this.returnAddress.toString(),
      callerInfo: describeAddress(this.returnAddress),
    });
  },
  onLeave(retval) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const resultSlot = retval && !ptr(retval).isNull()
      ? {
          address: ptr(retval).toString(),
          object: safeReadPointer(retval) ? safeReadPointer(retval).toString() : "0x0",
          valueAt8: safeReadPointer(ptr(retval).add(Process.pointerSize))
            ? safeReadPointer(ptr(retval).add(Process.pointerSize)).toString()
            : "0x0",
        }
      : null;
    rawSend({
      kind: "builder-message-prep-loop-finalize-await-result-slot-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      resultSlot,
    });
  },
});
Interceptor.attach(moduleBase.add(0x332e46d), {
  onEnter() {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const frame = ptr(this.context.rbp);
    const threadId = Process.getCurrentThreadId();
    const sourcePair = safeReadRcPair(frame.add(0x10));
    const itemPair = safeReadRcPair(frame.add(0xe0));
    const frameReturnSlot =
      frame && !frame.isNull() ? safeReadPointer(frame.add(0x2a8)) : null;
    const slotRepair = maybeRepairBuilderReturnSlot(frame, threadId, "loop-item-return-site");
    globalThis.loopFinalizeState.byThread[String(threadId)] = {
      loopIndex: Number(this.context.r15),
      sourcePair,
      itemPair,
    };
    rawSend({
      kind: "builder-message-prep-loop-item-return-site",
      threadId,
      loopIndex: Number(this.context.r15),
      itemPair,
      sourcePair,
      rbp: frame.toString(),
      frameReturnSlot: frameReturnSlot ? frameReturnSlot.toString() : "0x0",
      slotRepair,
    });
  },
});
Interceptor.attach(moduleBase.add(0x332e917), {
  onEnter() {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const frame = ptr(this.context.rbp);
    const frameReturnSlot =
      frame && !frame.isNull() ? safeReadPointer(frame.add(0x2a8)) : null;
    const slotRepair = maybeRepairBuilderReturnSlot(
      frame,
      Process.getCurrentThreadId(),
      "loop-finalize-return-site"
    );
    rawSend({
      kind: "builder-message-prep-loop-finalize-return-site",
      threadId: Process.getCurrentThreadId(),
      loopIndex: Number(this.context.r15),
      finalizeRetval: hex(this.context.rax),
      sourcePair: safeReadRcPair(frame.add(0x10)),
      itemPair: safeReadRcPair(frame.add(0xe0)),
      rbp: frame.toString(),
      frameReturnSlot: frameReturnSlot ? frameReturnSlot.toString() : "0x0",
      slotRepair,
    });
  },
});
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepPostFinalizeReturnSite), {
  onEnter() {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const threadId = Process.getCurrentThreadId();
    const rbp = this.context.rbp ? ptr(this.context.rbp) : null;
    const stackReturnAddress =
      rbp && !rbp.isNull() ? safeReadPointer(rbp.add(0x2a8)) : null;
    const entryState = globalThis.builderAuxAEntryState.byThread[String(threadId)] || null;
    const slotRepair = maybeRepairBuilderReturnSlot(rbp, threadId, "post-finalize-return-site");
    rawSend({
      kind: "builder-message-prep-post-finalize-return-site",
      threadId,
      returnValueCandidate: this.context.rdi ? ptr(this.context.rdi).toString() : "0x0",
      returnedPair: safeReadRcPair(this.context.rdi),
      rsp: this.context.rsp ? ptr(this.context.rsp).toString() : "0x0",
      rbp: rbp ? rbp.toString() : "0x0",
      stackReturnAddress: stackReturnAddress ? stackReturnAddress.toString() : "0x0",
      entryCaller: entryState ? entryState.caller : "0x0",
      entryRsp: entryState ? entryState.rsp : "0x0",
      entryRbp: entryState ? entryState.rbp : "0x0",
      entryStackReturnAddress: entryState ? entryState.stackReturnAddress : "0x0",
      slotRepair,
      expectedOuterWrapperReturnSite: moduleBase
        .add(OFFSETS.builderMessagePrepOuterWrapperInnerReturnSite)
        .sub(1)
        .toString(),
    });
  },
});
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepAuxC), {
  onEnter(args) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const threadId = Process.getCurrentThreadId();
    const entryRsp = this.context.rsp ? ptr(this.context.rsp) : null;
    const entryState = {
      caller: this.returnAddress ? this.returnAddress.toString() : "0x0",
      rsp: entryRsp ? entryRsp.toString() : "0x0",
      stackReturnAddress:
        entryRsp && !entryRsp.isNull() ? safeReadPointer(entryRsp).toString() : "0x0",
      frameSlotAddress: "0x0",
      frameStackReturnAddress: "0x0",
    };
    globalThis.outerWrapperEntryState.byThread[String(threadId)] = entryState;
    rawSend({
      kind: "builder-message-prep-outer-wrapper-enter",
      threadId,
      arg0: args[0] ? ptr(args[0]).toString() : "0x0",
      arg1: args[1] ? ptr(args[1]).toString() : "0x0",
      arg2: args[2] ? ptr(args[2]).toString() : "0x0",
      entryCaller: entryState.caller,
      entryRsp: entryState.rsp,
      entryStackReturnAddress: entryState.stackReturnAddress,
    });
  },
  onLeave(retval) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    delete globalThis.outerWrapperEntryState.byThread[String(Process.getCurrentThreadId())];
    rawSend({
      kind: "builder-message-prep-outer-wrapper-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  },
});
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepOuterWrapperInnerReturnSite), {
  onEnter() {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const threadId = Process.getCurrentThreadId();
    const rbp = this.context.rbp ? ptr(this.context.rbp) : null;
    const frameSlotAddress = rbp && !rbp.isNull() ? rbp.add(0x1b8) : null;
    const frameStackReturnAddress =
      frameSlotAddress && !frameSlotAddress.isNull() ? safeReadPointer(frameSlotAddress) : null;
    const state = globalThis.outerWrapperEntryState.byThread[String(threadId)] || {
      caller: "0x0",
      rsp: "0x0",
      stackReturnAddress: "0x0",
      frameSlotAddress: "0x0",
      frameStackReturnAddress: "0x0",
    };
    state.frameSlotAddress = frameSlotAddress ? frameSlotAddress.toString() : "0x0";
    state.frameStackReturnAddress = frameStackReturnAddress
      ? frameStackReturnAddress.toString()
      : "0x0";
    globalThis.outerWrapperEntryState.byThread[String(threadId)] = state;
    let slotRepair = null;
    const bypassApplied = !!globalThis.outerWrapperAwaitBypassState.enabled;
    if (
      bypassApplied &&
      frameSlotAddress &&
      !frameSlotAddress.isNull() &&
      state.stackReturnAddress &&
      state.stackReturnAddress !== "0x0"
    ) {
      const before = frameStackReturnAddress ? frameStackReturnAddress.toString() : "0x0";
      const expected = state.stackReturnAddress;
      const repaired = before !== expected;
      if (repaired) {
        try {
          frameSlotAddress.writePointer(ptr(expected));
        } catch (error) {
          slotRepair = {
            slotAddress: frameSlotAddress.toString(),
            before,
            expected,
            repaired: false,
            error: String(error),
          };
        }
      }
      if (!slotRepair) {
        slotRepair = {
          slotAddress: frameSlotAddress.toString(),
          before,
          expected,
          repaired,
          after: safeReadPointer(frameSlotAddress).toString(),
        };
      }
      this.context.rip = moduleBase.add(OFFSETS.builderMessagePrepOuterWrapperReturnSite);
    }
    rawSend({
      kind: "builder-message-prep-outer-wrapper-inner-return-site",
      threadId,
      outPairAddress: this.context.rsi ? ptr(this.context.rsi).toString() : "0x0",
      outPair: safeReadRcPair(this.context.rsi),
      rbp: rbp ? rbp.toString() : "0x0",
      frameReturnSlot: frameSlotAddress ? frameSlotAddress.toString() : "0x0",
      stackReturnAddress: frameStackReturnAddress ? frameStackReturnAddress.toString() : "0x0",
      bypassApplied,
      jumpTarget: bypassApplied ? this.context.rip.toString() : "0x0",
      slotRepair,
    });
  },
});
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepOuterWrapperAwaitReturnSite), {
  onEnter() {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const threadId = Process.getCurrentThreadId();
    const retval = this.context.rax ? ptr(this.context.rax) : ptr(0);
    const bypassApplied = !!globalThis.outerWrapperAwaitBypassState.enabled;
    const entryState = globalThis.outerWrapperEntryState.byThread[String(threadId)] || null;
    const rbp = this.context.rbp ? ptr(this.context.rbp) : null;
    const slotAddress = rbp && !rbp.isNull() ? rbp.add(0x1b8) : null;
    const stackReturnAddress =
      slotAddress && !slotAddress.isNull() ? safeReadPointer(slotAddress) : null;
    rawSend({
      kind: "builder-message-prep-outer-wrapper-await-return-site",
      threadId,
      retval: retval.toString(),
      outPairAddress: this.context.rsi ? ptr(this.context.rsi).toString() : "0x0",
      outPair: safeReadRcPair(this.context.rsi),
      bypassApplied,
      entryCaller: entryState ? entryState.caller : "0x0",
      entryRsp: entryState ? entryState.rsp : "0x0",
      entryStackReturnAddress: entryState ? entryState.stackReturnAddress : "0x0",
      entryFrameReturnSlot: entryState ? entryState.frameSlotAddress : "0x0",
      entryFrameStackReturnAddress: entryState ? entryState.frameStackReturnAddress : "0x0",
      rbp: rbp ? rbp.toString() : "0x0",
      frameReturnSlot: slotAddress ? slotAddress.toString() : "0x0",
      stackReturnAddress: stackReturnAddress ? stackReturnAddress.toString() : "0x0",
    });
    if (!bypassApplied) {
      return;
    }
    let slotRepair = null;
    if (
      slotAddress &&
      !slotAddress.isNull() &&
      entryState &&
      entryState.stackReturnAddress &&
      entryState.stackReturnAddress !== "0x0"
    ) {
      const before = stackReturnAddress ? stackReturnAddress.toString() : "0x0";
      const expected = entryState.stackReturnAddress;
      const repaired = before !== expected;
      if (repaired) {
        try {
          slotAddress.writePointer(ptr(expected));
        } catch (error) {
          slotRepair = {
            slotAddress: slotAddress.toString(),
            before,
            expected,
            repaired: false,
            error: String(error),
          };
        }
      }
      if (!slotRepair) {
        slotRepair = {
          slotAddress: slotAddress.toString(),
          before,
          expected,
          repaired,
          after: safeReadPointer(slotAddress).toString(),
        };
      }
    }
    this.context.rsi = retval;
    this.context.rip = moduleBase.add(OFFSETS.builderMessagePrepOuterWrapperReturnSite);
    rawSend({
      kind: "builder-message-prep-outer-wrapper-await-bypassed",
      threadId,
      forcedResult: retval.toString(),
      jumpTarget: this.context.rip.toString(),
      slotRepair,
    });
  },
});
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepUpstreamWrapperReturnSite), {
  onEnter() {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const threadId = Process.getCurrentThreadId();
    const retval = this.context.rax ? ptr(this.context.rax) : ptr(0);
    const rbp = this.context.rbp ? ptr(this.context.rbp) : null;
    const callerSlot = rbp && !rbp.isNull() ? rbp.add(0x1e8) : null;
    const stackReturnAddress =
      callerSlot && !callerSlot.isNull() ? safeReadPointer(callerSlot) : null;
    const entryState = globalThis.builderTailEntryState.byThread[String(threadId)] || null;
    const bypassApplied = !!globalThis.upstreamWrapperReturnBypassState.enabled;
    rawSend({
      kind: "builder-message-prep-upstream-wrapper-return-site",
      threadId,
      retval: retval.toString(),
      rbp: rbp ? rbp.toString() : "0x0",
      callerSlot: callerSlot ? callerSlot.toString() : "0x0",
      stackReturnAddress: stackReturnAddress ? stackReturnAddress.toString() : "0x0",
      entryCaller: entryState ? entryState.caller : "0x0",
      entryRsp: entryState ? entryState.rsp : "0x0",
      entryStackReturnAddress: entryState ? entryState.stackReturnAddress : "0x0",
      bypassApplied,
    });
    if (!bypassApplied) {
      return;
    }
    let slotRepair = null;
    if (
      callerSlot &&
      !callerSlot.isNull() &&
      entryState &&
      entryState.stackReturnAddress &&
      entryState.stackReturnAddress !== "0x0"
    ) {
      const before = stackReturnAddress ? stackReturnAddress.toString() : "0x0";
      const expected = entryState.stackReturnAddress;
      const repaired = before !== expected;
      if (repaired) {
        try {
          callerSlot.writePointer(ptr(expected));
        } catch (error) {
          slotRepair = {
            slotAddress: callerSlot.toString(),
            before,
            expected,
            repaired: false,
            error: String(error),
          };
        }
      }
      if (!slotRepair) {
        slotRepair = {
          slotAddress: callerSlot.toString(),
          before,
          expected,
          repaired,
          after: safeReadPointer(callerSlot).toString(),
        };
      }
    }
    if (rbp && !rbp.isNull()) {
      try {
        rbp.add(0x198).writePointer(retval);
      } catch (error) {
        rawSend({
          kind: "builder-message-prep-upstream-wrapper-return-bypass-error",
          threadId,
          error: String(error),
        });
      }
    }
    this.context.r14 = retval;
    this.context.rip = moduleBase.add(OFFSETS.builderMessagePrepUpstreamWrapperReturnLoad);
    rawSend({
      kind: "builder-message-prep-upstream-wrapper-return-bypassed",
      threadId,
      forcedResult: retval.toString(),
      jumpTarget: this.context.rip.toString(),
      slotRepair,
    });
  },
});
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepHigherWrapperAEntry), {
  onEnter(args) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const threadId = Process.getCurrentThreadId();
    const entryRsp = this.context.rsp ? ptr(this.context.rsp) : null;
    const entryState = {
      wrapper: "A",
      caller: this.returnAddress ? this.returnAddress.toString() : "0x0",
      rsp: entryRsp ? entryRsp.toString() : "0x0",
      stackReturnAddress:
        entryRsp && !entryRsp.isNull() ? safeReadPointer(entryRsp).toString() : "0x0",
    };
    globalThis.higherWrapperEntryState.byThread[`A:${threadId}`] = entryState;
    rawSend({
      kind: "builder-message-prep-higher-wrapper-a-enter",
      threadId,
      arg0: args[0] ? ptr(args[0]).toString() : "0x0",
      arg1: args[1] ? ptr(args[1]).toString() : "0x0",
      arg2: args[2] ? ptr(args[2]).toString() : "0x0",
      arg3: args[3] ? ptr(args[3]).toString() : "0x0",
      entryCaller: entryState.caller,
      entryRsp: entryState.rsp,
      entryStackReturnAddress: entryState.stackReturnAddress,
    });
  },
  onLeave(retval) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    delete globalThis.higherWrapperEntryState.byThread[`A:${Process.getCurrentThreadId()}`];
    rawSend({
      kind: "builder-message-prep-higher-wrapper-a-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  },
});
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepHigherWrapperAReturnSite), {
  onEnter() {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const threadId = Process.getCurrentThreadId();
    const rbp = this.context.rbp ? ptr(this.context.rbp) : null;
    const callerSlot = rbp && !rbp.isNull() ? rbp.add(0x228) : null;
    const stackReturnAddress =
      callerSlot && !callerSlot.isNull() ? safeReadPointer(callerSlot) : null;
    const entryState = globalThis.higherWrapperEntryState.byThread[`A:${threadId}`] || null;
    rawSend({
      kind: "builder-message-prep-higher-wrapper-a-return-site",
      threadId,
      retval: this.context.rax ? ptr(this.context.rax).toString() : "0x0",
      rbx: this.context.rbx ? ptr(this.context.rbx).toString() : "0x0",
      rdi: this.context.rdi ? ptr(this.context.rdi).toString() : "0x0",
      rbp: rbp ? rbp.toString() : "0x0",
      callerSlot: callerSlot ? callerSlot.toString() : "0x0",
      stackReturnAddress: stackReturnAddress ? stackReturnAddress.toString() : "0x0",
      entryCaller: entryState ? entryState.caller : "0x0",
      entryRsp: entryState ? entryState.rsp : "0x0",
      entryStackReturnAddress: entryState ? entryState.stackReturnAddress : "0x0",
    });
    if (!!globalThis.upstreamWrapperReturnBypassState.enabled) {
      let slotRepair = null;
      if (
        callerSlot &&
        !callerSlot.isNull() &&
        entryState &&
        entryState.stackReturnAddress &&
        entryState.stackReturnAddress !== "0x0"
      ) {
        const before = stackReturnAddress ? stackReturnAddress.toString() : "0x0";
        const expected = entryState.stackReturnAddress;
        const repaired = before !== expected;
        if (repaired) {
          try {
            callerSlot.writePointer(ptr(expected));
          } catch (error) {
            slotRepair = {
              slotAddress: callerSlot.toString(),
              before,
              expected,
              repaired: false,
              error: String(error),
            };
          }
        }
        if (!slotRepair) {
          slotRepair = {
            slotAddress: callerSlot.toString(),
            before,
            expected,
            repaired,
            after: safeReadPointer(callerSlot).toString(),
          };
        }
      }
      this.context.rip = moduleBase.add(OFFSETS.builderMessagePrepHigherWrapperAFastForward);
      rawSend({
        kind: "builder-message-prep-higher-wrapper-a-fastforwarded",
        threadId,
        jumpTarget: this.context.rip.toString(),
        slotRepair,
      });
    }
  },
});
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepHigherWrapperARet), {
  onEnter() {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const threadId = Process.getCurrentThreadId();
    const rsp = this.context.rsp ? ptr(this.context.rsp) : null;
    const stackReturnAddress = rsp && !rsp.isNull() ? safeReadPointer(rsp) : null;
    const entryState = globalThis.higherWrapperEntryState.byThread[`A:${threadId}`] || null;
    let slotRepair = null;
    if (
      rsp &&
      !rsp.isNull() &&
      entryState &&
      entryState.stackReturnAddress &&
      entryState.stackReturnAddress !== "0x0"
    ) {
      const before = stackReturnAddress ? stackReturnAddress.toString() : "0x0";
      const expected = entryState.stackReturnAddress;
      const repaired = before !== expected;
      if (repaired) {
        try {
          rsp.writePointer(ptr(expected));
        } catch (error) {
          slotRepair = {
            slotAddress: rsp.toString(),
            before,
            expected,
            repaired: false,
            error: String(error),
          };
        }
      }
      if (!slotRepair) {
        slotRepair = {
          slotAddress: rsp.toString(),
          before,
          expected,
          repaired,
          after: safeReadPointer(rsp).toString(),
        };
      }
    }
    rawSend({
      kind: "builder-message-prep-higher-wrapper-a-ret",
      threadId,
      rsp: rsp ? rsp.toString() : "0x0",
      stackReturnAddress: stackReturnAddress ? stackReturnAddress.toString() : "0x0",
      entryCaller: entryState ? entryState.caller : "0x0",
      entryRsp: entryState ? entryState.rsp : "0x0",
      entryStackReturnAddress: entryState ? entryState.stackReturnAddress : "0x0",
      slotRepair,
    });
  },
});
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepHigherWrapperBEntry), {
  onEnter(args) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const threadId = Process.getCurrentThreadId();
    const entryRsp = this.context.rsp ? ptr(this.context.rsp) : null;
    const entryState = {
      wrapper: "B",
      caller: this.returnAddress ? this.returnAddress.toString() : "0x0",
      rsp: entryRsp ? entryRsp.toString() : "0x0",
      stackReturnAddress:
        entryRsp && !entryRsp.isNull() ? safeReadPointer(entryRsp).toString() : "0x0",
    };
    globalThis.higherWrapperEntryState.byThread[`B:${threadId}`] = entryState;
    rawSend({
      kind: "builder-message-prep-higher-wrapper-b-enter",
      threadId,
      arg0: args[0] ? ptr(args[0]).toString() : "0x0",
      arg1: args[1] ? ptr(args[1]).toString() : "0x0",
      arg2: args[2] ? ptr(args[2]).toString() : "0x0",
      entryCaller: entryState.caller,
      entryRsp: entryState.rsp,
      entryStackReturnAddress: entryState.stackReturnAddress,
    });
  },
  onLeave(retval) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    delete globalThis.higherWrapperEntryState.byThread[`B:${Process.getCurrentThreadId()}`];
    rawSend({
      kind: "builder-message-prep-higher-wrapper-b-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  },
});
Interceptor.attach(moduleBase.add(OFFSETS.builderMessagePrepHigherWrapperBReturnSite), {
  onEnter() {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const threadId = Process.getCurrentThreadId();
    const rbp = this.context.rbp ? ptr(this.context.rbp) : null;
    const callerSlot = rbp && !rbp.isNull() ? rbp.add(0x448) : null;
    const stackReturnAddress =
      callerSlot && !callerSlot.isNull() ? safeReadPointer(callerSlot) : null;
    const entryState = globalThis.higherWrapperEntryState.byThread[`B:${threadId}`] || null;
    rawSend({
      kind: "builder-message-prep-higher-wrapper-b-return-site",
      threadId,
      retval: this.context.rax ? ptr(this.context.rax).toString() : "0x0",
      r13: this.context.r13 ? ptr(this.context.r13).toString() : "0x0",
      rbp: rbp ? rbp.toString() : "0x0",
      callerSlot: callerSlot ? callerSlot.toString() : "0x0",
      stackReturnAddress: stackReturnAddress ? stackReturnAddress.toString() : "0x0",
      entryCaller: entryState ? entryState.caller : "0x0",
      entryRsp: entryState ? entryState.rsp : "0x0",
      entryStackReturnAddress: entryState ? entryState.stackReturnAddress : "0x0",
    });
  },
});
Interceptor.attach(moduleBase.add(OFFSETS.builderTailFormat), {
  onEnter() {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const threadId = Process.getCurrentThreadId();
    const entryRsp = this.context.rsp ? ptr(this.context.rsp) : null;
    const entryState = {
      caller: this.returnAddress ? this.returnAddress.toString() : "0x0",
      rsp: entryRsp ? entryRsp.toString() : "0x0",
      stackReturnAddress:
        entryRsp && !entryRsp.isNull() ? safeReadPointer(entryRsp).toString() : "0x0",
    };
    globalThis.builderTailEntryState.byThread[String(threadId)] = entryState;
    rawSend({
      kind: "builder-tail-entry-state",
      threadId,
      entryCaller: entryState.caller,
      entryRsp: entryState.rsp,
      entryStackReturnAddress: entryState.stackReturnAddress,
    });
  },
  onLeave() {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    delete globalThis.builderTailEntryState.byThread[String(Process.getCurrentThreadId())];
  },
});
attachBuilderStageHook(OFFSETS.builderTailFormat, "builder-tail-format-enter", (args, meta) => ({
  arg0: formatHookArg(args, 0),
  arg1: formatHookArg(args, 1),
  arg2: formatHookArg(args, 2),
  caller: meta.returnAddress.toString(),
}));
attachBuilderStageHook(OFFSETS.builderTailA, "builder-tail-a-enter", (args, meta) => ({
  arg0: formatHookArg(args, 0),
  arg1: formatHookArg(args, 1),
  arg2: formatHookArg(args, 2),
  caller: meta.returnAddress.toString(),
}));
attachBuilderStageHook(OFFSETS.builderTailB, "builder-tail-b-enter", (args, meta) => ({
  arg0: formatHookArg(args, 0),
  arg1: formatHookArg(args, 1),
  arg2: formatHookArg(args, 2),
  caller: meta.returnAddress.toString(),
}));
attachBuilderStageHook(OFFSETS.builderTailC, "builder-tail-c-enter", (args, meta) => ({
  arg0: formatHookArg(args, 0),
  arg1: formatHookArg(args, 1),
  arg2: formatHookArg(args, 2),
  caller: meta.returnAddress.toString(),
}));
attachBuilderStageHook(OFFSETS.builderTailD, "builder-tail-d-enter", (args, meta) => ({
  arg0: formatHookArg(args, 0),
  arg1: formatHookArg(args, 1),
  arg2: formatHookArg(args, 2),
  caller: meta.returnAddress.toString(),
}));

Interceptor.attach(moduleBase.add(OFFSETS.cloneTail), {
  onEnter: guardHook("clone-tail", "enter", function (args) {
    if (!shouldTraceDetachedThread()) {
      return;
    }
    globalThis.tailCloneTraceCount = (globalThis.tailCloneTraceCount || 0) + 1;
    if (globalThis.tailCloneTraceCount > 12) {
      return;
    }
    const dst = ptr(args[0]);
    const src = ptr(args[1]);
    rawSend({
      kind: "tail-clone-enter",
      threadId: Process.getCurrentThreadId(),
      count: globalThis.tailCloneTraceCount,
      caller: this.returnAddress.toString(),
      dst: dst.toString(),
      src: src.toString(),
      sourceFields: inspectTailRegion(src),
    });
  }),
  onLeave: guardHook("clone-tail", "leave", function (retval) {
    if (!shouldTraceDetachedThread()) {
      return;
    }
    if ((globalThis.tailCloneTraceCount || 0) > 12) {
      return;
    }
    rawSend({
      kind: "tail-clone-leave",
      threadId: Process.getCurrentThreadId(),
      count: globalThis.tailCloneTraceCount || 0,
      retval: retval.toString(),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.asyncWorkerRun), {
  onEnter: guardHook("async-worker-run", "enter", function (args) {
    const worker = ptr(args[0]);
    this.traceLegacyWorker = shouldTraceDetachedWorker(worker);
    if (!this.traceLegacyWorker) {
      return;
    }
    rememberDetachedWorker(worker, "legacy-async-worker-run");
    rawSend({
      kind: "legacy-async-worker-run-enter",
      threadId: Process.getCurrentThreadId(),
      worker: worker.toString(),
      modeFlag: safeReadU8(worker.add(0x110)),
      tailFields: inspectTailRegion(worker.add(0x28)),
      caller: this.returnAddress.toString(),
    });
  }),
  onLeave: guardHook("async-worker-run", "leave", function (retval) {
    if (!this.traceLegacyWorker) {
      return;
    }
    rawSend({
      kind: "legacy-async-worker-run-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.queueSubmit), {
  onEnter: guardHook("queue-submit", "enter", function (args) {
    if (!shouldTraceDetachedThread()) {
      return;
    }
    const workerSlot = ptr(args[1]);
    const worker = safeReadPointer(workerSlot);
    if (!worker.isNull()) {
      rememberDetachedWorker(worker, "queue-submit");
    }
    rawSend({
      kind: "queue-submit-enter",
      threadId: Process.getCurrentThreadId(),
      queueContext: ptr(args[0]).toString(),
      workerSlot: workerSlot.toString(),
      worker: worker.toString(),
      modeFlag: worker.isNull() ? null : safeReadU8(worker.add(0x110)),
      statusBlock: worker.isNull() ? null : inspectAsyncStatus(worker.add(0x110)),
      tailFields: worker.isNull() ? null : inspectTailRegion(worker.add(0x28)),
      caller: this.returnAddress.toString(),
    });
  }),
  onLeave: guardHook("queue-submit", "leave", function (retval) {
    if (!shouldTraceDetachedThread()) {
      return;
    }
    rawSend({
      kind: "queue-submit-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.queueEnvelopeRun), {
  onEnter: guardHook("queue-envelope-run", "enter", function (args) {
    this.traceQueueEnvelope = Object.keys(globalThis.detachedTraceState.workers).length > 0;
    if (!this.traceQueueEnvelope) {
      return;
    }
    const envelope = ptr(args[0]);
    const wrapped = safeReadPointer(envelope.add(0x48));
    rawSend({
      kind: "queue-envelope-run-enter",
      threadId: Process.getCurrentThreadId(),
      envelope: envelope.toString(),
      wrapped: wrapped.toString(),
      envelopeFields: inspectPointerFields(envelope, [0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48]),
      wrappedFields: wrapped.isNull()
        ? null
        : inspectPointerFields(wrapped, [0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48]),
      caller: this.returnAddress.toString(),
    });
  }),
  onLeave: guardHook("queue-envelope-run", "leave", function (retval) {
    if (!this.traceQueueEnvelope) {
      return;
    }
    rawSend({
      kind: "queue-envelope-run-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.queueEnvelopeInvoke), {
  onEnter: guardHook("queue-envelope-invoke", "enter", function (args) {
    this.traceQueueInvoke = Object.keys(globalThis.detachedTraceState.workers).length > 0;
    if (!this.traceQueueInvoke) {
      return;
    }
    const wrappedSlot = ptr(args[1]);
    const wrapped = safeReadPointer(wrappedSlot);
    rawSend({
      kind: "queue-envelope-invoke-enter",
      threadId: Process.getCurrentThreadId(),
      envelopeState: ptr(args[0]).toString(),
      wrappedSlot: wrappedSlot.toString(),
      wrapped: wrapped.toString(),
      dispatchContext: ptr(args[2]).toString(),
      wrappedFields: wrapped.isNull()
        ? null
        : inspectPointerFields(wrapped, [0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48]),
      caller: this.returnAddress.toString(),
    });
  }),
  onLeave: guardHook("queue-envelope-invoke", "leave", function (retval) {
    if (!this.traceQueueInvoke) {
      return;
    }
    rawSend({
      kind: "queue-envelope-invoke-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.tailErrorHelper), {
  onEnter: guardHook("tail-error-helper", "enter", function (args) {
    this.traceTailError =
      (globalThis.swapState && globalThis.swapState.enabled) ||
      Object.keys(globalThis.detachedTraceState.workers).length > 0;
    if (!this.traceTailError) {
      return;
    }
    const tail = ptr(args[0]);
    const originalHead = safeReadPointer(tail);
    if (globalThis.tailErrorSentinel === null) {
      globalThis.tailErrorSentinel = Memory.alloc(0x10);
      globalThis.tailErrorSentinel.writeByteArray(new Uint8Array(0x10));
      globalThis.tailErrorSentinel.writeU8(1);
    }
    tail.writePointer(globalThis.tailErrorSentinel);
    rawSend({
      kind: "tail-error-helper-enter",
      threadId: Process.getCurrentThreadId(),
      caller: this.returnAddress.toString(),
      tail: tail.toString(),
      param2: ptr(args[1]).toString(),
      param3: ptr(args[2]).toString(),
      param4: ptr(args[3]).toString(),
      headFields: inspectPointerFields(tail, [0x0, 0x8, 0x88, 0xd8, 0xe0]),
      tailFields: inspectTailRegion(tail),
      statusBlock: inspectAsyncStatus(tail.add(0xe8)),
      originalHead: originalHead.toString(),
      sanitizedHead: globalThis.tailErrorSentinel.toString(),
    });
  }),
  onLeave: guardHook("tail-error-helper", "leave", function (retval) {
    if (!this.traceTailError) {
      return;
    }
    rawSend({
      kind: "tail-error-helper-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.entryBAsyncWorkerRun), {
  onEnter: guardHook("entryb-worker-run", "enter", function (args) {
    const worker = ptr(args[0]);
    this.traceEntryBWorker = shouldTraceDetachedWorker(worker);
    if (!this.traceEntryBWorker) {
      return;
    }
    rememberDetachedWorker(worker, "entryb-worker-run");
    rawSend({
      kind: "entryb-worker-run-enter",
      threadId: Process.getCurrentThreadId(),
      worker: worker.toString(),
      modeFlag: safeReadU8(worker.add(0x110)),
      statusBlock: inspectAsyncStatus(worker.add(0x110)),
      tailFields: inspectTailRegion(worker.add(0x28)),
      caller: this.returnAddress.toString(),
    });
  }),
  onLeave: guardHook("entryb-worker-run", "leave", function (retval) {
    if (!this.traceEntryBWorker) {
      return;
    }
    rawSend({
      kind: "entryb-worker-run-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.tailConsume), {
  onEnter: guardHook("tail-consume", "enter", function (args) {
    const tail = ptr(args[0]);
    this.traceTailConsume = shouldTraceDetachedTail(tail);
    if (!this.traceTailConsume) {
      return;
    }
    rawSend({
      kind: "tail-consume-enter",
      threadId: Process.getCurrentThreadId(),
      tail: tail.toString(),
      statusBlock: inspectAsyncStatus(tail.add(0xe8)),
      tailFields: inspectTailRegion(tail),
      caller: this.returnAddress.toString(),
    });
  }),
  onLeave: guardHook("tail-consume", "leave", function (retval) {
    if (!this.traceTailConsume) {
      return;
    }
    rawSend({
      kind: "tail-consume-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
    });
  }),
});
attachBuilderStageHook(OFFSETS.builderWorkerFieldA, "builder-worker-field-a-enter", (args) => ({
  worker: ptr(args[0]).toString(),
  value: Number(args[1]),
}));
attachBuilderStageHook(OFFSETS.builderWorkerFieldB, "builder-worker-field-b-enter", (args) => ({
  worker: ptr(args[0]).toString(),
  value: Number(args[1]),
}));

Interceptor.attach(moduleBase.add(OFFSETS.helperParseHitCast), {
  onEnter: guardHook("helper-parse-hit-cast", "enter", function (args) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    this.outPair = ptr(args[0]);
    this.inputPair = ptr(args[1]);
    rawSend({
      kind: "helper-parse-hit-cast-enter",
      threadId: Process.getCurrentThreadId(),
      outPair: this.outPair.toString(),
      inputPair: this.inputPair.toString(),
      inputPairView: safeReadRcPair(this.inputPair),
      inputPairPromiseObject:
        safeReadRcPair(this.inputPair).object !== "0x0" && !safeReadRcPair(this.inputPair).error
          ? inspectFinalizePromiseObject(safeReadRcPair(this.inputPair).object)
          : null,
      inputPointers: inspectPointerFields(this.inputPair, [0x0, 0x8, 0x10, 0x18]),
    });
  }),
  onLeave: guardHook("helper-parse-hit-cast", "leave", function (retval) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const outPair = safeReadRcPair(this.outPair);
    rawSend({
      kind: "helper-parse-hit-cast-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval.toString(),
      outPair,
      outPairPromiseObject:
        outPair.object !== "0x0" && !outPair.error
          ? inspectFinalizePromiseObject(outPair.object)
          : null,
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.resolveTypeNameHelper), {
  onEnter: guardHook("resolve-type-name-helper", "enter", function (args) {
    if (!shouldTraceFinalizeThread()) {
      return;
    }
    this.arg0 = ptr(args[0]);
    this.arg1 = ptr(args[1]);
    rawSend({
      kind: "resolve-type-name-helper-enter",
      threadId: Process.getCurrentThreadId(),
      arg0: this.arg0.toString(),
      arg1: this.arg1.toString(),
      caller: this.returnAddress.toString(),
      callerInfo: describeAddress(this.returnAddress),
      arg0Hex: readHex(this.arg0, 0x20),
    });
  }),
  onLeave: guardHook("resolve-type-name-helper", "leave", function (retval) {
    if (!shouldTraceFinalizeThread()) {
      return;
    }
    const value = retval ? ptr(retval) : null;
    rawSend({
      kind: "resolve-type-name-helper-leave",
      threadId: Process.getCurrentThreadId(),
      retval: value ? value.toString() : null,
      text: value && !value.isNull() ? safeReadCString(value) : null,
      textUtf16: value && !value.isNull() ? safeReadUtf16(value, 32) : null,
      retvalHex: value && !value.isNull() ? readHex(value, 0x40) : null,
      caller: this.returnAddress ? this.returnAddress.toString() : null,
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.helperTableInsert), {
  onEnter: guardHook("helper-table-insert", "enter", function (args) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const pair = safeReadRcPair(args[2]);
    const key = readSmallString(args[3]);
    if (pair.object !== "0x0" && !pair.error) {
      rememberHelperNodeObject(Process.getCurrentThreadId(), pair.object, key);
    }
    rawSend({
      kind: "helper-table-insert",
      threadId: Process.getCurrentThreadId(),
      manager: ptr(args[1]).toString(),
      pair,
      key,
      pairObject: pair.object === "0x0" || pair.error ? null : inspectHelperNodeObject(pair.object),
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.helperWalk), {
  onEnter: guardHook("helper-walk", "enter", function (args) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    rawSend({
      kind: "helper-walk-enter",
      threadId: Process.getCurrentThreadId(),
      owner: ptr(args[0]).toString(),
      key: readSmallString(args[1]),
    });
  }),
  onLeave: guardHook("helper-walk", "leave", function (retval) {
    if (!shouldTraceDetachedFocusedPath()) {
      return;
    }
    const helperNode = getHelperNodeForThread(Process.getCurrentThreadId());
    rawSend({
      kind: "helper-walk-leave",
      threadId: Process.getCurrentThreadId(),
      retval: retval ? retval.toString() : null,
      helperNode:
        helperNode && helperNode.object
          ? inspectHelperNodeObject(helperNode.object)
          : null,
    });
  }),
});

Interceptor.attach(moduleBase.add(OFFSETS.workerFinalize), {
  onEnter: guardHook("worker-finalize", "enter", function (args) {
    if (!shouldTraceFinalizeThread()) {
      return;
    }
    this.out = args[1];
    const threadId = Process.getCurrentThreadId();
    const helperNode = getHelperNodeForThread(threadId);
    let overrideApplied = null;
    if (
      globalThis.finalizeOverride &&
      globalThis.finalizeOverride.slot &&
      globalThis.finalizeOverride.slot !== "keep"
    ) {
      let replacementPair = null;
      if (globalThis.finalizeOverride.slot === "synthetic") {
        if (globalThis.swapState && globalThis.swapState.mode === "synthetic") {
          let synthetic = globalThis.syntheticPrepared;
          if (!synthetic) {
            synthetic = buildSyntheticGoodPair(
              globalThis.swapState.conversationId,
              globalThis.swapState.selfUsername
            );
          }
          if (synthetic) {
            replacementPair = {
              object: synthetic.object.toString(),
              ref: synthetic.base.toString(),
            };
          }
        }
      } else if (helperNode && helperNode.object) {
        replacementPair = readHelperNodeSlotPair(helperNode.object, globalThis.finalizeOverride.slot);
      }
      if (replacementPair && replacementPair.object !== "0x0" && !replacementPair.error) {
        const beforePair = safeReadRcPair(args[2]);
        ptr(args[2]).writePointer(ptr(replacementPair.object));
        ptr(args[2]).add(Process.pointerSize).writePointer(ptr(replacementPair.ref));
        overrideApplied = {
          slot: globalThis.finalizeOverride.slot,
          before: beforePair,
          after: safeReadRcPair(args[2]),
        };
      }
    }
    const sourcePair = safeReadRcPair(args[2]);
    rawSend({
      kind: "worker-finalize-enter",
      threadId,
      out: ptr(args[1]).toString(),
      sourcePair,
      helperNode:
        helperNode && helperNode.object
          ? inspectHelperNodeObject(helperNode.object)
          : null,
      overrideApplied,
      sourceObject: sourcePair.object === "0x0" || sourcePair.error ? null : inspectFinalizeSourceObject(sourcePair.object),
      sourcePromiseObject:
        sourcePair.object === "0x0" || sourcePair.error
          ? null
          : inspectFinalizePromiseObject(sourcePair.object),
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

  if (globalThis.swapState.mode === "synthetic" && globalThis.syntheticPrepared) {
    const embeddedState = prepareSyntheticEmbeddedRequestRegion(
      globalThis.syntheticPrepared,
      conversationId,
      body,
      msgsource,
      requestSelfUsername,
      requestNickname,
      requestAlias
    );
    rawSend({
      kind: "synthetic-embedded-request-prepared",
      threadId: Process.getCurrentThreadId(),
      object: globalThis.syntheticPrepared.object.toString(),
      templateRegion: globalThis.syntheticPrepared.templateRegion.toString(),
      embeddedState,
    });
  }

  writeSmallString(outer.add(0x38), conversationId, false);
  writeSmallString(outer.add(0x78), conversationId, false);
  writeSmallString(outer.add(0xc0), body, false);
  writeSmallString(outer.add(0xe0), msgsource, false);
  applyKnownSelfContextToRequestRegion(outer.add(0x08), requestSelfUsername, requestNickname, requestAlias);

  if (globalThis.swapState.mode === "synthetic" && globalThis.syntheticPrepared) {
    const bodyPatch = patchSourceBodyField(globalThis.syntheticPrepared.object, body);
    rawSend({
      kind: "synthetic-source-body-patched",
      threadId: Process.getCurrentThreadId(),
      object: globalThis.syntheticPrepared.object.toString(),
      body,
      bodyPatch,
    });
  }

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
  globalThis.lastDetachedRequest = {
    conversationId,
    body,
    msgsource,
    requestSelfUsername,
    requestNickname,
    requestAlias,
  };
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

function scheduleRunOnThreadTest(threadId, label) {
  globalThis.detachedStatus = {
    status: "pending",
    requestedThreadId: threadId,
    entry: "testrunonthread",
    label: label || null,
  };

  Process.runOnThread(threadId, function () {
    globalThis.detachedStatus = {
      status: "running",
      requestedThreadId: threadId,
      actualThreadId: Process.getCurrentThreadId(),
      entry: "testrunonthread",
      label: label || null,
    };
    rawSend({
      kind: "testrunonthread-enter",
      threadId: Process.getCurrentThreadId(),
      requestedThreadId: threadId,
      label: label || null,
    });
    globalThis.detachedStatus = {
      status: "done",
      requestedThreadId: threadId,
      actualThreadId: Process.getCurrentThreadId(),
      entry: "testrunonthread",
      label: label || null,
    };
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
    globalThis.capturedPrepared = null;
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
    deepTrace,
    directSchedule
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
    globalThis.capturedPrepared = null;
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
      directSchedule: !!directSchedule,
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
    if (globalThis.capturedTemplateBlock === null) {
      throw new Error("captured template not available");
    }
    const prepared = cloneCapturedTemplate(conversationId);
    globalThis.capturedPrepared = prepared;
    globalThis.swapState = {
      enabled: true,
      mode: "captured",
      threadId,
      conversationId,
      deepTrace: false,
      focusedTrace: false,
      selfUsername: null,
      liveWrapperAddress: null,
      preparedPairAddress: null,
      preparedWrapper: prepared.base.toString(),
      preparedObject: prepared.object.toString(),
      preparedTemplateRegion: prepared.object.add(0xd8).toString(),
    };
    rawSend({
      kind: "captured-template-prepared",
      threadId: Process.getCurrentThreadId(),
      preparedWrapper: prepared.base.toString(),
      preparedObject: prepared.object.toString(),
      preparedTemplateRegion: prepared.object.add(0xd8).toString(),
    });
    return globalThis.swapState;
  },
  setliveclone(threadId, conversationId, wrapperAddress) {
    const prepared = cloneTemplateFromLiveWrapper(wrapperAddress, conversationId);
    globalThis.liveCloneTemplateBlock = ptr(prepared.base).readByteArray(TEMPLATE_BLOCK_SIZE);
    globalThis.liveCloneTailTemplateBlock = readTailTemplateFromWrapper(wrapperAddress);
    globalThis.swapState = {
      enabled: true,
      mode: "liveclone",
      threadId,
      conversationId,
      deepTrace: false,
      focusedTrace: false,
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
    globalThis.liveCloneTailTemplateBlock = readTailTemplateFromWrapper(wrapperAddress);
    globalThis.swapState = {
      enabled: true,
      mode: "liveraw",
      threadId,
      conversationId,
      deepTrace: false,
      focusedTrace: false,
      selfUsername: null,
      liveWrapperAddress: wrapperAddress,
      preparedPairAddress: null,
      preparedWrapper: wrapperAddress,
      preparedObject: ptr(wrapperAddress).add(TEMPLATE_USER_OFFSET).toString(),
      preparedTemplateRegion: ptr(wrapperAddress).add(TEMPLATE_USER_OFFSET).add(0xd8).toString(),
    };
    return globalThis.swapState;
  },
  preparesynthetic(threadId, conversationId, selfUsername, embedSeedMode) {
    globalThis.syntheticEmbedSeedMode = embedSeedMode || "seed-template";
    const prepared = buildSyntheticGoodPair(conversationId, selfUsername);
    globalThis.syntheticPrepared = prepared;
    globalThis.swapState = {
      enabled: true,
      mode: "synthetic",
      threadId,
      conversationId,
      deepTrace: false,
      focusedTrace: false,
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
      embedSeedMode: globalThis.syntheticEmbedSeedMode,
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
      focusedTrace: false,
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
    globalThis.helperNodeState = {
      byThread: Object.create(null),
    };
    globalThis.builderTailEntryState = {
      byThread: Object.create(null),
    };
    globalThis.outerWrapperEntryState = {
      byThread: Object.create(null),
    };
    globalThis.higherWrapperEntryState = {
      byThread: Object.create(null),
    };
    globalThis.finalizeOverride = {
      slot: "keep",
    };
    globalThis.loopFinalizeBindRestore = {
      sourcePair: "keep",
    };
    globalThis.loopFinalizeState = {
      byThread: Object.create(null),
    };
    globalThis.builderReturnSlotRepairState = {
      enabled: false,
    };
    globalThis.loopFinalizeCastBypassState = {
      enabled: false,
      installed: false,
      target: null,
    };
    globalThis.loopFinalizeAwaitBypassState = {
      enabled: false,
      installed: false,
      awaitCheckTarget: null,
      awaitResultSlotTarget: null,
      nativeCheckBudget: 3,
      nativeCheckCountByThread: Object.create(null),
      passThroughResultSlotByThread: Object.create(null),
    };
    globalThis.outerWrapperAwaitBypassState = {
      enabled: false,
    };
    globalThis.upstreamWrapperReturnBypassState = {
      enabled: false,
    };
    globalThis.postFinalizeResolveBypassState = {
      enabled: false,
      installed: false,
      target: null,
    };
    globalThis.processExitProbeState = {
      enabled: false,
      installed: false,
      targets: [],
    };
    globalThis.latePairCopyPatchState = {
      enabled: false,
    };
    globalThis.latePairCopyRequestFieldPatchState = {
      enabled: false,
    };
    globalThis.watsonFailFastBypassState = {
      enabled: false,
    };
    globalThis.lastDetachedRequest = null;
    return globalThis.swapState;
  },
  setdeeptrace(enabled) {
    globalThis.swapState.deepTrace = !!enabled;
    return globalThis.swapState;
  },
  setfocusedtrace(enabled) {
    globalThis.swapState.focusedTrace = !!enabled;
    return globalThis.swapState;
  },
  setfinalizeoverrideslot(slotName) {
    globalThis.finalizeOverride = {
      slot: slotName || "keep",
    };
    return globalThis.finalizeOverride;
  },
  setlatepaircopyswap(enabled) {
    globalThis.latePairCopySwapState = {
      enabled: !!enabled,
    };
    return globalThis.latePairCopySwapState;
  },
  setlatepaircopypatch(enabled) {
    globalThis.latePairCopyPatchState = {
      enabled: !!enabled,
    };
    return globalThis.latePairCopyPatchState;
  },
  setlatepaircopyrequestfieldpatch(enabled) {
    globalThis.latePairCopyRequestFieldPatchState = {
      enabled: !!enabled,
    };
    return globalThis.latePairCopyRequestFieldPatchState;
  },
  setcrashstubbypass(enabled) {
    if (enabled) {
      return ensureCrashStubBypass();
    }
    return globalThis.crashStubBypassState;
  },
  setwatsonfailfastbypass(enabled) {
    if (enabled) {
      return ensureWatsonFailFastBypass();
    }
    return globalThis.watsonFailFastBypassState;
  },
  setroamservercrashprobe(enabled) {
    if (enabled) {
      return ensureRoamServerCrashProbe();
    }
    return globalThis.roamServerCrashProbeState;
  },
  setroamservercrashbypass(enabled) {
    if (enabled) {
      return ensureRoamServerCrashBypass();
    }
    return globalThis.roamServerCrashBypassState;
  },
  setloopfinalizesourceoverride(modeName) {
    globalThis.loopFinalizeOverride = {
      sourcePair: modeName || "keep",
    };
    return globalThis.loopFinalizeOverride;
  },
  setloopfinalizebindrestore(modeName) {
    globalThis.loopFinalizeBindRestore = {
      sourcePair: modeName || "keep",
    };
    return globalThis.loopFinalizeBindRestore;
  },
  setloopfinalizecastbypass(enabled) {
    if (enabled) {
      return ensureLoopFinalizeCastBypass();
    }
    return globalThis.loopFinalizeCastBypassState;
  },
  setloopfinalizeawaitbypass(enabled) {
    if (enabled) {
      return ensureLoopFinalizeAwaitBypass();
    }
    return globalThis.loopFinalizeAwaitBypassState;
  },
  setouterwrapperawaitbypass(enabled) {
    globalThis.outerWrapperAwaitBypassState = {
      enabled: !!enabled,
    };
    return globalThis.outerWrapperAwaitBypassState;
  },
  setupstreamwrapperreturnbypass(enabled) {
    globalThis.upstreamWrapperReturnBypassState = {
      enabled: !!enabled,
    };
    return globalThis.upstreamWrapperReturnBypassState;
  },
  setpostfinalizeresolvebypass(enabled) {
    if (enabled) {
      return ensurePostFinalizeResolveBypass();
    }
    return globalThis.postFinalizeResolveBypassState;
  },
  setbuilderreturnslotrepair(enabled) {
    globalThis.builderReturnSlotRepairState = {
      enabled: !!enabled,
    };
    return globalThis.builderReturnSlotRepairState;
  },
  setprocessexitprobe(enabled) {
    if (enabled) {
      return ensureProcessExitProbe();
    }
    return globalThis.processExitProbeState;
  },
  testrunonthread(threadId, label) {
    return scheduleRunOnThreadTest(threadId, label);
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
  probethreadcontext(threadId, conversationId) {
    return probeThreadContext(threadId, conversationId);
  },
  setcontextwatch(conversationId, maxHits) {
    globalThis.contextWatchState = {
      enabled: true,
      conversationId: conversationId || null,
      maxHits: Number(maxHits || 0),
      hits: [],
      reentrant: false,
      pendingByThread: Object.create(null),
    };
    return globalThis.contextWatchState;
  },
  getcontextwatch() {
    return globalThis.contextWatchState;
  },
  clearcontextwatch() {
    globalThis.contextWatchState = {
      enabled: false,
      conversationId: null,
      maxHits: 0,
      hits: [],
      reentrant: false,
      pendingByThread: Object.create(null),
    };
    return globalThis.contextWatchState;
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


def list_process_thread_ids(pid: int) -> list[int]:
    command = rf"""
    Get-Process -Id {pid} |
      Select-Object -ExpandProperty Threads |
      Select-Object -ExpandProperty Id
    """
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return [int(line.strip()) for line in completed.stdout.splitlines() if line.strip()]


def _extract_text_field(field: object) -> str | None:
    if isinstance(field, dict):
        text = field.get("text")
        if isinstance(text, str) and text:
            return text
    return None


def _extract_object_address(pair: object) -> str | None:
    if isinstance(pair, dict):
        obj = pair.get("object")
        if isinstance(obj, str) and obj != "0x0":
            return obj
    return None


def choose_context_watch_thread(watch_state: dict, conversation_id: str | None) -> dict | None:
    candidates: list[dict] = []

    def add_candidate(entry: dict, source: str) -> None:
        normalized_talker = _extract_text_field(entry.get("normalizedTalker"))
        copied_talker = _extract_text_field(entry.get("copiedTalker"))
        normalized_object = _extract_object_address(entry.get("normalizedPair"))
        copied_object = _extract_object_address(entry.get("copiedPair"))
        thread_id = entry.get("observedThreadId") or entry.get("threadId")
        if not thread_id:
            return
        score = 0
        reason_parts: list[str] = []
        if conversation_id and normalized_talker == conversation_id:
            score += 100
            reason_parts.append("normalized talker matched target conversation")
        if conversation_id and copied_talker == conversation_id:
            score += 80
            reason_parts.append("copied talker matched target conversation")
        if normalized_object:
            score += 40
            reason_parts.append("normalized pair object present")
        if copied_object:
            score += 20
            reason_parts.append("copied pair object present")
        if source == "pending":
            score += 5
            reason_parts.append("pending live pair-copy activity")
        if score == 0:
            return
        candidates.append(
            {
                "threadId": int(thread_id),
                "score": score,
                "source": source,
                "reason": ", ".join(reason_parts),
                "copiedTalker": copied_talker,
                "normalizedTalker": normalized_talker,
                "copiedObject": copied_object,
                "normalizedObject": normalized_object,
                "entry": entry,
            }
        )

    for entry in watch_state.get("hits", []):
        if isinstance(entry, dict):
            add_candidate(entry, "hit")
    pending_by_thread = watch_state.get("pendingByThread", {})
    if isinstance(pending_by_thread, dict):
        for entry in pending_by_thread.values():
            if isinstance(entry, dict):
                add_candidate(entry, "pending")

    if not candidates:
        return None

    candidates.sort(
        key=lambda item: (
            -item["score"],
            0 if item["source"] == "hit" else 1,
            item["threadId"],
        )
    )
    return candidates[0]


def main() -> int:
  parser = argparse.ArgumentParser(description="Attempt a detached Weixin text send from a live request template.")
  parser.add_argument("--pid", type=int, help="Target Weixin PID. Defaults to live Weixin.dll host.")
  parser.add_argument("--template-region", help="Pointer to a live request region captured from 15b20b0.")
  parser.add_argument("--conversation-id", help="Target conversation id.")
  parser.add_argument("--body", help="Detached body text.")
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
      "--direct-auto-detach-after-capture",
      action="store_true",
      help=(
          "Bypass the internal setImmediate hop and call scheduleDetached directly "
          "from the capture path. Only applies with --auto-detach-after-capture."
      ),
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
      "--post-run-wait-ms",
      type=int,
      default=0,
      help=(
          "Keep the Frida script/session alive for this long after detached completion. "
          "Useful when later async work still depends on Frida-allocated buffers."
      ),
  )
  parser.add_argument(
      "--deep-trace",
      action="store_true",
      help="Temporarily re-enable the hotter detached entryB trace hooks for debugging.",
  )
  parser.add_argument(
      "--focused-trace",
      action="store_true",
      help=(
          "Enable a narrower post-pair-copy trace around the late normalize/build loop "
          "without turning on the full deep detached trace set."
      ),
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
      "--synthetic-embed-seed-mode",
      choices=("seed-template", "patch-only", "leave-original"),
      default="seed-template",
      help=(
          "How to initialize the synthetic good-source object's embedded +0xd8 region: "
          "either memcpy the detached seed template, preserve the constructor-built "
          "header and patch only known fields, or leave the embedded region untouched."
      ),
  )
  parser.add_argument(
      "--override-finalize-source-pair-slot",
      choices=("keep", "slot0", "slot1", "slot2", "synthetic"),
      default="keep",
      help=(
          "For late cold-start experiments, override workerFinalize's input pair "
          "with one of the helper node's pair slots or the prepared synthetic pair."
      ),
  )
  parser.add_argument(
      "--disable-late-pair-copy-swap",
      action="store_true",
      help=(
          "Disable the extra synthetic replacement on later pairCopyMaybe callsites "
          "and keep only the initial worker-entry swap."
      ),
  )
  parser.add_argument(
      "--enable-late-pair-copy-field-patch",
      action="store_true",
      help=(
          "At later pairCopyMaybe callsites, preserve the copied donor object and patch "
          "only the known source/request string fields from the prepared synthetic source."
      ),
  )
  parser.add_argument(
      "--enable-late-pair-copy-request-field-patch",
      action="store_true",
      help=(
          "When late pair-copy field patching is enabled, also patch the copied donor's "
          "embedded +0xd8 request-region string fields (self/talker/body/msgsource/self-context) "
          "from the detached send request while preserving the donor's manager/container state."
      ),
  )
  parser.add_argument(
      "--bypass-crash-stub",
      action="store_true",
      help=(
          "Replace the Weixin.dll intentional crash stub at +0xf16b0 with a no-op so "
          "cold-start runs can continue past internal abort checks."
      ),
  )
  parser.add_argument(
      "--bypass-watson-failfast",
      action="store_true",
      help=(
          "Replace Weixin.dll FUN_1864c96c8, which calls _invoke_watson, with a no-op "
          "so cold-start runs can continue past internal failfast asserts."
      ),
  )
  parser.add_argument(
      "--probe-roam-crash-site",
      action="store_true",
      help=(
          "Watch for roam_server.dll loading and hook the later crash site at +0x364339 "
          "to log bytes/backtrace when it executes."
      ),
  )
  parser.add_argument(
      "--bypass-roam-crash-site",
      action="store_true",
      help=(
          "Patch roam_server.dll +0x364339 from int29h to NOP NOP so cold-start runs can "
          "continue past that fast-fail site."
      ),
  )
  parser.add_argument(
      "--override-loop-finalize-source-pair",
      choices=("keep", "saved", "synthetic"),
      default="keep",
      help=(
          "For cold-start finalize experiments, replace FUN_180968840's source pair "
          "argument with the last saved live source pair or the prepared synthetic pair."
      ),
  )
  parser.add_argument(
      "--restore-loop-finalize-bind-source-pair",
      choices=("keep", "saved", "synthetic"),
      default="keep",
      help=(
          "For cold-start finalize experiments, restore FUN_182ab2fc0's input pair "
          "from the last valid loop source pair on this thread or from the prepared synthetic pair."
      ),
  )
  parser.add_argument(
      "--force-loop-finalize-cast-bypass",
      action="store_true",
      help=(
          "Replace FUN_180968840 with a direct promise-result unwrap that skips the "
          "late RTTI/type-name cast check."
      ),
  )
  parser.add_argument(
      "--force-loop-finalize-await-bypass",
      action="store_true",
      help=(
          "Bypass FUN_180316b50/FUN_180319290 during the focused detached finalize path "
          "and directly treat the promise as already resolved."
      ),
  )
  parser.add_argument(
      "--force-post-finalize-resolve-bypass",
      action="store_true",
      help=(
          "Skip the late FUN_1833bafa0 promise-resolution wrapper that runs after "
          "FUN_180968840 returns in the focused detached path."
      ),
  )
  parser.add_argument(
      "--repair-builder-return-slot",
      action="store_true",
      help=(
          "If FUN_18332df80's saved caller return slot at [RBP+0x2a8] is corrupted "
          "during the focused detached path, restore it to the entry value before unwind."
      ),
  )
  parser.add_argument(
      "--force-outer-wrapper-await-bypass",
      action="store_true",
      help=(
          "At FUN_181618040's await-return site, jump directly to the caller epilogue so "
          "the detached path skips the late cleanup/logging block after FUN_180968840."
      ),
  )
  parser.add_argument(
      "--force-upstream-wrapper-return-bypass",
      action="store_true",
      help=(
          "After FUN_181618040 returns to FUN_182835d60, jump straight to that wrapper's "
          "epilogue to skip its rc cleanup/logging/final bookkeeping path."
      ),
  )
  parser.add_argument(
      "--probe-process-exit",
      action="store_true",
      help=(
          "Monitor process-termination and fail-fast APIs during the focused detached path "
          "to catch intentional self-termination after the native send pipeline returns."
      ),
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
  parser.add_argument(
      "--probe-thread-context",
      action="append",
      type=int,
      default=[],
      help="Probe threadPairFetch/pairCopy/normalize on this live thread id without sending.",
  )
  parser.add_argument(
      "--probe-all-threads",
      action="store_true",
      help="Probe threadPairFetch/pairCopy/normalize across all live threads in the target process.",
  )
  parser.add_argument(
      "--watch-context-ms",
      type=int,
      default=0,
      help="Passively watch real threadPairFetch activity for this long without sending.",
  )
  parser.add_argument(
      "--watch-max-hits",
      type=int,
      default=16,
      help="Maximum matching passive context-watch hits to retain.",
  )
  parser.add_argument(
      "--auto-thread-from-context-watch-ms",
      type=int,
      default=0,
      help=(
          "Before a detached send, passively watch threadPairFetch activity for this long "
          "and automatically choose the best observed live thread as --thread-id."
      ),
  )
  parser.add_argument(
      "--test-runonthread",
      action="store_true",
      help="Only verify that Process.runOnThread can execute on --thread-id.",
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
      if args.probe_all_threads or args.probe_thread_context:
          target_threads = args.probe_thread_context or []
          if args.probe_all_threads:
              target_threads = list_process_thread_ids(pid)
          probes = []
          for thread_id in target_threads:
              try:
                  probe = script.exports_sync.probethreadcontext(thread_id, args.conversation_id)
                  probes.append({"threadId": thread_id, "ok": True, "probe": probe})
              except Exception as exc:
                  probes.append({"threadId": thread_id, "ok": False, "error": str(exc)})
          print(json.dumps({"ok": True, "pid": pid, "probes": probes}, ensure_ascii=True))
          return 0

      if args.watch_context_ms > 0:
          script.exports_sync.setcontextwatch(args.conversation_id, args.watch_max_hits)
          time.sleep(args.watch_context_ms / 1000.0)
          print(json.dumps({"ok": True, "pid": pid, "watch": script.exports_sync.getcontextwatch()}, ensure_ascii=True))
          return 0

      if args.test_runonthread:
          if not args.thread_id:
              raise SystemExit("--test-runonthread requires --thread-id")
          result = script.exports_sync.testrunonthread(args.thread_id, args.conversation_id)
          deadline = time.time() + (args.run_timeout_ms / 1000.0)
          while time.time() < deadline:
              try:
                  status = script.exports_sync.getstatus()
              except frida.InvalidOperationError as exc:
                  raise SystemExit(
                      json.dumps(
                          {
                              "ok": False,
                              "error": "frida script destroyed while waiting for test-runonthread completion",
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
                              "error": "frida script destroyed while reading final test-runonthread status",
                              "detail": str(exc),
                          },
                          ensure_ascii=True,
                      )
                  )
              raise SystemExit(
                  json.dumps(
                      {
                          "ok": False,
                          "error": "timed out waiting for test-runonthread completion",
                          "status": result,
                      },
                      ensure_ascii=True,
                  )
              )

          if result.get("status") == "error":
              raise SystemExit(json.dumps({"ok": False, "error": result["error"], "status": result}, ensure_ascii=True))

          print(json.dumps({"ok": True, "pid": pid, "result": result}, ensure_ascii=True))
          return 0

      if not args.conversation_id:
          raise SystemExit("--conversation-id is required for detached send mode")
      if not args.body:
          raise SystemExit("--body is required for detached send mode")
      if not args.template_region and not args.init_request_from_seed_ctor:
          raise SystemExit("--template-region is required unless --init-request-from-seed-ctor is used")

      if not args.thread_id and args.auto_thread_from_context_watch_ms > 0:
          script.exports_sync.setcontextwatch(args.conversation_id, args.watch_max_hits)
          time.sleep(args.auto_thread_from_context_watch_ms / 1000.0)
          watch_state = script.exports_sync.getcontextwatch()
          chosen = choose_context_watch_thread(watch_state, args.conversation_id)
          print(
              json.dumps(
                  {
                      "kind": "python-auto-thread-watch",
                      "watchMs": args.auto_thread_from_context_watch_ms,
                      "watch": watch_state,
                      "chosen": chosen,
                  },
                  ensure_ascii=True,
              ),
              file=sys.stderr,
              flush=True,
          )
          script.exports_sync.clearcontextwatch()
          if not chosen:
              raise SystemExit(
                  json.dumps(
                      {
                          "ok": False,
                          "error": "no usable threadPairFetch context was observed during auto-thread watch",
                          "watch": watch_state,
                      },
                      ensure_ascii=True,
                  )
              )
          args.thread_id = int(chosen["threadId"])

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
                  args.direct_auto_detach_after_capture,
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

          if args.post_run_wait_ms > 0:
              print(
                  json.dumps(
                      {
                          "kind": "python-post-run-wait",
                          "waitMs": args.post_run_wait_ms,
                          "status": result,
                      },
                      ensure_ascii=True,
                  ),
                  file=sys.stderr,
                  flush=True,
              )
              time.sleep(args.post_run_wait_ms / 1000.0)

          print(json.dumps({"ok": True, "result": result, "capture_state": capture_state}, ensure_ascii=True))
          return 0

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
              args.synthetic_embed_seed_mode,
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
          captured_swap_state = script.exports_sync.setswap(args.thread_id, args.conversation_id)
          if args.use_captured_template_region:
              args.template_region = captured_swap_state["preparedTemplateRegion"]
      elif args.use_captured_template_region:
          args.template_region = capture_state["capturedTemplateRegion"]
      if args.deep_trace:
          script.exports_sync.setdeeptrace(True)
      if args.focused_trace:
          script.exports_sync.setfocusedtrace(True)
      if args.override_finalize_source_pair_slot != "keep":
          script.exports_sync.setfinalizeoverrideslot(args.override_finalize_source_pair_slot)
      if args.disable_late_pair_copy_swap:
          script.exports_sync.setlatepaircopyswap(False)
      if args.enable_late_pair_copy_field_patch:
          script.exports_sync.setlatepaircopypatch(True)
      if args.enable_late_pair_copy_request_field_patch:
          script.exports_sync.setlatepaircopyrequestfieldpatch(True)
      if args.bypass_crash_stub:
          script.exports_sync.setcrashstubbypass(True)
      if args.bypass_watson_failfast:
          script.exports_sync.setwatsonfailfastbypass(True)
      if args.probe_roam_crash_site:
          script.exports_sync.setroamservercrashprobe(True)
      if args.bypass_roam_crash_site:
          script.exports_sync.setroamservercrashbypass(True)
      if args.override_loop_finalize_source_pair != "keep":
          script.exports_sync.setloopfinalizesourceoverride(
              args.override_loop_finalize_source_pair
          )
      if args.restore_loop_finalize_bind_source_pair != "keep":
          script.exports_sync.setloopfinalizebindrestore(
              args.restore_loop_finalize_bind_source_pair
          )
      if args.force_loop_finalize_cast_bypass:
          script.exports_sync.setloopfinalizecastbypass(True)
      if args.force_loop_finalize_await_bypass:
          script.exports_sync.setloopfinalizeawaitbypass(True)
      if args.force_outer_wrapper_await_bypass:
          script.exports_sync.setouterwrapperawaitbypass(True)
      if args.force_upstream_wrapper_return_bypass:
          script.exports_sync.setupstreamwrapperreturnbypass(True)
      if args.force_post_finalize_resolve_bypass:
          script.exports_sync.setpostfinalizeresolvebypass(True)
      if args.repair_builder_return_slot:
          script.exports_sync.setbuilderreturnslotrepair(True)
      if args.probe_process_exit:
          script.exports_sync.setprocessexitprobe(True)

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

          if args.post_run_wait_ms > 0:
              print(
                  json.dumps(
                      {
                          "kind": "python-post-run-wait",
                          "waitMs": args.post_run_wait_ms,
                          "status": result,
                      },
                      ensure_ascii=True,
                  ),
                  file=sys.stderr,
                  flush=True,
              )
              time.sleep(args.post_run_wait_ms / 1000.0)

      print(json.dumps({"ok": True, "result": result}, ensure_ascii=True))
      return 0
  finally:
      session.detach()


if __name__ == "__main__":
  raise SystemExit(main())
