const TARGETS = {
  detachedCaller: 0x15b1350,
  detachedSeedCtor: 0x15b1c80,
  detachedSeedCopy: 0x15b20b0,
  cloneTail: 0x38880,
  dispatchWrapA: 0xdba6f0,
  dispatchSubmit: 0x314950,
  dispatchWrapB: 0x314b30,
  entryMode0: 0x15e8a80,
  entryMode1: 0x15ea920,
  workerEntry: 0x15e8200,
  workerCtor: 0x33fc800,
  builderPopulate: 0x33fccd0,
  workerFinalize: 0x15eb0d0,
  helperTableInsert: 0x15eb320,
  helperWalk: 0x15ebec0,
  altEntry: 0x15ea9e0,
  batchBuilder: 0x1664250,
};

function ptrHex(value) {
  if (value === null || value === undefined) {
    return null;
  }
  try {
    return ptr(value).toString();
  } catch (_) {
    return String(value);
  }
}

function safeReadU64(address) {
  try {
    return ptr(address).readU64().toString();
  } catch (_) {
    return null;
  }
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

function readSmallString(address) {
  const base = ptr(address);
  try {
    const length = base.add(0x10).readU64();
    const capacity = base.add(0x18).readU64();
    const heap = capacity.compare(0x0f) > 0;
    const dataPtr = heap ? base.readPointer() : base;
    const text = safeReadAnsi(dataPtr, length);
    return {
      address: base.toString(),
      data: dataPtr.toString(),
      length: length.toString(),
      capacity: capacity.toString(),
      heap,
      text,
    };
  } catch (error) {
    return {
      address: base.toString(),
      error: String(error),
    };
  }
}

function readRcPair(address) {
  const base = ptr(address);
  try {
    const object = base.readPointer();
    const ref = base.add(Process.pointerSize).readPointer();
    const vtable = object.isNull() ? null : safeReadPointer(object);
    return {
      address: base.toString(),
      object: object.toString(),
      ref: ref.toString(),
      vtable: vtable ? vtable.toString() : null,
    };
  } catch (error) {
    return {
      address: base.toString(),
      error: String(error),
    };
  }
}

function readFinalizeResult(address) {
  const base = ptr(address);
  try {
    const object = base.readPointer();
    const text = readSmallString(base.add(0x08));
    const tailValue = ptrHex(base.add(0x28).readPointer());
    const tailRef = ptrHex(base.add(0x30).readPointer());
    return {
      address: base.toString(),
      object: object.toString(),
      text,
      tailValue,
      tailRef,
    };
  } catch (error) {
    return {
      address: base.toString(),
      error: String(error),
    };
  }
}

function threadTag() {
  return {
    threadId: Process.getCurrentThreadId(),
  };
}

function emit(kind, payload) {
  send({
    kind,
    ...threadTag(),
    ...payload,
  });
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

function formatBacktrace(context) {
  try {
    return Thread.backtrace(context, Backtracer.ACCURATE).map((address) => ({
      address: ptrHex(address),
      symbol: DebugSymbol.fromAddress(address).toString(),
    }));
  } catch (_) {
    return [];
  }
}

function inspectObjectStrings(address, offsets) {
  const object = ptr(address);
  const strings = {};
  offsets.forEach((offset) => {
    strings[`0x${offset.toString(16)}`] = readSmallString(object.add(offset));
  });
  return strings;
}

function inspectPointerFields(address, offsets) {
  const object = ptr(address);
  const fields = {};
  offsets.forEach((offset) => {
    fields[`0x${offset.toString(16)}`] = ptrHex(safeReadPointer(object.add(offset)));
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
  const object = ptr(address);
  return {
    base: object.toString(),
    strings: inspectObjectStrings(object, [
      0x10, 0x30, 0x50, 0x70, 0xb8, 0xd8, 0x118, 0x138,
      0x160, 0x180, 0x1a0, 0x1c0, 0x1e0, 0x200, 0x230, 0x250,
      0x2a0, 0x2c0, 0x2e0, 0x300, 0x320, 0x340, 0x360,
    ]),
    dwords: inspectDwordFields(object, [
      0x90, 0x94, 0x98, 0x9c, 0xa0, 0xa4, 0xa8, 0xac,
      0xf8, 0xfc, 0x100, 0x104, 0x108, 0x10c, 0x110, 0x114,
      0x158, 0x220, 0x228, 0x270, 0x280, 0x290, 0x380,
    ]),
    pointers: inspectPointerFields(object, [0x288, 0x290, 0x298]),
    headHex: readHex(object, 0x3a0),
  };
}

function inspectSourceObject(address) {
  const object = ptr(address);
  return {
    address: object.toString(),
    vtable: ptrHex(safeReadPointer(object)),
    strings: inspectObjectStrings(object, [0x38, 0x78, 0xb0]),
    pointers: inspectPointerFields(object, [0x08, 0x10, 0x18, 0x20, 0x28, 0x30]),
    dwords: inspectDwordFields(object, [0x48, 0x50, 0x88, 0x90, 0xc0, 0xc8]),
    headHex: readHex(object, 0xc0),
    embeddedRequest: inspectRequestRegion(object.add(0xd8)),
  };
}

function inspectSendRequestObject(address) {
  const object = ptr(address);
  const requestBase = object.add(0x08);
  return {
    address: object.toString(),
    talker: readSmallString(object.add(0x38)),
    pointers: inspectPointerFields(object, [0x288, 0x290, 0x298, 0x380, 0x388, 0x390]),
    tailClonePointers: inspectPointerFields(object, [
      0x390, 0x398, 0x3a0, 0x3a8, 0x3b0, 0x3b8, 0x3c0, 0x3c8,
      0x3d0, 0x3d8, 0x3e0, 0x3e8, 0x3f0, 0x3f8, 0x400, 0x408,
      0x410, 0x418, 0x420, 0x428, 0x430, 0x438, 0x440, 0x448,
      0x450, 0x458, 0x460, 0x468, 0x470,
    ]),
    tailCloneHex: readHex(object.add(0x390), 0xe8),
    request: inspectRequestRegion(requestBase),
  };
}

function inspectWorkerState(address) {
  const object = ptr(address);
  return {
    address: object.toString(),
    vtable: ptrHex(safeReadPointer(object)),
    mode: safeReadU8(object.add(0xb8)),
    strings: inspectObjectStrings(object, [0x38, 0xc8]),
    pairs: {
      source: readRcPair(object.add(0x08)),
      built: readRcPair(object.add(0x18)),
      helper: readRcPair(object.add(0x28)),
    },
    headHex: readHex(object, 0xf0),
  };
}

function inspectHelperNodeObject(address) {
  const object = ptr(address);
  const slot0 = readRcPair(object.add(0x78));
  const slot1 = readRcPair(object.add(0x88));
  const slot2 = readRcPair(object.add(0x98));
  return {
    address: object.toString(),
    vtable: ptrHex(safeReadPointer(object)),
    strings: inspectObjectStrings(object, [0x38]),
    pointers: inspectPointerFields(object, [0x08, 0x10, 0x18, 0x20]),
    pairSlots: {
      slot0,
      slot1,
      slot2,
    },
    headHex: readHex(object, 0xc0),
  };
}

function inspectBuiltMessageObject(address) {
  const object = ptr(address);
  return {
    address: object.toString(),
    vtable: ptrHex(safeReadPointer(object)),
    strings: inspectObjectStrings(object, [0x18, 0x38, 0x180, 0x270]),
    pairs: {
      nested: readRcPair(object.add(0x240)),
    },
    dwords: inspectDwordFields(object, [0x0c, 0x10, 0x118, 0x124, 0x128, 0x134, 0x138, 0x230]),
    pointers: inspectPointerFields(object, [0x110, 0x120, 0x180, 0x240, 0x248, 0x270]),
    headHex: readHex(object, 0x100),
    tailHex180: readHex(object.add(0x180), 0x80),
    tailHex240: readHex(object.add(0x240), 0x60),
  };
}

function inspectFinalizeSourceObject(address) {
  const object = ptr(address);
  return {
    address: object.toString(),
    header: {
      qword0: ptrHex(safeReadPointer(object)),
      qword8: ptrHex(safeReadPointer(object.add(0x08))),
    },
    stage: {
      typePtr: ptrHex(safeReadPointer(object.add(0x270))),
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

function inspectTailCloneRegion(address) {
  const object = ptr(address);
  return {
    address: object.toString(),
    qwords: inspectPointerFields(object, [0x00, 0x08, 0x10, 0x48, 0x88, 0xc8, 0xd0, 0xd8, 0xe0]),
    firstPair: readRcPair(object),
    hex: readHex(object, 0xe8),
  };
}

function inspectDispatchWrapperObject(address) {
  const object = ptr(address);
  return {
    address: object.toString(),
    vtable: ptrHex(safeReadPointer(object)),
    contextQwords: inspectPointerFields(object, [0x28, 0x30, 0x38, 0x40]),
    contextHex: readHex(object.add(0x28), 0x20),
    payload: ptrHex(safeReadPointer(object.add(0x48))),
    headHex: readHex(object, 0x50),
  };
}

function attachTrace(name, offset, handlers) {
  const absoluteAddress = moduleBase.add(offset);
  Interceptor.attach(absoluteAddress, handlers);
  emit("hook-installed", {
    name,
    address: absoluteAddress.toString(),
    offset: `0x${offset.toString(16)}`,
  });
}

rpc.exports = {
  ping() {
    return "pong";
  },
};

const moduleBase = Process.getModuleByName("Weixin.dll").base;

Process.setExceptionHandler((details) => {
  emit("native-exception", {
    type: details.type || null,
    address: ptrHex(details.address),
    memory:
      details.memory === undefined
        ? null
        : {
            operation: details.memory.operation || null,
            address: ptrHex(details.memory.address),
          },
    context: {
      pc: details.context ? ptrHex(details.context.pc) : null,
      sp: details.context ? ptrHex(details.context.sp) : null,
      lr: details.context && details.context.lr !== undefined ? ptrHex(details.context.lr) : null,
    },
    backtrace: details.context ? formatBacktrace(details.context) : [],
  });
  return false;
});

emit("module-base", {
  module: "Weixin.dll",
  base: moduleBase.toString(),
});

attachTrace("detachedCaller", TARGETS.detachedCaller, {
  onEnter(args) {
    emit("detached-caller-enter", {
      address: moduleBase.add(TARGETS.detachedCaller).toString(),
      request: inspectSendRequestObject(args[0]),
    });
  },
});

attachTrace("detachedSeedCtor", TARGETS.detachedSeedCtor, {
  onEnter(args) {
    this.outAddress = args[0];
    emit("detached-seed-ctor-enter", {
      address: moduleBase.add(TARGETS.detachedSeedCtor).toString(),
      outAddress: ptrHex(args[0]),
    });
  },
  onLeave(retval) {
    const seedObject = safeReadPointer(this.outAddress);
    emit("detached-seed-ctor-leave", {
      address: moduleBase.add(TARGETS.detachedSeedCtor).toString(),
      retval: ptrHex(retval),
      out: ptrHex(seedObject),
      seedObject:
        seedObject === null || ptr(seedObject).isNull()
          ? null
          : inspectSourceObject(seedObject),
    });
  },
});

attachTrace("detachedSeedCopy", TARGETS.detachedSeedCopy, {
  onEnter(args) {
    emit("detached-seed-copy-enter", {
      address: moduleBase.add(TARGETS.detachedSeedCopy).toString(),
      destination: ptrHex(args[0]),
      source: ptrHex(args[1]),
      destinationRegion: inspectRequestRegion(args[0]),
      sourceRegion: inspectRequestRegion(args[1]),
    });
  },
});

attachTrace("cloneTail", TARGETS.cloneTail, {
  onEnter(args) {
    this.destination = args[0];
    emit("clone-tail-enter", {
      address: moduleBase.add(TARGETS.cloneTail).toString(),
      destination: ptrHex(args[0]),
      source: ptrHex(args[1]),
      sourceTail: inspectTailCloneRegion(args[1]),
    });
  },
  onLeave(retval) {
    emit("clone-tail-leave", {
      address: moduleBase.add(TARGETS.cloneTail).toString(),
      retval: ptrHex(retval),
      destinationTail: inspectTailCloneRegion(this.destination),
    });
  },
});

attachTrace("workerEntry", TARGETS.workerEntry, {
  onEnter(args) {
    this.output = args[1];
    this.inputPair = args[2];
    this.mode = args[3].toUInt32();
    this.callSite = this.returnAddress;
    this.inputPairSnapshot = readRcPair(this.inputPair);
    emit("worker-entry-enter", {
      address: moduleBase.add(TARGETS.workerEntry).toString(),
      callSite: ptrHex(this.callSite),
      mode: this.mode,
      inputPair: this.inputPairSnapshot,
      inputObject:
        this.inputPairSnapshot.object === "0x0"
          ? null
          : inspectSourceObject(this.inputPairSnapshot.object),
    });
  },
  onLeave(retval) {
    emit("worker-entry-leave", {
      address: moduleBase.add(TARGETS.workerEntry).toString(),
      mode: this.mode,
      retval: ptrHex(retval),
      output: readFinalizeResult(this.output),
    });
  },
});

attachTrace("workerCtor", TARGETS.workerCtor, {
  onEnter(args) {
    this.worker = args[0];
    this.inputPair = args[1];
    this.mode = args[2].toUInt32();
    const inputPair = readRcPair(this.inputPair);
    emit("worker-ctor-enter", {
      address: moduleBase.add(TARGETS.workerCtor).toString(),
      mode: this.mode,
      inputPair,
      inputObject: inputPair.object === "0x0" ? null : inspectSourceObject(inputPair.object),
      worker: inspectWorkerState(this.worker),
    });
  },
  onLeave(retval) {
    emit("worker-ctor-leave", {
      address: moduleBase.add(TARGETS.workerCtor).toString(),
      retval: ptrHex(retval),
      worker: inspectWorkerState(this.worker),
    });
  },
});

attachTrace("builderPopulate", TARGETS.builderPopulate, {
  onEnter(args) {
    this.worker = args[0];
    this.outPair = args[1];
    emit("builder-populate-enter", {
      address: moduleBase.add(TARGETS.builderPopulate).toString(),
      worker: inspectWorkerState(this.worker),
      outPairAddress: ptrHex(this.outPair),
    });
  },
  onLeave(retval) {
    const outPair = readRcPair(this.outPair);
    emit("builder-populate-leave", {
      address: moduleBase.add(TARGETS.builderPopulate).toString(),
      retval: ptrHex(retval),
      outPair,
      builtObject: outPair.object === "0x0" ? null : inspectBuiltMessageObject(outPair.object),
      worker: inspectWorkerState(this.worker),
    });
  },
});

attachTrace("helperTableInsert", TARGETS.helperTableInsert, {
  onEnter(args) {
    const pair = readRcPair(args[2]);
    emit("helper-table-insert", {
      address: moduleBase.add(TARGETS.helperTableInsert).toString(),
      manager: ptrHex(args[1]),
      pair,
      key: readSmallString(args[3]),
      pairObject:
        pair.object === "0x0"
          ? null
          : inspectHelperNodeObject(pair.object),
    });
  },
});

attachTrace("helperWalk", TARGETS.helperWalk, {
  onEnter(args) {
    emit("helper-walk-enter", {
      address: moduleBase.add(TARGETS.helperWalk).toString(),
      owner: ptrHex(args[0]),
      key: readSmallString(args[1]),
    });
  },
});

attachTrace("workerFinalize", TARGETS.workerFinalize, {
  onEnter(args) {
    this.out = args[1];
    const sourcePair = readRcPair(args[2]);
    emit("worker-finalize-enter", {
      address: moduleBase.add(TARGETS.workerFinalize).toString(),
      out: ptrHex(args[1]),
      sourcePair,
      sourceObject:
        sourcePair.object === "0x0"
          ? null
          : inspectFinalizeSourceObject(sourcePair.object),
    });
  },
  onLeave(retval) {
    emit("worker-finalize-leave", {
      address: moduleBase.add(TARGETS.workerFinalize).toString(),
      retval: ptrHex(retval),
      result: readFinalizeResult(this.out),
    });
  },
});

attachTrace("dispatchWrapA", TARGETS.dispatchWrapA, {
  onEnter(args) {
    this.out = args[0];
    this.payloadPtr = args[2];
    emit("dispatch-wrap-a-enter", {
      address: moduleBase.add(TARGETS.dispatchWrapA).toString(),
      out: ptrHex(args[0]),
      context: ptrHex(args[1]),
      contextHex: readHex(args[1], 0x20),
      payloadPointerSlot: ptrHex(args[2]),
      payloadObject: ptrHex(safeReadPointer(args[2])),
    });
  },
  onLeave(retval) {
    const wrapperObject = safeReadPointer(this.out);
    emit("dispatch-wrap-a-leave", {
      address: moduleBase.add(TARGETS.dispatchWrapA).toString(),
      retval: ptrHex(retval),
      wrapperOut: ptrHex(wrapperObject),
      wrapper: wrapperObject === null || ptr(wrapperObject).isNull() ? null : inspectDispatchWrapperObject(wrapperObject),
    });
  },
});

attachTrace("dispatchSubmit", TARGETS.dispatchSubmit, {
  onEnter(args) {
    this.payloadPtr = args[1];
    const payloadObject = safeReadPointer(args[1]);
    emit("dispatch-submit-enter", {
      address: moduleBase.add(TARGETS.dispatchSubmit).toString(),
      context: ptrHex(args[0]),
      contextHex: readHex(args[0], 0x20),
      payloadPointerSlot: ptrHex(args[1]),
      payloadObject: ptrHex(payloadObject),
      payload: payloadObject === null || ptr(payloadObject).isNull() ? null : inspectDispatchWrapperObject(payloadObject),
      param3: ptrHex(args[2]),
      param4: args[3].toUInt32(),
    });
  },
  onLeave(retval) {
    emit("dispatch-submit-leave", {
      address: moduleBase.add(TARGETS.dispatchSubmit).toString(),
      retval: ptrHex(retval),
      payloadAfter: ptrHex(safeReadPointer(this.payloadPtr)),
    });
  },
});

attachTrace("dispatchWrapB", TARGETS.dispatchWrapB, {
  onEnter(args) {
    const payloadObject = safeReadPointer(args[2]);
    emit("dispatch-wrap-b-enter", {
      address: moduleBase.add(TARGETS.dispatchWrapB).toString(),
      context: ptrHex(args[1]),
      contextHex: readHex(args[1], 0x20),
      payloadPointerSlot: ptrHex(args[2]),
      payloadObject: ptrHex(payloadObject),
      payload: payloadObject === null || ptr(payloadObject).isNull() ? null : inspectDispatchWrapperObject(payloadObject),
    });
  },
});

attachTrace("entryMode0", TARGETS.entryMode0, {
  onEnter(args) {
    emit("entry-mode0", {
      address: moduleBase.add(TARGETS.entryMode0).toString(),
      out: ptrHex(args[1]),
      sourcePair: readRcPair(args[2]),
    });
  },
});

attachTrace("entryMode1", TARGETS.entryMode1, {
  onEnter(args) {
    emit("entry-mode1", {
      address: moduleBase.add(TARGETS.entryMode1).toString(),
      out: ptrHex(args[1]),
      sourcePair: readRcPair(args[2]),
    });
  },
});

attachTrace("altEntry", TARGETS.altEntry, {
  onEnter(args) {
    emit("alt-entry", {
      address: moduleBase.add(TARGETS.altEntry).toString(),
      out: ptrHex(args[1]),
      sourcePair: readRcPair(args[2]),
    });
  },
});

attachTrace("batchBuilder", TARGETS.batchBuilder, {
  onEnter(args) {
    emit("batch-builder", {
      address: moduleBase.add(TARGETS.batchBuilder).toString(),
      context: ptrHex(args[1]),
      vector: ptrHex(args[2]),
      vectorStart: ptrHex(safeReadPointer(args[2])),
      vectorEnd: ptrHex(safeReadPointer(ptr(args[2]).add(Process.pointerSize))),
    });
  },
});
