// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Leftover sidecar IAT for OpenAL-class audio modules. A mapped openal32.dll
// still imports a few system symbols the Win32 HLE table does not yet name
// (today: kernel32!DebugBreak). Those slots stay hint RVAs unless this module
// writes a generic i386 gadget and retargets the IAT.
//
// Generic, not a title branch: any sidecar that imports a row in this table
// gets the same gadget. The real OpenAL export surface stays on the mapped PE.
// Callers must not treat a leftover RET as a presented frame or a completed
// interactive-freeware goal.

const leftoverPageAlignByte = 0x1000;
const leftoverSlotByte = 16;
const leftoverSectionFlag = 0x60000020; // CODE | MEM_EXECUTE | MEM_READ

export const leftoverSidecarIat = Object.freeze([
  Object.freeze({
    library: "kernel32.dll",
    symbol: "DebugBreak",
    argument_count: 0,
    calling_convention: "stdcall",
    return_value: 0,
  }),
]);

export function resolveLeftoverSidecarIat(library, symbol, ordinal = null) {
  const lib = String(library ?? "").toLowerCase();
  if (typeof symbol === "string") {
    return leftoverSidecarIat.find((entry) => entry.library === lib && entry.symbol === symbol) ?? null;
  }
  if (Number.isInteger(ordinal) && ordinal > 0) {
    return leftoverSidecarIat.find((entry) => entry.library === lib && entry.ordinal === ordinal) ?? null;
  }
  return null;
}

export function leftoverIatKey(library, symbol, ordinal = null) {
  return `${String(library ?? "").toLowerCase()}!${String(symbol ?? `#${ordinal}`).toLowerCase()}`;
}

// i386 gadget: EAX gets the declared return, then RET or RET n for stdcall.
export function encodeLeftoverStub(entry) {
  const value = (entry.return_value ?? 0) >>> 0;
  const byte = [0xb8, value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff];
  if (entry.calling_convention === "stdcall" && (entry.argument_count ?? 0) > 0) {
    const popByte = ((entry.argument_count ?? 0) * 4) & 0xffff;
    byte.push(0xc2, popByte & 0xff, popByte >>> 8);
  } else {
    byte.push(0xc3);
  }
  return Buffer.from(byte);
}

function alignUp(value, align) {
  return Math.ceil(Math.max(value, 0) / align) * align;
}

// After sidecar remap: grow the image with one executable leftover page, write
// gadgets, and patch IAT slots. Catalog bind cannot target an address inside
// the mapped PE (import_address_overlap), so this write is host-side.
export function applyLeftoverSidecarIat({ image, section, load_base, import_entry, unserved }) {
  const pending = [];
  for (const currentImport of import_entry ?? []) {
    const stub = resolveLeftoverSidecarIat(currentImport.library, currentImport.symbol, currentImport.ordinal);
    if (stub === null || !Number.isInteger(currentImport.iat_rva)) continue;
    pending.push({ import: currentImport, stub });
  }
  const leftoverServed = [];
  if (pending.length === 0) {
    return { image, section, unserved: [...(unserved ?? [])], leftover_served: leftoverServed };
  }
  const source = Buffer.isBuffer(image) ? image : Buffer.from(image);
  const startRva = alignUp(source.length, leftoverPageAlignByte);
  const unique = [];
  const addressByKey = new Map();
  for (const row of pending) {
    const key = leftoverIatKey(row.stub.library, row.stub.symbol, row.stub.ordinal);
    if (addressByKey.has(key)) continue;
    const address = (load_base + startRva + unique.length * leftoverSlotByte) >>> 0;
    addressByKey.set(key, address);
    unique.push({ stub: row.stub, address });
  }
  const pageByte = alignUp(unique.length * leftoverSlotByte, leftoverPageAlignByte);
  const grown = Buffer.alloc(startRva + pageByte);
  source.copy(grown);
  for (const [index, row] of unique.entries()) {
    const gadget = encodeLeftoverStub(row.stub);
    gadget.copy(grown, startRva + index * leftoverSlotByte);
  }
  for (const row of pending) {
    const key = leftoverIatKey(row.stub.library, row.stub.symbol, row.stub.ordinal);
    grown.writeUInt32LE(addressByKey.get(key), row.import.iat_rva);
    leftoverServed.push({
      library: row.import.library,
      symbol: row.import.symbol,
      ordinal: row.import.ordinal,
      address: addressByKey.get(key),
      iat_rva: row.import.iat_rva,
    });
  }
  const servedKey = new Set(leftoverServed.map((row) => leftoverIatKey(row.library, row.symbol, row.ordinal)));
  const nextSection = [
    ...(section ?? []),
    {
      name: ".hleiat",
      virtual_address: startRva,
      virtual_size_byte: pageByte,
      mapped_size_byte: pageByte,
      raw_offset: 0,
      raw_size_byte: 0,
      characteristic: leftoverSectionFlag,
    },
  ];
  return {
    image: grown,
    section: nextSection,
    unserved: (unserved ?? []).filter((key) => !servedKey.has(key.toLowerCase())),
    leftover_served: leftoverServed,
  };
}
