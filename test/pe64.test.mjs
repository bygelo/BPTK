// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { mapPe64State, peekPeMachine } from "../lib/pe64.mjs";

const PE = 0x80; // PE header offset written at 0x3c
const OPT = PE + 24; // optional header offset (0x98)
const SEC = OPT + 240; // section table follows a 240-byte optional header (0x188)
const IMAGE_BASE = 0x140000000n;
const SECTION_VA = 0x1000;
const SECTION_RAW = 0x200;

function tempFile(context, buffer, name = "image64.exe") {
  const root = mkdtempSync(join(tmpdir(), "bptk-pe64-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, name);
  writeFileSync(path, buffer);
  return path;
}

// Builds a minimal, correctly-laid-out PE32+ image. Section data (0x600 byte)
// maps from file 0x200 to VA 0x1000, so a byte at RVA 0x1000+k is file 0x200+k.
// Options overlay an import table, a relocation block, or a TLS directory.
function createPe64File(option = {}) {
  const file = Buffer.alloc(0x1000);
  file.writeUInt16LE(0x5a4d, 0); // MZ
  file.writeUInt32LE(PE, 0x3c);
  file.writeUInt32LE(0x00004550, PE); // "PE\0\0"
  file.writeUInt16LE(option.machine ?? 0x8664, PE + 4);
  file.writeUInt16LE(1, PE + 6); // one section
  file.writeUInt16LE(option.optionalSize ?? 240, PE + 20);
  file.writeUInt16LE(option.magic ?? 0x20b, OPT); // PE32+ magic
  file.writeUInt32LE(SECTION_VA, OPT + 16); // AddressOfEntryPoint
  file.writeBigUInt64LE(IMAGE_BASE, OPT + 24); // ImageBase (8 byte in PE32+)
  file.writeUInt32LE(0x2000, OPT + 56); // SizeOfImage
  file.writeUInt32LE(0x200, OPT + 60); // SizeOfHeaders
  file.writeBigUInt64LE(0x100000n, OPT + 72); // SizeOfStackReserve
  file.writeBigUInt64LE(0x1000n, OPT + 80); // SizeOfStackCommit
  file.writeBigUInt64LE(0x100000n, OPT + 88); // SizeOfHeapReserve
  file.writeBigUInt64LE(0x1000n, OPT + 96); // SizeOfHeapCommit
  file.writeUInt32LE(16, OPT + 108); // NumberOfRvaAndSizes
  // one section: .text, VA 0x1000, VirtualSize 0x1000, raw 0x600 @ file 0x200
  file.write(".text", SEC);
  file.writeUInt32LE(0x1000, SEC + 8);
  file.writeUInt32LE(SECTION_VA, SEC + 12);
  file.writeUInt32LE(0x600, SEC + 16);
  file.writeUInt32LE(SECTION_RAW, SEC + 20);
  file.writeUInt32LE(0x60000020, SEC + 36); // code | execute | read
  file[SECTION_RAW] = 0xc3; // entry byte (RET); never executed at load

  const rvaToFile = (rva) => SECTION_RAW + (rva - SECTION_VA);
  const setDir = (index, rva, size) => {
    file.writeUInt32LE(rva, OPT + 112 + index * 8);
    file.writeUInt32LE(size, OPT + 112 + index * 8 + 4);
  };

  if (option.withImport) {
    // descriptor @0x1100 (+ null descriptor @0x1114), thunks @0x1130 (clear of
    // the descriptor terminator), library @0x1140, hint/name @0x1150, IAT @0x1160
    setDir(1, 0x1100, 40);
    const d = rvaToFile(0x1100);
    file.writeUInt32LE(0x1130, d); // OriginalFirstThunk
    file.writeUInt32LE(0x1140, d + 12); // Name
    file.writeUInt32LE(0x1160, d + 16); // FirstThunk (IAT)
    file.writeBigUInt64LE(0x1150n, rvaToFile(0x1130)); // by-name thunk (bit 63 clear)
    file.writeBigUInt64LE(0n, rvaToFile(0x1138)); // terminator
    file.write("user32.dll\0", rvaToFile(0x1140), "ascii");
    file.writeUInt16LE(0, rvaToFile(0x1150)); // hint
    file.write("MessageBoxA\0", rvaToFile(0x1152), "ascii");
  }
  if (option.withReloc) {
    // a single IMAGE_REL_BASED_DIR64 (type 10) at RVA 0x1008
    file.writeBigUInt64LE(0x140001500n, rvaToFile(0x1008)); // target qword
    setDir(5, 0x1200, 12);
    const r = rvaToFile(0x1200);
    file.writeUInt32LE(SECTION_VA, r); // page RVA
    file.writeUInt32LE(12, r + 4); // block size: 8 header + 2 entries
    file.writeUInt16LE((10 << 12) | 0x008, r + 8); // DIR64 @ +0x008
    file.writeUInt16LE(0, r + 10); // ABSOLUTE padding
  }
  if (option.withTls) {
    // TLS dir @0x1300, callback array @0x1320 (one callback, then null)
    setDir(9, 0x1300, 40);
    const t = rvaToFile(0x1300);
    file.writeBigUInt64LE(IMAGE_BASE + 0x1310n, t + 16); // AddressOfIndex
    file.writeBigUInt64LE(IMAGE_BASE + 0x1320n, t + 24); // AddressOfCallBacks
    file.writeBigUInt64LE(IMAGE_BASE + 0x1000n, rvaToFile(0x1320)); // one callback
    file.writeBigUInt64LE(0n, rvaToFile(0x1328)); // terminator
  }
  return file;
}

test("mapPe64State maps a minimal PE32+ image to a loaded, unexecuted state", (context) => {
  const path = tempFile(context, createPe64File());
  const report = mapPe64State(path);
  assert.equal(report.machine, "x86_64");
  assert.equal(report.format, "pe32_plus");
  assert.equal(report.state, "loaded");
  assert.equal(report.is_executed, false);
  assert.equal(report.load_base, IMAGE_BASE);
  assert.equal(report.entry_address, IMAGE_BASE + BigInt(SECTION_VA));
  assert.equal(report.section.length, 1);
  assert.equal(report.import.length, 0);
  assert.equal(report.tls_callback.length, 0);
  assert.match(report.runtime_blocker.join(" "), /not executed/);
});

test("mapPe64State refuses an i386 machine", (context) => {
  const path = tempFile(context, createPe64File({ machine: 0x14c }));
  assert.throws(() => mapPe64State(path), (error) => error.input_code === "unsupported_machine");
});

test("mapPe64State refuses a PE32 optional header", (context) => {
  const path = tempFile(context, createPe64File({ magic: 0x10b }));
  assert.throws(() => mapPe64State(path), (error) => error.input_code === "unsupported_optional_header");
});

test("mapPe64State parses a 64-bit by-name import thunk", (context) => {
  const path = tempFile(context, createPe64File({ withImport: true }));
  const report = mapPe64State(path);
  assert.equal(report.import.length, 1);
  assert.equal(report.import[0].library, "user32.dll");
  assert.equal(report.import[0].symbol, "MessageBoxA");
  assert.equal(report.import[0].resolution_state, "unresolved");
  assert.equal(report.import_descriptor_count, 1);
  assert.ok(report.resolution_blocker.some((entry) => /Win64 HLE/.test(entry)));
});

test("mapPe64State applies an IMAGE_REL_BASED_DIR64 relocation for a moved base", (context) => {
  const path = tempFile(context, createPe64File({ withReloc: true }));
  const moved = 0x180000000n;
  const report = mapPe64State(path, moved);
  assert.equal(report.load_base, moved);
  assert.equal(report.relocation_count, 1);
  // the target qword gained exactly the load delta
  const delta = moved - IMAGE_BASE;
  // the mapped image is VA-indexed: the relocated qword sits at RVA 0x1008
  assert.equal(report.image.readBigUInt64LE(0x1008), 0x140001500n + delta);
});

test("mapPe64State refuses a moved base with no relocation directory", (context) => {
  const path = tempFile(context, createPe64File());
  assert.throws(() => mapPe64State(path, 0x180000000n), (error) => error.input_code === "relocation_required");
});

test("peekPeMachine reads the machine without a full load and returns null for non-PE input", (context) => {
  const x64 = tempFile(context, createPe64File(), "x64.exe");
  assert.equal(peekPeMachine(x64), 0x8664);
  // a large sparse non-PE file peeks null (and is never fully read)
  const junk = tempFile(context, Buffer.alloc(0x2000), "junk.bin");
  assert.equal(peekPeMachine(junk), null);
  assert.equal(peekPeMachine(""), null);
});

test("mapPe64State reads a 64-bit TLS callback array", (context) => {
  const path = tempFile(context, createPe64File({ withTls: true }));
  const report = mapPe64State(path);
  assert.equal(report.tls_callback.length, 1);
  assert.equal(report.tls_callback[0], IMAGE_BASE + 0x1000n);
  assert.match(report.runtime_blocker.join(" "), /TLS callback execution is not implemented/);
});
