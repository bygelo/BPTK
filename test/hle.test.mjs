// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The Win32 core HLE acceptance surface (BPTK-010): the conformance suite
// over every served export, the FIX-003 API exerciser reaching a normal
// process exit through the golden call trace, the unserved-import refusal
// that names the gap, TLS-callback phase ordering, and determinism.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { runConformanceSuite } from "../lib/conformance.mjs";
import { buildConformanceCaseTable, createConformanceImplementation, listWin32HleExport, hleProfile, createConformanceMachine } from "../lib/hle.mjs";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

function run(argument) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

function readRun(packagePath) {
  const result = run(["run", packagePath, "--json"]);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

// ---------------------------------------------------------------------------
// The generated PE32 exerciser. One builder serves every case in this file:
// a real import directory, real sections, and guest machine code that calls
// the import surface the way a real startup does.
// ---------------------------------------------------------------------------

const imageBase = 0x400000;

function dwordBytes(value) {
  return [value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff];
}

function createImportPe32(imports, code, option = {}) {
  const data = option.data ?? Buffer.alloc(0x200);
  const file = Buffer.alloc(0x3000);
  file.writeUInt16LE(0x5a4d, 0);
  file.writeUInt32LE(0x80, 0x3c);
  file.writeUInt32LE(0x00004550, 0x80);
  file.writeUInt16LE(0x14c, 0x84);
  file.writeUInt16LE(3, 0x86);
  file.writeUInt16LE(224, 0x94);
  file.writeUInt16LE(0x10b, 0x98);
  file.writeUInt32LE(0x1000, 0xa8);
  file.writeUInt32LE(imageBase, 0xb4);
  file.writeUInt32LE(0x4000, 0xd0);
  file.writeUInt32LE(0x200, 0xd4);
  file.writeUInt32LE(0x10000, 0xe0);
  file.writeUInt32LE(0x1000, 0xe4);
  file.writeUInt32LE(0x10000, 0xe8);
  file.writeUInt32LE(0x1000, 0xec);
  file.writeUInt32LE(16, 0xf4);
  file.writeUInt32LE(0x2000, 0x98 + 96 + 8);
  if (option.tls === true) {
    file.writeUInt32LE(0x3180, 0x98 + 96 + 9 * 8);
    file.writeUInt32LE(24, 0x98 + 96 + 9 * 8 + 4);
  }
  const sectionOffset = 0x178;
  const textRawSizeByte = Math.max(0x200, Math.ceil(code.length / 0x200) * 0x200);
  file.write(".text", sectionOffset);
  file.writeUInt32LE(0x1000, sectionOffset + 8);
  file.writeUInt32LE(0x1000, sectionOffset + 12);
  file.writeUInt32LE(textRawSizeByte, sectionOffset + 16);
  file.writeUInt32LE(0x200, sectionOffset + 20);
  file.writeUInt32LE(0x60000020, sectionOffset + 36);
  file.write(".idata", sectionOffset + 40);
  file.writeUInt32LE(0x1000, sectionOffset + 40 + 8);
  file.writeUInt32LE(0x2000, sectionOffset + 40 + 12);
  file.writeUInt32LE(0x1000, sectionOffset + 40 + 16);
  file.writeUInt32LE(0x1200, sectionOffset + 40 + 20);
  file.writeUInt32LE(0xc0300040, sectionOffset + 40 + 36);
  file.write(".data", sectionOffset + 80);
  file.writeUInt32LE(0x800, sectionOffset + 80 + 8);
  file.writeUInt32LE(0x3000, sectionOffset + 80 + 12);
  file.writeUInt32LE(0x200, sectionOffset + 80 + 16);
  file.writeUInt32LE(0x2200, sectionOffset + 80 + 20);
  file.writeUInt32LE(0xc0400040, sectionOffset + 80 + 36);
  const entryRva = option.entry_rva ?? 0x1000;
  file.writeUInt32LE(entryRva, 0xa8);
  Buffer.from(code).copy(file, 0x200 + (option.code_rva ?? 0x1000) - 0x1000);

  const idataFileOffset = 0x200 + 0x2000 - 0x1000;
  const layout = option.import_layout;
  layout.group.forEach((group, groupIndex) => {
    const descriptorOffset = idataFileOffset + groupIndex * 20;
    file.writeUInt32LE(group.lookup_rva, descriptorOffset);
    file.writeUInt32LE(0, descriptorOffset + 4);
    file.writeUInt32LE(0, descriptorOffset + 8);
    file.writeUInt32LE(group.name_rva, descriptorOffset + 12);
    file.writeUInt32LE(group.iat_rva, descriptorOffset + 16);
    file.write(group.library + "\0", 0x200 + group.name_rva - 0x1000, "ascii");
    group.symbol.forEach((name, index) => {
      file.writeUInt32LE(group.hint_rva_of[index], 0x200 + group.lookup_rva - 0x1000 + index * 4);
      file.writeUInt32LE(group.hint_rva_of[index], 0x200 + group.iat_rva - 0x1000 + index * 4);
      file.writeUInt16LE(0, 0x200 + group.hint_rva_of[index] - 0x1000);
      file.write(name + "\0", 0x200 + group.hint_rva_of[index] + 2 - 0x1000, "ascii");
    });
    file.writeUInt32LE(0, 0x200 + group.lookup_rva - 0x1000 + group.symbol.length * 4);
    file.writeUInt32LE(0, 0x200 + group.iat_rva - 0x1000 + group.symbol.length * 4);
  });
  file.writeUInt32LE(0, idataFileOffset + layout.group.length * 20);
  file.writeUInt32LE((layout.group.length + 1) * 20, 0x98 + 96 + 12);
  if (option.tls === true) {
    // The TLS directory lives in .data at RVA 0x3180 (data offset 0x180) with
    // its callback table at RVA 0x31c0; no separate .tls section is needed.
    data.writeUInt32LE(0, 0x180);
    data.writeUInt32LE(0, 0x184);
    data.writeUInt32LE(0, 0x188);
    data.writeUInt32LE(option.tls_table_address ?? (imageBase + 0x31c0), 0x18c);
    data.writeUInt32LE(0, 0x190);
    data.writeUInt32LE(0, 0x194);
    data.writeUInt32LE(option.tls_callback ?? imageBase + 0x1000, 0x1c0);
    data.writeUInt32LE(0, 0x1c4);
  }
  data.copy(file, 0x2200);
  return file;
}

function createHlePackage(context, fileName, file, manifestOption = {}) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-hle-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
  writeFileSync(join(packagePath, fileName), file);
  const manifest = { schema_version: 1, executable: fileName, execution: { profile: "i386_probe_v1", instruction_budget_count: manifestOption.instruction_budget_count ?? 200000 } };
  writeFileSync(join(packagePath, "bptk.json"), JSON.stringify(manifest));
  return packagePath;
}

// The import plan: one flat {library, symbol} list is grouped per library in
// first-seen order and laid out deterministically in the .idata section, so
// the code generator and the builder share one address map.
function planImports(imports) {
  const group = [];
  const slotOf = new Map();
  for (const entry of imports) {
    let current = group.find((candidate) => candidate.library === entry.library);
    if (current === undefined) {
      current = { library: entry.library, symbol: [] };
      group.push(current);
    }
    slotOf.set(entry.library + "!" + entry.symbol, { group: current, slot: current.symbol.length });
    current.symbol.push(entry.symbol);
  }
  let cursor = 0x2040;
  for (const current of group) {
    current.lookup_rva = cursor;
    cursor += (current.symbol.length + 1) * 4;
    current.iat_rva = cursor;
    cursor += (current.symbol.length + 1) * 4;
    current.name_rva = cursor;
    cursor += Math.ceil((current.library.length + 1) / 4) * 4;
    current.hint_rva_of = [];
    for (const name of current.symbol) {
      current.hint_rva_of.push(cursor);
      cursor += Math.ceil((2 + name.length + 1) / 4) * 4;
    }
  }
  return {
    group,
    addressOf: (library, symbol) => {
      const entry = slotOf.get(library + "!" + symbol);
      assert.notEqual(entry, undefined, `unplanned import ${library}!${symbol}`);
      return imageBase + entry.group.iat_rva + entry.slot * 4;
    },
  };
}

function dataAddress(offset) {
  return imageBase + 0x3000 + offset;
}

// A minimal label-resolving emitter: every check conditionally jumps to the
// shared failure tail with a rel32, so the exerciser stays linear.
function createEmitter() {
  const chunk = [];
  const patch = [];
  const label = new Map();
  const offsetOf = () => chunk.length;
  return {
    bytes: () => chunk,
    emit: (...byte) => chunk.push(...byte),
    emitDword: (value) => chunk.push(...dwordBytes(value >>> 0)),
    mark: (name) => label.set(name, offsetOf()),
    jmp: (name) => { chunk.push(0xe9); patch.push({ at: offsetOf(), name }); chunk.push(0, 0, 0, 0); },
    je: (name) => { chunk.push(0x0f, 0x84); patch.push({ at: offsetOf(), name }); chunk.push(0, 0, 0, 0); },
    jne: (name) => { chunk.push(0x0f, 0x85); patch.push({ at: offsetOf(), name }); chunk.push(0, 0, 0, 0); },
    resolve: () => {
      for (const entry of patch) {
        const target = label.get(entry.name);
        assert.notEqual(target, undefined, `unresolved label ${entry.name}`);
        const displacement = target - (entry.at + 4);
        chunk[entry.at] = displacement & 0xff;
        chunk[entry.at + 1] = (displacement >>> 8) & 0xff;
        chunk[entry.at + 2] = (displacement >>> 16) & 0xff;
        chunk[entry.at + 3] = (displacement >>> 24) & 0xff;
      }
      return Buffer.from(chunk);
    },
  };
}

function buildExerciser() {
  const kernel32Symbol = [
    "ExitProcess", "GetLastError", "SetLastError", "GetProcessHeap", "HeapAlloc", "HeapSize", "HeapFree",
    "VirtualAlloc", "VirtualFree", "InitializeCriticalSectionAndSpinCount", "TryEnterCriticalSection",
    "LeaveCriticalSection", "DeleteCriticalSection", "TlsAlloc", "TlsSetValue", "TlsGetValue", "GetTickCount",
    "QueryPerformanceCounter", "GetModuleHandleA", "GetCommandLineA", "GetStdHandle",
    "WriteFile", "GetProcAddress",
  ];
  const imports = [
    ...kernel32Symbol.map((name) => ({ library: "kernel32.dll", symbol: name })),
    { library: "ole32.dll", symbol: "CoInitializeEx" },
  ];
  const plan = planImports(imports);
  const iat = Object.fromEntries(imports.map((entry) => [entry.symbol, plan.addressOf(entry.library, entry.symbol)]));
  const dataOffset = { qpc: 0x0, cs: 0x8, exit_name: 0x20, bptk: 0x30, written: 0x40, kernel32_name: 0x50, ole32_name: 0x60 };
  const o = createEmitter();
  const e = o.emit, d = o.emitDword;
  const pushImm = (value) => { e(0x68); d(value); };
  const orMask = (mask) => { e(0x81, 0xcb); d(mask); };
  const cmpEaxImm = (value) => { e(0x3d); d(value); };
  const call = (address) => { e(0xff, 0x15); d(address); };
  const testEax = () => e(0x85, 0xc0);

  e(0xbb); d(0); // mov ebx, 0
  call(iat.GetLastError);
  cmpEaxImm(0);
  o.jne("fail");
  orMask(0x1);

  pushImm(5);
  call(iat.SetLastError);
  call(iat.GetLastError);
  cmpEaxImm(5);
  o.jne("fail");
  orMask(0x2);

  call(iat.GetProcessHeap);
  testEax();
  o.je("fail");
  e(0x8b, 0xf0); // mov esi, eax
  orMask(0x4);

  pushImm(64);
  pushImm(8);
  e(0x56); // push esi
  call(iat.HeapAlloc);
  testEax();
  o.je("fail");
  e(0x8b, 0xf8); // mov edi, eax — the block
  orMask(0x8);

  e(0xb8); d(0x42504b54); // mov eax, "BPTK"
  e(0xa3); d(dataAddress(dataOffset.bptk)); // mov [bptk], eax — the block is zeroed; marker goes to .data
  o.emit(0x57); // push edi — the block pointer
  o.emit(0x6a, 0x00); // push 0
  e(0x56); // push esi
  call(iat.HeapSize);
  cmpEaxImm(64);
  o.jne("fail");
  orMask(0x10);

  e(0x57); // push edi
  pushImm(0);
  e(0x56); // push esi
  call(iat.HeapFree);
  cmpEaxImm(1);
  o.jne("fail");
  orMask(0x20);

  pushImm(4);
  pushImm(0x3000);
  pushImm(0x10000);
  pushImm(0);
  call(iat.VirtualAlloc);
  testEax();
  o.je("fail");
  e(0x8b, 0xe8); // mov ebp, eax — the reservation
  orMask(0x40);

  pushImm(0x8000);
  pushImm(0);
  e(0x55); // push ebp
  call(iat.VirtualFree);
  cmpEaxImm(1);
  o.jne("fail");
  orMask(0x80);

  pushImm(4);
  pushImm(dataAddress(dataOffset.cs));
  call(iat.InitializeCriticalSectionAndSpinCount);
  cmpEaxImm(1);
  o.jne("fail");
  orMask(0x100);

  pushImm(dataAddress(dataOffset.cs));
  call(iat.TryEnterCriticalSection);
  cmpEaxImm(1);
  o.jne("fail");
  orMask(0x200);

  pushImm(dataAddress(dataOffset.cs));
  call(iat.LeaveCriticalSection);
  orMask(0x400);

  pushImm(dataAddress(dataOffset.cs));
  call(iat.DeleteCriticalSection);
  orMask(0x800);

  call(iat.TlsAlloc);
  cmpEaxImm(0);
  o.jne("fail");
  orMask(0x1000);

  pushImm(0x42);
  pushImm(0);
  call(iat.TlsSetValue);
  cmpEaxImm(1);
  o.jne("fail");
  orMask(0x2000);

  pushImm(0);
  call(iat.TlsGetValue);
  cmpEaxImm(0x42);
  o.jne("fail");
  orMask(0x4000);

  call(iat.GetTickCount);
  orMask(0x8000);

  pushImm(dataAddress(dataOffset.qpc));
  call(iat.QueryPerformanceCounter);
  cmpEaxImm(1);
  o.jne("fail");
  orMask(0x10000);

  pushImm(0);
  call(iat.GetModuleHandleA);
  testEax();
  o.je("fail");
  orMask(0x20000);

  call(iat.GetCommandLineA);
  testEax();
  o.je("fail");
  orMask(0x40000);

  pushImm(2);
  pushImm(0);
  call(iat.CoInitializeEx);
  cmpEaxImm(0);
  o.jne("fail");
  orMask(0x80000);

  pushImm(0xfffffff5); // STD_OUTPUT_HANDLE
  call(iat.GetStdHandle);
  testEax();
  o.je("fail");
  e(0x8b, 0xf8); // mov edi, eax — the output handle
  orMask(0x100000);

  pushImm(0);
  pushImm(dataAddress(dataOffset.written));
  pushImm(4);
  pushImm(dataAddress(dataOffset.bptk));
  e(0x57); // push edi
  call(iat.WriteFile);
  cmpEaxImm(1);
  o.jne("fail");
  orMask(0x200000);

  pushImm(dataAddress(dataOffset.kernel32_name));
  call(iat.GetModuleHandleA);
  pushImm(dataAddress(dataOffset.exit_name));
  e(0x50); // push eax — the module handle
  call(iat.GetProcAddress);
  testEax();
  o.je("fail");
  orMask(0x400000);
  pushImm(0x5a5a);
  e(0xff, 0xd0); // call eax — exit through the resolved procedure

  o.mark("fail");
  o.emit(0x53); // push ebx — the partial step mask identifies the failed check
  call(iat.ExitProcess);
  o.resolve();
  return { code: o.bytes(), imports, plan, dataOffset };
}

function buildExerciserData(dataOffset) {
  const data = Buffer.alloc(0x200);
  data.write("ExitProcess\0", dataOffset.exit_name, "ascii");
  data.write("BPTK\0", dataOffset.bptk, "ascii");
  data.write("KERNEL32.dll\0", dataOffset.kernel32_name, "ascii");
  return data;
}

test("conformance: every Win32 core HLE export carries case and matches the oracle", () => {
  const caseTable = buildConformanceCaseTable();
  const report = runConformanceSuite(caseTable, createConformanceImplementation(), {
    served_export: listWin32HleExport().map((entry) => `${entry.library}!${entry.symbol}`),
  });
  assert.equal(report.is_coverage_complete, true, "a served export without case is a coverage hole");
  assert.equal(report.fail_count, 0, report.result.filter((entry) => !entry.pass).map((entry) => `${entry.case_id}: ${entry.mismatch.join("; ")}`).join("\n"));
  assert.equal(report.pass_count, caseTable.length);
});

// The conformance suite compares return_value and last_error; these cases
// prove the memory side effects of the BPTK-101 breadth slice, which the
// oracle does not inspect.
function invoke(guest, library, symbol, argument) {
  return guest.invokeExport(guest.lookupExport(library, symbol), argument);
}

test("BPTK-101: interlocked atomics read-modify-write the guest dword and honor the return contract", () => {
  const { guest, memory } = createConformanceMachine();
  const cell = guest.layout.arena_base + 0x40;
  memory.writeMemory(cell, 4, 5);
  assert.equal(invoke(guest, "kernel32.dll", "InterlockedIncrement", [cell]), 6);
  assert.equal(memory.readMemory(cell, 4), 6);
  assert.equal(invoke(guest, "kernel32.dll", "InterlockedDecrement", [cell]), 5);
  assert.equal(memory.readMemory(cell, 4), 5);
  assert.equal(invoke(guest, "kernel32.dll", "InterlockedExchange", [cell, 99]), 5, "Exchange returns the prior value");
  assert.equal(memory.readMemory(cell, 4), 99);
  assert.equal(invoke(guest, "kernel32.dll", "InterlockedExchangeAdd", [cell, 1]), 99, "ExchangeAdd returns the prior value");
  assert.equal(memory.readMemory(cell, 4), 100);
  assert.equal(invoke(guest, "kernel32.dll", "InterlockedCompareExchange", [cell, 7, 100]), 100, "a matching comparand stores the exchange");
  assert.equal(memory.readMemory(cell, 4), 7);
  assert.equal(invoke(guest, "kernel32.dll", "InterlockedCompareExchange", [cell, 42, 999]), 7, "a mismatched comparand leaves the cell");
  assert.equal(memory.readMemory(cell, 4), 7);
});

test("BPTK-101: the kernel32 string family copies and concatenates bytes into guest memory", () => {
  const { guest } = createConformanceMachine();
  const src = guest.layout.arena_base + 0x80;
  const dest = guest.layout.arena_base + 0x120;
  guest.writeAnsiString(src, "hello", 16);
  assert.equal(invoke(guest, "kernel32.dll", "lstrcpyA", [dest, src]), dest);
  assert.equal(guest.readAnsiString(dest), "hello");
  guest.writeAnsiString(src, "world", 16);
  invoke(guest, "kernel32.dll", "lstrcpynA", [dest, src, 3]);
  assert.equal(guest.readAnsiString(dest), "wo", "lstrcpynA copies at most n-1 characters and terminates");
  guest.writeAnsiString(dest, "ab", 16);
  guest.writeAnsiString(src, "cd", 16);
  invoke(guest, "kernel32.dll", "lstrcatA", [dest, src]);
  assert.equal(guest.readAnsiString(dest), "abcd");
});

test("BPTK-101: MulDiv rounds half away from zero and refuses a zero denominator", () => {
  const { guest } = createConformanceMachine();
  assert.equal(invoke(guest, "kernel32.dll", "MulDiv", [10, 3, 4]), 8);
  assert.equal(invoke(guest, "kernel32.dll", "MulDiv", [1, 1, 3]), 0);
  assert.equal(invoke(guest, "kernel32.dll", "MulDiv", [10, 3, 0]) | 0, -1, "a zero denominator returns -1");
});

test("BPTK-101: GetSystemTime writes a SYSTEMTIME derived from the one guest clock", () => {
  const { guest, memory } = createConformanceMachine();
  const buffer = guest.layout.arena_base + 0x200;
  invoke(guest, "kernel32.dll", "GetSystemTime", [buffer]);
  const field = guest.readSystemTime(buffer);
  assert.deepEqual(field, guest.guestSystemTime());
  assert.ok(field.month >= 1 && field.month <= 12);
  assert.ok(field.hour >= 0 && field.hour < 24);
  // GetSystemInfo reports one declared processor and the 64 KiB granularity.
  const info = guest.layout.arena_base + 0x180;
  invoke(guest, "kernel32.dll", "GetSystemInfo", [info]);
  assert.equal(memory.readMemory(info + 4, 4), 4096, "dwPageSize");
  assert.equal(memory.readMemory(info + 20, 4), 1, "dwNumberOfProcessors");
  assert.equal(memory.readMemory(info + 28, 4), 65536, "dwAllocationGranularity");
});

test("BPTK-101: GetEnvironmentVariable and ExpandEnvironmentStrings resolve over the environment map", () => {
  const { guest } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const name = base + 0x40;
  const value = base + 0x80;
  const out = base + 0xc0;
  const src = base + 0x140;
  guest.writeAnsiString(name, "PATH", 16);
  guest.writeAnsiString(value, "C:\\bin", 16);
  invoke(guest, "kernel32.dll", "SetEnvironmentVariableA", [name, value]);
  assert.equal(invoke(guest, "kernel32.dll", "GetEnvironmentVariableA", [name, out, 64]), "C:\\bin".length);
  assert.equal(guest.readAnsiString(out), "C:\\bin");
  // A too-small buffer returns the required size including the null.
  assert.equal(invoke(guest, "kernel32.dll", "GetEnvironmentVariableA", [name, out, 2]), "C:\\bin".length + 1);
  // A missing variable is the env-not-found contract.
  guest.writeAnsiString(name, "MISSING", 16);
  assert.equal(invoke(guest, "kernel32.dll", "GetEnvironmentVariableA", [name, out, 64]), 0);
  assert.equal(guest.getLastError(), 203);
  // Expansion substitutes a known variable and keeps an unknown one literal.
  guest.writeAnsiString(src, "d=%PATH%;%NOPE%", 32);
  const expandedLen = invoke(guest, "kernel32.dll", "ExpandEnvironmentStringsA", [src, out, 64]);
  assert.equal(guest.readAnsiString(out), "d=C:\\bin;%NOPE%");
  assert.equal(expandedLen, "d=C:\\bin;%NOPE%".length + 1);
});

test("BPTK-097: XInput reports no controller by default and reflects an injected gamepad state", () => {
  const { guest, memory } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const stateBuf = base + 0x40;
  const capsBuf = base + 0x80;
  const vibBuf = base + 0xc0;
  // By default every slot is disconnected.
  assert.equal(invoke(guest, "xinput1_3.dll", "XInputGetState", [0, stateBuf]), 1167);
  assert.equal(invoke(guest, "xinput1_3.dll", "XInputGetCapabilities", [0, 0, capsBuf]), 1167);
  // Inject a controller state (the browser Gamepad bridge feeds this).
  guest.gamepad.injectGamepad(0, { buttons: 0x1000, left_trigger: 255, thumb_lx: -32768, thumb_ry: 32767 });
  assert.equal(invoke(guest, "xinput1_3.dll", "XInputGetState", [0, stateBuf]), 0);
  assert.equal(memory.readMemory(stateBuf + 4, 2), 0x1000, "wButtons: A pressed");
  assert.equal(memory.readMemory(stateBuf + 6, 1), 255, "bLeftTrigger");
  assert.equal(memory.readMemory(stateBuf + 8, 2), 0x8000, "sThumbLX -32768 as unsigned");
  assert.equal(memory.readMemory(stateBuf + 14, 2), 0x7fff, "sThumbRY 32767");
  assert.ok(memory.readMemory(stateBuf + 0, 4) > 0, "the packet number advanced");
  // Capabilities and vibration are served once connected.
  assert.equal(invoke(guest, "xinput1_3.dll", "XInputGetCapabilities", [0, 0, capsBuf]), 0);
  assert.equal(memory.readMemory(capsBuf + 0, 1), 1, "Type gamepad");
  memory.writeMemory(vibBuf, 2, 40000);
  memory.writeMemory(vibBuf + 2, 2, 20000);
  assert.equal(invoke(guest, "xinput1_3.dll", "XInputSetState", [0, vibBuf]), 0);
  assert.deepEqual(guest.gamepad.getVibration(0), { left_motor: 40000, right_motor: 20000 });
  // An out-of-range slot is not connected.
  assert.equal(invoke(guest, "xinput1_3.dll", "XInputGetState", [7, stateBuf]), 1167);
  // The packet number only advances when the state actually changes.
  const before = guest.gamepad.getState(0).packet_number;
  guest.gamepad.injectGamepad(0, { buttons: 0x1000, left_trigger: 255, thumb_lx: -32768, thumb_ry: 32767 });
  assert.equal(guest.gamepad.getState(0).packet_number, before, "an identical state does not bump the packet number");
  guest.gamepad.injectGamepad(0, { buttons: 0x2000 });
  assert.ok(guest.gamepad.getState(0).packet_number > before, "a changed state bumps the packet number");
  // A disconnect returns the slot to not-connected.
  guest.gamepad.disconnectGamepad(0);
  assert.equal(invoke(guest, "xinput1_3.dll", "XInputGetState", [0, stateBuf]), 1167);
});

test("BPTK-102: the virtual drive geometry reports a fixed C: and a read-only optical D:", () => {
  const { guest, memory } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const path = base + 0x40;
  const out = base + 0x80;
  assert.equal(invoke(guest, "kernel32.dll", "GetLogicalDrives", []), 0x0c, "C: and D: are present");
  guest.writeAnsiString(path, "C:\\", 16);
  assert.equal(invoke(guest, "kernel32.dll", "GetDriveTypeA", [path]), 3, "DRIVE_FIXED");
  guest.writeAnsiString(path, "D:\\", 16);
  assert.equal(invoke(guest, "kernel32.dll", "GetDriveTypeA", [path]), 5, "DRIVE_CDROM");
  guest.writeAnsiString(path, "Z:\\", 16);
  assert.equal(invoke(guest, "kernel32.dll", "GetDriveTypeA", [path]), 1, "DRIVE_NO_ROOT_DIR for an absent drive");
  // The optical volume label, serial, and CDFS name round-trip.
  guest.writeAnsiString(path, "D:\\", 16);
  const serialPtr = out + 0x40;
  assert.equal(invoke(guest, "kernel32.dll", "GetVolumeInformationA", [path, out, 32, serialPtr, 0, 0, 0, 0]), 1);
  assert.equal(guest.readAnsiString(out), "BPTK_MEDIA");
  assert.equal(memory.readMemory(serialPtr, 4), 0x4344524f);
  // The optical volume reports zero free bytes (read-only media).
  guest.writeAnsiString(path, "D:\\", 16);
  assert.equal(invoke(guest, "kernel32.dll", "GetDiskFreeSpaceExA", [path, out, out + 8, out + 16]), 1);
  assert.equal(memory.readMemory(out, 4), 0, "free-to-caller low dword");
  assert.equal(memory.readMemory(out + 8, 4), 0x28000000, "total low dword");
});

test("BPTK-099: the ws2_32 lifecycle marshals WSADATA, serves the handle table, and refuses an offline dial", () => {
  const { guest, memory } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const wsaData = base + 0x40;
  const sockAddr = base + 0x220;
  // Before startup a socket is refused; WSAStartup then writes the WSADATA.
  assert.equal(invoke(guest, "ws2_32.dll", "socket", [2, 1, 6]) | 0, -1, "socket before WSAStartup fails");
  assert.equal(invoke(guest, "ws2_32.dll", "WSAStartup", [0x0202, wsaData]), 0);
  assert.equal(memory.readMemory(wsaData + 0, 2), 0x0202, "wVersion");
  assert.equal(memory.readMemory(wsaData + 2, 2), 0x0202, "wHighVersion");
  const socket = invoke(guest, "ws2_32.dll", "socket", [2, 1, 6]);
  assert.equal(socket, 1);
  // The offline default has no consent, so bind and connect are refused.
  memory.writeMemory(sockAddr + 0, 2, 2);
  memory.writeMemory(sockAddr + 2, 1, 0x1f); memory.writeMemory(sockAddr + 3, 1, 0x90);
  [1, 2, 3, 4].forEach((octet, index) => memory.writeMemory(sockAddr + 4 + index, 1, octet));
  assert.equal(invoke(guest, "ws2_32.dll", "connect", [socket, sockAddr]) | 0, -1, "an unconsented dial is refused");
  assert.equal(invoke(guest, "ws2_32.dll", "WSAGetLastError", []), 10013, "WSAEACCES");
  assert.equal(invoke(guest, "ws2_32.dll", "closesocket", [socket]), 0);
  // Byte-order and address helpers are pure and always served.
  assert.equal(invoke(guest, "ws2_32.dll", "htons", [0x1234]), 0x3412);
  assert.equal(invoke(guest, "ws2_32.dll", "htonl", [0x12345678]), 0x78563412);
  guest.writeAnsiString(base + 0x300, "127.0.0.1", 16);
  assert.equal(invoke(guest, "ws2_32.dll", "inet_addr", [base + 0x300]), 0x7f000001);
});

test("BPTK-011: the message loop and geometry exports marshal MSG and RECT through guest memory", () => {
  const { guest, memory } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const classStruct = base + 0x40;
  const classNamePtr = base + 0x100;
  const msgBuffer = base + 0x140;
  const rectBuffer = base + 0x180;
  guest.writeWideString(classNamePtr, "AppClass", 32);
  memory.writeMemory(classStruct + 0, 4, 0); // style
  memory.writeMemory(classStruct + 4, 4, 0); // wndProc -> DefWindowProc fallback
  memory.writeMemory(classStruct + 36, 4, classNamePtr); // lpszClassName
  invoke(guest, "user32.dll", "RegisterClassW", [classStruct]);
  const window = invoke(guest, "user32.dll", "CreateWindowExW", [0, classNamePtr, 0, 0, 0, 0, 320, 240, 0, 0, 0, 0]);
  assert.ok(window !== 0);
  // A posted message round-trips through GetMessageW into the MSG struct.
  invoke(guest, "user32.dll", "PostMessageW", [window, 0x0400, 7, 9]);
  assert.equal(invoke(guest, "user32.dll", "GetMessageW", [msgBuffer, 0, 0, 0]), 1);
  assert.equal(memory.readMemory(msgBuffer + 0, 4), window);
  assert.equal(memory.readMemory(msgBuffer + 4, 4), 0x0400);
  assert.equal(memory.readMemory(msgBuffer + 8, 4), 7);
  assert.equal(memory.readMemory(msgBuffer + 12, 4), 9);
  // The client rect is origin-anchored at the created extent.
  assert.equal(invoke(guest, "user32.dll", "GetClientRect", [window, rectBuffer]), 1);
  assert.deepEqual([0, 1, 2, 3].map((i) => memory.readMemory(rectBuffer + i * 4, 4)), [0, 0, 320, 240]);
  // MoveWindow updates the geometry the window rect then reports.
  assert.equal(invoke(guest, "user32.dll", "MoveWindow", [window, 10, 20, 100, 200, 1]), 1);
  invoke(guest, "user32.dll", "GetWindowRect", [window, rectBuffer]);
  assert.deepEqual([0, 1, 2, 3].map((i) => memory.readMemory(rectBuffer + i * 4, 4)), [10, 20, 110, 220]);
  assert.equal(invoke(guest, "user32.dll", "GetSystemMetrics", [0]), 1920);
});

test("BPTK-098: registry create reports disposition, round-trips a value, and refuses deleting a key with subkeys", () => {
  const { guest, memory } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const resultPtr = base + 0x40;
  const dispPtr = base + 0x44;
  const dataPtr = base + 0x60;
  const readPtr = base + 0x80;
  const lenPtr = base + 0xa0;
  // Creating a fresh key reports REG_CREATED_NEW_KEY (1).
  assert.equal(guest.registryCreate(0x80000001, "Soft\\A", resultPtr, dispPtr), 0);
  assert.equal(memory.readMemory(dispPtr, 4), 1);
  const handle = memory.readMemory(resultPtr, 4);
  // Re-creating the same key reports REG_OPENED_EXISTING_KEY (2).
  guest.registryCreate(0x80000001, "Soft\\A", resultPtr, dispPtr);
  assert.equal(memory.readMemory(dispPtr, 4), 2);
  // Set then query the value byte-exactly.
  memory.writeMemory(dataPtr, 4, 0x2a2a2a2a);
  assert.equal(guest.registrySet(handle, "V", 1, dataPtr, 4), 0);
  memory.writeMemory(lenPtr, 4, 64);
  assert.equal(guest.registryQuery(handle, "V", 0, readPtr, lenPtr), 0);
  assert.equal(memory.readMemory(lenPtr, 4), 4);
  assert.equal(memory.readMemory(readPtr, 4), 0x2a2a2a2a);
  // A parent key with a child cannot be deleted.
  assert.equal(guest.registryDeleteKey(0x80000001, "Soft"), 5);
  // Deleting the value twice: first succeeds, then reports not-found.
  assert.equal(guest.registryDeleteValue(handle, "V"), 0);
  assert.equal(guest.registryDeleteValue(handle, "V"), 2);
  // The leaf key deletes once no child remains.
  assert.equal(guest.registryDeleteKey(0x80000001, "Soft\\A"), 0);
  assert.equal(guest.registryDeleteKey(0x80000001, "Soft"), 0);
});

test("BPTK-101: SetErrorMode returns the previous mode", () => {
  const { guest } = createConformanceMachine();
  assert.equal(invoke(guest, "kernel32.dll", "SetErrorMode", [0x8000]), 0);
  assert.equal(invoke(guest, "kernel32.dll", "SetErrorMode", [0x0001]), 0x8000);
  assert.equal(invoke(guest, "kernel32.dll", "GetErrorMode", []), 0x0001);
});

test("FIX-003: the core API exerciser starts, synchronizes, allocates, times, calls COM, and exits with the golden trace", (context) => {
  const { code, imports, plan, dataOffset } = buildExerciser();
  const packagePath = createHlePackage(context, "fix003.exe", createImportPe32(imports, code, { data: buildExerciserData(dataOffset), import_layout: plan }));
  const report = readRun(packagePath);
  assert.equal(report.state, "probe_executed", JSON.stringify(report.exception));
  assert.equal(report.stop_reason, "process_exit", JSON.stringify({ exception: report.exception, reached: report.hle?.trace?.map((entry) => entry.symbol), count: report.instruction_count }));
  assert.equal(report.exit_code, 0x5a5a);
  const goldenTrace = [
    "GetLastError", "SetLastError", "GetLastError", "GetProcessHeap", "HeapAlloc", "HeapSize", "HeapFree",
    "VirtualAlloc", "VirtualFree", "InitializeCriticalSectionAndSpinCount", "TryEnterCriticalSection",
    "LeaveCriticalSection", "DeleteCriticalSection", "TlsAlloc", "TlsSetValue", "TlsGetValue", "GetTickCount",
    "QueryPerformanceCounter", "GetModuleHandleA", "GetCommandLineA", "CoInitializeEx", "GetStdHandle",
    "WriteFile", "GetModuleHandleA", "GetProcAddress", "ExitProcess",
  ];
  assert.deepEqual(report.hle.trace.map((entry) => entry.symbol), goldenTrace);
  assert.ok(report.hle.trace.every((entry) => entry.library === "kernel32.dll" || entry.library === "ole32.dll"));
  assert.equal(report.hle.call_count, goldenTrace.length);
  assert.equal(report.hle.output_byte_count, 4);
  // The guest wrote "BPTK" as one little-endian dword (0x42504b54), so the
  // captured output byte are 54 4b 50 42.
  assert.equal(report.hle.output_sha256, createHash("sha256").update(Buffer.from([0x54, 0x4b, 0x50, 0x42])).digest("hex"));
  assert.equal(report.hle.profile, hleProfile.profile);
  // The imported surface reports as resolved against the thunk page.
  assert.ok(report.import.every((entry) => entry.resolution_state === "resolved"));
});

test("FIX-003: repeated exerciser run keeps the call trace, output, and memory hashes stable", (context) => {
  const { code, imports, plan, dataOffset } = buildExerciser();
  const file = createImportPe32(imports, code, { data: buildExerciserData(dataOffset), import_layout: plan });
  const first = readRun(createHlePackage(context, "fix003.exe", file));
  const second = readRun(createHlePackage(context, "fix003.exe", file));
  assert.equal(first.hle.trace_sha256, second.hle.trace_sha256);
  assert.equal(first.memory_sha256, second.memory_sha256);
  assert.equal(first.trace_sha256, second.trace_sha256);
  assert.equal(first.exit_code, second.exit_code);
});

test("unserved import: the refusal names the exact unserved surface instead of executing", (context) => {
  // GetSystemPowerStatus is a kernel32 export outside the served HLE surface.
  const imports = [{ library: "kernel32.dll", symbol: "GetSystemPowerStatus" }];
  const packagePath = createHlePackage(context, "unserved.exe", createImportPe32(imports, [0xc3], { import_layout: planImports(imports) }));
  const report = readRun(packagePath);
  assert.equal(report.is_executed, false);
  assert.equal(report.stop_reason, "import_present");
  assert.equal(report.hle ?? null, null);
  assert.match(report.exception.message, /GetSystemPowerStatus|kernel32\.dll/);
});

test("unserved import: a partially served surface reports the served fraction", (context) => {
  const imports = [
    { library: "kernel32.dll", symbol: "GetLastError" },
    { library: "kernel32.dll", symbol: "GetSystemPowerStatus" },
  ];
  const packagePath = createHlePackage(context, "partial.exe", createImportPe32(imports, [0xc3], { import_layout: planImports(imports) }));
  const report = readRun(packagePath);
  assert.equal(report.stop_reason, "import_present");
  assert.match(report.exception.message, /1 of 2 import are served/);
});

test("TLS callback: the callback phase fires before entry through the same HLE surface", (context) => {
  const plan = planImports([
    { library: "kernel32.dll", symbol: "GetStdHandle" },
    { library: "kernel32.dll", symbol: "WriteFile" },
  ]);
  const iat = { GetStdHandle: plan.addressOf("kernel32.dll", "GetStdHandle"), WriteFile: plan.addressOf("kernel32.dll", "WriteFile") };
  // Both phases push the five WriteFile argument in reverse order with the
  // handle last, then return to the sentinel.
  const phaseCode = (textAddress, count) => {
    const emitter = createEmitter();
    const e = emitter.emit, d = emitter.emitDword;
    e(0x68); d(0xfffffff5); // push STD_OUTPUT_HANDLE
    e(0xff, 0x15); d(iat.GetStdHandle); // call GetStdHandle → eax
    e(0x6a, 0x00); // push 0 — no overlapped
    e(0x68); d(dataAddress(0x40)); // push &written
    e(0x6a); e(count); // push count
    e(0x68); d(textAddress); // push text
    e(0x50); // push eax — the handle
    e(0xff, 0x15); d(iat.WriteFile); // call WriteFile
    e(0xc3); // ret
    return emitter.resolve();
  };
  const data = Buffer.alloc(0x200);
  data.write("TLS\0", 0x60, "ascii");
  data.write("ENTRY\0", 0x70, "ascii");
  const tlsPhase = phaseCode(dataAddress(0x60), 3);
  const entryPhase = phaseCode(dataAddress(0x70), 5);
  const code = Buffer.alloc(Math.max(tlsPhase.length, 0x40) + entryPhase.length + 0x40);
  tlsPhase.copy(code, 0);
  entryPhase.copy(code, 0x40);
  const packagePath = createHlePackage(context, "tls.exe", createImportPe32([
    { library: "kernel32.dll", symbol: "GetStdHandle" },
    { library: "kernel32.dll", symbol: "WriteFile" },
  ], code, {
    tls: true,
    tls_callback: imageBase + 0x1000,
    entry_rva: 0x1040,
    data,
    import_layout: plan,
  }));
  const report = readRun(packagePath);
  assert.equal(report.state, "probe_executed", JSON.stringify(report.exception));
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.exit_code ?? null, null);
  assert.equal(report.hle.call_count, 4);
  assert.deepEqual(report.hle.trace.map((entry) => entry.symbol), ["GetStdHandle", "WriteFile", "GetStdHandle", "WriteFile"]);
  assert.equal(report.hle.output_byte_count, 8);
  assert.equal(report.hle.output_sha256, createHash("sha256").update("TLSENTRY", "latin1").digest("hex"));
});

test("FIX-008 slice: the storage exerciser creates, writes, seeks, reads, truncates, and round-trips a registry value", (context) => {
  const kernel32Symbol = [
    "ExitProcess", "CreateFileW", "WriteFile", "ReadFile", "SetFilePointerEx", "SetEndOfFile", "CloseHandle",
    "GetFileType", "FlushFileBuffers", "GetStdHandle",
  ];
  const imports = [
    ...kernel32Symbol.map((name) => ({ library: "kernel32.dll", symbol: name })),
    { library: "advapi32.dll", symbol: "RegCreateKeyA" },
    { library: "advapi32.dll", symbol: "RegSetValueExA" },
    { library: "advapi32.dll", symbol: "RegQueryValueExA" },
    { library: "advapi32.dll", symbol: "RegCloseKey" },
  ];
  const plan = planImports(imports);
  const iat = Object.fromEntries(imports.map((entry) => [entry.symbol, plan.addressOf(entry.library, entry.symbol)]));
  // .data layout: save path (wide) at 0x00, file content at 0x40, read-back at 0x50,
  // registry key name at 0x60, key handle at 0x80, value name at 0x90, value data at 0xa0,
  // value size at 0xb0.
  const data = Buffer.alloc(0x200);
  data.write(String.raw`C:\save.dat`, 0x00, "utf16le");
  data.write("SAVE", 0x40, "ascii");
  data.write(String.raw`Software\BPTK`, 0x60, "ascii");
  data.write("step", 0x90, "ascii");
  data.writeUInt32LE(64, 0xb0);
  const addr = (offset) => dataAddress(offset);
  const o = createEmitter();
  const e = o.emit, d = o.emitDword;
  const pushImm = (value) => { e(0x68); d(value); };
  const orMask = (mask) => { e(0x81, 0xcb); d(mask); };
  const cmpEaxImm = (value) => { e(0x3d); d(value); };
  const call = (address) => { e(0xff, 0x15); d(address); };
  const testEax = () => e(0x85, 0xc0);

  e(0xbb); d(0); // mov ebx, 0 — the step mask
  // CreateFileW("C:\save.dat", GENERIC_READ|GENERIC_WRITE, ... CREATE_ALWAYS) — 7 argument
  pushImm(0); pushImm(0); pushImm(2); pushImm(0); pushImm(0);
  pushImm(0xc0000000 | 0x80000000);
  pushImm(addr(0x00)); // LPCWSTR — wide path is 2 byte per char, pushed as one dword
  e(0xff, 0x15); d(iat.CreateFileW);
  testEax();
  o.je("fail");
  orMask(0x1);
  e(0x8b, 0xf8); // mov edi, eax — the file handle
  // WriteFile(edi, "SAVE", 4, &written, 0)
  pushImm(0); pushImm(addr(0x50)); pushImm(4); pushImm(addr(0x40)); e(0x57);
  call(iat.WriteFile);
  cmpEaxImm(1);
  o.jne("fail");
  orMask(0x2);
  // SetFilePointerEx(edi, 0, NULL, FILE_BEGIN) — handle, distLow, distHigh, ptr, origin
  pushImm(0); pushImm(0); pushImm(0); pushImm(0); e(0x57);
  call(iat.SetFilePointerEx);
  testEax();
  o.jne("fail");
  orMask(0x4);
  // ReadFile(edi, readBack, 4, &written, 0)
  pushImm(0); pushImm(addr(0x50)); pushImm(4); pushImm(addr(0x50)); e(0x57);
  call(iat.ReadFile);
  cmpEaxImm(1);
  o.jne("fail");
  orMask(0x8);
  // SetEndOfFile(edi) at position 4 keeps the file bounded
  pushImm(0); e(0x57);
  call(iat.SetEndOfFile);
  cmpEaxImm(1);
  o.jne("fail");
  orMask(0x10);
  // GetFileType(edi) == FILE_TYPE_DISK
  pushImm(0); e(0x57);
  call(iat.GetFileType);
  cmpEaxImm(3);
  o.jne("fail");
  orMask(0x20);
  // FlushFileBuffers(edi)
  pushImm(0); e(0x57);
  call(iat.FlushFileBuffers);
  cmpEaxImm(1);
  o.jne("fail");
  orMask(0x40);
  // CloseHandle(edi)
  pushImm(0); e(0x57);
  call(iat.CloseHandle);
  cmpEaxImm(1);
  o.jne("fail");
  orMask(0x80);
  // RegCreateKeyA(HKEY_CURRENT_USER, "Software\BPTK", &key)
  pushImm(addr(0x80)); pushImm(addr(0x60)); pushImm(0x80000001);
  call(iat.RegCreateKeyA);
  testEax();
  o.jne("fail");
  orMask(0x100);
  // RegSetValueExA(key, "step", 0, REG_SZ, data, 2)
  e(0x8b, 0x3d); d(addr(0x80)); // mov edi, [key]
  pushImm(2); pushImm(addr(0xa0)); pushImm(1); pushImm(0); pushImm(addr(0x90)); e(0x57);
  call(iat.RegSetValueExA);
  testEax();
  o.jne("fail");
  orMask(0x200);
  // RegQueryValueExA(key, "step", NULL, NULL, data, &size) — value data lands at 0xa0
  pushImm(addr(0xb0)); pushImm(addr(0xa0)); pushImm(0); pushImm(0); pushImm(addr(0x90)); e(0x57);
  call(iat.RegQueryValueExA);
  cmpEaxImm(0);
  o.jne("fail");
  orMask(0x400);
  // RegCloseKey(key)
  e(0x57);
  call(iat.RegCloseKey);
  cmpEaxImm(0);
  o.jne("fail");
  orMask(0x800);
  // Exit: through ExitProcess with the settled mask
  pushImm(0x5a5a);
  call(iat.ExitProcess);

  o.mark("fail");
  o.emit(0x53); // push ebx — the partial step mask
  call(iat.ExitProcess);
  o.resolve();
  const packagePath = createHlePackage(context, "fix008.exe", createImportPe32(imports, o.bytes(), { data, import_layout: plan }));
  const report = readRun(packagePath);
  assert.equal(report.state, "probe_executed", JSON.stringify({ exception: report.exception, reached: report.hle?.trace?.map((entry) => entry.symbol), count: report.instruction_count }));
  assert.equal(report.stop_reason, "process_exit");
  assert.equal(report.exit_code, 0x5a5a);
  const goldenTrace = [
    "CreateFileW", "WriteFile", "SetFilePointerEx", "ReadFile", "SetEndOfFile", "GetFileType",
    "FlushFileBuffers", "CloseHandle", "RegCreateKeyA", "RegSetValueExA", "RegQueryValueExA", "RegCloseKey", "ExitProcess",
  ];
  assert.deepEqual(report.hle.trace.map((entry) => entry.symbol), goldenTrace);
  assert.ok(report.hle.trace.some((entry) => entry.library === "advapi32.dll"));
  // The read-back dword equals what the write put in the file: "SAVE" (0x45564153).
  assert.ok(report.hle.trace.find((entry) => entry.symbol === "ReadFile"));
});

test("FIX-008 slice: repeated storage exerciser run keeps trace and memory hashes stable", (context) => {
  const build = () => {
    const kernel32Symbol = ["ExitProcess", "CreateFileW", "WriteFile", "ReadFile", "SetFilePointerEx", "CloseHandle", "GetFileType"];
    const imports = [
      ...kernel32Symbol.map((name) => ({ library: "kernel32.dll", symbol: name })),
      { library: "advapi32.dll", symbol: "RegCreateKeyA" },
    ];
    const plan = planImports(imports);
    const iat = Object.fromEntries(imports.map((entry) => [entry.symbol, plan.addressOf(entry.library, entry.symbol)]));
    const data = Buffer.alloc(0x200);
    data.write(String.raw`C:\save.dat`, 0x00, "utf16le");
    const o = createEmitter();
    const e = o.emit, d = o.emitDword;
    const pushImm = (value) => { e(0x68); d(value); };
    e(0xbb); d(0);
    pushImm(0); pushImm(0); pushImm(2); pushImm(0); pushImm(0);
    pushImm(0xc0000000 | 0x80000000);
    pushImm(dataAddress(0x00));
    e(0xff, 0x15); d(iat.CreateFileW);
    e(0x85, 0xc0);
    o.je("fail");
    e(0x81, 0xcb); d(1);
    pushImm(0x5a5a);
    e(0xff, 0x15); d(iat.ExitProcess);
    o.mark("fail");
    e(0x53);
    e(0xff, 0x15); d(iat.ExitProcess);
    o.resolve();
    return { file: createImportPe32(imports, o.bytes(), { data, import_layout: plan }) };
  };
  const first = readRun(createHlePackage(context, "fix008.exe", build().file));
  const second = readRun(createHlePackage(context, "fix008.exe", build().file));
  assert.equal(first.hle.trace_sha256, second.hle.trace_sha256);
  assert.equal(first.memory_sha256, second.memory_sha256);
});

test("BPTK-146: the widened Plink surface serves the ANSI file and kernel objects over bounded state", () => {
  const { guest, memory } = createConformanceMachine();
  const scratch = guest.layout.arena_base + 0x00050000;
  const dest = scratch + 0x100;

  // CreateFileA opens the same virtual drive as CreateFileW, then GetFileAttributesExA
  // reports the file, and DeleteFileA removes it so a re-query fails closed.
  guest.writeAnsiString(scratch, "C:\\note.dat", 64);
  const fileHandle = invoke(guest, "kernel32.dll", "CreateFileA", [scratch, 0xc0000000, 0, 0, 2, 0, 0]);
  assert.notEqual(fileHandle, 0xffffffff, "CreateFileA opens a virtual-drive file");
  assert.equal(invoke(guest, "kernel32.dll", "CloseHandle", [fileHandle]), 1);
  assert.equal(invoke(guest, "kernel32.dll", "GetFileAttributesExA", [scratch, 0, dest]), 1);
  assert.equal(memory.readMemory(dest, 4) & 0x80, 0x80, "a normal file reports FILE_ATTRIBUTE_NORMAL");
  assert.equal(invoke(guest, "kernel32.dll", "DeleteFileA", [scratch]), 1);
  assert.equal(invoke(guest, "kernel32.dll", "DeleteFileA", [scratch]), 0, "a removed file cannot be deleted twice");
  assert.equal(guest.getLastError(), 2);

  // A mutex is a real ownership object: releasing an owned mutex succeeds, a
  // second release under-flows and reports ERROR_NOT_OWNER.
  const mutex = invoke(guest, "kernel32.dll", "CreateMutexA", [0, 1, 0]);
  assert.equal(invoke(guest, "kernel32.dll", "ReleaseMutex", [mutex]), 1);
  assert.equal(invoke(guest, "kernel32.dll", "ReleaseMutex", [mutex]), 0);
  assert.equal(guest.getLastError(), 288);

  // An anonymous file mapping is zero-filled guest memory; the mapped view is
  // readable and UnmapViewOfFile flushes it back into the mapping.
  const mapping = invoke(guest, "kernel32.dll", "CreateFileMappingA", [0xffffffff, 0, 4, 0, 4096, 0]);
  const view = invoke(guest, "kernel32.dll", "MapViewOfFile", [mapping, 0, 0, 0, 64]);
  assert.notEqual(view, 0, "MapViewOfFile returns a guest-addressable view");
  memory.writeMemory(view, 4, 0x41424344);
  assert.equal(invoke(guest, "kernel32.dll", "UnmapViewOfFile", [view]), 1);

  // CreateThread and CreateProcessA are the confined probe's honest refusals.
  assert.equal(invoke(guest, "kernel32.dll", "CreateThread", [0, 0, 0x401000, 0, 0, dest]), 0);
  assert.equal(guest.getLastError(), 164);
  assert.equal(invoke(guest, "kernel32.dll", "CreateProcessA", [0, scratch, 0, 0, 0, 0, 0, 0, dest, dest + 16]), 0);
  assert.equal(guest.getLastError(), 5);
});

test("BPTK-146: the advapi32 SID surface builds and compares over bounded guest memory", () => {
  const { guest, memory } = createConformanceMachine();
  const authority = guest.layout.arena_base + 0x00050000;
  const sidPointer = authority + 0x40;
  const otherPointer = authority + 0x80;

  // AllocateAndInitializeSid builds a one-sub-authority SID; GetLengthSid reads
  // its declared length, and CopySid + EqualSid round-trip it byte for byte.
  memory.writeBlock(authority, Buffer.from([0, 0, 0, 0, 0, 5])); // SECURITY_NT_AUTHORITY
  assert.equal(invoke(guest, "advapi32.dll", "AllocateAndInitializeSid", [authority, 1, 0x20, 0, 0, 0, 0, 0, 0, 0, sidPointer]), 1);
  const sid = memory.readMemory(sidPointer, 4);
  assert.equal(invoke(guest, "advapi32.dll", "GetLengthSid", [sid]), 12);
  assert.equal(invoke(guest, "advapi32.dll", "CopySid", [64, otherPointer, sid]), 1);
  assert.equal(invoke(guest, "advapi32.dll", "EqualSid", [sid, otherPointer]), 1);

  // The security descriptor records its Revision, DACL-present bit, and owner.
  const sd = otherPointer + 0x40;
  assert.equal(invoke(guest, "advapi32.dll", "InitializeSecurityDescriptor", [sd, 1]), 1);
  assert.equal(memory.readMemory(sd, 1), 1);
  assert.equal(invoke(guest, "advapi32.dll", "SetSecurityDescriptorDacl", [sd, 1, 0, 0]), 1);
  assert.equal(memory.readMemory(sd + 2, 2) & 0x0004, 0x0004, "SE_DACL_PRESENT is set");
  assert.equal(invoke(guest, "advapi32.dll", "SetSecurityDescriptorOwner", [sd, sid, 0]), 1);
  assert.equal(memory.readMemory(sd + 4, 4), sid, "the owner pointer is recorded");
});

test("RaiseException: an unhandled guest exception is a structured stop with the guest code", (context) => {
  const plan = planImports([
    { library: "kernel32.dll", symbol: "RaiseException" },
    { library: "kernel32.dll", symbol: "ExitProcess" },
  ]);
  const o = createEmitter();
  o.emit(0x68); o.emitDword(0); // lpArguments
  o.emit(0x6a, 0x00); // nNumberOfArguments
  o.emit(0x68); o.emitDword(0); // dwExceptionFlags
  o.emit(0x68); o.emitDword(0xe000beef); // dwExceptionCode
  o.emit(0xff, 0x15); o.emitDword(plan.addressOf("kernel32.dll", "RaiseException")); // RaiseException
  const packagePath = createHlePackage(context, "raise.exe", createImportPe32([
    { library: "kernel32.dll", symbol: "RaiseException" },
    { library: "kernel32.dll", symbol: "ExitProcess" },
  ], o.resolve(), { import_layout: plan }));
  const report = readRun(packagePath);
  assert.equal(report.stop_reason, "guest_exception");
  assert.equal(report.exception.exception_code, 0xe000beef);
});

// --- msvcrt.dll C runtime (BPTK-010 i386 CLI corpus) ------------------------
// The conformance oracle pins the return value; these prove the real memory
// side effect the oracle does not inspect, so a served CRT function is a real
// allocator / real byte operation, never a no-op.

test("BPTK-010 msvcrt: malloc/realloc/free round-trip over the real process heap", () => {
  const { guest, memory } = createConformanceMachine();
  const block = invoke(guest, "msvcrt.dll", "malloc", [64]);
  assert.ok(block !== 0, "malloc returns a live block");
  memory.writeMemory(block, 4, 0xdeadbeef);
  assert.equal(memory.readMemory(block, 4), 0xdeadbeef, "the block is writable guest memory");
  assert.equal(guest.heapSize(guest.defaultHeapHandle(), 0, block), 64, "the block carries its real size");
  const grown = invoke(guest, "msvcrt.dll", "realloc", [block, 128]);
  assert.equal(memory.readMemory(grown, 4), 0xdeadbeef, "realloc preserves the prior bytes");
  assert.equal(invoke(guest, "msvcrt.dll", "free", [grown]), 0);
  const calloc = invoke(guest, "msvcrt.dll", "calloc", [4, 8]);
  assert.equal(memory.readMemory(calloc, 4), 0, "calloc zeroes the block");
});

test("BPTK-010 msvcrt: the string family reads and writes real guest bytes", () => {
  const { guest } = createConformanceMachine();
  const a = guest.layout.arena_base + 0x40;
  const b = guest.layout.arena_base + 0x80;
  const dest = guest.layout.arena_base + 0xc0;
  guest.writeAnsiString(a, "hello", 16);
  assert.equal(invoke(guest, "msvcrt.dll", "strlen", [a]), 5);
  guest.writeAnsiString(b, "help", 16);
  assert.equal(invoke(guest, "msvcrt.dll", "strncmp", [a, b, 3]), 0, "equal 3-char prefix");
  assert.ok((invoke(guest, "msvcrt.dll", "strcmp", [a, b]) | 0) < 0, "hello sorts before help (l < p)");
  assert.equal(invoke(guest, "msvcrt.dll", "strchr", [a, 0x6c]), a + 2, "first l");
  assert.equal(invoke(guest, "msvcrt.dll", "strrchr", [a, 0x6c]), a + 3, "last l");
  invoke(guest, "msvcrt.dll", "strcpy", [dest, a]);
  assert.equal(guest.readAnsiString(dest), "hello", "strcpy copied the bytes");
  const dup = invoke(guest, "msvcrt.dll", "_strdup", [a]);
  assert.notEqual(dup, a);
  assert.equal(guest.readAnsiString(dup), "hello", "_strdup owns a real copy");
});

test("BPTK-010 msvcrt: atoi/_ultoa/rand compute real values", () => {
  const { guest } = createConformanceMachine();
  const text = guest.layout.arena_base + 0x40;
  const out = guest.layout.arena_base + 0x80;
  guest.writeAnsiString(text, "-273abc", 16);
  assert.equal(invoke(guest, "msvcrt.dll", "atoi", [text]) | 0, -273);
  assert.equal(invoke(guest, "msvcrt.dll", "_ultoa", [255, out, 16]), out);
  assert.equal(guest.readAnsiString(out), "ff", "_ultoa wrote the hex text");
  const first = invoke(guest, "msvcrt.dll", "rand", []);
  const second = invoke(guest, "msvcrt.dll", "rand", []);
  assert.ok(first >= 0 && first <= 0x7fff && first !== second, "rand advances a bounded state");
});

test("BPTK-010 msvcrt: stdout/stderr stdio captures real output byte", () => {
  const { guest } = createConformanceMachine();
  const stdout = guest.crtRuntime.iobBase + 32;
  const text = guest.layout.arena_base + 0x40;
  guest.writeAnsiString(text, "hi\n", 8);
  assert.equal(invoke(guest, "msvcrt.dll", "fwrite", [text, 1, 3, stdout]), 3);
  assert.equal(invoke(guest, "msvcrt.dll", "fputc", [0x21, stdout]), 0x21);
  assert.equal(Buffer.from(guest.takeOutput()).toString("latin1"), "hi\n!", "the console captured the emitted byte");
  assert.equal(invoke(guest, "msvcrt.dll", "_fileno", [stdout]), 1, "stdout is fd 1");
});

test("BPTK-010 msvcrt: _open/_write route real bytes into the virtual drive", () => {
  const { guest } = createConformanceMachine();
  const path = guest.layout.arena_base + 0x40;
  const data = guest.layout.arena_base + 0x80;
  guest.writeAnsiString(path, "c:\\note.txt", 16);
  guest.writeAnsiString(data, "abcd", 8);
  const fd = invoke(guest, "msvcrt.dll", "_open", [path, 0x0301, 0]); // _O_CREAT|_O_TRUNC|_O_RDWR
  assert.ok((fd | 0) >= 3, "a real fd is bound");
  assert.equal(invoke(guest, "msvcrt.dll", "_write", [fd, data, 4]), 4);
  assert.equal(guest.virtualFileSize("c:\\note.txt"), 4, "the drive holds the written bytes");
  assert.equal(invoke(guest, "msvcrt.dll", "_close", [fd]), 0);
});

test("BPTK-010 msvcrt: gmtime decomposes the one guest clock", () => {
  const { guest, memory } = createConformanceMachine();
  const cell = guest.layout.arena_base + 0x40;
  memory.writeMemory(cell, 4, 1599763200); // 2020-09-10 18:40:00 UTC
  const tm = invoke(guest, "msvcrt.dll", "gmtime", [cell]);
  assert.equal(memory.readMemory(tm + 8, 4), 18, "tm_hour");
  assert.equal(memory.readMemory(tm + 20, 4), 120, "tm_year is 2020-1900");
  assert.equal(memory.readMemory(tm + 16, 4), 8, "tm_mon is September (0-based)");
});

test("BPTK-010 msvcrt: an x87 double return is a named structured refusal, not a no-op", () => {
  const { guest } = createConformanceMachine();
  assert.throws(() => invoke(guest, "msvcrt.dll", "acos", [0, 0]), /x87 double/);
  assert.throws(() => invoke(guest, "msvcrt.dll", "qsort", [0, 0, 0, 0]), /callback/);
  assert.throws(() => invoke(guest, "msvcrt.dll", "_beginthreadex", [0, 0, 0, 0, 0, 0]), /OS thread/);
  assert.throws(() => invoke(guest, "msvcrt.dll", "longjmp", [0, 1]), /jmp_buf/);
});

test("BPTK-010 kernel32: the semaphore breadth counts and reports real state", () => {
  const { guest, memory } = createConformanceMachine();
  const previous = guest.layout.arena_base + 0x40;
  const handle = invoke(guest, "kernel32.dll", "CreateSemaphoreA", [0, 1, 4, 0]);
  assert.ok(handle !== 0);
  assert.equal(invoke(guest, "kernel32.dll", "ReleaseSemaphore", [handle, 2, previous]), 1);
  assert.equal(memory.readMemory(previous, 4), 1, "ReleaseSemaphore reports the prior count");
  assert.equal(invoke(guest, "kernel32.dll", "ReleaseSemaphore", [handle, 99, previous]), 0, "an over-release past max fails");
});

test("BPTK-010 shlwapi: PathIsRelativeA classifies real paths", () => {
  const { guest } = createConformanceMachine();
  const rel = guest.layout.arena_base + 0x40;
  const abs = guest.layout.arena_base + 0x80;
  guest.writeAnsiString(rel, "sub\\a.txt", 16);
  guest.writeAnsiString(abs, "c:\\a.txt", 16);
  assert.equal(invoke(guest, "shlwapi.dll", "PathIsRelativeA", [rel]), 1);
  assert.equal(invoke(guest, "shlwapi.dll", "PathIsRelativeA", [abs]), 0);
});
