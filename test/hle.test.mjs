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
import { icmProfilePath } from "../lib/gdi.mjs";
import { buildConformanceCaseTable, computeImportService, createConformanceImplementation, createHleLayout, hleCrtDataLayout, listWin32HleExport, resolveHleExport, hleProfile, createConformanceMachine, createWin32Hle, createIsolatedWin32Memory, hleBound } from "../lib/hle.mjs";

// A bounded machine with a read-only host-file store and an initial
// environment, for the file-read + WAD-search path (the corpus-007 lane). The
// clock is the one deterministic virtual source the HLE requires.
function createHostMachine(hostFile, environment) {
  const memory = createIsolatedWin32Memory();
  let guestMs = 0;
  const clock = {
    mode: "virtual_monotonic",
    elapsedGuestMs: () => guestMs,
    advanceVirtualMs: (delta) => { guestMs += delta; },
    tickCount: () => Math.floor(guestMs) >>> 0,
    qpc: () => Math.floor(guestMs * hleProfile.qpc_frequency_hz / 1000),
    rdtsc: () => Math.floor(guestMs * 1000000 / 1000),
    describe: () => ({ source: "one_monotonic_clock", mode: "virtual_monotonic" }),
  };
  return { memory, guest: createWin32Hle(memory, memory.layout, { executable_name: "game.exe", clock, host_file: hostFile, environment }) };
}

function invokeHost(guest, library, symbol, argument) {
  return guest.invokeExport(guest.lookupExport(library, symbol), argument);
}

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

test("api-set and ntdll names resolve to the same kernel32 or msvcrt row", () => {
  const wait = resolveHleExport("api-ms-win-core-synch-l1-2-0.dll", "WaitOnAddress");
  assert.equal(wait?.library, "kernel32.dll");
  assert.equal(wait?.symbol, "WaitOnAddress");
  const exit = resolveHleExport("ntdll.dll", "ExitProcess");
  assert.equal(exit?.library, "kernel32.dll");
  const crt = resolveHleExport("api-ms-win-crt-heap-l1-1-0.dll", "malloc");
  assert.ok(crt, "the CRT heap api-set must resolve");
  assert.equal(crt.symbol, "malloc");
  assert.equal(resolveHleExport("kernel32.dll", "NoSuchExport"), null);
  assert.equal(resolveHleExport("ws2_32.dll", null, 115)?.symbol, "WSAStartup");
  assert.equal(resolveHleExport("sspicli.dll", "InitSecurityInterfaceW")?.library, "secur32.dll");
  const appPolicy = resolveHleExport("api-ms-win-appmodel-runtime-l1-1-2.dll", "AppPolicyGetProcessTerminationMethod");
  assert.equal(appPolicy?.library, "kernel32.dll");
  assert.equal(appPolicy?.symbol, "AppPolicyGetProcessTerminationMethod");
});

test("WSACreateEvent is a manual-reset event; EnumNetworkEvents reports no FD bits", () => {
  const { guest, memory } = createConformanceMachine();
  assert.equal(invoke(guest, "ws2_32.dll", "WSAStartup", [0x0202, 0]), 0);
  const socket = invoke(guest, "ws2_32.dll", "socket", [2, 1, 6]);
  assert.equal(socket, 1);
  const event = invoke(guest, "ws2_32.dll", "WSACreateEvent", []);
  assert.notEqual(event, 0);
  assert.equal(invoke(guest, "ws2_32.dll", "WSAWaitForMultipleEvents", [1, 0, 0, 0, 0]), 0xffffffff);
  const list = 0x00150040;
  memory.writeMemory(list, 4, event);
  assert.equal(invoke(guest, "ws2_32.dll", "WSAWaitForMultipleEvents", [1, list, 0, 0, 0]), 0x102, "unset event times out");
  assert.equal(invoke(guest, "ws2_32.dll", "WSASetEvent", [event]), 1);
  assert.equal(invoke(guest, "ws2_32.dll", "WSAWaitForMultipleEvents", [1, list, 0, 0, 0]), 0, "set event is signaled");
  assert.equal(invoke(guest, "ws2_32.dll", "WSAEventSelect", [socket, event, 0x2b]), 0);
  const report = 0x00150180;
  assert.equal(invoke(guest, "ws2_32.dll", "WSAEnumNetworkEvents", [socket, event, report]), 0);
  assert.equal(memory.readMemory(report, 4), 0, "lNetworkEvents stays 0: no traffic");
  assert.equal(invoke(guest, "ws2_32.dll", "WSACloseEvent", [event]), 1);
});

test("ws2_32 ordinal imports bind to the same HLE thunk as the named export", () => {
  const layout = createHleLayout({ load_base: 0x400000, image_size_byte: 0x10000, stack_base: 0x70000000, stack_end: 0x70100000 });
  assert.ok(layout);
  const service = computeImportService({
    import: [
      { library: "ws2_32.dll", symbol: "WSAStartup" },
      { library: "ws2_32.dll", symbol: null, ordinal: 115 },
    ],
  }, layout);
  assert.equal(service.unserved_count, 0);
  assert.equal(service.import_catalog[0].address, service.import_catalog[1].address);
});

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

test("GetCommandLineW includes the declared command_line tail", () => {
  const { guest } = createConformanceMachine("rg.exe", { command_line: ["--version"] });
  const pointer = invoke(guest, "kernel32.dll", "GetCommandLineW", []);
  assert.match(guest.readWideString(pointer), /--version/);
});

test("i386 CRT argv is a 4-byte pointer vector so argv[1] is the first argument", () => {
  const { guest, memory } = createConformanceMachine("jq.exe", { command_line: ["--version"], pointer_size_byte: 4 });
  const argvCell = invoke(guest, "msvcrt.dll", "__p___argv", []);
  const argvArray = memory.readMemory(argvCell, 4);
  const argv1 = memory.readMemory(argvArray + 4, 4);
  assert.notEqual(argv1, 0, "argv[1] must not be the high dword of argv[0]");
  assert.equal(guest.readAnsiString(argv1), "--version");
  const argcCell = guest.layout.arena_base;
  invoke(guest, "msvcrt.dll", "__getmainargs", [argcCell, argcCell + 4, argcCell + 8, 0, 0]);
  assert.equal(memory.readMemory(argcCell, 4), 2);
});

test("CRT data imports bind to the FILE table, not a code thunk", () => {
  const layout = createHleLayout({ load_base: 0x400000, image_size_byte: 0x10000, stack_base: 0x70000000, stack_end: 0x70100000 });
  assert.ok(layout);
  const placed = hleCrtDataLayout(layout);
  const service = computeImportService({
    import: [
      { library: "msvcrt.dll", symbol: "_iob" },
      { library: "msvcrt.dll", symbol: "_tzname" },
      { library: "msvcrt.dll", symbol: "__mb_cur_max" },
      { library: "msvcrt.dll", symbol: "_environ" },
      { library: "msvcrt.dll", symbol: "fputc" },
    ],
  }, layout);
  assert.equal(service.import_catalog.find((row) => row.symbol === "_iob").address, placed.iob_base);
  assert.equal(service.import_catalog.find((row) => row.symbol === "_tzname").address, placed.tzname_base);
  assert.equal(service.import_catalog.find((row) => row.symbol === "__mb_cur_max").address, placed.mb_cur_max_cell);
  assert.equal(service.import_catalog.find((row) => row.symbol === "_environ").address, placed.environ_cell);
  const fputc = service.import_catalog.find((row) => row.symbol === "fputc").address;
  assert.ok(fputc >= layout.thunk_base && fputc < layout.thunk_base + layout.thunk_page_byte);
  assert.notEqual(placed.iob_base, fputc);
  const { guest } = createConformanceMachine("jq.exe", { pointer_size_byte: 4 });
  const stdout = guest.crtRuntime.iobBase + 32;
  assert.equal(invoke(guest, "msvcrt.dll", "fputc", [0x41, stdout]), 0x41);
  assert.deepEqual([...guest.takeOutput()], [0x41]);
});

test("i386 _initterm walks each guest constructor before returning", (context) => {
  const imports = [
    { library: "msvcrt.dll", symbol: "_initterm" },
    { library: "kernel32.dll", symbol: "ExitProcess" },
  ];
  const plan = planImports(imports);
  const iat = Object.fromEntries(imports.map((entry) => [entry.symbol, plan.addressOf(entry.library, entry.symbol)]));
  const marker = dataAddress(0);
  const table = dataAddress(0x10);
  const ctor = imageBase + 0x1100;
  const data = Buffer.alloc(0x200);
  data.writeUInt32LE(ctor, 0x10);
  data.writeUInt32LE(0, 0x14);
  const code = Buffer.alloc(0x200);
  // ctor: mov dword [marker], 1; ret
  code[0x100] = 0xc7;
  code[0x101] = 0x05;
  code.writeUInt32LE(marker, 0x102);
  code.writeUInt32LE(1, 0x106);
  code[0x10a] = 0xc3;
  // entry: push table+8; push table; call [_initterm]; cmp [marker], 1; jne fail; push 0; call [ExitProcess]
  let at = 0;
  code[at++] = 0x68; code.writeUInt32LE(table + 8, at); at += 4;
  code[at++] = 0x68; code.writeUInt32LE(table, at); at += 4;
  code[at++] = 0xff; code[at++] = 0x15; code.writeUInt32LE(iat._initterm, at); at += 4;
  code[at++] = 0x83; code[at++] = 0x3d; code.writeUInt32LE(marker, at); at += 4; code[at++] = 1;
  code[at++] = 0x75; code[at++] = 0x08; // jne fail (skip push 0 + call ExitProcess)
  code[at++] = 0x6a; code[at++] = 0x00;
  code[at++] = 0xff; code[at++] = 0x15; code.writeUInt32LE(iat.ExitProcess, at); at += 4;
  code[at++] = 0x6a; code[at++] = 0x02; // fail: ExitProcess(2)
  code[at++] = 0xff; code[at++] = 0x15; code.writeUInt32LE(iat.ExitProcess, at);
  const packagePath = createHlePackage(context, "initterm.exe", createImportPe32(imports, code, { data, import_layout: plan }));
  const report = readRun(packagePath);
  assert.equal(report.state, "probe_executed", JSON.stringify(report.exception));
  assert.equal(report.stop_reason, "process_exit");
  assert.equal(report.exit_code, 0, "the constructor must store 1 before _initterm returns");
});

test("WriteConsoleW writes the character count, not the byte count", () => {
  const { guest, memory } = createConformanceMachine();
  const handle = invoke(guest, "kernel32.dll", "GetStdHandle", [-11]);
  const text = guest.layout.arena_base + 0x40;
  const written = guest.layout.arena_base + 0x80;
  guest.writeWideString(text, "HELLO", 16);
  assert.equal(invoke(guest, "kernel32.dll", "WriteConsoleW", [handle, text, 5, written, 0]), 1);
  assert.equal(memory.readMemory(written, 4), 5);
});

test("GetConsoleMode writes the mode dword and returns BOOL", () => {
  const { guest, memory } = createConformanceMachine();
  const handle = invoke(guest, "kernel32.dll", "GetStdHandle", [-11]);
  const dest = guest.layout.arena_base + 0x40;
  assert.equal(invoke(guest, "kernel32.dll", "GetConsoleMode", [handle, dest]), 1);
  assert.equal(memory.readMemory(dest, 4), 3);
});

test("CreateDIBSection writes a guest-visible bits pointer that GetPixel can read", () => {
  const { guest, memory } = createConformanceMachine();
  const info = guest.layout.arena_base + 0x150040;
  const bitsOut = guest.layout.arena_base + 0x150080;
  memory.writeMemory(info + 0, 4, 40);
  memory.writeMemory(info + 4, 4, 2);
  memory.writeMemory(info + 8, 4, 0xfffffffe);
  memory.writeMemory(info + 12, 2, 1);
  memory.writeMemory(info + 14, 2, 32);
  memory.writeMemory(info + 16, 4, 0);
  const bitmap = invoke(guest, "gdi32.dll", "CreateDIBSection", [0, info, 0, bitsOut, 0, 0]);
  assert.notEqual(bitmap, 0);
  const bits = memory.readMemory(bitsOut, 4);
  assert.notEqual(bits, 0);
  memory.writeMemory(bits + 0, 1, 9);
  memory.writeMemory(bits + 1, 1, 8);
  memory.writeMemory(bits + 2, 1, 7);
  memory.writeMemory(bits + 3, 1, 0);
  const dc = invoke(guest, "gdi32.dll", "CreateCompatibleDC", [0]);
  invoke(guest, "gdi32.dll", "SelectObject", [dc, bitmap]);
  assert.equal(invoke(guest, "gdi32.dll", "GetPixel", [dc, 0, 0]), 0x00090807);
});

test("GetICMProfileW writes the declared sRGB path and refuses a NULL size pointer", () => {
  const { guest, memory } = createConformanceMachine();
  const size = guest.layout.arena_base + 0x40;
  const dest = guest.layout.arena_base + 0x80;
  assert.equal(invoke(guest, "gdi32.dll", "GetICMProfileW", [0, 0, 0]), 0);
  assert.equal(guest.getLastError(), 87);
  memory.writeMemory(size, 4, 0);
  assert.equal(invoke(guest, "gdi32.dll", "GetICMProfileW", [0, size, 0]), 0);
  assert.equal(guest.getLastError(), 122);
  assert.equal(memory.readMemory(size, 4), icmProfilePath.length + 1);
  memory.writeMemory(size, 4, 260);
  assert.equal(invoke(guest, "gdi32.dll", "GetICMProfileW", [0, size, dest]), 1);
  assert.equal(guest.readWideString(dest), icmProfilePath);
});

test("EnumDisplayDevicesW writes the one virtual adapter and stops after it", () => {
  const { guest, memory } = createConformanceMachine();
  const info = guest.layout.arena_base + 0x150040;
  memory.writeMemory(info, 4, 840);
  assert.equal(invoke(guest, "user32.dll", "EnumDisplayDevicesW", [0, 0, info, 0]), 1);
  assert.equal(guest.readWideString(info + 4), "\\\\.\\DISPLAY1");
  assert.equal(guest.readWideString(info + 4 + 64), "Virtual Display");
  assert.equal(memory.readMemory(info + 4 + 64 + 256, 4), 5);
  assert.equal(invoke(guest, "user32.dll", "EnumDisplayDevicesW", [0, 1, info, 0]), 0);
});

test("EnumDisplaySettingsW writes the one 1920x1080 mode and stops after it", () => {
  const { guest, memory } = createConformanceMachine();
  const mode = guest.layout.arena_base + 0x150040;
  memory.writeMemory(mode + 68, 2, 220);
  assert.equal(invoke(guest, "user32.dll", "EnumDisplaySettingsW", [0, 0xffffffff, mode]), 1);
  assert.equal(memory.readMemory(mode + 172, 4), 1920);
  assert.equal(memory.readMemory(mode + 176, 4), 1080);
  assert.equal(memory.readMemory(mode + 168, 4), 32);
  assert.equal(memory.readMemory(mode + 184, 4), 60);
  assert.equal(invoke(guest, "user32.dll", "EnumDisplaySettingsW", [0, 1, mode]), 0);
});

test("MonitorFromPoint and MonitorFromWindow return the one virtual display", () => {
  const { guest, memory } = createConformanceMachine();
  const point = guest.layout.arena_base + 0x150080;
  memory.writeMemory(point, 4, 100);
  memory.writeMemory(point + 4, 4, 100);
  assert.equal(invoke(guest, "user32.dll", "MonitorFromPoint", [0, 1]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "user32.dll", "MonitorFromPoint", [point, 1]), 0x00020000);
  assert.equal(invoke(guest, "user32.dll", "MonitorFromWindow", [0, 0]), 0);
  assert.equal(invoke(guest, "user32.dll", "MonitorFromWindow", [0, 2]), 0x00020000);
  assert.equal(invoke(guest, "user32.dll", "InvalidateRect", [0, 0, 1]), 1);
  assert.equal(invoke(guest, "user32.dll", "ValidateRect", [0, 0]), 1);
  assert.equal(invoke(guest, "user32.dll", "GetUpdateRect", [0, 0, 0]), 0);
  assert.equal(guest.getLastError(), 0x578);
  assert.equal(invoke(guest, "user32.dll", "SetFocus", [0]), 0);
  assert.equal(invoke(guest, "user32.dll", "FillRect", [0, 0, 0]), 0);
  assert.equal(guest.getLastError(), 87);
});

test("GetMonitorInfoW writes the one virtual desktop and EnumDisplayMonitors queues its callback", () => {
  const { guest, memory } = createConformanceMachine();
  const info = guest.layout.arena_base + 0x150040;
  memory.writeMemory(info, 4, 104);
  assert.equal(invoke(guest, "user32.dll", "GetMonitorInfoW", [0x00020000, info]), 1);
  assert.equal(memory.readMemory(info + 12, 4), 1920);
  assert.equal(memory.readMemory(info + 16, 4), 1080);
  assert.equal(memory.readMemory(info + 36, 4), 1);
  assert.equal(guest.readWideString(info + 40), "\\\\.\\DISPLAY1");
  assert.equal(invoke(guest, "user32.dll", "EnumDisplayMonitors", [0, 0, 0x401000, 7]), 1);
  assert.equal(guest.pending_guest_call?.kind, "enum_callback");
  assert.equal(guest.pending_guest_call?.argument[0], 0x00020000);
  assert.equal(guest.pending_guest_call?.argument[3], 7);
});

test("EnumResourceNamesW refuses a null callback and a missing type without inventing names", () => {
  const { guest } = createConformanceMachine();
  assert.equal(invoke(guest, "kernel32.dll", "EnumResourceNamesW", [0, 14, 0, 0]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "kernel32.dll", "EnumResourceNamesW", [0, 14, 0x401000, 0]), 0);
  assert.equal(guest.getLastError(), 1813);
  assert.equal(guest.pending_guest_call, null);
});

test("SetConsoleCtrlHandler records a handler and never fires it", () => {
  const { guest } = createConformanceMachine();
  assert.equal(invoke(guest, "kernel32.dll", "SetConsoleCtrlHandler", [0, 1]), 1);
  assert.equal(guest.console_ctrl_ignore, true);
  assert.equal(invoke(guest, "kernel32.dll", "SetConsoleCtrlHandler", [0x401000, 1]), 1);
  assert.deepEqual(guest.console_ctrl_handler, [0x401000]);
  assert.equal(invoke(guest, "kernel32.dll", "SetConsoleCtrlHandler", [0x401000, 0]), 1);
  assert.deepEqual(guest.console_ctrl_handler, []);
});

test("SetThreadExecutionState records ES_CONTINUOUS and never sleeps the host", () => {
  const { guest } = createConformanceMachine();
  assert.equal(invoke(guest, "kernel32.dll", "SetThreadExecutionState", [0]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "kernel32.dll", "SetThreadExecutionState", [0x80000003]), 0x80000000);
  assert.equal(guest.execution_state, 0x80000003);
  assert.equal(invoke(guest, "kernel32.dll", "SetThreadExecutionState", [0x00000002]), 0x80000003);
  assert.equal(guest.execution_state, 0x80000003);
  assert.equal(invoke(guest, "kernel32.dll", "SetThreadExecutionState", [0x80000000]), 0x80000003);
  assert.equal(guest.execution_state, 0x80000000);
  assert.equal(invoke(guest, "kernel32.dll", "SetThreadExecutionState", [0x80000004]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "kernel32.dll", "SetThreadExecutionState", [0x00000040]), 0);
  assert.equal(guest.getLastError(), 87);
});

test("GetKeyboardState writes 256 zero bytes when no key is down", () => {
  const { guest, memory } = createConformanceMachine();
  const dest = guest.layout.arena_base + 0x40;
  memory.writeMemory(dest, 1, 0xff);
  memory.writeMemory(dest + 255, 1, 0xff);
  assert.equal(invoke(guest, "user32.dll", "GetKeyboardState", [0]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "user32.dll", "GetKeyboardState", [dest]), 1);
  assert.equal(memory.readMemory(dest, 1), 0);
  assert.equal(memory.readMemory(dest + 255, 1), 0);
});

test("ToUnicode writes a US-layout character from the key table", () => {
  const { guest, memory } = createConformanceMachine();
  const key_state = guest.layout.arena_base + 0x40;
  const dest = key_state + 256;
  for (let index = 0; index < 256; index += 4) memory.writeMemory(key_state + index, 4, 0);
  assert.equal(invoke(guest, "user32.dll", "ToUnicode", [0x20, 0x39, 0, 0, 16, 0]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "user32.dll", "ToUnicode", [0x20, 0x39, key_state, dest, 16, 0]), 1);
  assert.equal(memory.readMemory(dest, 2), 0x20);
  assert.equal(invoke(guest, "user32.dll", "ToUnicode", [0x41, 0x1e, key_state, dest, 16, 0]), 1);
  assert.equal(memory.readMemory(dest, 2), 0x61);
  memory.writeMemory(key_state + 0x10, 1, 0x80);
  assert.equal(invoke(guest, "user32.dll", "ToUnicode", [0x41, 0x1e, key_state, dest, 16, 0]), 1);
  assert.equal(memory.readMemory(dest, 2), 0x41);
  assert.equal(invoke(guest, "user32.dll", "ToUnicode", [0xff, 0, key_state, dest, 16, 0]), 0);
});

test("GetDisplayConfigBufferSizes and QueryDisplayConfig describe one 1920x1080 path", () => {
  const { guest, memory } = createConformanceMachine();
  const numPath = guest.layout.arena_base + 0x40;
  const numMode = guest.layout.arena_base + 0x44;
  const pathArray = guest.layout.arena_base + 0x150040;
  const modeArray = pathArray + 72;
  assert.equal(invoke(guest, "user32.dll", "GetDisplayConfigBufferSizes", [2, 0, 0]), 87);
  assert.equal(invoke(guest, "user32.dll", "GetDisplayConfigBufferSizes", [2, numPath, numMode]), 0);
  assert.equal(memory.readMemory(numPath, 4), 1);
  assert.equal(memory.readMemory(numMode, 4), 2);
  memory.writeMemory(numPath, 4, 1);
  memory.writeMemory(numMode, 4, 2);
  assert.equal(invoke(guest, "user32.dll", "QueryDisplayConfig", [2, numPath, pathArray, numMode, modeArray, 0]), 0);
  assert.equal(memory.readMemory(modeArray + 16, 4), 1920);
  assert.equal(memory.readMemory(modeArray + 20, 4), 1080);
  assert.equal(invoke(guest, "user32.dll", "SetProcessDPIAware", []), 1);
  assert.equal(invoke(guest, "user32.dll", "GetDpiForWindow", [0]), 0);
  assert.equal(guest.getLastError(), 0x578);
});

test("AdjustWindowRectEx leaves the rect unchanged when there is no nonclient frame", () => {
  const { guest, memory } = createConformanceMachine();
  const rect = guest.layout.arena_base + 0x40;
  memory.writeMemory(rect, 4, 0);
  memory.writeMemory(rect + 4, 4, 0);
  memory.writeMemory(rect + 8, 4, 1280);
  memory.writeMemory(rect + 12, 4, 800);
  assert.equal(invoke(guest, "user32.dll", "AdjustWindowRectEx", [0, 0, 0, 0]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "user32.dll", "AdjustWindowRectEx", [rect, 0x00cf0000, 0, 0]), 1);
  assert.equal(memory.readMemory(rect, 4), 0);
  assert.equal(memory.readMemory(rect + 8, 4), 1280);
  assert.equal(memory.readMemory(rect + 12, 4), 800);
});

test("GetWindowLongW returns GWL_HINSTANCE stored at CreateWindowEx", () => {
  const { guest, memory } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const classStruct = base + 0x40;
  const classNamePtr = base + 0x100;
  guest.writeWideString(classNamePtr, "AppClass", 32);
  memory.writeMemory(classStruct + 0, 4, 0);
  memory.writeMemory(classStruct + 4, 4, 0);
  memory.writeMemory(classStruct + 36, 4, classNamePtr);
  invoke(guest, "user32.dll", "RegisterClassW", [classStruct]);
  const window = invoke(guest, "user32.dll", "CreateWindowExW", [0, classNamePtr, 0, 0, 0, 0, 320, 240, 0, 0, 0x00400000, 0]);
  assert.notEqual(window, 0);
  assert.equal(invoke(guest, "user32.dll", "GetWindowLongW", [window, -6]), 0x00400000);
  assert.equal(invoke(guest, "user32.dll", "GetWindowLongW", [0, -6]), 0);
});

test("SetPropW stores a HANDLE that GetPropW and RemovePropW round-trip", () => {
  const { guest, memory } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const classStruct = base + 0x40;
  const classNamePtr = base + 0x100;
  const propName = base + 0x140;
  guest.writeWideString(classNamePtr, "AppClass", 32);
  guest.writeWideString(propName, "SDL", 8);
  memory.writeMemory(classStruct + 0, 4, 0);
  memory.writeMemory(classStruct + 4, 4, 0);
  memory.writeMemory(classStruct + 36, 4, classNamePtr);
  invoke(guest, "user32.dll", "RegisterClassW", [classStruct]);
  const window = invoke(guest, "user32.dll", "CreateWindowExW", [0, classNamePtr, 0, 0, 0, 0, 320, 240, 0, 0, 0, 0]);
  assert.equal(invoke(guest, "user32.dll", "SetPropW", [0, 0, 0]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "user32.dll", "SetPropW", [window, propName, 0x1234]), 1);
  assert.equal(invoke(guest, "user32.dll", "GetPropW", [window, propName]), 0x1234);
  assert.equal(invoke(guest, "user32.dll", "RemovePropW", [window, propName]), 0x1234);
  assert.equal(invoke(guest, "user32.dll", "GetPropW", [window, propName]), 0);
});

test("SetWindowTextW stores a caption that GetWindowTextW and GetWindowTextLengthW round-trip", () => {
  const { guest, memory } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const classStruct = base + 0x40;
  const classNamePtr = base + 0x100;
  const titlePtr = base + 0x140;
  const dest = base + 0x180;
  guest.writeWideString(classNamePtr, "AppClass", 32);
  guest.writeWideString(titlePtr, "SuperTux", 16);
  memory.writeMemory(classStruct + 0, 4, 0);
  memory.writeMemory(classStruct + 4, 4, 0);
  memory.writeMemory(classStruct + 36, 4, classNamePtr);
  invoke(guest, "user32.dll", "RegisterClassW", [classStruct]);
  const window = invoke(guest, "user32.dll", "CreateWindowExW", [0, classNamePtr, 0, 0, 0, 0, 320, 240, 0, 0, 0, 0]);
  assert.equal(invoke(guest, "user32.dll", "SetWindowTextW", [0, titlePtr]), 0);
  assert.equal(invoke(guest, "user32.dll", "SetWindowTextW", [window, titlePtr]), 1);
  assert.equal(invoke(guest, "user32.dll", "GetWindowTextLengthW", [window]), 8);
  assert.equal(invoke(guest, "user32.dll", "GetWindowTextW", [window, dest, 32]), 8);
  assert.equal(guest.readWideString(dest), "SuperTux");
});

test("DragAcceptFiles records drop acceptance on a live HWND and refuses HWND 0", () => {
  const { guest, memory } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const classStruct = base + 0x40;
  const classNamePtr = base + 0x100;
  guest.writeWideString(classNamePtr, "AppClass", 32);
  memory.writeMemory(classStruct + 0, 4, 0);
  memory.writeMemory(classStruct + 4, 4, 0);
  memory.writeMemory(classStruct + 36, 4, classNamePtr);
  invoke(guest, "user32.dll", "RegisterClassW", [classStruct]);
  const window = invoke(guest, "user32.dll", "CreateWindowExW", [0, classNamePtr, 0, 0, 0, 0, 320, 240, 0, 0, 0, 0]);
  assert.equal(invoke(guest, "shell32.dll", "DragAcceptFiles", [0, 1]), 0);
  assert.equal(guest.getLastError(), 0x578);
  assert.equal(invoke(guest, "shell32.dll", "DragAcceptFiles", [window, 1]), 0);
  assert.equal(guest.user.isDropAccepted(window), true);
  assert.equal(invoke(guest, "shell32.dll", "DragAcceptFiles", [window, 0]), 0);
  assert.equal(guest.user.isDropAccepted(window), false);
});

test("GetClassInfoExW writes the registered class and refuses a missing name", () => {
  const { guest, memory } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const classStruct = base + 0x40;
  const classNamePtr = base + 0x100;
  const missingPtr = base + 0x140;
  const dest = base + 0x180;
  guest.writeWideString(classNamePtr, "AppClass", 32);
  guest.writeWideString(missingPtr, "NoClass", 16);
  memory.writeMemory(classStruct + 0, 4, 48);
  memory.writeMemory(classStruct + 4, 4, 0x0003);
  memory.writeMemory(classStruct + 8, 4, 0x00401000);
  memory.writeMemory(classStruct + 20, 4, 0x00400000);
  memory.writeMemory(classStruct + 28, 4, 0x8200);
  memory.writeMemory(classStruct + 40, 4, classNamePtr);
  invoke(guest, "user32.dll", "RegisterClassExW", [classStruct]);
  assert.equal(invoke(guest, "user32.dll", "GetClassInfoExW", [0, 0, dest]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "user32.dll", "GetClassInfoExW", [0, missingPtr, dest]), 0);
  assert.equal(guest.getLastError(), 0x583);
  assert.equal(invoke(guest, "user32.dll", "GetClassInfoExW", [0, classNamePtr, dest]), 1);
  assert.equal(memory.readMemory(dest + 0, 4), 48);
  assert.equal(memory.readMemory(dest + 4, 4), 0x0003);
  assert.equal(memory.readMemory(dest + 8, 4), 0x00401000);
  assert.equal(memory.readMemory(dest + 20, 4), 0x00400000);
  assert.equal(memory.readMemory(dest + 28, 4), 0x8200);
  assert.equal(memory.readMemory(dest + 40, 4), classNamePtr);
});

test("GetModuleFileNameW(NULL) writes the current executable path", () => {
  const { guest } = createConformanceMachine();
  const dest = guest.layout.arena_base + 0x40;
  assert.equal(invoke(guest, "kernel32.dll", "GetModuleFileNameW", [0, dest, 260]), "C:\\game\\game.exe".length);
  assert.equal(guest.readWideString(dest), "C:\\game\\game.exe");
  assert.equal(guest.getLastError(), 0);
});

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

test("BPTK-031: the ucrt formatted-output backend expands a real x64 va_list", () => {
  const { guest, memory } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const format = base + 0x40;
  const dest = base + 0x100;
  const valist = base + 0x200;
  const strArg = base + 0x300;
  guest.writeAnsiString(format, "n=%d h=%x s=%s c=%c%%", 40);
  guest.writeAnsiString(strArg, "OK", 8);
  // The va_list is eight-byte slots in argument order: 42, 0xbeef, &"OK", 'Z'.
  memory.writeMemory(valist + 0, 4, 42); memory.writeMemory(valist + 4, 4, 0);
  memory.writeMemory(valist + 8, 4, 0xbeef); memory.writeMemory(valist + 12, 4, 0);
  memory.writeMemory(valist + 16, 4, strArg); memory.writeMemory(valist + 20, 4, 0);
  memory.writeMemory(valist + 24, 4, 0x5a); memory.writeMemory(valist + 28, 4, 0);
  const written = invoke(guest, "api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vsprintf", [0, dest, 64, format, 0, valist]);
  assert.equal(guest.readAnsiString(dest), "n=42 h=beef s=OK c=Z%");
  assert.equal(written, "n=42 h=beef s=OK c=Z%".length, "the return is the full conversion length");
});

test("BPTK-031: printf width, precision, zero-fill, and sign flags render like C", () => {
  const { guest, memory } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const format = base + 0x40;
  const dest = base + 0x100;
  const valist = base + 0x200;
  guest.writeAnsiString(format, "[%05d][%+d][%8.3f][%-4d|]", 40);
  memory.writeMemory(valist + 0, 4, 0xffffffd6); memory.writeMemory(valist + 4, 4, 0xffffffff); // -42 (int, sign-extended low dword)
  memory.writeMemory(valist + 8, 4, 7); memory.writeMemory(valist + 12, 4, 0);
  memory.writeMemory(valist + 16, 8, 0); // 3.14159 as a double, written below
  memory.writeMemory(valist + 24, 4, 5); memory.writeMemory(valist + 28, 4, 0);
  const buf = Buffer.alloc(8); buf.writeDoubleLE(3.14159, 0);
  memory.writeBlock(valist + 16, buf);
  invoke(guest, "api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vsprintf", [0, dest, 64, format, 0, valist]);
  assert.equal(guest.readAnsiString(dest), "[-0042][+7][   3.142][5   |]");
});

test("BPTK-031: fopen honors its mode string — a read of an absent file never creates it", () => {
  const { guest } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const path = base + 0x40;
  const modeRead = base + 0x80;
  const modeWrite = base + 0x90;
  guest.writeAnsiString(path, "c:\\iwad.wad", 16);
  guest.writeAnsiString(modeRead, "rb", 4);
  guest.writeAnsiString(modeWrite, "wb", 4);
  assert.equal(invoke(guest, "msvcrt.dll", "fopen", [path, modeRead]), 0, "a read of an absent file returns NULL");
  assert.equal(guest.virtualFileSize("c:\\iwad.wad"), null, "and does not fabricate the file");
  const stream = invoke(guest, "msvcrt.dll", "fopen", [path, modeWrite]);
  assert.notEqual(stream, 0, "a write mode creates the file and returns a stream");
  assert.equal(guest.virtualFileSize("c:\\iwad.wad"), 0, "the created file exists at zero length");
});

test("BPTK-031: a staged host file reads its real bytes through fopen/fseek/ftell/fread", () => {
  const wad = Buffer.from("IWAD\x02\x00\x00\x00payloadbytes");
  const { guest, memory } = createHostMachine(new Map([["c:\\game\\freedoom1.wad", wad]]), { DOOMWADDIR: "C:\\game" });
  const base = guest.layout.arena_base;
  const path = base + 0x40;
  const mode = base + 0x80;
  const buffer = base + 0x100;
  guest.writeAnsiString(path, "C:\\game\\freedoom1.wad", 40);
  guest.writeAnsiString(mode, "rb", 4);
  // The file exists at its real size before any read, and never mutates the host.
  assert.equal(guest.virtualFileSize("c:\\game\\freedoom1.wad"), wad.length);
  const stream = invokeHost(guest, "msvcrt.dll", "fopen", [path, mode]);
  assert.notEqual(stream, 0, "the staged file opens for read");
  assert.equal(invokeHost(guest, "msvcrt.dll", "fseek", [stream, 0, 2]), 0, "seek to end");
  assert.equal(invokeHost(guest, "msvcrt.dll", "ftell", [stream]), wad.length, "ftell reports the real size");
  assert.equal(invokeHost(guest, "msvcrt.dll", "fseek", [stream, 0, 0]), 0, "seek back to start");
  const count = invokeHost(guest, "msvcrt.dll", "fread", [buffer, 1, 8, stream]);
  assert.equal(count, 8, "fread returns the item count");
  assert.equal(memory.readBlock(buffer, 8).toString("latin1"), "IWAD\x02\x00\x00\x00", "the real header bytes land in the guest buffer");
});

test("BPTK-031: a staged host file passed as a plain Uint8Array reads identically to a Buffer", () => {
  // The browser host reads files through fetch().arrayBuffer(), which yields a
  // plain Uint8Array, not a Node Buffer. Such a file must register and read
  // exactly like a Buffer — otherwise it is silently dropped and a WAD-backed
  // guest (Chocolate Doom) exits early having found no IWAD.
  const source = Buffer.from("IWAD\x02\x00\x00\x00payloadbytes");
  const wad = new Uint8Array(source); // a distinct plain view, not a Buffer
  assert.equal(Buffer.isBuffer(wad), false, "the input is genuinely a plain Uint8Array");
  const { guest, memory } = createHostMachine(new Map([["c:\\game\\freedoom1.wad", wad]]), { DOOMWADDIR: "C:\\game" });
  const base = guest.layout.arena_base;
  const path = base + 0x40;
  const mode = base + 0x80;
  const buffer = base + 0x100;
  guest.writeAnsiString(path, "C:\\game\\freedoom1.wad", 40);
  guest.writeAnsiString(mode, "rb", 4);
  assert.equal(guest.virtualFileSize("c:\\game\\freedoom1.wad"), wad.length, "the Uint8Array file registers at its real size");
  const stream = invokeHost(guest, "msvcrt.dll", "fopen", [path, mode]);
  assert.notEqual(stream, 0, "the Uint8Array-backed file opens for read");
  assert.equal(invokeHost(guest, "msvcrt.dll", "fread", [buffer, 1, 8, stream]), 8, "fread returns the item count");
  assert.equal(memory.readBlock(buffer, 8).toString("latin1"), "IWAD\x02\x00\x00\x00", "the real header bytes land in the guest buffer");
});

test("BPTK-031: DOOMWADDIR is served through _wgetenv from the initial environment", () => {
  const { guest } = createHostMachine(new Map(), { DOOMWADDIR: "C:\\game" });
  const name = guest.layout.arena_base + 0x40;
  guest.writeWideString(name, "DOOMWADDIR", 16);
  const pointer = invokeHost(guest, "msvcrt.dll", "_wgetenv", [name]);
  assert.notEqual(pointer, 0, "a seeded variable resolves");
  assert.equal(guest.readWideString(pointer), "C:\\game");
});

test("BPTK-031: the scanf engine parses a %s word and a %d integer from a string", () => {
  const { guest, memory } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const buffer = base + 0x40;
  const format = base + 0x80;
  const word = base + 0x100;
  const number = base + 0x180;
  const valist = base + 0x200;
  guest.writeAnsiString(buffer, "Frame 419", 16);
  guest.writeAnsiString(format, "%19s %d", 16);
  memory.writeMemory(valist + 0, 4, word); memory.writeMemory(valist + 4, 4, 0);
  memory.writeMemory(valist + 8, 4, number); memory.writeMemory(valist + 12, 4, 0);
  const assigned = invoke(guest, "api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vsscanf", [0, buffer, 16, format, 0, valist]);
  assert.equal(assigned, 2, "both fields assign");
  assert.equal(guest.readAnsiString(word), "Frame");
  assert.equal(memory.readMemory(number, 4), 419);
});

test("BPTK-031: _wmkdir over a valid c:\\ path succeeds and feof tracks a real file position", () => {
  const { guest } = createConformanceMachine();
  const base = guest.layout.arena_base;
  const dir = base + 0x40;
  guest.writeWideString(dir, "c:\\game\\cfg", 16);
  assert.equal(invoke(guest, "msvcrt.dll", "_wmkdir", [dir]), 0, "a valid directory path succeeds");
  const bad = base + 0x100;
  guest.writeWideString(bad, "d:\\notallowed", 20);
  assert.equal(invoke(guest, "msvcrt.dll", "_wmkdir", [bad]) | 0, -1, "an out-of-tree path is refused");
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
  // No nonclient frame: ClientToScreen adds the window origin; ScreenToClient inverts it.
  const pointBuffer = base + 0x1c0;
  memory.writeMemory(pointBuffer, 4, 5);
  memory.writeMemory(pointBuffer + 4, 4, 7);
  assert.equal(invoke(guest, "user32.dll", "ClientToScreen", [0, 0]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "user32.dll", "ClientToScreen", [window, pointBuffer]), 1);
  assert.deepEqual([memory.readMemory(pointBuffer, 4), memory.readMemory(pointBuffer + 4, 4)], [15, 27]);
  assert.equal(invoke(guest, "user32.dll", "ScreenToClient", [window, pointBuffer]), 1);
  assert.deepEqual([memory.readMemory(pointBuffer, 4), memory.readMemory(pointBuffer + 4, 4)], [5, 7]);
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
  cmpEaxImm(1);
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
  assert.equal(view & 0xffff, 0, "MapViewOfFile is allocation-granularity aligned");
  memory.writeMemory(view, 4, 0x41424344);
  const oldProtect = dest + 0x40;
  assert.equal(invoke(guest, "kernel32.dll", "VirtualProtect", [view, 64, 0x02, oldProtect]), 1, "VirtualProtect succeeds on a mapped view");
  assert.equal(invoke(guest, "kernel32.dll", "UnmapViewOfFile", [view]), 1);

  // CreateThread returns a guest_thread handle. Isolated HLE has no probe
  // loop, so the start address is not entered here; GetExitCodeThread stays
  // STILL_ACTIVE. CreateProcessA remains the containment refusal.
  const thread = invoke(guest, "kernel32.dll", "CreateThread", [0, 0, 0x401000, 0, 0, dest]);
  assert.notEqual(thread, 0);
  assert.equal(memory.readMemory(dest, 4), 2);
  assert.equal(invoke(guest, "kernel32.dll", "GetExitCodeThread", [thread, dest + 4]), 1);
  assert.equal(memory.readMemory(dest + 4, 4), 259);
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

test("RaiseException: a guest FS:[0] handler that continues execution resumes the caller", (context) => {
  const plan = planImports([
    { library: "kernel32.dll", symbol: "RaiseException" },
    { library: "kernel32.dll", symbol: "ExitProcess" },
  ]);
  const o = createEmitter();
  o.jmp("main");
  o.mark("handler");
  o.emit(0xb8); o.emitDword(0); // ExceptionContinueExecution
  o.emit(0xc3);
  o.mark("main");
  o.emit(0x68); o.emitDword(imageBase + 0x1000 + 5);
  o.emit(0x64, 0xff, 0x35, 0, 0, 0, 0);
  o.emit(0x64, 0x89, 0x25, 0, 0, 0, 0);
  o.emit(0x6a, 0x00);
  o.emit(0x6a, 0x00);
  o.emit(0x6a, 0x00);
  o.emit(0x68); o.emitDword(0xe0000001);
  o.emit(0xff, 0x15); o.emitDword(plan.addressOf("kernel32.dll", "RaiseException"));
  o.emit(0x6a, 0x2a);
  o.emit(0xff, 0x15); o.emitDword(plan.addressOf("kernel32.dll", "ExitProcess"));
  const packagePath = createHlePackage(context, "sehcont.exe", createImportPe32([
    { library: "kernel32.dll", symbol: "RaiseException" },
    { library: "kernel32.dll", symbol: "ExitProcess" },
  ], o.resolve(), { import_layout: plan }));
  const report = readRun(packagePath);
  assert.equal(report.stop_reason, "process_exit");
  assert.equal(report.exit_code, 42);
});

test("RaiseException: ExceptionContinueSearch walks to the next FS:[0] frame", (context) => {
  const plan = planImports([
    { library: "kernel32.dll", symbol: "RaiseException" },
    { library: "kernel32.dll", symbol: "ExitProcess" },
  ]);
  const o = createEmitter();
  o.jmp("main");
  o.mark("search");
  o.emit(0xb8); o.emitDword(1); // ExceptionContinueSearch
  o.emit(0xc3);
  o.mark("resume");
  o.emit(0xb8); o.emitDword(0); // ExceptionContinueExecution
  o.emit(0xc3);
  o.mark("main");
  o.emit(0x68); o.emitDword(imageBase + 0x1000 + 11);
  o.emit(0x64, 0xff, 0x35, 0, 0, 0, 0);
  o.emit(0x64, 0x89, 0x25, 0, 0, 0, 0);
  o.emit(0x68); o.emitDword(imageBase + 0x1000 + 5);
  o.emit(0x64, 0xff, 0x35, 0, 0, 0, 0);
  o.emit(0x64, 0x89, 0x25, 0, 0, 0, 0);
  o.emit(0x6a, 0x00);
  o.emit(0x6a, 0x00);
  o.emit(0x6a, 0x00);
  o.emit(0x68); o.emitDword(0xe0000001);
  o.emit(0xff, 0x15); o.emitDword(plan.addressOf("kernel32.dll", "RaiseException"));
  o.emit(0x6a, 0x2a);
  o.emit(0xff, 0x15); o.emitDword(plan.addressOf("kernel32.dll", "ExitProcess"));
  const packagePath = createHlePackage(context, "sehwalk.exe", createImportPe32([
    { library: "kernel32.dll", symbol: "RaiseException" },
    { library: "kernel32.dll", symbol: "ExitProcess" },
  ], o.resolve(), { import_layout: plan }));
  const report = readRun(packagePath);
  assert.equal(report.stop_reason, "process_exit");
  assert.equal(report.exit_code, 42);
});

test("RtlUnwind: TargetIp records a seh_transfer and returns the unwind value", () => {
  const { guest } = createConformanceMachine();
  const value = invoke(guest, "kernel32.dll", "RtlUnwind", [0, 0x403000, 0, 7]);
  assert.equal(value, 7);
  assert.deepEqual(guest.seh_transfer, { eip: 0x403000, eax: 7 });
});

test("InitSecurityInterfaceW: the table is version 3 and AcquireCredentialsHandleW is a real thunk", () => {
  const { guest, memory, layout } = createConformanceMachine();
  const table = invoke(guest, "secur32.dll", "InitSecurityInterfaceW", []);
  assert.equal(table, hleCrtDataLayout(layout).sspi_table);
  assert.equal(memory.readMemory(table, 4), 3, "dwVersion is SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_3");
  const acquireThunk = layout.thunk_base + listWin32HleExport().findIndex((entry) => entry.library === "secur32.dll" && entry.symbol === "AcquireCredentialsHandleW") * 4;
  assert.equal(memory.readMemory(table + 12, 4), acquireThunk);
  assert.equal(invoke(guest, "secur32.dll", "AcquireCredentialsHandleW", [0, 0, 2, 0, 0, 0, 0, 0, 0]), 0x80090305);
  const countPtr = table + 120;
  const infoPtr = table + 124;
  assert.equal(invoke(guest, "secur32.dll", "EnumerateSecurityPackagesW", [countPtr, infoPtr]), 0);
  assert.equal(memory.readMemory(countPtr, 4), 0);
  assert.equal(memory.readMemory(infoPtr, 4), 0);
});

test("RaiseException: a ContinueSearch-only chain is still an unhandled guest exception", (context) => {
  const plan = planImports([
    { library: "kernel32.dll", symbol: "RaiseException" },
    { library: "kernel32.dll", symbol: "ExitProcess" },
  ]);
  const o = createEmitter();
  o.jmp("main");
  o.mark("search");
  o.emit(0xb8); o.emitDword(1);
  o.emit(0xc3);
  o.mark("main");
  o.emit(0x68); o.emitDword(imageBase + 0x1000 + 5);
  o.emit(0x64, 0xff, 0x35, 0, 0, 0, 0);
  o.emit(0x64, 0x89, 0x25, 0, 0, 0, 0);
  o.emit(0x6a, 0x00);
  o.emit(0x6a, 0x00);
  o.emit(0x6a, 0x00);
  o.emit(0x68); o.emitDword(0xe000beef);
  o.emit(0xff, 0x15); o.emitDword(plan.addressOf("kernel32.dll", "RaiseException"));
  o.emit(0x6a, 0x2a);
  o.emit(0xff, 0x15); o.emitDword(plan.addressOf("kernel32.dll", "ExitProcess"));
  const packagePath = createHlePackage(context, "sehmiss.exe", createImportPe32([
    { library: "kernel32.dll", symbol: "RaiseException" },
    { library: "kernel32.dll", symbol: "ExitProcess" },
  ], o.resolve(), { import_layout: plan }));
  const report = readRun(packagePath);
  assert.equal(report.stop_reason, "guest_exception");
  assert.equal(report.exception.exception_code, 0xe000beef);
});

test("RaiseException: MSVC SetThreadName continues and the caller resumes", (context) => {
  const plan = planImports([
    { library: "kernel32.dll", symbol: "RaiseException" },
    { library: "kernel32.dll", symbol: "ExitProcess" },
  ]);
  const o = createEmitter();
  o.emit(0x6a, 0x00);
  o.emit(0x6a, 0x00);
  o.emit(0x6a, 0x00);
  o.emit(0x68); o.emitDword(0x406d1388);
  o.emit(0xff, 0x15); o.emitDword(plan.addressOf("kernel32.dll", "RaiseException"));
  o.emit(0x6a, 0x2a);
  o.emit(0xff, 0x15); o.emitDword(plan.addressOf("kernel32.dll", "ExitProcess"));
  const packagePath = createHlePackage(context, "setthreadname.exe", createImportPe32([
    { library: "kernel32.dll", symbol: "RaiseException" },
    { library: "kernel32.dll", symbol: "ExitProcess" },
  ], o.resolve(), { import_layout: plan }));
  const report = readRun(packagePath);
  assert.equal(report.stop_reason, "process_exit");
  assert.equal(report.exit_code, 42);
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

test("BPTK-031 CRT ctype: the C-locale classification is served on the ucrt string api-set and msvcrt", () => {
  const { guest } = createConformanceMachine();
  const api = "api-ms-win-crt-string-l1-1-0.dll";
  // isspace: space and the \t..\r whitespace run classify; a letter does not.
  // This is the exact frontier Dwarf Fortress reached (isspace on the api-set).
  for (const library of [api, "msvcrt.dll"]) {
    assert.ok(invoke(guest, library, "isspace", [0x20]) !== 0, `${library} isspace(' ')`);
    assert.ok(invoke(guest, library, "isspace", [0x09]) !== 0, `${library} isspace('\\t')`);
    assert.equal(invoke(guest, library, "isspace", [0x41]), 0, `${library} isspace('A') is zero`);
    assert.ok(invoke(guest, library, "isdigit", [0x37]) !== 0, `${library} isdigit('7')`);
    assert.equal(invoke(guest, library, "isdigit", [0x41]), 0, `${library} isdigit('A') is zero`);
    assert.ok(invoke(guest, library, "isalpha", [0x41]) !== 0, `${library} isalpha('A')`);
    assert.ok(invoke(guest, library, "isalpha", [0x7a]) !== 0, `${library} isalpha('z')`);
    assert.equal(invoke(guest, library, "isalpha", [0x39]), 0, `${library} isalpha('9') is zero`);
    assert.ok(invoke(guest, library, "isalnum", [0x39]) !== 0, `${library} isalnum('9')`);
    assert.ok(invoke(guest, library, "isupper", [0x41]) !== 0 && invoke(guest, library, "isupper", [0x61]) === 0);
    assert.ok(invoke(guest, library, "islower", [0x61]) !== 0 && invoke(guest, library, "islower", [0x41]) === 0);
    assert.ok(invoke(guest, library, "isxdigit", [0x66]) !== 0 && invoke(guest, library, "isxdigit", [0x67]) === 0, `${library} isxdigit f vs g`);
    assert.ok(invoke(guest, library, "ispunct", [0x2e]) !== 0 && invoke(guest, library, "ispunct", [0x41]) === 0, `${library} ispunct('.')`);
    assert.ok(invoke(guest, library, "iscntrl", [0x00]) !== 0 && invoke(guest, library, "iscntrl", [0x41]) === 0);
    // isgraph excludes the space; isprint includes it. isgraph was DF's second
    // ctype import from the api-set.
    assert.ok(invoke(guest, library, "isgraph", [0x41]) !== 0 && invoke(guest, library, "isgraph", [0x20]) === 0, `${library} isgraph`);
    assert.ok(invoke(guest, library, "isprint", [0x20]) !== 0, `${library} isprint(' ')`);
    // The _l locale-tagged variant ignores its locale argument (the "C" locale).
    assert.equal(invoke(guest, library, "isspace_l", [0x20, 0]), invoke(guest, library, "isspace", [0x20]));
    assert.equal(invoke(guest, library, "isdigit_l", [0x37, 0]), invoke(guest, library, "isdigit", [0x37]));
    // _isctype tests an arbitrary class mask over the same table (_ALPHA 0x100).
    assert.ok(invoke(guest, library, "_isctype", [0x41, 0x100]) !== 0 && invoke(guest, library, "_isctype", [0x39, 0x100]) === 0);
  }
});

test("BPTK-031 CRT ctype: toupper/tolower transform over the C locale on the api-set", () => {
  const { guest } = createConformanceMachine();
  for (const library of ["api-ms-win-crt-string-l1-1-0.dll", "api-ms-win-crt-convert-l1-1-0.dll", "msvcrt.dll"]) {
    assert.equal(invoke(guest, library, "toupper", [0x61]), 0x41, `${library} toupper('a')`);
    assert.equal(invoke(guest, library, "toupper", [0x41]), 0x41, `${library} toupper('A') is idempotent`);
    assert.equal(invoke(guest, library, "toupper", [0x39]), 0x39, `${library} toupper('9') unchanged`);
    assert.equal(invoke(guest, library, "tolower", [0x5a]), 0x7a, `${library} tolower('Z')`);
    assert.equal(invoke(guest, library, "tolower", [0x7a]), 0x7a, `${library} tolower('z') is idempotent`);
    assert.equal(invoke(guest, library, "_tolower_l", [0x41, 0]), 0x61, `${library} _tolower_l ignores locale`);
  }
});

test("BPTK-031 CRT convert: strtol/strtoul/_itoa parse and format over the convert api-set", () => {
  const { guest } = createConformanceMachine();
  const api = "api-ms-win-crt-convert-l1-1-0.dll";
  const text = guest.layout.arena_base + 0x40;
  const endptr = guest.layout.arena_base + 0x80;
  const out = guest.layout.arena_base + 0xc0;
  // strtol: leading whitespace, sign, base-10 digit run; endptr at the first
  // unconsumed byte.
  guest.writeAnsiString(text, "  -42xyz", 16);
  assert.equal(invoke(guest, api, "strtol", [text, endptr, 10]) | 0, -42);
  assert.equal(guest.memory.readMemory(endptr, 4), text + 5, "strtol endptr points past -42");
  // strtoul with a 0x prefix under base 16.
  guest.writeAnsiString(text, "0xFF", 8);
  assert.equal(invoke(guest, api, "strtoul", [text, 0, 16]), 255);
  // strtol base 0 auto-detects octal.
  guest.writeAnsiString(text, "0755", 8);
  assert.equal(invoke(guest, api, "strtol", [text, 0, 0]), 0o755);
  // _itoa is signed for base 10, an unsigned bit pattern for base 16.
  assert.equal(invoke(guest, api, "_itoa", [-5, out, 10]), out);
  assert.equal(guest.readAnsiString(out), "-5", "_itoa base 10 is signed");
  assert.equal(invoke(guest, api, "_itoa", [255, out, 16]), out);
  assert.equal(guest.readAnsiString(out), "ff", "_itoa base 16 is an unsigned pattern");
  // srand reseeds the deterministic rand LCG on the utility api-set.
  invoke(guest, "api-ms-win-crt-utility-l1-1-0.dll", "srand", [1]);
  const first = invoke(guest, "api-ms-win-crt-utility-l1-1-0.dll", "rand", []);
  invoke(guest, "api-ms-win-crt-utility-l1-1-0.dll", "srand", [1]);
  assert.equal(invoke(guest, "api-ms-win-crt-utility-l1-1-0.dll", "rand", []), first, "srand(1) makes rand replay");
});

test("BPTK-031 CRT string: strrchr/strstr return a full-width x64 pointer", () => {
  const { guest } = createConformanceMachine();
  // vcruntime140 exports these intrinsics; Dwarf Fortress reached strrchr here.
  const text = guest.layout.arena_base + 0x40;
  guest.writeAnsiString(text, "a/b/c", 8);
  assert.equal(invoke(guest, "vcruntime140.dll", "strrchr", [text, 0x2f]), text + 3, "last '/' at index 3");
  assert.equal(invoke(guest, "vcruntime140.dll", "strchr", [text, 0x2f]), text + 1, "first '/' at index 1");
  const hay = guest.layout.arena_base + 0x80;
  const needle = guest.layout.arena_base + 0xc0;
  guest.writeAnsiString(hay, "hello", 8);
  guest.writeAnsiString(needle, "ll", 4);
  assert.equal(invoke(guest, "vcruntime140.dll", "strstr", [hay, needle]), hay + 2, "strstr finds 'll'");
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

// ---------------------------------------------------------------------------
// The synchronization breadth slice (extends BPTK-010/101): the state changes
// and wake semantics the conformance oracle does not inspect — the interlocked
// prior-and-store contract, the timer wake on the one virtual clock, the
// multi-object wait-any/wait-all consume, the named-object open family, and
// the futex-style address wait timeout.
// ---------------------------------------------------------------------------

test("BPTK-010 sync breadth: the interlocked bitwise family returns the prior value and stores the new one", () => {
  const { guest, memory } = createConformanceMachine();
  const target = guest.layout.arena_base + 0x40;
  memory.writeMemory(target, 4, 0xff00ff00);
  assert.equal(invoke(guest, "kernel32.dll", "InterlockedAnd", [target, 0x0f0f0f0f]), 0xff00ff00 >>> 0, "And returns the prior value");
  assert.equal(memory.readMemory(target, 4), 0x0f000f00 >>> 0, "And stores the masked value");
  memory.writeMemory(target, 4, 0x80000000);
  assert.equal(invoke(guest, "kernel32.dll", "InterlockedOr", [target, 1]), 0x80000000 >>> 0);
  assert.equal(memory.readMemory(target, 4), 0x80000001 >>> 0);
  memory.writeMemory(target, 4, 0x000000ff);
  assert.equal(invoke(guest, "kernel32.dll", "InterlockedXor", [target, 0x0000000f]), 0xff);
  assert.equal(memory.readMemory(target, 4), 0xf0);
  memory.writeMemory(target, 4, 0x00400000);
  assert.equal(invoke(guest, "kernel32.dll", "InterlockedCompareExchangePointer", [target, 0x00401000, 0x00400000]), 0x00400000);
  assert.equal(memory.readMemory(target, 4), 0x00401000, "a matching comparand stores the exchange value");
  assert.equal(invoke(guest, "kernel32.dll", "InterlockedCompareExchangePointer", [target, 0x00500000, 0x00400000]), 0x00401000, "a mismatched comparand returns the current value");
  assert.equal(memory.readMemory(target, 4), 0x00401000, "a mismatched comparand stores nothing");
  assert.equal(invoke(guest, "kernel32.dll", "InterlockedExchangePointer", [target, 0x00600000]), 0x00401000);
  assert.equal(memory.readMemory(target, 4), 0x00600000);
});

test("BPTK-010 sync breadth: a waitable timer wakes the finite wait on the one virtual clock", () => {
  const { guest } = createConformanceMachine();
  const due = guest.layout.arena_base + 0x40;
  const handle = invoke(guest, "kernel32.dll", "CreateWaitableTimerA", [0, 0, 0]);
  assert.ok(handle !== 0);
  guest.memory.writeBlock(due, Buffer.alloc(8).fill(0).map((byte) => byte));
  const buffer = Buffer.alloc(8);
  buffer.writeBigInt64LE(-10000n, 0); // 1ms relative
  guest.memory.writeBlock(due, buffer);
  assert.equal(invoke(guest, "kernel32.dll", "SetWaitableTimer", [handle, due, 0, 0, 0, 0]), 1);
  // A finite wait past the due time succeeds and consumes the auto-reset signal.
  assert.equal(invoke(guest, "kernel32.dll", "WaitForSingleObject", [handle, 100]), 0);
  assert.ok(Math.abs(guest.clock.elapsedGuestMs() - 1) < 0.001, "the clock advanced to the due time, not the full timeout");
  // The one-shot auto-reset timer is spent: the next finite wait burns its budget.
  assert.equal(invoke(guest, "kernel32.dll", "WaitForSingleObject", [handle, 5]), 0x102);
  // An APC routine can never fire in the bounded world, so the set refuses.
  assert.equal(invoke(guest, "kernel32.dll", "SetWaitableTimer", [handle, due, 0, 0x00401000, 0, 0]), 0);
  assert.equal(invoke(guest, "kernel32.dll", "CancelWaitableTimer", [handle]), 1);
});

test("BPTK-010 sync breadth: the multi-object wait reports the signaled index and consumes a wait-all", () => {
  const { guest, memory } = createConformanceMachine();
  const handles = guest.layout.arena_base + 0x40;
  const first = invoke(guest, "kernel32.dll", "CreateEventW", [0, 0, 0, 0]); // auto-reset, unsignaled
  const second = invoke(guest, "kernel32.dll", "CreateEventW", [0, 1, 1, 0]); // manual-reset, signaled
  memory.writeMemory(handles, 4, first);
  memory.writeMemory(handles + 4, 4, second);
  assert.equal(invoke(guest, "kernel32.dll", "WaitForMultipleObjects", [2, handles, 0, 0]), 1, "wait-any reports WAIT_OBJECT_0 + 1");
  invoke(guest, "kernel32.dll", "SetEvent", [first]);
  // The manual-reset event stays signaled, so the wait-all consumes both sides.
  assert.equal(invoke(guest, "kernel32.dll", "WaitForMultipleObjectsEx", [2, handles, 1, 0, 0]), 0);
  const semaphore = invoke(guest, "kernel32.dll", "CreateSemaphoreA", [0, 1, 4, 0]);
  memory.writeMemory(handles, 4, semaphore);
  assert.equal(invoke(guest, "kernel32.dll", "WaitForMultipleObjects", [2, handles, 1, 0]), 0, "semaphore count 1 plus the still-signaled event satisfies the wait-all");
  assert.equal(invoke(guest, "kernel32.dll", "WaitForMultipleObjects", [2, handles, 1, 0]), 0x102, "the wait-all consumed the semaphore count");
  assert.equal(invoke(guest, "kernel32.dll", "WaitForMultipleObjects", [0, handles, 0, 0]), 0xffffffff, "a zero-count wait is a parameter error");
  const badHandles = guest.layout.arena_base + 0x80;
  memory.writeMemory(badHandles, 4, 0xdeadbeef);
  assert.equal(invoke(guest, "kernel32.dll", "WaitForMultipleObjects", [1, badHandles, 0, 0]), 0xffffffff, "a non-waitable handle is an invalid-handle error");
});

test("BPTK-010: CreateEventExW maps flags onto CreateEvent and refuses unknown bits", () => {
  const { guest } = createConformanceMachine();
  const auto = invoke(guest, "kernel32.dll", "CreateEventExW", [0, 0, 0, 0x1f0003]);
  assert.ok(auto !== 0);
  assert.equal(invoke(guest, "kernel32.dll", "WaitForSingleObject", [auto, 0]), 0x102);
  const signaled = invoke(guest, "kernel32.dll", "CreateEventExW", [0, 0, 2, 0x1f0003]);
  assert.equal(invoke(guest, "kernel32.dll", "WaitForSingleObject", [signaled, 0]), 0);
  assert.equal(invoke(guest, "kernel32.dll", "CreateEventExW", [0, 0, 4, 0x1f0003]), 0);
  assert.equal(guest.getLastError(), 87);
});

test("BPTK-010: the HLE call trace keeps a bounded tail so a long load is not a 1M-entry stop", () => {
  const { guest } = createConformanceMachine();
  for (let index = 0; index < 20000; index += 1) invoke(guest, "kernel32.dll", "GetLastError", []);
  assert.equal(guest.call_count, 20000);
  assert.ok(guest.trace_record.length <= hleBound.trace_keep * 2);
  assert.ok(guest.trace_record.length >= hleBound.trace_keep);
});

test("BPTK-010 sync breadth: the named-object open family finds its own creates and misses honestly", () => {
  const { guest } = createConformanceMachine();
  const nameA = guest.layout.arena_base + 0x40;
  const nameW = guest.layout.arena_base + 0x80;
  guest.writeWideString(nameW, "BPTK_MUTEX", 16);
  const mutex = invoke(guest, "kernel32.dll", "CreateMutexW", [0, 0, nameW]);
  assert.ok(mutex !== 0);
  guest.writeAnsiString(nameA, "BPTK_MUTEX", 16);
  assert.equal(invoke(guest, "kernel32.dll", "OpenMutexW", [0, 0, nameW]), mutex, "the open returns the create's handle");
  guest.writeAnsiString(nameA, "BPTK_ABSENT", 16);
  assert.equal(invoke(guest, "kernel32.dll", "OpenMutexA", [0, 0, nameA]), 0);
  assert.equal(guest.getLastError(), 2, "an absent named object is ERROR_FILE_NOT_FOUND");
  const semaphore = invoke(guest, "kernel32.dll", "CreateSemaphoreA", [0, 1, 4, nameA]);
  assert.ok(semaphore !== 0, "a named semaphore create succeeds");
  assert.equal(invoke(guest, "kernel32.dll", "OpenSemaphoreA", [0, 0, nameA]), semaphore);
  const timer = invoke(guest, "kernel32.dll", "CreateWaitableTimerW", [0, 0, nameW]);
  assert.ok(timer !== 0);
  assert.equal(invoke(guest, "kernel32.dll", "OpenWaitableTimerW", [0, 0, nameW]), timer);
  const event = invoke(guest, "kernel32.dll", "CreateEventA", [0, 0, 0, nameA]);
  assert.ok(event !== 0);
  assert.equal(invoke(guest, "kernel32.dll", "OpenEventA", [0, 0, nameA]), event, "an ANSI named event opens by its ANSI name");
});

test("BPTK-010 sync breadth: the address wait times out on an unchanged value and skips a changed one", () => {
  const { guest } = createConformanceMachine();
  const target = guest.layout.arena_base + 0x40;
  const comparand = guest.layout.arena_base + 0x80;
  guest.memory.writeMemory(target, 4, 5);
  guest.memory.writeMemory(comparand, 4, 6);
  assert.equal(invoke(guest, "kernel32.dll", "WaitOnAddress", [target, comparand, 4, 0]), 1, "a changed value never parks");
  guest.memory.writeMemory(comparand, 4, 5);
  assert.equal(invoke(guest, "kernel32.dll", "WaitOnAddress", [target, comparand, 4, 50]), 0);
  assert.equal(guest.getLastError(), 258, "an unchanged value burns the timeout and reports WAIT_TIMEOUT");
  assert.ok(Math.abs(guest.clock.elapsedGuestMs() - 50) < 0.001);
  assert.equal(invoke(guest, "kernel32.dll", "WakeByAddressAll", [target]), 1);
  assert.equal(invoke(guest, "kernel32.dll", "WakeByAddressSingle", [target]), 1);
});

test("BPTK-010: SleepConditionVariableSRW times out, refuses NULL, and does not deadlock a zero wait", () => {
  const { guest } = createConformanceMachine();
  const condition = guest.layout.arena_base + 0x40;
  const lock = guest.layout.arena_base + 0x80;
  guest.memory.writeMemory(condition, 4, 0);
  guest.memory.writeMemory(lock, 4, 0);
  assert.equal(invoke(guest, "kernel32.dll", "SleepConditionVariableSRW", [0, lock, 0, 0]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "kernel32.dll", "SleepConditionVariableSRW", [condition, 0, 0, 0]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "kernel32.dll", "SleepConditionVariableSRW", [condition, lock, 0, 0]), 0);
  assert.equal(guest.getLastError(), 258);
  assert.equal(invoke(guest, "kernel32.dll", "SleepConditionVariableCS", [condition, lock, 50]), 0);
  assert.equal(guest.getLastError(), 258);
  assert.equal(invoke(guest, "kernel32.dll", "WakeConditionVariable", [condition]), 0);
  assert.equal(invoke(guest, "kernel32.dll", "WakeAllConditionVariable", [condition]), 0);
});

test("BPTK-053: RaiseException of MSVC SetThreadName continues without a debugger", () => {
  const { guest } = createConformanceMachine();
  assert.equal(invoke(guest, "kernel32.dll", "RaiseException", [0x406d1388, 0, 0, 0]), 0);
});

test("BPTK-010: HeapAlloc returns an 8-byte-aligned block", () => {
  const { guest } = createConformanceMachine();
  const block = invoke(guest, "kernel32.dll", "HeapAlloc", [0, 0, 1]);
  assert.equal(block & 7, 0);
  assert.equal(invoke(guest, "kernel32.dll", "HeapFree", [0, 0, block]), 1);
});

test("BPTK-103: CP_ACP is the declared 1252 page for conversion and GetCPInfo", () => {
  const { guest, memory } = createConformanceMachine();
  const ansi = guest.layout.arena_base + 0x80;
  const wide = guest.layout.arena_base + 0x100;
  const info = guest.layout.arena_base + 0x200;
  guest.writeAnsiString(ansi, "Hello", 32);
  assert.equal(invoke(guest, "kernel32.dll", "MultiByteToWideChar", [0, 0, ansi, 5, wide, 32]), 5);
  guest.writeWideString(wide, "Hello", 32);
  assert.equal(invoke(guest, "kernel32.dll", "WideCharToMultiByte", [0, 0, wide, 5, ansi, 64, 0, 0]), 5);
  assert.equal(invoke(guest, "kernel32.dll", "GetCPInfo", [0, info]), 1);
  assert.equal(memory.readMemory(info, 4), 1);
  assert.equal(invoke(guest, "kernel32.dll", "IsValidCodePage", [0]), 0);
});

test("BPTK-103: GetUserDefaultLocaleName and LCIDToLocaleName write en-US", () => {
  const { guest } = createConformanceMachine();
  const dest = guest.layout.arena_base + 0x80;
  assert.equal(invoke(guest, "kernel32.dll", "GetUserDefaultLocaleName", [dest, 16]), 6);
  assert.equal(guest.readWideString(dest), "en-US");
  assert.equal(invoke(guest, "kernel32.dll", "LCIDToLocaleName", [0x0409, dest, 16, 0]), 6);
  assert.equal(invoke(guest, "kernel32.dll", "AppPolicyGetProcessTerminationMethod", [0, dest]), 0);
  assert.equal(guest.memory.readMemory(dest, 4), 1);
});

test("BPTK-010: VerSetConditionMask packs a 3-bit condition and VerifyVersionInfoW compares the profile", () => {
  const { guest, memory } = createConformanceMachine();
  assert.equal(invoke(guest, "kernel32.dll", "VerSetConditionMask", [0, 0, 2, 3]), 24);
  assert.equal(guest.return_edx ?? 0, 0);
  const info = guest.layout.arena_base + 0x200;
  memory.writeMemory(info, 4, 284);
  memory.writeMemory(info + 4, 4, 5);
  memory.writeMemory(info + 8, 4, 0);
  memory.writeMemory(info + 12, 4, 0);
  memory.writeMemory(info + 16, 4, 0);
  assert.equal(invoke(guest, "kernel32.dll", "VerifyVersionInfoW", [info, 2, 24, 0]), 1);
  memory.writeMemory(info + 4, 4, 10);
  assert.equal(invoke(guest, "kernel32.dll", "VerifyVersionInfoW", [info, 2, 8, 0]), 0);
  assert.equal(guest.getLastError(), 1150);
  assert.equal(invoke(guest, "kernel32.dll", "IsThreadAFiber", []), 0);
  assert.equal(invoke(guest, "ntdll.dll", "RtlVerifyVersionInfo", [info, 2, 24, 0]), 0xc0000059);
  memory.writeMemory(info + 4, 4, 5);
  assert.equal(invoke(guest, "ntdll.dll", "RtlVerifyVersionInfo", [info, 2, 24, 0]), 0);
  assert.equal(invoke(guest, "kernel32.dll", "SetThreadDescription", [0xfffffffe, 0]), 0);
});

test("BPTK-010: LoadLibraryExW appends .dll and honors LOAD_LIBRARY_SEARCH_SYSTEM32", () => {
  const { guest } = createConformanceMachine();
  guest.writeWideString(guest.layout.arena_base + 0x80, "kernel32", 32);
  assert.equal(invoke(guest, "kernel32.dll", "LoadLibraryExW", [guest.layout.arena_base + 0x80, 0, 0x800]), 0x00020002);
  guest.writeWideString(guest.layout.arena_base + 0x80, "api-ms-win-core-localization-l1-2-1", 64);
  assert.equal(invoke(guest, "kernel32.dll", "LoadLibraryExW", [guest.layout.arena_base + 0x80, 0, 0x800]), 0x00020002);
  guest.writeWideString(guest.layout.arena_base + 0x80, "api-ms-win-appmodel-runtime-l1-1-2", 64);
  assert.equal(invoke(guest, "kernel32.dll", "LoadLibraryExW", [guest.layout.arena_base + 0x80, 0, 0x800]), 0x00020002);
  guest.writeAnsiString(guest.layout.arena_base + 0x180, "AppPolicyGetProcessTerminationMethod", 64);
  const appThunk = invoke(guest, "kernel32.dll", "GetProcAddress", [0x00020002, guest.layout.arena_base + 0x180]);
  assert.notEqual(appThunk, 0);
  const dest = guest.layout.arena_base + 0x200;
  assert.equal(guest.invokeExport(guest.exportAt(appThunk), [0, dest]), 0);
  assert.equal(guest.memory.readMemory(dest, 4), 1);
  guest.writeAnsiString(guest.layout.arena_base + 0x80, "kernelbase", 32);
  assert.equal(invoke(guest, "kernel32.dll", "LoadLibraryA", [guest.layout.arena_base + 0x80]), 0x00020002);
});

test("LoadLibraryW of OPENGL32.DLL returns a handle GetProcAddress can resolve", () => {
  const { guest } = createConformanceMachine();
  const name = guest.layout.arena_base + 0x80;
  const symbol = guest.layout.arena_base + 0x100;
  guest.writeWideString(name, "OPENGL32.DLL", 32);
  const module = invoke(guest, "kernel32.dll", "LoadLibraryW", [name]);
  assert.equal(module, 0x0002000c);
  guest.writeAnsiString(symbol, "glGetError", 16);
  const thunk = invoke(guest, "kernel32.dll", "GetProcAddress", [module, symbol]);
  assert.notEqual(thunk, 0);
  assert.equal(guest.invokeExport(guest.exportAt(thunk), []), 0);
});

test("BPTK-010: VirtualProtect succeeds on a mapped PE image range", () => {
  const memory = createIsolatedWin32Memory();
  let guestMs = 0;
  const clock = {
    mode: "virtual_monotonic",
    elapsedGuestMs: () => guestMs,
    advanceVirtualMs: (delta) => { guestMs += delta; },
    tickCount: () => 0,
    qpc: () => 0,
    rdtsc: () => 0,
    describe: () => ({ source: "one_monotonic_clock", mode: "virtual_monotonic" }),
  };
  const guest = createWin32Hle(memory, memory.layout, { executable_name: "game.exe", clock, image_base: 0x400000, image_size_byte: 0x20000 });
  const oldProtect = memory.layout.arena_base + 0x40;
  assert.equal(invoke(guest, "kernel32.dll", "VirtualProtect", [0x401000, 0x80, 4, oldProtect]), 1);
  assert.equal(memory.readMemory(oldProtect, 4), 0x40);
});

test("BPTK-010: HeapAlloc(NULL) is the process heap the ucrt uses before HeapCreate", () => {
  const { guest } = createConformanceMachine();
  const block = invoke(guest, "kernel32.dll", "HeapAlloc", [0, 0, 32]);
  assert.notEqual(block, 0, "a null heap handle allocates from the process heap");
  assert.equal(invoke(guest, "kernel32.dll", "HeapFree", [0, 0, block]), 1);
});

test("BPTK-010: FlsGet/Set on FLS_OUT_OF_INDEXES keep the CRT per-thread block", () => {
  const { guest } = createConformanceMachine();
  assert.equal(invoke(guest, "kernel32.dll", "FlsSetValue", [0xffffffff, 0x1234]), 1);
  assert.equal(invoke(guest, "kernel32.dll", "FlsGetValue", [0xffffffff]), 0x1234);
});

test("BPTK-010: DisableThreadLibraryCalls succeeds so a sidecar DllMain IAT is bound", () => {
  const { guest } = createConformanceMachine();
  assert.equal(invoke(guest, "kernel32.dll", "DisableThreadLibraryCalls", [0x00400000]), 1);
});

test("BPTK-010: EnterCriticalSection adopts a zeroed CRITICAL_SECTION on first use", () => {
  const { guest, memory } = createConformanceMachine();
  const cell = guest.layout.arena_base + 0x200;
  memory.writeBlock(cell, Buffer.alloc(24));
  assert.equal(invoke(guest, "kernel32.dll", "EnterCriticalSection", [cell]), 0);
  assert.equal(invoke(guest, "kernel32.dll", "LeaveCriticalSection", [cell]), 0);
});

test("BPTK-010: EnterCriticalSection still refuses a non-zero uninitialized cell", () => {
  const { guest, memory } = createConformanceMachine();
  const cell = guest.layout.arena_base + 0x240;
  memory.writeMemory(cell, 4, 0x12345678);
  assert.throws(() => invoke(guest, "kernel32.dll", "EnterCriticalSection", [cell]), /not initialized/);
});

test("BPTK-010 sync breadth: SignalObjectAndWait releases then waits, and the thread exit rows answer", () => {
  const { guest, memory } = createConformanceMachine();
  const scratch = guest.layout.arena_base + 0x40;
  const semaphore = invoke(guest, "kernel32.dll", "CreateSemaphoreA", [0, 0, 4, 0]);
  const event = invoke(guest, "kernel32.dll", "CreateEventW", [0, 0, 0, 0]);
  assert.equal(invoke(guest, "kernel32.dll", "SignalObjectAndWait", [semaphore, event, 0, 0]), 0x102, "the released semaphore cannot satisfy the unsignaled event wait");
  memory.writeMemory(scratch, 4, 0);
  assert.equal(invoke(guest, "kernel32.dll", "ReleaseSemaphore", [semaphore, 0, scratch]), 0, "the signal half released the count, so an over-release check sees count 1");
  assert.equal(invoke(guest, "kernel32.dll", "GetExitCodeThread", [0xfffffffe, scratch]), 1);
  assert.equal(memory.readMemory(scratch, 4), 259, "the one live thread reports STILL_ACTIVE");
  assert.equal(invoke(guest, "kernel32.dll", "GetExitCodeThread", [0x00012345, scratch]), 0, "no other thread handle exists");
  assert.throws(() => invoke(guest, "kernel32.dll", "ExitThread", [0]), /ended its own process/);
  assert.equal(invoke(guest, "kernel32.dll", "SleepEx", [10, 0]), 0);
  assert.equal(invoke(guest, "kernel32.dll", "SwitchToThread", []), 0);
});
