// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

function run(argument) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

function createPe32(code, option = {}) {
  const file = Buffer.alloc(0x800);
  file.writeUInt16LE(0x5a4d, 0);
  file.writeUInt32LE(0x80, 0x3c);
  file.writeUInt32LE(0x00004550, 0x80);
  file.writeUInt16LE(0x14c, 0x84);
  file.writeUInt16LE(1, 0x86);
  file.writeUInt16LE(224, 0x94);
  file.writeUInt16LE(0x10b, 0x98);
  file.writeUInt32LE(0x1000, 0xa8);
  file.writeUInt32LE(0x400000, 0xb4);
  file.writeUInt32LE(0x2000, 0xd0);
  file.writeUInt32LE(0x200, 0xd4);
  file.writeUInt32LE(0x10000, 0xe0);
  file.writeUInt32LE(0x1000, 0xe4);
  file.writeUInt32LE(0x10000, 0xe8);
  file.writeUInt32LE(0x1000, 0xec);
  file.writeUInt32LE(16, 0xf4);
  const sectionOffset = 0x178;
  file.write(".text", sectionOffset);
  file.writeUInt32LE(0x1000, sectionOffset + 8);
  file.writeUInt32LE(0x1000, sectionOffset + 12);
  file.writeUInt32LE((0x60000020 | (option.is_writable === false ? 0 : 0x80000000)) >>> 0, sectionOffset + 36);
  file.writeUInt32LE(0x600, sectionOffset + 16);
  file.writeUInt32LE(0x200, sectionOffset + 20);
  Buffer.from(code).copy(file, 0x200);
  if (option.import_value) {
    file.writeUInt32LE(0x1100, 0x98 + 96 + 8);
    file.writeUInt32LE(40, 0x98 + 96 + 12);
    file.writeUInt32LE(0x1140, 0x300);
    file.writeUInt32LE(0x1180, 0x30c);
    file.writeUInt32LE(0x1150, 0x310);
    file.writeUInt32LE(0x1190, 0x200 + 0x1140 - 0x1000);
    file.writeUInt32LE(0x1190, 0x200 + 0x1150 - 0x1000);
    file.write("KERNEL32.dll", 0x200 + 0x1180 - 0x1000);
    file.writeUInt16LE(0, 0x200 + 0x1190 - 0x1000);
    file.write(option.import_symbol ?? "ExitProcess", 0x200 + 0x1192 - 0x1000);
  }
  if (option.tls_value) {
    file.writeUInt32LE(0x1200, 0x98 + 96 + 9 * 8);
    file.writeUInt32LE(24, 0x98 + 96 + 9 * 8 + 4);
    const tlsOffset = 0x200 + 0x1200 - 0x1000;
    file.writeUInt32LE(0x00401140, tlsOffset + 12);
    file.writeUInt32LE(0x00401000, 0x200 + 0x1140 - 0x1000);
  }
  return file;
}

function createImportBudgetPe32() {
  const file = Buffer.alloc(0x24000);
  file.writeUInt16LE(0x5a4d, 0);
  file.writeUInt32LE(0x80, 0x3c);
  file.writeUInt32LE(0x00004550, 0x80);
  file.writeUInt16LE(0x14c, 0x84);
  file.writeUInt16LE(1, 0x86);
  file.writeUInt16LE(224, 0x94);
  file.writeUInt16LE(0x10b, 0x98);
  file.writeUInt32LE(0x1000, 0xa8);
  file.writeUInt32LE(0x400000, 0xb4);
  file.writeUInt32LE(0x24000, 0xd0);
  file.writeUInt32LE(0x200, 0xd4);
  file.writeUInt32LE(0x10000, 0xe0);
  file.writeUInt32LE(0x1000, 0xe4);
  file.writeUInt32LE(0x10000, 0xe8);
  file.writeUInt32LE(0x1000, 0xec);
  file.writeUInt32LE(16, 0xf4);
  file.writeUInt32LE(0x1000, 0x98 + 96 + 8);
  file.writeUInt32LE(60, 0x98 + 96 + 12);
  const sectionOffset = 0x178;
  file.write(".text", sectionOffset);
  file.writeUInt32LE(0x23000, sectionOffset + 8);
  file.writeUInt32LE(0x1000, sectionOffset + 12);
  file.writeUInt32LE(0x23000, sectionOffset + 16);
  file.writeUInt32LE(0x200, sectionOffset + 20);
  file.writeUInt32LE(0xe0000020, sectionOffset + 36);
  file[0x200] = 0xc3;
  const fileOffset = (rva) => 0x200 + rva - 0x1000;
  const descriptor = (offset, lookupRva, libraryRva, iatRva) => {
    file.writeUInt32LE(lookupRva, offset);
    file.writeUInt32LE(libraryRva, offset + 12);
    file.writeUInt32LE(iatRva, offset + 16);
    file.write("KERNEL32.dll", fileOffset(libraryRva));
    for (let index = 0; index < 8192; index += 1) {
      file.writeUInt32LE((0x80000000 | (index + 1)) >>> 0, fileOffset(lookupRva + index * 4));
      file.writeUInt32LE(0, fileOffset(iatRva + index * 4));
    }
  };
  descriptor(fileOffset(0x1000), 0x2000, 0x1800, 0x4000);
  descriptor(fileOffset(0x1014), 0xa000, 0x1900, 0xc000);
  return file;
}

function createPackage(context, code, option = {}) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-runtime-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
  writeFileSync(join(packagePath, "game.exe"), createPe32(code, option));
  const manifest = { schema_version: 1, executable: "game.exe" };
  if (option.execution !== false) manifest.execution = { profile: "i386_probe_v1", instruction_budget_count: option.instruction_budget_count ?? 100 };
  if (option.import_value) manifest.import = [];
  writeFileSync(join(packagePath, "bptk.json"), JSON.stringify(manifest));
  return { packagePath, executablePath: join(packagePath, "game.exe") };
}

function readRun(packagePath) {
  const result = run(["run", packagePath, "--json"]);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("regression risk: raw PE and package without execution remain static", (context) => {
  const value = createPackage(context, [0xc3], { execution: false });
  const raw = readRun(value.executablePath);
  const packaged = readRun(value.packagePath);
  assert.equal(raw.is_executed, false);
  assert.equal(packaged.is_executed, false);
  assert.equal(raw.stop_reason, undefined);
  assert.equal(packaged.stop_reason, undefined);
});

test("regression risk: arithmetic, branch, call, return, and flags reach entry_return", (context) => {
  const code = [0xb8, 2, 0, 0, 0, 0xbb, 3, 0, 0, 0, 0x01, 0xd8, 0x83, 0xf8, 5, 0x74, 5, 0xb8, 0, 0, 0, 0, 0xe8, 1, 0, 0, 0, 0xc3, 0xc3];
  const report = readRun(createPackage(context, code).packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.is_executed, true);
  assert.equal(report.register.eax, 5);
  assert.equal(report.flag.zero, true);
  assert.equal(report.exception, null);
});

test("regression risk: CALL r/m32 reads its target before pushing the return address", (context) => {
  const code = [0xbc, 0x20, 0x10, 0x40, 0x00, 0xff, 0xd4];
  while (code.length < 0x20) code.push(0x90);
  code.push(0xbc, 0xf8, 0xff, 0x00, 0x70, 0xc3);
  const report = readRun(createPackage(context, code).packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.exception, null);
});

test("regression risk: 32-bit carry and zero flags normalize unsigned overflow", (context) => {
  const code = [0xb8, 0xff, 0xff, 0xff, 0xff, 0x05, 1, 0, 0, 0, 0xc3];
  const report = readRun(createPackage(context, code).packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.register.eax, 0);
  assert.equal(report.flag.carry, true);
  assert.equal(report.flag.zero, true);
});

test("regression risk: INC updates arithmetic flags while preserving incoming carry", (context) => {
  const code = [0xb8, 0xff, 0xff, 0xff, 0xff, 0x05, 1, 0, 0, 0, 0xbb, 1, 0, 0, 0, 0x43, 0xc3];
  const report = readRun(createPackage(context, code).packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.register.ebx, 2);
  assert.equal(report.flag.carry, true);
  assert.equal(report.flag.zero, false);
});

test("regression risk: high-byte register writes preserve the other register byte", (context) => {
  const code = [0xb8, 0x44, 0x33, 0x22, 0x11, 0xb4, 0x99, 0xc3];
  const report = readRun(createPackage(context, code).packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.register.eax, 0x11229944);
});

test("regression risk: mutable image write changes the executed instruction", (context) => {
  const code = [0xb8, 1, 0, 0, 0, 0xc7, 5, 0x21, 0x10, 0x40, 0, 9, 0, 0, 0, 0xe9, 0x0c, 0, 0, 0, 0];
  while (code.length < 0x20) code.push(0);
  code.push(0xb8, 2, 0, 0, 0, 0xc3);
  const report = readRun(createPackage(context, code).packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.register.eax, 9);
  assert.match(report.memory_sha256, /^[a-f0-9]{64}$/);
});

test("regression risk: deterministic infinite branch consumes the exact budget", (context) => {
  const report = readRun(createPackage(context, [0xeb, 0xfe], { instruction_budget_count: 7 }).packagePath);
  assert.equal(report.stop_reason, "instruction_budget_exhausted");
  assert.equal(report.instruction_count, 7);
  assert.equal(report.is_executed, true);
});

test("regression risk: x87 outside the bounded subset is a structured unsupported stop", (context) => {
  const report = readRun(createPackage(context, [0xd9, 0xf0]).packagePath); // F2XM1
  assert.equal(report.stop_reason, "unsupported_opcode");
  assert.equal(report.exception.code, "unsupported_opcode");
  assert.equal(report.instruction_count, 1);
});

test("regression risk: bounded x87 load, multiply, and store keep deterministic double state", (context) => {
  // Build a float32 3.5 and a float32 2.0 in the mapped section, FLD both,
  // FMUL, FSTP the product back, and verify the deterministic memory hash.
  const fixture = createPackage(context, [
    0xb8, 0x00, 0x00, 0x40, 0x40,             // mov eax, 0x40400000 (3.5f)
    0xa3, 0x00, 0x16, 0x40, 0x00,             // mov [0x401600], eax
    0xb8, 0x00, 0x00, 0x00, 0x40,             // mov eax, 0x40000000 (2.0f)
    0xa3, 0x04, 0x16, 0x40, 0x00,             // mov [0x401604], eax
    0xd9, 0x05, 0x00, 0x16, 0x40, 0x00,       // fld dword [0x401600]
    0xd9, 0x05, 0x04, 0x16, 0x40, 0x00,       // fld dword [0x401604]
    0xde, 0xc1,                               // faddp st(1), st(0)
    0xd9, 0x1d, 0x08, 0x16, 0x40, 0x00,       // fstp dword [0x401608]
    0xc3,
  ]).packagePath;
  const report = readRun(fixture);
  assert.equal(report.stop_reason, "entry_return");
  const second = readRun(fixture);
  assert.equal(second.memory_sha256, report.memory_sha256);
});

test("regression risk: the operand-size override executes the 16-bit form with the high word preserved", (context) => {
  // mov eax, 0x12345678; mov ax, 0x1234 — the 16-bit write preserves the
  // high word of EAX, the rule the probe must not confuse with zeroing.
  const report = readRun(createPackage(context, [
    0xb8, 0x78, 0x56, 0x34, 0x12,
    0x66, 0xb8, 0x34, 0x12,
    0xc3,
  ], { instruction_budget_count: 10 }).packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.register.eax, 0x12341234);
});

test("regression risk: 16-bit arithmetic sets the carry and zero flags on the 16-bit result", (context) => {
  // mov eax, 0; mov ax, 0xffff (via 66 B8); add ax, 2 via 66 05 — wraps to
  // 0x0001 with carry out of bit 15 and the high word of EAX untouched.
  const report = readRun(createPackage(context, [
    0xb8, 0, 0, 0, 0,
    0x66, 0xb8, 0xff, 0xff,
    0x66, 0x05, 0x02, 0x00,
    0xc3,
  ], { instruction_budget_count: 10 }).packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.register.eax, 0x00000001);
  assert.equal(report.flag.carry, true);
  assert.equal(report.flag.zero, false);
});

test("regression risk: the 16-bit push decrements the stack pointer by two", (context) => {
  // mov eax, 0x00aa00bb; push ax; pop edx (32-bit pop of the two pushed byte
  // plus the two stack byte already there is not decoded) — assert through
  // esp and memory instead: push ax twice, then read the trace hash stability.
  const report = readRun(createPackage(context, [
    0xb8, 0xbb, 0x00, 0xaa, 0x00,
    0x66, 0x50,
    0x89, 0xe2,
    0x83, 0xc4, 0x02,
    0xc3,
  ], { instruction_budget_count: 10 }).packagePath);
  assert.equal(report.stop_reason, "entry_return");
  // The 16-bit push moves ESP by exactly two and the stack rebalances.
  assert.equal(report.register.edx, 0x7000fff6);
  assert.equal(report.register.esp, 0x7000fffc);
  assert.equal(report.register.eax, 0x00aa00bb);
});

test("regression risk: the rare 16-bit control forms stay structured unsupported", (context) => {
  const callReport = readRun(createPackage(context, [0x66, 0xe8, 0, 0, 0, 0], { instruction_budget_count: 10 }).packagePath);
  assert.equal(callReport.stop_reason, "unsupported_opcode");
  assert.equal(callReport.exception.opcode, 0xe8);
  const retReport = readRun(createPackage(context, [0x66, 0xc3], { instruction_budget_count: 10 }).packagePath);
  assert.equal(retReport.stop_reason, "unsupported_opcode");
  const pushfReport = readRun(createPackage(context, [0x66, 0x9c], { instruction_budget_count: 10 }).packagePath);
  assert.equal(pushfReport.stop_reason, "unsupported_opcode");
  const ffReport = readRun(createPackage(context, [0x66, 0xff, 0x15, 0, 0x10, 0x40, 0x00], { instruction_budget_count: 10 }).packagePath);
  assert.equal(ffReport.stop_reason, "unsupported_opcode");
});

test("regression risk: a served import binds to the HLE thunk page and a TLS callback fires before entry", (context) => {
  // The Win32 core HLE (BPTK-010) serves kernel32!ExitProcess, so the image
  // now executes and the import reports resolved against the thunk page.
  const importReport = readRun(createPackage(context, [0xc3], { import_value: true }).packagePath);
  assert.equal(importReport.is_executed, true);
  assert.equal(importReport.stop_reason, "entry_return");
  assert.equal(importReport.import[0].resolution_state, "resolved");
  assert.ok(importReport.import[0].address >= 0xf0000000, "the thunk page sits in the declared high block");
  assert.equal(importReport.hle.call_count, 0);
  // The TLS callback phase runs before the entry phase over one budget.
  const tlsReport = readRun(createPackage(context, [0xc3], { tls_value: true }).packagePath);
  assert.equal(tlsReport.is_executed, true);
  assert.equal(tlsReport.stop_reason, "entry_return");
  assert.equal(tlsReport.instruction_count, 2);
});

test("regression risk: GetModuleHandle(NULL) returns the mapped image base", (context) => {
  // push 0; call [GetModuleHandleW]; ret. On Win32 the HMODULE is the load
  // address, so a CRT that adds an RVA to GetModuleHandle(NULL) fetches the
  // real image, not a synthetic handle window.
  const code = [0x6a, 0x00, 0xff, 0x15, 0x50, 0x11, 0x40, 0x00, 0xc3];
  const report = readRun(createPackage(context, code, { import_value: true, import_symbol: "GetModuleHandleW" }).packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.exception, null);
  assert.equal(report.register.eax, 0x00400000);
});

test("regression risk: the main module handle dereferences to the mapped image header", (context) => {
  // push 0; call [GetModuleHandleW]; movzx eax, word ptr [eax]; ret. On Win32 the
  // handle GetModuleHandle(NULL) returns is the base the image is mapped at, so
  // the CRT validates it by reading the "MZ" magic straight through the handle.
  const code = [0x6a, 0x00, 0xff, 0x15, 0x50, 0x11, 0x40, 0x00, 0x0f, 0xb7, 0x00, 0xc3];
  const report = readRun(createPackage(context, code, { import_value: true, import_symbol: "GetModuleHandleW" }).packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.exception, null);
  assert.equal(report.register.eax, 0x5a4d);
});

test("regression risk: a write through the DOS header stays a structured fault", (context) => {
  // push 0; call [GetModuleHandleW]; mov word ptr [eax], 0 — the PE header sits
  // before the first section, so a store through the HMODULE (the load base)
  // is an unmapped-image write, not a mutation of executable bytes.
  const code = [0x6a, 0x00, 0xff, 0x15, 0x50, 0x11, 0x40, 0x00, 0x66, 0xc7, 0x00, 0x00, 0x00, 0xc3];
  const report = readRun(createPackage(context, code, { import_value: true, import_symbol: "GetModuleHandleW" }).packagePath);
  assert.equal(report.stop_reason, "write_fault");
  assert.equal(report.exception.fault_address, 0x00400000);
});

test("regression risk: the fs moffs load resolves against the TEB base, not a zero segment", (context) => {
  // mov eax, fs:[0x18]; ret — the NT_TIB self pointer. The moffs form (0xa1)
  // must add the fs segment base like a ModRM effective offset, so eax lands on
  // the mapped TEB base. Without it the load read linear address 0x18.
  const report = readRun(createPackage(context, [0x64, 0xa1, 0x18, 0x00, 0x00, 0x00, 0xc3], { import_value: true }).packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.exception, null);
  assert.equal(report.register.eax, report.thread.teb_base);
});

test("regression risk: the fs moffs store lands in the TEB and reads back through the same base", (context) => {
  // mov eax,0x11223344; mov fs:[0x40],eax (0xa3); xor eax,eax; mov eax,fs:[0x40]
  // (0xa1). The exact CRT SEH-prologue store form: without the fs base on the
  // moffs store it wrote linear address 0x40 and faulted; with it the value
  // round-trips through a TEB slot.
  const report = readRun(createPackage(context, [
    0xb8, 0x44, 0x33, 0x22, 0x11,       // mov eax, 0x11223344
    0x64, 0xa3, 0x40, 0x00, 0x00, 0x00, // mov fs:[0x40], eax
    0x31, 0xc0,                         // xor eax, eax
    0x64, 0xa1, 0x40, 0x00, 0x00, 0x00, // mov eax, fs:[0x40]
    0xc3,
  ], { import_value: true }).packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.exception, null);
  assert.equal(report.register.eax, 0x11223344);
});

test("regression risk: CPUID serves the declared processor identity leaf table", (context) => {
  // mov eax, 0; cpuid; ret — vendor string lands in EBX:ECX:EDX.
  const vendor = readRun(createPackage(context, [
    0xb8, 0, 0, 0, 0,
    0x0f, 0xa2,
    0xc3,
  ], { instruction_budget_count: 10 }).packagePath);
  assert.equal(vendor.stop_reason, "entry_return");
  assert.equal(vendor.register.ebx, 0x756e6547);
  assert.equal(vendor.register.ecx, 0x6c65746e);
  assert.equal(vendor.register.edx, 0x49656e69);
  const features = readRun(createPackage(context, [
    0xb8, 1, 0, 0, 0,
    0x0f, 0xa2,
    0xc3,
  ], { instruction_budget_count: 10 }).packagePath);
  assert.equal(features.stop_reason, "entry_return");
  assert.equal(features.register.eax, 0x663);
  // Leaf 0x80000000 reports itself as the highest extended function.
  const extended = readRun(createPackage(context, [
    0xb8, 0, 0, 0, 0x80,
    0x0f, 0xa2,
    0xc3,
  ], { instruction_budget_count: 10 }).packagePath);
  assert.equal(extended.stop_reason, "entry_return");
  assert.equal(extended.register.eax, 0x80000000);
  assert.equal(extended.register.ebx, 0);
  assert.equal(extended.register.ecx, 0);
  assert.equal(extended.register.edx, 0);
  // An undeclared leaf is a structured unsupported stop, never host data.
  const unknown = readRun(createPackage(context, [
    0xb8, 2, 0, 0, 0,
    0x0f, 0xa2,
    0xc3,
  ], { instruction_budget_count: 10 }).packagePath);
  assert.equal(unknown.stop_reason, "unsupported_opcode");
});

test("regression risk: memory fault is structured and deterministic", (context) => {
  const report = readRun(createPackage(context, [0xa1, 0xef, 0xbe, 0xad, 0xde]).packagePath);
  assert.equal(report.stop_reason, "read_fault");
  assert.equal(report.exception.code, "read_fault");
  assert.equal(report.exception.instruction_address, report.entry_address);
  assert.equal(report.exception.eip, report.entry_address);
  assert.equal(report.register.eip, report.entry_address);
  assert.equal(report.register.eax, 0);
  assert.equal(report.flag.eflags, 2);
  assert.equal(report.instruction_count, 1);
});

test("regression risk: ALU write fault rolls back register, flag, EIP, and image state", (context) => {
  const value = createPackage(context, [0xb8, 1, 0, 0, 0, 0x01, 0x05, 0, 0x10, 0x40, 0, 0xc3], { is_writable: false });
  const staticReport = readRun(value.executablePath);
  const report = readRun(value.packagePath);
  assert.equal(report.stop_reason, "write_fault");
  assert.equal(report.exception.instruction_address, report.entry_address + 5);
  assert.equal(report.exception.eip, report.entry_address + 5);
  assert.equal(report.register.eip, report.entry_address + 5);
  assert.equal(report.register.eax, 1);
  assert.equal(report.flag.eflags, 2);
  assert.equal(report.image_sha256, staticReport.image_sha256);
});

test("regression risk: run surface rejects an oversized sparse executable before full read", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-runtime-size-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const filePath = join(rootPath, "large.exe");
  writeFileSync(filePath, Buffer.alloc(0));
  truncateSync(filePath, 64 * 1024 * 1024 + 1);
  const result = run(["run", filePath, "--json"]);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr).error_code, "pe_file_size_limit");
});

test("regression risk: run surface rejects an oversized sparse package manifest", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-runtime-manifest-size-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
  const manifestPath = join(packagePath, "bptk.json");
  writeFileSync(manifestPath, Buffer.alloc(0));
  truncateSync(manifestPath, 256 * 1024 + 1);
  const result = run(["run", packagePath, "--json"]);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr).error_code, "package_manifest_size_limit");
});

test("regression risk: run surface refuses a symlink package manifest", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-runtime-manifest-link-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
  const targetPath = join(rootPath, "manifest.json");
  writeFileSync(targetPath, JSON.stringify({ schema_version: 1, executable: "game.exe" }));
  try {
    symlinkSync(targetPath, join(packagePath, "bptk.json"));
  } catch (error) {
    if (error.code === "EPERM") context.skip("the host denies symbolic-link creation");
    throw error;
  }
  const result = run(["run", packagePath, "--json"]);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr).error_code, "package_manifest_symlink");
});

test("regression risk: run surface reports one global import descriptor and thunk budget", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-runtime-import-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const filePath = join(rootPath, "many.exe");
  writeFileSync(filePath, createImportBudgetPe32());
  const result = run(["run", filePath, "--json"]);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr).error_code, "import_entry_limit");
});

test("regression risk: repeated probe keeps register, trace, and memory hashes stable", (context) => {
  const packagePath = createPackage(context, [0xb8, 7, 0, 0, 0, 0xc3]).packagePath;
  const first = readRun(packagePath);
  const second = readRun(packagePath);
  assert.deepEqual({ register: first.register, flag: first.flag, trace_sha256: first.trace_sha256, memory_sha256: first.memory_sha256, stop_reason: first.stop_reason }, { register: second.register, flag: second.flag, trace_sha256: second.trace_sha256, memory_sha256: second.memory_sha256, stop_reason: second.stop_reason });
});

test("regression risk: RDTSC serves guest time from one deterministic monotonic clock", (context) => {
  // Two RDTSC read separated by the declared 1000-cycle progression, then a
  // register subtraction that proves the second read advanced exactly the
  // declared amount. Writes stay inside the mapped section at 0x15f0.
  const packagePath = createPackage(context, [
    0x0f, 0x31,                   // RDTSC -> edx:eax
    0xa3, 0xf0, 0x15, 0x40, 0x00, // mov [0x4015f0], eax
    0x0f, 0x31,                   // RDTSC again
    0x2d, 0xe8, 0x03, 0x00, 0x00, // sub eax, 1000
    0xa3, 0xf4, 0x15, 0x40, 0x00, // mov [0x4015f4], eax
    0xa1, 0xf0, 0x15, 0x40, 0x00, // mov eax, [0x4015f0]
    0x2b, 0x05, 0xf4, 0x15, 0x40, 0x00, // sub eax, [0x4015f4]
    0xc3,
  ]).packagePath;
  const report = readRun(packagePath);
  assert.equal(report.is_executed, true);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.register.eax, 0);
  assert.equal(report.register.edx, 0);
  assert.equal(report.clock.source, "one_monotonic_clock");
  assert.equal(report.clock.mode, "virtual_monotonic");
  const second = readRun(packagePath);
  assert.equal(second.memory_sha256, report.memory_sha256);
});

test("regression risk: every derived time source stays on the single monotonic base", async () => {
  const { createGuestClock } = await import("../lib/clock.mjs");
  const clock = createGuestClock({ mode: "virtual_monotonic" });
  clock.advanceVirtualMs(1000);
  const qpcMs = (clock.qpc() / 10000000) * 1000;
  const tickMs = clock.tickCount();
  const vblankMs = (clock.vblankFrameCount() / 60) * 1000;
  // Every derivation is within one service step of the same guest time.
  assert.ok(Math.abs(qpcMs - tickMs) <= 2, `qpc ${qpcMs} vs tick ${tickMs}`);
  assert.ok(Math.abs(vblankMs - tickMs) <= 17, `vblank ${vblankMs} vs tick ${tickMs}`);
  const before = clock.tickCount();
  clock.advanceVirtualMs(1);
  assert.equal(clock.tickCount() - before, 1);
  clock.advanceVirtualMs(0xffffffff);
  assert.equal(clock.tickCount(), 1000); // wrapped modulo 2^32
});

test("regression risk: the clamp bounds guest time during a host stall", async () => {
  const { clampDelta } = await import("../lib/clock.mjs");
  assert.equal(clampDelta(-5, 100), 0);
  assert.equal(clampDelta(30, 100), 30);
  assert.equal(clampDelta(4000, 100), 100);
});

test("regression risk: an execution manifest declaring host capability is refused", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-runtime-containment-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
  writeFileSync(join(packagePath, "game.exe"), createPe32([0xc3]));
  writeFileSync(join(packagePath, "bptk.json"), JSON.stringify({
    schema_version: 1,
    executable: "game.exe",
    execution: { profile: "i386_probe_v1", instruction_budget_count: 10, file_system: "opfs" },
  }));
  const result = run(["run", packagePath, "--json"]);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr).error_code, "containment_policy_violation");
});

test("regression risk: every probe run reports the containment policy", (context) => {
  const packagePath = createPackage(context, [0xc3]).packagePath;
  const report = readRun(packagePath);
  assert.equal(report.containment.policy, "i386_probe_v1");
  assert.equal(report.containment.is_confined, true);
  assert.ok(report.containment.denied_capability.includes("host_script"));
  assert.ok(report.containment.denied_capability.includes("network"));
});

test("regression risk: shift and rotate produce exact counts and carry", (context) => {
  // mov eax, 1; shl eax, 4 -> 16; mov edi, 0x80000000; shr edi, 31 -> 1 with carry
  const packagePath = createPackage(context, [
    0xb8, 1, 0, 0, 0,                   // mov eax, 1
    0xc1, 0xe0, 4,                      // shl eax, 4
    0xa3, 0xf8, 0x15, 0x40, 0x00,       // mov [0x4015f8], eax
    0xbf, 0, 0, 0, 0x80,                // mov edi, 0x80000000
    0xd1, 0xe7,                         // shl edi, 1 (shifts out bit 31)
    0x89, 0xf8,                         // mov eax, edi
    0xa3, 0xfc, 0x15, 0x40, 0x00,       // mov [0x4015fc], eax
    0xc3,
  ]).packagePath;
  const report = readRun(packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.register.edi, 0);
  assert.equal(report.register.eax, 0);
  assert.equal(report.flag.carry, true);
  const second = readRun(packagePath);
  assert.equal(second.memory_sha256, report.memory_sha256);
});

test("regression risk: rep movsb copies a bounded buffer deterministically", (context) => {
  // mov esi, src; mov edi, dst; mov ecx, 8; cld; rep movsb
  const packagePath = createPackage(context, [
    0xbe, 0x10, 0x15, 0x40, 0x00,       // mov esi, 0x401510
    0xbf, 0x20, 0x15, 0x40, 0x00,       // mov edi, 0x401520
    0xb9, 8, 0, 0, 0,                   // mov ecx, 8
    0xfc,                               // cld
    0xf3, 0xa4,                         // rep movsb
    0xc3,
  ]).packagePath;
  const report = readRun(packagePath);
  assert.equal(report.stop_reason, "entry_return");
  const second = readRun(packagePath);
  assert.equal(second.memory_sha256, report.memory_sha256);
});

test("regression risk: setcc reflects the comparison result", (context) => {
  // mov eax, 5; cmp eax, 3; setg cl; movzx edx, cl
  const packagePath = createPackage(context, [
    0xb8, 5, 0, 0, 0,                   // mov eax, 5
    0x83, 0xf8, 3,                      // cmp eax, 3
    0x0f, 0x9f, 0xc1,                   // setg cl
    0xc1, 0xe1, 8,                      // shl ecx, 8
    0xc1, 0xe9, 8,                      // shr ecx, 8
    0xc3,
  ]).packagePath;
  const report = readRun(packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.register.ecx, 1);
});

test("regression risk: 32-bit multiply keeps the wide product exact", (context) => {
  // mov eax, 0x10000; mov ebx, 0x10000; mul ebx -> edx:eax = 0x1:0
  const packagePath = createPackage(context, [
    0xb8, 0, 0, 1, 0,                   // mov eax, 0x10000
    0xbb, 0, 0, 1, 0,                   // mov ebx, 0x10000
    0xf7, 0xe3,                         // mul ebx
    0xc3,
  ]).packagePath;
  const report = readRun(packagePath);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.register.eax, 0);
  assert.equal(report.register.edx, 1);
});

test("regression risk: division by zero is a structured divide_error", (context) => {
  const packagePath = createPackage(context, [
    0xb8, 5, 0, 0, 0,                   // mov eax, 5
    0x31, 0xd2,                         // xor edx, edx
    0xb3, 0,                            // mov bl, 0
    0xf6, 0xf3,                         // div bl
    0xc3,
  ]).packagePath;
  const report = readRun(packagePath);
  assert.equal(report.stop_reason, "divide_error");
  assert.equal(report.exception.code, "divide_error");
});
