// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The guest thread subsystem conformance suite (BPTK-025). Cycle 1 maps the
// Thread Environment Block into guest memory and resolves the fs segment
// override against it. Two layers are proven: the TEB image builder in
// isolation (every documented field at its documented displacement), and the
// live probe reading those fields through fs:[disp] on the real run surface,
// with the bare CPU-conformance probe keeping its structured refusal.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildTebImage, tebField, pebField, SEH_CHAIN_END, TEB_SIZE_BYTE } from "../lib/thread.mjs";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

function run(argument) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

// One flat PE with an entry .text section. When importValue is set the image
// imports kernel32!ExitProcess, which the Win32 core HLE serves, so execution
// takes the HLE path that maps the TEB. Without it the bare probe runs and the
// fs override stays a structured refusal.
function createPe32(code, importValue) {
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
  file.writeUInt32LE((0x60000020 | 0x80000000) >>> 0, sectionOffset + 36);
  file.writeUInt32LE(0x600, sectionOffset + 16);
  file.writeUInt32LE(0x200, sectionOffset + 20);
  Buffer.from(code).copy(file, 0x200);
  if (importValue) {
    file.writeUInt32LE(0x1100, 0x98 + 96 + 8);
    file.writeUInt32LE(40, 0x98 + 96 + 12);
    file.writeUInt32LE(0x1140, 0x300);
    file.writeUInt32LE(0x1180, 0x30c);
    file.writeUInt32LE(0x1150, 0x310);
    file.writeUInt32LE(0x1190, 0x200 + 0x1140 - 0x1000);
    file.writeUInt32LE(0x1190, 0x200 + 0x1150 - 0x1000);
    file.write("KERNEL32.dll", 0x200 + 0x1180 - 0x1000);
    file.writeUInt16LE(0, 0x200 + 0x1190 - 0x1000);
    file.write("ExitProcess", 0x200 + 0x1192 - 0x1000);
  }
  return file;
}

function readRun(context, code, option = {}) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-thread-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
  writeFileSync(join(packagePath, "game.exe"), createPe32(code, option.import_value ?? false));
  const manifest = { schema_version: 1, executable: "game.exe", execution: { profile: "i386_probe_v1", instruction_budget_count: option.instruction_budget_count ?? 100 } };
  if (option.import_value) manifest.import = [];
  writeFileSync(join(packagePath, "bptk.json"), JSON.stringify(manifest));
  const result = run(["run", packagePath, "--json"]);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

// A memory read of the TEB through fs: mov reg, fs:[disp]; the encoding is the
// fs prefix, 0x8b /r with mode 0 rm 5 (disp32 absolute), then ret.
const fsLoadEax = (disp) => [0x64, 0x8b, 0x05, disp & 0xff, (disp >>> 8) & 0xff, (disp >>> 16) & 0xff, (disp >>> 24) & 0xff];

test("teb builder places every documented field at its documented displacement", () => {
  const built = buildTebImage({
    tebBase: 0xf0000000,
    pebBase: 0xf0001000,
    stackHighAddress: 0x70010000,
    stackLowAddress: 0x70000000,
    imageBase: 0x00400000,
    processId: 0x111,
    threadId: 0x222,
  });
  assert.equal(built.teb.length, TEB_SIZE_BYTE);
  assert.equal(built.teb.readUInt32LE(tebField.seh_head), SEH_CHAIN_END);
  assert.equal(built.teb.readUInt32LE(tebField.stack_base), 0x70010000);
  assert.equal(built.teb.readUInt32LE(tebField.stack_limit), 0x70000000);
  assert.equal(built.teb.readUInt32LE(tebField.self), 0xf0000000);
  assert.equal(built.teb.readUInt32LE(tebField.process_environment_block), 0xf0001000);
  assert.equal(built.teb.readUInt32LE(tebField.process_id), 0x111);
  assert.equal(built.teb.readUInt32LE(tebField.thread_id), 0x222);
  assert.equal(built.teb.readUInt32LE(tebField.tls_slot), 0, "the inline TLS slot array starts zeroed");
  assert.equal(built.peb.readUInt32LE(pebField.image_base_address), 0x00400000);
  assert.equal(built.peb.readUInt8(pebField.being_debugged), 0);
  assert.equal(built.fs_base, 0xf0000000);
  assert.equal(built.gs_base, 0);
});

test("fs:[0] reads the empty SEH chain head through the mapped TEB", (context) => {
  const report = readRun(context, [...fsLoadEax(tebField.seh_head), 0xc3], { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.notEqual(report.thread, null);
  assert.equal(report.register.eax >>> 0, 0xffffffff);
});

test("fs:[0x18] self pointer is the TEB linear address and dereferences to itself", (context) => {
  // mov eax, fs:[0x18]; mov ecx, [eax]; ret — eax is the TEB base, and the
  // first dword at that linear address is the SEH chain head.
  const report = readRun(context, [...fsLoadEax(tebField.self), 0x8b, 0x08, 0xc3], { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.eax >>> 0, report.thread.teb_base >>> 0);
  assert.equal(report.register.ecx >>> 0, 0xffffffff);
});

test("fs:[0x30] walks the PEB to the image base", (context) => {
  // mov eax, fs:[0x30]; mov eax, [eax+8]; ret — PEB.ImageBaseAddress.
  const report = readRun(context, [...fsLoadEax(tebField.process_environment_block), 0x8b, 0x40, 0x08, 0xc3], { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.eax >>> 0, 0x00400000);
});

test("fs:[4] and fs:[8] carry the real stack bounds the probe runs on", (context) => {
  // mov eax, fs:[4] (StackBase); mov ebx, fs:[8] (StackLimit); ret.
  const code = [...fsLoadEax(tebField.stack_base), 0x64, 0x8b, 0x1d, tebField.stack_limit, 0x00, 0x00, 0x00, 0xc3];
  const report = readRun(context, code, { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.eax >>> 0, report.thread.stack_base >>> 0);
  assert.equal(report.register.ebx >>> 0, report.thread.stack_limit >>> 0);
  assert.ok((report.register.eax >>> 0) > (report.register.ebx >>> 0), "the stack base is above the stack limit");
});

test("a TLS slot written through fs reads back through fs", (context) => {
  // mov dword ptr fs:[0xE10], 0x12345678; mov eax, fs:[0xE10]; ret.
  const code = [
    0x64, 0xc7, 0x05, tebField.tls_slot & 0xff, (tebField.tls_slot >>> 8) & 0xff, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12,
    ...fsLoadEax(tebField.tls_slot),
    0xc3,
  ];
  const report = readRun(context, code, { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.eax >>> 0, 0x12345678);
});

test("LEA under an fs override ignores the segment base", (context) => {
  // lea eax, fs:[0x1000]; ret — LEA loads the effective offset itself, so the
  // TEB base must not be folded in.
  const report = readRun(context, [0x64, 0x8d, 0x05, 0x00, 0x10, 0x00, 0x00, 0xc3], { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.eax >>> 0, 0x1000);
});

test("the bare probe with no thread-environment block keeps refusing the fs override", (context) => {
  const report = readRun(context, [...fsLoadEax(tebField.self), 0xc3]);
  assert.equal(report.thread, null);
  assert.equal(report.stop_reason, "unsupported_opcode");
  assert.equal(report.exception.opcode, 0x64);
  assert.match(report.exception.message, /thread-environment block/);
});
