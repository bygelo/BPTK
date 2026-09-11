// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createHleLayout } from "../lib/hle.mjs";
import { mapPe32 } from "../lib/pe.mjs";
import { runPackage } from "../lib/run.mjs";
import { bindSidecarModules, isSystemLibrary, resolveSidecarPath } from "../lib/sidecar.mjs";

function writePe32({ imageBase, code }) {
  const file = Buffer.alloc(0x800);
  file.writeUInt16LE(0x5a4d, 0);
  file.writeUInt32LE(0x80, 0x3c);
  file.writeUInt32LE(0x00004550, 0x80);
  file.writeUInt16LE(0x14c, 0x84);
  file.writeUInt16LE(1, 0x86);
  file.writeUInt16LE(224, 0x94);
  file.writeUInt16LE(0x10b, 0x98);
  file.writeUInt32LE(0x1000, 0xa8);
  file.writeUInt32LE(imageBase, 0xb4);
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
  return file;
}

function fileOffset(rva) {
  return 0x200 + rva - 0x1000;
}

function createHelperDll() {
  const file = writePe32({
    imageBase: 0x28000000,
    code: [0xc3, 0x40, 0xc3],
  });
  file.writeUInt16LE(0x2102, 0x96);
  file.writeUInt32LE(0x1200, 0xf8);
  file.writeUInt32LE(0x80, 0xfc);
  const dirRva = 0x1200;
  file.writeUInt32LE(0x1240, fileOffset(dirRva + 12));
  file.writeUInt32LE(1, fileOffset(dirRva + 16));
  file.writeUInt32LE(1, fileOffset(dirRva + 20));
  file.writeUInt32LE(1, fileOffset(dirRva + 24));
  file.writeUInt32LE(0x1230, fileOffset(dirRva + 28));
  file.writeUInt32LE(0x1234, fileOffset(dirRva + 32));
  file.writeUInt32LE(0x1238, fileOffset(dirRva + 36));
  file.writeUInt32LE(0x1001, fileOffset(0x1230));
  file.writeUInt32LE(0x1250, fileOffset(0x1234));
  file.writeUInt16LE(0, fileOffset(0x1238));
  file.write("helper.dll\0", fileOffset(0x1240));
  file.write("add_one\0", fileOffset(0x1250));
  return file;
}

function createGameExe(library = "helper.dll") {
  const file = writePe32({
    imageBase: 0x400000,
    code: [
      0xb8, 0x06, 0x00, 0x00, 0x00,
      0xff, 0x15, 0x80, 0x11, 0x40, 0x00,
      0xc3,
    ],
  });
  const libraryRva = 0x11c0;
  file.writeUInt32LE(0x1140, 0xf8 + 8);
  file.writeUInt32LE(40, 0xf8 + 12);
  file.writeUInt32LE(0x1170, fileOffset(0x1140));
  file.writeUInt32LE(0, fileOffset(0x1144));
  file.writeUInt32LE(0, fileOffset(0x1148));
  file.writeUInt32LE(libraryRva, fileOffset(0x114c));
  file.writeUInt32LE(0x1180, fileOffset(0x1150));
  file.writeUInt32LE(0x11a0, fileOffset(0x1170));
  file.writeUInt32LE(0, fileOffset(0x1174));
  file.writeUInt32LE(0x11a0, fileOffset(0x1180));
  file.writeUInt32LE(0, fileOffset(0x1184));
  file.writeUInt16LE(0, fileOffset(0x11a0));
  file.write("add_one\0", fileOffset(0x11a2));
  file.write(`${library}\0`, fileOffset(libraryRva));
  return file;
}

function createPackage(context) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-sidecar-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
  const executablePath = join(packagePath, "game.exe");
  writeFileSync(executablePath, createGameExe());
  writeFileSync(join(packagePath, "helper.dll"), createHelperDll());
  writeFileSync(join(packagePath, "kernel32.dll"), createHelperDll());
  writeFileSync(join(packagePath, "bptk.json"), JSON.stringify({
    schema_version: 1,
    executable: "game.exe",
    execution: { profile: "i386_probe_v1", instruction_budget_count: 64 },
  }));
  return { packagePath, executablePath };
}

test("system libraries stay on the HLE even when a file sits next to the executable", () => {
  assert.equal(isSystemLibrary("KERNEL32.dll"), true);
  assert.equal(isSystemLibrary("api-ms-win-core-synch-l1-2-0.dll"), true);
  assert.equal(isSystemLibrary("helper.dll"), false);
  assert.equal(isSystemLibrary("ucrtbase.dll"), false);
});

test("resolveSidecarPath is case-insensitive and skips system libraries", (context) => {
  const { executablePath, packagePath } = createPackage(context);
  assert.equal(resolveSidecarPath(executablePath, "HELPER.DLL"), join(packagePath, "helper.dll"));
  assert.equal(resolveSidecarPath(executablePath, "kernel32.dll"), null);
  assert.equal(resolveSidecarPath(executablePath, "missing.dll"), null);
});

test("bindSidecarModules maps a package-local export and leaves kernel32 on the HLE", (context) => {
  const { executablePath } = createPackage(context);
  const mapped = mapPe32(executablePath);
  const layout = createHleLayout({
    ...mapped,
    stack_base: 0x70000000,
    stack_end: 0x70010000,
  });
  const service = bindSidecarModules({
    executablePath,
    import: mapped.import,
    layout,
  });
  assert.equal(service.is_fully_served, true);
  assert.equal(service.sidecar_count, 1);
  assert.equal(service.sidecar[0].name, "helper.dll");
  assert.equal(service.sidecar[0].load_base, 0x28000000);
  assert.equal(service.import_catalog[0].address, 0x28001001);
  assert.equal(service.sidecar.some((module) => module.name === "kernel32.dll"), false);
});

test("an api-set CRT import binds to a shipped ucrtbase export when HLE has no row", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-ucrt-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
  writeFileSync(join(packagePath, "ucrtbase.dll"), createHelperDll());
  const executablePath = join(packagePath, "game.exe");
  writeFileSync(executablePath, createGameExe("api-ms-win-crt-math-l1-1-0.dll"));
  const mapped = mapPe32(executablePath);
  const layout = createHleLayout({
    ...mapped,
    stack_base: 0x70000000,
    stack_end: 0x70010000,
  });
  const service = bindSidecarModules({
    executablePath,
    import: mapped.import,
    layout,
  });
  assert.equal(mapped.import[0].library, "api-ms-win-crt-math-l1-1-0.dll");
  assert.equal(service.is_fully_served, true);
  assert.equal(service.sidecar.some((module) => module.name === "ucrtbase.dll"), true);
  assert.equal(service.import_catalog[0].address, 0x28001001);
});

test("runPackage executes a call through a sidecar export", (context) => {
  const { packagePath } = createPackage(context);
  const report = runPackage(packagePath);
  assert.equal(report.state, "probe_executed", `state ${report.state}: ${JSON.stringify(report.exception)}`);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.register.eax, 7);
});
