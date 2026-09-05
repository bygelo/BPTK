// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { censusWin32Modules, classifyWin32Modules, formatWin32Modules } from "../lib/import.mjs";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

// A minimal PE32 whose single import descriptor names one library, mirroring
// the census fixture, so the module census exercises the real import parser.
function createPe32WithImport(context, library) {
  const root = mkdtempSync(join(tmpdir(), "bptk-import-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
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
  file.write(".text", 0x178);
  file.writeUInt32LE(0x1000, 0x180);
  file.writeUInt32LE(0x1000, 0x184);
  file.writeUInt32LE(0x60000020, 0x19c);
  file.writeUInt32LE(0x600, 0x188);
  file.writeUInt32LE(0x200, 0x18c);
  file[0x200] = 0xc3;
  file.writeUInt32LE(0x1100, 0x98 + 96 + 8);
  file.writeUInt32LE(40, 0x98 + 96 + 12);
  const fileOffset = (rva) => 0x200 + rva - 0x1000;
  file.writeUInt32LE(0x1140, fileOffset(0x1100));
  file.writeUInt32LE(0, fileOffset(0x1104));
  file.writeUInt32LE(0, fileOffset(0x1108));
  file.writeUInt32LE(0x1160, fileOffset(0x110c));
  file.writeUInt32LE(0x1180, fileOffset(0x1110));
  file.writeUInt32LE(0, fileOffset(0x1114));
  file.write(library, fileOffset(0x1160));
  const path = join(root, "game.exe");
  writeFileSync(path, file);
  return path;
}

test("the module classifier tiers hosted, planned, and unrecognized Win32 modules", () => {
  const coverage = classifyWin32Modules(["USER32.dll", "gdi32.dll", "ole32.dll", "msvbvm60.dll", "zzz_unknown.dll"]);
  const tier = Object.fromEntries(coverage.module.map((entry) => [entry.module, entry.tier]));
  assert.equal(tier["user32.dll"], "hosted");
  assert.equal(tier["gdi32.dll"], "hosted");
  assert.equal(tier["ole32.dll"], "planned");
  assert.equal(tier["msvbvm60.dll"], "planned");
  assert.equal(tier["zzz_unknown.dll"], "unrecognized");
  assert.equal(coverage.ledger.hosted, 2);
  assert.equal(coverage.ledger.planned, 2);
  assert.equal(coverage.ledger.unrecognized, 1);
  assert.equal(coverage.ledger.total, 5);
});

test("a title needing a broader module is not fully hosted", () => {
  assert.equal(classifyWin32Modules(["kernel32.dll", "user32.dll", "gdi32.dll"]).is_fully_hosted, true);
  assert.equal(classifyWin32Modules(["kernel32.dll", "ole32.dll"]).is_fully_hosted, false);
  assert.equal(classifyWin32Modules([]).is_fully_hosted, false);
});

test("the classifier is deduplicated, lowercased, and order-independent", () => {
  const a = classifyWin32Modules(["USER32.dll", "user32.DLL", "ole32.dll"]);
  const b = classifyWin32Modules(["ole32.dll", "user32.dll"]);
  assert.equal(a.ledger.total, 2);
  assert.deepEqual(a.module.map((entry) => entry.module), b.module.map((entry) => entry.module));
});

test("the module census reads a real PE import table and stays honestly blocked", (context) => {
  // Implemented-but-red (BPTK-101): the coverage ledger over the declared Win32
  // module set exists, but broadening the emulation surface to a passing state
  // needs every imported module to carry a passing conformance slice, so the
  // census stays blocked and never claims the title starts.
  const report = censusWin32Modules(createPe32WithImport(context, "ole32.dll"));
  assert.ok(report.module.some((entry) => entry.module === "ole32.dll" && entry.tier === "planned"));
  assert.equal(report.is_fully_hosted, false);
  assert.equal(report.state, "blocked");
  assert.equal(report.is_executed, false);
  assert.match(formatWin32Modules(report), /Ledger:/);
});

test("the module census is reachable at the real CLI", (context) => {
  const path = createPe32WithImport(context, "user32.dll");
  const result = spawnSync(process.execPath, [binPath, "modules", path, "--json"], { encoding: "utf8" });
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.ok(report.module.some((entry) => entry.module === "user32.dll" && entry.tier === "hosted"));
  assert.equal(report.is_executed, false);
});
