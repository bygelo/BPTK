// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

function run(argument) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

function createDirectory(context, name) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-census-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const directory = join(rootPath, name);
  mkdirSync(directory);
  return directory;
}

// Builds a minimal PE32 whose import directory names one library.
function createPe32WithImport(context, library, option = {}) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-census-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
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
  file[0x200] = 0xc3; // ret
  // Import directory at RVA 0x1100: one descriptor naming the library, then
  // the null terminator descriptor.
  file.writeUInt32LE(0x1100, 0x98 + 96 + 8);
  file.writeUInt32LE(40, 0x98 + 96 + 12);
  const fileOffset = (rva) => 0x200 + rva - 0x1000;
  file.writeUInt32LE(0x1140, fileOffset(0x1100)); // original first thunk
  file.writeUInt32LE(0, fileOffset(0x1104));
  file.writeUInt32LE(0, fileOffset(0x1108));
  file.writeUInt32LE(0x1160, fileOffset(0x110c)); // library name
  file.writeUInt32LE(0x1180, fileOffset(0x1110)); // first thunk
  file.writeUInt32LE(0, fileOffset(0x1114));
  file.write(library, fileOffset(0x1160));
  if (option.embeddedString) file.write(option.embeddedString, fileOffset(0x1200), "latin1");
  const path = join(rootPath, "game.exe");
  writeFileSync(path, file);
  return path;
}

test("a middleware import warns and stays classified", (context) => {
  const path = createPe32WithImport(context, "BINKW32.dll");
  const result = run(["inspect", path, "--json"]);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.census.route, "warn");
  assert.equal(report.census.middleware.length, 1);
  assert.equal(report.census.middleware[0].family, "Bink Video");
  assert.equal(report.lane, "binary");
});

test("a clean PE32 input routes as handle", (context) => {
  const path = createPe32WithImport(context, "GAMELOT.dll");
  const result = run(["inspect", path, "--json"]);
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.census.route, "handle");
  assert.equal(report.census.middleware.length, 0);
  assert.equal(report.census.protection.length, 0);
});

test("the SafeDisc loader string refuses a portability claim", (context) => {
  const path = createPe32WithImport(context, "GAMELOT.dll", { embeddedString: "x BoG_ *90.0&!!  Yy> y" });
  const result = run(["inspect", path, "--json"]);
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.census.route, "refuse");
  assert.equal(report.census.protection[0].family, "SafeDisc");
  assert.equal(report.lane, "blocked");
  assert.match(report.blocker.join("\n"), /refuses a portability claim/);
});

test("SafeDisc sibling artifact refuses a directory input", (context) => {
  const directory = createDirectory(context, "safedisc-game");
  writeFileSync(join(directory, "GAME.EXE"), Buffer.alloc(64, 0x90));
  writeFileSync(join(directory, "00000001.TMP"), Buffer.alloc(10));
  writeFileSync(join(directory, "DPLAYERX.DLL"), Buffer.alloc(10));
  const result = run(["inspect", directory, "--json"]);
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.census.route, "refuse");
  assert.equal(report.census.protection.length, 2);
});

test("a proprietary codec import refuses like the video posture", (context) => {
  const path = createPe32WithImport(context, "IR50_32.DLL");
  const result = run(["inspect", path, "--json"]);
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.census.route, "refuse");
  assert.equal(report.census.protection[0].family, "Indeo video");
});

test("a Build engine asset directory routes to its open reimplementation", (context) => {
  const directory = createDirectory(context, "build-game");
  writeFileSync(join(directory, "DUKE3D.GRP"), Buffer.alloc(64, 0x90));
  const result = run(["inspect", directory, "--json"]);
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.census.engine.family, "Build");
  assert.equal(report.census.engine.route, "EDuke32");
  assert.equal(report.census.engine.is_bundled, false);
  assert.match(report.evidence.join("\n"), /open reimplementation EDuke32/);
});

test("an id Tech 1 asset directory routes to PrBoom+", (context) => {
  const directory = createDirectory(context, "doom-wad");
  writeFileSync(join(directory, "DOOM.WAD"), Buffer.alloc(64, 0x90));
  const result = run(["inspect", directory, "--json"]);
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.census.engine.family, "id Tech 1");
  assert.equal(report.census.engine.route, "PrBoom+");
});

test("an input without engine evidence reports no engine match", (context) => {
  const path = createPe32WithImport(context, "GAMELOT.dll");
  const result = run(["inspect", path, "--json"]);
  const report = JSON.parse(result.stdout);
  assert.equal(report.census.engine.family, null);
  assert.equal(report.census.engine.route, null);
});
