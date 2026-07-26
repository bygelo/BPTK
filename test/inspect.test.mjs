// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

function run(argument) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

function writePe32(filePath) {
  const value = Buffer.alloc(512);
  value.write("MZ", 0, "ascii");
  value.writeUInt32LE(0x80, 0x3c);
  value.write("PE\0\0", 0x80, "ascii");
  value.writeUInt16LE(0x14c, 0x84);
  value.writeUInt16LE(1, 0x86);
  value.writeUInt16LE(224, 0x94);
  value.writeUInt16LE(0x10b, 0x98);
  writeFileSync(filePath, value);
}

test("inspect classifies generated PE32 without executing or uploading it", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-inspect-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const filePath = join(rootPath, "sample.exe");
  writePe32(filePath);
  const runValue = run(["inspect", filePath, "--json"]);
  assert.equal(runValue.status, 0);
  const report = JSON.parse(runValue.stdout);
  assert.equal(report.classification, "pe32");
  assert.equal(report.lane, "binary");
  assert.equal(report.compatibility_state, "classified");
  assert.equal(report.privacy.is_local_only, true);
  assert.equal(report.privacy.is_uploaded, false);
  assert.equal(report.privacy.is_executed, false);
});

test("inspect identifies a generated native source project", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-source-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  writeFileSync(join(rootPath, "CMakeLists.txt"), "project(sample)\n");
  writeFileSync(join(rootPath, "main.c"), "int main(void) { return 0; }\n");
  const runValue = run(["inspect", rootPath, "--json"]);
  assert.equal(runValue.status, 0);
  const report = JSON.parse(runValue.stdout);
  assert.equal(report.classification, "source_project");
  assert.equal(report.lane, "source");
});

test("inspect refuses a symbolic-link root", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-link-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const targetPath = join(rootPath, "target");
  const linkPath = join(rootPath, "link");
  mkdirSync(targetPath);
  symlinkSync(targetPath, linkPath);
  const runValue = run(["inspect", linkPath, "--json"]);
  assert.equal(runValue.status, 1);
  const failure = JSON.parse(runValue.stderr);
  assert.equal(failure.error_code, "symlink_input");
});
