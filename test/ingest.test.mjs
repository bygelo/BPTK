// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { ingestInput } from "../lib/ingest.mjs";
import { createInnoFixture } from "./extract.test.mjs";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

function run(argument) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

function createRoot(context, name) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-ingest-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  return join(rootPath, name ?? "input");
}

// Builds a minimal PE32 i386 executable whose entry is a single RET.
function createPe32File(option = {}) {
  const file = Buffer.alloc(0x800);
  file.writeUInt16LE(0x5a4d, 0);
  file.writeUInt32LE(0x80, 0x3c);
  file.writeUInt32LE(0x00004550, 0x80);
  file.writeUInt16LE(option.machine ?? 0x14c, 0x84);
  file.writeUInt16LE(1, 0x86);
  file.writeUInt16LE(224, 0x94);
  file.writeUInt16LE(option.machine === 0x8664 ? 0x20b : 0x10b, 0x98);
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
  return file;
}

test("ingest packages any plain PE32 executable and synthesizes its manifest", (context) => {
  const inputPath = createRoot(context, "game.exe");
  writeFileSync(inputPath, createPe32File());
  const outputDir = createRoot(context, "out") + "-out";
  const report = ingestInput(inputPath, { output: outputDir });
  assert.equal(report.state, "packaged_no_runtime");
  assert.equal(report.is_ingested, true);
  assert.equal(report.detection.probe_eligible, true);
  assert.equal(report.package_manifest.executable, "game.exe");
  assert.ok(existsSync(join(outputDir, "bptk.json")));
  // The synthesized package is immediately consumable by the run surface.
  const runResult = run(["run", outputDir, "--json"]);
  assert.equal(runResult.status, 0, runResult.stderr);
  const runReport = JSON.parse(runResult.stdout);
  assert.equal(runReport.machine, "i386");
  assert.equal(runReport.is_executed, false);
});

test("plan-only ingest writes nothing", (context) => {
  const inputPath = createRoot(context, "game.exe");
  writeFileSync(inputPath, createPe32File());
  const report = ingestInput(inputPath);
  assert.equal(report.is_ingested, false);
  assert.equal(report.state, "classified_no_runtime");
  assert.equal(report.output_dir, null);
});

test("ingest extracts a supported installer and synthesizes the payload manifest", (context) => {
  const pe = createPe32File();
  const { installerPath } = createInnoFixture(context, {
    payload: [
      { destination: "{app}\\bin\\game.exe", content: pe },
      { destination: "{app}\\readme.txt", content: Buffer.from("readme\n") },
    ],
  });
  const outputDir = createRoot(context, "payload") + "-out";
  const report = ingestInput(installerPath, { output: outputDir });
  assert.equal(report.state, "packaged_no_runtime");
  assert.equal(report.package_manifest.executable, "bin/game.exe");
  assert.ok(existsSync(join(outputDir, "bin", "game.exe")));
  const runResult = run(["run", outputDir, "--json"]);
  assert.equal(runResult.status, 0, runResult.stderr);
  assert.equal(JSON.parse(runResult.stdout).machine, "i386");
});

test("an x86_64 executable is packaged but honestly not probe-eligible", (context) => {
  const inputPath = createRoot(context, "game64.exe");
  writeFileSync(inputPath, createPe32File({ machine: 0x8664 }));
  const outputDir = createRoot(context, "out64") + "-out";
  const report = ingestInput(inputPath, { output: outputDir });
  assert.equal(report.state, "packaged_no_runtime");
  assert.equal(report.detection.probe_eligible, false);
  assert.match(report.detection.probe_reason, /BPTK-031/);
});

test("a DOS-only executable is refused with a structured reason", (context) => {
  const inputPath = createRoot(context, "dos.exe");
  const file = Buffer.alloc(0x200);
  file.writeUInt16LE(0x5a4d, 0);
  file.writeUInt32LE(0x10, 0x3c);
  writeFileSync(inputPath, file);
  assert.throws(() => ingestInput(inputPath), (error) => error.input_code === "unsupported_executable_format");
});

test("a zip archive is refused until archive ingestion is implemented", (context) => {
  const inputPath = createRoot(context, "game.zip");
  writeFileSync(inputPath, Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0]));
  assert.throws(() => ingestInput(inputPath), (error) => error.input_code === "archive_ingest_unimplemented");
});

test("ingest of an existing package directory recognizes it", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-ingest-pkg-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
  writeFileSync(join(packagePath, "game.exe"), createPe32File());
  writeFileSync(join(packagePath, "bptk.json"), JSON.stringify({ schema_version: 1, executable: "game.exe" }));
  const report = ingestInput(packagePath);
  assert.equal(report.state, "package_ready");
  assert.equal(report.package_manifest.executable, "game.exe");
});

test("an installer bomb refusal propagates loudly through ingest", (context) => {
  const bomb = Buffer.alloc(8 * 1024 * 1024);
  const { installerPath } = createInnoFixture(context, {
    payload: [{ destination: "{app}\\bomb.bin", content: bomb }],
  });
  const outputDir = createRoot(context, "bomb-out") + "-out";
  assert.throws(() => ingestInput(installerPath, { output: outputDir }), (error) => error.input_code === "bound_ratio_exceeded");
  const cliResult = run(["ingest", installerPath, "--output", outputDir, "--json"]);
  assert.equal(cliResult.status, 1);
  assert.equal(JSON.parse(cliResult.stderr).error_code, "bound_ratio_exceeded");
});
