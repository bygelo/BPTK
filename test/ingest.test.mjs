// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { formatFallbackChain, ingestInput, resolveFallbackChain } from "../lib/ingest.mjs";
import { readSevenZip } from "../lib/sevenzip.mjs";
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

test("the fallback chain carries a plain PE32 as a binary-lane candidate without executing it", (context) => {
  const inputPath = createRoot(context, "game.exe");
  writeFileSync(inputPath, createPe32File());
  const chain = resolveFallbackChain(inputPath);
  assert.equal(chain.carried_lane, "binary_i386");
  assert.equal(chain.state, "candidate");
  assert.equal(chain.is_executed, false);
  assert.equal(chain.is_terminal_bounded, true);
});

test("the fallback chain falls from a refused binary to the engine lane and records the hop", (context) => {
  const dir = createRoot(context, "protected");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "game.exe"), createPe32File());
  writeFileSync(join(dir, "bptk.json"), JSON.stringify({ schema_version: 1, executable: "game.exe" }));
  writeFileSync(join(dir, "00000001.tmp"), "safedisc loader artifact");
  writeFileSync(join(dir, "game.wad"), "IWAD payload");
  const chain = resolveFallbackChain(dir);
  assert.ok(chain.ranked_lane.includes("binary_i386") && chain.ranked_lane.includes("engine_asset"));
  assert.equal(chain.carried_lane, "engine_asset");
  assert.equal(chain.state, "candidate");
  assert.ok(chain.hop.some((entry) => entry.lane === "binary_i386" && entry.reason.includes("protection")));
});

test("the fallback chain terminates in a bounded no-lane state for an unroutable input", (context) => {
  const inputPath = createRoot(context, "mystery.bin");
  writeFileSync(inputPath, Buffer.from("this is not any known executable or asset"));
  const chain = resolveFallbackChain(inputPath);
  assert.equal(chain.carried_lane, "no_lane");
  assert.equal(chain.state, "no_lane");
  assert.equal(chain.is_terminal_bounded, true);
  assert.ok(chain.hop.length <= chain.ranked_lane.length);
});

test("the fallback chain is reachable at the real CLI and never asserts the title runs", (context) => {
  const inputPath = createRoot(context, "game.exe");
  writeFileSync(inputPath, createPe32File());
  const result = run(["route", "--fallback", inputPath, "--json"]);
  assert.equal(result.status, 0);
  const chain = JSON.parse(result.stdout);
  assert.equal(chain.is_executed, false);
  assert.match(chain.note, /does not assert the title runs/);
});

// A bounded 7z archive built with 7-Zip's own default exe pipeline: readme.txt
// under plain LZMA and bin/game.exe under the LZMA + BCJ x86 filter chain. The
// blob is embedded so the codec path is exercised with no external tool.
const sevenZipLzmaBase64 =
  "N3q8ryccAAQAoJDEFQEAAAAAAAAjAAAAAAAAAHQHzXEANhhLVQA45N4vBRoGbyP30oCeTHzYUUkKk58Yy+y/z07xEeqO29tYPFoo4LVH8+xdkvhSe5No8bwAYXmZs1Y3PRa8ACaWfBuMu0QtksPPKJ0lO3XY6RAMVBgdDSx1HN/rQsPV/l7NKxCu806Gwb1i1pYFakZtKhXUsmXCye4cPARPGpy/KZHXMtsRCKEnrmhReOZAAACBMweuMZwiLUtYhUPhMfotoj5laO2nG7wjp3jVJjJcRocK/Iz4GR3FHzzZZDtDrqG+TGDzJo473jGgRfCmLWpb/cXxN7uewLTK12eEmhpXU0u5ny7od49GCUlBcflt0eZvBNhMQM1UdNRcbo82w+OuQhoMyDqjfDiKgL7JIAAAFwaAlAEJgIEABwsBAAEjAwEBBV0AEAAADICmCgE2KTnQAAA=";
// The same archive with header and payload encryption (-mhe=on -p): the header
// itself is an AES-256 folder, so the reader refuses before any structure read.
const sevenZipEncryptedBase64 =
  "N3q8ryccAASIdA5ccAEAAAAAAAA/AAAAAAAAAFStacs5wFPCicZVwCJi9ooXs3Cp6CeA9q143mj4zfG/4yhWZMqX8Fm/evHSod6MC3fsXbH9ANDy9PGvSkW9sIEY/dyAbrR7lIDFls9FHShAuKAPJ+zr1IXuSrsqqhgvHOHVRbI6+aRpy1wGJieRNo4OPTXzR2wyMMDvFhjpzE0b3/y6gA6hvIMcK0MsVN6n8qnL25/wvLXBfPlDpL9+FyzCwT9hGGZFrOFgA00AP2yCshTUXyV4EOjVvPErCILcIimQ2ZAitLjkpl9U+4yvTyucdS8Q7ATnPcjWYxCRYYdaxTFGcT2JxGcq75K3PRwFKzmR92MEmZEanGzYYRCrYNTHXWxJ7cp5KKwdL11oajrMLfynNG96CaXO3J2eb4XDhrTtPB7/pvHJwGZQCduhJSUUiFSZL232TFPNq+FCtbdbQszeC2BNM7AcJUOYejhHXjVlFBNHP9WdK55IeqXIjXGB36WN/YRJ3aokUrRNXXpSLzx1HBcGgLABCYDAAAcLAQACJAbxBwESUw+HT5nSOopocJPnhWJ8MZ7oIwMBAQVdABAAAAEADICxgNYKATNIQfUAAA==";
const sevenZipExeSha256 = "8f342b758b051baa813e23d0daa2d563c3d7af9f4d9c2255c5d34401b569357c";

test("ingest stages a bounded 7z archive and packages its recovered executable", (context) => {
  const inputPath = createRoot(context, "tool.7z");
  writeFileSync(inputPath, Buffer.from(sevenZipLzmaBase64, "base64"));
  const outputDir = createRoot(context, "out7z") + "-out";
  const report = ingestInput(inputPath, { output: outputDir });
  assert.equal(report.is_ingested, true);
  assert.equal(report.extraction.installer_family, "7z");
  assert.equal(report.package_manifest.executable, "bin/game.exe");
  // The recovered executable is the real bytes, verified against its own hash.
  const recovered = readFileSync(join(outputDir, "bin", "game.exe"));
  assert.equal(createHash("sha256").update(recovered).digest("hex"), sevenZipExeSha256);
  assert.ok(existsSync(join(outputDir, "readme.txt")));
  assert.ok(report.extraction.entry.some((entry) => entry.path === "readme.txt"));
});

test("a 7z archive without an output directory is refused with the archive gap", (context) => {
  const inputPath = createRoot(context, "tool.7z");
  writeFileSync(inputPath, Buffer.from(sevenZipLzmaBase64, "base64"));
  assert.throws(() => ingestInput(inputPath), (error) => error.input_code === "archive_ingest_unimplemented");
});

test("an encrypted 7z folder is refused with a structured reason before any write", (context) => {
  const encrypted = Buffer.from(sevenZipEncryptedBase64, "base64");
  assert.throws(() => readSevenZip(encrypted), (error) => error.input_code === "archive_entry_encrypted");
  const inputPath = createRoot(context, "secret.7z");
  writeFileSync(inputPath, encrypted);
  const outputDir = createRoot(context, "secret-out") + "-out";
  assert.throws(() => ingestInput(inputPath, { output: outputDir }), (error) => error.input_code === "archive_entry_encrypted");
});

// The full BCJ2 coder chain and end-to-end corpus proof run only when the
// lawful freeware payload is staged locally; the codec surface above stays
// hermetic, so this is gated on the staged file exactly like the other
// corpus-dependent tests.
const stagedSevenZip = process.env.BPTK_SEVENZIP_PAYLOAD
  ?? join(process.env.BPTK_CORPUS_STAGE ?? join(fileURLToPath(new URL("../..", import.meta.url)), "bptk-corpus", "stage"), "corpus-004", "7z2501-extra.7z");

test("the staged 7-Zip corpus payload recovers its x86-64 executable byte-for-byte", (context) => {
  if (!existsSync(stagedSevenZip)) {
    context.skip(`The 7-Zip corpus payload is not staged at ${stagedSevenZip}`);
    return;
  }
  const recovered = readSevenZip(readFileSync(stagedSevenZip));
  const executable = recovered.file.find((entry) => entry.path === "x64/7za.exe");
  assert.ok(executable, "the archive carries x64/7za.exe");
  assert.equal(executable.checksum_state, "verified");
  assert.equal(
    createHash("sha256").update(executable.content).digest("hex"),
    "574bb90d17732f3cc4145fd4ba12d8f29b9d63400881c0e6fe3110c88b0485de",
  );
  // The recovered executable is a real x86-64 PE image, so the run surface can
  // only load it into the research lane; extraction never asserts it runs.
  const headerOffset = executable.content.readUInt32LE(0x3c);
  assert.equal(executable.content.toString("ascii", headerOffset, headerOffset + 4), "PE\0\0");
  assert.equal(executable.content.readUInt16LE(headerOffset + 4), 0x8664);
});
