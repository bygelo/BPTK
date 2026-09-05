// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { acquireCorpus, computeGeneralizationDelta, loadAcquisitionManifest, loadRunRecords, runCorpus } from "../lib/corpus.mjs";
import { ingestInput } from "../lib/ingest.mjs";
import { createExtractionBound, assertChunkRatioBound } from "../lib/bound.mjs";
import { buildExportLedger } from "../lib/corpus.mjs";
import { canonicalizeTrace, runConformanceSuite, verifyTrace, verifyTraceCorpus } from "../lib/conformance.mjs";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

function run(argument = []) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

function createPe32() {
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
  file.writeUInt32LE(0x60000020, sectionOffset + 36);
  file.writeUInt32LE(0x600, sectionOffset + 16);
  file.writeUInt32LE(0x200, sectionOffset + 20);
  file[0x200] = 0xc3;
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
  return file;
}

function createStoredZip(entry) {
  const local = [];
  const central = [];
  let offset = 0;
  for (const item of entry) {
    const name = Buffer.from(item.path, "utf8");
    const data = item.data ?? Buffer.alloc(0);
    const isDirectory = item.path.endsWith("/");
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt32LE(data.length, 18);
    localHeader.writeUInt32LE(data.length, 22);
    localHeader.writeUInt16LE(name.length, 26);
    local.push(localHeader, name, isDirectory ? Buffer.alloc(0) : data);
    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt32LE(data.length, 20);
    centralHeader.writeUInt32LE(data.length, 24);
    centralHeader.writeUInt16LE(name.length, 28);
    centralHeader.writeUInt32LE(offset, 42);
    central.push(centralHeader, name);
    offset += 30 + name.length + data.length;
  }
  const centralBuffer = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entry.length, 10);
  eocd.writeUInt32LE(centralBuffer.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, centralBuffer, eocd]);
}

function createStage(context, entryId, payload) {
  const stage = mkdtempSync(join(tmpdir(), "bptk-corpus-stage-"));
  context.after(() => rmSync(stage, { recursive: true, force: true }));
  const entryDir = join(stage, entryId.toLowerCase());
  mkdirSync(entryDir, { recursive: true });
  const payloadPath = join(entryDir, "payload.exe");
  writeFileSync(payloadPath, payload);
  return { stage, payloadPath };
}

function createManifest(context, entry, stageDir) {
  const root = mkdtempSync(join(tmpdir(), "bptk-corpus-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const manifestPath = join(root, "corpus.json");
  writeFileSync(manifestPath, JSON.stringify({ schema_version: 1, record: [entry] }));
  process.env.BPTK_ACQUISITION_PATH = manifestPath;
  return { manifestPath, restore: () => { delete process.env.BPTK_ACQUISITION_PATH; } };
}

test("the acquisition manifest resolves every entry to a lawful basis and pin", () => {
  const manifest = loadAcquisitionManifest();
  assert.ok(manifest.record.length >= 5);
  for (const entry of manifest.record) {
    assert.ok(entry.license, `${entry.entry_id} carries a license`);
    assert.ok(entry.redistribution_basis && entry.redistribution_basis.length > 20, `${entry.entry_id} carries a redistribution basis`);
    assert.match(entry.source_url, /^https:/, `${entry.entry_id} names an https source`);
    assert.match(entry.sha256, /^[a-f0-9]{64}$/, `${entry.entry_id} pins a sha256`);
    assert.ok(Number.isInteger(entry.size_byte) && entry.size_byte > 0, `${entry.entry_id} pins a size`);
    assert.ok(["game", "program"].includes(entry.kind), `${entry.entry_id} is a game or program`);
  }
});

test("acquire verifies a staged payload against its pin without downloading", async (context) => {
  const payload = createPe32();
  const { stage } = createStage(context, "CORPUS-901", payload);
  const entry = {
    entry_id: "CORPUS-901",
    title: "generated probe fixture",
    kind: "program",
    source_url: "https://corpus.invalid/fixture/payload.exe",
    license: "MIT",
    redistribution_basis: "Generated in-test fixture with no upstream claim",
    size_byte: payload.length,
    sha256: createHash("sha256").update(payload).digest("hex"),
    game_loop: false,
    state: "acquired",
  };
  const { restore } = createManifest(context, entry);
  context.after(restore);
  const report = await acquireCorpus({ stage });
  assert.equal(report.verified_count, 1);
  assert.equal(report.downloaded_count, 0);
  assert.equal(report.record[0].action, "verified");
  assert.equal(report.payload_in_repository, false);
});

test("acquire refuses a staged payload whose byte differ from the pin", async (context) => {
  const payload = createPe32();
  const { stage, payloadPath } = createStage(context, "CORPUS-902", payload);
  payload[payload.length - 1] ^= 0xff;
  writeFileSync(payloadPath, payload);
  const entry = {
    entry_id: "CORPUS-902",
    title: "tampered fixture",
    kind: "program",
    source_url: "https://corpus.invalid/fixture/payload.exe",
    license: "MIT",
    redistribution_basis: "Generated in-test fixture with no upstream claim",
    size_byte: payload.length,
    sha256: createHash("sha256").update(createPe32()).digest("hex"),
    game_loop: false,
    state: "acquired",
  };
  const { restore } = createManifest(context, entry);
  context.after(restore);
  const report = await acquireCorpus({ stage });
  assert.equal(report.refused_count, 1);
  assert.match(report.record[0].reason, /differs from the manifest pin/);
});

test("the run harness records the real stage and the named generic gap", async (context) => {
  const payload = createPe32();
  const { stage } = createStage(context, "CORPUS-903", payload);
  const entry = {
    entry_id: "CORPUS-903",
    title: "generated probe fixture",
    kind: "program",
    source_url: "https://corpus.invalid/fixture/payload.exe",
    license: "MIT",
    redistribution_basis: "Generated in-test fixture with no upstream claim",
    size_byte: payload.length,
    sha256: createHash("sha256").update(payload).digest("hex"),
    game_loop: false,
    state: "acquired",
  };
  const { restore } = createManifest(context, entry);
  context.after(restore);
  const report = runCorpus({ stage });
  const record = report.record[0];
  assert.equal(record.architecture, "i386");
  // The corpus is the consented, bounded execution context: it fires the i386
  // probe, so a valid i386 image executes from its entry point and reaches the
  // `entry` stage. The generic gap is now runtime_game_loop_absent (BPTK-010) —
  // executed, but a real session needs the full Win32 runtime. Not playable.
  assert.equal(record.reached_stage, "entry");
  assert.equal(record.gap_item, "BPTK-010");
  assert.equal(record.is_playable_claim, false);
  assert.ok(record.command.includes("run"));
});

test("the generalization gate refuses a single-beneficiary fix", () => {
  const before = { record: [
    { entry_id: "a", reached_stage: "classified" },
    { entry_id: "b", reached_stage: "classified" },
  ] };
  const after = { record: [
    { entry_id: "a", reached_stage: "loaded" },
    { entry_id: "b", reached_stage: "classified" },
  ] };
  const report = computeGeneralizationDelta(before, after);
  assert.equal(report.verdict, "refused_single_beneficiary");
  assert.equal(report.is_generic, false);
});

test("the generalization gate accepts breadth and refuses regression", () => {
  const before = { record: [
    { entry_id: "a", reached_stage: "classified" },
    { entry_id: "b", reached_stage: "classified" },
    { entry_id: "c", reached_stage: "loaded" },
  ] };
  const after = { record: [
    { entry_id: "a", reached_stage: "loaded" },
    { entry_id: "b", reached_stage: "loaded" },
    { entry_id: "c", reached_stage: "classified" },
  ] };
  const accepted = computeGeneralizationDelta(before, { record: after.record.slice(0, 2) });
  assert.equal(accepted.verdict, "generic_accepted");
  assert.equal(accepted.beneficiary_count, 2);
  const refused = computeGeneralizationDelta(before, after);
  assert.equal(refused.verdict, "refused_regression");
  const adapter = computeGeneralizationDelta(
    { record: [{ entry_id: "a", reached_stage: "classified" }] },
    { record: [{ entry_id: "a", reached_stage: "loaded" }] },
    { adapter: true },
  );
  assert.equal(adapter.verdict, "adapter_accepted");
});

test("a stored zip stages through ingest under the declared bound", (context) => {
  const root = mkdtempSync(join(tmpdir(), "bptk-corpus-zip-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const zipPath = join(root, "game.zip");
  writeFileSync(zipPath, createStoredZip([
    { path: "data/" },
    { path: "data/readme.txt", data: Buffer.from("lawful payload") },
    { path: "game.exe", data: createPe32() },
  ]));
  const outputDir = join(root, "out");
  const report = ingestInput(zipPath, { output: outputDir });
  assert.equal(report.is_ingested, true);
  assert.equal(report.package_manifest.executable, "game.exe");
  assert.equal(report.extraction.installer_family, "zip");
});

test("a zip path escape is refused before any write", (context) => {
  const root = mkdtempSync(join(tmpdir(), "bptk-corpus-zip-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const zipPath = join(root, "evil.zip");
  writeFileSync(zipPath, createStoredZip([
    { path: "../evil.txt", data: Buffer.from("escape") },
  ]));
  const outputDir = join(root, "out");
  assert.throws(() => ingestInput(zipPath, { output: outputDir }), (error) => error.input_code === "archive_path_escape");
});

test("the amplification guard ignores small output and refuses large", () => {
  const bound = createExtractionBound();
  assert.doesNotThrow(() => assertChunkRatioBound(bound, 5351, 196662));
  assert.throws(() => assertChunkRatioBound(bound, 8192, 8 * 1024 * 1024), (error) => error.input_code === "bound_ratio_exceeded");
});

test("the generalize command refuses on the live record set through the CLI", (context) => {
  const root = mkdtempSync(join(tmpdir(), "bptk-corpus-cli-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const recordPath = join(root, "records.json");
  writeFileSync(recordPath, JSON.stringify({ record: [
    { entry_id: "a", reached_stage: "classified" },
    { entry_id: "b", reached_stage: "loaded" },
  ] }));
  const result = run(["corpus", "generalize", recordPath, recordPath, "--json"]);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stdout).verdict, "refused_single_beneficiary");
});

test("loadRunRecords refuses a file without a record array", (context) => {
  const root = mkdtempSync(join(tmpdir(), "bptk-corpus-cli-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const badPath = join(root, "bad.json");
  writeFileSync(badPath, JSON.stringify({ no_record: true }));
  assert.throws(() => loadRunRecords(badPath), (error) => error.input_code === "run_record_invalid");
});

test("the export-coverage ledger marks the served Win32 core surface covered and the rest absent", (context) => {
  const stage = mkdtempSync(join(tmpdir(), "bptk-coverage-"));
  context.after(() => rmSync(stage, { recursive: true, force: true }));
  const entryDir = join(stage, "corpus-904");
  const packageDir = join(entryDir, "package");
  mkdirSync(packageDir, { recursive: true });
  const payload = createPe32();
  writeFileSync(join(packageDir, "payload.exe"), payload);
  writeFileSync(join(packageDir, "bptk.json"), JSON.stringify({ schema_version: 1, executable: "payload.exe" }));
  const manifestPath = join(stage, "corpus.json");
  writeFileSync(manifestPath, JSON.stringify({
    schema_version: 1,
    record: [{ entry_id: "CORPUS-904", title: "coverage fixture", kind: "program", source_url: "https://corpus.invalid/fixture/payload.exe", license: "MIT", redistribution_basis: "Generated in-test fixture", size_byte: payload.length, sha256: createHash("sha256").update(payload).digest("hex"), game_loop: false, state: "acquired" }],
  }));
  process.env.BPTK_ACQUISITION_PATH = manifestPath;
  context.after(() => { delete process.env.BPTK_ACQUISITION_PATH; });
  const report = buildExportLedger({ stage });
  assert.equal(report.record[0].status, "mapped");
  assert.ok(report.symbol_count >= 1);
  // kernel32!ExitProcess is served by the Win32 core HLE (BPTK-010) and its
  // conformance case exist, so the real import surface is partially covered.
  const exitProcess = report.ledger.find((entry) => entry.key.toLowerCase() === "kernel32.dll!exitprocess");
  assert.notEqual(exitProcess, undefined);
  assert.equal(exitProcess.status, "covered");
  assert.ok(exitProcess.case_count >= 1);
  // This fixture imports only ExitProcess, so the whole surface is covered.
  assert.equal(report.covered_count, 1);
  assert.equal(report.absent_count, 0);
  assert.equal(report.covered_count + report.absent_count, report.symbol_count);
  assert.equal(report.is_within_budget, false);
  assert.ok(report.ledger.some((entry) => /^kernel32\.dll!/i.test(entry.key)));
});

test("the conformance engine fails a zero-case export and passes an oracle match", () => {
  const stub = (library, symbol) => {
    if (library === "KERNEL32.dll" && symbol === "GetStdHandle") return { return_value: 42, last_error: 0 };
    if (library === "KERNEL32.dll" && symbol === "ExitProcess") return { return_value: null, last_error: 0 };
    return { return_value: null, last_error: "absent" };
  };
  const cases = [
    { case_id: "C1", library: "KERNEL32.dll", symbol: "GetStdHandle", input: [-11], expected: { return_value: 42, last_error: 0 } },
    { case_id: "C2", library: "KERNEL32.dll", symbol: "ExitProcess", input: [0], expected: { return_value: null, last_error: 0 } },
  ];
  const covered = runConformanceSuite(cases, stub, { served_export: ["KERNEL32.dll!GetStdHandle", "KERNEL32.dll!ExitProcess"] });
  assert.equal(covered.pass_count, 2);
  assert.equal(covered.is_coverage_complete, true);
  const uncovered = runConformanceSuite(cases, stub, { served_export: ["KERNEL32.dll!GetStdHandle", "KERNEL32.dll!ExitProcess", "USER32.dll!MessageBoxA"] });
  assert.equal(uncovered.is_coverage_complete, false);
  assert.deepEqual(uncovered.uncovered_export, ["USER32.dll!MessageBoxA"]);
  const wrong = runConformanceSuite([{ case_id: "C3", library: "KERNEL32.dll", symbol: "GetStdHandle", input: [-11], expected: { return_value: 7, last_error: 0 } }], stub);
  assert.equal(wrong.fail_count, 1);
  assert.match(wrong.result[0].mismatch[0], /return_value/);
});

test("the trace corpus admits a well-formed trace and rejects each defect class", () => {
  const call = { library: "KERNEL32.dll", symbol: "GetStdHandle", input: [-11], return_value: 42, last_error: 0 };
  const proof = createHash("sha256").update(canonicalizeTrace(call)).digest("hex");
  const provenance = { source_id: "SRC-002", capture_method: "synthetic", revision: "sha256:abc", tool_version: "0.1.0", captured_at: "2026-09-05" };
  const good = { trace_id: "T1", provenance, redaction: { method: "field_strip", proof_sha256: proof }, call };
  const corpus = verifyTraceCorpus([good]);
  assert.equal(corpus.is_corpus_admissible, true);
  assert.equal(corpus.provenance_complete, true);
  assert.equal(corpus.redaction_proven, true);
  assert.equal(corpus.byte_stable, true);

  // Missing a provenance field is rejected.
  const noProvenance = verifyTrace({ trace_id: "T2", provenance: { ...provenance, revision: "" }, redaction: { method: "field_strip", proof_sha256: proof }, call });
  assert.equal(noProvenance.is_admitted, false);
  assert.match(noProvenance.reason.join(" "), /provenance missing revision/);

  // A leaked personal-data byte is caught even when a proof is offered.
  const leakCall = { ...call, note: "PERSONAL_DATA_MARKER" };
  const leakProof = createHash("sha256").update(canonicalizeTrace(leakCall)).digest("hex");
  const leak = verifyTrace({ trace_id: "T3", provenance, redaction: { method: "field_strip", proof_sha256: leakProof }, call: leakCall });
  assert.equal(leak.is_admitted, false);
  assert.match(leak.reason.join(" "), /redaction leak: personal_data/);

  // A proof hash that does not match the canonical byte is rejected.
  const staleProof = verifyTrace({ trace_id: "T4", provenance, redaction: { method: "field_strip", proof_sha256: "0".repeat(64) }, call });
  assert.equal(staleProof.has_redaction_proof, false);
  assert.equal(staleProof.is_admitted, false);

  // Canonicalization is order-independent, which is what makes it byte-stable.
  assert.equal(canonicalizeTrace({ b: 1, a: 2 }), canonicalizeTrace({ a: 2, b: 1 }));
});

test("the committed SDK API manifest matches the live package entry exactly", async () => {
  const fs = await import("node:fs");
  const manifest = JSON.parse(fs.readFileSync(new URL("../data/sdk-api.json", import.meta.url), "utf8"));
  assert.equal(manifest.contract, "semver");
  const live = Object.keys(await import("../lib/index.mjs")).sort();
  assert.deepEqual(live, [...manifest.api].sort());
});

test("the host emission carries the declared cross-origin constraint", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-host-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const projectPath = join(rootPath, "project");
  mkdirSync(projectPath);
  writeFileSync(join(projectPath, "asset.txt"), "asset");
  const result = run(["package", projectPath, "--host", "html", "--json"]);
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.hosting_constraint.cross_origin_embedder_policy, "require-corp");
  assert.equal(report.hosting_constraint.cross_origin_opener_policy, "same-origin");
  assert.equal(report.hosting_constraint.cross_origin_isolation_expected, true);
  assert.match(report.hosting_constraint.fallback, /single-thread bundle/);
});
