// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Security-layer tests for the import boundary (GS-088, GS-089), the
// capability manifest (GS-090), the trust tier (GS-091), the lane profile
// model (GS-086), and the license graph (GS-084). Every refusal is exercised
// at the real CLI surface.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

function run(argument) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

function createExePackage(context, option = {}) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-batcha-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
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
  file.writeUInt32LE(0x1000, 0x178 + 8);
  file.writeUInt32LE(0x1000, 0x178 + 12);
  file.writeUInt32LE(0x60000020, 0x178 + 36);
  file.writeUInt32LE(0x600, 0x178 + 16);
  file.writeUInt32LE(0x200, 0x178 + 20);
  file[0x200] = 0xc3;
  writeFileSync(join(packagePath, "game.exe"), file);
  writeFileSync(join(packagePath, "bptk.json"), JSON.stringify({
    schema_version: 1,
    executable: "game.exe",
    ...option.manifest,
  }));
  return { rootPath, packagePath };
}

test("a protection-evidence input is refused before any staging artifact exists", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-batcha-drm-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const projectPath = join(rootPath, "protected");
  mkdirSync(projectPath);
  writeFileSync(join(projectPath, "game.exe"), "fake executable content\n");
  writeFileSync(join(projectPath, "clcd32.dll"), "SafeDisc driver evidence\n");
  const outputDir = join(rootPath, "out");
  const result = run(["ingest", projectPath, "--output", outputDir, "--json"]);
  assert.equal(result.status, 1);
  const failure = JSON.parse(result.stderr);
  assert.equal(failure.error_code, "census_protection_refused");
  assert.match(failure.message, /SafeDisc/);
  assert.equal(existsSync(outputDir), false, "no artifact is written for a refused input");
});

test("a threat-scan hit quarantines the input from every staging path", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-batcha-threat-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const inputPath = join(rootPath, "eicar.com");
  writeFileSync(inputPath, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
  const outputDir = join(rootPath, "out");
  const result = run(["ingest", inputPath, "--output", outputDir, "--json"]);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr).error_code, "threat_scan_flagged");
  assert.equal(existsSync(outputDir), false);
  const security = run(["security", inputPath, "--json"]);
  assert.equal(security.status, 0);
  const report = JSON.parse(security.stdout);
  assert.equal(report.trust_tier.tier, "refused");
  assert.equal(report.threat_scan.is_flagged, true);
});

test("the trust tier grades a byte-mismatched lookalike as unknown-untrusted", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-batcha-tier-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const knownPath = join(rootPath, "openttd-13.4-windows-win64.zip");
  writeFileSync(knownPath, "fake byte that match no pin\n");
  const known = run(["security", knownPath, "--json"]);
  const knownReport = JSON.parse(known.stdout);
  assert.equal(knownReport.trust_tier.tier, "unknown_untrusted");
  assert.equal(knownReport.trust_tier.is_upgrade_possible, false);
  assert.deepEqual(knownReport.trust_tier.allowed_surface, ["inspect", "security"]);
});

test("the capability manifest refuses any declared grant", (context) => {
  const { packagePath } = createExePackage(context, {
    manifest: { capability: { host_script: false, file_system: false, network: true, process: false, device: false } },
  });
  const result = run(["run", packagePath, "--json"]);
  assert.equal(result.status, 1);
  const failure = JSON.parse(result.stderr);
  assert.equal(failure.error_code, "containment_policy_violation");
  assert.match(failure.message, /network/);
});

test("the capability manifest refuses capability outside the policy", (context) => {
  const { packagePath } = createExePackage(context, {
    manifest: { capability: { host_script: false, file_system: false, network: false, process: false, device: false, clipboard: true } },
  });
  const result = run(["run", packagePath, "--json"]);
  assert.equal(result.status, 1);
  const failure = JSON.parse(result.stderr);
  assert.equal(failure.error_code, "containment_policy_violation");
  assert.match(failure.message, /clipboard/);
});

test("a manifest declaring an absent lane is refused instead of mis-run", (context) => {
  const { packagePath } = createExePackage(context, { manifest: { lane: "emulator" } });
  const result = run(["run", packagePath, "--json"]);
  assert.equal(result.status, 1);
  const failure = JSON.parse(result.stderr);
  assert.equal(failure.error_code, "lane_not_available");
  assert.match(failure.message, /emulator/);
});

test("the least-privilege capability block surfaces on the run report", (context) => {
  const { packagePath } = createExePackage(context);
  const result = run(["run", packagePath, "--json"]);
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.capability_report.is_least_privilege, true);
  assert.deepEqual(report.capability_report.granted, []);
  assert.equal(report.lane, "binary_probe");
});

test("the license graph refuses unknown, unlicensed, and expired node", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-batcha-legal-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const unknown = join(rootPath, "unknown");
  mkdirSync(unknown);
  writeFileSync(join(unknown, "package.json"), JSON.stringify({ license: "Proprietary-Widgets-Inc" }));
  const unknownReport = JSON.parse(run(["legal", unknown, "--json"]).stdout);
  assert.equal(unknownReport.decision, "refused_unresolved_graph");
  assert.ok(unknownReport.graph.refusal.some((entry) => entry.includes("Proprietary-Widgets-Inc")));

  const unlicensed = join(rootPath, "unlicensed");
  mkdirSync(unlicensed);
  const unlicensedReport = JSON.parse(run(["legal", unlicensed, "--json"]).stdout);
  assert.equal(unlicensedReport.decision, "refused_unresolved_graph");
  assert.ok(unlicensedReport.graph.refusal.some((entry) => entry.includes("no license")));

  const expired = join(rootPath, "expired");
  mkdirSync(expired);
  writeFileSync(join(expired, "package.json"), JSON.stringify({ license: "MIT", grant_expiry: "2020-01-01" }));
  const expiredReport = JSON.parse(run(["legal", expired, "--json"]).stdout);
  assert.ok(expiredReport.graph.refusal.some((entry) => entry.includes("expired")));

  const current = join(rootPath, "current");
  mkdirSync(current);
  writeFileSync(join(current, "package.json"), JSON.stringify({ license: "MIT", grant_expiry: "2099-01-01" }));
  const currentReport = JSON.parse(run(["legal", current, "--json"]).stdout);
  assert.equal(currentReport.decision, "review_required");
  assert.equal(currentReport.graph.refusal.length, 0);
});

test("the lane router ranks the eight-lane taxonomy with a hard mislabel failure", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-batchb-route-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const pe = createExePackage(context);
  const peRun = run(["inspect", pe.packagePath, "--json"]);
  const peReport = JSON.parse(peRun.stdout);
  assert.equal(peReport.lane_decision.primary_lane, "binary_i386");
  assert.equal(peReport.lane_decision.is_executed, false);

  const web = join(rootPath, "webexport");
  mkdirSync(web);
  writeFileSync(join(web, "index.html"), "<html></html>");
  writeFileSync(join(web, "game.wasm"), Buffer.alloc(8));
  const webRun = run(["inspect", web, "--json"]);
  const webReport = JSON.parse(webRun.stdout);
  assert.equal(webReport.lane_decision.primary_lane, "web_native");

  const empty = join(rootPath, "empty");
  mkdirSync(empty);
  const emptyRun = run(["inspect", empty, "--json"]);
  assert.equal(JSON.parse(emptyRun.stdout).lane_decision.primary_lane, "no_lane");
});

test("a schema-2 lane bundle runs on the probe lane and refuses a payload mismatch", (context) => {
  const good = createExePackage(context, {
    manifest: { schema_version: 2, package_kind: "lane_bundle", lane: "binary_probe", executable: "game.exe" },
  });
  const goodRun = run(["run", good.packagePath, "--json"]);
  assert.equal(goodRun.status, 0);
  const goodReport = JSON.parse(goodRun.stdout);
  assert.equal(goodReport.lane, "binary_probe");
  assert.equal(goodReport.lane_accuracy.is_playable_claim, false);
  assert.equal(goodReport.unsupported_set.schema_version, 1);
  assert.match(goodReport.lane_accuracy.accuracy_note, /not a playable claim/);

  const mismatch = createExePackage(context, {
    manifest: { schema_version: 2, package_kind: "lane_bundle", lane: "binary_probe", executable: "page.html" },
  });
  writeFileSync(join(mismatch.packagePath, "page.html"), "<html></html>");
  const mismatchRun = run(["run", mismatch.packagePath, "--json"]);
  assert.equal(mismatchRun.status, 1);
  assert.equal(JSON.parse(mismatchRun.stderr).error_code, "lane_payload_mismatch");

  const absent = createExePackage(context, {
    manifest: { schema_version: 2, package_kind: "lane_bundle", lane: "web_native", executable: "game.exe" },
  });
  const absentRun = run(["run", absent.packagePath, "--json"]);
  assert.equal(absentRun.status, 1);
  assert.equal(JSON.parse(absentRun.stderr).error_code, "lane_not_available");
});

test("a web-native export stages only under a least-privilege capability manifest", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-batchb-web-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const web = join(rootPath, "export");
  mkdirSync(web);
  writeFileSync(join(web, "index.html"), "<html></html>");
  writeFileSync(join(web, "game.wasm"), Buffer.alloc(8));

  const missing = run(["ingest", web, "--json"]);
  assert.equal(missing.status, 1);
  assert.equal(JSON.parse(missing.stderr).error_code, "web_native_manifest_required");

  writeFileSync(join(web, "bptk.json"), JSON.stringify({
    schema_version: 1,
    package_kind: "web_native",
    capability: { host_script: false, file_system: false, network: false, process: false, device: false },
  }));
  const outputDir = join(rootPath, "staged");
  const staged = run(["ingest", web, "--output", outputDir, "--json"]);
  assert.equal(staged.status, 0);
  const stagedReport = JSON.parse(staged.stdout);
  assert.equal(stagedReport.state, "web_native_host_pending");
  assert.equal(stagedReport.is_executed, false);

  writeFileSync(join(web, "bptk.json"), JSON.stringify({
    schema_version: 1,
    package_kind: "web_native",
    capability: { host_script: false, file_system: false, network: true, process: false, device: false },
  }));
  const granted = run(["ingest", web, "--output", outputDir, "--json"]);
  assert.equal(granted.status, 1);
  assert.equal(JSON.parse(granted.stderr).error_code, "web_native_capability_refused");
});
