// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

function run(argument) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

function createProject(context, fill) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-package-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const projectPath = join(rootPath, "project");
  mkdirSync(projectPath);
  writeFileSync(join(projectPath, "game.dat"), fill ?? Buffer.from("BPTK generated package input\n"));
  return { root_path: rootPath, project_path: projectPath, package_path: `${projectPath}.bptk-package` };
}

test("HTML and React host preserve one generated package identity", (context) => {
  const value = createProject(context);
  const assetRun = run(["package", value.project_path, "--asset-mode", "stream", "--json"]);
  assert.equal(assetRun.status, 0);
  const assetReport = JSON.parse(assetRun.stdout);
  const htmlRun = run(["package", value.package_path, "--host", "html", "--json"]);
  const reactRun = run(["package", value.package_path, "--host", "react", "--json"]);
  assert.equal(htmlRun.status, 0);
  assert.equal(reactRun.status, 0);
  const htmlReport = JSON.parse(htmlRun.stdout);
  const reactReport = JSON.parse(reactRun.stdout);
  assert.equal(htmlReport.package_id, assetReport.package_id);
  assert.equal(reactReport.package_id, assetReport.package_id);
  assert.match(readFileSync(join(htmlReport.output_path, "index.html"), "utf8"), new RegExp(assetReport.package_id));
  assert.match(readFileSync(join(reactReport.output_path, "BptkHost.mjs"), "utf8"), new RegExp(assetReport.package_id));
});

test("compressed streaming shrinks stored bytes and every chunk hash verifies", (context) => {
  // A compressible payload larger than one chunk so compression is measurable.
  const payload = Buffer.from("BPTK streaming payload block. ".repeat(120000));
  const value = createProject(context, payload);
  const packageRun = run(["package", value.project_path, "--asset-mode", "stream-compressed", "--json"]);
  assert.equal(packageRun.status, 0);
  const report = JSON.parse(packageRun.stdout);
  assert.equal(report.chunk_codec, "gzip");
  assert.ok(report.chunk_count > 1, "payload spans more than one chunk");
  assert.ok(report.stored_fraction < 1, "compression stores fewer bytes than plain");
  assert.ok(report.stored_byte_total < report.plain_byte_total);

  const verifyRun = run(["package", value.package_path, "--verify", "--json"]);
  assert.equal(verifyRun.status, 0);
  const verify = JSON.parse(verifyRun.stdout);
  assert.equal(verify.is_all_verified, true);
  assert.equal(verify.verified_count, verify.chunk_count);
  assert.equal(verify.chunk_count, report.chunk_count);
  assert.deepEqual(verify.failure, []);
});

test("verify rejects a tampered stored chunk", (context) => {
  const value = createProject(context);
  assert.equal(run(["package", value.project_path, "--asset-mode", "stream-compressed", "--json"]).status, 0);
  const chunkDirectory = join(value.package_path, "chunk");
  const [chunkName] = readdirSync(chunkDirectory);
  writeFileSync(join(chunkDirectory, chunkName), Buffer.from("corrupted-stored-bytes"));
  const verifyRun = run(["package", value.package_path, "--verify", "--json"]);
  assert.equal(verifyRun.status, 1);
  const verify = JSON.parse(verifyRun.stdout);
  assert.equal(verify.is_all_verified, false);
  assert.ok(verify.failure.length >= 1);
});

test("report off writes nothing and consent writes one minimized local report", (context) => {
  const value = createProject(context);
  assert.equal(run(["package", value.project_path, "--asset-mode", "stream", "--json"]).status, 0);
  const offRun = run(["report", value.package_path, "--record", "off", "--json"]);
  assert.equal(offRun.status, 0);
  assert.equal(JSON.parse(offRun.stdout).output_path, null);
  assert.equal(existsSync(join(value.package_path, "report")), false);
  const consentRun = run(["report", value.package_path, "--record", "consent", "--json"]);
  assert.equal(consentRun.status, 0);
  const consentValue = JSON.parse(consentRun.stdout);
  assert.equal(existsSync(consentValue.output_path), true);
  const report = JSON.parse(readFileSync(consentValue.output_path, "utf8"));
  assert.equal(report.is_game_content_included, false);
  assert.equal(report.is_personal_data_included, false);
  assert.deepEqual(readdirSync(join(value.package_path, "report")), [basename(consentValue.output_path)]);
});
