// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { computePrecacheDiff } from "../lib/package.mjs";

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

test("CDN store dedups a shared payload and never merges a differing hash", (context) => {
  const storePath = mkdtempSync(join(tmpdir(), "bptk-cdn-"));
  context.after(() => rmSync(storePath, { recursive: true, force: true }));
  const shared = Buffer.from("BPTK shared redistributable runtime payload\n");
  const different = Buffer.from("BPTK unrelated payload\n");

  const first = createProject(context, shared);
  assert.equal(run(["package", first.project_path, "--asset-mode", "stream", "--json"]).status, 0);
  const firstPublish = JSON.parse(run(["package", first.package_path, "--publish-cdn", storePath, "--json"]).stdout);
  assert.ok(firstPublish.stored_count >= 1);
  assert.equal(firstPublish.hit_count, 0);

  const second = createProject(context, shared);
  assert.equal(run(["package", second.project_path, "--asset-mode", "stream", "--json"]).status, 0);
  const secondPublish = JSON.parse(run(["package", second.package_path, "--publish-cdn", storePath, "--json"]).stdout);
  assert.equal(secondPublish.stored_count, 0, "shared payload stored once");
  assert.equal(secondPublish.hit_count, firstPublish.stored_count, "second title hits the cache");

  const third = createProject(context, different);
  assert.equal(run(["package", third.project_path, "--asset-mode", "stream", "--json"]).status, 0);
  const thirdPublish = JSON.parse(run(["package", third.package_path, "--publish-cdn", storePath, "--json"]).stdout);
  assert.ok(thirdPublish.stored_count >= 1, "differing hash is a new key, never merged");
  assert.equal(thirdPublish.hit_count, 0);
  assert.equal(readdirSync(join(storePath, "object")).length, firstPublish.stored_count + thirdPublish.stored_count);
});

test("PWA emits a hash-precaching service worker and a single-block edit invalidates only that block", (context) => {
  const value = createProject(context);
  const assetReport = JSON.parse(run(["package", value.project_path, "--asset-mode", "stream", "--json"]).stdout);
  const pwaRun = run(["package", value.package_path, "--pwa", "--json"]);
  assert.equal(pwaRun.status, 0);
  const pwa = JSON.parse(pwaRun.stdout);
  const serviceWorker = readFileSync(join(pwa.output_path, "sw.js"), "utf8");
  for (const sha of pwa.precache) assert.match(serviceWorker, new RegExp(sha));
  assert.equal(pwa.precache_count, assetReport.chunk_count);
  assert.match(readFileSync(join(pwa.output_path, "index.html"), "utf8"), /serviceWorker\.register/);

  // A content-addressed precache set invalidates exactly the changed block.
  const before = ["aaa", "bbb", "ccc"];
  const after = ["aaa", "ddd", "ccc"];
  const diff = computePrecacheDiff(before, after);
  assert.deepEqual(diff.added, ["ddd"]);
  assert.deepEqual(diff.removed, ["bbb"]);
  assert.deepEqual(diff.retained, ["aaa", "ccc"]);
  assert.equal(diff.invalidated_count, 2);
});

test("stream plan splits prefetch from deferred and absent reads never block", (context) => {
  const payload = Buffer.from("BPTK range streaming payload. ".repeat(120000));
  const value = createProject(context, payload);
  assert.equal(run(["package", value.project_path, "--asset-mode", "stream", "--json"]).status, 0);
  const planRun = run(["package", value.package_path, "--stream-plan", "--prefetch", "1", "--json"]);
  assert.equal(planRun.status, 0);
  const plan = JSON.parse(planRun.stdout);
  assert.ok(plan.block_count > 1);
  assert.equal(plan.prefetch_count, 1);
  assert.equal(plan.deferred_count, plan.block_count - 1);
  assert.equal(plan.is_interactive_partly_unfetched, true);
  assert.equal(plan.is_absent_read_blocking, false);
  assert.equal(plan.absent_block_read.state, "pending");
  // A second run with the same package is byte-identical (deterministic plan).
  const planRun2 = run(["package", value.package_path, "--stream-plan", "--prefetch", "1", "--json"]);
  assert.equal(planRun2.stdout, planRun.stdout);
});

test("every host shape carries one identity, a release path, and a sandboxed frame", (context) => {
  const value = createProject(context);
  const assetReport = JSON.parse(run(["package", value.project_path, "--asset-mode", "stream", "--json"]).stdout);
  const shape = ["html", "react", "webcomponent", "iframe"];
  const artifact = [];
  for (const host of shape) {
    const hostRun = run(["package", value.package_path, "--host", host, "--json"]);
    assert.equal(hostRun.status, 0, `${host} host emits`);
    const report = JSON.parse(hostRun.stdout);
    assert.equal(report.package_id, assetReport.package_id, `${host} preserves identity`);
    const source = readFileSync(join(report.output_path, report.host_file), "utf8");
    assert.match(source, new RegExp(assetReport.package_id), `${host} embeds package id`);
    artifact.push({ host, source });
  }
  // Web component releases every worker/audio/GPU handle on disconnect.
  const webComponent = artifact.find((entry) => entry.host === "webcomponent").source;
  assert.match(webComponent, /disconnectedCallback/);
  assert.match(webComponent, /terminate\?\.\(\)/);
  // Both framed shapes sandbox the embedded document.
  for (const host of ["react", "iframe"]) {
    assert.match(artifact.find((entry) => entry.host === host).source, /sandbox/);
  }
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
