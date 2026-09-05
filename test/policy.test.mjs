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

function createPackage(context, content = "temporary policy input\n") {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-policy-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const projectPath = join(rootPath, "project");
  mkdirSync(projectPath);
  writeFileSync(join(projectPath, "game.dat"), content);
  const packageRun = run(["package", projectPath, "--asset-mode", "stream", "--json"]);
  assert.equal(packageRun.status, 0);
  return { root_path: rootPath, project_path: projectPath, package_path: `${projectPath}.bptk-package` };
}

test("network off denies every package attempt", (context) => {
  const packagePath = createPackage(context).package_path;
  const networkRun = run(["run", packagePath, "--network", "off", "--json"]);
  assert.equal(networkRun.status, 0);
  const report = JSON.parse(networkRun.stdout);
  assert.equal(report.state, "denied");
  assert.equal(report.attempt_count, 0);
  assert.equal(report.allowed_count, 0);
});

test("network prompt requires consent without attempting a connection", (context) => {
  const packagePath = createPackage(context).package_path;
  const networkRun = run(["run", packagePath, "--network", "prompt", "--json"]);
  assert.equal(networkRun.status, 0);
  const report = JSON.parse(networkRun.stdout);
  assert.equal(report.state, "consent_required");
  assert.equal(report.attempt_count, 0);
  assert.equal(report.allowed_count, 0);
});

test("cloud save sync uploads only the overlay diff, never the base", (context) => {
  const value = createPackage(context, "base game payload\n");
  // The base file (game.dat) is unchanged; a new save file and a changed copy
  // of the base are the only things transmitted.
  const overlayPath = join(value.root_path, "overlay");
  mkdirSync(overlayPath);
  writeFileSync(join(overlayPath, "game.dat"), "base game payload\n"); // matches base -> excluded
  writeFileSync(join(overlayPath, "save.dat"), "player slot 1\n"); // new -> transmitted
  const syncRun = run(["save", "sync", value.package_path, overlayPath, "--json"]);
  assert.equal(syncRun.status, 0);
  const report = JSON.parse(syncRun.stdout);
  assert.equal(report.transmitted_count, 1);
  assert.equal(report.transmitted[0].path, "save.dat");
  assert.equal(report.transmitted[0].reason, "new");
  assert.equal(report.excluded_count, 1);
  assert.equal(report.is_base_excluded, true);
});

test("cloud save conflict resolves deterministically regardless of device order", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-save-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const deviceA = join(rootPath, "device-a.json");
  const deviceB = join(rootPath, "device-b.json");
  writeFileSync(deviceA, JSON.stringify({ file: [{ path: "slot.dat", sha256: "aaa", clock: 5 }, { path: "opt.dat", sha256: "ooo", clock: 1 }] }));
  writeFileSync(deviceB, JSON.stringify({ file: [{ path: "slot.dat", sha256: "bbb", clock: 7 }] }));
  const forward = JSON.parse(run(["save", "resolve", deviceA, deviceB, "--json"]).stdout);
  const reverse = JSON.parse(run(["save", "resolve", deviceB, deviceA, "--json"]).stdout);
  assert.equal(forward.result_hash, reverse.result_hash, "resolution is order-independent");
  const slot = forward.resolved.find((entry) => entry.path === "slot.dat");
  assert.equal(slot.sha256, "bbb", "higher clock wins");
  assert.equal(forward.conflict_count, 1);
});
