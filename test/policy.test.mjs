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

function createPackage(context) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-policy-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const projectPath = join(rootPath, "project");
  mkdirSync(projectPath);
  writeFileSync(join(projectPath, "game.dat"), "temporary policy input\n");
  const packageRun = run(["package", projectPath, "--asset-mode", "stream", "--json"]);
  assert.equal(packageRun.status, 0);
  return `${projectPath}.bptk-package`;
}

test("network off denies every package attempt", (context) => {
  const packagePath = createPackage(context);
  const networkRun = run(["run", packagePath, "--network", "off", "--json"]);
  assert.equal(networkRun.status, 0);
  const report = JSON.parse(networkRun.stdout);
  assert.equal(report.state, "denied");
  assert.equal(report.attempt_count, 0);
  assert.equal(report.allowed_count, 0);
});

test("network prompt requires consent without attempting a connection", (context) => {
  const packagePath = createPackage(context);
  const networkRun = run(["run", packagePath, "--network", "prompt", "--json"]);
  assert.equal(networkRun.status, 0);
  const report = JSON.parse(networkRun.stdout);
  assert.equal(report.state, "consent_required");
  assert.equal(report.attempt_count, 0);
  assert.equal(report.allowed_count, 0);
});
