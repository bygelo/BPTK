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
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-boundary-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const projectPath = join(rootPath, "project");
  mkdirSync(projectPath);
  writeFileSync(join(projectPath, "game.dat"), "temporary boundary input\n");
  assert.equal(run(["package", projectPath, "--asset-mode", "stream", "--json"]).status, 0);
  return `${projectPath}.bptk-package`;
}

test("save diagnosis keeps the package base read-only and creates no overlay", (context) => {
  const packagePath = createPackage(context);
  const saveRun = run(["run", packagePath, "--save", "slot-1", "--json"]);
  assert.equal(saveRun.status, 0);
  const report = JSON.parse(saveRun.stdout);
  assert.equal(report.is_base_read_only, true);
  assert.equal(report.is_overlay_created, false);
  assert.equal(report.is_persistent, false);
});

test("save diagnosis rejects a path-shaped profile", (context) => {
  const packagePath = createPackage(context);
  const saveRun = run(["run", packagePath, "--save", "../escape", "--json"]);
  assert.equal(saveRun.status, 1);
  assert.equal(JSON.parse(saveRun.stderr).error_code, "invalid_save_profile");
});

test("import and run diagnosis never stages or executes an asset package", (context) => {
  const packagePath = createPackage(context);
  const importRun = run(["import", packagePath, "--run", "--json"]);
  assert.equal(importRun.status, 0);
  const report = JSON.parse(importRun.stdout);
  assert.equal(report.state, "imported_assets_no_runtime");
  assert.equal(report.is_staged, false);
  assert.equal(report.is_executed, false);
});
