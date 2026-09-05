// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));
const hashA = "a".repeat(64);
const hashB = "b".repeat(64);

function run(argument) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

function scratch(context) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-library-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  return rootPath;
}

test("catalog validates the frozen schema and gates instant-play", (context) => {
  const rootPath = scratch(context);
  const catalogPath = join(rootPath, "catalog.json");
  writeFileSync(catalogPath, JSON.stringify({
    entry: [
      { title: "Demo A", build_hash: hashA, license: "Apache-2.0", redistribution: "approved", capability: "passing" },
      { title: "Demo B", build_hash: hashB, license: "Freeware", redistribution: "none", capability: "unknown" },
      { title: "Demo C", build_hash: hashA, license: "Apache-2.0", redistribution: "approved", capability: "failing" },
    ],
  }));
  const catalogRun = run(["library", "catalog", catalogPath, "--json"]);
  assert.equal(catalogRun.status, 0);
  const report = JSON.parse(catalogRun.stdout);
  assert.equal(report.is_all_valid, true);
  assert.equal(report.entry[0].access, "instant_play_eligible");
  assert.equal(report.entry[1].access, "bring_your_own_only");
  assert.equal(report.entry[2].access, "hosted_no_capability");
  assert.equal(report.instant_play_count, 1);
  assert.equal(report.byo_only_count, 1);
});

test("catalog rejects an entry that violates the schema", (context) => {
  const rootPath = scratch(context);
  const catalogPath = join(rootPath, "catalog.json");
  writeFileSync(catalogPath, JSON.stringify({
    entry: [{ title: "Bad", build_hash: "not-a-hash", license: "Apache-2.0", redistribution: "maybe", capability: "passing" }],
  }));
  const catalogRun = run(["library", "catalog", catalogPath, "--json"]);
  assert.equal(catalogRun.status, 1);
  const report = JSON.parse(catalogRun.stdout);
  assert.equal(report.is_all_valid, false);
  assert.equal(report.entry[0].access, "rejected");
  assert.ok(report.entry[0].failure.length >= 2);
});
