// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

function createProject(rootPath, packageValue) {
  const projectPath = join(rootPath, `project-${Math.random().toString(36).slice(2)}`);
  mkdirSync(projectPath);
  writeFileSync(join(projectPath, "game.dat"), "first-party demo payload\n");
  if (packageValue) writeFileSync(join(projectPath, "package.json"), JSON.stringify(packageValue));
  return projectPath;
}

test("BYO import stages locally with zero network and never publishes", (context) => {
  const rootPath = scratch(context);
  const filePath = join(rootPath, "my-save.dat");
  writeFileSync(filePath, "user owned game file\n");
  const stagePath = join(rootPath, "library");
  const importRun = run(["library", "import", filePath, "--stage", stagePath, "--json"]);
  assert.equal(importRun.status, 0);
  const report = JSON.parse(importRun.stdout);
  assert.equal(report.network_byte, 0);
  assert.equal(report.is_published, false);
  assert.equal(report.is_launch_local, true);
  assert.equal(existsSync(report.staged_path), true);
});

test("hosting publishes an in-date grant and refuses an expired one", (context) => {
  const rootPath = scratch(context);
  const inDate = createProject(rootPath, { name: "demo", license: "Apache-2.0", grant_expiry: "2999-01-01" });
  const okRun = run(["library", "publish", inDate, "--json"]);
  assert.equal(okRun.status, 0);
  const okReport = JSON.parse(okRun.stdout);
  assert.equal(okReport.is_published, true);
  assert.equal(okReport.state, "hosted_no_runtime");

  const expired = createProject(rootPath, { name: "demo", license: "Apache-2.0", grant_expiry: "2000-01-01" });
  const expiredRun = run(["library", "publish", expired, "--json"]);
  assert.equal(expiredRun.status, 1);
  const expiredReport = JSON.parse(expiredRun.stdout);
  assert.equal(expiredReport.is_published, false);
  assert.ok(expiredReport.refusal.some((entry) => /expired/.test(entry)));

  const unlicensed = createProject(rootPath, null);
  const unlicensedRun = run(["library", "publish", unlicensed, "--json"]);
  assert.equal(unlicensedRun.status, 1);
  assert.equal(JSON.parse(unlicensedRun.stdout).is_published, false);
});

test("preservation catalog is append-only and exports reproducibly and PII-free", (context) => {
  const rootPath = scratch(context);
  const catalogPath = join(rootPath, "preservation.json");
  const entryOne = join(rootPath, "entry-one.json");
  const entryTwo = join(rootPath, "entry-two.json");
  writeFileSync(entryOne, JSON.stringify({ id: "title-1", title: "Preserved One", provenance: "freeware release 1999" }));
  writeFileSync(entryTwo, JSON.stringify({ id: "title-2", title: "Preserved Two", provenance: "freeware release 2001" }));
  assert.equal(run(["library", "preserve", catalogPath, entryOne, "--json"]).status, 0);
  assert.equal(run(["library", "preserve", catalogPath, entryTwo, "--json"]).status, 0);
  // Re-appending the identical entry is a no-op duplicate, not an error.
  const duplicate = JSON.parse(run(["library", "preserve", catalogPath, entryOne, "--json"]).stdout);
  assert.equal(duplicate.is_appended, false);
  assert.equal(duplicate.is_duplicate, true);

  // Mutating an existing id is refused.
  const mutated = join(rootPath, "entry-mutated.json");
  writeFileSync(mutated, JSON.stringify({ id: "title-1", title: "Preserved One CHANGED", provenance: "tampered" }));
  const mutateRun = run(["library", "preserve", catalogPath, mutated, "--json"]);
  assert.equal(mutateRun.status, 1);

  // Export is byte-identical across two runs and personal-data-free.
  const exportA = JSON.parse(run(["library", "preserve-export", catalogPath, "--json"]).stdout);
  const exportB = JSON.parse(run(["library", "preserve-export", catalogPath, "--json"]).stdout);
  assert.equal(exportA.export_hash, exportB.export_hash);
  assert.equal(exportA.export_body, exportB.export_body);
  assert.equal(exportA.is_personal_data_free, true);
});

test("preservation export refuses a record carrying personal data", (context) => {
  const rootPath = scratch(context);
  const catalogPath = join(rootPath, "preservation.json");
  const entry = join(rootPath, "entry.json");
  writeFileSync(entry, JSON.stringify({ id: "t", title: "Has PII", provenance: "contact person@example.com" }));
  assert.equal(run(["library", "preserve", catalogPath, entry, "--json"]).status, 0);
  const exportRun = run(["library", "preserve-export", catalogPath, "--json"]);
  assert.equal(exportRun.status, 1);
  const report = JSON.parse(exportRun.stdout);
  assert.equal(report.is_personal_data_free, false);
  assert.ok(report.personal_data_hit.includes("email"));
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
