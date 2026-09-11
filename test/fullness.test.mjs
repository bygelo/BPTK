// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { corpusLeg } from "../tool/fullness.mjs";

const fullnessPath = fileURLToPath(new URL("../tool/fullness.mjs", import.meta.url));
const residencyPath = fileURLToPath(new URL("../tool/residency.mjs", import.meta.url));

function run(scriptPath, argument = []) {
  return spawnSync(process.execPath, [scriptPath, ...argument], { encoding: "utf8" });
}

test("corpusLeg: a sibling still at staged keeps the CPU leg red", () => {
  const report = corpusLeg(
    {
      record: [
        { entry_id: "a", reached_stage: "entry" },
        { entry_id: "b", reached_stage: "staged", gap_code: "integrity_mismatch" },
      ],
    },
    ["a", "b"],
  );
  assert.equal(report.is_green, false);
  assert.equal(report.entry_count, 1);
  assert.equal(report.below.length, 1);
  assert.equal(report.below[0].entry_id, "b");
  assert.equal(report.below[0].reached_stage, "staged");
  assert.equal(report.missing.length, 0);
  assert.equal(report.invented.length, 0);
});

test("corpusLeg: every declared record at entry is green", () => {
  const report = corpusLeg(
    {
      record: [
        { entry_id: "a", reached_stage: "entry" },
        { entry_id: "b", reached_stage: "interactive" },
      ],
    },
    ["a", "b"],
  );
  assert.equal(report.is_green, true);
  assert.equal(report.entry_count, 2);
  assert.equal(report.below.length, 0);
});

test("fullness --help names the fullness question and a measured denominator", () => {
  const result = run(fullnessPath, ["--help"]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /fullness/i);
  assert.match(result.stdout, /Is full WASM \+ full CPU \+ full GPU emulation reached yet\?/);
  assert.match(result.stdout, /measured against a denominator/);
  assert.equal(result.stderr, "");
});

test("residency --help names the residency question and a measured denominator", () => {
  const result = run(residencyPath, ["--help"]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /residency/i);
  assert.match(result.stdout, /Is the WASM tier carrying every staged x86-64 run/);
  assert.match(result.stdout, /denominator is measured/);
  assert.equal(result.stderr, "");
});

test("unknown option is a usage error (exit 2)", () => {
  const fullness = run(fullnessPath, ["--bogus"]);
  assert.equal(fullness.status, 2);
  assert.match(fullness.stderr, /fullness: unknown option --bogus/);
  const residency = run(residencyPath, ["--bogus"]);
  assert.equal(residency.status, 2);
  assert.match(residency.stderr, /residency: unknown option --bogus/);
});

test("missing option value is a usage error (exit 2)", () => {
  const fullness = run(fullnessPath, ["--stage"]);
  assert.equal(fullness.status, 2);
  assert.match(fullness.stderr, /fullness: option --stage requires a value/);
  const residency = run(residencyPath, ["--budget"]);
  assert.equal(residency.status, 2);
  assert.match(residency.stderr, /residency: option --budget requires a value/);
});

test("fullness --json on a missing stage is red, not a throw, and does not need a corpus", () => {
  const stage = mkdtempSync(join(tmpdir(), "bptk-fullness-"));
  try {
    const result = run(fullnessPath, ["--json", "--no-gpu", "--stage", stage]);
    assert.notEqual(result.status, 2, `usage/throw: stdout=${result.stdout} stderr=${result.stderr}`);
    assert.equal(result.status, 1);
    const report = JSON.parse(result.stdout);
    assert.equal(report.schema_version, 1);
    assert.equal(report.tool, "tool/fullness.mjs");
    assert.equal(report.is_full, false);
    assert.ok(Array.isArray(report.red));
    assert.ok(report.red.includes("cpu"));
    assert.equal(report.leg.gpu.is_checked, false);
    assert.match(report.scope_note, /not a playability claim/);
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
});

test("residency --json on a missing stage is not resident, not a throw, and does not need a corpus", () => {
  const stage = mkdtempSync(join(tmpdir(), "bptk-residency-"));
  try {
    const result = run(residencyPath, ["--json", "--stage", stage, "--budget", "64"]);
    assert.notEqual(result.status, 2, `usage/throw: stdout=${result.stdout} stderr=${result.stderr}`);
    assert.equal(result.status, 1);
    const report = JSON.parse(result.stdout);
    assert.equal(report.schema_version, 1);
    assert.equal(report.tool, "tool/residency.mjs");
    assert.equal(report.is_resident, false);
    assert.equal(report.payload_count, 0);
    assert.equal(report.budget, 64);
    assert.match(report.scope_note, /not a playability claim/);
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
});
