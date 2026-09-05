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

function run(argument) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

function scratch(context) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-governance-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  return rootPath;
}

function writeJsonFile(rootPath, name, value) {
  const path = join(rootPath, name);
  writeFileSync(path, JSON.stringify(value));
  return path;
}

test("tracker rejects a bare report and accepts a complete one within the freshness level", (context) => {
  const rootPath = scratch(context);
  const bare = writeJsonFile(rootPath, "bare.json", { title: "it crashes" });
  const bareRun = run(["tracker", "submit", bare, "--json"]);
  assert.equal(bareRun.status, 1);
  assert.equal(JSON.parse(bareRun.stdout).is_accepted, false);

  const complete = writeJsonFile(rootPath, "complete.json", {
    environment: "chrome-120-linux",
    revision: "rev-9",
    repro_hash: "abc123",
    submitted_at: "2026-01-01T00:00:00Z",
    triaged_at: "2026-01-02T00:00:00Z",
  });
  const completeRun = run(["tracker", "submit", complete, "--json"]);
  assert.equal(completeRun.status, 0);
  const report = JSON.parse(completeRun.stdout);
  assert.equal(report.is_accepted, true);
  assert.equal(report.is_triaged_within_level, true);
  assert.ok(report.triage_latency_hour <= report.triage_freshness_hour);
});

test("compatibility export is byte-stable and refuses unbacked and personal rows", (context) => {
  const rootPath = scratch(context);
  const clean = writeJsonFile(rootPath, "db.json", {
    row: [
      { title: "Demo B", environment: "chrome", evidence_hash: "b".repeat(64) },
      { title: "Demo A", environment: "firefox", evidence_hash: "a".repeat(64) },
    ],
  });
  const exportA = JSON.parse(run(["tracker", "export", clean, "--json"]).stdout);
  const exportB = JSON.parse(run(["tracker", "export", clean, "--json"]).stdout);
  assert.equal(exportA.is_accepted, true);
  assert.equal(exportA.export_hash, exportB.export_hash);
  assert.equal(exportA.export_body, exportB.export_body);

  const unbacked = writeJsonFile(rootPath, "unbacked.json", { row: [{ title: "No evidence", environment: "chrome" }] });
  assert.equal(run(["tracker", "export", unbacked, "--json"]).status, 1);

  const personal = writeJsonFile(rootPath, "personal.json", { row: [{ title: "contact me@example.com", environment: "chrome", evidence_hash: "c".repeat(64) }] });
  assert.equal(run(["tracker", "export", personal, "--json"]).status, 1);
});

test("undisclosed agent PR is refused; disclosed-agent and human PRs take the identical gate", (context) => {
  const rootPath = scratch(context);
  const undisclosed = writeJsonFile(rootPath, "agent.json", { author_type: "agent" });
  assert.equal(run(["governance", "contribution", undisclosed, "--json"]).status, 1);

  const disclosed = writeJsonFile(rootPath, "agent-ok.json", { author_type: "agent", ai_disclosure: true });
  const human = writeJsonFile(rootPath, "human.json", { author_type: "human" });
  const disclosedReport = JSON.parse(run(["governance", "contribution", disclosed, "--json"]).stdout);
  const humanReport = JSON.parse(run(["governance", "contribution", human, "--json"]).stdout);
  assert.equal(disclosedReport.is_accepted, true);
  assert.equal(humanReport.is_accepted, true);
  assert.deepEqual(disclosedReport.gate_path, humanReport.gate_path);
});

test("breaking change without a decision record is refused; analytics property is audited", (context) => {
  const rootPath = scratch(context);
  const honestAnalytics = { is_aggregate: true, is_opt_in: true, carries_personal_data: false };
  const refused = writeJsonFile(rootPath, "breaking.json", { is_breaking: true, analytics: honestAnalytics });
  assert.equal(run(["governance", "change", refused, "--json"]).status, 1);

  const accepted = writeJsonFile(rootPath, "recorded.json", { is_breaking: true, decision_record: "doc/DECISION-9.md", analytics: honestAnalytics });
  const acceptedReport = JSON.parse(run(["governance", "change", accepted, "--json"]).stdout);
  assert.equal(acceptedReport.is_change_accepted, true);
  assert.equal(acceptedReport.is_analytics_honest, true);
  assert.ok(acceptedReport.code_of_conduct.length > 0);

  const dishonest = writeJsonFile(rootPath, "leaky.json", { is_breaking: false, analytics: { is_aggregate: true, is_opt_in: false, carries_personal_data: true } });
  const dishonestReport = JSON.parse(run(["governance", "change", dishonest, "--json"]).stdout);
  assert.equal(dishonestReport.is_analytics_honest, false);
  assert.equal(dishonestReport.is_accepted, false);
});
