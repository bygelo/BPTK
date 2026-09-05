// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCompatibilityDatabase, buildReplayArtifact, compareReplay, computeCompatibilityRating, exportCompatibilityDatabase, verifyCompatibilityRow, verifyReplayArtifact } from "../lib/report.mjs";

const provenance = { boots: "replay:aa", in_game: "replay:bb", playable: "replay:cc", complete: "replay:dd" };

test("the rating ladder grants each rung only on a passing, evidence-backed predicate", () => {
  const full = computeCompatibilityRating({ predicate: { boots: true, in_game: true, playable: true, complete: true }, provenance });
  assert.equal(full.rating, "complete");
  assert.equal(full.is_false_green, false);
  assert.equal(full.is_provenance_backed, true);

  const partial = computeCompatibilityRating({ predicate: { boots: true, in_game: true }, provenance });
  assert.equal(partial.rating, "in_game");
});

test("a passing higher rung above a failed lower rung never lifts the rating (no false green)", () => {
  // boots fails but playable "passes" — the contiguous ceiling is still broken.
  const gap = computeCompatibilityRating({ predicate: { boots: false, in_game: true, playable: true }, provenance });
  assert.equal(gap.rating, "broken");
  assert.equal(gap.is_false_green, false);
  assert.match(gap.stop_reason, /predicate for boots did not pass/);
});

test("a rung that passes its predicate but carries no evidence is not granted", () => {
  const unbacked = computeCompatibilityRating({ predicate: { boots: true, in_game: true }, provenance: { boots: "replay:aa" } });
  assert.equal(unbacked.rating, "boots");
  assert.match(unbacked.stop_reason, /no backing evidence/);
});

test("with no passing predicate the honest rating is broken", () => {
  const none = computeCompatibilityRating({ predicate: {}, provenance: {} });
  assert.equal(none.rating, "broken");
  assert.equal(none.rating_index, 0);
});

const run = {
  title_id: "T-DEMO",
  revision: "sha256:rev",
  checkpoint: [
    { label: "boot", state: { frame: 0, pc: 4096 } },
    { label: "menu", state: { frame: 60, pc: 8192 } },
  ],
};

test("two replays of the same run hash-match at every checkpoint", () => {
  const first = buildReplayArtifact(run);
  const second = buildReplayArtifact({ ...run, checkpoint: run.checkpoint.map((entry) => ({ ...entry })) });
  assert.equal(first.artifact_sha256, second.artifact_sha256);
  const verdict = compareReplay(first, second);
  assert.equal(verdict.is_deterministic, true);
  assert.equal(verdict.first_divergence, null);
});

test("a divergent checkpoint is caught at its index", () => {
  const first = buildReplayArtifact(run);
  const drift = buildReplayArtifact({ ...run, checkpoint: [run.checkpoint[0], { label: "menu", state: { frame: 61, pc: 8192 } }] });
  const verdict = compareReplay(first, drift);
  assert.equal(verdict.is_deterministic, false);
  assert.equal(verdict.first_divergence.index, 1);
});

test("the built artifact embeds no raw state, only hashes, and passes the clean check", () => {
  const artifact = buildReplayArtifact(run);
  assert.equal("state" in artifact.checkpoint[0], false);
  assert.match(artifact.checkpoint[0].state_sha256, /^[a-f0-9]{64}$/);
  assert.equal(verifyReplayArtifact(artifact).is_clean, true);
});

test("an artifact that embeds personal data or a raw state blob is refused", () => {
  const leak = { title_id: "T", revision: "r", checkpoint: [{ label: "x", state_sha256: "a".repeat(64), state: { note: "PERSONAL_DATA_MARKER" } }] };
  const verdict = verifyReplayArtifact(leak);
  assert.equal(verdict.is_clean, false);
  assert.match(verdict.reason.join(" "), /embedded personal_data/);
  assert.match(verdict.reason.join(" "), /embeds raw state/);
});

const goodRow = {
  title_id: "T-DEMO",
  build_hash: "sha256:build",
  environment: "linux-node22",
  browser: "chrome-141",
  revision: "sha256:rev1",
  evidence_sha256: "b".repeat(64),
  rating: "boots",
};

test("a fully-backed, revision-pinned row publishes and the export is byte-stable", () => {
  const db = buildCompatibilityDatabase({ revision: "sha256:rev1", row: [goodRow] });
  assert.equal(db.is_publishable, true);
  assert.equal(db.row_count, 1);
  const first = exportCompatibilityDatabase(db);
  const second = exportCompatibilityDatabase(buildCompatibilityDatabase({ revision: "sha256:rev1", row: [{ ...goodRow }] }));
  assert.equal(first.export_sha256, second.export_sha256);
});

test("every published row regenerates from its own evidence", () => {
  const db = buildCompatibilityDatabase({ revision: "sha256:rev1", row: [goodRow] });
  assert.equal(verifyCompatibilityRow(db.row[0], "sha256:rev1").is_regenerable, true);
});

test("an unbacked row is refused", () => {
  const db = buildCompatibilityDatabase({ revision: "sha256:rev1", row: [{ ...goodRow, evidence_sha256: undefined }] });
  assert.equal(db.is_publishable, false);
  assert.match(db.refused[0].reason.join(" "), /missing evidence_sha256|unbacked/);
});

test("a stale row pinned to an older revision is refused", () => {
  const db = buildCompatibilityDatabase({ revision: "sha256:rev2", row: [goodRow] });
  assert.equal(db.is_publishable, false);
  assert.match(db.refused[0].reason.join(" "), /stale/);
});

test("a row carrying personal data is refused", () => {
  const db = buildCompatibilityDatabase({ revision: "sha256:rev1", row: [{ ...goodRow, environment: "user PERSONAL_DATA_MARKER" }] });
  assert.equal(db.is_publishable, false);
  assert.match(db.refused[0].reason.join(" "), /personal data/);
});
