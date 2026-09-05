// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { getStatus } from "./status.mjs";
import { compareCase } from "./conformance.mjs";
import { computeFrameDiff } from "./shader.mjs";
import { compareReplay, computeCompatibilityRating, verifyCompatibilityRow } from "./report.mjs";

// The no-false-green promotion self-audit (GS-042): a battery of sabotage
// fixtures — a wrong return value, an out-of-tolerance frame, an inflated
// rating, a stale provenance row, and a non-deterministic replay — is pushed
// through the real promotion predicates, and the audit is clean only when every
// sabotage is REJECTED. It is the guard that a green is never manufactured. The
// apparatus is generic and driven by synthetic sabotage; the benchmark stays
// red because there is no real passing promotion candidate to guard yet (the
// runtime, BPTK-010, is absent), so the audit has only sabotage to reject,
// never a real green to admit.
export function runPromotionSelfAudit() {
  const check = [];

  // 1. Wrong return: the oracle comparator must not pass a mismatched return.
  const wrongReturn = compareCase({ return_value: 7, last_error: 0 }, { case_id: "SAB-1", expected: { return_value: 42, last_error: 0 } });
  check.push({ sabotage: "wrong_return", is_rejected: wrongReturn.pass === false });

  // 2. Out-of-tolerance frame: a frame past the mean tolerance must not pass.
  const frame = computeFrameDiff([[255, 255, 255]], [[0, 0, 0]], { mean_tolerance: 2.0 });
  check.push({ sabotage: "out_of_tolerance_frame", is_rejected: frame.pass === false });

  // 3. Inflated rating: a passing higher rung above a failed lower rung must
  // not lift the rating (no false green).
  const inflated = computeCompatibilityRating({ predicate: { boots: false, in_game: true, playable: true }, provenance: { in_game: "e", playable: "e" } });
  check.push({ sabotage: "inflated_rating", is_rejected: inflated.rating === "broken" && inflated.is_false_green === false });

  // 4. Stale provenance: a row pinned to an older revision must be refused.
  const staleRow = { title_id: "T", build_hash: "b", environment: "env", browser: "chrome", revision: "sha256:old", evidence_sha256: "a".repeat(64), rating: "boots" };
  const stale = verifyCompatibilityRow(staleRow, "sha256:new");
  check.push({ sabotage: "stale_provenance", is_rejected: stale.is_admitted === false && stale.reason.some((entry) => entry.includes("stale")) });

  // 5. Non-deterministic replay: two divergent replays must not be deterministic.
  const replay = compareReplay(
    { checkpoint: [{ label: "c0", state_sha256: "a".repeat(64) }] },
    { checkpoint: [{ label: "c0", state_sha256: "b".repeat(64) }] },
  );
  check.push({ sabotage: "nondeterministic_replay", is_rejected: replay.is_deterministic === false });

  const rejectedCount = check.filter((entry) => entry.is_rejected).length;
  return {
    schema_version: 1,
    command: "benchmark self-audit",
    check,
    sabotage_count: check.length,
    rejected_count: rejectedCount,
    all_rejected: rejectedCount === check.length,
  };
}

export function formatPromotionSelfAudit(report) {
  return [
    `Promotion self-audit: ${report.rejected_count}/${report.sabotage_count} sabotage rejected`,
    ...report.check.map((entry) => `${entry.is_rejected ? "REJECTED" : "LEAKED"}: ${entry.sabotage}`),
    "A green is never manufactured; every sabotage fixture is rejected by the real predicate.",
  ].join("\n");
}

function digestGeneratedInput() {
  const input = Buffer.alloc(4096);
  for (let index = 0; index < input.length; index += 1) input[index] = (index * 17 + 31) & 0xff;
  return createHash("sha256").update(input).digest("hex");
}

export function runBenchmark() {
  const status = getStatus();
  const startedAt = performance.now();
  let firstDigest;
  let secondDigest;
  for (let index = 0; index < 256; index += 1) firstDigest = digestGeneratedInput();
  for (let index = 0; index < 256; index += 1) secondDigest = digestGeneratedInput();
  const durationMillisecond = performance.now() - startedAt;
  const check = [
    { name: "generated_input_is_deterministic", is_pass: firstDigest === secondDigest },
    { name: "passing_count_is_bounded", is_pass: status.count.passing <= status.count.implemented },
    { name: "source_revision_is_content_addressed", is_pass: status.source.revision === `sha256:${status.source.sha256}` },
  ];
  return {
    schema_version: 1,
    command: "benchmark",
    profile: "tooling_self_check",
    verdict: check.every((entry) => entry.is_pass) ? "pass" : "fail",
    duration_millisecond: Number(durationMillisecond.toFixed(3)),
    iteration_count: 512,
    check,
    roadmap_promotion: false,
    blocker: ["BPTK-001 legal approval is red", "BPTK-002 corpus denominator is red"],
  };
}

export function formatBenchmark(report) {
  return [
    `Profile: ${report.profile}`,
    `Verdict: ${report.verdict}`,
    `Duration: ${report.duration_millisecond} ms for ${report.iteration_count} iteration`,
    ...report.check.map((entry) => `${entry.is_pass ? "PASS" : "FAIL"}: ${entry.name}`),
    ...report.blocker.map((entry) => `Promotion blocked: ${entry}`),
    "Result is live and ephemeral; no retained evidence artifact is written",
  ].join("\n");
}
