// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { getStatus } from "./status.mjs";

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
