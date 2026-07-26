// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

function getCorpusPath() {
  return resolve(process.env.BPTK_CORPUS_PATH || ".bptk/corpus.json");
}

export function getCorpusStatus() {
  const corpusPath = getCorpusPath();
  if (!existsSync(corpusPath)) {
    return {
      schema_version: 1,
      command: "corpus status",
      corpus_path: corpusPath,
      review_state: "missing",
      entry_count: 0,
      threshold_state: "missing",
      is_publishable: false,
      blocker: ["No local corpus registry exists", "No lawful denominator or numeric threshold is approved"],
    };
  }
  let value;
  try {
    value = JSON.parse(readFileSync(corpusPath, "utf8"));
  } catch (error) {
    throw new Error(`Corpus registry is not strict JSON: ${error.message}`);
  }
  const entry = Array.isArray(value.entry) ? value.entry : [];
  const threshold = value.threshold && typeof value.threshold === "object" ? value.threshold : null;
  const isApproved = value.review_state === "approved" && typeof value.reviewer === "string" && value.reviewer.trim() !== "";
  return {
    schema_version: 1,
    command: "corpus status",
    corpus_path: corpusPath,
    review_state: isApproved ? "approved" : "review_required",
    entry_count: entry.length,
    threshold_state: threshold ? "declared_not_approved" : "missing",
    is_publishable: Boolean(isApproved && threshold && entry.length > 0),
    blocker: isApproved ? [] : ["A named reviewer has not approved the lawful denominator and threshold"],
  };
}

export function formatCorpusStatus(report) {
  return [
    `Corpus: ${report.corpus_path}`,
    `Review: ${report.review_state}`,
    `Entry count: ${report.entry_count}`,
    `Threshold: ${report.threshold_state}`,
    `Publishable: ${report.is_publishable ? "yes" : "no"}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}
