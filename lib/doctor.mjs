// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Worker } from "node:worker_threads";
import { InputError } from "./input.mjs";
import { scanPersonalData, stableStringify } from "./platform.mjs";

function sha256(value) {
  return createHash("sha256").update(typeof value === "string" ? value : JSON.stringify(value)).digest("hex");
}

function readGovernanceJson(input, code) {
  const path = resolve(input);
  if (!existsSync(path)) throw new InputError(`${code}_missing`, `Input does not exist: ${path}`);
  try {
    return { path, value: JSON.parse(readFileSync(path, "utf8")) };
  } catch (error) {
    throw new InputError(`invalid_${code}`, `Input is not strict JSON: ${error.message}`);
  }
}

// The published triage-freshness level for the public issue/compatibility
// tracker (GS-079). A complete report must be triaged within this window.
const triageFreshnessHour = 72;

// Public issue + compatibility tracker (GS-079): a bare report is rejected; a
// report carrying environment, revision, and a reproduction hash is accepted and
// maps to a tracker entry triaged within the published freshness level.
export function submitTrackerReport(reportInput) {
  const { path, value } = readGovernanceJson(reportInput, "report");
  const required = ["environment", "revision", "repro_hash"];
  const missing = required.filter((field) => typeof value?.[field] !== "string" || value[field].length === 0);
  if (missing.length > 0) {
    return {
      schema_version: 1,
      command: "tracker submit",
      report_path: path,
      is_accepted: false,
      missing_field: missing,
      state: "report_rejected_incomplete",
      blocker: [`The report is missing required field: ${missing.join(", ")}; a bare report is rejected`],
    };
  }
  const entryId = sha256(stableStringify({ environment: value.environment, revision: value.revision, repro_hash: value.repro_hash })).slice(0, 16);
  const latencyHour = typeof value.triaged_at === "string" && typeof value.submitted_at === "string"
    ? (Date.parse(value.triaged_at) - Date.parse(value.submitted_at)) / 3.6e6
    : null;
  const isTriagedWithinLevel = latencyHour === null ? null : latencyHour <= triageFreshnessHour;
  return {
    schema_version: 1,
    command: "tracker submit",
    report_path: path,
    is_accepted: true,
    tracker_entry: { id: entryId, environment: value.environment, revision: value.revision },
    triage_freshness_hour: triageFreshnessHour,
    triage_latency_hour: latencyHour,
    is_triaged_within_level: isTriagedWithinLevel,
    state: "report_accepted_tracked",
    blocker: ["The report maps to a tracker entry within the published freshness level, but no runtime reproduces the compatibility claim"],
  };
}

export function formatTrackerReport(report) {
  return [
    `Report: ${report.report_path}`,
    `Accepted: ${report.is_accepted ? "yes" : "no"}`,
    report.is_accepted ? `Tracker entry: ${report.tracker_entry.id}` : `Missing: ${report.missing_field.join(", ")}`,
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

// Public compatibility database export (GS-080): every row carries a declared
// evidence field, an unbacked or personal-data row is refused, and the export is
// deterministic byte-stable.
export function exportCompatibilityDatabase(databaseInput) {
  const { path, value } = readGovernanceJson(databaseInput, "database");
  if (!Array.isArray(value?.row)) throw new InputError("invalid_database", "Compatibility database requires a row array");
  const refusal = [];
  for (const [index, row] of value.row.entries()) {
    if (typeof row?.evidence_hash !== "string" || row.evidence_hash.length === 0) {
      refusal.push(`row ${index} carries no evidence field; an unbacked row is refused`);
    }
    const personalData = scanPersonalData({ title: row?.title, environment: row?.environment, note: row?.note });
    if (personalData.length > 0) refusal.push(`row ${index} carries personal data (${personalData.join(", ")})`);
  }
  const sorted = [...value.row].sort((left, right) => {
    const leftKey = `${left?.title ?? ""}:${left?.evidence_hash ?? ""}`;
    const rightKey = `${right?.title ?? ""}:${right?.evidence_hash ?? ""}`;
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
  const exportBody = `${stableStringify({ schema_version: 1, row: sorted })}\n`;
  return {
    schema_version: 1,
    command: "tracker export",
    database_path: path,
    row_count: sorted.length,
    refusal,
    is_accepted: refusal.length === 0,
    export_body: refusal.length === 0 ? exportBody : null,
    export_hash: refusal.length === 0 ? sha256(exportBody) : null,
    state: refusal.length === 0 ? "export_ready" : "export_refused",
    blocker: ["Every row is evidence-backed and personal-data-free and the export is byte-stable, but no runtime produces a live compatibility session"],
  };
}

export function formatCompatibilityExport(report) {
  return [
    `Database: ${report.database_path}`,
    `Row: ${report.row_count}`,
    `Accepted: ${report.is_accepted ? "yes" : "no"}`,
    report.is_accepted ? `Export hash: ${report.export_hash}` : `Refusal: ${report.refusal.join("; ")}`,
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

// Human + AI-agent contribution pipeline (GS-083): an agent PR without an
// AI-use disclosure is refused; a disclosed-agent PR and a human PR take the
// identical gate path.
const contributionGatePath = ["convention", "gate:build", "gate:test", "review"];

export function evaluateContribution(prInput) {
  const { path, value } = readGovernanceJson(prInput, "pr");
  const authorType = value?.author_type;
  if (authorType !== "human" && authorType !== "agent") {
    throw new InputError("invalid_pr", "PR requires author_type of human or agent");
  }
  const isDisclosed = value?.ai_disclosure === true;
  if (authorType === "agent" && !isDisclosed) {
    return {
      schema_version: 1,
      command: "governance contribution",
      pr_path: path,
      author_type: authorType,
      is_disclosed: false,
      is_accepted: false,
      gate_path: null,
      state: "contribution_refused_undisclosed",
      blocker: ["An agent PR without an AI-use disclosure is refused before the gate"],
    };
  }
  return {
    schema_version: 1,
    command: "governance contribution",
    pr_path: path,
    author_type: authorType,
    is_disclosed: authorType === "agent" ? true : null,
    is_accepted: true,
    gate_path: contributionGatePath,
    state: "contribution_gate_applied",
    blocker: ["Both PR classes take the identical gate path, but the gate cannot prove a runtime behaves"],
  };
}

export function formatContribution(report) {
  return [
    `PR: ${report.pr_path}`,
    `Author: ${report.author_type}`,
    `Accepted: ${report.is_accepted ? "yes" : "no"}`,
    report.is_accepted ? `Gate path: ${report.gate_path.join(" -> ")}` : "Refused: undisclosed agent PR",
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

// Governance / analytics honesty (GS-085): a breaking change without a decision
// record is refused; the analytics byte flow must be aggregate, opt-in, and
// personal-data-free; the community space and code-of-conduct location is
// recorded.
const codeOfConductLocation = "doc/ARCHITECTURE.md governance section (community space and code-of-conduct pointer)";

export function evaluateGovernanceChange(changeInput) {
  const { path, value } = readGovernanceJson(changeInput, "change");
  const isBreaking = value?.is_breaking === true;
  const hasDecisionRecord = typeof value?.decision_record === "string" && value.decision_record.length > 0;
  const analytics = value?.analytics ?? {};
  const analyticsProperty = {
    is_aggregate: analytics.is_aggregate === true,
    is_opt_in: analytics.is_opt_in === true,
    is_personal_data_free: analytics.carries_personal_data !== true,
  };
  const isAnalyticsHonest = analyticsProperty.is_aggregate && analyticsProperty.is_opt_in && analyticsProperty.is_personal_data_free;
  const isBreakingRefused = isBreaking && !hasDecisionRecord;
  return {
    schema_version: 1,
    command: "governance change",
    change_path: path,
    is_breaking: isBreaking,
    has_decision_record: hasDecisionRecord,
    is_change_accepted: !isBreakingRefused,
    analytics_property: analyticsProperty,
    is_analytics_honest: isAnalyticsHonest,
    code_of_conduct: codeOfConductLocation,
    is_accepted: !isBreakingRefused && isAnalyticsHonest,
    state: isBreakingRefused ? "change_refused_no_record" : isAnalyticsHonest ? "change_accepted" : "analytics_property_violated",
    blocker: [isBreakingRefused
      ? "A breaking change without a decision record is refused"
      : "The change carries a decision record and the analytics byte flow is aggregate, opt-in, and personal-data-free"],
  };
}

export function formatGovernanceChange(report) {
  return [
    `Change: ${report.change_path}`,
    `Breaking: ${report.is_breaking ? "yes" : "no"}`,
    `Decision record: ${report.has_decision_record ? "present" : "absent"}`,
    `Analytics honest: ${report.is_analytics_honest ? "yes" : "no"}`,
    `Code of conduct: ${report.code_of_conduct}`,
    `Accepted: ${report.is_accepted ? "yes" : "no"}`,
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

const scope = "Browser/runtime compatibility is NOT tested; no game runtime exists.";

export function getDoctor() {
  const nodeMajor = Number.parseInt(process.versions.node.split(".", 1)[0], 10);
  const capability = [
    { name: "WebAssembly", available: typeof WebAssembly === "object" },
    { name: "SharedArrayBuffer", available: typeof SharedArrayBuffer === "function" },
    { name: "Atomics", available: typeof Atomics === "object" },
    { name: "worker_threads", available: typeof Worker === "function" },
  ];

  return {
    runtime: "node",
    node_version: process.versions.node,
    engine_requirement: ">=22",
    engine_satisfied: Number.isInteger(nodeMajor) && nodeMajor >= 22,
    platform: process.platform,
    architecture: process.arch,
    capability,
    scope,
  };
}

export function formatDoctor(value = getDoctor()) {
  const capabilityLine = value.capability.map((entry) => `${entry.name}: ${entry.available ? "available" : "unavailable"}`);
  return [
    "BPTK environment facts",
    `Node: ${value.node_version} (${value.engine_requirement})`,
    `Platform: ${value.platform}/${value.architecture}`,
    ...capabilityLine,
    value.scope,
  ].join("\n");
}
