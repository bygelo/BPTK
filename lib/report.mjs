// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { InputError } from "./input.mjs";

function loadPackage(packagePath) {
  const resolvedPath = resolve(packagePath);
  if (!existsSync(resolvedPath)) throw new InputError("not_found", `Package does not exist: ${resolvedPath}`);
  const manifestPath = join(resolvedPath, "bptk.json");
  if (!existsSync(manifestPath)) throw new InputError("package_manifest_missing", `Package has no bptk.json: ${resolvedPath}`);
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (error) {
    throw new InputError("invalid_package_manifest", `bptk.json is not strict JSON: ${error.message}`);
  }
  if (typeof manifest.package_id !== "string") throw new InputError("invalid_package_manifest", "bptk.json has no package_id");
  return { package_path: resolvedPath, manifest };
}

export function createReport(packagePath, record) {
  if (!new Set(["off", "consent"]).has(record)) throw new InputError("invalid_record_mode", "Record mode must be off or consent");
  const packageValue = loadPackage(packagePath);
  const report = {
    schema_version: 1,
    package_id: packageValue.manifest.package_id,
    package_kind: packageValue.manifest.package_kind ?? "unknown",
    toolkit_version: "0.1.0-alpha.0",
    environment: { runtime: "node", node_version: process.versions.node, platform: process.platform, architecture: process.arch },
    compatibility_state: "classified",
    evidence_state: "local_unretained",
    is_game_content_included: false,
    is_personal_data_included: false,
    blocker: ["No game runtime session exists to reproduce"],
  };
  let outputPath = null;
  if (record === "consent") {
    const reportPath = join(packageValue.package_path, "report");
    mkdirSync(reportPath, { recursive: true });
    const reportHash = createHash("sha256").update(JSON.stringify(report)).digest("hex");
    outputPath = join(reportPath, `${reportHash.slice(0, 16)}.json`);
    writeFileSync(outputPath, `${JSON.stringify({ ...report, evidence_state: "local_retained_with_consent" }, null, 2)}\n`);
  }
  return {
    command: "report --record",
    record_mode: record,
    output_path: outputPath,
    report,
  };
}

// The compatibility rating ladder (GS-038): a title climbs broken → boots →
// in-game → playable → complete, and each rung is granted only when its own
// predicate passes AND every lower rung already passed, so a rating can never
// sit above the highest contiguously-passing rung. Each granted rung must also
// cite provenance (the evidence that backs it); a rung whose predicate passes
// but carries no evidence is not granted, because an unbacked rating is a
// false-green claim. The engine is generic; the benchmark stays red because the
// real predicates read a live runtime session (BPTK-010) that does not exist,
// so every real predicate fails and the honest rating is "broken".
const RATING_LADDER = Object.freeze(["broken", "boots", "in_game", "playable", "complete"]);

export function computeCompatibilityRating(rung) {
  const predicate = rung?.predicate ?? {};
  const provenance = rung?.provenance ?? {};
  const granted = [];
  let rating = "broken";
  let stopReason = null;
  // "broken" is the floor and needs no predicate; every rung above it must pass
  // its own predicate and carry backing evidence, in ladder order.
  for (let index = 1; index < RATING_LADDER.length; index += 1) {
    const name = RATING_LADDER[index];
    if (predicate[name] !== true) {
      stopReason = `predicate for ${name} did not pass`;
      break;
    }
    const evidence = provenance[name];
    if (typeof evidence !== "string" || evidence.trim() === "") {
      stopReason = `rung ${name} passed its predicate but carries no backing evidence, so it is not granted`;
      break;
    }
    granted.push({ rung: name, evidence });
    rating = name;
  }
  // A predicate that passes above a broken lower rung is ignored — the highest
  // CONTIGUOUS passing rung is the ceiling, never the highest passing rung.
  const highestPassing = RATING_LADDER.reduce((best, name, index) => (index > 0 && predicate[name] === true ? index : best), 0);
  const ratingIndex = RATING_LADDER.indexOf(rating);
  return {
    schema_version: 1,
    command: "compatibility rating",
    rating,
    rating_index: ratingIndex,
    granted_rung: granted,
    highest_passing_index: highestPassing,
    is_false_green: ratingIndex > highestPassing,
    is_provenance_backed: granted.every((entry) => typeof entry.evidence === "string" && entry.evidence.trim() !== ""),
    stop_reason: stopReason,
  };
}

export function formatCompatibilityRating(report) {
  return [
    `Compatibility rating: ${report.rating}`,
    `Granted: ${report.granted_rung.map((entry) => entry.rung).join(" → ") || "broken"}`,
    ...(report.stop_reason ? [`Stopped: ${report.stop_reason}`] : []),
    `False green: ${report.is_false_green ? "yes" : "no"}`,
    "A rating never exceeds the highest contiguously-passing, evidence-backed rung.",
  ].join("\n");
}

// The deterministic reference/replay artifact (GS-039): a recorded run is
// captured as an ordered list of checkpoints, each reduced to a state hash — no
// raw asset byte and no personal data ever enter the artifact, only hashes and
// metadata. Two replays of the same run are deterministic when their checkpoint
// hashes match pairwise at every checkpoint; the first divergence is the defect.
// The engine is generic; the benchmark stays red because the real checkpoints
// come from a live runtime session (BPTK-010) that does not exist, so no real
// artifact can be recorded.
const REPLAY_FORBIDDEN = Object.freeze([
  { code: "email", regex: /[\w.+-]+@[\w-]+\.[\w.-]+/ },
  { code: "personal_data", regex: /PERSONAL_DATA_MARKER/ },
  { code: "embedded_asset", regex: /ASSET_PAYLOAD_BYTE/ },
]);

// A checkpoint carries a label and a 64-hex state hash. A raw byte blob field is
// itself a defect: the artifact must reference state by hash, never embed it.
function hashCheckpoint(checkpoint) {
  return {
    label: checkpoint.label,
    state_sha256: createHash("sha256").update(canonicalReplay(checkpoint.state ?? null)).digest("hex"),
  };
}

function canonicalReplay(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalReplay).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalReplay(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

export function buildReplayArtifact(run) {
  const checkpoint = Array.isArray(run?.checkpoint) ? run.checkpoint : [];
  if (checkpoint.length === 0) throw new InputError("replay_checkpoint_required", "A replay artifact requires at least one checkpoint");
  const reduced = checkpoint.map(hashCheckpoint);
  const artifact = {
    schema_version: 1,
    title_id: typeof run.title_id === "string" ? run.title_id : null,
    revision: typeof run.revision === "string" ? run.revision : null,
    checkpoint: reduced,
  };
  const canonical = canonicalReplay(artifact);
  return { ...artifact, artifact_sha256: createHash("sha256").update(canonical).digest("hex") };
}

// Rejects an artifact that embeds an asset byte or personal data, that carries a
// raw state blob instead of a hash, or that has no stable title identity.
export function verifyReplayArtifact(artifact) {
  const reason = [];
  const canonical = canonicalReplay(artifact ?? null);
  for (const pattern of REPLAY_FORBIDDEN) if (pattern.regex.test(canonical)) reason.push(`embedded ${pattern.code}`);
  for (const checkpoint of artifact?.checkpoint ?? []) {
    if (typeof checkpoint.state_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(checkpoint.state_sha256)) {
      reason.push(`checkpoint ${checkpoint.label ?? "?"} is not reduced to a state hash`);
    }
    if ("state" in checkpoint) reason.push(`checkpoint ${checkpoint.label ?? "?"} embeds raw state rather than a hash`);
  }
  if (typeof artifact?.title_id !== "string" || artifact.title_id.trim() === "") reason.push("artifact has no title identity");
  return { is_clean: reason.length === 0, reason };
}

// Compares two replays checkpoint by checkpoint; the verdict is deterministic
// only when every checkpoint hash matches and the checkpoint counts agree.
export function compareReplay(first, second) {
  const a = first?.checkpoint ?? [];
  const b = second?.checkpoint ?? [];
  const divergence = [];
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const left = a[index];
    const right = b[index];
    if (!left || !right || left.state_sha256 !== right.state_sha256 || left.label !== right.label) {
      divergence.push({ index, first: left?.label ?? null, second: right?.label ?? null });
    }
  }
  return {
    schema_version: 1,
    command: "replay compare",
    checkpoint_count: length,
    is_deterministic: divergence.length === 0 && a.length === b.length,
    first_divergence: divergence[0] ?? null,
    divergence_count: divergence.length,
  };
}

export function formatReplay(report) {
  return [
    `Replay checkpoints: ${report.checkpoint_count}`,
    `Deterministic: ${report.is_deterministic ? "yes" : "no"}`,
    ...(report.first_divergence ? [`First divergence at checkpoint ${report.first_divergence.index}`] : []),
  ].join("\n");
}

export function formatReport(value) {
  return [
    `Package ID: ${value.report.package_id}`,
    `Compatibility: ${value.report.compatibility_state}`,
    `Evidence: ${value.output_path ? "local_retained_with_consent" : value.report.evidence_state}`,
    `Game content included: ${value.report.is_game_content_included ? "yes" : "no"}`,
    `Personal data included: ${value.report.is_personal_data_included ? "yes" : "no"}`,
    `Output: ${value.output_path ?? "none"}`,
    ...value.report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}
