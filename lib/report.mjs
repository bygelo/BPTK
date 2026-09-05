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
