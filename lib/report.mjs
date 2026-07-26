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
