// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { inspectPath } from "./input.mjs";

const licensePattern = /(^|\/)(license|licence|copying|notice)(\.[^/]*)?$/i;

function readPackageLicense(value) {
  const packageEntry = value.entry.find((entry) => entry.type === "file" && entry.path.toLowerCase() === "package.json");
  if (!packageEntry) return null;
  try {
    const packageValue = JSON.parse(readFileSync(resolve(value.input_path, packageEntry.path), "utf8"));
    return typeof packageValue.license === "string" ? packageValue.license : null;
  } catch {
    return null;
  }
}

export function analyzeLegal(input) {
  const value = inspectPath(input);
  const license = value.type === "directory"
    ? value.entry.filter((entry) => entry.type === "file" && licensePattern.test(entry.path)).map((entry) => entry.path)
    : licensePattern.test(value.input_name) ? [basename(value.input_path)] : [];
  const declaredLicense = value.type === "directory" ? readPackageLicense(value) : null;
  return {
    schema_version: 1,
    command: "legal",
    project_path: value.input_path,
    decision: "review_required",
    declared_license: declaredLicense,
    license,
    provenance_state: license.length > 0 || declaredLicense ? "declared_not_approved" : "missing",
    requirement: [
      "Confirm the contributor has the right to provide every source and asset",
      "Review every incorporated component and distribution obligation",
      "Keep user-owned game content outside BPTK distribution",
      "Obtain public-name and trade-dress review before launch",
    ],
    reviewer: { legal: null, product_name: null },
    is_approved: false,
  };
}

export function formatLegal(report) {
  return [
    `Project: ${report.project_path}`,
    `Decision: ${report.decision}`,
    `Provenance: ${report.provenance_state}`,
    `Declared license: ${report.declared_license ?? "none"}`,
    ...report.license.map((entry) => `License file: ${entry}`),
    ...report.requirement.map((entry) => `Required: ${entry}`),
    "Approval: open; no legal or naming reviewer is recorded",
  ].join("\n");
}
