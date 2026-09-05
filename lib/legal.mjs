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

// The license, reuse, and provenance graph (GS-084): every component of a
// project resolves to a license family and a disposition from one frozen
// decision table, and publish, host, or bundle is refused on an unlicensed,
// unknown, or expired node. The table is the law; an unknown family is a
// refusal, not a guess.
const licenseDisposition = Object.freeze({
  "Apache-2.0": "distribute",
  "MIT": "distribute",
  "ISC": "distribute",
  "0BSD": "distribute",
  "BSD-2-Clause": "distribute",
  "BSD-3-Clause": "distribute",
  "Zlib": "distribute",
  "CC0-1.0": "distribute",
  "LGPL-2.1-or-later": "link_dynamic_only",
  "LGPL-3.0-or-later": "link_dynamic_only",
  "MPL-2.0": "link_file_only",
  "GPL-2.0-or-later": "distribute_copyleft",
  "GPL-3.0-or-later": "distribute_copyleft",
  "Freeware": "distribute_unmodified",
});

export function resolveLicenseGraph(value) {
  const component = [];
  const refusal = [];
  const declaredLicense = value.type === "directory" ? readPackageLicense(value) : null;
  let grantExpiry = null;
  if (value.type === "directory") {
    const packageEntry = value.entry.find((entry) => entry.type === "file" && entry.path.toLowerCase() === "package.json");
    if (packageEntry) {
      try {
        const packageValue = JSON.parse(readFileSync(resolve(value.input_path, packageEntry.path), "utf8"));
        if (typeof packageValue.grant_expiry === "string") grantExpiry = packageValue.grant_expiry;
      } catch {
        // A malformed package manifest is an inspection concern, not a license one.
      }
    }
  }
  if (declaredLicense) {
    const disposition = licenseDisposition[declaredLicense];
    if (disposition === undefined) {
      refusal.push(`unknown license family ${declaredLicense}; the decision table has no disposition for it`);
    } else {
      component.push({ name: "the project declaration", license: declaredLicense, disposition, is_expired: false });
    }
  } else if (value.type === "directory" && value.entry.some((entry) => entry.type === "file" && licensePattern.test(entry.path))) {
    component.push({ name: "license file evidence", license: "declared by file without a machine-readable family", disposition: "review_required", is_expired: false });
  } else {
    refusal.push("the project carries no license declaration or license file; publication is refused");
  }
  if (grantExpiry !== null && Number.isNaN(Date.parse(grantExpiry))) {
    refusal.push(`the redistribution grant expiry ${grantExpiry} is not an ISO date`);
  } else if (grantExpiry !== null && Date.parse(grantExpiry) < Date.now()) {
    refusal.push(`the redistribution grant expired ${grantExpiry}; publication is refused until a fresh grant is recorded`);
  }
  return { component, refusal, grant_expiry: grantExpiry };
}

export function analyzeLegal(input) {
  const value = inspectPath(input);
  const license = value.type === "directory"
    ? value.entry.filter((entry) => entry.type === "file" && licensePattern.test(entry.path)).map((entry) => entry.path)
    : licensePattern.test(value.input_name) ? [basename(value.input_path)] : [];
  const declaredLicense = value.type === "directory" ? readPackageLicense(value) : null;
  const graph = resolveLicenseGraph(value);
  return {
    graph,
    decision: graph.refusal.length > 0 ? "refused_unresolved_graph" : "review_required",
    schema_version: 1,
    command: "legal",
    project_path: value.input_path,
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
    ...report.graph.component.map((entry) => `Component: ${entry.name} — ${entry.license} → ${entry.disposition}`),
    ...report.graph.refusal.map((entry) => `Graph refusal: ${entry}`),
    ...report.requirement.map((entry) => `Required: ${entry}`),
    "Approval: open; no legal or naming reviewer is recorded",
  ].join("\n");
}
