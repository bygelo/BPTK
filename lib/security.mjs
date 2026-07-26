// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { inspectPath } from "./input.mjs";

function archivePathRisk(prefix) {
  const text = prefix.toString("latin1");
  return /(^|[\\/])\.\.([\\/]|$)/.test(text) ? ["Archive byte stream contains a parent-path marker"] : [];
}

export function analyzeSecurity(input) {
  const value = inspectPath(input);
  const risk = [];
  const control = [
    "Input is read locally with bounded file, entry, and depth limits",
    "Symbolic-link roots are rejected and nested symbolic links are not followed",
    "Imported content is never executed or uploaded by this command",
    "Network remains denied until an explicit mediated policy exists",
  ];
  if (value.type === "directory") {
    const symlinkCount = value.entry.filter((entry) => entry.type === "symlink").length;
    if (symlinkCount > 0) risk.push(`${symlinkCount} nested symbolic link requires exclusion from packaging`);
  } else {
    if (value.prefix[0] === 0x4d && value.prefix[1] === 0x5a) risk.push("Executable content must remain inert during inspection");
    if (value.prefix.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) risk.push(...archivePathRisk(value.prefix));
  }
  return {
    schema_version: 1,
    command: "security",
    input_path: value.input_path,
    review_state: "review_required",
    risk,
    control,
    limit: { entry_count: 4096, depth_count: 8, file_size_byte: 67108864 },
    reviewer: null,
    is_approved: false,
  };
}

export function formatSecurity(report) {
  return [
    `Input: ${report.input_path}`,
    `Review: ${report.review_state}`,
    ...report.risk.map((entry) => `Risk: ${entry}`),
    ...report.control.map((entry) => `Control: ${entry}`),
    `Limit: ${report.limit.entry_count} entry; depth ${report.limit.depth_count}; ${report.limit.file_size_byte} byte per file`,
    "Approval: open; no named security reviewer is recorded",
  ].join("\n");
}
