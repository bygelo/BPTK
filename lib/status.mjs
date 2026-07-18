// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";

const statusUrl = new URL("../data/status.json", import.meta.url);
const status = JSON.parse(readFileSync(statusUrl, "utf8"));

export function getStatus() {
  return structuredClone(status);
}

export function formatStatus(value = status) {
  return [
    `BPTK ${value.version} roadmap snapshot`,
    `Accepted: ${value.count.accepted}`,
    `Implemented: ${value.count.implemented}`,
    `Passing: ${value.count.passing}`,
    `Source: ${value.source.path}@${value.source.revision.slice(0, 12)}`,
    `Generated: ${value.generated_at}`,
    "No game runtime exists. This snapshot is not compatibility evidence.",
  ].join("\n");
}
