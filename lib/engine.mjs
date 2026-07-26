// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { inspectInput } from "./inspect.mjs";

export function diagnoseEnginePort(engine, asset) {
  const inspection = inspectInput(asset);
  return {
    schema_version: 1,
    command: "port --engine",
    requested_engine: engine,
    asset_path: inspection.input_path,
    asset_classification: inspection.classification,
    supported_engine: [],
    state: "blocked",
    is_right_attested: false,
    is_asset_copied: false,
    blocker: [
      "No engine-family adapter has been approved or implemented",
      "The user must attest rights before any asset is read into an adapter package",
      "No generic runtime package exists for save, mod, input, or network behavior",
    ],
  };
}

export function formatEnginePort(report) {
  return [
    `Engine: ${report.requested_engine}`,
    `Asset: ${report.asset_path}`,
    `Classification: ${report.asset_classification}`,
    `State: ${report.state}`,
    `Supported engine count: ${report.supported_engine.length}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
    "Asset copied: no",
  ].join("\n");
}
