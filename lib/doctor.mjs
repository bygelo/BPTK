// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { Worker } from "node:worker_threads";

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
