#!/usr/bin/env node
// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifestRelative = "bench/roadmap/manifest.json";
const manifestPath = resolve(root, manifestRelative);
const packagePath = resolve(root, "package.json");
const statusPath = resolve(root, "data/status.json");

export function createStatus() {
  const manifestBuffer = readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBuffer.toString("utf8"));
  const packageValue = JSON.parse(readFileSync(packagePath, "utf8"));
  const sourceHash = createHash("sha256").update(manifestBuffer).digest("hex");

  return {
    schema_version: 1,
    package: packageValue.name,
    version: packageValue.version,
    snapshot: true,
    generated_at: manifest.checked_at,
    source: {
      path: manifestRelative,
      revision: `sha256:${sourceHash}`,
      committed_at: null,
      sha256: sourceHash,
    },
    count: manifest.count,
  };
}

const expected = `${JSON.stringify(createStatus(), null, 2)}\n`;
const isCheck = process.argv.slice(2).includes("--check");

if (isCheck) {
  const actual = readFileSync(statusPath, "utf8");
  if (actual !== expected) {
    process.stderr.write("data/status.json differs from its deterministic roadmap source\n");
    process.exitCode = 1;
  }
} else {
  writeFileSync(statusPath, expected);
}
