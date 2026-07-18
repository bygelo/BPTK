#!/usr/bin/env node
// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifestRelative = "bench/roadmap/manifest.json";
const manifestPath = resolve(root, manifestRelative);
const packagePath = resolve(root, "package.json");
const statusPath = resolve(root, "data/status.json");

function readGit(format) {
  return execFileSync("git", ["log", "-1", `--format=${format}`, "--", manifestRelative], {
    cwd: root,
    encoding: "utf8",
  }).trim();
}

export function createStatus() {
  const manifestBuffer = readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBuffer.toString("utf8"));
  const packageValue = JSON.parse(readFileSync(packagePath, "utf8"));
  const committedAt = readGit("%aI");

  return {
    schema_version: 1,
    package: packageValue.name,
    version: packageValue.version,
    snapshot: true,
    generated_at: committedAt.slice(0, 10),
    source: {
      path: manifestRelative,
      revision: readGit("%H"),
      committed_at: committedAt,
      sha256: createHash("sha256").update(manifestBuffer).digest("hex"),
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
