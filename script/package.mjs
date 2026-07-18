#!/usr/bin/env node
// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const contentPath = resolve(root, "bench/npm/content.json");
const content = JSON.parse(readFileSync(contentPath, "utf8"));
const pack = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
  cwd: root,
  encoding: "utf8",
});

if (pack.status !== 0) {
  process.stderr.write(pack.stderr || "npm pack --dry-run failed\n");
  process.exitCode = pack.status ?? 1;
} else {
  const report = JSON.parse(pack.stdout);
  const artifact = report[0];
  const actualFile = artifact.files.map((entry) => entry.path).sort();
  const expectedFile = [...content.file].sort();

  if (artifact.name !== content.package || artifact.version !== content.version) {
    process.stderr.write(
      `package identity differs: ${artifact.name}@${artifact.version}, expected ${content.package}@${content.version}\n`,
    );
    process.exitCode = 1;
  } else if (JSON.stringify(actualFile) !== JSON.stringify(expectedFile)) {
    process.stderr.write("package content differs from bench/npm/content.json\n");
    process.stderr.write(`actual:   ${JSON.stringify(actualFile)}\n`);
    process.stderr.write(`expected: ${JSON.stringify(expectedFile)}\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`PASS package content: ${artifact.name}@${artifact.version}; ${actualFile.length} file.\n`);
  }
}
