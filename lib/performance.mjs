// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { InputError } from "./input.mjs";
import { readPackageManifest } from "./package.mjs";

function verifyPackage(packagePath, manifest) {
  const chunkHash = new Set(manifest.asset.flatMap((entry) => entry.chunk.map((currentChunk) => currentChunk.sha256)));
  let byteCount = 0;
  for (const hash of chunkHash) {
    const chunkPath = join(packagePath, "chunk", hash);
    if (!existsSync(chunkPath)) throw new InputError("package_chunk_missing", `Package chunk is missing: ${hash}`);
    const content = readFileSync(chunkPath);
    if (createHash("sha256").update(content).digest("hex") !== hash) throw new InputError("package_chunk_corrupt", `Package chunk hash differs: ${hash}`);
    byteCount += content.length;
  }
  return { byte_count: byteCount, chunk_count: chunkHash.size };
}

export function benchmarkPerformance(packageInput) {
  const packagePath = resolve(packageInput);
  const manifest = readPackageManifest(packagePath);
  if (!manifest || manifest.package_kind !== "stream_asset" || !Array.isArray(manifest.asset)) throw new InputError("stream_package_required", "Performance profile requires a stream-asset package");
  const memoryBeforeByte = process.memoryUsage().rss;
  const coldStartedAt = performance.now();
  const cold = verifyPackage(packagePath, manifest);
  const coldMillisecond = performance.now() - coldStartedAt;
  const warmStartedAt = performance.now();
  const warm = verifyPackage(packagePath, manifest);
  const warmMillisecond = performance.now() - warmStartedAt;
  return {
    schema_version: 1,
    command: "benchmark --profile performance",
    package_id: manifest.package_id,
    profile: "package_integrity_only",
    cold_read_millisecond: Number(coldMillisecond.toFixed(3)),
    warm_read_millisecond: Number(warmMillisecond.toFixed(3)),
    byte_count: cold.byte_count,
    chunk_count: cold.chunk_count,
    memory_delta_byte: Math.max(0, process.memoryUsage().rss - memoryBeforeByte),
    is_integrity_verified: cold.byte_count === warm.byte_count && cold.chunk_count === warm.chunk_count,
    blocker: ["Startup, frame, audio, guest CPU, and game-runtime memory cannot be measured because no game runtime exists"],
  };
}

export function formatPerformance(report) {
  return [
    `Package ID: ${report.package_id}`,
    `Profile: ${report.profile}`,
    `Cold read: ${report.cold_read_millisecond} ms`,
    `Warm read: ${report.warm_read_millisecond} ms`,
    `Verified: ${report.byte_count} byte across ${report.chunk_count} chunk`,
    `Memory delta: ${report.memory_delta_byte} byte`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}
