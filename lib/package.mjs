// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { gunzipSync, gzipSync } from "node:zlib";
import { basename, dirname, join, resolve } from "node:path";
import { inspectPath, InputError } from "./input.mjs";

const chunkSizeByte = 1024 * 1024;

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

export function readPackageManifest(packagePath) {
  const manifestPath = join(packagePath, "bptk.json");
  if (!existsSync(manifestPath)) return null;
  try {
    const value = JSON.parse(readFileSync(manifestPath, "utf8"));
    return typeof value.package_id === "string" ? value : null;
  } catch {
    return null;
  }
}

export function packageAsset(project, option = {}) {
  const isCompressed = option.compress === true;
  const source = inspectPath(project);
  if (source.type !== "directory") throw new InputError("project_directory_required", "Stream packaging requires a project directory");
  const outputPath = resolve(dirname(source.input_path), `${basename(source.input_path)}.bptk-package`);
  const stagingPath = `${outputPath}.partial-${process.pid}`;
  if (existsSync(outputPath)) throw new InputError("package_output_exists", `Package output already exists: ${outputPath}`);
  if (existsSync(stagingPath)) rmSync(stagingPath, { recursive: true, force: true });
  mkdirSync(join(stagingPath, "chunk"), { recursive: true });
  const asset = [];
  let plainByteTotal = 0;
  let storedByteTotal = 0;
  try {
    for (const entry of source.entry.filter((currentEntry) => currentEntry.type === "file")) {
      const content = readFileSync(join(source.input_path, entry.path));
      const chunk = [];
      for (let offsetByte = 0; offsetByte < content.length; offsetByte += chunkSizeByte) {
        const currentChunk = content.subarray(offsetByte, Math.min(content.length, offsetByte + chunkSizeByte));
        const chunkHash = digest(currentChunk);
        // Chunk identity stays the uncompressed hash so a compressed and an
        // uncompressed package address the same content; the stored bytes are
        // codec-encoded and separately hashed for integrity before decode.
        const storedByte = isCompressed ? gzipSync(currentChunk, { level: 9 }) : currentChunk;
        const chunkPath = join(stagingPath, "chunk", chunkHash);
        if (!existsSync(chunkPath)) writeFileSync(chunkPath, storedByte);
        plainByteTotal += currentChunk.length;
        storedByteTotal += storedByte.length;
        chunk.push({
          sha256: chunkHash,
          offset_byte: offsetByte,
          size_byte: currentChunk.length,
          stored_sha256: isCompressed ? digest(storedByte) : chunkHash,
          stored_size_byte: storedByte.length,
        });
      }
      asset.push({ path: entry.path, size_byte: content.length, sha256: digest(content), chunk });
    }
    const codec = isCompressed ? "gzip" : "identity";
    const identityInput = JSON.stringify(asset);
    const manifest = {
      schema_version: 1,
      package_kind: "stream_asset",
      package_id: digest(identityInput),
      asset_mode: "stream",
      chunk_codec: codec,
      chunk_size_byte: chunkSizeByte,
      asset,
      is_offline_capable: true,
      is_resumable: true,
      is_game_runtime_included: false,
    };
    writeJson(join(stagingPath, "bptk.json"), manifest);
    renameSync(stagingPath, outputPath);
    return {
      schema_version: 1,
      command: isCompressed ? "package --asset-mode stream-compressed" : "package --asset-mode stream",
      project_path: source.input_path,
      output_path: outputPath,
      package_id: manifest.package_id,
      chunk_codec: codec,
      asset_count: asset.length,
      chunk_count: new Set(asset.flatMap((entry) => entry.chunk.map((currentChunk) => currentChunk.sha256))).size,
      plain_byte_total: plainByteTotal,
      stored_byte_total: storedByteTotal,
      stored_fraction: plainByteTotal === 0 ? 1 : Number((storedByteTotal / plainByteTotal).toFixed(6)),
      state: "packaged_assets",
      blocker: ["The package contains content-addressed assets but no game runtime or browser entry point"],
    };
  } catch (error) {
    rmSync(stagingPath, { recursive: true, force: true });
    throw error;
  }
}

// Stream-verify every stored chunk exactly as a browser loader would: fetch the
// stored (possibly compressed) bytes, verify the codec-stored hash, decode, then
// verify the content-addressed hash. Any mismatch is a hard integrity failure.
export function verifyPackage(packageInput) {
  const packagePath = resolve(packageInput);
  const manifest = readPackageManifest(packagePath);
  if (!manifest) throw new InputError("package_manifest_missing", `Package has no valid bptk.json: ${packagePath}`);
  const codec = manifest.chunk_codec ?? "identity";
  const chunkDirectory = join(packagePath, "chunk");
  const failure = [];
  let verifiedCount = 0;
  let chunkCount = 0;
  let plainByteTotal = 0;
  let storedByteTotal = 0;
  const seen = new Set();
  for (const asset of manifest.asset ?? []) {
    for (const chunk of asset.chunk ?? []) {
      if (seen.has(chunk.sha256)) continue;
      seen.add(chunk.sha256);
      chunkCount += 1;
      const chunkPath = join(chunkDirectory, chunk.sha256);
      if (!existsSync(chunkPath)) { failure.push({ sha256: chunk.sha256, reason: "missing_chunk" }); continue; }
      const storedByte = readFileSync(chunkPath);
      storedByteTotal += storedByte.length;
      if (chunk.stored_sha256 && digest(storedByte) !== chunk.stored_sha256) { failure.push({ sha256: chunk.sha256, reason: "stored_hash_mismatch" }); continue; }
      let plainByte;
      try {
        plainByte = codec === "gzip" ? gunzipSync(storedByte) : storedByte;
      } catch {
        failure.push({ sha256: chunk.sha256, reason: "decode_failed" });
        continue;
      }
      plainByteTotal += plainByte.length;
      if (digest(plainByte) !== chunk.sha256) { failure.push({ sha256: chunk.sha256, reason: "content_hash_mismatch" }); continue; }
      verifiedCount += 1;
    }
  }
  return {
    schema_version: 1,
    command: "package --verify",
    package_path: packagePath,
    package_id: manifest.package_id,
    chunk_codec: codec,
    chunk_count: chunkCount,
    verified_count: verifiedCount,
    is_all_verified: chunkCount > 0 && failure.length === 0,
    plain_byte_total: plainByteTotal,
    stored_byte_total: storedByteTotal,
    stored_fraction: plainByteTotal === 0 ? 1 : Number((storedByteTotal / plainByteTotal).toFixed(6)),
    failure,
    state: failure.length === 0 ? "verified_no_runtime" : "integrity_failure",
    blocker: ["Every chunk is hash-verified, but no browser streaming runtime measures bytes-to-interactive"],
  };
}

export function ensurePackage(project) {
  const projectPath = resolve(project);
  const manifest = readPackageManifest(projectPath);
  if (manifest) return { package_path: projectPath, manifest };
  const output = packageAsset(projectPath);
  return { package_path: output.output_path, manifest: readPackageManifest(output.output_path) };
}

function htmlSource(manifest) {
  return `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BPTK package ${manifest.package_id.slice(0, 12)}</title>
<canvas id="bptk-surface" width="960" height="540" aria-label="BPTK game surface"></canvas>
<output id="bptk-state">asset_ready_no_game_runtime</output>
<script type="module">
const packageId = ${JSON.stringify(manifest.package_id)};
const surface = document.getElementById("bptk-surface");
const state = document.getElementById("bptk-state");
globalThis.bptkHost = Object.freeze({
  package_id: packageId,
  mount() { state.value = "mounted_asset_ready_no_game_runtime"; },
  resize(width, height) { surface.width = width; surface.height = height; },
  unmount() { state.value = "unmounted"; }
});
globalThis.bptkHost.mount();
</script>`;
}

function reactSource(manifest) {
  return `// Generated BPTK React lifecycle adapter. The package owns its canvas and future game loop.
import React, { useEffect, useRef } from "react";

export const packageId = ${JSON.stringify(manifest.package_id)};

export function BptkHost({ source = "../host-html/index.html", on_state }) {
  const frame = useRef(null);
  useEffect(() => {
    on_state?.("mounted_asset_ready_no_game_runtime");
    return () => on_state?.("unmounted");
  }, [on_state]);
  return React.createElement("iframe", {
    ref: frame,
    src: source,
    title: "BPTK package",
    "data-package-id": packageId,
    sandbox: "allow-scripts"
  });
}
`;
}

export function packageHost(project, host) {
  if (!new Set(["html", "react"]).has(host)) throw new InputError("invalid_host", "Host must be html or react");
  const packageValue = ensurePackage(project);
  const hostPath = join(packageValue.package_path, `host-${host}`);
  if (existsSync(hostPath)) throw new InputError("host_output_exists", `Host output already exists: ${hostPath}`);
  mkdirSync(hostPath, { recursive: true });
  const fileName = host === "html" ? "index.html" : "BptkHost.mjs";
  writeFileSync(join(hostPath, fileName), host === "html" ? htmlSource(packageValue.manifest) : reactSource(packageValue.manifest));
  return {
    schema_version: 1,
    command: "package --host",
    host,
    package_path: packageValue.package_path,
    package_id: packageValue.manifest.package_id,
    output_path: hostPath,
    hosting_constraint: {
      cross_origin_embedder_policy: "require-corp",
      cross_origin_opener_policy: "same-origin",
      cross_origin_isolation_expected: true,
      fallback: "the single-thread bundle is selected when isolation is absent, never a broken shared-memory build",
    },
    state: "host_emitted_asset_only",
    blocker: ["The host preserves package identity but no game runtime is included"],
  };
}

export function formatAssetPackage(report) {
  return [
    `Project: ${report.project_path}`,
    `Package: ${report.output_path}`,
    `Package ID: ${report.package_id}`,
    `Asset count: ${report.asset_count}`,
    `Chunk count: ${report.chunk_count}`,
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

export function formatVerifyPackage(report) {
  return [
    `Package: ${report.package_path}`,
    `Package ID: ${report.package_id}`,
    `Chunk codec: ${report.chunk_codec}`,
    `Verified chunk: ${report.verified_count}/${report.chunk_count}`,
    `Stored fraction: ${report.stored_fraction}`,
    `State: ${report.state}`,
    ...report.failure.map((entry) => `Failure: ${entry.sha256} ${entry.reason}`),
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

export function formatHostPackage(report) {
  return [
    `Package: ${report.package_path}`,
    `Package ID: ${report.package_id}`,
    `Host: ${report.host}`,
    `Output: ${report.output_path}`,
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}
