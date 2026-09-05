// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { diagnoseEnginePort, formatEnginePort } from "../lib/engine.mjs";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

function makeAssetDir(context, file) {
  const root = mkdtempSync(join(tmpdir(), "bptk-engine-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const dir = join(root, "asset");
  mkdirSync(dir, { recursive: true });
  for (const [name, content] of Object.entries(file)) writeFileSync(join(dir, name), content);
  return dir;
}

test("the engine host pairs a fingerprinted asset to its open reimplementation while holding the asset separate", (context) => {
  const asset = makeAssetDir(context, { "doom.wad": "IWAD payload" });
  const report = diagnoseEnginePort("PrBoom+", asset);
  assert.equal(report.fingerprint_family, "id Tech 1");
  assert.ok(report.pairing);
  assert.equal(report.pairing.reimplementation, "PrBoom+");
  assert.equal(report.pairing.is_asset_held_separate, true);
  assert.equal(report.is_asset_copied, false);
  assert.equal(report.is_mislabel, false);
});

test("the engine host refuses a requested engine that contradicts the fingerprint", (context) => {
  const asset = makeAssetDir(context, { "doom.wad": "IWAD payload" });
  const report = diagnoseEnginePort("EDuke32", asset);
  assert.equal(report.is_mislabel, true);
  assert.equal(report.state, "refused");
  assert.equal(report.pairing, null);
  assert.ok(report.blocker.some((line) => line.includes("mislabel")));
});

test("the engine host stays blocked until a Wasm build is embedded and rights are attested", (context) => {
  // Implemented-but-red (BPTK-091): the census label now has a runnable-path
  // pairing plan, but no Wasm engine build is embedded and no rights are
  // attested, so the host never reads the asset or runs anything.
  const asset = makeAssetDir(context, { "monkey.000": "SCUMM", "monkey.001": "SCUMM", "monkey.he0": "SCUMM heap" });
  const report = diagnoseEnginePort("ScummVM", asset);
  assert.equal(report.state, "blocked");
  assert.equal(report.is_right_attested, false);
  assert.equal(report.is_asset_copied, false);
  assert.equal(report.is_executed, false);
  assert.ok(report.blocker.some((line) => line.includes("attest rights")));
  assert.ok(report.blocker.some((line) => line.includes("Wasm build")));
  assert.match(formatEnginePort(report), /Pairing:/);
});

test("an asset with no engine fingerprint pairs with nothing", (context) => {
  const asset = makeAssetDir(context, { "readme.txt": "no engine here" });
  const report = diagnoseEnginePort("PrBoom+", asset);
  assert.equal(report.fingerprint_family, null);
  assert.equal(report.pairing, null);
  assert.ok(report.blocker.some((line) => line.includes("No engine family")));
});

test("the engine host is reachable at the real CLI and never copies the asset", (context) => {
  const asset = makeAssetDir(context, { "doom.wad": "IWAD payload" });
  const result = spawnSync(process.execPath, [binPath, "port", "--engine", "PrBoom+", asset, "--json"], { encoding: "utf8" });
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.is_asset_copied, false);
  assert.equal(report.pairing.reimplementation, "PrBoom+");
});
