// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The engine lane runtime host (GS-046). Without it the engine lane stays a
// census label with no runnable path. This surface fingerprints the asset's
// engine family, pairs it to the declared open-reimplementation Wasm build for
// that family, and produces a host pairing plan that keeps the user-owned
// asset held SEPARATE from the engine build under an explicit rights boundary:
// no asset is read into a package until rights are attested, and no build is
// embedded, so the terminal state stays blocked and honest. A requested engine
// that contradicts the fingerprint is refused as a mislabel. The family-to-
// build mapping is data — broadening the lane is adding a row, never a branch.

import { inspectInput } from "./inspect.mjs";

// Declared open-reimplementation build per engine family. is_wasm_build_ready
// is the honest state: the reimplementation project exists and is a lawful
// browser target, but no Wasm artifact is embedded in this preview.
const engineBuildCatalog = Object.freeze([
  { family: "id Tech 1", reimplementation: "PrBoom+", license: "GPL-2.0", is_wasm_build_ready: false },
  { family: "Build", reimplementation: "EDuke32", license: "GPL-2.0", is_wasm_build_ready: false },
  { family: "id Tech 2", reimplementation: "QuakeSpasm", license: "GPL-2.0", is_wasm_build_ready: false },
  { family: "SCUMM", reimplementation: "ScummVM", license: "GPL-3.0", is_wasm_build_ready: false },
  { family: "Sierra AGI", reimplementation: "Sarien", license: "GPL-2.0", is_wasm_build_ready: false },
  { family: "Sierra SCI", reimplementation: "ScummVM", license: "GPL-3.0", is_wasm_build_ready: false },
]);

const buildByFamily = new Map(engineBuildCatalog.map((entry) => [entry.family, entry]));
const buildByReimplementation = new Map(engineBuildCatalog.map((entry) => [entry.reimplementation.toLowerCase(), entry]));

// Resolves the requested engine name against the declared catalog, accepting
// either a family name or a reimplementation name so the caller can ask by
// either identity.
function resolveRequestedBuild(engine) {
  const key = (engine ?? "").trim();
  return buildByFamily.get(key) ?? buildByReimplementation.get(key.toLowerCase()) ?? null;
}

export function diagnoseEnginePort(engine, asset) {
  const inspection = inspectInput(asset);
  const family = inspection.census.engine.family;
  const fingerprintBuild = family ? buildByFamily.get(family) ?? null : null;
  const requestedBuild = resolveRequestedBuild(engine);

  const blocker = [];
  let state = "blocked";
  const isFingerprinted = fingerprintBuild !== null;
  // A requested engine that contradicts the fingerprinted family is a mislabel
  // and is refused before any pairing is offered.
  const isMislabel = isFingerprinted && requestedBuild !== null && requestedBuild.reimplementation !== fingerprintBuild.reimplementation;
  if (isMislabel) {
    state = "refused";
    blocker.push(`Requested engine ${engine} contradicts the ${fingerprintBuild.family} fingerprint; the mislabel is refused`);
  }
  if (!isFingerprinted) {
    blocker.push("No engine family was fingerprinted in the asset, so no open reimplementation pairs with it");
  }
  if (isFingerprinted && !fingerprintBuild.is_wasm_build_ready) {
    blocker.push(`No embedded Wasm build of ${fingerprintBuild.reimplementation} exists yet, so the paired engine cannot host the asset`);
  }
  // The rights boundary: the user asset is never read into a package until the
  // caller attests rights, which this preview never grants.
  blocker.push("The user must attest rights before any asset is read into the engine build package");

  const pairing = isFingerprinted && !isMislabel
    ? {
        engine_family: fingerprintBuild.family,
        reimplementation: fingerprintBuild.reimplementation,
        reimplementation_license: fingerprintBuild.license,
        is_wasm_build_ready: fingerprintBuild.is_wasm_build_ready,
        asset_root: inspection.input_path,
        is_asset_held_separate: true,
      }
    : null;

  return {
    schema_version: 1,
    command: "port --engine",
    requested_engine: engine,
    asset_path: inspection.input_path,
    asset_classification: inspection.classification,
    fingerprint_family: family,
    supported_engine: engineBuildCatalog.map((entry) => entry.reimplementation),
    pairing,
    state,
    is_mislabel: isMislabel,
    is_right_attested: false,
    is_asset_copied: false,
    is_executed: false,
    blocker,
  };
}

export function formatEnginePort(report) {
  return [
    `Engine: ${report.requested_engine}`,
    `Asset: ${report.asset_path}`,
    `Classification: ${report.asset_classification}`,
    `Fingerprint: ${report.fingerprint_family ?? "none"}`,
    `State: ${report.state}`,
    ...(report.pairing
      ? [`Pairing: ${report.pairing.engine_family} → ${report.pairing.reimplementation} (${report.pairing.reimplementation_license}); asset held separate`]
      : []),
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
    "Asset copied: no",
  ].join("\n");
}
