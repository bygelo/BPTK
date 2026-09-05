// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { InputError } from "./input.mjs";
import { inspectPath } from "./input.mjs";
import { probeGraphics } from "./graphics.mjs";
import { ensurePackage, readPackageManifest } from "./package.mjs";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function getPackage(packageInput) {
  const packagePath = resolve(packageInput);
  const manifest = readPackageManifest(packagePath);
  if (!manifest) throw new InputError("package_manifest_missing", `Package has no valid bptk.json: ${packagePath}`);
  return { package_path: packagePath, manifest };
}

function writeAtomic(path, value) {
  const temporaryPath = `${path}.partial-${process.pid}`;
  writeFileSync(temporaryPath, `${JSON.stringify(value, null, 2)}\n`);
  renameSync(temporaryPath, path);
}

export function configureThread(project, mode) {
  if (!new Set(["auto", "on", "off"]).has(mode)) throw new InputError("invalid_thread_mode", "Thread mode must be auto, on, or off");
  const packageValue = ensurePackage(project);
  const graphics = probeGraphics();
  const isIsolationAvailable = graphics.capability?.is_cross_origin_isolated === true && graphics.capability?.is_shared_array_buffer_available === true;
  const isThreadSelected = mode === "on" ? isIsolationAvailable : mode === "auto" ? isIsolationAvailable : false;
  const state = mode === "on" && !isIsolationAvailable ? "blocked" : "configured";
  const value = {
    schema_version: 1,
    requested_mode: mode,
    selected_mode: isThreadSelected ? "on" : "off",
    state,
    is_cross_origin_isolated: graphics.capability?.is_cross_origin_isolated === true,
    is_shared_array_buffer_available: graphics.capability?.is_shared_array_buffer_available === true,
    required_header: isThreadSelected ? { opener_policy: "same-origin", embedder_policy: "require-corp" } : null,
    blocker: state === "blocked" ? ["Thread mode on requires cross-origin isolation and SharedArrayBuffer"] : ["No worker-backed game runtime exists; selection configures packaging only"],
  };
  if (state === "configured") writeAtomic(join(packageValue.package_path, "thread.json"), value);
  return { command: "package --thread", package_path: packageValue.package_path, ...value };
}

export function evaluateNetwork(packageInput, mode) {
  if (!new Set(["off", "prompt"]).has(mode)) throw new InputError("invalid_network_mode", "Network mode must be off or prompt");
  const packageValue = getPackage(packageInput);
  const endpoint = Array.isArray(packageValue.manifest.network_endpoint) ? packageValue.manifest.network_endpoint.filter((entry) => typeof entry === "string") : [];
  return {
    schema_version: 1,
    command: "run --network",
    package_id: packageValue.manifest.package_id,
    requested_mode: mode,
    state: mode === "off" ? "denied" : "consent_required",
    endpoint,
    attempt_count: 0,
    allowed_count: 0,
    is_proxy_disclosed: false,
    blocker: mode === "off" ? ["All package network access is denied"] : ["No consent was granted and no runtime network bridge exists"],
  };
}

function loadControlProfile(profile) {
  if (profile === "default") {
    return {
      profile: "default",
      action: [
        { action: "exit", input: "Escape" },
        { action: "fullscreen", input: "KeyF" },
        { action: "primary", input: "Space" },
      ],
      is_touch_enabled: false,
    };
  }
  const profilePath = resolve(profile);
  if (!existsSync(profilePath)) throw new InputError("control_profile_missing", `Control profile does not exist: ${profilePath}`);
  let value;
  try {
    value = JSON.parse(readFileSync(profilePath, "utf8"));
  } catch (error) {
    throw new InputError("invalid_control_profile", `Control profile is not strict JSON: ${error.message}`);
  }
  if (!Array.isArray(value.action) || value.action.some((entry) => typeof entry?.action !== "string" || typeof entry?.input !== "string")) {
    throw new InputError("invalid_control_profile", "Control profile requires an action array with action and input string");
  }
  return { profile: profilePath, action: value.action, is_touch_enabled: value.is_touch_enabled === true };
}

export function evaluateControl(packageInput, profile) {
  const packageValue = getPackage(packageInput);
  const control = loadControlProfile(profile);
  return {
    schema_version: 1,
    command: "run --control",
    package_id: packageValue.manifest.package_id,
    ...control,
    state: "profile_validated_no_runtime",
    blocker: ["The control profile is valid, but no browser game host exists to observe input, focus recovery, fullscreen, touch, or safe exit"],
  };
}

export function evaluateCompatibility(packageInput, browserProfile) {
  const packageValue = getPackage(packageInput);
  const profile = new Set(["chrome", "edge", "firefox", "safari", "mobile"]);
  if (!profile.has(browserProfile)) throw new InputError("invalid_browser_profile", `Unknown browser profile: ${browserProfile}`);
  let observation;
  if (browserProfile === "chrome") {
    observation = probeGraphics();
  } else {
    const installedPath = browserProfile === "safari" && existsSync("/Applications/Safari.app/Contents/MacOS/Safari")
      ? "/Applications/Safari.app/Contents/MacOS/Safari"
      : browserProfile === "firefox" && existsSync("/Applications/Firefox.app/Contents/MacOS/firefox")
        ? "/Applications/Firefox.app/Contents/MacOS/firefox"
        : null;
    observation = { state: "blocked", browser: installedPath ? { path: installedPath, version: "not_automated" } : null, capability: null, selected_path: null, blocker: [installedPath ? "Browser is installed but no bounded live probe is implemented for this profile" : "Browser profile is not installed"] };
  }
  const blocker = [...observation.blocker];
  if (packageValue.manifest.is_game_runtime_included !== true) blocker.push("Package contains no game runtime, so compatibility cannot be supported or degraded");
  return {
    schema_version: 1,
    command: "compatibility --browser",
    package_id: packageValue.manifest.package_id,
    browser_profile: browserProfile,
    state: "blocked",
    observation,
    blocker,
    is_compatibility_claim: false,
  };
}

// Cloud save sync transmits only the save overlay diff: files that are new or
// whose hash differs from the read-only base. A base file, and any overlay file
// whose bytes match the base, is never uploaded.
export function syncCloudSave(baseInput, overlayInput) {
  const packagePath = resolve(baseInput);
  const manifest = readPackageManifest(packagePath);
  if (!manifest) throw new InputError("package_manifest_missing", `Base package has no valid bptk.json: ${packagePath}`);
  const baseHash = new Map((manifest.asset ?? []).map((asset) => [asset.path, asset.sha256]));
  const overlay = inspectPath(overlayInput);
  if (overlay.type !== "directory") throw new InputError("overlay_directory_required", "Cloud save sync requires an overlay directory");
  const transmitted = [];
  const excluded = [];
  for (const entry of overlay.entry.filter((currentEntry) => currentEntry.type === "file")) {
    const hash = sha256(readFileSync(join(overlay.input_path, entry.path)));
    if (baseHash.get(entry.path) === hash) {
      excluded.push({ path: entry.path, reason: "matches_base" });
    } else {
      transmitted.push({ path: entry.path, sha256: hash, reason: baseHash.has(entry.path) ? "changed" : "new" });
    }
  }
  transmitted.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  return {
    schema_version: 1,
    command: "save sync",
    package_id: manifest.package_id,
    base_file_count: baseHash.size,
    transmitted,
    transmitted_count: transmitted.length,
    excluded_count: excluded.length,
    is_base_excluded: transmitted.every((file) => baseHash.get(file.path) !== file.sha256),
    state: "overlay_diff_no_cloud",
    blocker: ["The transmitted set is exactly the overlay diff, but no cloud endpoint receives it"],
  };
}

function loadDeviceOverlay(deviceInput) {
  const devicePath = resolve(deviceInput);
  if (!existsSync(devicePath)) throw new InputError("device_overlay_missing", `Device overlay does not exist: ${devicePath}`);
  let value;
  try {
    value = JSON.parse(readFileSync(devicePath, "utf8"));
  } catch (error) {
    throw new InputError("invalid_device_overlay", `Device overlay is not strict JSON: ${error.message}`);
  }
  if (!Array.isArray(value.file) || value.file.some((entry) => typeof entry?.path !== "string" || typeof entry?.sha256 !== "string" || typeof entry?.clock !== "number")) {
    throw new InputError("invalid_device_overlay", "Device overlay requires a file array with path, sha256, and clock");
  }
  return value.file;
}

// Deterministic conflict resolution: for a path present on both devices with a
// differing hash, the higher logical clock wins; a clock tie breaks on the
// lexicographically greater hash. The result is independent of argument order.
export function resolveSaveConflict(deviceInputA, deviceInputB) {
  const fileA = loadDeviceOverlay(deviceInputA);
  const fileB = loadDeviceOverlay(deviceInputB);
  const byPath = new Map();
  const conflict = [];
  for (const file of [...fileA, ...fileB]) {
    const current = byPath.get(file.path);
    if (!current) { byPath.set(file.path, file); continue; }
    if (current.sha256 === file.sha256) continue;
    const winner = file.clock !== current.clock
      ? (file.clock > current.clock ? file : current)
      : (file.sha256 > current.sha256 ? file : current);
    byPath.set(file.path, winner);
    conflict.push({ path: file.path, winner_sha256: winner.sha256 });
  }
  const resolved = [...byPath.values()].sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  return {
    schema_version: 1,
    command: "save resolve",
    resolved,
    resolved_count: resolved.length,
    conflict,
    conflict_count: conflict.length,
    result_hash: sha256(JSON.stringify(resolved)),
    state: "conflict_resolved_no_cloud",
    blocker: ["Conflict resolution is deterministic, but no cloud endpoint applies the merged overlay"],
  };
}

export function formatCloudSave(report) {
  return [
    `Package ID: ${report.package_id}`,
    `Base file: ${report.base_file_count}`,
    `Transmitted: ${report.transmitted_count}`,
    `Excluded (matches base): ${report.excluded_count}`,
    `State: ${report.state}`,
    ...report.transmitted.map((entry) => `Upload: ${entry.path} (${entry.reason})`),
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

export function formatSaveResolve(report) {
  return [
    `Resolved file: ${report.resolved_count}`,
    `Conflict: ${report.conflict_count}`,
    `Result hash: ${report.result_hash}`,
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

export function formatThread(report) {
  return [
    `Package: ${report.package_path}`,
    `Requested thread mode: ${report.requested_mode}`,
    `Selected thread mode: ${report.selected_mode}`,
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

export function formatNetwork(report) {
  return [
    `Package ID: ${report.package_id}`,
    `Network: ${report.state}`,
    `Allowlisted endpoint: ${report.endpoint.length}`,
    `Attempt count: ${report.attempt_count}`,
    `Allowed count: ${report.allowed_count}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

export function formatControl(report) {
  return [
    `Package ID: ${report.package_id}`,
    `Profile: ${report.profile}`,
    `Action count: ${report.action.length}`,
    `State: ${report.state}`,
    ...report.action.map((entry) => `Action: ${entry.action} <- ${entry.input}`),
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

export function formatCompatibility(report) {
  return [
    `Package ID: ${report.package_id}`,
    `Browser profile: ${report.browser_profile}`,
    `State: ${report.state}`,
    `Observed browser: ${report.observation.browser?.version ?? "none"}`,
    `Observed graphics path: ${report.observation.selected_path ?? "none"}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
    "Compatibility claim: no",
  ].join("\n");
}
