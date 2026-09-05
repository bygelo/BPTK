// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { InputError } from "./input.mjs";
import { inspectPath } from "./input.mjs";
import { probeGraphics } from "./graphics.mjs";
import { resolveLicenseGraph } from "./legal.mjs";
import { ensurePackage, readPackageManifest } from "./package.mjs";
import { assertImportSafety, inspectWithThreat } from "./security.mjs";
import { modOverlayByteDefault } from "./bound.mjs";
import { cpSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const moduleRoot = resolve(fileURLToPath(import.meta.url), "..", "..");

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

// Personal-data guard shared by every publish/export/submission surface. A hit
// is a refusal, never a redaction guess: the catalog names its own coverage.
const piiPattern = Object.freeze([
  { name: "email", pattern: /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i },
  { name: "phone", pattern: /(?:\+?\d[\d ().-]{7,}\d)/ },
  { name: "us_ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
]);

export function scanPersonalData(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  const hit = [];
  for (const entry of piiPattern) {
    if (entry.pattern.test(text)) hit.push(entry.name);
  }
  return hit;
}

// Deterministic key-sorted serialization so an export is byte-stable across runs.
export function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
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

// The frozen catalog metadata schema (GS-068). Every field is required and
// typed; an entry that misses a field or carries an unknown enum value fails
// validation. Instant-play is gated: only an approved-redistribution entry with
// a passing capability record is eligible, and a no-rights entry is
// bring-your-own only. The schema is the law — it never grows to admit a bad row.
const catalogRedistribution = new Set(["approved", "none"]);
const catalogCapability = new Set(["passing", "failing", "unknown"]);

function validateCatalogEntry(entry) {
  const failure = [];
  if (typeof entry?.title !== "string" || entry.title.length === 0) failure.push("title must be a non-empty string");
  if (typeof entry?.build_hash !== "string" || !/^[0-9a-f]{64}$/.test(entry.build_hash)) failure.push("build_hash must be a sha256 hex string");
  if (typeof entry?.license !== "string" || entry.license.length === 0) failure.push("license must be a non-empty string");
  if (!catalogRedistribution.has(entry?.redistribution)) failure.push("redistribution must be approved or none");
  if (!catalogCapability.has(entry?.capability)) failure.push("capability must be passing, failing, or unknown");
  return failure;
}

export function validateCatalog(catalogInput) {
  const catalogPath = resolve(catalogInput);
  if (!existsSync(catalogPath)) throw new InputError("catalog_missing", `Catalog does not exist: ${catalogPath}`);
  let value;
  try {
    value = JSON.parse(readFileSync(catalogPath, "utf8"));
  } catch (error) {
    throw new InputError("invalid_catalog", `Catalog is not strict JSON: ${error.message}`);
  }
  if (!Array.isArray(value.entry)) throw new InputError("invalid_catalog", "Catalog requires an entry array");
  const entry = value.entry.map((current) => {
    const failure = validateCatalogEntry(current);
    const isValid = failure.length === 0;
    const isInstantPlay = isValid && current.redistribution === "approved" && current.capability === "passing";
    const isByoOnly = isValid && current.redistribution === "none";
    return {
      title: typeof current?.title === "string" ? current.title : null,
      build_hash: typeof current?.build_hash === "string" ? current.build_hash : null,
      is_valid: isValid,
      access: !isValid ? "rejected" : isInstantPlay ? "instant_play_eligible" : isByoOnly ? "bring_your_own_only" : "hosted_no_capability",
      failure,
    };
  });
  return {
    schema_version: 1,
    command: "library catalog",
    catalog_path: catalogPath,
    entry,
    entry_count: entry.length,
    valid_count: entry.filter((current) => current.is_valid).length,
    instant_play_count: entry.filter((current) => current.access === "instant_play_eligible").length,
    byo_only_count: entry.filter((current) => current.access === "bring_your_own_only").length,
    is_all_valid: entry.every((current) => current.is_valid),
    state: "catalog_validated_no_runtime",
    blocker: ["Every entry validates against the frozen schema and instant-play gating holds, but no browser game runtime serves the entry"],
  };
}

// First-party BPTK tech-demo title (GS-071). The title is generated
// deterministically on the public authoring SDK (a clean build reproduces the
// same build hash), licensed Apache-2.0 so it is publishable, and the runner
// records its run as capability evidence — honestly not-passing until a runtime
// exists. The passing run is the red acceptance; the clean reproducible build
// and the evidence record are implemented.
function readSdkMajor() {
  try {
    const sdk = JSON.parse(readFileSync(resolve(moduleRoot, "data", "sdk-api.json"), "utf8"));
    return typeof sdk.major === "number" ? sdk.major : null;
  } catch {
    return null;
  }
}

export function buildFirstPartyDemo(outputInput) {
  const outputPath = resolve(outputInput);
  if (existsSync(outputPath)) throw new InputError("demo_output_exists", `Demo output already exists: ${outputPath}`);
  mkdirSync(outputPath, { recursive: true });
  const sdkMajor = readSdkMajor();
  // Deterministic generated content: a fixed procedural level so two clean
  // builds are byte-identical. No committed binary asset, no external input.
  const level = Buffer.from(Array.from({ length: 4096 }, (unused, index) => (index * 2654435761) % 251));
  const source = {
    "package.json": Buffer.from(`${JSON.stringify({ name: "bptk-tech-demo", version: "0.1.0", license: "Apache-2.0", bptk_sdk_major: sdkMajor }, null, 2)}\n`),
    "level.dat": level,
    "title.json": Buffer.from(`${JSON.stringify({ title: "BPTK Tech Demo", authored_on_sdk_major: sdkMajor, is_first_party: true }, null, 2)}\n`),
  };
  const fileHash = [];
  for (const [name, content] of Object.entries(source)) {
    writeFileSync(join(outputPath, name), content);
    fileHash.push({ path: name, sha256: sha256(content) });
  }
  fileHash.sort((left, right) => (left.path < right.path ? -1 : 1));
  const buildHash = sha256(stableStringify(fileHash));
  // The runner records the run as capability evidence. No runtime exists, so the
  // run does not pass and no passing evidence is promoted.
  const capabilityEvidence = {
    build_hash: buildHash,
    run_state: "no_runtime",
    is_passing: false,
    evidence_hash: null,
    reason: "no browser game runtime exists to execute the title and produce a passing run",
  };
  return {
    schema_version: 1,
    command: "library demo",
    output_path: outputPath,
    sdk_major: sdkMajor,
    is_first_party: true,
    is_clean_build: true,
    build_hash: buildHash,
    file: fileHash,
    capability_evidence: capabilityEvidence,
    is_passing: false,
    state: "demo_built_not_run",
    blocker: ["The first-party title builds reproducibly and is publishable, but no runtime executes it so no passing capability evidence is promoted"],
  };
}

export function formatFirstPartyDemo(report) {
  return [
    `Output: ${report.output_path}`,
    `SDK major: ${report.sdk_major}`,
    `Clean build: ${report.is_clean_build ? "yes" : "no"}`,
    `Build hash: ${report.build_hash}`,
    `Capability run: ${report.capability_evidence.run_state} (passing ${report.capability_evidence.is_passing ? "yes" : "no"})`,
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

// Community submission pipeline (GS-073): a submission maps to a tracker entry,
// proprietary/asset content and personal data are refused (never stored), and a
// claim without a valid attestation never promotes. The pipeline emits an entry,
// not a compatibility claim.
const submissionForbiddenField = ["game_content", "asset_payload", "payload", "rom", "iso"];

export function submitReport(reportInput) {
  const reportPath = resolve(reportInput);
  if (!existsSync(reportPath)) throw new InputError("submission_missing", `Submission does not exist: ${reportPath}`);
  let report;
  try {
    report = JSON.parse(readFileSync(reportPath, "utf8"));
  } catch (error) {
    throw new InputError("invalid_submission", `Submission is not strict JSON: ${error.message}`);
  }
  if (typeof report?.title !== "string" || typeof report?.claim !== "string") {
    throw new InputError("invalid_submission", "Submission requires title and claim strings");
  }
  const proprietary = submissionForbiddenField.filter((field) => report[field] !== undefined);
  if (proprietary.length > 0) {
    throw new InputError("submission_proprietary_refused", `Submission carries proprietary or asset content (${proprietary.join(", ")}); it is refused, never stored`);
  }
  const personalData = scanPersonalData({ title: report.title, claim: report.claim, note: report.note });
  if (personalData.length > 0) {
    throw new InputError("submission_personal_data_refused", `Submission carries personal data (${personalData.join(", ")}); it is refused, never stored`);
  }
  const isAttested = report?.attestation?.is_attested === true && typeof report?.attestation?.signer === "string" && report.attestation.signer.length > 0;
  const entryId = sha256(stableStringify({ title: report.title, claim: report.claim })).slice(0, 16);
  return {
    schema_version: 1,
    command: "library submit",
    submission_path: reportPath,
    tracker_entry: {
      id: entryId,
      title: report.title,
      claim: report.claim,
      signer: isAttested ? report.attestation.signer : null,
      status: isAttested ? "accepted" : "rejected_unattested",
    },
    is_attested: isAttested,
    is_promotable: isAttested,
    state: isAttested ? "submission_tracked" : "submission_unattested",
    blocker: [isAttested ? "The submission maps to an attested tracker entry, but no runtime reproduces the compatibility claim" : "The claim is unattested and never promotes to a compatibility record"],
  };
}

export function formatSubmission(report) {
  return [
    `Submission: ${report.submission_path}`,
    `Tracker entry: ${report.tracker_entry.id} — ${report.tracker_entry.status}`,
    `Attested: ${report.is_attested ? `yes (${report.tracker_entry.signer})` : "no"}`,
    `Promotable: ${report.is_promotable ? "yes" : "no"}`,
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

// Modding (GS-076): a mod is layered as a copy-on-write overlay over a
// read-only base. The base package identity is unchanged by the apply, every
// mod path stays inside the overlay (a parent-path escape is refused), and the
// total overlay is refused above the declared bound. Running the modded title
// needs the absent runtime.
export function applyMod(baseInput, modInput, option = {}) {
  const basePath = resolve(baseInput);
  const baseManifest = readPackageManifest(basePath);
  if (!baseManifest) throw new InputError("package_manifest_missing", `Base package has no valid bptk.json: ${basePath}`);
  const baseHashBefore = baseManifest.package_id;
  const mod = inspectPath(modInput);
  if (mod.type !== "directory") throw new InputError("mod_directory_required", "A mod must be a directory of overlay files");
  const bound = Number.isSafeInteger(option.max) && option.max > 0 ? option.max : modOverlayByteDefault;

  const overlayEntry = [];
  let overlayByte = 0;
  for (const entry of mod.entry.filter((current) => current.type === "file")) {
    // Containment: no parent-path escape, no absolute path.
    const segment = entry.path.split(/[\\/]/);
    if (segment.includes("..") || entry.path.startsWith("/")) {
      throw new InputError("mod_containment_violation", `Mod path escapes containment: ${entry.path}`);
    }
    const content = readFileSync(join(mod.input_path, entry.path));
    overlayByte += content.length;
    if (overlayByte > bound) {
      throw new InputError("mod_bound_exceeded", `Mod overlay ${overlayByte} byte exceeds the declared bound ${bound}`);
    }
    overlayEntry.push({ path: entry.path, size_byte: content.length, sha256: sha256(content), disposition: baseManifest.asset?.some((asset) => asset.path === entry.path) ? "override" : "addition" });
  }

  const stagePath = resolve(option.stage ?? `${basePath}.mod-overlay`);
  mkdirSync(stagePath, { recursive: true });
  for (const entry of overlayEntry) {
    const destination = join(stagePath, entry.path);
    mkdirSync(dirname(destination), { recursive: true });
    cpSync(join(mod.input_path, entry.path), destination);
  }
  // The base must be byte-identical after the apply: read its identity again.
  const baseHashAfter = readPackageManifest(basePath).package_id;
  return {
    schema_version: 1,
    command: "library mod",
    base_path: basePath,
    base_hash: baseHashBefore,
    is_base_unchanged: baseHashBefore === baseHashAfter,
    overlay_path: stagePath,
    overlay: overlayEntry,
    overlay_byte: overlayByte,
    bound_byte: bound,
    is_within_containment: true,
    state: "mod_overlaid_no_runtime",
    blocker: ["The overlay is contained and bounded and the base is unchanged, but no browser game runtime runs the modded title"],
  };
}

export function formatMod(report) {
  return [
    `Base: ${report.base_path}`,
    `Base hash: ${report.base_hash}`,
    `Base unchanged: ${report.is_base_unchanged ? "yes" : "no"}`,
    `Overlay: ${report.overlay.length} file / ${report.overlay_byte} byte (bound ${report.bound_byte})`,
    `State: ${report.state}`,
    ...report.overlay.map((entry) => `Overlay: ${entry.path} (${entry.disposition})`),
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

// Compatibility ratings (GS-075): a rating shows only when it is backed by a
// replay record that reproduces (the record's session re-hashes to the declared
// record hash) and its revision is current. A rating from a superseded revision
// greys out; an unbacked rating never shows.
export function summarizeRatings(ratingInput) {
  const ratingPath = resolve(ratingInput);
  if (!existsSync(ratingPath)) throw new InputError("rating_missing", `Rating file does not exist: ${ratingPath}`);
  let value;
  try {
    value = JSON.parse(readFileSync(ratingPath, "utf8"));
  } catch (error) {
    throw new InputError("invalid_rating", `Rating file is not strict JSON: ${error.message}`);
  }
  if (typeof value?.current_revision !== "string" || !Array.isArray(value.rating)) {
    throw new InputError("invalid_rating", "Rating file requires current_revision and a rating array");
  }
  const rating = value.rating.map((entry) => {
    // Record-backed means the replay reproduces the recorded session exactly.
    const hasRecord = Array.isArray(entry?.record?.session) && Array.isArray(entry?.record?.replay);
    const isReproduced = hasRecord && stableStringify(entry.record.session) === stableStringify(entry.record.replay);
    const isCurrent = entry?.revision === value.current_revision;
    const display = !isReproduced ? "hidden_no_record" : isCurrent ? "shown" : "greyed_out_stale";
    return {
      title: typeof entry?.title === "string" ? entry.title : null,
      score: typeof entry?.score === "number" ? entry.score : null,
      revision: entry?.revision ?? null,
      is_record_backed: isReproduced,
      is_current: isCurrent,
      display,
    };
  });
  return {
    schema_version: 1,
    command: "library rating",
    rating_path: ratingPath,
    current_revision: value.current_revision,
    rating,
    shown_count: rating.filter((entry) => entry.display === "shown").length,
    greyed_count: rating.filter((entry) => entry.display === "greyed_out_stale").length,
    hidden_count: rating.filter((entry) => entry.display === "hidden_no_record").length,
    state: "ratings_resolved_no_runtime",
    blocker: ["Only record-backed current ratings show and stale ones grey out, but no runtime produces a live replay session"],
  };
}

export function formatRatings(report) {
  return [
    `Rating: ${report.rating_path}`,
    `Current revision: ${report.current_revision}`,
    `Shown: ${report.shown_count}; greyed: ${report.greyed_count}; hidden: ${report.hidden_count}`,
    `State: ${report.state}`,
    ...report.rating.map((entry) => `Rating: ${entry.title ?? "?"} — ${entry.display}`),
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

// Preservation catalog (GS-074): an append-only, provenance-carrying record set.
// Appending an entry whose id already exists with different content is refused
// (no mutation); the export is deterministic byte-stable and personal-data-free.
function loadCatalogFile(catalogPath) {
  if (!existsSync(catalogPath)) return { schema_version: 1, record: [] };
  let value;
  try {
    value = JSON.parse(readFileSync(catalogPath, "utf8"));
  } catch (error) {
    throw new InputError("invalid_preservation_catalog", `Preservation catalog is not strict JSON: ${error.message}`);
  }
  if (!Array.isArray(value.record)) throw new InputError("invalid_preservation_catalog", "Preservation catalog requires a record array");
  return value;
}

export function appendPreservation(catalogInput, entryInput) {
  const catalogPath = resolve(catalogInput);
  const catalog = loadCatalogFile(catalogPath);
  let entry;
  try {
    entry = JSON.parse(readFileSync(resolve(entryInput), "utf8"));
  } catch (error) {
    throw new InputError("invalid_preservation_entry", `Preservation entry is not strict JSON: ${error.message}`);
  }
  if (typeof entry?.id !== "string" || typeof entry?.title !== "string" || typeof entry?.provenance !== "string") {
    throw new InputError("invalid_preservation_entry", "Preservation entry requires id, title, and provenance strings");
  }
  const entryHash = sha256(stableStringify(entry));
  const existing = catalog.record.find((record) => record.id === entry.id);
  if (existing && existing.content_hash !== entryHash) {
    throw new InputError("preservation_mutation_refused", `Entry ${entry.id} already exists with different content; the catalog is append-only`);
  }
  const isDuplicate = Boolean(existing);
  if (!isDuplicate) {
    catalog.record.push({ id: entry.id, title: entry.title, provenance: entry.provenance, content_hash: entryHash, payload: entry });
    writeAtomic(catalogPath, catalog);
  }
  return {
    schema_version: 1,
    command: "library preserve",
    catalog_path: catalogPath,
    id: entry.id,
    content_hash: entryHash,
    is_appended: !isDuplicate,
    is_duplicate: isDuplicate,
    record_count: catalog.record.length,
    state: "preservation_appended",
    blocker: ["The catalog is append-only and provenance-carrying, but no runtime plays the preserved title"],
  };
}

export function exportPreservation(catalogInput) {
  const catalogPath = resolve(catalogInput);
  const catalog = loadCatalogFile(catalogPath);
  const sorted = [...catalog.record].sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  // Scan the human-authored payload only; content hashes carry long digit runs
  // that are not personal data.
  const personalData = scanPersonalData(sorted.map((record) => record.payload ?? { title: record.title, provenance: record.provenance }));
  const exportBody = `${stableStringify({ schema_version: 1, record: sorted })}\n`;
  return {
    schema_version: 1,
    command: "library preserve-export",
    catalog_path: catalogPath,
    record_count: sorted.length,
    export_body: exportBody,
    export_hash: sha256(exportBody),
    personal_data_hit: personalData,
    is_personal_data_free: personalData.length === 0,
    is_reproducible: true,
    state: personalData.length === 0 ? "export_ready" : "export_refused_personal_data",
    blocker: ["The export is deterministic and personal-data-free, but no runtime plays the preserved title"],
  };
}

export function formatPreservation(report) {
  return [
    `Catalog: ${report.catalog_path}`,
    `Entry: ${report.id}`,
    `Appended: ${report.is_appended ? "yes" : `no (duplicate)`}`,
    `Record count: ${report.record_count}`,
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

export function formatPreservationExport(report) {
  return [
    `Catalog: ${report.catalog_path}`,
    `Record: ${report.record_count}`,
    `Export hash: ${report.export_hash}`,
    `Personal-data free: ${report.is_personal_data_free ? "yes" : `no (${report.personal_data_hit.join(", ")})`}`,
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

// Bring-your-own-file import (GS-070). A user-owned file is threat- and
// protection-scanned, refused if flagged, then staged into a local
// content-addressed library. No byte leaves the machine and the entry is never
// published — a BYO title is private to its owner. Launching it needs the runtime.
export function stageUserImport(fileInput, stageInput) {
  const inspection = inspectWithThreat(fileInput);
  assertImportSafety(inspection);
  const filePath = resolve(fileInput);
  const content = readFileSync(filePath);
  const contentHash = sha256(content);
  const stagePath = resolve(stageInput ?? join(resolve("."), ".bptk-library"));
  mkdirSync(join(stagePath, "object"), { recursive: true });
  const stagedObjectPath = join(stagePath, "object", contentHash);
  writeFileSync(stagedObjectPath, content);
  const entry = {
    source_name: inspection.input_name ?? filePath,
    build_hash: contentHash,
    byte: content.length,
    is_published: false,
    access: "bring_your_own_only",
  };
  writeAtomic(join(stagePath, `${contentHash}.entry.json`), entry);
  return {
    schema_version: 1,
    command: "library import",
    source_path: filePath,
    stage_path: stagePath,
    staged_path: stagedObjectPath,
    build_hash: contentHash,
    network_byte: 0,
    is_published: false,
    is_launch_local: true,
    trust_tier: inspection.trust_tier?.tier ?? null,
    state: "staged_local_no_runtime",
    blocker: ["The file is staged locally with zero network transfer and is never published, but no browser game runtime launches it"],
  };
}

export function formatUserImport(report) {
  return [
    `Source: ${report.source_path}`,
    `Staged: ${report.staged_path}`,
    `Build hash: ${report.build_hash}`,
    `Network byte: ${report.network_byte}`,
    `Published: ${report.is_published ? "yes" : "no"}`,
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

// Instant-play redistributable hosting (GS-069). Publication is gated by the
// license/reuse/provenance graph: an unlicensed component or an expired
// redistribution grant refuses publication outright. A clean graph yields a
// hosted-title descriptor; reaching interactive from a cold browser still needs
// the absent runtime.
export function publishHostedTitle(projectInput) {
  const value = inspectPath(projectInput);
  if (value.type !== "directory") throw new InputError("project_directory_required", "Hosting requires a project directory");
  const graph = resolveLicenseGraph(value);
  const buildHash = sha256(JSON.stringify(value.entry.filter((entry) => entry.type === "file").map((entry) => entry.path).sort()));
  if (graph.refusal.length > 0) {
    return {
      schema_version: 1,
      command: "library publish",
      project_path: value.input_path,
      build_hash: buildHash,
      grant_expiry: graph.grant_expiry,
      is_published: false,
      state: "refused_publication",
      refusal: graph.refusal,
      blocker: graph.refusal.map((entry) => `Publication refused: ${entry}`),
    };
  }
  return {
    schema_version: 1,
    command: "library publish",
    project_path: value.input_path,
    build_hash: buildHash,
    grant_expiry: graph.grant_expiry,
    component: graph.component,
    is_published: true,
    state: "hosted_no_runtime",
    refusal: [],
    blocker: ["The title is publishable with an in-date grant, but no browser game runtime measures cold-start time-to-interactive"],
  };
}

export function formatHostedTitle(report) {
  return [
    `Project: ${report.project_path}`,
    `Build hash: ${report.build_hash}`,
    `Grant expiry: ${report.grant_expiry ?? "none"}`,
    `Published: ${report.is_published ? "yes" : "no"}`,
    `State: ${report.state}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

export function formatCatalog(report) {
  return [
    `Catalog: ${report.catalog_path}`,
    `Entry: ${report.entry_count} (valid ${report.valid_count})`,
    `Instant-play eligible: ${report.instant_play_count}`,
    `Bring-your-own only: ${report.byo_only_count}`,
    `State: ${report.state}`,
    ...report.entry.map((entry) => `Entry: ${entry.title ?? "?"} — ${entry.access}${entry.failure.length ? ` (${entry.failure.join("; ")})` : ""}`),
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
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
