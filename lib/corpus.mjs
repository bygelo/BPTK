// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The lawful freeware corpus pipeline (GS-104 through GS-107): a versioned
// manifest of DRM-free, offline, lawfully-redistributable program and game
// payload is verified and staged outside the repository by `corpus acquire`,
// every payload is then executed end to end through the real ingest and run
// path by `corpus run` with the reached stage and the named generic gap that
// stopped it, and `corpus generalize` is the merge gate that accepts a
// candidate fix only when it raises the reached stage of the declared number
// of distinct entry. Payload byte never enter the repository and nothing here
// marks a title playable: a reached stage is not a compatibility claim.

import { createHash } from "node:crypto";
import { createWriteStream, existsSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { get as httpsGet } from "node:https";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { InputError } from "./input.mjs";
import { inspectInput } from "./inspect.mjs";
import { ingestInput } from "./ingest.mjs";
import { runPackage } from "./run.mjs";
import { mapPe32 } from "./pe.mjs";
import { buildConformanceCaseTable, listWin32HleExport as hleExport } from "./hle.mjs";

const root = resolve(fileURLToPath(import.meta.url), "..", "..");

function corpusError(code, message) {
  return new InputError(code, message);
}

function getCorpusPath() {
  return resolve(process.env.BPTK_CORPUS_PATH || ".bptk/corpus.json");
}

export function getCorpusStatus() {
  const corpusPath = getCorpusPath();
  if (!existsSync(corpusPath)) {
    return {
      schema_version: 1,
      command: "corpus status",
      corpus_path: corpusPath,
      review_state: "missing",
      entry_count: 0,
      threshold_state: "missing",
      is_publishable: false,
      blocker: ["No local corpus registry exists", "No lawful denominator or numeric threshold is approved"],
    };
  }
  let value;
  try {
    value = JSON.parse(readFileSync(corpusPath, "utf8"));
  } catch (error) {
    throw new Error(`Corpus registry is not strict JSON: ${error.message}`);
  }
  const entry = Array.isArray(value.entry) ? value.entry : [];
  const threshold = value.threshold && typeof value.threshold === "object" ? value.threshold : null;
  const isApproved = value.review_state === "approved" && typeof value.reviewer === "string" && value.reviewer.trim() !== "";
  return {
    schema_version: 1,
    command: "corpus status",
    corpus_path: corpusPath,
    review_state: isApproved ? "approved" : "review_required",
    entry_count: entry.length,
    threshold_state: threshold ? "declared_not_approved" : "missing",
    is_publishable: Boolean(isApproved && threshold && entry.length > 0),
    blocker: isApproved ? [] : ["A named reviewer has not approved the lawful denominator and threshold"],
  };
}

export function formatCorpusStatus(report) {
  return [
    `Corpus: ${report.corpus_path}`,
    `Review: ${report.review_state}`,
    `Entry count: ${report.entry_count}`,
    `Threshold: ${report.threshold_state}`,
    `Publishable: ${report.is_publishable ? "yes" : "no"}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

function getAcquisitionManifestPath() {
  return resolve(process.env.BPTK_ACQUISITION_PATH || join(root, "data", "corpus.json"));
}

export function loadAcquisitionManifest() {
  const manifestPath = getAcquisitionManifestPath();
  if (!existsSync(manifestPath)) {
    throw corpusError("corpus_manifest_missing", `The acquisition manifest does not exist: ${manifestPath}`);
  }
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (error) {
    throw corpusError("corpus_manifest_invalid", `The acquisition manifest is not strict JSON: ${error.message}`);
  }
  if (manifest.schema_version !== 1 || !Array.isArray(manifest.record) || manifest.record.length === 0) {
    throw corpusError("corpus_manifest_invalid", "The acquisition manifest requires schema_version 1 and a non-empty record array");
  }
  return manifest;
}

export function resolveStageDir(option = {}) {
  return resolve(option.stage || process.env.BPTK_CORPUS_STAGE || join(root, "..", "bptk-corpus", "stage"));
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

// Reads one remote payload over https under the declared download bound:
// scheme pinned, redirect chain bounded, wall clock bounded, and a payload
// larger than the declared byte cap is aborted mid-stream.
function downloadPayload(sourceUrl, targetPath, bound) {
  return new Promise((resolveDownload, rejectDownload) => {
    let remainingRedirect = bound.redirect_max;
    const start = (url) => {
      let request;
      let settled = false;
      const settle = (fn) => {
        if (!settled) {
          settled = true;
          fn();
        }
      };
      const timer = setTimeout(() => settle(() => {
        request?.destroy();
        rejectDownload(corpusError("corpus_download_timeout", `The download exceeded ${bound.timeout_ms} ms: ${url}`));
      }), bound.timeout_ms);
      request = httpsGet(url, { headers: { "user-agent": "BPTK-corpus/0.1" } }, (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          response.resume();
          clearTimeout(timer);
          if (remainingRedirect <= 0) {
            settle(() => rejectDownload(corpusError("corpus_download_redirect", `The download redirect chain exceeds ${bound.redirect_max}`)));
            return;
          }
          remainingRedirect -= 1;
          const next = new URL(response.headers.location, url);
          if (next.protocol !== "https:") {
            settle(() => rejectDownload(corpusError("corpus_download_scheme", "The download redirected away from https")));
            return;
          }
          start(next.toString());
          return;
        }
        if (response.statusCode !== 200) {
          response.resume();
          clearTimeout(timer);
          settle(() => rejectDownload(corpusError("corpus_download_status", `The download returned HTTP ${response.statusCode}: ${url}`)));
          return;
        }
        const declared = Number(response.headers["content-length"] ?? 0);
        if (declared > bound.max_byte) {
          response.resume();
          clearTimeout(timer);
          settle(() => rejectDownload(corpusError("bound_download_exceeded", `The declared payload ${declared} byte exceeds the download bound ${bound.max_byte}`)));
          return;
        }
        const hash = createHash("sha256");
        let received = 0;
        const file = createWriteStream(targetPath);
        response.on("data", (chunk) => {
          received += chunk.length;
          if (received > bound.max_byte) {
            response.destroy();
            file.close(() => unlinkSync(targetPath));
            clearTimeout(timer);
            settle(() => rejectDownload(corpusError("bound_download_exceeded", `The payload exceeded the download bound ${bound.max_byte} mid-stream`)));
            return;
          }
          hash.update(chunk);
        });
        response.on("error", (error) => {
          clearTimeout(timer);
          settle(() => rejectDownload(corpusError("corpus_download_failure", `The download failed: ${error.message}`)));
        });
        response.on("end", () => {
          file.end(() => {
            clearTimeout(timer);
            settle(() => resolveDownload({ sha256: hash.digest("hex"), size_byte: received }));
          });
        });
      });
      request.on("error", (error) => {
        clearTimeout(timer);
        settle(() => rejectDownload(corpusError("corpus_download_failure", `The download failed: ${error.message}`)));
      });
    };
    const parsed = new URL(sourceUrl);
    if (parsed.protocol !== "https:") {
      rejectDownload(corpusError("corpus_download_scheme", "Only https source are admitted"));
      return;
    }
    start(parsed.toString());
  });
}

function payloadFileName(sourceUrl) {
  return basename(new URL(sourceUrl).pathname);
}

// Verifies one entry against its manifest pin: redistribution basis, license,
// https source, staged byte, and hash. A mismatch is a refusal, never a
// replacement, so the manifest pin stays the law of the corpus.
function verifyEntry(entry, stageDir, option = {}) {
  const record = {
    entry_id: entry.entry_id,
    title: entry.title,
    kind: entry.kind,
    state: "refused",
    action: "refused",
    verified: false,
    size_byte: entry.size_byte ?? null,
    sha256_pinned: entry.sha256 ?? null,
    sha256_staged: null,
    stage_path: null,
    reason: null,
  };
  if (!entry.redistribution_basis || !entry.license) {
    record.reason = "The entry carries no redistribution basis or license";
    return record;
  }
  let source;
  try {
    source = new URL(entry.source_url);
  } catch {
    record.reason = "The source URL is not a valid URL";
    return record;
  }
  if (source.protocol !== "https:") {
    record.reason = "Only https source are admitted";
    return record;
  }
  const fileName = payloadFileName(entry.source_url);
  const targetPath = join(stageDir, entry.entry_id.toLowerCase(), fileName);
  record.stage_path = targetPath;
  if (!existsSync(targetPath)) {
    if (option.is_plan_only) {
      record.state = "planned";
      record.action = "plan";
      record.reason = "The payload is not staged";
      return record;
    }
    throw corpusError("corpus_payload_missing", `The payload is not staged: ${targetPath}`);
  }
  const actualSize = statSync(targetPath).size;
  record.size_byte = actualSize;
  if (entry.size_byte !== null && entry.size_byte !== undefined && actualSize !== entry.size_byte) {
    record.reason = `The staged payload is ${actualSize} byte, the manifest pins ${entry.size_byte}`;
    return record;
  }
  const actualHash = sha256File(targetPath);
  record.sha256_staged = actualHash;
  if (entry.sha256 && actualHash !== entry.sha256) {
    record.reason = "The staged payload hash differs from the manifest pin; the payload is refused";
    return record;
  }
  record.state = "acquired";
  record.action = "verified";
  record.verified = true;
  record.reason = null;
  return record;
}

export async function acquireCorpus(option = {}) {
  const manifest = loadAcquisitionManifest();
  const stageDir = resolveStageDir(option);
  const downloadBound = { ...manifest.download_bound };
  const record = [];
  for (const entry of manifest.record) {
    const verified = verifyEntry(entry, stageDir, { is_plan_only: option.plan_only === true });
    record.push(verified);
    if (verified.verified || option.plan_only === true) continue;
    if (verified.reason && verified.state === "refused") continue;
    const targetPath = join(stageDir, entry.entry_id.toLowerCase(), payloadFileName(entry.source_url));
    mkdirSync(join(stageDir, entry.entry_id.toLowerCase()), { recursive: true });
    const download = await downloadPayload(entry.source_url, targetPath, downloadBound);
    if (entry.sha256 && download.sha256 !== entry.sha256) {
      unlinkSync(targetPath);
      verified.state = "refused";
      verified.action = "refused";
      verified.reason = "The downloaded payload hash differs from the manifest pin; the download is deleted";
      continue;
    }
    verified.state = "acquired";
    verified.action = "download";
    verified.verified = true;
    verified.size_byte = download.size_byte;
    verified.sha256_staged = download.sha256;
    verified.reason = null;
  }
  return {
    schema_version: 1,
    command: "corpus acquire",
    stage_dir: stageDir,
    download_bound: downloadBound,
    record,
    downloaded_count: record.filter((entry) => entry.action === "download").length,
    verified_count: record.filter((entry) => entry.action === "verified").length,
    refused_count: record.filter((entry) => entry.action === "refused").length,
    payload_in_repository: false,
    privacy: { is_local_only: true, is_uploaded: false, payload_committed: false },
  };
}

// The named generic gap taxonomy: each refusal maps to the roadmap item that
// owns the missing capability, so the run record ranks downstream work instead
// of inviting a per-title patch.
const gapTaxonomy = Object.freeze({
  integrity_mismatch: "BPTK-044",
  archive_format_unsupported: "BPTK-038",
  archive_ingest_unimplemented: "BPTK-007",
  archive_entry_encrypted: "BPTK-038",
  bound_entry_exceeded: "BPTK-044",
  bound_output_exceeded: "BPTK-044",
  bound_depth_exceeded: "BPTK-044",
  bound_ratio_exceeded: "BPTK-044",
  bound_input_exceeded: "BPTK-044",
  unsupported_executable_format: "BPTK-007",
  pe32_plus_mapping_absent: "BPTK-008",
  machine_x86_64: "BPTK-031",
  import_present: "BPTK-010",
  tls_callback_present: "BPTK-010",
  runtime_game_loop_absent: "BPTK-010",
  execution_refused: "BPTK-009",
  no_executable_payload: "BPTK-007",
});

const stageRank = Object.freeze({ staged: 0, classified: 1, packaged: 2, loaded: 3, entry: 4, interactive: 5 });

function runOneEntry(entry, stageDir, option = {}) {
  const record = {
    entry_id: entry.entry_id,
    title: entry.title,
    kind: entry.kind,
    runtime_class: entry.game_loop ? "game" : "program",
    payload_kind: entry.payload_kind,
    architecture: null,
    classification: null,
    reached_stage: "staged",
    gap_code: null,
    gap_item: null,
    gap_note: null,
    command: [],
    duration_ms: 0,
    is_playable_claim: false,
  };
  const startedAt = Date.now();
  const finish = () => {
    record.duration_ms = Date.now() - startedAt;
    return record;
  };
  let integrity;
  try {
    integrity = verifyEntry(entry, stageDir, {});
  } catch (error) {
    record.gap_code = "integrity_mismatch";
    record.gap_item = gapTaxonomy.integrity_mismatch;
    record.gap_note = error.message;
    record.reached_stage = "staged";
    return finish();
  }
  if (!integrity.verified) {
    record.gap_code = "integrity_mismatch";
    record.gap_item = gapTaxonomy.integrity_mismatch;
    record.gap_note = integrity.reason ?? "The staged payload failed verification";
    return finish();
  }
  const payloadPath = integrity.stage_path;
  record.command.push("verify");
  try {
    const inspection = inspectInput(payloadPath);
    record.classification = inspection.classification;
    record.reached_stage = "classified";
  } catch (error) {
    record.gap_code = "integrity_mismatch";
    record.gap_item = gapTaxonomy.integrity_mismatch;
    record.gap_note = error.message;
    return finish();
  }
  record.command.push("ingest");
  const packageDir = join(stageDir, entry.entry_id.toLowerCase(), "package");
  let ingest;
  try {
    ingest = ingestInput(payloadPath, { output: packageDir });
  } catch (error) {
    if (error instanceof InputError) {
      record.gap_code = error.input_code;
      record.gap_item = gapTaxonomy[error.input_code] ?? "BPTK-007";
      record.gap_note = error.message;
    } else {
      record.gap_code = "execution_refused";
      record.gap_item = gapTaxonomy.execution_refused;
      record.gap_note = error.message;
    }
    return finish();
  }
  const probeReason = ingest.detection?.probe_reason ?? null;
  if (probeReason === null) record.architecture = "i386";
  else if (probeReason.includes("x86_64")) record.architecture = "x86_64";
  if (!ingest.is_ingested || !ingest.package_manifest) {
    record.gap_code = "no_executable_payload";
    record.gap_item = gapTaxonomy.no_executable_payload;
    record.gap_note = "The ingest left no executable package to run";
    return finish();
  }
  record.reached_stage = "packaged";
  record.command.push("run");
  if (option.run === false) {
    return finish();
  }
  // The corpus is the consented, bounded execution context: for a PE image we
  // can execute — i386 (probeReason null) or x86-64 (the runtime-v2 exec64
  // path) — declare the opt-in profile so the bounded probe actually runs and
  // the `entry` stage becomes measurable. The sandbox bound (instruction
  // budget, HLE-only for i386 / no Win64 HLE yet for x86-64, no host I/O) is
  // unchanged — this is a controlled benchmark, not a passive scan.
  if (probeReason === null || (typeof probeReason === "string" && probeReason.includes("x86_64"))) {
    const manifestFile = join(packageDir, "bptk.json");
    try {
      const manifest = JSON.parse(readFileSync(manifestFile, "utf8"));
      if (!manifest.execution) {
        manifest.execution = { profile: "i386_probe_v1", instruction_budget_count: 2000000 };
        writeFileSync(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`);
      }
    } catch {
      // A package without a rewritable manifest simply maps; the run reports it.
    }
  }
  let run;
  try {
    run = runPackage(packageDir);
  } catch (error) {
    if (error instanceof InputError) {
      record.gap_code = error.input_code === "unsupported_machine" ? "machine_x86_64" : error.input_code;
      record.gap_item = gapTaxonomy[record.gap_code] ?? "BPTK-008";
      record.gap_note = error.message;
      if (error.input_code === "unsupported_machine") record.architecture = "x86_64";
    } else {
      record.gap_code = "execution_refused";
      record.gap_item = gapTaxonomy.execution_refused;
      record.gap_note = error.message;
    }
    return finish();
  }
  if (run.state === "probe_blocked") {
    record.reached_stage = "loaded";
    record.architecture = "i386";
    if (run.stop_reason === "import_present") {
      record.gap_code = "import_present";
      record.gap_item = gapTaxonomy.import_present;
      record.gap_note = run.exception?.message ?? "Execution requires every imported function served by the Win32 core HLE";
    } else if (run.stop_reason === "tls_callback_present") {
      record.gap_code = "tls_callback_present";
      record.gap_item = gapTaxonomy.tls_callback_present;
      record.gap_note = run.exception?.message ?? "Execution requires zero TLS callback";
    } else if (run.stop_reason === "unsupported_opcode") {
      record.gap_code = "unsupported_opcode";
      record.gap_item = "BPTK-009";
      record.gap_note = run.exception?.message ?? "The instruction is outside the bounded i386 probe subset";
    } else {
      record.gap_code = "machine_x86_64";
      record.gap_item = gapTaxonomy.machine_x86_64;
      record.gap_note = "The machine class is the research lane, not the bounded i386 probe";
    }
    return finish();
  }
  if (run.state === "probe_executed") {
    // Real instructions ran from the entry point: the image reached the `entry`
    // stage. Keep the architecture detected at ingest and name the actual stop
    // so the gap ranks the true next work, not a generic label.
    record.reached_stage = "entry";
    const is64 = record.architecture === "x86_64";
    if (run.stop_reason === "import_present") {
      record.gap_code = is64 ? "machine_x86_64" : "import_present";
      record.gap_item = is64 ? gapTaxonomy.machine_x86_64 : gapTaxonomy.import_present;
      record.gap_note = run.exception?.message ?? (is64
        ? "The x86-64 image executed from entry and reached its first import; a Win64 HLE is not implemented"
        : "Execution reached an import the Win32 core HLE does not serve");
    } else if (run.stop_reason === "unsupported_opcode") {
      record.gap_code = "unsupported_opcode";
      record.gap_item = "BPTK-009";
      record.gap_note = run.exception?.message ?? "The instruction is outside the bounded probe subset";
    } else if (typeof run.stop_reason === "string" && run.stop_reason.endsWith("_fault")) {
      record.gap_code = run.stop_reason;
      record.gap_item = "BPTK-009";
      record.gap_note = run.exception?.message ?? `Execution stopped on ${run.stop_reason}`;
    } else {
      record.gap_code = "runtime_game_loop_absent";
      record.gap_item = gapTaxonomy.runtime_game_loop_absent;
      record.gap_note = "The bounded probe executed, but a real session needs the full Win32 runtime";
    }
    return finish();
  }
  // The probe is opt-in: a package without an execution manifest only maps.
  record.reached_stage = "loaded";
  record.architecture = run.machine ?? record.architecture;
  if ((run.import_count ?? 0) > 0) {
    record.gap_code = "import_present";
    record.gap_item = gapTaxonomy.import_present;
    record.gap_note = `The image imports ${run.import_count} function and no Win32 HLE serves them; execution stays opt-in under the containment policy`;
  } else {
    record.gap_code = "execution_profile_absent";
    record.gap_item = "BPTK-009";
    record.gap_note = "The image maps cleanly but the bundle declares no execution profile, so the opt-in probe never runs";
  }
  return finish();
}

export function runCorpus(option = {}) {
  const manifest = loadAcquisitionManifest();
  const stageDir = resolveStageDir(option);
  const record = manifest.record.map((entry) => runOneEntry(entry, stageDir, option));
  const report = {
    schema_version: 1,
    command: "corpus run",
    stage_dir: stageDir,
    record,
    run_count: record.length,
    reached: Object.fromEntries(Object.keys(stageRank).map((stage) => [stage, record.filter((entry) => entry.reached_stage === stage).length])),
    refused_count: record.filter((entry) => entry.gap_code === "integrity_mismatch").length,
    gap: record.filter((entry) => entry.gap_item !== null).reduce((tally, entry) => {
      tally[entry.gap_item] = (tally[entry.gap_item] ?? 0) + 1;
      return tally;
    }, {}),
    records_path: option.save === false ? null : join(stageDir, "corpus-run.json"),
    privacy: { is_local_only: true, is_uploaded: false, payload_committed: false, personal_data: false },
  };
  if (report.records_path !== null) {
    writeFileSync(report.records_path, `${JSON.stringify(report, null, 2)}\n`);
  }
  return report;
}

export function loadRunRecords(path) {
  if (typeof path !== "string" || path.trim() === "") {
    throw corpusError("missing_input", "A run-record path is required");
  }
  let value;
  try {
    value = JSON.parse(readFileSync(resolve(path), "utf8"));
  } catch (error) {
    throw corpusError("run_record_invalid", `The run-record file is not strict JSON: ${error.message}`);
  }
  if (!Array.isArray(value.record)) {
    throw corpusError("run_record_invalid", "The run-record file requires a record array");
  }
  return value;
}

// The generalization gate (GS-106): a candidate fix is accepted only when it
// raises the reached stage of at least the declared number of distinct entry,
// and regresses none. A single-beneficiary fix is refused unless the caller
// declares it a sandboxed last-resort adapter.
export function computeGeneralizationDelta(before, after, option = {}) {
  const minBeneficiary = option.min ?? 2;
  const rank = (record) => stageRank[record?.reached_stage] ?? 0;
  const beforeRecord = Array.isArray(before) ? before : before.record ?? [];
  const afterRecord = Array.isArray(after) ? after : after.record ?? [];
  const beforeById = new Map(beforeRecord.map((entry) => [entry.entry_id, entry]));
  const improved = [];
  const regressed = [];
  for (const entry of afterRecord) {
    const beforeValue = rank(beforeById.get(entry.entry_id));
    const afterValue = rank(entry);
    if (afterValue > beforeValue) improved.push(entry.entry_id);
    if (afterValue < beforeValue) regressed.push(entry.entry_id);
  }
  const distinct = [...new Set(improved)].length;
  const verdict = regressed.length > 0
    ? "refused_regression"
    : option.adapter
      ? "adapter_accepted"
      : distinct >= minBeneficiary
        ? "generic_accepted"
        : "refused_single_beneficiary";
  return {
    schema_version: 1,
    command: "corpus generalize",
    min_beneficiary: minBeneficiary,
    beneficiary_count: distinct,
    improved_entry: [...new Set(improved)],
    regressed_entry: [...new Set(regressed)],
    is_generic: verdict === "generic_accepted",
    verdict,
    adapter_declared: option.adapter === true,
    refusal_reason: verdict === "refused_single_beneficiary"
      ? `The fix raises ${distinct} distinct entry, fewer than the declared minimum ${minBeneficiary}; a per-title fix does not generalize`
      : verdict === "refused_regression"
        ? `The fix regresses ${regressed.length} entry`
        : null,
  };
}

export function formatAcquire(report) {
  return [
    `Corpus acquire: ${report.stage_dir}`,
    `Download bound: ${report.download_bound.max_byte} byte, ${report.download_bound.timeout_ms} ms`,
    ...report.record.map((entry) => `  ${entry.entry_id} ${entry.title}: ${entry.action}${entry.reason ? ` — ${entry.reason}` : ""}`),
    `Download: ${report.downloaded_count}, verified: ${report.verified_count}, refused: ${report.refused_count}`,
    "Payload in repository: no",
  ].join("\n");
}

export function formatCorpusRun(report) {
  return [
    `Corpus run: ${report.stage_dir}`,
    ...report.record.map((entry) => `  ${entry.entry_id} ${entry.title} [${entry.runtime_class}] ${entry.reached_stage}${entry.gap_item ? ` — gap ${entry.gap_code} → ${entry.gap_item}` : ""}`),
    `Reached: ${Object.entries(report.reached).filter(([, count]) => count > 0).map(([stage, count]) => `${stage} ${count}`).join(", ")}`,
    `Gap: ${Object.entries(report.gap).map(([item, count]) => `${item} ${count}`).join(", ") || "none"}`,
    "Reached stage is not a playable claim.",
  ].join("\n");
}

export function formatGeneralize(report) {
  return [
    `Corpus generalize: ${report.verdict}`,
    `Beneficiary: ${report.beneficiary_count} distinct entry (minimum ${report.min_beneficiary})`,
    `Improved: ${report.improved_entry.join(", ") || "none"}`,
    `Regressed: ${report.regressed_entry.join(", ") || "none"}`,
    ...(report.refusal_reason ? [`Refused: ${report.refusal_reason}`] : []),
  ].join("\n");
}

// The emulation export-coverage ledger (GS-041): the corpus import surface
// joined against the Win32 core HLE registry. A served symbol is covered only
// when the conformance case table carries it; a symbol with zero conformance
// case is a tracked gap, and the release gate holds the declared gap budget.
// Unserved symbol stay honestly absent, so the ledger ranks the next API by
// how many corpus entry import it.
export function buildExportLedger(option = {}) {
  const manifest = loadAcquisitionManifest();
  const stageDir = resolveStageDir(option);
  const gapBudget = option.gap_budget ?? 0;
  const servedExport = new Set(hleExport().map((entry) => [entry.library, entry.symbol]));
  const conformanceCase = new Map();
  for (const oracleCase of buildConformanceCaseTable()) {
    const key = oracleCase.library + "!" + oracleCase.symbol;
    conformanceCase.set(key, (conformanceCase.get(key) ?? 0) + 1);
  }
  const record = [];
  const symbolState = new Map();
  const symbolTally = new Map();
  for (const entry of manifest.record) {
    const packageDir = join(stageDir, entry.entry_id.toLowerCase(), "package");
    const packageManifestPath = join(packageDir, "bptk.json");
    if (!existsSync(packageManifestPath)) {
      record.push({ entry_id: entry.entry_id, status: "no_package", library_count: 0, symbol_count: 0 });
      continue;
    }
    const packageManifest = JSON.parse(readFileSync(packageManifestPath, "utf8"));
    if (typeof packageManifest.executable !== "string") {
      record.push({ entry_id: entry.entry_id, status: "no_executable", library_count: 0, symbol_count: 0 });
      continue;
    }
    const executablePath = join(packageDir, packageManifest.executable);
    if (!existsSync(executablePath)) {
      record.push({ entry_id: entry.entry_id, status: "no_executable", library_count: 0, symbol_count: 0 });
      continue;
    }
    try {
      const mapped = mapPe32(executablePath);
      const library = new Set();
      for (const imported of mapped.import ?? []) {
        const key = `${imported.library}!${imported.symbol ?? `#${imported.ordinal}`}`;
        symbolState.set(key, "absent");
        symbolTally.set(key, (symbolTally.get(key) ?? 0) + 1);
        library.add(imported.library);
      }
      record.push({ entry_id: entry.entry_id, status: "mapped", library_count: library.size, symbol_count: (mapped.import ?? []).length });
    } catch (error) {
      record.push({ entry_id: entry.entry_id, status: "unmapped", reason: error.message, library_count: 0, symbol_count: 0 });
    }
  }
  for (const [library, symbol] of servedExport) {
    if (symbolState.has(`${library}!${symbol}`)) symbolState.set(`${library}!${symbol}`, "covered");
  }
  const ledger = [...symbolState.entries()].map(([key, status]) => ({ key, status, case_count: conformanceCase.get(key) ?? 0, corpus_import_count: symbolTally.get(key) ?? 0 }));
  const rankedGap = ledger
    .filter((entry) => entry.status === "absent")
    .sort((a, b) => b.corpus_import_count - a.corpus_import_count)
    .slice(0, 24)
    .map((entry) => ({ key: entry.key, corpus_import_count: entry.corpus_import_count }));
  return {
    schema_version: 1,
    command: "corpus coverage",
    stage_dir: stageDir,
    record,
    symbol_count: ledger.length,
    covered_count: ledger.filter((entry) => entry.status === "covered").length,
    absent_count: ledger.filter((entry) => entry.status === "absent").length,
    gap_budget: gapBudget,
    is_within_budget: ledger.length <= gapBudget,
    unserved_ranking: rankedGap,
    ledger: ledger.slice(0, 256),
    ledger_truncated: ledger.length > 256,
    privacy: { is_local_only: true, is_uploaded: false },
  };
}

export function formatExportLedger(report) {
  return [
    `Corpus coverage: ${report.symbol_count} imported symbol from ${report.record.length} entry`,
    `Covered: ${report.covered_count}, absent: ${report.absent_count}, gap budget: ${report.gap_budget}`,
    `Within budget: ${report.is_within_budget ? "yes" : "no"}`,
    ...report.ledger.slice(0, 12).map((entry) => `  ${entry.key}: ${entry.status} (${entry.case_count} case)`),
    ...(report.ledger_truncated ? [`  ... ${report.symbol_count - 12} more`] : []),
    "A zero-case symbol is a tracked gap; the release gate holds the budget.",
  ].join("\n");
}
