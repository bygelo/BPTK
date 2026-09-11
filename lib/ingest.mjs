// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// One-command ingestion for any executable input, modeled on the
// bring-your-own-file flow of the closest prior art: the input is classified,
// census-routed, extracted when it is a supported installer, and — when it is
// a Windows PE — packaged into a BPTK bundle with a synthesized manifest so
// `bptk run` can consume it. Nothing is executed during ingestion, every
// write goes to a caller-declared output directory under the declared
// extraction bound, and every input BPTK cannot carry stays a structured
// refusal with its reason.

import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { inflateRawSync } from "node:zlib";
import {
  assertChunkInputBound,
  assertChunkRatioBound,
  assertDepthBound,
  assertEntryBound,
  assertOutputBound,
  chunkOutputCap,
  createExtractionBound,
  describeExtractionBound,
} from "./bound.mjs";
import { admitEmulatorLane } from "./emulator.mjs";
import { detectInstaller, extractInstaller } from "./extract.mjs";
import { isSevenZip, readSevenZip } from "./sevenzip.mjs";
import { InputError, inspectPath } from "./input.mjs";
import { inspectInput } from "./inspect.mjs";
import { diagnoseSourcePort } from "./port.mjs";
import { assertImportSafety, inspectWithThreat } from "./security.mjs";

const packageExecutableCapByte = 64 * 1024 * 1024;

function ingestError(code, message) {
  return new InputError(code, message);
}

// Reads the packaged manifest from a directory input when one exists.
function readPackageManifest(directory) {
  const manifestPath = resolve(directory, "bptk.json");
  if (!existsSync(manifestPath)) return null;
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch {
    throw ingestError("invalid_package_manifest", "The directory carries a bptk.json that is not strict JSON");
  }
  if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest) || manifest.schema_version !== 1) {
    throw ingestError("invalid_package_manifest", "The directory bptk.json requires schema_version 1");
  }
  if (manifest.package_kind === "web_native") {
    // A web-native export must declare its capability set before the host
    // will run it (GS-048); an undeclared or granted capability is refused.
    if (typeof manifest.capability !== "object" || manifest.capability === null) {
      throw ingestError("web_native_capability_required", "A web-native export bptk.json requires a capability object");
    }
    return { schema_version: 1, package_kind: "web_native", capability: manifest.capability };
  }
  if (typeof manifest.executable !== "string") {
    throw ingestError("invalid_package_manifest", "The directory bptk.json requires an executable field");
  }
  return { schema_version: 1, executable: manifest.executable, capability: manifest.capability ?? null };
}

const leastPrivilegeCapability = Object.freeze({
  host_script: false,
  file_system: false,
  network: false,
  process: false,
  device: false,
});

// The web-native capability gate (GS-048): the host grants no capability, so
// the export declaration must deny every capability. Any grant is a refusal
// with the offending key surfaced.
function assertWebNativeCapability(capability) {
  const unknownKey = Object.keys(capability).filter((key) => !(key in leastPrivilegeCapability));
  if (unknownKey.length > 0) {
    throw ingestError("web_native_capability_refused", `The export declares capability the host never serves: ${unknownKey.join(", ")}`);
  }
  const grantedKey = Object.keys(capability).filter((key) => capability[key] !== false);
  if (grantedKey.length > 0) {
    throw ingestError("web_native_capability_refused", `The export declares a granted capability: ${grantedKey.join(", ")}`);
  }
}

// Synthesizes the bundle manifest for an extracted installer payload: the
// largest .exe in the payload becomes the declared executable.
function synthesizePayloadManifest(outputDir, extraction) {
  const executable = extraction.entry
    .filter((entry) => entry.path.toLowerCase().endsWith(".exe"))
    .sort((left, right) => right.size_byte - left.size_byte)[0];
  if (!executable) {
    return { manifest: null, blocker: "The payload carries no executable, so no package manifest was synthesized" };
  }
  const manifest = { schema_version: 1, executable: executable.path };
  writeFileSync(resolve(outputDir, "bptk.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return { manifest, blocker: [] };
}

// Analyzes a plain executable from its bounded prefix: machine, format, and
// whether the bounded i386 probe could ever carry it.
function analyzeExecutable(prefix) {
  if (prefix.length < 64 || prefix[0] !== 0x4d || prefix[1] !== 0x5a) {
    return { format: "unknown", machine: null, probe_eligible: false, reason: "The input does not carry an MZ executable signature" };
  }
  const headerOffset = prefix.readUInt32LE(0x3c);
  if (headerOffset + 26 > prefix.length || prefix.toString("ascii", headerOffset, headerOffset + 4) !== "PE\0\0") {
    return { format: "dos_executable", machine: "i8086", probe_eligible: false, reason: "DOS and 16-bit executables are outside the supported census" };
  }
  const machineCode = prefix.readUInt16LE(headerOffset + 4);
  const optionalSizeByte = prefix.readUInt16LE(headerOffset + 20);
  const magic = optionalSizeByte >= 2 ? prefix.readUInt16LE(headerOffset + 24) : 0;
  const machine = machineCode === 0x14c ? "i386" : machineCode === 0x8664 ? "x86_64" : `0x${machineCode.toString(16)}`;
  if (magic !== 0x10b && magic !== 0x20b) {
    return { format: "pe_unknown", machine, probe_eligible: false, reason: "The optional header magic is outside the PE32 and PE32+ census" };
  }
  const format = magic === 0x10b ? "pe32" : "pe32_plus";
  if (machine !== "i386" || format !== "pe32") {
    return { format, machine, probe_eligible: false, reason: `${machine} execution is the BPTK-031 research path, not the bounded i386 probe` };
  }
  return { format, machine, probe_eligible: true, reason: null };
}

function applyPackagedProbe(outputDir, packageManifest, probeEligibility, blocker) {
  if (!packageManifest?.executable || !outputDir) return probeEligibility;
  const exePath = resolve(outputDir, packageManifest.executable);
  if (!existsSync(exePath)) return probeEligibility;
  try {
    const raw = inspectPath(exePath);
    const analysis = analyzeExecutable(raw.prefix);
    if (analysis.machine && analysis.machine !== "i386") {
      blocker.push(`${analysis.machine} executable are classified but outside the bounded i386 probe`);
    }
    return { is_eligible: analysis.probe_eligible, reason: analysis.reason };
  } catch {
    return probeEligibility;
  }
}

function copyBounded(sourcePath, targetPath) {
  const sizeByte = statSync(sourcePath).size;
  if (sizeByte > packageExecutableCapByte) {
    throw ingestError("bound_input_exceeded", `Executable ${sizeByte} byte exceeds the declared package bound ${packageExecutableCapByte}`);
  }
  copyFileSync(sourcePath, targetPath);
  return sizeByte;
}

// Reads the central directory of a plain zip archive and extracts stored and
// deflate entry under the declared extraction bound. Every escape vector is a
// refusal: an entry path that leaves the output directory, an encrypted entry,
// an unsupported method, and any total or per-entry output beyond the bound.
function extractZipArchive(sourcePath, outputDir) {
  const bound = createExtractionBound();
  const sourceSizeByte = statSync(sourcePath).size;
  if (sourceSizeByte > bound.archive_input_byte) {
    throw ingestError("bound_input_exceeded", `Archive ${sourceSizeByte} byte exceeds the declared bound ${bound.archive_input_byte}`);
  }
  const data = readFileSync(sourcePath);
  let eocdOffset = -1;
  const scanFloor = Math.max(0, data.length - 22 - 65535);
  for (let offset = data.length - 22; offset >= scanFloor; offset -= 1) {
    if (data.readUInt32LE(offset) === 0x06054b50) {
      eocdOffset = offset;
      break;
    }
  }
  if (eocdOffset < 0) {
    throw ingestError("archive_format_unsupported", "The archive carries no zip end-of-central-directory record");
  }
  const entryCount = data.readUInt16LE(eocdOffset + 10);
  const centralOffset = data.readUInt32LE(eocdOffset + 16);
  assertEntryBound(bound, entryCount);
  mkdirSync(outputDir, { recursive: true });
  const writtenFile = [];
  const entry = [];
  let outputByte = 0;
  let centralCursor = centralOffset;
  for (let index = 0; index < entryCount; index += 1) {
    if (centralCursor + 46 > data.length || data.readUInt32LE(centralCursor) !== 0x02014b50) {
      throw ingestError("archive_format_unsupported", "The zip central directory is malformed");
    }
    const flags = data.readUInt16LE(centralCursor + 8);
    const method = data.readUInt16LE(centralCursor + 10);
    const compressedSize = data.readUInt32LE(centralCursor + 20);
    const uncompressedSize = data.readUInt32LE(centralCursor + 24);
    const nameLen = data.readUInt16LE(centralCursor + 28);
    const extraLen = data.readUInt16LE(centralCursor + 30);
    const commentLen = data.readUInt16LE(centralCursor + 32);
    const localOffset = data.readUInt32LE(centralCursor + 42);
    const name = data.toString("utf8", centralCursor + 46, centralCursor + 46 + nameLen);
    centralCursor += 46 + nameLen + extraLen + commentLen;
    if ((flags & 0x1) !== 0) {
      throw ingestError("archive_entry_encrypted", `The zip entry ${name} is encrypted, and encrypted payload is refused`);
    }
    const isDirectory = name.endsWith("/");
    const normalized = isDirectory ? name.slice(0, -1) : name;
    const part = normalized.split(/[\\/]/).filter((segment) => segment.length > 0 && segment !== ".");
    if (part.some((segment) => segment === "..") || /^[a-zA-Z]:/.test(normalized) || normalized.startsWith("/")) {
      throw ingestError("archive_path_escape", `The zip entry ${name} escapes the output directory`);
    }
    assertDepthBound(bound, part.length);
    const targetPath = resolve(outputDir, ...part);
    entry.push({ path: normalized, type: isDirectory ? "directory" : "file", size_byte: isDirectory ? 0 : uncompressedSize });
    if (isDirectory) {
      mkdirSync(targetPath, { recursive: true });
      continue;
    }
    if (localOffset + 30 > data.length || data.readUInt32LE(localOffset) !== 0x04034b50) {
      throw ingestError("archive_format_unsupported", `The zip local header for ${name} is malformed`);
    }
    const localNameLen = data.readUInt16LE(localOffset + 26);
    const localExtraLen = data.readUInt16LE(localOffset + 28);
    const dataOffset = localOffset + 30 + localNameLen + localExtraLen;
    if (dataOffset + compressedSize > data.length) {
      throw ingestError("archive_format_unsupported", `The zip data for ${name} is truncated`);
    }
    assertChunkInputBound(bound, compressedSize);
    assertChunkRatioBound(bound, compressedSize, uncompressedSize);
    if (uncompressedSize > chunkOutputCap(bound, compressedSize)) {
      throw ingestError("bound_output_exceeded", `The zip entry ${name} exceeds its declared output cap`);
    }
    outputByte += uncompressedSize;
    assertOutputBound(bound, outputByte);
    const compressed = data.subarray(dataOffset, dataOffset + compressedSize);
    let content;
    if (method === 0) {
      content = compressed;
    } else if (method === 8) {
      content = inflateRawSync(compressed, { maxOutputLength: chunkOutputCap(bound, compressedSize) });
    } else {
      throw ingestError("archive_entry_method_unsupported", `The zip entry ${name} uses method ${method}, which is not stored or deflate`);
    }
    mkdirSync(resolve(targetPath, ".."), { recursive: true });
    writeFileSync(targetPath, content);
    writtenFile.push({ path: normalized, size_byte: uncompressedSize });
  }
  return {
    schema_version: 1,
    command: "ingest --output",
    input_path: sourcePath,
    installer: null,
    installer_family: "zip",
    version_id: null,
    header_summary: { entry_count: entryCount, folder_count: entry.filter((value) => value.type === "directory").length },
    entry_count: entryCount,
    output_byte: outputByte,
    entry,
    file: writtenFile,
    output_dir: outputDir,
    is_extracted: true,
    refusal: [],
    evidence: ["The zip archive was extracted under the declared bound with stored and deflate method only"],
    bound: describeExtractionBound(bound),
    is_executed: false,
    privacy: { is_local_only: true, is_uploaded: false },
  };
}

// Recovers a bounded 7z archive and stages its real bytes under the declared
// output directory. The 7z container, its LZMA-encoded header, and the LZMA and
// BCJ2 coders are decoded in lib/sevenzip.mjs; every recovered file is CRC-
// verified against the archive digest, and each written target is confined to
// the output directory. A path escape, an encrypted folder, or an unsupported
// coder is a structured refusal that propagates before any write.
function extractSevenZipArchive(sourcePath, outputDir) {
  const bound = createExtractionBound();
  const sourceSizeByte = statSync(sourcePath).size;
  if (sourceSizeByte > bound.archive_input_byte) {
    throw ingestError("bound_input_exceeded", `Archive ${sourceSizeByte} byte exceeds the declared bound ${bound.archive_input_byte}`);
  }
  const data = readFileSync(sourcePath);
  const recovered = readSevenZip(data, { bound });
  mkdirSync(outputDir, { recursive: true });
  const writtenFile = [];
  const entry = [];
  let folderCount = 0;
  for (const item of recovered.file) {
    entry.push({ path: item.path, type: item.type, size_byte: item.size_byte });
    const target = resolve(outputDir, ...item.path.split("/"));
    if (relative(outputDir, target).startsWith(`..${sep}`) || target === outputDir) {
      throw ingestError("archive_path_escape", `The 7z entry ${item.path} escapes the output directory`);
    }
    if (item.type === "directory") {
      folderCount += 1;
      mkdirSync(target, { recursive: true });
      continue;
    }
    mkdirSync(resolve(target, ".."), { recursive: true });
    writeFileSync(target, item.content);
    writtenFile.push({ path: item.path, size_byte: item.size_byte });
  }
  return {
    schema_version: 1,
    command: "ingest --output",
    input_path: sourcePath,
    installer: null,
    installer_family: "7z",
    version_id: null,
    header_summary: { entry_count: recovered.entry_count, folder_count: folderCount },
    entry_count: recovered.entry_count,
    output_byte: recovered.output_byte,
    entry,
    file: writtenFile,
    output_dir: outputDir,
    is_extracted: true,
    refusal: [],
    evidence: recovered.evidence,
    bound: describeExtractionBound(bound),
    is_executed: false,
    privacy: { is_local_only: true, is_uploaded: false },
  };
}

// Packages a plain Windows PE: the executable is copied into the output
// directory and a minimal opt-in manifest is synthesized. The probe stays
// opt-in: the manifest declares the executable without an execution profile.
function packagePlainExecutable(inputPath, outputDir, executableName) {
  mkdirSync(outputDir, { recursive: true });
  const targetPath = resolve(outputDir, executableName);
  const sizeByte = copyBounded(inputPath, targetPath);
  // The synthesized manifest carries the default least-privilege capability
  // block (GS-090): every capability denied, no grant the runtime could serve.
  const manifest = {
    schema_version: 1,
    executable: executableName,
    capability: { host_script: false, file_system: false, network: false, process: false, device: false },
  };
  writeFileSync(resolve(outputDir, "bptk.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return { manifest, executable_name: executableName, executable_size_byte: sizeByte };
}

export function ingestInput(input, option = {}) {
  const outputDir = option.output ? resolve(option.output) : null;
  // The report carries classification and census; the raw value carries the
  // bounded prefix that executable analysis reads.
  // The import boundary (GS-088, GS-089) runs on the threat-scanned
  // inspection: protection evidence and a flagged threat refuse the input
  // before any staging artifact is written, so a refused input never leaves
  // an unwrap, patch, or partial payload behind.
  const inspection = inspectWithThreat(input);
  const raw = inspectPath(input);
  assertImportSafety(inspection);
  const isDirectory = raw.type === "directory";
  const blocker = [];
  let extraction = null;
  let packaged = null;
  let packageManifest = null;
  let installerKind = null;
  let probeEligibility = { is_eligible: false, reason: null };
  let isWebNativeStaged = false;

  if (isDirectory) {
    if (inspection.classification === "web_native_export") {
      // A web-native export boots in the host only under a declared
      // least-privilege capability manifest (GS-048).
      packageManifest = readPackageManifest(inspection.input_path);
      if (packageManifest === null || packageManifest.package_kind !== "web_native") {
        throw ingestError("web_native_manifest_required", "A web-native export requires a bptk.json declaring package_kind web_native and its capability set");
      }
      assertWebNativeCapability(packageManifest.capability);
      isWebNativeStaged = true;
      blocker.push("The web-native export is validated, but the browser host runtime that boots it is absent");
    } else {
      packageManifest = readPackageManifest(inspection.input_path);
      if (packageManifest === null) blocker.push("The directory carries no bptk.json, so it is not yet a BPTK package");
    }
  } else if (inspection.classification === "zip_archive") {
    if (outputDir === null) {
      throw ingestError("archive_ingest_unimplemented", "ZIP archive staging needs an output directory; pass --output to stage the archive payload under the declared bound");
    }
    extraction = extractZipArchive(inspection.input_path, outputDir);
    const synthesized = synthesizePayloadManifest(outputDir, extraction);
    packageManifest = synthesized.manifest;
    blocker.push(...synthesized.blocker);
    probeEligibility = applyPackagedProbe(outputDir, packageManifest, probeEligibility, blocker);
  } else if (isSevenZip(raw.prefix)) {
    if (outputDir === null) {
      throw ingestError("archive_ingest_unimplemented", "7z archive staging needs an output directory; pass --output to stage the archive payload under the declared bound");
    }
    // Extraction refusals (path escape, encrypted or unsupported coder) are
    // security boundaries and propagate before any staging artifact is written.
    extraction = extractSevenZipArchive(inspection.input_path, outputDir);
    const synthesized = synthesizePayloadManifest(outputDir, extraction);
    packageManifest = synthesized.manifest;
    blocker.push(...synthesized.blocker);
    probeEligibility = applyPackagedProbe(outputDir, packageManifest, probeEligibility, blocker);
  } else {
    installerKind = detectInstaller(inspection.input_path);
    if (installerKind !== null) {
      // Extraction refusals are security boundaries and propagate.
      extraction = extractInstaller(inspection.input_path, { extract: outputDir });
      if (outputDir !== null) {
        const synthesized = synthesizePayloadManifest(outputDir, extraction);
        packageManifest = synthesized.manifest;
        blocker.push(...synthesized.blocker);
      }
    } else {
      const analysis = analyzeExecutable(raw.prefix);
      probeEligibility = { is_eligible: analysis.probe_eligible, reason: analysis.reason };
      if (analysis.format === "unknown" || analysis.format === "dos_executable" || analysis.format === "pe_unknown") {
        throw ingestError("unsupported_executable_format", analysis.reason);
      }
      if (outputDir !== null) {
        packaged = packagePlainExecutable(inspection.input_path, outputDir, raw.input_name);
        packageManifest = packaged.manifest;
      }
      if (analysis.machine !== "i386") blocker.push(`${analysis.machine} executable are classified but outside the bounded i386 probe`);
    }
  }

  const isPackaged = !isDirectory && packageManifest !== null;
  const state = isWebNativeStaged
    ? "web_native_host_pending"
    : isPackaged
      ? "packaged_no_runtime"
      : extraction?.is_extracted
      ? "extracted_no_runtime"
      : extraction
        ? "extractable_no_runtime"
        : isDirectory
          ? "package_ready"
          : "classified_no_runtime";

  return {
    schema_version: 1,
    command: option.output ? "ingest --output" : "ingest",
    input_path: inspection.input_path,
    input_type: inspection.input_type,
    classification: inspection.classification,
    census: inspection.census,
    detection: {
      installer: installerKind,
      probe_eligible: probeEligibility.is_eligible,
      probe_reason: probeEligibility.reason,
    },
    extraction,
    package: packaged,
    package_manifest: packageManifest,
    output_dir: outputDir,
    is_ingested: isPackaged,
    state,
    is_staged: false,
    is_executed: false,
    blocker,
    privacy: { is_local_only: true, is_uploaded: false },
  };
}

// The cross-lane fallback chain (GS-050). Without it a title dies at the first
// failed precondition even when a lower-ranked lane would carry it. This
// consumes the front-door ranking and, for each candidate lane in confidence
// order, evaluates a structural precondition: the first lane whose precondition
// holds becomes the carried candidate; every skipped lane records why it was
// skipped; when every ranked lane is exhausted the chain terminates in a
// bounded no_lane state. A carried candidate is a structural match only — it
// never asserts the title runs, so the chain is honest while every lane's own
// runtime benchmark stays red.
const lanePrecondition = Object.freeze({
  binary_i386: (context) => (context.inspection.census.route === "refuse"
    ? { ok: false, reason: "census protection evidence refuses the binary lane" }
    : context.inspection.classification === "pe32"
      ? { ok: true, reason: "a PE32/i386 image is a binary-lane candidate" }
      : { ok: false, reason: "the input is not a PE32 image" }),
  binary_x64_research: () => ({ ok: false, reason: "the x86-64 research lane has no passing benchmark to carry a title" }),
  web_native: (context) => (context.inspection.classification === "web_native_export"
    ? { ok: true, reason: "an index.html export with a WebAssembly payload is a web-native candidate" }
    : { ok: false, reason: "no web-native export was detected" }),
  source_project: (context) => (context.source.build_system !== null
    ? { ok: true, reason: `a ${context.source.build_system} source tree is a source-lane candidate` }
    : { ok: false, reason: "no build system was detected in the source tree" }),
  engine_asset: (context) => (context.inspection.census.engine.family !== null
    ? { ok: true, reason: `the ${context.inspection.census.engine.family} engine fingerprint is an engine-lane candidate` }
    : { ok: false, reason: "no engine family was fingerprinted" }),
  emulator_legacy: (context) => (context.emulator.is_admitted
    ? { ok: true, reason: `a pre-Win32 ${context.emulator.era} image is an emulator-lane candidate` }
    : { ok: false, reason: "the input is not a pre-Win32 image" }),
  archive_import: () => ({ ok: true, reason: "an archive is a bounded-extraction candidate" }),
  no_lane: () => ({ ok: false, reason: "the terminal no-lane state carries nothing" }),
});

export function resolveFallbackChain(input) {
  const inspection = inspectInput(input);
  const context = {
    inspection,
    source: diagnoseSourcePort(input),
    emulator: admitEmulatorLane(input),
  };
  const ranked = inspection.lane_decision.ranked;
  const hop = [];
  let carried = null;
  // Bounded by the taxonomy length so a chain can never loop.
  for (const candidate of ranked.slice(0, inspection.lane_decision.taxonomy.length)) {
    const predicate = lanePrecondition[candidate.lane] ?? (() => ({ ok: false, reason: "the lane has no precondition" }));
    const verdict = predicate(context);
    if (verdict.ok) {
      carried = { lane: candidate.lane, confidence: candidate.confidence, reason: verdict.reason };
      break;
    }
    hop.push({ lane: candidate.lane, confidence: candidate.confidence, reason: verdict.reason });
  }
  return {
    schema_version: 1,
    command: "route --fallback",
    input_path: inspection.input_path,
    classification: inspection.classification,
    ranked_lane: ranked.map((entry) => entry.lane),
    hop,
    carried_lane: carried ? carried.lane : "no_lane",
    carried_confidence: carried ? carried.confidence : 0,
    state: carried ? "candidate" : "no_lane",
    is_terminal_bounded: true,
    is_executed: false,
    is_uploaded: false,
    note: carried
      ? "A carried candidate is a structural lane match; it does not assert the title runs."
      : "No lane precondition held; the chain terminated in the bounded no-lane state.",
  };
}

export function formatFallbackChain(report) {
  return [
    `Input: ${report.input_path}`,
    `Classification: ${report.classification}`,
    `Ranked lane: ${report.ranked_lane.join(" > ")}`,
    ...report.hop.map((entry) => `Skipped ${entry.lane} (${entry.confidence}): ${entry.reason}`),
    `Carried lane: ${report.carried_lane}${report.state === "candidate" ? ` (${report.carried_confidence})` : ""}`,
    `State: ${report.state}`,
    report.note,
    "Executed: no; the fallback chain never runs the input",
  ].join("\n");
}

export function formatIngest(report) {
  return [
    `Input: ${report.input_path}`,
    `Classification: ${report.classification}`,
    `State: ${report.state}`,
    `Census route: ${report.census.route}`,
    ...(report.census.engine.family ? [`Census engine: ${report.census.engine.family} → ${report.census.engine.route}`] : []),
    ...(report.extraction
      ? [
          `Installer: ${report.extraction.installer} (${report.extraction.installer_family})`,
          `Payload entry: ${report.extraction.entry_count} (${report.extraction.output_byte} byte)`,
        ]
      : []),
    ...(report.package ? [`Packaged executable: ${report.package.executable_name} (${report.package.executable_size_byte} byte)`] : []),
    ...(report.package_manifest ? [`Package manifest: ${JSON.stringify(report.package_manifest)}`] : []),
    ...(report.detection.probe_reason
      ? [`Probe: not eligible — ${report.detection.probe_reason}`]
      : report.detection.probe_eligible
        ? ["Probe: eligible for the bounded i386 probe (opt-in via the package manifest)"]
        : []),
    `Ingested: ${report.is_ingested ? `yes → ${report.output_dir}` : "no (plan only)"}`,
    "Executed: no; ingestion never runs the input",
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}
