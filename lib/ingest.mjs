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
import { resolve } from "node:path";
import { detectInstaller, extractInstaller } from "./extract.mjs";
import { InputError, inspectPath } from "./input.mjs";
import { inspectInput } from "./inspect.mjs";

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
  if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest) || manifest.schema_version !== 1 || typeof manifest.executable !== "string") {
    throw ingestError("invalid_package_manifest", "The directory bptk.json requires schema_version 1 and an executable field");
  }
  return { schema_version: 1, executable: manifest.executable };
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

function copyBounded(sourcePath, targetPath) {
  const sizeByte = statSync(sourcePath).size;
  if (sizeByte > packageExecutableCapByte) {
    throw ingestError("bound_input_exceeded", `Executable ${sizeByte} byte exceeds the declared package bound ${packageExecutableCapByte}`);
  }
  copyFileSync(sourcePath, targetPath);
  return sizeByte;
}

// Packages a plain Windows PE: the executable is copied into the output
// directory and a minimal opt-in manifest is synthesized. The probe stays
// opt-in: the manifest declares the executable without an execution profile.
function packagePlainExecutable(inputPath, outputDir, executableName) {
  mkdirSync(outputDir, { recursive: true });
  const targetPath = resolve(outputDir, executableName);
  const sizeByte = copyBounded(inputPath, targetPath);
  const manifest = { schema_version: 1, executable: executableName };
  writeFileSync(resolve(outputDir, "bptk.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return { manifest, executable_name: executableName, executable_size_byte: sizeByte };
}

export function ingestInput(input, option = {}) {
  const outputDir = option.output ? resolve(option.output) : null;
  // The report carries classification and census; the raw value carries the
  // bounded prefix that executable analysis reads.
  const inspection = inspectInput(input);
  const raw = inspectPath(input);
  const isDirectory = raw.type === "directory";
  const blocker = [];
  let extraction = null;
  let packaged = null;
  let packageManifest = null;
  let installerKind = null;
  let probeEligibility = { is_eligible: false, reason: null };

  if (isDirectory) {
    packageManifest = readPackageManifest(inspection.input_path);
    if (packageManifest === null) blocker.push("The directory carries no bptk.json, so it is not yet a BPTK package");
  } else if (inspection.classification === "zip_archive") {
    throw ingestError("archive_ingest_unimplemented", "ZIP archive ingestion is not implemented; extract the archive and ingest the folder or executable");
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
  const state = isPackaged
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
