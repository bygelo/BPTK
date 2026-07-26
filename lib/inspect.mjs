// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { extname } from "node:path";
import { inspectPath } from "./input.mjs";

const sourceSuffix = new Set([".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"]);
const engineSuffix = new Set([".gob", ".grp", ".pak", ".pk3", ".wad"]);

function parsePe(prefix) {
  if (prefix.length < 64 || prefix[0] !== 0x4d || prefix[1] !== 0x5a) return null;
  const headerOffset = prefix.readUInt32LE(0x3c);
  if (headerOffset + 26 > prefix.length || prefix.toString("ascii", headerOffset, headerOffset + 4) !== "PE\0\0") {
    return { format: "dos_executable", blocker: ["PE header is absent or outside the bounded prefix"] };
  }
  const machineCode = prefix.readUInt16LE(headerOffset + 4);
  const sectionCount = prefix.readUInt16LE(headerOffset + 6);
  const optionalSizeByte = prefix.readUInt16LE(headerOffset + 20);
  const magic = optionalSizeByte >= 2 ? prefix.readUInt16LE(headerOffset + 24) : 0;
  const machine = machineCode === 0x14c ? "i386" : machineCode === 0x8664 ? "x86_64" : `0x${machineCode.toString(16)}`;
  const format = magic === 0x10b ? "pe32" : magic === 0x20b ? "pe32_plus" : "pe_unknown";
  return { format, machine, section_count: sectionCount, optional_size_byte: optionalSizeByte, blocker: [] };
}

function classifyDirectory(value) {
  const filePath = value.entry.filter((entry) => entry.type === "file").map((entry) => entry.path.toLowerCase());
  const isBuildFilePresent = filePath.some((path) => /(^|\/)(cmakelists\.txt|makefile|meson\.build)$/.test(path));
  const sourceCount = filePath.filter((path) => sourceSuffix.has(extname(path))).length;
  const engineAsset = filePath.find((path) => engineSuffix.has(extname(path)));
  if (isBuildFilePresent && sourceCount > 0) {
    return { classification: "source_project", lane: "source", evidence: [`${sourceCount} C/C++ source file`, "native build metadata"] };
  }
  if (engineAsset) {
    return { classification: "engine_asset_folder", lane: "engine", evidence: [`engine asset: ${engineAsset}`] };
  }
  return { classification: "folder", lane: "blocked", evidence: [`${filePath.length} regular file`] };
}

export function inspectInput(input) {
  const value = inspectPath(input);
  let classification;
  let lane;
  let evidence = [];
  const blocker = [];
  const warning = [];

  if (value.type === "directory") {
    ({ classification, lane, evidence } = classifyDirectory(value));
    const symlinkCount = value.entry.filter((entry) => entry.type === "symlink").length;
    if (symlinkCount > 0) warning.push(`${symlinkCount} symbolic link ignored`);
  } else {
    const suffix = extname(value.input_name).toLowerCase();
    const pe = parsePe(value.prefix);
    if (pe) {
      classification = pe.format;
      lane = pe.format === "pe32" && pe.machine === "i386" ? "binary" : "blocked";
      evidence.push(`machine=${pe.machine ?? "unknown"}`, `section_count=${pe.section_count ?? 0}`);
      blocker.push(...pe.blocker);
      if (lane === "blocked") blocker.push("Only the planned PE32/i386 lane matches the initial target");
    } else if (value.prefix.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) {
      classification = "zip_archive";
      lane = "inspect_archive";
      evidence.push("ZIP local-file signature");
    } else if (value.prefix.subarray(0, 8).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]))) {
      classification = "installer_container";
      lane = "blocked";
      evidence.push("OLE compound-file signature");
      blocker.push("Installer execution is prohibited; extraction support is not implemented");
    } else if (engineSuffix.has(suffix)) {
      classification = "engine_asset";
      lane = "engine";
      evidence.push(`engine-family suffix ${suffix}`);
    } else {
      classification = "unknown_file";
      lane = "blocked";
      evidence.push(`suffix=${suffix || "none"}`);
      blocker.push("No supported format signature was detected");
    }
  }

  if (lane !== "blocked") blocker.push(`The ${lane} route is classified but its execution pipeline is not yet passing`);
  return {
    schema_version: 1,
    command: "inspect",
    input_path: value.input_path,
    input_type: value.type,
    size_byte: value.size_byte,
    classification,
    lane,
    compatibility_state: "classified",
    evidence,
    blocker,
    warning,
    privacy: { is_local_only: true, is_uploaded: false, is_executed: false },
  };
}

export function formatInspect(report) {
  return [
    `Input: ${report.input_path}`,
    `Classification: ${report.classification}`,
    `Lane: ${report.lane}`,
    `State: ${report.compatibility_state}`,
    ...report.evidence.map((entry) => `Evidence: ${entry}`),
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
    ...report.warning.map((entry) => `Warning: ${entry}`),
    "Privacy: local-only; not uploaded; not executed",
  ].join("\n");
}
