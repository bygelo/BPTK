// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { extname, resolve } from "node:path";
import { censusInput } from "./census.mjs";
import { inspectPath, readPrefix } from "./input.mjs";

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
  const isWebNativeExport = filePath.some((path) => path === "index.html" || path.endsWith("/index.html"))
    && filePath.some((path) => path.endsWith(".wasm"));
  if (isWebNativeExport) {
    return { classification: "web_native_export", lane: "web_native", machine: null, evidence: ["index.html with a WebAssembly payload"] };
  }
  if (filePath.includes("bptk.json")) {
    try {
      const manifest = JSON.parse(readFileSync(resolve(value.input_path, "bptk.json"), "utf8"));
      const executable = typeof manifest.executable === "string" ? manifest.executable : null;
      if (executable && filePath.includes(executable.toLowerCase())) {
        const pe = parsePe(readPrefix(resolve(value.input_path, executable), 4096));
        if (pe && pe.format !== "dos_executable" && pe.format !== "pe_unknown") {
          return {
            classification: pe.format,
            lane: pe.format === "pe32" && pe.machine === "i386" ? "binary" : "blocked",
            machine: pe.machine,
            evidence: [`package executable ${executable} machine=${pe.machine}`],
          };
        }
      }
    } catch {
      // A malformed manifest falls through to the plain folder classification.
    }
  }
  if (isBuildFilePresent && sourceCount > 0) {
    return { classification: "source_project", lane: "source", machine: null, evidence: [`${sourceCount} C/C++ source file`, "native build metadata"] };
  }
  if (engineAsset) {
    return { classification: "engine_asset_folder", lane: "engine", machine: null, evidence: [`engine asset: ${engineAsset}`] };
  }
  return { classification: "folder", lane: "blocked", machine: null, evidence: [`${filePath.length} regular file`] };
}

// The diagnose-and-route front door (GS-043): the eight-lane taxonomy with a
// ranked decision and evidence-weighted confidence over the classification and
// census. A mislabel is a hard failure in the routing test, and an unmatched
// input lands in no_lane rather than pretending a lane matched.
const laneTaxonomy = Object.freeze([
  "binary_i386",
  "binary_x64_research",
  "web_native",
  "source_project",
  "engine_asset",
  "archive_import",
  "emulator_legacy",
  "no_lane",
]);

function routeLanes(context) {
  const { classification, machine, census, is_directory } = context;
  const ranked = [];
  const push = (lane, confidence, reason) => ranked.push({ lane, confidence, reason });
  if (classification === "pe32" && machine === "i386") {
    push("binary_i386", 0.9, "a PE32 i386 image is the bounded probe's own input");
  } else if (classification === "pe32_plus" || (classification === "pe32" && machine === "x86_64")) {
    push("binary_x64_research", 0.7, "an x86-64 image is the research lane until a passing benchmark exists");
  }
  if (classification === "web_native_export") {
    push("web_native", 0.9, "an index.html export with a WebAssembly payload boots in the host");
  }
  if (classification === "source_project") {
    push("source_project", 0.8, "a native source tree routes to the source-assisted lane");
  }
  if (classification === "engine_asset_folder" || census?.engine?.family !== null && census?.engine?.family !== undefined) {
    push("engine_asset", 0.8, census?.engine?.family
      ? `the ${census.engine.family} fingerprint routes to ${census.engine.route}`
      : "an engine asset folder routes to the open reimplementation lane");
  }
  if (classification === "zip_archive" || classification === "installer_container") {
    push("archive_import", 0.7, "a container payload routes to the bounded import extractor");
  }
  if (classification === "dos_executable") {
    push("emulator_legacy", 0.6, "a pre-Win32 executable routes to the sandboxed emulator lane");
  }
  if (ranked.length === 0) {
    push("no_lane", 0.5, "no lane signal matched; the input stays unclassified");
  }
  ranked.sort((left, right) => right.confidence - left.confidence);
  return { schema_version: 1, taxonomy: laneTaxonomy, ranked, primary_lane: ranked[0].lane, is_executed: false, is_uploaded: false };
}

export function inspectInput(input) {
  const value = inspectPath(input);
  let classification;
  let lane;
  let evidence = [];
  const blocker = [];
  const warning = [];

  let machine = null;
  if (value.type === "directory") {
    ({ classification, lane, machine, evidence } = classifyDirectory(value));
    const symlinkCount = value.entry.filter((entry) => entry.type === "symlink").length;
    if (symlinkCount > 0) warning.push(`${symlinkCount} symbolic link ignored`);
  } else {
    const suffix = extname(value.input_name).toLowerCase();
    const pe = parsePe(value.prefix);
    if (pe) {
      classification = pe.format;
      machine = pe.machine;
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

  // The static middleware, copy-protection, and engine census (BPTK-037 and
  // BPTK-043) runs over the bounded prefix and directory listing without
  // executing the input. A refuse route blocks the lane outright.
  const census = censusInput(value.input_name, value.prefix, value.entry);
  if (census.route === "refuse") {
    lane = "blocked";
    for (const signature of census.protection) {
      blocker.push(`The ${signature.family} census evidence (${signature.evidence}) refuses a portability claim; no protection is circumvented`);
    }
  } else if (census.route === "extract") {
    blocker.push("The cabinet census routes this input to the bounded import extractor");
  }
  if (census.engine.family !== null) {
    evidence.push(`engine fingerprint ${census.engine.family} routes to the open reimplementation ${census.engine.route}`);
  }

  return {
    schema_version: 1,
    command: "inspect",
    input_path: value.input_path,
    input_type: value.type,
    size_byte: value.size_byte,
    classification,
    lane_decision: routeLanes({ classification, machine, census, is_directory: value.type === "directory" }),
    lane,
    compatibility_state: "classified",
    census,
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
    `Census route: ${report.census.route}`,
    ...report.census.middleware.map((entry) => `Census middleware: ${entry.family} (${entry.dependency})`),
    ...report.census.protection.map((entry) => `Census protection: ${entry.family} (${entry.evidence})`),
    ...(report.census.engine.family ? [`Census engine: ${report.census.engine.family} → ${report.census.engine.route}`] : []),
    ...report.evidence.map((entry) => `Evidence: ${entry}`),
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
    ...report.warning.map((entry) => `Warning: ${entry}`),
    "Privacy: local-only; not uploaded; not executed",
  ].join("\n");
}
