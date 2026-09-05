// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The source lane (GS-045): before any browser build can run, the source lane
// must stop being manual per project. This surface autodetects the build
// system generically from marker files (never `if (project === …)`), pins the
// Emscripten adapter patch set that lane declares for that system, and derives
// a reproducibility digest over the detected inputs plus the pinned patch set
// so a clean-environment rebuild can be compared byte-for-byte against the
// same plan. No compiler runs and nothing is written during diagnosis; the
// honest terminal state stays blocked until emcc is present and the browser
// adapter lands.

import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, extname, relative, resolve, sep } from "node:path";
import { inspectInput } from "./inspect.mjs";
import { getToolchain } from "./toolchain.mjs";

// The build systems the source lane recognizes, ordered by specificity so the
// most-declarative system wins when a tree carries more than one marker. Each
// carries the pinned Emscripten adapter step that lane runs in place of the
// native driver — the patch set is data, so a new system is one row, not code.
const buildSystemSignature = Object.freeze([
  { system: "cmake", marker: Object.freeze(["cmakelists.txt"]), native_driver: "cmake", emscripten_wrapper: "emcmake cmake", pinned_patch: "emscripten/cmake/Modules/Platform/Emscripten.cmake" },
  { system: "meson", marker: Object.freeze(["meson.build"]), native_driver: "meson", emscripten_wrapper: "meson --cross-file emscripten", pinned_patch: "emscripten/cross/emscripten.txt" },
  { system: "autotools", marker: Object.freeze(["configure.ac", "configure.in", "makefile.am"]), native_driver: "autoreconf", emscripten_wrapper: "emconfigure ./configure", pinned_patch: "emscripten/autotools/config.site" },
  { system: "premake", marker: Object.freeze(["premake5.lua", "premake4.lua"]), native_driver: "premake5", emscripten_wrapper: "premake5 gmake2 && emmake make", pinned_patch: "emscripten/premake/emscripten.lua" },
  { system: "scons", marker: Object.freeze(["sconstruct"]), native_driver: "scons", emscripten_wrapper: "emscons scons", pinned_patch: "emscripten/scons/site_scons/emscripten.py" },
  { system: "msbuild", marker: Object.freeze([]), marker_extension: Object.freeze([".sln", ".vcxproj"]), native_driver: "msbuild", emscripten_wrapper: "no direct Emscripten driver; requires CMake or Make regeneration", pinned_patch: null },
  { system: "make", marker: Object.freeze(["makefile", "gnumakefile"]), native_driver: "make", emscripten_wrapper: "emmake make", pinned_patch: "emscripten/make/emscripten.mk" },
]);

// A bounded shallow walk of the project tree that collects the base name and
// extension of every regular file, so detection never depends on how deep a
// marker sits and never follows an unbounded tree.
const scanDepthBound = 4;
const scanEntryBound = 4096;

function collectProjectFile(projectPath) {
  const collected = [];
  const stack = [{ dir: projectPath, depth: 0 }];
  while (stack.length > 0 && collected.length < scanEntryBound) {
    const { dir, depth } = stack.pop();
    let entry;
    try {
      entry = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const child of entry) {
      if (child.name.startsWith(".")) continue;
      const childPath = resolve(dir, child.name);
      if (child.isDirectory()) {
        if (depth < scanDepthBound) stack.push({ dir: childPath, depth: depth + 1 });
      } else if (child.isFile()) {
        collected.push({
          path: relative(projectPath, childPath).split(sep).join("/"),
          name: child.name.toLowerCase(),
          extension: extname(child.name).toLowerCase(),
        });
        if (collected.length >= scanEntryBound) break;
      }
    }
  }
  return collected;
}

// Detects every build system present in the tree and ranks them by signature
// specificity. Generic: the ranking is the fixed signature order, never a
// per-project branch.
function detectBuildSystem(file) {
  const detected = [];
  for (const signature of buildSystemSignature) {
    const evidence = file.filter((entry) => {
      if (signature.marker.includes(entry.name)) return true;
      if (signature.marker_extension && signature.marker_extension.includes(entry.extension)) return true;
      return false;
    });
    if (evidence.length === 0) continue;
    detected.push({
      system: signature.system,
      native_driver: signature.native_driver,
      emscripten_wrapper: signature.emscripten_wrapper,
      pinned_patch: signature.pinned_patch,
      is_browser_adaptable: signature.pinned_patch !== null,
      evidence: evidence.map((entry) => entry.path).sort(),
    });
  }
  return detected;
}

// The reproducibility digest: a stable hash over the sorted detected file
// inventory and the pinned patch set of the chosen system. A clean-environment
// rebuild that produces the same inventory and pins the same patch set derives
// the same digest, so plan reproducibility is an assertable property even
// before a compiler exists to produce a binary.
function reproducibilityDigest(file, chosen) {
  const manifest = {
    schema_version: 1,
    file: file.map((entry) => entry.path).sort(),
    build_system: chosen ? chosen.system : null,
    pinned_patch: chosen ? chosen.pinned_patch : null,
    emscripten_wrapper: chosen ? chosen.emscripten_wrapper : null,
  };
  return `sha256:${createHash("sha256").update(JSON.stringify(manifest)).digest("hex")}`;
}

export function diagnoseSourcePort(project) {
  const inspection = inspectInput(project);
  const toolchain = getToolchain();
  let file = [];
  try {
    if (statSync(inspection.input_path).isDirectory()) file = collectProjectFile(inspection.input_path);
  } catch {
    file = [];
  }
  const detected = detectBuildSystem(file);
  const chosen = detected[0] ?? null;
  const blocker = [];
  if (inspection.classification !== "source_project") blocker.push("Input is not a C or C++ project with native build metadata");
  if (detected.length === 0) blocker.push("No recognized build system was detected in the project tree");
  if (chosen && !chosen.is_browser_adaptable) blocker.push(`The detected ${chosen.system} build has no direct Emscripten driver and needs CMake or Make regeneration`);
  if (!toolchain.emcc) blocker.push("Emscripten emcc is not installed or not on PATH");
  if (!toolchain.emrun) blocker.push("Emscripten emrun is not installed or not on PATH");
  blocker.push("The SDL/OpenGL browser adapter and clean-browser package step are not implemented");
  return {
    schema_version: 1,
    command: "port --source",
    project_path: inspection.input_path,
    classification: inspection.classification,
    toolchain,
    detected_build_system: detected,
    build_system: chosen ? chosen.system : null,
    pinned_patch: chosen ? chosen.pinned_patch : null,
    emscripten_wrapper: chosen ? chosen.emscripten_wrapper : null,
    reproducibility_digest: reproducibilityDigest(file, chosen),
    state: "blocked",
    blocker,
    output_path: null,
    is_package_emitted: false,
  };
}

export function formatSourcePort(report) {
  const detectionLine = report.detected_build_system.length === 0
    ? ["Build system: none detected"]
    : report.detected_build_system.map((entry) => `Build system: ${entry.system} (${entry.evidence.join(", ")}) -> ${entry.emscripten_wrapper}`);
  return [
    `Project: ${report.project_path}`,
    `Classification: ${report.classification}`,
    `State: ${report.state}`,
    `clang: ${report.toolchain.clang ?? "missing"}`,
    `cmake: ${report.toolchain.cmake ?? "missing"}`,
    `ninja: ${report.toolchain.ninja ?? "missing"}`,
    `emcc: ${report.toolchain.emcc ?? "missing"}`,
    `emrun: ${report.toolchain.emrun ?? "missing"}`,
    ...detectionLine,
    `Pinned patch set: ${report.pinned_patch ?? "none"}`,
    `Reproducibility digest: ${report.reproducibility_digest}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
    "No scaffold or browser package was emitted",
  ].join("\n");
}
