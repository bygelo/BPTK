// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { diagnoseSourcePort, formatSourcePort } from "../lib/port.mjs";

function makeProject(context, file) {
  const root = mkdtempSync(join(tmpdir(), "bptk-port-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  for (const [path, content] of Object.entries(file)) {
    const full = join(root, path);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, content);
  }
  return root;
}

test("the source lane autodetects a CMake build and pins its Emscripten patch set", (context) => {
  const project = makeProject(context, {
    "CMakeLists.txt": "add_executable(game main.c)\n",
    "src/main.c": "int main(void){return 0;}\n",
  });
  const report = diagnoseSourcePort(project);
  assert.equal(report.classification, "source_project");
  assert.equal(report.build_system, "cmake");
  assert.equal(report.emscripten_wrapper, "emcmake cmake");
  assert.ok(report.pinned_patch.includes("Emscripten.cmake"));
  assert.ok(report.detected_build_system[0].evidence.includes("CMakeLists.txt"));
});

test("the source lane autodetects Make and Meson trees generically", (context) => {
  const make = makeProject(context, { "Makefile": "all:\n\t$(CC) main.c\n", "main.cpp": "int main(){}\n" });
  assert.equal(diagnoseSourcePort(make).build_system, "make");
  const meson = makeProject(context, { "meson.build": "executable('game','main.c')\n", "main.c": "int main(void){return 0;}\n" });
  assert.equal(diagnoseSourcePort(meson).build_system, "meson");
});

test("a more declarative build system outranks a plain Makefile in the same tree", (context) => {
  const project = makeProject(context, {
    "CMakeLists.txt": "add_executable(game main.c)\n",
    "Makefile": "all:\n\techo generated\n",
    "main.c": "int main(void){return 0;}\n",
  });
  const report = diagnoseSourcePort(project);
  assert.equal(report.build_system, "cmake");
  const detected = report.detected_build_system.map((entry) => entry.system);
  assert.ok(detected.includes("cmake") && detected.includes("make"));
  assert.ok(detected.indexOf("cmake") < detected.indexOf("make"));
});

test("the reproducibility digest is stable across runs and moves when the input tree changes", (context) => {
  const first = makeProject(context, { "CMakeLists.txt": "add_executable(game main.c)\n", "main.c": "int main(void){return 0;}\n" });
  const digestA = diagnoseSourcePort(first).reproducibility_digest;
  const digestB = diagnoseSourcePort(first).reproducibility_digest;
  assert.equal(digestA, digestB, "the same clean checkout must derive the same plan digest");
  assert.match(digestA, /^sha256:[0-9a-f]{64}$/);
  const second = makeProject(context, {
    "CMakeLists.txt": "add_executable(game main.c)\n",
    "main.c": "int main(void){return 0;}\n",
    "extra.c": "void extra(void){}\n",
  });
  assert.notEqual(diagnoseSourcePort(second).reproducibility_digest, digestA);
});

test("the source lane stays honestly blocked with no package emitted until emcc and the adapter land", (context) => {
  const project = makeProject(context, { "CMakeLists.txt": "add_executable(game main.c)\n", "main.c": "int main(void){return 0;}\n" });
  const report = diagnoseSourcePort(project);
  // Implemented-but-red (BPTK-090): detection and the pinned plan exist, yet the
  // clean-environment browser build cannot run until Emscripten is present and
  // the SDL/OpenGL adapter is implemented, so nothing is emitted.
  assert.equal(report.state, "blocked");
  assert.equal(report.is_package_emitted, false);
  assert.equal(report.output_path, null);
  assert.ok(report.blocker.some((line) => line.includes("emcc")) || report.blocker.some((line) => line.includes("adapter")));
  assert.match(formatSourcePort(report), /Pinned patch set:/);
});
