// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { admitEmulatorLane, classifyExecutableEra, formatEmulatorLane } from "../lib/emulator.mjs";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

// Builds a minimal image with an MZ header and a chosen new-executable
// signature at e_lfanew; a null signature leaves a plain DOS stub.
function makeImage(signature) {
  const buffer = Buffer.alloc(0x100);
  buffer.write("MZ", 0, "ascii");
  if (signature === null) {
    buffer.writeUInt32LE(0, 0x3c);
    return buffer;
  }
  const newOffset = 0x80;
  buffer.writeUInt32LE(newOffset, 0x3c);
  buffer.write(signature, newOffset, "ascii");
  return buffer;
}

function makeFile(context, name, buffer) {
  const root = mkdtempSync(join(tmpdir(), "bptk-emu-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, name);
  writeFileSync(path, buffer);
  return path;
}

test("the era classifier separates DOS, Win16, Win32, and linear executables by signature", () => {
  assert.equal(classifyExecutableEra(makeImage(null)).kind, "dos");
  assert.equal(classifyExecutableEra(makeImage("NE")).kind, "ne_win16");
  assert.equal(classifyExecutableEra(makeImage("PE\0\0")).kind, "pe");
  assert.equal(classifyExecutableEra(makeImage("LE")).kind, "le_extended");
  assert.equal(classifyExecutableEra(Buffer.from("not an exe")).kind, "not_executable");
});

test("DOS and Win16 input are admitted to the sandboxed emulator lane with host reach denied", (context) => {
  for (const [name, signature] of [["game.exe", null], ["setup16.exe", "NE"], ["vxd.exe", "LE"]]) {
    const report = admitEmulatorLane(makeFile(context, name, makeImage(signature)));
    assert.equal(report.lane, "emulator_legacy");
    assert.equal(report.is_admitted, true);
    assert.equal(report.sandbox.host_filesystem, false);
    assert.equal(report.sandbox.host_network, false);
    assert.equal(report.sandbox.host_process, false);
    assert.equal(report.sandbox.is_persisted, false);
  }
});

test("a Win32 PE image is refused so the emulator lane never swallows a binary-lane title", (context) => {
  const report = admitEmulatorLane(makeFile(context, "win32.exe", makeImage("PE\0\0")));
  assert.equal(report.is_admitted, false);
  assert.equal(report.state, "refused");
  assert.equal(report.lane, "binary");
  assert.equal(report.sandbox, null);
  assert.ok(report.reason.some((line) => line.includes("binary lane")));
});

test("the emulator lane never runs the input and stays blocked until a core is embedded", (context) => {
  // Implemented-but-red (BPTK-094): the lane boundary and sandbox contract
  // exist, but no emulator core is embedded, so admission never becomes
  // execution and the terminal state is blocked, not runnable.
  const report = admitEmulatorLane(makeFile(context, "dos.exe", makeImage(null)));
  assert.equal(report.state, "blocked");
  assert.equal(report.is_emulator_embedded, false);
  assert.equal(report.is_executed, false);
  assert.match(formatEmulatorLane(report), /Sandbox: host reach denied/);
});

test("the emulator lane is reachable at the real CLI and keeps PE32 out", (context) => {
  const dos = makeFile(context, "dos.exe", makeImage(null));
  const win32 = makeFile(context, "win32.exe", makeImage("PE\0\0"));
  const dosRun = spawnSync(process.execPath, [binPath, "emulator", "admit", dos, "--json"], { encoding: "utf8" });
  assert.equal(dosRun.status, 0);
  assert.equal(JSON.parse(dosRun.stdout).lane, "emulator_legacy");
  const win32Run = spawnSync(process.execPath, [binPath, "emulator", "admit", win32, "--json"], { encoding: "utf8" });
  assert.equal(win32Run.status, 0);
  assert.equal(JSON.parse(win32Run.stdout).is_admitted, false);
});
