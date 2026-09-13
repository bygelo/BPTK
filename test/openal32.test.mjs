// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createHleLayout } from "../lib/hle.mjs";
import {
  applyLeftoverSidecarIat,
  encodeLeftoverStub,
  leftoverSidecarIat,
  resolveLeftoverSidecarIat,
} from "../lib/openal32.mjs";
import { mapPe32 } from "../lib/pe.mjs";
import { runPackage } from "../lib/run.mjs";
import { bindSidecarModules } from "../lib/sidecar.mjs";

test("leftover sidecar IAT names DebugBreak as a generic kernel32 stub", () => {
  assert.equal(leftoverSidecarIat.some((entry) => entry.symbol === "DebugBreak"), true);
  const debugBreak = resolveLeftoverSidecarIat("KERNEL32.dll", "DebugBreak");
  assert.equal(debugBreak?.library, "kernel32.dll");
  assert.equal(debugBreak?.argument_count, 0);
  assert.equal(debugBreak?.calling_convention, "stdcall");
  assert.equal(resolveLeftoverSidecarIat("kernel32.dll", "IsDebuggerPresent"), null);
  assert.equal(resolveLeftoverSidecarIat("openal32.dll", "alGenSources"), null);
});

test("the leftover DebugBreak gadget is mov eax,0; ret", () => {
  const gadget = encodeLeftoverStub(resolveLeftoverSidecarIat("kernel32.dll", "DebugBreak"));
  assert.deepEqual([...gadget], [0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3]);
});

test("applyLeftoverSidecarIat patches the IAT and grows an executable page", () => {
  const image = Buffer.alloc(0x2000);
  image.writeUInt32LE(0x00001234, 0x1180);
  const applied = applyLeftoverSidecarIat({
    image,
    section: [{ name: ".text", virtual_address: 0x1000, mapped_size_byte: 0x1000, characteristic: 0x60000020 }],
    load_base: 0x28000000,
    import_entry: [{ library: "kernel32.dll", symbol: "DebugBreak", ordinal: null, iat_rva: 0x1180 }],
    unserved: ["kernel32.dll!DebugBreak", "libcurl.dll!curl_easy_init"],
  });
  assert.equal(applied.unserved.length, 1);
  assert.equal(applied.unserved[0], "libcurl.dll!curl_easy_init");
  assert.equal(applied.leftover_served.length, 1);
  assert.equal(applied.leftover_served[0].address, 0x28002000);
  assert.equal(applied.image.readUInt32LE(0x1180), 0x28002000);
  assert.deepEqual([...applied.image.subarray(0x2000, 0x2006)], [0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3]);
  const leftoverSection = applied.section.find((entry) => entry.name === ".hleiat");
  assert.equal(leftoverSection.virtual_address, 0x2000);
  assert.equal((leftoverSection.characteristic & 0x20000000) !== 0, true);
});

function writePe32({ imageBase, code }) {
  const file = Buffer.alloc(0x800);
  file.writeUInt16LE(0x5a4d, 0);
  file.writeUInt32LE(0x80, 0x3c);
  file.writeUInt32LE(0x00004550, 0x80);
  file.writeUInt16LE(0x14c, 0x84);
  file.writeUInt16LE(1, 0x86);
  file.writeUInt16LE(224, 0x94);
  file.writeUInt16LE(0x10b, 0x98);
  file.writeUInt32LE(0x1000, 0xa8);
  file.writeUInt32LE(imageBase, 0xb4);
  file.writeUInt32LE(0x2000, 0xd0);
  file.writeUInt32LE(0x200, 0xd4);
  file.writeUInt32LE(0x10000, 0xe0);
  file.writeUInt32LE(0x1000, 0xe4);
  file.writeUInt32LE(0x10000, 0xe8);
  file.writeUInt32LE(0x1000, 0xec);
  file.writeUInt32LE(16, 0xf4);
  const sectionOffset = 0x178;
  file.write(".text", sectionOffset);
  file.writeUInt32LE(0x1000, sectionOffset + 8);
  file.writeUInt32LE(0x1000, sectionOffset + 12);
  file.writeUInt32LE((0x60000020 | 0x80000000) >>> 0, sectionOffset + 36);
  file.writeUInt32LE(0x600, sectionOffset + 16);
  file.writeUInt32LE(0x200, sectionOffset + 20);
  Buffer.from(code).copy(file, 0x200);
  return file;
}

function fileOffset(rva) {
  return 0x200 + rva - 0x1000;
}

function createAudioHelperDll() {
  // Export add_one at 0x1001: call [IAT DebugBreak]; mov eax, 7; ret
  const file = writePe32({
    imageBase: 0x28000000,
    code: [
      0xc3,
      0xff, 0x15, 0x50, 0x13, 0x00, 0x28,
      0xb8, 0x07, 0x00, 0x00, 0x00,
      0xc3,
    ],
  });
  file.writeUInt16LE(0x2102, 0x96);
  file.writeUInt32LE(0x1200, 0xf8);
  file.writeUInt32LE(0x80, 0xfc);
  file.writeUInt32LE(0x1300, 0xf8 + 8);
  file.writeUInt32LE(40, 0xf8 + 12);
  const dirRva = 0x1200;
  file.writeUInt32LE(0x1240, fileOffset(dirRva + 12));
  file.writeUInt32LE(1, fileOffset(dirRva + 16));
  file.writeUInt32LE(1, fileOffset(dirRva + 20));
  file.writeUInt32LE(1, fileOffset(dirRva + 24));
  file.writeUInt32LE(0x1230, fileOffset(dirRva + 28));
  file.writeUInt32LE(0x1234, fileOffset(dirRva + 32));
  file.writeUInt32LE(0x1238, fileOffset(dirRva + 36));
  file.writeUInt32LE(0x1001, fileOffset(0x1230));
  file.writeUInt32LE(0x1250, fileOffset(0x1234));
  file.writeUInt16LE(0, fileOffset(0x1238));
  file.write("helper.dll\0", fileOffset(0x1240));
  file.write("add_one\0", fileOffset(0x1250));
  file.writeUInt32LE(0x1340, fileOffset(0x1300));
  file.writeUInt32LE(0, fileOffset(0x1304));
  file.writeUInt32LE(0, fileOffset(0x1308));
  file.writeUInt32LE(0x1380, fileOffset(0x130c));
  file.writeUInt32LE(0x1350, fileOffset(0x1310));
  file.writeUInt32LE(0x1360, fileOffset(0x1340));
  file.writeUInt32LE(0, fileOffset(0x1344));
  file.writeUInt32LE(0x1360, fileOffset(0x1350));
  file.writeUInt32LE(0, fileOffset(0x1354));
  file.writeUInt16LE(0, fileOffset(0x1360));
  file.write("DebugBreak\0", fileOffset(0x1362));
  file.write("kernel32.dll\0", fileOffset(0x1380));
  return file;
}

function createGameExe() {
  const file = writePe32({
    imageBase: 0x400000,
    code: [
      0xb8, 0x06, 0x00, 0x00, 0x00,
      0xff, 0x15, 0x80, 0x11, 0x40, 0x00,
      0xc3,
    ],
  });
  const libraryRva = 0x11c0;
  file.writeUInt32LE(0x1140, 0xf8 + 8);
  file.writeUInt32LE(40, 0xf8 + 12);
  file.writeUInt32LE(0x1170, fileOffset(0x1140));
  file.writeUInt32LE(0, fileOffset(0x1144));
  file.writeUInt32LE(0, fileOffset(0x1148));
  file.writeUInt32LE(libraryRva, fileOffset(0x114c));
  file.writeUInt32LE(0x1180, fileOffset(0x1150));
  file.writeUInt32LE(0x11a0, fileOffset(0x1170));
  file.writeUInt32LE(0, fileOffset(0x1174));
  file.writeUInt32LE(0x11a0, fileOffset(0x1180));
  file.writeUInt32LE(0, fileOffset(0x1184));
  file.writeUInt16LE(0, fileOffset(0x11a0));
  file.write("add_one\0", fileOffset(0x11a2));
  file.write("helper.dll\0", fileOffset(libraryRva));
  return file;
}

function createPackage(context) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-openal32-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
  const executablePath = join(packagePath, "game.exe");
  writeFileSync(executablePath, createGameExe());
  writeFileSync(join(packagePath, "helper.dll"), createAudioHelperDll());
  writeFileSync(join(packagePath, "bptk.json"), JSON.stringify({
    schema_version: 1,
    executable: "game.exe",
    execution: { profile: "i386_probe_v1", instruction_budget_count: 64 },
  }));
  return { packagePath, executablePath };
}

test("sidecar leftover DebugBreak is bound without an HLE row", (context) => {
  const { executablePath } = createPackage(context);
  const mapped = mapPe32(executablePath);
  const layout = createHleLayout({
    ...mapped,
    stack_base: 0x70000000,
    stack_end: 0x70010000,
  });
  const service = bindSidecarModules({
    executablePath,
    import: mapped.import,
    layout,
  });
  assert.equal(service.sidecar_count, 1);
  const helper = service.sidecar[0];
  assert.equal(helper.unserved.includes("kernel32.dll!DebugBreak"), false, JSON.stringify(helper.unserved));
  assert.equal(helper.leftover_served.length, 1);
  assert.equal(helper.leftover_served[0].symbol, "DebugBreak");
  const iatRva = helper.leftover_served[0].iat_rva;
  assert.equal(helper.image.readUInt32LE(iatRva), helper.leftover_served[0].address);
});

test("a sidecar call through leftover DebugBreak returns to the export", (context) => {
  const { packagePath } = createPackage(context);
  const report = runPackage(packagePath);
  assert.equal(report.state, "probe_executed", `state ${report.state}: ${JSON.stringify(report.exception)}`);
  assert.equal(report.stop_reason, "entry_return");
  assert.equal(report.register.eax, 7);
});
