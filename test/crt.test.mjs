// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Leftover ucrtbase sidecar IAT: heap walk/validate/compact/query,
// SetLocalTime, console input, TzSpecificLocalTimeToSystemTime, Beep.
// Generic kernel32 HLE — no title branch.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { buildCrtConformanceCaseTable, crtExportTable } from "../lib/crt.mjs";
import { runConformanceSuite } from "../lib/conformance.mjs";
import { createConformanceImplementation, createConformanceMachine, resolveHleExport } from "../lib/hle.mjs";

const leftover = [
  "HeapQueryInformation",
  "HeapCompact",
  "HeapWalk",
  "HeapValidate",
  "SetLocalTime",
  "PeekConsoleInputA",
  "GetNumberOfConsoleInputEvents",
  "ReadConsoleInputW",
  "TzSpecificLocalTimeToSystemTime",
  "Beep",
];

function invoke(guest, symbol, argument) {
  return guest.invokeExport(guest.lookupExport("kernel32.dll", symbol), argument);
}

test("the CRT leftover table is the remesure ucrtbase sidecar IAT and is generic kernel32", () => {
  assert.deepEqual(crtExportTable.map((row) => row.symbol), leftover);
  assert.ok(crtExportTable.every((row) => row.library === "kernel32.dll"));
  const source = readFileSync(fileURLToPath(new URL("../lib/crt.mjs", import.meta.url)), "utf8");
  assert.equal(source.includes("SuperTux"), false, "no title branch");
  assert.equal(source.includes("title ==="), false);
});

test("api-ms-win-core leftover names resolve to the kernel32 CRT rows", () => {
  const forward = [
    ["api-ms-win-core-heap-l1-1-0.dll", "HeapQueryInformation"],
    ["api-ms-win-core-heap-l1-1-0.dll", "HeapCompact"],
    ["api-ms-win-core-heap-l1-1-0.dll", "HeapWalk"],
    ["api-ms-win-core-heap-l1-1-0.dll", "HeapValidate"],
    ["api-ms-win-core-sysinfo-l1-1-0.dll", "SetLocalTime"],
    ["api-ms-win-core-console-l1-1-0.dll", "PeekConsoleInputA"],
    ["api-ms-win-core-console-l1-1-0.dll", "GetNumberOfConsoleInputEvents"],
    ["api-ms-win-core-console-l1-1-0.dll", "ReadConsoleInputW"],
    ["api-ms-win-core-timezone-l1-1-0.dll", "TzSpecificLocalTimeToSystemTime"],
    ["api-ms-win-core-util-l1-1-0.dll", "Beep"],
  ];
  for (const [library, symbol] of forward) {
    const row = resolveHleExport(library, symbol);
    assert.ok(row, `${library}!${symbol} stays unserved`);
    assert.equal(row.library, "kernel32.dll");
    assert.equal(row.symbol, symbol);
  }
});

test("HeapWalk walks the region then busy blocks then ERROR_NO_MORE_ITEMS", () => {
  const { guest } = createConformanceMachine();
  const heap = invoke(guest, "HeapCreate", [0, 0, 0]);
  const block = invoke(guest, "HeapAlloc", [heap, 0, 32]);
  assert.notEqual(block, 0);
  const entry = 0x00150100;
  guest.memory.writeBlock(entry, Buffer.alloc(28));
  assert.equal(invoke(guest, "HeapWalk", [heap, entry]), 1);
  assert.equal(guest.memory.readMemory(entry + 10, 2), 0x0001, "first row is PROCESS_HEAP_REGION");
  assert.equal(invoke(guest, "HeapWalk", [heap, entry]), 1);
  assert.equal(guest.memory.readMemory(entry, 4), block >>> 0);
  assert.equal(guest.memory.readMemory(entry + 10, 2), 0x0004, "busy allocation");
  assert.equal(invoke(guest, "HeapWalk", [heap, entry]), 0);
  assert.equal(guest.getLastError(), 259);
  assert.equal(invoke(guest, "HeapValidate", [heap, 0, block]), 1);
  assert.equal(invoke(guest, "HeapValidate", [heap, 0, 0x00ffffff]), 0);
  assert.equal(guest.getLastError(), 87);
});

test("HeapQueryInformation writes HEAP_STANDARD and HeapCompact is the largest free run", () => {
  const { guest } = createConformanceMachine();
  const heap = invoke(guest, "HeapCreate", [0, 0, 0]);
  const dest = 0x00150040;
  const needed = 0x00150000;
  assert.equal(invoke(guest, "HeapQueryInformation", [heap, 0, dest, 4, needed]), 1);
  assert.equal(guest.memory.readMemory(dest, 4), 0);
  assert.equal(guest.memory.readMemory(needed, 4), 4);
  assert.equal(invoke(guest, "HeapQueryInformation", [heap, 99, dest, 4, 0]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "HeapCompact", [heap, 0]), 25165808);
});

test("SetLocalTime validates SYSTEMTIME; timezone convert is the UTC identity", () => {
  const { guest } = createConformanceMachine();
  const src = 0x00170000;
  const dest = 0x00150100;
  guest.writeSystemTime(src, { year: 2020, month: 9, day_of_week: 0, day: 13, hour: 12, minute: 0, second: 0, millisecond: 0 });
  assert.equal(invoke(guest, "SetLocalTime", [src]), 1);
  guest.memory.writeMemory(src + 2, 2, 0);
  assert.equal(invoke(guest, "SetLocalTime", [src]), 0);
  assert.equal(guest.getLastError(), 87);
  guest.writeSystemTime(src, { year: 2020, month: 9, day_of_week: 0, day: 13, hour: 12, minute: 0, second: 0, millisecond: 0 });
  assert.equal(invoke(guest, "TzSpecificLocalTimeToSystemTime", [0, src, dest]), 1);
  assert.deepEqual(guest.memory.readBlock(dest, 16), guest.memory.readBlock(src, 16));
});

test("console input reports an empty queue; ReadConsoleInputW stays output-only", () => {
  const { guest } = createConformanceMachine();
  const stdin = invoke(guest, "GetStdHandle", [-10]);
  const count = 0x00150040;
  const buffer = 0x00150100;
  assert.equal(invoke(guest, "PeekConsoleInputA", [stdin, buffer, 1, count]), 1);
  assert.equal(guest.memory.readMemory(count, 4), 0);
  assert.equal(invoke(guest, "GetNumberOfConsoleInputEvents", [stdin, count]), 1);
  assert.equal(guest.memory.readMemory(count, 4), 0);
  assert.equal(invoke(guest, "ReadConsoleInputW", [stdin, buffer, 1, count]), 0);
  assert.equal(guest.getLastError(), 5);
  assert.equal(invoke(guest, "Beep", [750, 250]), 1);
});

test("conformance: every CRT leftover export carries a case and matches the oracle", () => {
  const caseTable = buildCrtConformanceCaseTable();
  const report = runConformanceSuite(caseTable, createConformanceImplementation(), {
    served_export: crtExportTable.map((entry) => `${entry.library}!${entry.symbol}`),
  });
  assert.equal(report.is_coverage_complete, true, `uncovered: ${report.uncovered_export.join(", ")}`);
  assert.equal(report.fail_count, 0, report.result.filter((entry) => !entry.pass).map((entry) => `${entry.case_id}: ${entry.mismatch.join("; ")}`).join("\n"));
});
