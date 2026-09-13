// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";
import { createConformanceMachine, listWin32HleExport, resolveHleExport } from "../lib/hle.mjs";
import { listMsvcpHleExport } from "../lib/msvcp.mjs";

function invoke(guest, library, symbol, argument) {
  return guest.invokeExport(guest.lookupExport(library, symbol), argument);
}

test("leftover msvcp140 IAT rows are generic HLE, not a title branch", () => {
  const source = listMsvcpHleExport().map((row) => `${row.library}!${row.symbol}`).join("\n");
  assert.equal(/supertux/i.test(source), false);
  assert.ok(listMsvcpHleExport().some((row) => row.symbol === "CreateThreadpoolWork"));
  assert.ok(listMsvcpHleExport().some((row) => row.symbol === "_CxxThrowException"));
});

test("threadpool and leftover C++ runtime names resolve on the Win32 HLE", () => {
  for (const [library, symbol] of [
    ["kernel32.dll", "CreateThreadpoolWork"],
    ["kernel32.dll", "SubmitThreadpoolWork"],
    ["kernel32.dll", "CloseThreadpoolWork"],
    ["kernel32.dll", "CreateThreadpoolWait"],
    ["kernel32.dll", "CreateThreadpoolTimer"],
    ["kernel32.dll", "InitOnceExecuteOnce"],
    ["kernel32.dll", "CreateSemaphoreExW"],
    ["vcruntime140.dll", "_CxxThrowException"],
    ["vcruntime140.dll", "__CxxFrameHandler3"],
    ["msvcrt.dll", "_initterm_e"],
    ["msvcrt.dll", "terminate"],
    ["api-ms-win-crt-string-l1-1-0.dll", "strcspn"],
  ]) {
    const resolved = resolveHleExport(library, symbol);
    assert.ok(resolved, `${library}!${symbol}`);
    assert.equal(listWin32HleExport().some((row) => row.library === resolved.library && row.symbol === resolved.symbol), true);
  }
});

test("CreateThreadpoolWork queues a real callback and Close releases the object", () => {
  const { guest } = createConformanceMachine();
  assert.equal(invoke(guest, "kernel32.dll", "CreateThreadpoolWork", [0, 0, 0]), 0);
  assert.equal(guest.getLastError(), 87);
  const work = invoke(guest, "kernel32.dll", "CreateThreadpoolWork", [0x401000, 9, 0]);
  assert.ok(work !== 0);
  assert.equal(invoke(guest, "kernel32.dll", "SubmitThreadpoolWork", [work]), 0);
  assert.equal(guest.pending_guest_call?.proc, 0x401000);
  assert.deepEqual(guest.pending_guest_call?.argument, [1, 9, work]);
  assert.equal(invoke(guest, "kernel32.dll", "WaitForThreadpoolWorkCallbacks", [work, 0]), 0);
  assert.equal(invoke(guest, "kernel32.dll", "CloseThreadpoolWork", [work]), 0);
  assert.equal(invoke(guest, "kernel32.dll", "SubmitThreadpoolWork", [work]), 0);
  assert.equal(guest.getLastError(), 6);
});

test("InitOnceExecuteOnce completes a cell and CreateSemaphoreExW is the Ex twin", () => {
  const { guest, memory } = createConformanceMachine();
  const once = 0x00150040;
  memory.writeMemory(once, 4, 0);
  assert.equal(invoke(guest, "kernel32.dll", "InitOnceExecuteOnce", [0, 0x401000, 0, 0]), 0);
  assert.equal(guest.getLastError(), 87);
  assert.equal(invoke(guest, "kernel32.dll", "InitOnceExecuteOnce", [once, 0x401000, 5, 0]), 1);
  assert.equal(memory.readMemory(once, 4) & 1, 1);
  assert.equal(guest.pending_guest_call?.proc, 0x401000);
  const handle = invoke(guest, "kernel32.dll", "CreateSemaphoreExW", [0, 1, 4, 0, 0, 0x1f0003]);
  assert.ok(handle !== 0);
  assert.equal(invoke(guest, "kernel32.dll", "CreateSemaphoreExW", [0, 1, 4, 0, 2, 0]), 0);
  assert.equal(guest.getLastError(), 87);
});

test("leftover CRT string and locale rows are real", () => {
  const { guest, memory } = createConformanceMachine();
  memory.writeBlock(0x00150080, Buffer.from("hello\0reject\0", "latin1"));
  assert.equal(invoke(guest, "msvcrt.dll", "strcspn", [0x00150080, 0x00150086]), 2);
  assert.equal(invoke(guest, "msvcrt.dll", "iswdigit", [0x35]), 1);
  assert.equal(invoke(guest, "msvcrt.dll", "iswspace", [0x41]), 0);
  assert.equal(invoke(guest, "msvcrt.dll", "___lc_codepage_func", []), 1252);
  const pctype = invoke(guest, "msvcrt.dll", "__pctype_func", []);
  assert.ok(pctype !== 0);
  assert.equal(memory.readMemory(pctype + 0x35 * 2, 2) & 0x0004, 0x0004);
});
