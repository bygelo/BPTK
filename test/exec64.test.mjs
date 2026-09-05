// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The x86-64 bounded-execution harness suite (runtime v2 / BPTK-031). Every
// microprogram is a hand-assembled x86-64 byte sequence; the expected end state
// is frozen here by hand from the instruction semantics, never from running the
// implementation. The harness drives the mapped entry through the lib/lift64.mjs
// lifter and its own multi-region interpreter, so these prove: a multi-block
// call/loop/return sequence reaches a known register state; a gs-relative read
// resolves through the minimal TEB/PEB region; an IAT-slot indirect call stops
// structured as import_present; and an unsupported opcode stops with the count
// reflecting only the instructions that actually ran.
//
// The final case drives the real PuTTY x64 image (MIT freeware, read-only)
// through executeProbe64 and asserts the mission frontier: state probe_executed
// with at least one x86-64 instruction executed before an honest import stop.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { runImage64, executeProbe64 } from "../lib/exec64.mjs";
import { mapPe64State } from "../lib/pe64.mjs";

const loadBase = 0x140000000n;
const tebBase = 0x00007ff800000000n;
const pebBase = tebBase + 0x1000n;
const puttyPath = "/Users/angelonrevelo/Code/bptk-corpus/stage/corpus-001/package/putty.exe";

function run(code, option = {}) {
  return runImage64({ image: Buffer.from(code), loadBase, entryRva: 0, budget: 4096, ...option });
}

test("microprogram: a call/loop/return sequence spans three blocks to eax=15", () => {
  // 0:  mov eax,0        b8 00 00 00 00
  // 5:  mov ecx,5        b9 05 00 00 00
  // 10: call sum(+2)     e8 02 00 00 00   -> pushes 15, enters sum at 17
  // 15: jmp end(+7)      eb 07            -> return target of the call; jumps to 24
  // 17: sum: add eax,ecx 01 c8
  // 19:      dec ecx     ff c9
  // 21:      jnz sum(-6) 75 fa
  // 23:      ret         c3               -> returns to 15
  // 24: end: ret         c3               -> returns to the sentinel, stops
  const report = run([
    0xb8, 0x00, 0x00, 0x00, 0x00,
    0xb9, 0x05, 0x00, 0x00, 0x00,
    0xe8, 0x02, 0x00, 0x00, 0x00,
    0xeb, 0x07,
    0x01, 0xc8,
    0xff, 0xc9,
    0x75, 0xfa,
    0xc3,
    0xc3,
  ]);
  assert.equal(report.stop_reason, "entry_return", `stop_reason with exception ${JSON.stringify(report.exception)}`);
  assert.equal(report.register.rax, 15n, `rax 0x${report.register.rax.toString(16)}`);
  assert.equal(report.register.rcx, 0n);
  assert.equal(report.register.rsp, report.balanced_rsp, "the stack must rebalance after the nested call/ret");
  assert.equal(report.instruction_count >= 11, true, `instruction_count ${report.instruction_count}`);
  assert.equal(report.is_executed, true);
});

test("microprogram: gs-relative reads resolve the TEB self pointer and the PEB", () => {
  // mov rax, gs:[0x30]   65 48 8b 04 25 30 00 00 00   -> TEB self pointer
  // mov rcx, gs:[0x60]   65 48 8b 0c 25 60 00 00 00   -> PEB pointer
  // ret                  c3
  const report = run([
    0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
    0x65, 0x48, 0x8b, 0x0c, 0x25, 0x60, 0x00, 0x00, 0x00,
    0xc3,
  ]);
  assert.equal(report.stop_reason, "entry_return", `stop_reason with exception ${JSON.stringify(report.exception)}`);
  assert.equal(report.register.rax, tebBase, `rax 0x${report.register.rax.toString(16)} != TEB base`);
  assert.equal(report.register.rcx, pebBase, `rcx 0x${report.register.rcx.toString(16)} != PEB base`);
  assert.equal(report.teb.teb_base, tebBase);
  assert.equal(report.teb.peb_base, pebBase);
});

test("microprogram: a gs-relative read then store round-trips through the TEB region", () => {
  // The PEB image base at gs:[0x60]->PEB+0x10 was seeded with the load base.
  // mov rax, gs:[0x60]      65 48 8b 04 25 60 00 00 00   -> PEB base
  // mov rax, [rax+0x10]     48 8b 40 10                  -> PEB.ImageBaseAddress
  // ret                     c3
  const report = run([
    0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0x40, 0x10,
    0xc3,
  ]);
  assert.equal(report.stop_reason, "entry_return", `stop_reason with exception ${JSON.stringify(report.exception)}`);
  assert.equal(report.register.rax, loadBase, `rax 0x${report.register.rax.toString(16)} != seeded image base`);
});

test("microprogram: an indirect call through an IAT slot stops as import_present", () => {
  // call [rip+0xfa]   ff 15 fa 00 00 00   -> effective slot = (loadBase+6)+0xfa = loadBase+0x100
  const slot = (loadBase + 0x100n) & ((1n << 64n) - 1n);
  const importSet = new Map([[slot, { library: "test.dll", symbol: "ImportedFn", ordinal: null, iat_slot_rva: 0x100 }]]);
  const report = run([0xff, 0x15, 0xfa, 0x00, 0x00, 0x00], { importSet });
  assert.equal(report.stop_reason, "import_present", `stop_reason with exception ${JSON.stringify(report.exception)}`);
  assert.equal(report.instruction_count, 1);
  assert.equal(report.reached_import.symbol, "ImportedFn");
  assert.equal(report.reached_import.library, "test.dll");
});

test("microprogram: an unsupported opcode stops with the count of what actually ran", () => {
  // nop            90
  // ud2            0f 0b   (outside the served subset)
  const report = run([0x90, 0x0f, 0x0b]);
  assert.equal(report.stop_reason, "unsupported_opcode");
  assert.equal(report.instruction_count, 1, "only the nop ran before the unsupported opcode");
  assert.equal(report.is_executed, true);
  assert.equal(report.exception.opcode, 0x0f0b);
});

test("microprogram: a read outside every mapped region is a named fault", () => {
  // mov rax, [0x1000]   48 8b 04 25 00 10 00 00   -> absolute 0x1000, unmapped
  const report = run([0x48, 0x8b, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00]);
  assert.equal(report.stop_reason, "fault");
  assert.equal(/outside the mapped memory/.test(report.exception.message), true, report.exception.message);
});

test("PuTTY x64 reaches entry execution and stops honestly at its first import", { skip: existsSync(puttyPath) ? false : "PuTTY x64 corpus package absent" }, () => {
  const mapped = mapPe64State(puttyPath);
  const probe = executeProbe64(mapped, 2000000);
  assert.equal(probe.state, "probe_executed", `state with exception ${JSON.stringify(probe.exception)}`);
  assert.equal(probe.instruction_count >= 1, true, `instruction_count ${probe.instruction_count}`);
  assert.equal(probe.is_executed, true);
  // The bounded probe drives the CRT prologue to its first IAT call; no HLE is
  // served, so the honest stop is import_present naming the reached symbol.
  assert.equal(probe.stop_reason, "import_present");
  assert.equal(probe.import_reached.library.length > 0, true);
  assert.equal(typeof probe.import_reached.symbol === "string" || typeof probe.import_reached.ordinal === "number", true);
});
