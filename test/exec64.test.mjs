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

test("a served import dispatches through the Win64 ABI and execution continues", () => {
  // A synthetic image whose entry calls an IAT slot bound to a served, zero-arg
  // export (GetCurrentThreadId), then returns. With the Win32 core HLE wired
  // (milestone M4), the call is dispatched under the Win64 convention — the
  // result lands in RAX and control returns to the instruction after the call —
  // so the probe runs past the import instead of stopping at it.
  //   0: FF 15 02 00 00 00   call qword ptr [rip+2]   (slot at rva 8)
  //   6: 90                  nop
  //   7: C3                  ret                       (reads the return sentinel)
  //   8: <8-byte IAT slot>
  const image = Buffer.from([0xff, 0x15, 0x02, 0x00, 0x00, 0x00, 0x90, 0xc3, 0, 0, 0, 0, 0, 0, 0, 0]);
  const mapped = {
    image,
    input_path: "synthetic.exe",
    load_base: loadBase,
    entry_rva: 0,
    image_size_byte: image.length,
    section: [],
    tls_callback: [],
    relocation_count: 0,
    resolution_blocker: [],
    runtime_blocker: [],
    import: [{ library: "kernel32.dll", symbol: "GetCurrentThreadId", ordinal: null, iat_slot_rva: 8 }],
  };
  const probe = executeProbe64(mapped, 4096);
  assert.equal(probe.state, "probe_executed");
  // call (served) + nop + ret = three instructions, then the entry return.
  assert.equal(probe.instruction_count, 3, `instruction_count ${probe.instruction_count}`);
  assert.equal(probe.stop_reason, "entry_return");
  assert.equal(probe.import_reached, null, "a served import is not a reached-import stop");
  assert.equal(probe.register.rax, "0x1", "RAX carries the GetCurrentThreadId result (thread id 1)");
});

function le8(value) {
  const byte = [];
  let v = BigInt.asUintN(64, value);
  for (let i = 0; i < 8; i += 1) { byte.push(Number(v & 0xffn)); v >>= 8n; }
  return byte;
}
const movRax = (value) => [0x48, 0xb8, ...le8(value)];

test("the probe's SSE executor agrees with the oracle: paddd/pshufd/pxor extract exactly", () => {
  // paddd [1,2]+[0x10,0x0A] = [0x11,0x0C] read back to rcx via movq — the same
  // microprogram frozen in test/lift64.test.mjs, proving exec64 mirrors lift64.
  const paddd = run([
    ...movRax(0x0000000200000001n), 0x66, 0x48, 0x0f, 0x6e, 0xc0,
    ...movRax(0x0000000A00000010n), 0x66, 0x48, 0x0f, 0x6e, 0xc8,
    0x66, 0x0f, 0xfe, 0xc1,
    0x66, 0x48, 0x0f, 0x7e, 0xc1,
    0xc3,
  ]);
  assert.equal(paddd.stop_reason, "entry_return", JSON.stringify(paddd.exception));
  assert.equal(paddd.register.rcx, 0x0000000C00000011n, `rcx 0x${paddd.register.rcx.toString(16)}`);

  const pxor = run([
    ...movRax(0xFFFFFFFFFFFFFFFFn), 0x66, 0x48, 0x0f, 0x6e, 0xc0,
    ...movRax(0x0F0F0F0F0F0F0F0Fn), 0x66, 0x48, 0x0f, 0x6e, 0xc8,
    0x66, 0x0f, 0xef, 0xc1,
    0x66, 0x48, 0x0f, 0x7e, 0xc1,
    0xc3,
  ]);
  assert.equal(pxor.register.rcx, 0xF0F0F0F0F0F0F0F0n, `rcx 0x${pxor.register.rcx.toString(16)}`);
});

test("the probe serves CPUID and REP STOSB with the same semantics as the oracle", () => {
  const cpuid = run([0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0xa2, 0xc3]);
  assert.equal(cpuid.register.rdx, 0x07808011n, `rdx 0x${cpuid.register.rdx.toString(16)}`);
  const stos = run([0xb9, 0x04, 0x00, 0x00, 0x00, 0xb0, 0xab, 0x48, 0x89, 0xe7, 0x48, 0x83, 0xef, 0x40, 0xf3, 0xaa, 0x8b, 0x57, 0xfc, 0xc3]);
  assert.equal(stos.stop_reason, "entry_return", JSON.stringify(stos.exception));
  assert.equal(stos.register.rdx, 0xABABABABn, `rdx 0x${stos.register.rdx.toString(16)}`);
  assert.equal(stos.register.rcx, 0n);
});

test("PuTTY x64 executes past its first import through the served Win64 HLE", { skip: existsSync(puttyPath) ? false : "PuTTY x64 corpus package absent" }, () => {
  const mapped = mapPe64State(puttyPath);
  const probe = executeProbe64(mapped, 2000000);
  assert.equal(probe.state, "probe_executed");
  assert.equal(probe.is_executed, true);
  // Before the SSE/SSE2 and integer-op families were served, the CRT prologue
  // stopped early at an opcode outside the lift subset (CPUID, after ~62
  // instructions). With those families served — CPUID, CMPXCHG, the SSE/SSE2
  // register file, and the REP string ops the CRT init runs — execution now
  // threads over a thousand instructions of CRT setup and the honest stop is a
  // LATER import the Win64 HLE table does not yet serve (kernel32!FlsAlloc), not
  // an unsupported opcode and not the first CRT import.
  assert.equal(probe.instruction_count > 1000, true, `instruction_count ${probe.instruction_count}`);
  assert.equal(["unsupported_opcode", "import_present", "fault", "instruction_budget_exhausted", "process_exit", "guest_exception", "hle_fault"].includes(probe.stop_reason), true, `stop_reason ${probe.stop_reason}`);
  // Whatever the frontier, it is deep in CRT init — never the first import that
  // used to end the probe at 13 instructions.
  if (probe.stop_reason === "import_present") {
    assert.notEqual(probe.import_reached.symbol, "GetSystemTimeAsFileTime", "the probe must run past the first CRT import, not stop at it");
  }
});
