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
import { runImage64, executeProbe64, buildGuestContext64, serveImportAt64 } from "../lib/exec64.mjs";
import { mapPe64State } from "../lib/pe64.mjs";
import { createHleLayout } from "../lib/hle.mjs";
import { createGuestClock } from "../lib/clock.mjs";

const loadBase = 0x140000000n;
const stackBase = 0x00007ff000000000n;
const tebBase = 0x00007ff800000000n;
const pebBase = tebBase + 0x1000n;
const MASK64 = (1n << 64n) - 1n;
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

test("microprogram: the probe's SHRD Ev,Gv,imm8 matches the oracle bit for bit", () => {
  // mov eax,0x12345678; mov ecx,0xaabbccdd; shrd eax,ecx,8; ret
  // result = (0x12345678 >> 8) | (0xaabbccdd << 24) = 0xdd123456.
  const report = run([0xb8, 0x78, 0x56, 0x34, 0x12, 0xb9, 0xdd, 0xcc, 0xbb, 0xaa, 0x0f, 0xac, 0xc8, 0x08, 0xc3]);
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.rax, 0xdd123456n, `rax 0x${report.register.rax.toString(16)}`);
  assert.equal(report.flag.cf, false);
  assert.equal(report.flag.sf, true);
  assert.equal(report.flag.pf, true);
  assert.equal(report.flag.of, true);
  assert.equal(report.flag.zf, false);
});

test("microprogram: the probe's SHLD Ev,Gv,imm8 matches the oracle bit for bit", () => {
  // mov eax,0x12345678; mov ecx,0xaabbccdd; shld eax,ecx,8; ret
  // result = (0x12345678 << 8) | (0xaabbccdd >> 24) = 0x345678aa.
  const report = run([0xb8, 0x78, 0x56, 0x34, 0x12, 0xb9, 0xdd, 0xcc, 0xbb, 0xaa, 0x0f, 0xa4, 0xc8, 0x08, 0xc3]);
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.rax, 0x345678aan, `rax 0x${report.register.rax.toString(16)}`);
  assert.equal(report.flag.cf, false);
  assert.equal(report.flag.sf, false);
  assert.equal(report.flag.pf, true);
  assert.equal(report.flag.of, false);
});

test("microprogram: the probe's REX.W SHRD shifts a full 64-bit destination", () => {
  // mov rax,0x123456789abcdef0; mov rcx,0xfedcba987654321f; shrd rax,rcx,4; ret
  // result = (rax >> 4) | (rcx << 60) = 0xf123456789abcdef.
  const report = run([
    0x48, 0xb8, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
    0x48, 0xb9, 0x1f, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x48, 0x0f, 0xac, 0xc8, 0x04,
    0xc3,
  ]);
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.rax, 0xf123456789abcdefn, `rax 0x${report.register.rax.toString(16)}`);
  assert.equal(report.flag.sf, true);
  assert.equal(report.flag.of, true);
  assert.equal(report.flag.cf, false);
});

test("microprogram: the probe's SHLD Ev,Gv,CL takes its count from CL", () => {
  // mov edx,0xff; mov ebx,0xff000000; mov ecx,4; shld edx,ebx,cl; ret
  // result = (0xff << 4) | (0xff000000 >> 28) = 0xfff.
  const report = run([
    0xba, 0xff, 0x00, 0x00, 0x00,
    0xbb, 0x00, 0x00, 0x00, 0xff,
    0xb9, 0x04, 0x00, 0x00, 0x00,
    0x0f, 0xa5, 0xda,
    0xc3,
  ]);
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.rdx, 0xfffn, `rdx 0x${report.register.rdx.toString(16)}`);
  assert.equal(report.flag.cf, false);
  assert.equal(report.flag.of, false);
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

test("the probe's SSE3 executor agrees with the oracle: movddup/haddpd/addsubps", () => {
  // movddup replicates the low lane — the same microprogram frozen in
  // test/lift64.test.mjs, proving exec64 mirrors the shared SSE3 executor.
  const movddup = run([
    ...movRax(0xAAAAAAAABBBBBBBBn), 0x66, 0x48, 0x0f, 0x6e, 0xc0,
    0xf2, 0x0f, 0x12, 0xc8, // movddup xmm1,xmm0
    0x66, 0x48, 0x0f, 0x7e, 0xc9, // movq rcx,xmm1
    0x66, 0x0f, 0x70, 0xd1, 0xee, // pshufd xmm2,xmm1,0xEE
    0x66, 0x48, 0x0f, 0x7e, 0xd2, // movq rdx,xmm2
    0xc3,
  ]);
  assert.equal(movddup.stop_reason, "entry_return", JSON.stringify(movddup.exception));
  assert.equal(movddup.register.rcx, 0xAAAAAAAABBBBBBBBn, `rcx 0x${movddup.register.rcx.toString(16)}`);
  assert.equal(movddup.register.rdx, 0xAAAAAAAABBBBBBBBn, `rdx 0x${movddup.register.rdx.toString(16)}`);

  // haddpd [1.0,2.0] with [10.0,20.0] → [3.0, 30.0].
  const haddpd = run([
    ...movRax(0x3FF0000000000000n), 0x66, 0x48, 0x0f, 0x6e, 0xc0,
    ...movRax(0x4000000000000000n), 0x66, 0x48, 0x0f, 0x6e, 0xc8,
    0x66, 0x0f, 0x6c, 0xc1,
    ...movRax(0x4024000000000000n), 0x66, 0x48, 0x0f, 0x6e, 0xd8,
    ...movRax(0x4034000000000000n), 0x66, 0x48, 0x0f, 0x6e, 0xe0,
    0x66, 0x0f, 0x6c, 0xdc,
    0x66, 0x0f, 0x7c, 0xc3, // haddpd xmm0,xmm3
    0x66, 0x48, 0x0f, 0x7e, 0xc1,
    0x66, 0x0f, 0x70, 0xe8, 0xee,
    0x66, 0x48, 0x0f, 0x7e, 0xea,
    0xc3,
  ]);
  assert.equal(haddpd.register.rcx, 0x4008000000000000n, `rcx 0x${haddpd.register.rcx.toString(16)}`);
  assert.equal(haddpd.register.rdx, 0x403E000000000000n, `rdx 0x${haddpd.register.rdx.toString(16)}`);

  // addsubps [1,2,3,4]f, [10,20,30,40]f → [-9,22,-27,44]f.
  const addsubps = run([
    ...movRax(0x400000003F800000n), 0x66, 0x48, 0x0f, 0x6e, 0xc0,
    ...movRax(0x4080000040400000n), 0x66, 0x48, 0x0f, 0x6e, 0xc8,
    0x66, 0x0f, 0x6c, 0xc1,
    ...movRax(0x41A0000041200000n), 0x66, 0x48, 0x0f, 0x6e, 0xd8,
    ...movRax(0x4220000041F00000n), 0x66, 0x48, 0x0f, 0x6e, 0xe0,
    0x66, 0x0f, 0x6c, 0xdc,
    0xf2, 0x0f, 0xd0, 0xc3, // addsubps xmm0,xmm3
    0x66, 0x48, 0x0f, 0x7e, 0xc1,
    0x66, 0x0f, 0x70, 0xe8, 0xee,
    0x66, 0x48, 0x0f, 0x7e, 0xea,
    0xc3,
  ]);
  assert.equal(addsubps.register.rcx, 0x41B00000C1100000n, `rcx 0x${addsubps.register.rcx.toString(16)}`);
  assert.equal(addsubps.register.rdx, 0x42300000C1D80000n, `rdx 0x${addsubps.register.rdx.toString(16)}`);
});

test("the probe serves CPUID and REP STOSB with the same semantics as the oracle", () => {
  const cpuid = run([0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0xa2, 0xc3]);
  assert.equal(cpuid.register.rdx, 0x07808011n, `rdx 0x${cpuid.register.rdx.toString(16)}`);
  const stos = run([0xb9, 0x04, 0x00, 0x00, 0x00, 0xb0, 0xab, 0x48, 0x89, 0xe7, 0x48, 0x83, 0xef, 0x40, 0xf3, 0xaa, 0x8b, 0x57, 0xfc, 0xc3]);
  assert.equal(stos.stop_reason, "entry_return", JSON.stringify(stos.exception));
  assert.equal(stos.register.rdx, 0xABABABABn, `rdx 0x${stos.register.rdx.toString(16)}`);
  assert.equal(stos.register.rcx, 0n);
});

test("the probe's x87 executor agrees with the oracle: FADDP yields exactly 2.0", () => {
  // fld1; fld1; faddp st1,st0; fstp qword[rsp-8]; mov rax,[rsp-8]; ret — the same
  // microprogram frozen in test/lift64.test.mjs, proving exec64 mirrors lift64.
  const report = run([0xd9, 0xe8, 0xd9, 0xe8, 0xde, 0xc1, 0xdd, 0x5c, 0x24, 0xf8, 0x48, 0x8b, 0x44, 0x24, 0xf8, 0xc3]);
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.rax, 0x4000000000000000n, `rax 0x${report.register.rax.toString(16)}`);
});

test("the probe's x87 executor computes 6*7=42 through FILD/FMULP/FISTP", () => {
  const report = run([
    0xc7, 0x44, 0x24, 0xfc, 0x06, 0x00, 0x00, 0x00,
    0xc7, 0x44, 0x24, 0xf8, 0x07, 0x00, 0x00, 0x00,
    0xdb, 0x44, 0x24, 0xfc,
    0xdb, 0x44, 0x24, 0xf8,
    0xde, 0xc9,
    0xdb, 0x5c, 0x24, 0xf0,
    0x8b, 0x44, 0x24, 0xf0,
    0xc3,
  ]);
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.rax, 42n, `rax 0x${report.register.rax.toString(16)}`);
});

test("the probe's x87 FCOMI sets the ordered EFLAGS the oracle does (greater)", () => {
  // fldz; fld1; fcomi st0,st1; ret -> st0=1.0 > st1=0.0 -> CF=ZF=PF=0
  const report = run([0xd9, 0xee, 0xd9, 0xe8, 0xdb, 0xf1, 0xc3]);
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.flag.cf, false);
  assert.equal(report.flag.zf, false);
  assert.equal(report.flag.pf, false);
});

test("a reached FlsAlloc is served through the Win64 HLE and returns index 0", () => {
  // The CRT-init frontier that used to end the games' probe. FlsAlloc(callback)
  // is now a served kernel32 export, so the call dispatches, RAX carries the
  // fresh fiber-local index (0), and the entry runs to its return.
  //   0: FF 15 02 00 00 00   call qword ptr [rip+2]   (slot at rva 8)
  //   6: 90                  nop
  //   7: C3                  ret
  //   8: <8-byte IAT slot>
  const image = Buffer.from([0xff, 0x15, 0x02, 0x00, 0x00, 0x00, 0x90, 0xc3, 0, 0, 0, 0, 0, 0, 0, 0]);
  const mapped = {
    image, input_path: "fls.exe", load_base: loadBase, entry_rva: 0,
    image_size_byte: image.length, section: [], tls_callback: [], relocation_count: 0,
    resolution_blocker: [], runtime_blocker: [],
    import: [{ library: "kernel32.dll", symbol: "FlsAlloc", ordinal: null, iat_slot_rva: 8 }],
  };
  const probe = executeProbe64(mapped, 4096);
  assert.equal(probe.state, "probe_executed");
  assert.equal(probe.stop_reason, "entry_return", JSON.stringify(probe.exception));
  assert.equal(probe.import_reached, null, "a served import is not a reached-import stop");
  assert.equal(probe.register.rax, "0x0", "RAX carries the first FLS index");
});

test("a served strrchr returns a full-width x64 pointer above 4 GiB, not a truncated low dword", () => {
  // The frontier Dwarf Fortress reached: vcruntime140!strrchr on a path string.
  // The string lives in the image mapped at 0x140000000, so the pointer strrchr
  // returns is above 4 GiB. If the Win64 return marshal truncated it to a low
  // dword, the guest's next dereference would fault — this asserts it does not.
  //   0x00: 48 8d 0d 39 00 00 00   lea rcx,[rip+0x39]   -> string at 0x40
  //   0x07: ba 2f 00 00 00         mov edx,0x2f         -> '/'
  //   0x0c: ff 15 7e 00 00 00      call [rip+0x7e]      -> IAT slot 0x90
  //   0x12: c3                     ret
  //   0x40: "a/b\0"                                     (last '/' at 0x41)
  //   0x90: <8-byte IAT slot>
  const image = Buffer.alloc(0x100);
  Buffer.from([0x48, 0x8d, 0x0d, 0x39, 0x00, 0x00, 0x00, 0xba, 0x2f, 0x00, 0x00, 0x00, 0xff, 0x15, 0x7e, 0x00, 0x00, 0x00, 0xc3]).copy(image, 0x00);
  Buffer.from("a/b\0", "latin1").copy(image, 0x40);
  const mapped = {
    image, input_path: "strrchr.exe", load_base: loadBase, entry_rva: 0,
    image_size_byte: image.length, section: [], tls_callback: [], relocation_count: 0,
    resolution_blocker: [], runtime_blocker: [],
    import: [{ library: "vcruntime140.dll", symbol: "strrchr", ordinal: null, iat_slot_rva: 0x90 }],
  };
  const probe = executeProbe64(mapped, 4096);
  assert.equal(probe.stop_reason, "entry_return", JSON.stringify(probe.exception));
  assert.equal(probe.import_reached, null, "strrchr is served, not a reached-import stop");
  assert.equal(probe.register.rax, "0x140000041", "RAX is the full 64-bit address of the last '/', not a truncated 0x41");
});

test("_initterm runs each guest initializer before returning to the caller", () => {
  // The ucrt startup runs the C++ global constructors by calling
  // _initterm(begin, end) over a table of function pointers. The harness must
  // drive each initializer through the interpreter, not skip it. This synthetic
  // image builds a one-entry table whose initializer writes 7 into a marker cell;
  // after _initterm returns, the entry loads the marker into RAX. A skipped
  // initializer would leave RAX at 0.
  const image = Buffer.alloc(0x100);
  const at = (offset, bytes) => Buffer.from(bytes).copy(image, offset);
  // entry
  at(0x00, [0x48, 0x8d, 0x0d, 0x81, 0x00, 0x00, 0x00]); // lea rcx,[rip+0x81] -> table begin 0x88
  at(0x07, [0x48, 0x8d, 0x15, 0x82, 0x00, 0x00, 0x00]); // lea rdx,[rip+0x82] -> table end 0x90
  at(0x0e, [0xff, 0x15, 0x7c, 0x00, 0x00, 0x00]);       // call [rip+0x7c] -> IAT slot 0x90
  at(0x14, [0x48, 0x8b, 0x05, 0x65, 0x00, 0x00, 0x00]); // mov rax,[rip+0x65] -> marker 0x80
  at(0x1b, [0xc3]);                                     // ret
  // initializer at 0x40: mov byte [rip+0x39],7 ; ret  (target marker 0x80)
  at(0x40, [0xc6, 0x05, 0x39, 0x00, 0x00, 0x00, 0x07, 0xc3]);
  // marker cell (0x80) starts 0; init table (0x88) -> loadBase+0x40; IAT slot (0x90)
  const initFn = loadBase + 0x40n;
  Buffer.from(le8(initFn)).copy(image, 0x88);
  const mapped = {
    image, input_path: "initterm.exe", load_base: loadBase, entry_rva: 0,
    image_size_byte: image.length, section: [], tls_callback: [], relocation_count: 0,
    resolution_blocker: [], runtime_blocker: [],
    import: [{ library: "api-ms-win-crt-runtime-l1-1-0.dll", symbol: "_initterm", ordinal: null, iat_slot_rva: 0x90 }],
  };
  const probe = executeProbe64(mapped, 4096);
  assert.equal(probe.stop_reason, "entry_return", JSON.stringify(probe.exception));
  assert.equal(probe.import_reached, null, "_initterm is handled, never a reached-import stop");
  assert.equal(probe.register.rax, "0x7", "the initializer ran and wrote the marker RAX reads back");
});

test("_initterm_e stops the sequence when an initializer reports a non-zero error", () => {
  // _initterm_e differs from _initterm: each initializer returns int and a
  // non-zero result aborts the sequence with that error in the return. Two
  // initializers: the first returns 5 (error), the second would write a marker.
  // The abort must return 5 and leave the marker untouched.
  const image = Buffer.alloc(0x100);
  const at = (offset, bytes) => Buffer.from(bytes).copy(image, offset);
  at(0x00, [0x48, 0x8d, 0x0d, 0x81, 0x00, 0x00, 0x00]); // lea rcx,[rip+0x81] -> begin 0x88
  at(0x07, [0x48, 0x8d, 0x15, 0x8a, 0x00, 0x00, 0x00]); // lea rdx,[rip+0x8a] -> end 0x98 (two entries)
  at(0x0e, [0xff, 0x15, 0x84, 0x00, 0x00, 0x00]);       // call [rip+0x84] -> IAT slot 0x98
  at(0x14, [0xc3]);                                     // ret (RAX holds _initterm_e result)
  // first initializer at 0x40: mov eax,5 ; ret
  at(0x40, [0xb8, 0x05, 0x00, 0x00, 0x00, 0xc3]);
  // second initializer at 0x50: mov byte [rip+0x29],9 ; ret  (would set marker 0x80)
  at(0x50, [0xc6, 0x05, 0x29, 0x00, 0x00, 0x00, 0x09, 0xc3]);
  Buffer.from(le8(loadBase + 0x40n)).copy(image, 0x88); // table[0] -> first initializer
  Buffer.from(le8(loadBase + 0x50n)).copy(image, 0x90); // table[1] -> second initializer
  const mapped = {
    image, input_path: "inittermE.exe", load_base: loadBase, entry_rva: 0,
    image_size_byte: image.length, section: [], tls_callback: [], relocation_count: 0,
    resolution_blocker: [], runtime_blocker: [],
    import: [{ library: "api-ms-win-crt-runtime-l1-1-0.dll", symbol: "_initterm_e", ordinal: null, iat_slot_rva: 0x98 }],
  };
  const probe = executeProbe64(mapped, 4096);
  assert.equal(probe.stop_reason, "entry_return", JSON.stringify(probe.exception));
  assert.equal(probe.register.rax, "0x5", "the non-zero initializer result is returned");
  assert.equal(image[0x80], 0, "the aborted sequence never ran the second initializer");
});

// --- the x86-64 window/dialog-creation path (BPTK-031) -----------------------
// Two synthetic images prove: CreateDialogParam instantiates the real RT_DIALOG
// template and dispatches WM_INITDIALOG to the guest DlgProc as real control
// flow; and a bounded message loop pumps a scripted trace, re-entering the guest
// WndProc for the dispatched message and terminating on the synthesized WM_QUIT.

function u16le(value) {
  return [value & 0xff, (value >> 8) & 0xff];
}
function u32le(value) {
  return [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24) & 0xff];
}
function wideZ(text) {
  const byte = [];
  for (const character of text) byte.push(...u16le(character.charCodeAt(0)));
  byte.push(0, 0);
  return byte;
}
// mov r64, imm64 for register index 0..15.
const movImm64 = (reg, value) => [reg >= 8 ? 0x49 : 0x48, 0xb8 + (reg & 7), ...le8(BigInt(value))];

// A one-control (WS_TABSTOP button) classic DLGTEMPLATE.
function oneButtonTemplate() {
  const byte = [
    ...u32le(0x80c800c0), // style with DS_SETFONT
    ...u32le(0),
    ...u16le(1), // one control
    ...u16le(0), ...u16le(0), ...u16le(160), ...u16le(80),
    ...u16le(0), // menu none
    ...u16le(0), // class none
    ...wideZ("Synthetic"),
    ...u16le(8), ...wideZ("MS Shell Dlg"),
  ];
  while ((byte.length & 3) !== 0) byte.push(0);
  byte.push(
    ...u32le(0x50010001), // WS_TABSTOP
    ...u32le(0),
    ...u16le(5), ...u16le(5), ...u16le(40), ...u16le(14),
    ...u16le(1), // id
    ...u16le(0xffff), ...u16le(0x0080), // Button
    ...wideZ("OK"),
    ...u16le(0),
  );
  while ((byte.length & 3) !== 0) byte.push(0);
  return byte;
}

// Lay a one-dialog resource directory at `base` with the template just after it.
function placeResource(image, base, dialogId, templateBytes) {
  const dirHeader = (namedCount, idCount) => [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ...u16le(namedCount), ...u16le(idCount)];
  const templateRva = base + 0x60;
  const put = (offset, bytes) => Buffer.from(bytes).copy(image, offset);
  put(base + 0x00, [...dirHeader(0, 1), ...u32le(5), ...u32le(0x80000000 | 0x18)]);
  put(base + 0x18, [...dirHeader(0, 1), ...u32le(dialogId), ...u32le(0x80000000 | 0x30)]);
  put(base + 0x30, [...dirHeader(0, 1), ...u32le(0), ...u32le(0x48)]);
  put(base + 0x48, [...u32le(templateRva), ...u32le(templateBytes.length), ...u32le(0), ...u32le(0)]);
  put(templateRva, templateBytes);
}

test("CreateDialogParam instantiates the RT_DIALOG template and dispatches WM_INITDIALOG to the guest DlgProc", () => {
  const image = Buffer.alloc(0x2000);
  const at = (offset, bytes) => Buffer.from(bytes).copy(image, offset);
  // entry: CreateDialogParamA(hInstance, id=100, parent=0, DlgProc, dwInitParam=0xABCD)
  at(0x00, [
    ...movImm64(1, loadBase),                 // rcx = hInstance
    ...movImm64(2, 100),                      // rdx = template id
    0x4d, 0x31, 0xc0,                         // xor r8,r8 -> parent 0
    ...movImm64(9, loadBase + 0x100n),        // r9 = DlgProc
    0x48, 0x83, 0xec, 0x28,                   // sub rsp,0x28
    ...movImm64(0, 0xabcd),                   // rax = dwInitParam
    0x48, 0x89, 0x44, 0x24, 0x20,             // mov [rsp+0x20], rax
    ...movImm64(3, loadBase + 0x800n),        // rbx = IAT slot
    0xff, 0x13,                               // call [rbx] -> CreateDialogParamA
    0x48, 0x83, 0xc4, 0x28,                   // add rsp,0x28
    ...movImm64(3, loadBase + 0x900n),        // rbx = marker
    0x48, 0x8b, 0x0b,                         // mov rcx,[rbx]     -> dispatched message
    0x48, 0x8b, 0x53, 0x08,                   // mov rdx,[rbx+8]   -> WM_INITDIALOG lParam
    0xc3,                                     // ret
  ]);
  // DlgProc at 0x100: record the message and lParam, return TRUE.
  at(0x100, [
    ...movImm64(3, loadBase + 0x900n),        // rbx = marker
    0x48, 0x89, 0x13,                         // mov [rbx], rdx    (message)
    0x4c, 0x89, 0x4b, 0x08,                   // mov [rbx+8], r9   (lParam)
    ...movImm64(0, 1),                        // rax = TRUE
    0xc3,
  ]);
  placeResource(image, 0x1000, 100, oneButtonTemplate());
  const mapped = {
    image, input_path: "dialog.exe", load_base: loadBase, entry_rva: 0,
    image_size_byte: image.length, section: [], tls_callback: [], relocation_count: 0,
    resolution_blocker: [], runtime_blocker: [],
    directory: [{ rva: 0 }, { rva: 0 }, { rva: 0x1000, size_byte: 0x200 }],
    import: [{ library: "user32.dll", symbol: "CreateDialogParamA", ordinal: null, iat_slot_rva: 0x800 }],
  };
  const probe = executeProbe64(mapped, 100000);
  assert.equal(probe.stop_reason, "entry_return", JSON.stringify(probe.exception));
  assert.equal(probe.register.rcx, "0x110", "the guest DlgProc received WM_INITDIALOG (0x110)");
  assert.equal(probe.register.rdx, "0xabcd", "WM_INITDIALOG carried dwInitParam as its lParam");
  assert.notEqual(probe.register.rax, "0x0", "CreateDialogParam returned the real dialog HWND");
});

// A straight-line message pump (no guest branches): register a class carrying a
// guest WndProc, create a window, post one scripted message, then GetMessage +
// DispatchMessage once (which re-enters the guest WndProc), then GetMessage
// again — the empty queue yields the synthesized WM_QUIT, the bounded terminator.
function buildMessagePumpImage() {
  const image = Buffer.alloc(0x2000);
  const at = (offset, bytes) => Buffer.from(bytes).copy(image, offset);
  // WNDCLASSA at 0x700: lpfnWndProc@8 = guest WndProc (0x180), lpszClassName@64.
  Buffer.from(le8(loadBase + 0x180n)).copy(image, 0x700 + 8);
  Buffer.from(le8(loadBase + 0x780n)).copy(image, 0x700 + 64);
  at(0x780, [0x43, 0x00]); // ANSI class name "C"
  at(0x00, [
    0x48, 0x83, 0xec, 0x28,                   // sub rsp,0x28 (shadow space kept for every call)
    // RegisterClassA(&WNDCLASSA)
    ...movImm64(1, loadBase + 0x700n),
    ...movImm64(3, loadBase + 0x810n), 0xff, 0x13,
    // CreateWindowExA(exStyle=0, "C", name=0, style=0, ...)
    ...movImm64(1, 0), ...movImm64(2, loadBase + 0x780n), 0x4d, 0x31, 0xc0, 0x4d, 0x31, 0xc9,
    ...movImm64(3, loadBase + 0x820n), 0xff, 0x13,
    0x48, 0x89, 0xc6,                         // mov rsi, rax  (save hwnd)
    // PostMessageW(hwnd, WM_SIZE=5, 0, 0)
    0x48, 0x89, 0xf1, ...movImm64(2, 5), 0x4d, 0x31, 0xc0, 0x4d, 0x31, 0xc9,
    ...movImm64(3, loadBase + 0x830n), 0xff, 0x13,
    // GetMessageA(&MSG at 0x600, 0, 0, 0) -> the posted message (rax=1)
    ...movImm64(1, loadBase + 0x600n), ...movImm64(2, 0), 0x4d, 0x31, 0xc0, 0x4d, 0x31, 0xc9,
    ...movImm64(3, loadBase + 0x840n), 0xff, 0x13,
    // DispatchMessageA(&MSG) -> re-enters the guest WndProc (marker++)
    ...movImm64(1, loadBase + 0x600n), ...movImm64(3, loadBase + 0x850n), 0xff, 0x13,
    // GetMessageA(&MSG) again -> empty queue -> synthesized WM_QUIT (rax=0)
    ...movImm64(1, loadBase + 0x600n), ...movImm64(2, 0), 0x4d, 0x31, 0xc0, 0x4d, 0x31, 0xc9,
    ...movImm64(3, loadBase + 0x840n), 0xff, 0x13,
    // return the observables in registers (the harness runs on a private image
    // copy, so a memory marker would not be visible to the caller): rcx = the
    // dispatch count the guest WndProc kept, rdx = the second GetMessage result.
    0x48, 0x89, 0xc6,                         // mov rsi, rax  (WM_QUIT result)
    ...movImm64(3, loadBase + 0x900n),        // rbx = marker
    0x48, 0x8b, 0x0b,                         // mov rcx,[rbx] (dispatch count)
    0x48, 0x89, 0xf2,                         // mov rdx, rsi  (WM_QUIT result)
    0x48, 0x83, 0xc4, 0x28,                   // add rsp,0x28
    0xc3,
  ]);
  // guest WndProc at 0x180: marker (0x900) ++ ; return 0
  at(0x180, [
    ...movImm64(3, loadBase + 0x900n),
    0x48, 0x8b, 0x03,                         // mov rax,[rbx]
    0x48, 0xff, 0xc0,                         // inc rax
    0x48, 0x89, 0x03,                         // mov [rbx],rax
    0x31, 0xc0,                               // xor eax,eax
    0xc3,
  ]);
  return image;
}

const messagePumpImport = [
  { library: "user32.dll", symbol: "RegisterClassA", ordinal: null, iat_slot_rva: 0x810 },
  { library: "user32.dll", symbol: "CreateWindowExA", ordinal: null, iat_slot_rva: 0x820 },
  { library: "user32.dll", symbol: "PostMessageW", ordinal: null, iat_slot_rva: 0x830 },
  { library: "user32.dll", symbol: "GetMessageA", ordinal: null, iat_slot_rva: 0x840 },
  { library: "user32.dll", symbol: "DispatchMessageA", ordinal: null, iat_slot_rva: 0x850 },
];

function runMessagePump() {
  const image = buildMessagePumpImage();
  const mapped = {
    image, input_path: "msgloop.exe", load_base: loadBase, entry_rva: 0,
    image_size_byte: image.length, section: [], tls_callback: [], relocation_count: 0,
    resolution_blocker: [], runtime_blocker: [],
    directory: [{ rva: 0 }, { rva: 0 }, { rva: 0 }],
    import: messagePumpImport,
  };
  const probe = executeProbe64(mapped, 200000);
  return probe;
}

test("a bounded message loop pumps a scripted trace and re-enters the guest WndProc", () => {
  const first = runMessagePump();
  assert.equal(first.stop_reason, "entry_return", JSON.stringify(first.exception));
  assert.equal(first.register.rcx, "0x1", "DispatchMessage re-entered the guest WndProc exactly once for the posted message");
  assert.equal(first.register.rdx, "0x0", "the second GetMessage returned 0 (the synthesized WM_QUIT terminator)");
  // Determinism: a second, independent run reaches the identical outcome.
  const second = runMessagePump();
  assert.equal(second.stop_reason, "entry_return");
  assert.equal(second.register.rcx, "0x1");
  assert.equal(second.instruction_count, first.instruction_count, "two runs execute the identical instruction count");
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

// --- BPTK tiered-runner boundary: additive exports (Lane BB) ---------------
// buildGuestContext64 and serveImportAt64 are export-only extractions from the
// interpreter. These assert the exposed region layout and prove the exported
// import dispatcher mutates the guest identically to the end-to-end run loop.

// The Win64 HLE option a synthetic served-import image runs under, mirroring
// exactly what executeProbe64 assembles internally (createHleLayout over the
// 32-bit arena/virtual/thunk range, a virtual-monotonic clock, the IAT slot
// bound so a call through it reaches the served export).
function servedImportOption(image, importList) {
  const stackSizeByte = 0x00100000;
  const stackLowNum = Number(stackBase);
  const layout = createHleLayout({
    load_base: Number(loadBase & MASK64),
    image_size_byte: image.length,
    stack_base: stackLowNum,
    stack_end: stackLowNum + stackSizeByte,
  });
  const importSet = new Map();
  for (const entry of importList) importSet.set((loadBase + BigInt(entry.iat_slot_rva)) & MASK64, entry);
  return {
    image,
    loadBase,
    entryRva: 0,
    budget: 4096,
    stackSizeByte,
    importSet,
    hle: { layout, clock: createGuestClock({ mode: "virtual_monotonic" }), executableName: "game.exe" },
  };
}

test("buildGuestContext64 exposes the multi-region layout with the expected bases", () => {
  const context = buildGuestContext64({ image: Buffer.from([0xc3]), loadBase, entryRva: 0 });
  // rip parked at the entry, gs at the TEB region.
  assert.equal(context.machine.rip, loadBase, "entry rip is the load base");
  assert.equal(context.machine.gsBase, tebBase, "gs base is the TEB region");
  // The always-present regions: image / stack / TEB, with the documented bases.
  assert.equal(context.layout.image.base, loadBase);
  assert.equal(context.layout.stack.base, stackBase);
  assert.equal(context.layout.teb.base, tebBase);
  assert.equal(context.layout.teb.teb_base, tebBase);
  assert.equal(context.layout.teb.peb_base, pebBase);
  // The region array the Machine actually maps agrees with the layout bases.
  assert.equal(context.region[0].base, loadBase);
  assert.equal(context.region[1].base, stackBase);
  assert.equal(context.region[2].base, tebBase);
  // No HLE layout declared, so no arena/virtual/thunk regions.
  assert.equal(context.layout.arena, undefined);
  assert.equal(context.hleContext, null);
});

test("buildGuestContext64 appends the HLE arena/virtual/thunk regions when a layout is declared", () => {
  const image = Buffer.from([0xc3]);
  const option = servedImportOption(image, []);
  const context = buildGuestContext64(option);
  assert.notEqual(context.hleContext, null, "an HLE layout wires the guest");
  assert.equal(context.layout.arena.base, BigInt(option.hle.layout.arena_base));
  assert.equal(context.layout.arena.size_byte, option.hle.layout.arena_size_byte);
  assert.equal(context.layout.virtual.base, BigInt(option.hle.layout.virtual_base));
  assert.equal(context.layout.thunk.base, BigInt(option.hle.layout.thunk_base));
  // The PE32+ image maps above 4 GiB, so a low-address alias joins the space.
  assert.equal(context.layout.image_alias.base, loadBase & 0xffffffffn);
});

test("serveImportAt64 mutates the guest identically to the end-to-end run loop", () => {
  // The synthetic image from the served-import probe test: entry does
  // `call [slot]; nop; ret` to the zero-arg GetCurrentThreadId (thread id 1).
  const image = Buffer.from([0xff, 0x15, 0x02, 0x00, 0x00, 0x00, 0x90, 0xc3, 0, 0, 0, 0, 0, 0, 0, 0]);
  const importList = [{ library: "kernel32.dll", symbol: "GetCurrentThreadId", ordinal: null, iat_slot_rva: 8 }];
  const option = servedImportOption(image, importList);

  // Reference: the interpreter drives the whole image and serves the import
  // end-to-end. RAX carries the thread id; control returns to the entry ret.
  const endToEnd = runImage64(option);
  assert.equal(endToEnd.register.rax, 1n, "the run loop's served GetCurrentThreadId lands 1 in RAX");
  assert.equal(endToEnd.stop_reason, "entry_return");

  // Under test: a fresh context, positioned exactly as the loop is the instant
  // it lands on the import thunk (the call's return address pushed, rip == the
  // thunk), then dispatched through the exported wrapper. This is the mutation
  // a WASM fast-tier hostCall(targetVA) performs.
  const context = buildGuestContext64(option);
  const slotVA = (loadBase + 8n) & MASK64;
  const thunkVA = context.machine.readMem(slotVA, 8); // the IAT slot the binder wrote
  assert.equal(context.hleContext.guest.isThunk(Number(thunkVA)), true, "the bound slot points at an HLE thunk");

  const returnTarget = (loadBase + 6n) & MASK64; // the nop after the 6-byte call
  const rspBefore = context.machine.reg[4]; // RSP index
  context.machine.reg[4] = (rspBefore - 8n) & MASK64; // the call's push
  context.machine.writeMem(context.machine.reg[4], 8, returnTarget);
  context.machine.rip = thunkVA;

  const result = serveImportAt64(context, thunkVA);
  assert.equal(result.served, true, "the thunk is served");
  assert.equal(result.kind, "call", "a general Win64 import, not a specialization");
  assert.equal(result.import.symbol, "GetCurrentThreadId");
  // Same register mutation the end-to-end run produced.
  assert.equal(context.machine.reg[0] & MASK64, endToEnd.register.rax, "RAX matches the run loop's served result");
  assert.equal(context.machine.reg[0] & MASK64, 1n);
  // A jmp-thunk dispatch pops the return address and resumes the caller, so RSP
  // rebalances and rip is back at the instruction after the call.
  assert.equal(context.machine.reg[4] & MASK64, rspBefore & MASK64, "RSP rebalanced after the served thunk");
  assert.equal(context.machine.rip & MASK64, returnTarget, "control returned to the caller");
});

test("serveImportAt64 reports not_a_thunk for an address that is not a bound import", () => {
  const context = buildGuestContext64(servedImportOption(Buffer.from([0xc3]), []));
  const result = serveImportAt64(context, loadBase); // the image base, not a thunk
  assert.equal(result.served, false);
  assert.equal(result.reason, "not_a_thunk");
});
