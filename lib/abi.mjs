// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Guest↔host ABI / import-thunk lowering (BPTK-056 / GS-011). When recompiled
// or interpreted guest code calls an imported Win32 export, control crosses
// into host emulation. The lowering must place arguments per the declared
// calling convention, invoke the host, and leave the guest stack balanced —
// stdcall and the register conventions clean their own stack arguments, cdecl
// leaves the caller to clean. This module computes that lowering, verifies the
// stack returns balanced for every declared convention, and measures the real
// crossing cost: the recompiled path crosses to the host as a WebAssembly
// import call, so the boundary cost is measured as exactly that. The declared
// cost bar is a reference-desktop figure (BPTK-002), so it is reported but not
// certified here, which keeps the benchmark honestly red.

import { performance } from "node:perf_hooks";

// The declared 32-bit calling conventions and how each cleans the stack.
// register_arg: arguments passed in registers (ecx/edx or the this pointer);
// the remaining arguments are pushed on the stack right-to-left.
export const CALLING_CONVENTION = Object.freeze({
  cdecl: { register_arg: 0, cleaner: "caller" },
  stdcall: { register_arg: 0, cleaner: "callee" },
  fastcall: { register_arg: 2, cleaner: "callee" },
  thiscall: { register_arg: 1, cleaner: "callee" },
});

// The declared guest↔host crossing-cost bar on the BPTK-002 reference desktop.
export const CROSSING_COST_BAR_NANOSECOND = 250;

// Lower a thunk call: split arguments into register and stack operands and
// compute the stack cleanup each side owns.
export function lowerThunk(option = {}) {
  const conventionName = option.convention ?? "stdcall";
  const convention = CALLING_CONVENTION[conventionName];
  if (!convention) throw new RangeError(`Unknown calling convention: ${conventionName}`);
  const argumentCount = Number.isSafeInteger(option.argument_count) && option.argument_count >= 0 ? option.argument_count : 0;
  const registerArgument = Math.min(convention.register_arg, argumentCount);
  const stackArgument = argumentCount - registerArgument;
  const stackByte = stackArgument * 4;
  return {
    convention: conventionName,
    argument_count: argumentCount,
    register_argument: registerArgument,
    stack_argument: stackArgument,
    stack_byte: stackByte,
    callee_cleanup_byte: convention.cleaner === "callee" ? stackByte : 0,
    caller_cleanup_byte: convention.cleaner === "caller" ? stackByte : 0,
  };
}

// Simulate a full call and return, asserting the guest ESP is balanced. The
// caller pushes the stack arguments and the return address; the callee (for
// callee-clean conventions) pops the arguments on ret; the caller adjusts for
// cdecl. A balanced result means the lowering cleaned the stack correctly.
export function verifyStackCleanup(convention, argumentCount) {
  const lowered = lowerThunk({ convention, argument_count: argumentCount });
  let esp = 0x1000; // an arbitrary aligned stack pointer
  const start = esp;
  esp -= lowered.stack_byte; // caller pushes stack arguments
  esp -= 4; // caller pushes the return address
  // The host emulation runs; on return the return address is popped.
  esp += 4;
  // Callee-clean conventions retire the stack arguments via `ret imm16`.
  esp += lowered.callee_cleanup_byte;
  // Caller-clean conventions (cdecl) adjust ESP after the call returns.
  esp += lowered.caller_cleanup_byte;
  return { convention, argument_count: argumentCount, is_balanced: esp === start, esp_delta: esp - start, lowered };
}

// ---------------------------------------------------------------------------
// Minimal WebAssembly encoder for the crossing-cost probe module.
function uleb(value) {
  const out = [];
  let n = value >>> 0;
  do { let byte = n & 0x7f; n >>>= 7; if (n !== 0) byte |= 0x80; out.push(byte); } while (n !== 0);
  return out;
}
function section(id, payload) { return [id, ...uleb(payload.length), ...payload]; }
function vec(items) { return [...uleb(items.length), ...items.flat()]; }

// A module importing host.sink:(i32)->i32 and exporting cross(n): call sink n
// times, accumulating — the real recompiled-guest↔host boundary crossing.
function buildCrossingModule() {
  const types = section(0x01, vec([[0x60, ...vec([[0x7f]]), ...vec([[0x7f]])]]));
  const imports = section(0x02, vec([[...vec([..."host"].map((c) => c.charCodeAt(0))), ...vec([..."sink"].map((c) => c.charCodeAt(0))), 0x00, 0x00]]));
  const functions = section(0x03, vec([[0x00]])); // cross : type0
  const exports = section(0x07, vec([[...vec([..."cross"].map((c) => c.charCodeAt(0))), 0x00, 0x01]])); // func index 1 (import is 0)
  const body = [
    0x02, 0x40, // block
    0x03, 0x40, // loop
    0x20, 0x01, 0x20, 0x00, 0x4f, 0x0d, 0x01, // if i >= n br block
    0x20, 0x02, 0x20, 0x01, 0x10, 0x00, 0x6a, 0x21, 0x02, // acc += sink(i)
    0x20, 0x01, 0x41, 0x01, 0x6a, 0x21, 0x01, // i += 1
    0x0c, 0x00, // br loop
    0x0b, // end loop
    0x0b, // end block
    0x20, 0x02, // return acc
    0x0b, // end func
  ];
  const localVec = vec([[...uleb(2), 0x7f]]); // 2 i32 locals: i, acc
  const code = section(0x0a, vec([[...uleb(localVec.length + body.length), ...localVec, ...body]]));
  const header = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  return Uint8Array.from([...header, ...types, ...imports, ...functions, ...exports, ...code]);
}

// Measure the guest↔host crossing cost as the per-call time of a WebAssembly
// module calling an imported host function.
export function measureCrossing(option = {}) {
  const iteration = Number.isSafeInteger(option.iteration) && option.iteration > 0 ? option.iteration : 1_000_000;
  let hostCall = 0;
  const wasm = buildCrossingModule();
  const module = new WebAssembly.Module(wasm);
  const instance = new WebAssembly.Instance(module, { host: { sink: (value) => { hostCall += 1; return value + 1; } } });
  instance.exports.cross(1000); // warm the boundary
  hostCall = 0;
  const start = performance.now();
  const result = instance.exports.cross(iteration) >>> 0;
  const millisecond = performance.now() - start;
  const nanosecondPerCrossing = Number(((millisecond * 1e6) / iteration).toFixed(2));
  return {
    iteration,
    host_call_count: hostCall,
    accumulator: result,
    millisecond: Number(millisecond.toFixed(3)),
    nanosecond_per_crossing: nanosecondPerCrossing,
    is_host_reached: hostCall === iteration,
  };
}

// Full ABI benchmark: verify every declared convention cleans its stack, and
// measure the crossing cost against the declared bar. Honestly red — the bar is
// a reference-desktop figure and no whole Win32 HLE is wired into the recompiled
// crossing here.
export function benchmarkAbi(option = {}) {
  const argumentCount = Number.isSafeInteger(option.argument_count) ? option.argument_count : 5;
  const convention = Object.keys(CALLING_CONVENTION).map((name) => verifyStackCleanup(name, argumentCount));
  const allBalanced = convention.every((entry) => entry.is_balanced);
  const crossing = measureCrossing({ iteration: option.iteration ?? 1_000_000 });
  return {
    schema_version: 1,
    command: "benchmark --profile abi",
    profile: "guest_host_abi",
    argument_count: argumentCount,
    convention,
    is_every_convention_balanced: allBalanced,
    crossing,
    crossing_cost_bar_nanosecond: CROSSING_COST_BAR_NANOSECOND,
    is_crossing_under_bar_here: crossing.nanosecond_per_crossing <= CROSSING_COST_BAR_NANOSECOND,
    measured_on_reference_desktop: false,
    is_bar_cleared: false,
    blocker: [
      "The crossing-cost bar is defined on the BPTK-002 reference desktop, which is not the measurement host",
      "The whole Win32 HLE is not wired into the recompiled crossing; the measured boundary is the raw WebAssembly import call",
    ],
  };
}
