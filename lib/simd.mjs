// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// SSE packed-SIMD strict-fallback conformance (BPTK-052 / GS-007). The bounded
// interpreter executes packed single/double float arithmetic and the 128-bit
// logical operations over the xmm register file (the "primary path"). This
// module verifies that primary path against an independent strict per-lane
// IEEE-754 reference (the "strict fallback"): for every declared packed
// operation the two must agree lane-for-lane within the declared tolerance
// (zero ULP for these deterministic single/double ops). The 80-bit x87
// extended-precision path and the 256-bit AVX register width are declared
// gaps, so the full vectorization benchmark stays honestly red.

import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mapPe32ForRuntime } from "./pe.mjs";
import { executeProbe } from "./runtime.mjs";

// The declared match tolerance in ULP. The single/double packed operations are
// deterministic IEEE-754, so the strict fallback must match exactly.
export const PACKED_TOLERANCE_ULP = 0;

// A PE32 whose .text holds the code at the entry and two 16-byte operands in
// the readable body, so a packed op reads xmm0/xmm1 from memory and leaves the
// result in xmm0 for the probe to report.
function buildSsePe(directory, code, operandA, operandB) {
  const file = Buffer.alloc(0x800);
  file.writeUInt16LE(0x5a4d, 0);
  file.writeUInt32LE(0x80, 0x3c);
  file.writeUInt32LE(0x00004550, 0x80);
  file.writeUInt16LE(0x14c, 0x84);
  file.writeUInt16LE(1, 0x86);
  file.writeUInt16LE(224, 0x94);
  file.writeUInt16LE(0x10b, 0x98);
  file.writeUInt32LE(0x1000, 0xa8);
  file.writeUInt32LE(0x400000, 0xb4);
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
  file.writeUInt32LE((0x80000000 | 0x60000020) >>> 0, sectionOffset + 36);
  file.writeUInt32LE(0x600, sectionOffset + 16);
  file.writeUInt32LE(0x200, sectionOffset + 20);
  Buffer.from(code).copy(file, 0x200); // entry RVA 0x1000 -> file 0x200
  operandA.copy(file, 0x300); // RVA 0x1100
  operandB.copy(file, 0x310); // RVA 0x1110
  const path = join(directory, "simd.exe");
  writeFileSync(path, file);
  return path;
}

// ModRM/disp32 movaps loads of the two operands, the op (reg-reg xmm0,xmm1),
// then ret. `prefix` selects the packed form (undefined = single, 0x66 =
// double). `opcode` is the 0x0f extension byte.
function buildProgram(prefix, opcode) {
  const load0 = [0x0f, 0x28, 0x05, 0x00, 0x11, 0x40, 0x00]; // movaps xmm0,[0x401100]
  const load1 = [0x0f, 0x28, 0x0d, 0x10, 0x11, 0x40, 0x00]; // movaps xmm1,[0x401110]
  const op = prefix === undefined ? [0x0f, opcode, 0xc1] : [prefix, 0x0f, opcode, 0xc1];
  return [...load0, ...load1, ...op, 0xc3];
}

function runPacked(prefix, opcode, operandA, operandB) {
  const directory = mkdtempSync(join(tmpdir(), "bptk-simd-"));
  try {
    const code = buildProgram(prefix, opcode);
    const path = buildSsePe(directory, code, operandA, operandB);
    const mapped = mapPe32ForRuntime(path, null, null);
    const report = executeProbe(mapped, 16, {});
    if (report.stop_reason !== "entry_return") {
      return { ok: false, stop_reason: report.stop_reason, exception: report.exception };
    }
    // xmm[0] is reported as a 0x-prefixed 32-byte hex string.
    const hex = report.xmm[0].replace(/^0x/, "");
    return { ok: true, result: Buffer.from(hex, "hex") };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

// The strict per-lane reference (the fallback), computed independently of the
// interpreter, lane-for-lane over the raw operand bytes.
function strictReference(form, opcode, a, b) {
  const result = Buffer.alloc(16);
  if (form === "logical") {
    for (let i = 0; i < 16; i += 1) {
      result[i] = opcode === 0x54 ? a[i] & b[i] : opcode === 0x56 ? a[i] | b[i] : a[i] ^ b[i];
    }
    return result;
  }
  const isDouble = form === "pd";
  const laneByte = isDouble ? 8 : 4;
  const laneCount = 16 / laneByte;
  const binary = { 0x58: (x, y) => x + y, 0x59: (x, y) => x * y, 0x5c: (x, y) => x - y, 0x5e: (x, y) => x / y }[opcode];
  for (let lane = 0; lane < laneCount; lane += 1) {
    const offset = lane * laneByte;
    if (isDouble) {
      result.writeDoubleLE(binary(a.readDoubleLE(offset), b.readDoubleLE(offset)), offset);
    } else {
      result.writeFloatLE(Math.fround(binary(a.readFloatLE(offset), b.readFloatLE(offset))), offset);
    }
  }
  return result;
}

function packedSingle(values) {
  const buffer = Buffer.alloc(16);
  values.forEach((value, index) => buffer.writeFloatLE(value, index * 4));
  return buffer;
}
function packedDouble(values) {
  const buffer = Buffer.alloc(16);
  values.forEach((value, index) => buffer.writeDoubleLE(value, index * 8));
  return buffer;
}

// The declared packed operation battery.
const OPERATION = [
  { name: "addps", form: "ps", prefix: undefined, opcode: 0x58, a: packedSingle([1.5, -2.25, 3e7, 0.1]), b: packedSingle([2.5, 2.25, 1e7, 0.2]) },
  { name: "mulps", form: "ps", prefix: undefined, opcode: 0x59, a: packedSingle([1.5, -2.25, 3.5, 0.1]), b: packedSingle([2.0, 4.0, 2.0, 10.0]) },
  { name: "subps", form: "ps", prefix: undefined, opcode: 0x5c, a: packedSingle([5.5, -2.25, 3.5, 0.3]), b: packedSingle([2.0, 4.0, 2.0, 0.1]) },
  { name: "addpd", form: "pd", prefix: 0x66, opcode: 0x58, a: packedDouble([1.5, -2.25]), b: packedDouble([2.5, 2.25]) },
  { name: "mulpd", form: "pd", prefix: 0x66, opcode: 0x59, a: packedDouble([1.25, 3.5]), b: packedDouble([4.0, 2.0]) },
  { name: "andps", form: "logical", prefix: undefined, opcode: 0x54, a: packedSingle([1.5, -2.25, 3.5, 0.1]), b: packedSingle([2.0, 4.0, 2.0, 10.0]) },
  { name: "orps", form: "logical", prefix: undefined, opcode: 0x56, a: packedSingle([1.5, -2.25, 3.5, 0.1]), b: packedSingle([2.0, 4.0, 2.0, 10.0]) },
  { name: "xorps", form: "logical", prefix: undefined, opcode: 0x57, a: packedSingle([1.5, -2.25, 3.5, 0.1]), b: packedSingle([2.0, 4.0, 2.0, 10.0]) },
];

export function benchmarkPackedSimd() {
  const operation = [];
  for (const entry of OPERATION) {
    const primary = runPacked(entry.prefix, entry.opcode, entry.a, entry.b);
    if (!primary.ok) {
      operation.push({ name: entry.name, is_supported: false, stop_reason: primary.stop_reason });
      continue;
    }
    const strict = strictReference(entry.form, entry.opcode, entry.a, entry.b);
    operation.push({
      name: entry.name,
      form: entry.form,
      is_supported: true,
      matches_strict: primary.result.equals(strict),
      primary_hex: primary.result.toString("hex"),
      strict_hex: strict.toString("hex"),
    });
  }
  const supported = operation.filter((entry) => entry.is_supported);
  const allMatch = supported.length > 0 && supported.every((entry) => entry.matches_strict);
  return {
    schema_version: 1,
    command: "benchmark --profile simd",
    profile: "packed_simd_strict_fallback",
    tolerance_ulp: PACKED_TOLERANCE_ULP,
    operation,
    supported_count: supported.length,
    is_strict_fallback_matching: allMatch,
    covers_80bit_x87: false,
    covers_avx256: false,
    is_bar_cleared: false,
    blocker: [
      "The x87 path is 64-bit precision; 80-bit extended precision is not modeled, so the 80-bit tolerance leg is unmet",
      "AVX-256 register width is not covered; only the 128-bit SSE packed forms are verified",
    ],
  };
}
