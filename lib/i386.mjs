// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The declared i386 decoder/executor inventory (BPTK-009): the exact opcode
// surface the bounded probe serves, in one machine-readable place, plus the
// linear .text decode sweep that measures how far a real corpus binary
// decodes toward its entry. Every declared-served form must carry at least
// one microprogram conformance case (the suite in test/i386.test.mjs walks
// the inventory and refuses a case-free form), and every undeclared form
// stops as a structured unsupported_opcode diagnostic — never garbage.

import { readFileSync } from "node:fs";
import { mapPe32 } from "./pe.mjs";

// Prefix byte the decoder consumes: the operand-size override selects the
// 16-bit form, the flat-model segment override (cs, ds, es, ss) and lock are
// the identity, and rep prefixes the string operation. The address-size
// override and fs/gs (no declared thread-environment block) stay structured
// refusals and are deliberately absent.
export const i386Prefix = Object.freeze([0x26, 0x2e, 0x36, 0x3e, 0x66, 0xf0, 0xf2, 0xf3]);

// One-byte opcodes served with their register-form ModRM or with no ModRM.
// The two-operand ALU space (0x00-0x3f) is served in its byte and dword
// columns except the segment and BCD forms. 0x8d (LEA) is served only with a
// memory ModRM and is covered by a dedicated microprogram case. 0x9a (far
// call) is deliberately absent.
export const i386OpcodeOneByte = Object.freeze([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
  ...range(0x40, 0x5f), 0x60, 0x61, 0x68, 0x69, 0x6a, 0x6b, ...range(0x70, 0x7f),
  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
  0x8c, 0x8d, 0x8e, 0x8f, 0x90, ...range(0x91, 0x99), 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
  0xa0, 0xa1, 0xa2, 0xa3, ...range(0xa4, 0xa9),
  ...range(0xaa, 0xbf), 0xc0, 0xc1, 0xc2, 0xc3, 0xc6, 0xc7, 0xc8, 0xc9,
  ...range(0xd0, 0xd3), 0xd7, ...range(0xd8, 0xdf),
  0xe0, 0xe1, 0xe2, 0xe3, 0xe8, 0xe9, 0xeb,
  0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfc, 0xfd, 0xfe, 0xff,
]);

// Group opcodes whose served /reg field is restricted. Everything absent
// here serves every /reg value (or is not a group at all).
export const i386OpcodeGroup = Object.freeze({
  0xc6: [0],
  0xc7: [0],
  0xf6: [0, 2, 3, 4, 5, 6, 7],
  0xf7: [0, 2, 3, 4, 5, 6, 7],
  0xfe: [0, 1],
  0xff: [0, 1, 2, 4, 6],
});

// Two-byte 0x0f opcodes served: the integer extension family. The x87/FPU
// one-byte range 0xd8-0xdf decodes through the declared x87 subset whose
// /reg and register-form refinement happens at execution.
// The MMX integer family (movd/movq, packed logical, packed add/sub, packed
// equality, the four-word shuffle, the register-form shifts, and EMMS) is
// served through the 64-bit lanes; the immediate-group shifts 0x71/0x72/0x73
// carry their served /reg in i386Opcode0fGroup below.
export const i386Opcode0f = Object.freeze([
  0x0d, 0x31, 0xa2, ...range(0x18, 0x1f), ...range(0x40, 0x4f), ...range(0x80, 0x9f), 0xa3, 0xa4, 0xa5,
  0xab, 0xac, 0xad, 0xaf, 0xb0, 0xb1, 0xb3, 0xb6, 0xb7, 0xbb, 0xbc, 0xbd,
  0xbe, 0xbf, 0xc0, 0xc1,
  0x6e, 0x6f, 0x7e, 0x7f, 0x70, 0x77, 0xdb, 0xdf, 0xeb, 0xef, 0x74, 0x75, 0x76,
  0xfc, 0xfd, 0xfe, 0xf8, 0xf9, 0xfa, 0xd1, 0xd2, 0xd3, 0xe1, 0xe2, 0xf1, 0xf2, 0xf3,
  // The SSE/SSE2 map: the mandatory prefix selects the packed/scalar and the
  // single/double form at execution. Prefix-blind here because the linear
  // sweep classifies by opcode; the prefix rides ahead of the 0f escape.
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x28, 0x29, 0x51, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
  0x5c, 0x5d, 0x5e, 0x5f, 0x2e, 0x2f, 0x2a, 0x2c, 0x2d, 0xc5, 0xc6, 0xe6,
]);

// Two-byte 0x0f opcodes with no ModRM byte at all (system and accumulator
// forms). None is served; the sweep must still consume exactly two byte so
// the linear walk stays aligned.
export const i386Opcode0fNoModrm = Object.freeze([0x05, 0x07, 0x08, 0x09, 0x0b, 0x30, 0x32, 0x33, 0x34, 0x35, 0xa0, 0xa1, 0xa8, 0xa9]);

export const i386Opcode0fGroup = Object.freeze({
  0xba: [4, 5, 6, 7],
  // MMX immediate-group shifts: /2 psrl, /4 psra, /6 psll. 0x73 (qword) has
  // no arithmetic form, so /4 is not served there.
  0x71: [2, 4, 6],
  0x72: [2, 4, 6],
  0x73: [2, 6],
  // CMPXCHG8B m64 only. /6 rdrand and /7 rdseed stay structured refusals.
  0xc7: [1],
  // LDMXCSR /2 and STMXCSR /3. FXSAVE/XRSTOR/CLFLUSH stay structured refusals.
  0xae: [2, 3],
});

function range(from, to, step = 1) {
  const value = [];
  for (let opcode = from; opcode <= to; opcode += step) value.push(opcode);
  return value;
}

const noModrmImmediate = new Map([
  [0x68, "operand"], [0x6a, 1], [0xa8, 1], [0xa9, "operand"], [0xc2, 2],
  [0xe8, 4], [0xe9, 4], [0xeb, 1],
  ...range(0x70, 0x7f).map((opcode) => [opcode, 1]),
  ...range(0xb0, 0xb7).map((opcode) => [opcode, 1]),
  ...range(0xb8, 0xbf).map((opcode) => [opcode, "operand"]),
  ...range(0xe0, 0xe3).map((opcode) => [opcode, 1]),
  ...range(0x04, 0x3c, 8).map((opcode) => [opcode, 1]),
  ...range(0x05, 0x3d, 8).map((opcode) => [opcode, "operand"]),
]);

const modrmImmediate = new Map([
  [0x80, 1], [0x81, "operand"], [0x82, 1], [0x83, 1], [0x69, "operand"],
  [0x6b, 1], [0xc0, 1], [0xc1, 1], [0xc6, 1], [0xc7, "operand"],
]);
const modrmImmediateByReg = new Map([
  [0xf6, 1], [0xf7, "operand"],
]);
const immediateGroupByReg = new Set([0xf6, 0xf7]);

function isServed(opcode, groupReg) {
  if (opcode >= 0xd8 && opcode <= 0xdf) return true;
  if (i386OpcodeGroup[opcode] !== undefined) return i386OpcodeGroup[opcode].includes(groupReg);
  if (i386OpcodeOneByte.includes(opcode)) return true;
  return false;
}

function isServed0f(extension, groupReg) {
  if (i386Opcode0fGroup[extension] !== undefined) return i386Opcode0fGroup[extension].includes(groupReg);
  return i386Opcode0f.includes(extension);
}

// Decodes one instruction for the sweep: returns its byte length, the
// canonical opcode identity, and whether the inventory serves it. The ModRM
// displacement encoding is independent of the operand size, so only the
// immediate tail depends on the 0x66 override.
export function decodeSweepInstruction(bytes, offset) {
  let cursor = offset;
  let operandSizeByte = 4;
  let opcode = bytes[cursor];
  while (opcode === 0x26 || opcode === 0x2e || opcode === 0x36 || opcode === 0x3e || opcode === 0x64 || opcode === 0x65 || opcode === 0x66 || opcode === 0x67 || opcode === 0xf0 || opcode === 0xf2 || opcode === 0xf3) {
    if (opcode === 0x64 || opcode === 0x65 || opcode === 0x67) return { length: 1, opcode, is_served: false };
    if (opcode === 0x66) operandSizeByte = 2;
    cursor += 1;
    opcode = bytes[cursor];
  }
  cursor += 1;
  const immediateSize = () => operandSizeByte === 2 ? 2 : 4;
  if (opcode === 0x0f) {
    const extension = bytes[cursor];
    cursor += 1;
    if (extension === 0xa2 || extension === 0x31 || extension === 0x77) return { length: cursor - offset, opcode: 0x0f00 | extension, is_served: true };
    if (i386Opcode0fNoModrm.includes(extension)) return { length: cursor - offset, opcode: 0x0f00 | extension, is_served: false };
    if (extension >= 0x80 && extension <= 0x8f) return { length: cursor - offset + 4, opcode: 0x0f00 | extension, is_served: true };
    const groupReg = (bytes[cursor] >>> 3) & 7;
    let length = cursor - offset + 1 + modrmLength(bytes, cursor, 4);
    if (extension === 0xa4 || extension === 0xac || extension === 0xba || extension === 0x70 || extension === 0x71 || extension === 0x72 || extension === 0x73 || extension === 0xc2 || extension === 0xc4 || extension === 0xc5 || extension === 0xc6) length += 1;
    return { length, opcode: 0x0f00 | extension, is_served: isServed0f(extension, groupReg) };
  }
  if (opcode >= 0xd8 && opcode <= 0xdf) {
    return { length: cursor - offset + 1 + modrmLength(bytes, cursor, 4), opcode, is_served: true };
  }
  const noModrm = noModrmImmediate.get(opcode);
  if (noModrm !== undefined) {
    const tail = noModrm === "operand" ? immediateSize() : noModrm;
    return { length: cursor - offset + tail, opcode, is_served: isServed(opcode, 0) };
  }
  const groupReg = (bytes[cursor] >>> 3) & 7;
  let tail = 0;
  if (modrmImmediate.has(opcode)) tail = modrmImmediate.get(opcode) === "operand" ? immediateSize() : modrmImmediate.get(opcode);
  else if (immediateGroupByReg.has(opcode) && (groupReg === 0 || groupReg === 1)) tail = modrmImmediateByReg.get(opcode) === "operand" ? immediateSize() : modrmImmediateByReg.get(opcode);
  return { length: cursor - offset + 1 + modrmLength(bytes, cursor, 4) + tail, opcode, is_served: isServed(opcode, groupReg) };
}

// ModRM displacement and SIB length in byte for the sweep's linear progress.
function modrmLength(bytes, modrmOffset, sizeByte) {
  const modrm = bytes[modrmOffset];
  const mode = modrm >>> 6;
  const rm = modrm & 7;
  if (mode === 3) return 0;
  let length = 0;
  if (rm === 4) {
    length += 1;
    const sib = bytes[modrmOffset + 1];
    if (mode === 0 && (sib & 7) === 5) length += 4;
  } else if (mode === 0 && rm === 5) length += 4;
  if (mode === 1) length += 1;
  else if (mode === 2) length += 4;
  return length;
}

const histogramBound = 64;

// Linear decode sweep over one executable section: walks the bytes with the
// same prefix and ModRM length rules the probe decodes, classifies every
// instruction against the declared inventory, and reports how far the real
// .text decodes toward the entry. A byte the decoder cannot serve is counted
// as one unsupported instruction with its opcode; the sweep never executes.
export function sweepI386Text(inputPath) {
  const mapped = mapPe32(inputPath);
  const image = readFileSync(inputPath);
  const section = mapped.section.find((entry) => entry.virtual_address <= mapped.entry_rva && mapped.entry_rva < entry.virtual_address + entry.mapped_size_byte) ?? mapped.section.find((entry) => entry.name === ".text");
  if (section === undefined) throw new Error("The image carries no decodable section");
  const sectionEnd = Math.min(section.virtual_address + section.virtual_size_byte, section.virtual_address + section.raw_size_byte);
  const bytes = image.subarray(section.raw_offset, section.raw_offset + (sectionEnd - section.virtual_address));
  const histogram = new Map();
  let decodedCount = 0;
  let unsupportedCount = 0;
  let firstUnsupported = null;
  let offset = 0;
  while (offset < bytes.length) {
    const instruction = decodeSweepInstruction(bytes, offset);
    if (!Number.isFinite(instruction.length) || instruction.length < 1) {
      throw new Error(`The decode sweep produced an invalid instruction length at ${section.virtual_address + offset}`);
    }
    decodedCount += 1;
    if (!instruction.is_served) {
      unsupportedCount += 1;
      histogram.set(instruction.opcode, (histogram.get(instruction.opcode) ?? 0) + 1);
      if (firstUnsupported === null) firstUnsupported = { virtual_address: mapped.image_base + section.virtual_address + offset, opcode: instruction.opcode };
    }
    offset += instruction.length;
  }
  return {
    schema_version: 1,
    input_path: inputPath,
    section_name: section.name,
    section_virtual_address: section.virtual_address,
    text_size_byte: bytes.length,
    decoded_instruction_count: decodedCount,
    served_instruction_count: decodedCount - unsupportedCount,
    unsupported_instruction_count: unsupportedCount,
    coverage_ratio: decodedCount === 0 ? 1 : Number(((decodedCount - unsupportedCount) / decodedCount).toFixed(6)),
    first_unsupported: firstUnsupported,
    unsupported_histogram: [...histogram.entries()].sort((left, right) => right[1] - left[1]).slice(0, histogramBound).map(([opcode, count]) => ({ opcode, count })),
    is_executed: false,
  };
}

export { executeProbe, refuseI386Execution, chooseStackBase, normalizeStackSize, RuntimeFault } from "./runtime.mjs";
