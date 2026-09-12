// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The i386 fast-plan extension for tight integer / switch loops. The probe's
// register-only cache (lib/runtime.mjs buildFastPlan) already replays inc/dec,
// jcc rel8, and a handful of SSE forms. Inflate-class loops — `sub/cmp eax,imm`
// then a backward `jmp rel32` into `jmp [index*scale+disp32]` — still fell
// through to the byte-at-a-time decoder. This module names those shapes
// generically (any similar switch or counted back-edge, no title test) and
// returns a plan the existing cache can replay. IAT `jmp [slot]` (no index)
// and 16-bit operand-size forms stay unplanned so the interpreter remains
// the one path that can see an import thunk.

const ALU_KIND = Object.freeze(["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]);
const EAX_IMM32 = Object.freeze({
  0x05: "add", 0x0d: "or", 0x15: "adc", 0x1d: "sbb",
  0x25: "and", 0x2d: "sub", 0x35: "xor", 0x3d: "cmp",
});

function u32(raw, offset) {
  return (raw[offset] | (raw[offset + 1] << 8) | (raw[offset + 2] << 16) | (raw[offset + 3] << 24)) >>> 0;
}

function s32(raw, offset) {
  return u32(raw, offset) | 0;
}

function plan(length, apply) {
  return { length, apply };
}

// `ctx` is the live probe closure: the same getRegister / arithmetic /
// readMemory / HLE dispatch the interpreter uses, so a planned instruction
// is bit-exact with falling through to executeInstruction.
export function extendI386FastPlan(ctx) {
  const {
    raw, eip, is_prefix66, is_prefix_f2, is_prefix_f3,
    getRegister, setRegister, arithmetic, unsigned, signExtend, readMemory,
    set_instruction_pointer, hleGuest, dispatchHle,
  } = ctx;
  if (!raw || raw.length < 1) return null;
  if (is_prefix66 || is_prefix_f2 || is_prefix_f3) return null;

  const opcode = raw[0];

  const eaxImm = EAX_IMM32[opcode];
  if (eaxImm !== undefined && raw.length >= 5) {
    const immediate = u32(raw, 1);
    const writeBack = eaxImm !== "cmp";
    return plan(5, () => {
      const result = arithmetic(eaxImm, getRegister(0, 4), immediate, 4, writeBack);
      if (writeBack) setRegister(0, result, 4);
      set_instruction_pointer(unsigned(eip + 5));
    });
  }

  if (opcode === 0xe9 && raw.length >= 5) {
    const displacement = s32(raw, 1);
    return plan(5, () => {
      set_instruction_pointer(unsigned(eip + 5 + displacement));
    });
  }

  if (opcode === 0xeb && raw.length >= 2) {
    const displacement = signExtend(raw[1], 8);
    return plan(2, () => {
      set_instruction_pointer(unsigned(eip + 2 + displacement));
    });
  }

  if ((opcode === 0x81 || opcode === 0x83) && raw.length >= 2 && (raw[1] >>> 6) === 3) {
    const modrm = raw[1];
    const kind = ALU_KIND[(modrm >>> 3) & 7];
    const dest = modrm & 7;
    const isImm8 = opcode === 0x83;
    const length = isImm8 ? 3 : 6;
    if (raw.length < length) return null;
    const immediate = isImm8 ? signExtend(raw[2], 8) : u32(raw, 2);
    const writeBack = kind !== "cmp";
    return plan(length, () => {
      const result = arithmetic(kind, getRegister(dest, 4), immediate, 4, writeBack);
      if (writeBack) setRegister(dest, result, 4);
      set_instruction_pointer(unsigned(eip + length));
    });
  }

  if (opcode !== 0xff || raw.length < 2) return null;
  const modrm = raw[1];
  const operation = (modrm >>> 3) & 7;
  if (operation !== 4) return null;
  const mode = modrm >>> 6;
  const rm = modrm & 7;

  // jmp r32 — a computed pointer, including a recovered table index sitting
  // in a register. Not an IAT slot.
  if (mode === 3) {
    return plan(2, () => {
      const target = getRegister(rm, 4);
      const hleEntry = hleGuest !== null && (target & 3) === 0 ? hleGuest.exportAt(target) : null;
      if (hleEntry !== null) {
        dispatchHle(hleEntry, true);
        return;
      }
      set_instruction_pointer(target);
    });
  }

  // Compiler jump table: jmp [index*scale + disp32], SIB with no base.
  // `jmp [disp32]` (no index) is the IAT tail-jump and stays unplanned.
  if (mode !== 0 || rm !== 4 || raw.length < 7) return null;
  const sib = raw[2];
  const scale = 1 << (sib >>> 6);
  const index = (sib >>> 3) & 7;
  const base = sib & 7;
  if (base !== 5 || index === 4) return null;
  if (scale !== 4 && scale !== 8) return null;
  const displacement = u32(raw, 3);
  return plan(7, () => {
    const address = unsigned(displacement + getRegister(index, 4) * scale);
    const target = readMemory(address, 4);
    const hleEntry = hleGuest !== null && (target & 3) === 0 ? hleGuest.exportAt(target) : null;
    if (hleEntry !== null) {
      dispatchHle(hleEntry, true);
      return;
    }
    set_instruction_pointer(target);
  });
}
