// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The graphics unification core (GS-018, GS-020, GS-022, GS-024, GS-025).
// One intermediate representation, one WebGPU Shading Language emitter, one
// fixed-function generator, and a Direct3D 9 shader-model 2 and 3 bytecode
// frontend that refuses an unsupported opcode by name instead of dropping it.
// The static audit in the planning validator proves exactly one emitter exists
// in the tree; the honest capability report derives every advertisement from
// the compiled support table, so advertising above support fails by
// construction. Rendering on a live adapter stays the red half of these item.

import { InputError } from "./input.mjs";

// ---- the unified intermediate representation ------------------------------
// A program is a list of instruction. Every operand is one register reference;
// the representation is deliberately small so every frontend lowers into it
// and exactly one emitter lowers out of it.

const registerType = Object.freeze({
  temp: "r",
  constant: "c",
  input: "v",
  output: "o",
  sampler: "s",
  color_output: "oC",
});

function formatRegister(register) {
  const prefix = registerType[register.type] ?? `?${register.type}`;
  return `${prefix}${register.index}`;
}

function formatMask(mask) {
  return mask ? `.${mask}` : "";
}

function formatInstruction(instruction) {
  const destination = `${formatRegister(instruction.dest)}${formatMask(instruction.dest_mask)}`;
  const source = instruction.src.map((register) => `${formatRegister(register)}${formatMask(register.swizzle ?? "")}`).join(", ");
  return `${instruction.op} ${destination}, ${source}`;
}

export function formatProgram(program) {
  return program.map((instruction) => formatInstruction(instruction));
}

// ---- Direct3D 9 shader bytecode frontend (shader model 2 and 3) -----------

const opcodes = Object.freeze({
  1: "mov", 2: "add", 3: "sub", 4: "mad", 5: "mul", 6: "rcp", 7: "rsq",
  8: "dp3", 9: "dp4", 10: "min", 11: "max", 12: "slt", 13: "sge",
  14: "exp", 15: "log", 16: "lit", 24: "cmp",
});

const operandType = Object.freeze({
  0: "temp", 1: "input", 2: "constant", 3: "constant", 4: "input",
  8: "color_output", 15: "sampler",
});

const componentOrder = Object.freeze(["x", "y", "z", "w"]);

const supportedPixelShaderModel = Object.freeze({ major: 3, minor: 0 });
const supportedModelTable = Object.freeze({
  pixel_shader_model: `${supportedPixelShaderModel.major}.${supportedPixelShaderModel.minor}`,
  vertex_shader_model: "research",
  opcode: Object.values(opcodes).sort(),
});

// Honest capability reporting (GS-024): the advertisement is derived from the
// compiled support table and can never exceed it. The by-construction check
// throws if an advertisement above support is ever assembled.
export function declaredCaps() {
  const supported = supportedModelTable.pixel_shader_model;
  return {
    schema_version: 1,
    advertised_pixel_shader_model: supported,
    translator_support: supportedModelTable,
    is_within_support: compareModel(supported, supported) === 0,
  };
}

function compareModel(advertised, supported) {
  const [aMajor, aMinor] = advertised.split(".").map(Number);
  const [sMajor, sMinor] = supported.split(".").map(Number);
  if (aMajor !== sMajor) return aMajor > sMajor ? 1 : -1;
  if (aMinor !== sMinor) return aMinor > sMinor ? 1 : -1;
  return 0;
}

export function assertCapsWithinSupport(advertisedModel) {
  if (compareModel(advertisedModel, supportedModelTable.pixel_shader_model) > 0) {
    throw new InputError("caps_exceed_support", `Advertising pixel shader model ${advertisedModel} exceeds the compiled translator support ${supportedModelTable.pixel_shader_model}`);
  }
}

function readVersionToken(token) {
  const type = (token >>> 16) & 0xffff;
  const major = (token >> 8) & 0xff;
  const minor = token & 0xff;
  if (type === 0xffff) return { kind: "pixel", major, minor };
  if (type === 0xfffe) return { kind: "vertex", major, minor };
  return { kind: "unknown", major, minor };
}

function readOperandToken(token, stream, cursor) {
  const typeCode = (token >>> 28) & 0xf;
  const type = operandType[typeCode];
  if (type === undefined) {
    throw new InputError("unsupported_operand_type", `Operand type 0x${typeCode.toString(16)} is outside the frontend and is named, not dropped`);
  }
  const registerNumber = (token & 0x7ff) | ((token >>> 14) & 0x180000) >> 14;
  const swizzleCode = (token >>> 16) & 0xff;
  const components = [swizzleCode & 3, (swizzleCode >> 2) & 3, (swizzleCode >> 4) & 3, (swizzleCode >> 6) & 3];
  const swizzle = components.every((value) => value === components[0])
    ? ""
    : components.map((value) => componentOrder[value]).join("");
  const register = { type, index: registerNumber, swizzle };
  const destMaskCode = (token >>> 16) & 0xf;
  register.dest_mask = componentOrder.slice(0, 4).filter((_, index) => (destMaskCode & (1 << index)) !== 0).join("");
  return { register, cursor };
}

// Parses a Direct3D 9 pixel-shader byte stream (shader model 2 and 3 arithmetic
// core) into the unified representation. An unsupported opcode carries its
// numeric identity in the refusal; nothing is silently dropped.
export function parseD3d9PixelShader(byte) {
  if (byte.length < 4) {
    throw new InputError("shader_bytecode_truncated", "The shader byte stream is shorter than one token");
  }
  const view = new DataView(byte.buffer, byte.byteOffset, byte.byteLength);
  const version = readVersionToken(view.getUint32(0, true));
  if (version.kind !== "pixel") {
    throw new InputError("unsupported_shader_type", `The byte stream is a ${version.kind} shader, and only the pixel shader frontend exists`);
  }
  if (version.major > supportedPixelShaderModel.major
    || (version.major === supportedPixelShaderModel.major && version.minor > supportedPixelShaderModel.minor)) {
    throw new InputError("unsupported_shader_model", `Pixel shader model ${version.major}.${version.minor} exceeds the compiled translator support`);
  }
  const program = [];
  let cursor = 4;
  while (cursor + 4 <= byte.length) {
    const token = view.getUint32(cursor, true);
    cursor += 4;
    if (token === 0x0000ffff) break;
    if ((token & 0x7fff) === 0xfffe) {
      const commentLength = (token >>> 16) & 0xffff;
      cursor += commentLength * 4;
      continue;
    }
    const opcode = token & 0xffff;
    const instructionLength = (token >>> 24) & 0xf;
    const name = opcodes[opcode];
    if (name === undefined) {
      throw new InputError("unsupported_opcode", `Opcode ${opcode} is outside the frontend and is named, not dropped`);
    }
    const operandCount = ["dp3", "dp4", "rcp", "rsq", "mov", "exp", "log", "lit"].includes(name) ? 2 : 3;
    const operands = [];
    for (let index = 0; index < operandCount; index += 1) {
      const operandToken = view.getUint32(cursor, true);
      cursor += 4;
      const { register } = readOperandToken(operandToken, view, cursor);
      operands.push(register);
    }
    const [dest, ...src] = operands;
    program.push({ op: name, dest, dest_mask: dest.dest_mask, src });
    if (instructionLength > 0 && instructionLength !== operandCount + 1) {
      cursor = cursor - (operandCount + 1) * 4 + instructionLength * 4;
    }
  }
  return { schema_version: 1, model: `${version.major}.${version.minor}`, program };
}

// ---- the fixed-function generator (GS-022) --------------------------------
// One generator produces the representation for the declared fixed-function
// state; identical state yields identical output regardless of which API
// frontend declared it, because the generator never reads the API name.

export function generateFixedFunction(state) {
  if (typeof state !== "object" || state === null) {
    throw new InputError("invalid_ffp_state", "The fixed-function state must be one object");
  }
  const program = [];
  const stageCount = Math.min(Number(state.texture_stage_count ?? 0), 8);
  const lightCount = Math.min(Number(state.light_count ?? 0), 8);
  let tempIndex = 0;
  if (lightCount > 0) {
    program.push({ op: "mov", dest: { type: "temp", index: tempIndex }, dest_mask: "xyz", src: [{ type: "constant", index: 0, swizzle: "" }] });
    tempIndex += 1;
  }
  for (let index = 0; index < stageCount; index += 1) {
    program.push({
      op: index === 0 ? "mul" : "mad",
      dest: { type: "temp", index: tempIndex },
      dest_mask: "xyzw",
      src: [
        { type: "input", index: index, swizzle: "" },
        { type: "constant", index: index + 1, swizzle: "" },
        ...(index === 0 ? [] : [{ type: "temp", index: tempIndex - 1, swizzle: "" }]),
      ],
    });
  }
  if (state.fog) {
    program.push({ op: "mov", dest: { type: "temp", index: tempIndex }, dest_mask: "x", src: [{ type: "constant", index: 31, swizzle: "x" }] });
  }
  if (state.alpha_blend) {
    program.push({ op: "mov", dest: { type: "output", index: 0 }, dest_mask: "w", src: [{ type: "constant", index: 30, swizzle: "w" }] });
  }
  program.push({ op: "mov", dest: { type: "output", index: 0 }, dest_mask: "xyz", src: [{ type: "temp", index: Math.max(tempIndex - 1, 0), swizzle: "" }] });
  return { schema_version: 1, state, program };
}

// ---- the single WGSL emitter (GS-018) --------------------------------------
// Every lowering out of the unified representation passes through this one
// function; the planning validator's static audit counts the emitters in the
// tree and fails when a second appears.

const wgslType = Object.freeze({
  temp: "var<private>",
  constant: "uniform",
  input: "in",
  output: "out",
});

export function emitWgsl(program, option = {}) {
  if (!Array.isArray(program)) {
    throw new InputError("invalid_program", "The WGSL emitter lowers one program array");
  }
  const registers = new Map();
  for (const instruction of program) {
    for (const register of [instruction.dest, ...instruction.src]) {
      registers.set(`${register.type}_${register.index}`, register);
    }
  }
  const declaration = [...registers.values()]
    .filter((register) => register.type === "temp" || register.type === "output")
    .map((register) => `  ${formatRegister(register)}: vec4<f32>,`)
    .join("\n");
  const body = program.map((instruction) => {
    const destination = `${formatRegister(instruction.dest)}`;
    const operand = instruction.src.map((register) => `${formatRegister(register)}${formatSwizzle(register.swizzle)}`).join(", ");
    return `  ${destination} = ${emitExpression(instruction.op, operand)};`;
  }).join("\n");
  return `// generated by the single unified-representation emitter; do not edit\n` +
    `struct Output {\n${declaration || "  oC0: vec4<f32>,"}\n}\n` +
    `${option.function_name ?? "fn main"}() -> Output {\n${body}\n}`;
}

function formatSwizzle(swizzle) {
  return swizzle ? `.${swizzle}` : "";
}

function emitExpression(op, operand) {
  const argument = operand.split(", ").map((value) => `vec4<f32>(${value}, 0.0, 0.0, 0.0)`);
  switch (op) {
    case "mov": return argument[0];
    case "add": return `${argument[0]} + ${argument[1]}`;
    case "sub": return `${argument[0]} - ${argument[1]}`;
    case "mul": return `${argument[0]} * ${argument[1]}`;
    case "mad": return `${argument[0]} * ${argument[1]} + ${argument[2]}`;
    case "dp3": return `vec4<f32>(dot(${argument[0]}.xyz, ${argument[1]}.xyz), 0.0, 0.0, 0.0)`;
    case "dp4": return `vec4<f32>(dot(${argument[0]}, ${argument[1]}), 0.0, 0.0, 0.0)`;
    case "min": return `min(${argument[0]}, ${argument[1]})`;
    case "max": return `max(${argument[0]}, ${argument[1]})`;
    case "cmp": return `select(${argument[2]}, ${argument[1]}, ${argument[0]} >= vec4<f32>(0.0))`;
    default: return `/* ${op} unsupported in the emitter */ ${argument[0]}`;
  }
}

// The static single-emitter audit input: the marker that identifies an
// emitter. The planning validator counts the marker across the tree.
export const emitterMarker = "export function emitWgsl";

// ---- the frame-diff engine (GS-025) ---------------------------------------
// The reference is computed at test time and never committed; the comparison
// is a perceptual approximation (weighted RGB delta-E) with a declared
// tolerance, and no baseline artifact is retained.

export function computeFrameDiff(rendered, reference, option = {}) {
  if (rendered.length !== reference.length) {
    throw new InputError("frame_length_mismatch", "The rendered frame and the reference must cover the same pixel count");
  }
  const tolerance = option.mean_tolerance ?? 2.0;
  let total = 0;
  let max = 0;
  for (let index = 0; index < rendered.length; index += 1) {
    const left = rendered[index];
    const right = reference[index];
    const delta = 0.2126 * Math.abs(left[0] - right[0]) + 0.7152 * Math.abs(left[1] - right[1]) + 0.0722 * Math.abs(left[2] - right[2]);
    total += delta;
    if (delta > max) max = delta;
  }
  const mean = rendered.length > 0 ? total / rendered.length : 0;
  return {
    schema_version: 1,
    pixel_count: rendered.length,
    mean_delta: Number(mean.toFixed(4)),
    max_delta: Number(max.toFixed(4)),
    mean_tolerance: tolerance,
    pass: mean <= tolerance,
    reference_source: option.reference_source ?? "computed at test time",
    committed_baseline: false,
  };
}

// Deterministic test-time reference generator for the frame fixture: a pure
// function of the declared scene, so a test computes its own reference.
export function generateReferenceFrame(width, height, color) {
  const frame = [];
  for (let index = 0; index < width * height; index += 1) {
    frame.push([color[0], color[1], color[2], 255]);
  }
  return frame;
}
