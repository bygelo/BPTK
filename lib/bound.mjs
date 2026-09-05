// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { InputError } from "./input.mjs";

// Declared resource bound. Every extraction, streaming, and execution surface
// refuses input beyond the frozen constant instead of growing unbounded.
export const extractionBoundDefault = Object.freeze({
  // Largest total decompressed payload one extraction may emit.
  output_byte: 1024 * 1024 * 1024,
  // Largest decompressed-to-compressed amplification one chunk may have.
  // Calibrated at 64 after the corpus refused a lawful game archive at 33:1
  // (a bitmap-heavy release); genuine bomb input sits near 1000:1, and the
  // total output bound still caps every extraction regardless of ratio.
  ratio_max: 64,
  // Smallest output the amplification guard applies to. A small high-ratio
  // entry cannot exhaust anything, and the corpus showed a lawful game
  // archive refused at 196662 byte; the guard scales with absolute output.
  ratio_floor_byte: 1024 * 1024,
  // Largest number of payload entry one extraction may enumerate.
  entry_count: 200000,
  // Deepest payload directory nesting one extraction may create.
  depth_count: 16,
  // Largest single compressed read handed to a decompressor.
  chunk_input_byte: 64 * 1024 * 1024,
});

// Largest total mod overlay one apply may layer over a read-only base. A mod is
// content, not an archive, so it is bounded on absolute output alone.
export const modOverlayByteDefault = 256 * 1024 * 1024;

export const executionBoundDefault = Object.freeze({
  // Largest guest instruction count one probe execution may run.
  instruction_count: 10000000,
  // Largest stack reservation one probe execution may map.
  stack_byte: 16 * 1024 * 1024,
});

function boundError(code, message) {
  return new InputError(code, message);
}

export function createExtractionBound(option = {}) {
  const bound = { ...extractionBoundDefault, ...option };
  for (const key of Object.keys(extractionBoundDefault)) {
    if (!Number.isSafeInteger(bound[key]) || bound[key] < 1) {
      throw boundError("invalid_bound", `Bound ${key} must be a safe positive integer`);
    }
  }
  return Object.freeze(bound);
}

// Declares the per-chunk decompression output cap derived from the bound so a
// decompression bomb is refused before its output is allocated.
export function chunkOutputCap(bound, inputSizeByte) {
  const inputByte = Math.max(Number(inputSizeByte), 1);
  const ratioCap = inputByte * bound.ratio_max;
  return Math.min(bound.output_byte, ratioCap, Number.MAX_SAFE_INTEGER);
}

export function assertEntryBound(bound, entryCount) {
  if (entryCount > bound.entry_count) {
    throw boundError("bound_entry_exceeded", `Payload entry count ${entryCount} exceeds the declared bound ${bound.entry_count}`);
  }
}

export function assertDepthBound(bound, depthCount) {
  if (depthCount > bound.depth_count) {
    throw boundError("bound_depth_exceeded", `Payload depth ${depthCount} exceeds the declared bound ${bound.depth_count}`);
  }
}

export function assertOutputBound(bound, outputByte) {
  if (outputByte > bound.output_byte) {
    throw boundError("bound_output_exceeded", `Decompressed output ${outputByte} byte exceeds the declared bound ${bound.output_byte}`);
  }
}

export function assertChunkInputBound(bound, inputByte) {
  if (inputByte > bound.chunk_input_byte) {
    throw boundError("bound_input_exceeded", `Compressed chunk ${inputByte} byte exceeds the declared bound ${bound.chunk_input_byte}`);
  }
}

export function assertChunkRatioBound(bound, inputByte, outputByte) {
  const inputCount = Math.max(Number(inputByte), 1);
  if (outputByte <= bound.ratio_floor_byte) {
    return;
  }
  if (outputByte / inputCount > bound.ratio_max) {
    throw boundError("bound_ratio_exceeded", `Decompression ratio ${outputByte}/${inputByte} exceeds the declared bound ${bound.ratio_max}`);
  }
}

export function describeExtractionBound(bound) {
  return {
    output_byte: bound.output_byte,
    ratio_max: bound.ratio_max,
    entry_count: bound.entry_count,
    depth_count: bound.depth_count,
    chunk_input_byte: bound.chunk_input_byte,
  };
}
