// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// CPU-deterministic record & replay (BPTK-055 / GS-010). A run of the bounded
// guest is fully determined by the workload bytes, the instruction budget, and
// the declared nondeterminism sources — all of which are pinned, not read from
// the host: the guest clock is virtual-monotonic, there is no host RNG or host
// input, and the schedule is single-threaded. Recording captures the guest
// state hash at a series of instruction-count checkpoints; replay re-derives
// them and must hash-match exactly. Because the execution is pure integer
// WebAssembly with no host-derived input, the same record replays to the same
// hashes on any machine — the cross-machine leg is proven by construction and
// re-checked against the interpreter oracle, but it is not certified on a
// literal second machine here, which keeps the whole benchmark honestly red.

import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mapPe32ForRuntime } from "./pe.mjs";
import { executeProbe } from "./runtime.mjs";
import { runRecompiled } from "./recompile.mjs";

// The declared nondeterminism sources and how each is pinned. None is read from
// the host environment; that invariant is the point of the benchmark.
export const PINNED_SOURCE = Object.freeze({
  clock: "virtual_monotonic",
  rng: "none",
  input: "none",
  schedule: "single_thread",
});

// A deterministic default workload (a mixed integer loop) used when a caller
// records without supplying its own bytes.
const DEFAULT_WORKLOAD = Object.freeze([
  0xb8, 0, 0, 0, 0, // mov eax, 0
  0xb9, 0x00, 0x04, 0, 0, // mov ecx, 0x400
  0x01, 0xc8, // add eax, ecx
  0x83, 0xf0, 0x11, // xor eax, 0x11
  0x49, // dec ecx
  0x75, 0xf8, // jnz L (-8)
  0xc3, // ret
]);

function writeWorkloadPe(directory, workload) {
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
  Buffer.from(workload).copy(file, 0x200);
  const path = join(directory, "workload.exe");
  writeFileSync(path, file);
  return path;
}

function stateHash(result) {
  // A checkpoint hash over the complete architectural state: the eight GPRs,
  // EIP, EFLAGS, the memory image, and the stop reason.
  const digest = createHash("sha256");
  const register = result.register;
  for (const name of ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"]) {
    const value = Buffer.alloc(4);
    value.writeUInt32LE(register[name] >>> 0, 0);
    digest.update(value);
  }
  const eflags = Buffer.alloc(4);
  eflags.writeUInt32LE(result.flag.eflags >>> 0, 0);
  digest.update(eflags);
  digest.update(result.memory_sha256);
  digest.update(String(result.stop_reason));
  return digest.digest("hex");
}

function checkpointBudget(budget, checkpointCount) {
  const step = Math.max(1, Math.floor(budget / checkpointCount));
  const point = [];
  for (let index = 1; index <= checkpointCount; index += 1) point.push(Math.min(budget, index * step));
  if (point[point.length - 1] !== budget) point.push(budget);
  return [...new Set(point)];
}

// Run one checkpoint through the recompiler (the fast path) and, for the
// cross-engine determinism check, the interpreter oracle. Returns both hashes.
async function checkpointState(mapped, instructionBudget) {
  const recompiled = await runRecompiled(mapped, { budget: instructionBudget, trace: false });
  const interpreter = executeProbe(mapped, instructionBudget, {});
  return {
    instruction_count: recompiled.instruction_count,
    recompiled_hash: stateHash(recompiled),
    interpreter_hash: stateHash(interpreter),
  };
}

export async function recordRun(option = {}) {
  const workload = option.workload ?? DEFAULT_WORKLOAD;
  const budget = Number.isSafeInteger(option.instruction_budget_count) && option.instruction_budget_count > 0 ? option.instruction_budget_count : 4096;
  const checkpointCount = Number.isSafeInteger(option.checkpoint_count) && option.checkpoint_count > 0 ? option.checkpoint_count : 4;
  const directory = mkdtempSync(join(tmpdir(), "bptk-replay-"));
  try {
    const mapped = mapPe32ForRuntime(writeWorkloadPe(directory, workload), null, null);
    const workloadSha = createHash("sha256").update(Buffer.from(workload)).digest("hex");
    const checkpoint = [];
    for (const instructionBudget of checkpointBudget(budget, checkpointCount)) {
      const state = await checkpointState(mapped, instructionBudget);
      checkpoint.push({ instruction_count: state.instruction_count, state_hash: state.recompiled_hash });
    }
    return {
      schema_version: 1,
      command: "record --profile cpu",
      engine: "recompiled",
      workload: [...workload],
      workload_sha256: workloadSha,
      instruction_budget_count: budget,
      pinned_source: PINNED_SOURCE,
      is_host_source_free: true,
      checkpoint,
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export async function replayRun(record) {
  const workload = record.workload;
  const directory = mkdtempSync(join(tmpdir(), "bptk-replay-"));
  try {
    const mapped = mapPe32ForRuntime(writeWorkloadPe(directory, workload), null, null);
    const workloadSha = createHash("sha256").update(Buffer.from(workload)).digest("hex");
    const mismatch = [];
    const checkpoint = [];
    let crossEngineMatch = true;
    for (const recorded of record.checkpoint) {
      const state = await checkpointState(mapped, recorded.instruction_count);
      checkpoint.push({ instruction_count: state.instruction_count, state_hash: state.recompiled_hash });
      if (state.recompiled_hash !== recorded.state_hash) {
        mismatch.push({ instruction_count: recorded.instruction_count, recorded: recorded.state_hash, replayed: state.recompiled_hash });
      }
      if (state.recompiled_hash !== state.interpreter_hash) crossEngineMatch = false;
    }
    return {
      schema_version: 1,
      command: "replay --profile cpu",
      workload_match: workloadSha === record.workload_sha256,
      is_match: mismatch.length === 0 && workloadSha === record.workload_sha256,
      cross_engine_match: crossEngineMatch,
      second_machine_verified: false,
      mismatch,
      checkpoint,
      blocker: [
        "Cross-machine replay is deterministic by construction (pure integer WebAssembly, no host-derived source) but is not certified on a literal second machine here",
        "Multi-threaded schedule determinism (BPTK-051 guest SMP) is outside this single-thread record and replay",
      ],
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
