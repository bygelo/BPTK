// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { InputError } from "./input.mjs";
import { readPackageManifest } from "./package.mjs";
import { mapPe32ForRuntime } from "./pe.mjs";
import { executeProbe } from "./runtime.mjs";
import { recompileImage } from "./recompile.mjs";
import { measureCrossing, CROSSING_COST_BAR_NANOSECOND } from "./abi.mjs";

// The declared performance bars (BPTK-002 pins the reference machine profile).
// These are the numbers "gold standard" means; the harness measures against
// them honestly and never claims a bar cleared on an unpinned host.
export const PERFORMANCE_BAR = Object.freeze({
  mips_floor: 770, // GS-092: the throughput floor BottleShip's own traces cite (it reaches 174).
  interpreter_multiple: 5, // GS-093: recompiled must be >= 5x the interpreter.
  native_fraction: 0.5, // GS-093: recompiled must be >= 50% of native.
});

// The frozen CPU-bound workload (the FIX-016 microprogram, pinned here as a
// deterministic byte sequence so the measurement is reproducible). It mixes
// register ALU, wide-immediate logic, byte-immediate arithmetic, and a
// conditional loop so no single instruction class dominates the throughput.
const FROZEN_WORKLOAD = Object.freeze([
  0xb8, 0, 0, 0, 0, // mov eax, 0
  0xb9, 0, 0, 0x10, 0, // mov ecx, 0x00100000
  // L:
  0x01, 0xc8, // add eax, ecx
  0x35, 0x5a, 0x5a, 0x5a, 0x5a, // xor eax, 0x5a5a5a5a
  0x83, 0xc0, 0x07, // add eax, 7
  0x29, 0xc8, // sub eax, ecx
  0x25, 0xff, 0xff, 0xff, 0x7f, // and eax, 0x7fffffff
  0x49, // dec ecx
  0x75, 0xec, // jnz L (-20)
  0xc3, // ret
]);

function writeFrozenWorkloadPe(directory) {
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
  Buffer.from(FROZEN_WORKLOAD).copy(file, 0x200);
  const path = join(directory, "workload.exe");
  writeFileSync(path, file);
  return path;
}

function mips(instructionCount, millisecond) {
  if (millisecond <= 0) return 0;
  return Number(((instructionCount / (millisecond / 1000)) / 1e6).toFixed(1));
}

// BPTK-136 (GS-092) throughput floor + BPTK-137 (GS-093) recompile-vs-interpret
// speedup — the moat metric. Runs the frozen workload through the interpreter
// oracle and the recompiled WebAssembly module on this host, measures sustained
// instruction throughput and the speedup, and reports honestly: the recompiled
// path is proven to compute the same result as the interpreter, but the 770-MIPS
// floor and the >=50%-of-native fraction cannot be *cleared* here because the
// BPTK-002 reference desktop and a native baseline are not available, so the
// benchmark stays red.
export function benchmarkRecompiler(option = {}) {
  const instructionBudget = Number.isSafeInteger(option.instruction_budget_count) && option.instruction_budget_count > 0
    ? option.instruction_budget_count
    : 2_000_000;
  const directory = mkdtempSync(join(tmpdir(), "bptk-perf-"));
  try {
    const mapped = mapPe32ForRuntime(writeFrozenWorkloadPe(directory), null, null);

    // Interpreter oracle timing.
    const interpreterStart = performance.now();
    const interpreter = executeProbe(mapped, instructionBudget, {});
    const interpreterMillisecond = performance.now() - interpreterStart;

    // Recompiled module: compile once, then time only sustained execution.
    const compiled = recompileImage(mapped, { trace: false, budget: instructionBudget });
    if (compiled.refuse) throw new InputError("recompile_refused", `The frozen workload did not recompile: ${compiled.refuse.message}`);
    const module = new WebAssembly.Module(compiled.wasm);
    const instance = new WebAssembly.Instance(module, {});
    instance.exports.run(1); // warm the tier-up path with a negligible run
    const resetInstance = new WebAssembly.Instance(module, {});
    const recompiledStart = performance.now();
    resetInstance.exports.run(instructionBudget);
    const recompiledMillisecond = performance.now() - recompiledStart;

    const recompiledInstruction = resetInstance.exports.count.value >>> 0;
    const recompiledEax = resetInstance.exports.eax.value >>> 0;
    const recompiledEcx = resetInstance.exports.ecx.value >>> 0;
    const isEquivalent = recompiledInstruction === interpreter.instruction_count
      && recompiledEax === interpreter.register.eax
      && recompiledEcx === interpreter.register.ecx;

    const interpreterMips = mips(interpreter.instruction_count, interpreterMillisecond);
    const recompiledMips = mips(recompiledInstruction, recompiledMillisecond);
    const interpreterMultiple = interpreterMips > 0 ? Number((recompiledMips / interpreterMips).toFixed(2)) : null;

    return {
      schema_version: 1,
      command: "benchmark --profile recompiler",
      profile: "recompiler_throughput",
      workload: "frozen_cpu_bound_v1",
      instruction_budget_count: instructionBudget,
      interpreter: { instruction_count: interpreter.instruction_count, millisecond: Number(interpreterMillisecond.toFixed(3)), mips: interpreterMips },
      recompiled: { instruction_count: recompiledInstruction, millisecond: Number(recompiledMillisecond.toFixed(3)), mips: recompiledMips, block_count: compiled.blockCount, fallback_count: compiled.fallbackCount },
      interpreter_multiple: interpreterMultiple,
      native_fraction: null,
      is_equivalent: isEquivalent,
      bar: PERFORMANCE_BAR,
      measured_on_reference_desktop: false,
      is_floor_cleared_here: recompiledMips >= PERFORMANCE_BAR.mips_floor,
      is_multiple_cleared_here: interpreterMultiple !== null && interpreterMultiple >= PERFORMANCE_BAR.interpreter_multiple,
      is_bar_cleared: false,
      blocker: [
        "The BPTK-002 reference desktop profile is not the measurement host, so the 770-MIPS floor cannot be certified here",
        "No native-execution baseline exists, so the >=50%-of-native fraction of GS-093 cannot be measured",
      ],
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

// The declared cold/warm start and memory-ceiling bars (BPTK-002 reference).
export const START_BUDGET_MILLISECOND = Object.freeze({ cold: 5000, warm: 1500 });
export const MEMORY_CEILING_BYTE = 2 * 1024 * 1024 * 1024; // 2 GB declared ceiling.

function mapFrozen(directory) {
  return mapPe32ForRuntime(writeFrozenWorkloadPe(directory), null, null);
}

// BPTK-139 (GS-095) cold-start / time-to-first-executable. Cold start is the
// full recompile (WebAssembly module compile) plus instantiate; warm start
// re-instantiates the already-compiled module. Honestly red: this measures the
// time to the first executable instruction, not the first *frame*, which needs
// a graphics and streamed-asset runtime that does not exist.
export function benchmarkColdStart(option = {}) {
  const directory = mkdtempSync(join(tmpdir(), "bptk-cold-"));
  try {
    const mapped = mapFrozen(directory);
    const coldStart = performance.now();
    const compiled = recompileImage(mapped, { trace: false, budget: 1 });
    if (compiled.refuse) throw new InputError("recompile_refused", compiled.refuse.message);
    const module = new WebAssembly.Module(compiled.wasm);
    new WebAssembly.Instance(module, {});
    const coldMillisecond = performance.now() - coldStart;
    const warmStart = performance.now();
    new WebAssembly.Instance(module, {});
    const warmMillisecond = performance.now() - warmStart;
    return {
      schema_version: 1,
      command: "benchmark --profile cold-start",
      profile: "recompiler_cold_start",
      cold_millisecond: Number(coldMillisecond.toFixed(3)),
      warm_millisecond: Number(warmMillisecond.toFixed(3)),
      budget: START_BUDGET_MILLISECOND,
      is_cold_under_budget_here: coldMillisecond <= START_BUDGET_MILLISECOND.cold,
      is_warm_under_budget_here: warmMillisecond <= START_BUDGET_MILLISECOND.warm,
      includes_asset_streaming: false,
      measured_on_reference_desktop: false,
      is_bar_cleared: false,
      blocker: [
        "This is time-to-first-executable-instruction, not time-to-first-frame; no graphics or streamed-asset runtime exists to include",
        "The start budget is a BPTK-002 reference-desktop figure, not certified on this host",
      ],
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

// BPTK-140 (GS-096) memory ceiling + guest-host boundary cost. The recompiled
// module's linear memory is bounded and does not grow with execution length;
// the crossing cost is the WebAssembly import call. Honestly red: the 2-GB
// whole-game ceiling and the reference-desktop crossing bound need a real game.
export function benchmarkMemory(option = {}) {
  const directory = mkdtempSync(join(tmpdir(), "bptk-mem-"));
  try {
    const mapped = mapFrozen(directory);
    const compiled = recompileImage(mapped, { trace: false, budget: 4_000_000 });
    if (compiled.refuse) throw new InputError("recompile_refused", compiled.refuse.message);
    const module = new WebAssembly.Module(compiled.wasm);
    const shortInstance = new WebAssembly.Instance(module, {});
    shortInstance.exports.run(10_000);
    const shortByte = shortInstance.exports.memory.buffer.byteLength;
    const longInstance = new WebAssembly.Instance(module, {});
    longInstance.exports.run(4_000_000);
    const longByte = longInstance.exports.memory.buffer.byteLength;
    const crossing = measureCrossing({ iteration: option.iteration ?? 500_000 });
    return {
      schema_version: 1,
      command: "benchmark --profile memory",
      profile: "recompiler_memory",
      peak_memory_byte: longByte,
      short_run_memory_byte: shortByte,
      is_growth_bounded: longByte === shortByte,
      memory_ceiling_byte: MEMORY_CEILING_BYTE,
      is_under_ceiling_here: longByte <= MEMORY_CEILING_BYTE,
      crossing_nanosecond: crossing.nanosecond_per_crossing,
      crossing_bound_nanosecond: CROSSING_COST_BAR_NANOSECOND,
      is_crossing_under_bound_here: crossing.nanosecond_per_crossing <= CROSSING_COST_BAR_NANOSECOND,
      measured_on_reference_desktop: false,
      is_bar_cleared: false,
      blocker: [
        "The 2-GB peak ceiling is a whole-game figure; no game runtime exists to reach it",
        "The crossing bound is a BPTK-002 reference-desktop figure, not certified on this host",
      ],
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

// BPTK-142 (GS-098) sustained-run stability / jitter. Repeats the frozen
// workload many times and measures the run-to-run jitter and that memory
// returns to baseline. Honestly red: a real 30-minute game run over the
// declared host set is out of reach without a game runtime.
export function benchmarkStability(option = {}) {
  const repeat = Number.isSafeInteger(option.repeat) && option.repeat > 0 ? option.repeat : 50;
  const perRunBudget = Number.isSafeInteger(option.per_run_budget) && option.per_run_budget > 0 ? option.per_run_budget : 200_000;
  const directory = mkdtempSync(join(tmpdir(), "bptk-stab-"));
  try {
    const mapped = mapFrozen(directory);
    const compiled = recompileImage(mapped, { trace: false, budget: perRunBudget });
    if (compiled.refuse) throw new InputError("recompile_refused", compiled.refuse.message);
    const module = new WebAssembly.Module(compiled.wasm);
    const sample = [];
    const baselineByte = new WebAssembly.Instance(module, {}).exports.memory.buffer.byteLength;
    let lastByte = baselineByte;
    for (let index = 0; index < repeat; index += 1) {
      const instance = new WebAssembly.Instance(module, {});
      const start = performance.now();
      instance.exports.run(perRunBudget);
      sample.push(performance.now() - start);
      lastByte = instance.exports.memory.buffer.byteLength;
    }
    const sorted = [...sample].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)];
    const p99 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.99))];
    return {
      schema_version: 1,
      command: "benchmark --profile stability",
      profile: "recompiler_stability",
      repeat,
      per_run_budget: perRunBudget,
      median_millisecond: Number(median.toFixed(3)),
      p99_millisecond: Number(p99.toFixed(3)),
      jitter_millisecond: Number((p99 - median).toFixed(3)),
      memory_returns_to_baseline: lastByte === baselineByte,
      measured_on_reference_desktop: false,
      is_bar_cleared: false,
      blocker: [
        "A real 30-minute sustained game run over the declared host set needs a game runtime that does not exist",
      ],
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export function formatRecompilerBenchmark(report) {
  return [
    `Workload: ${report.workload} (${report.instruction_budget_count} instruction budget)`,
    `Interpreter: ${report.interpreter.mips} MIPS (${report.interpreter.instruction_count} instruction in ${report.interpreter.millisecond} ms)`,
    `Recompiled: ${report.recompiled.mips} MIPS (${report.recompiled.instruction_count} instruction in ${report.recompiled.millisecond} ms)`,
    `Speedup vs interpreter: ${report.interpreter_multiple}x (bar >= ${report.bar.interpreter_multiple}x)`,
    `MIPS floor: ${report.bar.mips_floor} (cleared here: ${report.is_floor_cleared_here})`,
    `Same computation as interpreter: ${report.is_equivalent}`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}

function verifyPackage(packagePath, manifest) {
  const chunkHash = new Set(manifest.asset.flatMap((entry) => entry.chunk.map((currentChunk) => currentChunk.sha256)));
  let byteCount = 0;
  for (const hash of chunkHash) {
    const chunkPath = join(packagePath, "chunk", hash);
    if (!existsSync(chunkPath)) throw new InputError("package_chunk_missing", `Package chunk is missing: ${hash}`);
    const content = readFileSync(chunkPath);
    if (createHash("sha256").update(content).digest("hex") !== hash) throw new InputError("package_chunk_corrupt", `Package chunk hash differs: ${hash}`);
    byteCount += content.length;
  }
  return { byte_count: byteCount, chunk_count: chunkHash.size };
}

export function benchmarkPerformance(packageInput) {
  const packagePath = resolve(packageInput);
  const manifest = readPackageManifest(packagePath);
  if (!manifest || manifest.package_kind !== "stream_asset" || !Array.isArray(manifest.asset)) throw new InputError("stream_package_required", "Performance profile requires a stream-asset package");
  const memoryBeforeByte = process.memoryUsage().rss;
  const coldStartedAt = performance.now();
  const cold = verifyPackage(packagePath, manifest);
  const coldMillisecond = performance.now() - coldStartedAt;
  const warmStartedAt = performance.now();
  const warm = verifyPackage(packagePath, manifest);
  const warmMillisecond = performance.now() - warmStartedAt;
  return {
    schema_version: 1,
    command: "benchmark --profile performance",
    package_id: manifest.package_id,
    profile: "package_integrity_only",
    cold_read_millisecond: Number(coldMillisecond.toFixed(3)),
    warm_read_millisecond: Number(warmMillisecond.toFixed(3)),
    byte_count: cold.byte_count,
    chunk_count: cold.chunk_count,
    memory_delta_byte: Math.max(0, process.memoryUsage().rss - memoryBeforeByte),
    is_integrity_verified: cold.byte_count === warm.byte_count && cold.chunk_count === warm.chunk_count,
    blocker: ["Startup, frame, audio, guest CPU, and game-runtime memory cannot be measured because no game runtime exists"],
  };
}

export function formatPerformance(report) {
  return [
    `Package ID: ${report.package_id}`,
    `Profile: ${report.profile}`,
    `Cold read: ${report.cold_read_millisecond} ms`,
    `Warm read: ${report.warm_read_millisecond} ms`,
    `Verified: ${report.byte_count} byte across ${report.chunk_count} chunk`,
    `Memory delta: ${report.memory_delta_byte} byte`,
    ...report.blocker.map((entry) => `Blocked: ${entry}`),
  ].join("\n");
}
