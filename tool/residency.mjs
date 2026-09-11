#!/usr/bin/env node
// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// THE WASM-RESIDENCY VERIFIER. It answers one question with an exit code,
// offline and with no per-title knowledge:
//
//   Is the WASM tier carrying every staged x86-64 run, with the interpreter off
//   the hot path?
//
// Exit 0 means every staged x86-64 payload ran with `wasm_tier_instruction >
// interpreter_tier_instruction` and an interpreter RESIDENCY at or under the
// ceiling. Exit 1 means at least one payload missed, and the payload and its
// numbers are named on stderr.
//
// WHY THIS IS NOT THE SAME AS tool/fullness.mjs. Fullness asks whether the whole
// project is done (three legs). This asks one leg's question precisely, so a loop
// can grind on it without the CPU and GPU legs turning red for reasons the loop
// cannot act on. The loop must be able to WIN, or it is just churning.
//
// THE DENOMINATOR IS MEASURED, NOT REMEMBERED. Payloads are discovered by walking
// the stage directory and header-peeking each .exe for the PE32+ machine class —
// so an image that is added to the corpus, or one whose payload is missing, moves
// the denominator instead of hiding inside it.
//
// A RUN THAT DID NOT FINISH IS NOT A PASS. A payload that stops on a `fault` or on
// `instruction_budget_exhausted` has a residency computed over an unfinished run,
// which is not evidence about the tier's steady state. Those are reported with
// `is_settled: false` and held out of the green set, because a low residency over
// a crashed run is the easiest way to fake this number.
//
// Usage:
//   node tool/residency.mjs [option]
//     --json             machine-readable report on stdout
//     --stage <path>     corpus stage directory (default: resolveStageDir())
//     --budget <count>   guest instruction budget per payload (default: 2000000)
//     --ceiling <ratio>  interpreter residency ceiling (default: 0.01)
//     --help             this text
//
// Exit code: 0 every settled payload resident, 1 a payload missed, 2 usage or the
// product surface threw.

import { pathToFileURL } from "node:url";

import { resolveStageDir } from "../lib/corpus.mjs";

const SCOPE_NOTE =
  "Residency is the fraction of guest instruction the INTERPRETER carried. It is a throughput " +
  "measurement, not correctness, not a run, not a playability claim; `passing` is untouched.";

const PE_MACHINE_AMD64 = 0x8664;

// A run that stopped on one of these has not reached a steady state, so its
// residency is a measurement of an unfinished thing rather than of the tier.
const UNSETTLED_STOP = new Set(["fault", "instruction_budget_exhausted", "precise_fault"]);

class UsageError extends Error {}

function parseArgument(argv) {
  const option = { isJson: false, stage: null, budget: 2_000_000, ceiling: 0.01, isHelp: false };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    const next = () => {
      const value = argv[index + 1];
      if (value === undefined) throw new UsageError(`option ${token} requires a value`);
      index += 1;
      return value;
    };
    if (token === "--help" || token === "-h") option.isHelp = true;
    else if (token === "--json") option.isJson = true;
    else if (token === "--stage") option.stage = next();
    else if (token.startsWith("--stage=")) option.stage = token.slice(8);
    else if (token === "--budget") option.budget = Number(next());
    else if (token.startsWith("--budget=")) option.budget = Number(token.slice(9));
    else if (token === "--ceiling") option.ceiling = Number(next());
    else if (token.startsWith("--ceiling=")) option.ceiling = Number(token.slice(10));
    else if (token.startsWith("-")) throw new UsageError(`unknown option ${token}`);
    else throw new UsageError(`unexpected argument ${token}`);
  }
  if (!Number.isSafeInteger(option.budget) || option.budget <= 0) throw new UsageError("--budget must be a positive integer");
  if (!(option.ceiling > 0 && option.ceiling < 1)) throw new UsageError("--ceiling must be a ratio between 0 and 1");
  return option;
}

// Every staged x86-64 payload. `peekPeMachine` takes a PATH and reads only the
// header, so a large image is never fully mapped just to decide its class.
async function stageX64Payload(stageDir) {
  const { readdirSync, existsSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { peekPeMachine } = await import("../lib/pe64.mjs");
  const found = [];
  let directory;
  try {
    directory = readdirSync(stageDir, { withFileTypes: true });
  } catch {
    return found;
  }
  for (const item of directory) {
    if (!item.isDirectory() || !/^corpus-\d+$/.test(item.name)) continue;
    const packagePath = join(stageDir, item.name, "package");
    if (!existsSync(packagePath)) continue;
    for (const file of readdirSync(packagePath)) {
      if (!/\.exe$/i.test(file)) continue;
      const path = join(packagePath, file);
      let machine;
      try {
        machine = peekPeMachine(path);
      } catch {
        continue;
      }
      if (machine === PE_MACHINE_AMD64) found.push({ entry_id: item.name, path, file });
    }
  }
  return found.sort((left, right) => left.entry_id.localeCompare(right.entry_id) || left.file.localeCompare(right.file));
}

// One tiered run over one x86-64 payload, using the SAME option shape
// test/tierrun.test.mjs builds — the HLE layout, the import map, the bounded
// stack. A failure to construct is returned, never thrown, so one bad payload
// reports itself instead of taking the verifier down.
async function measureOneResidency(payload, budget) {
  const { readFileSync } = await import("node:fs");
  const { mapPe64State } = await import("../lib/pe64.mjs");
  const { createHleLayout } = await import("../lib/hle.mjs");
  const { createGuestClock } = await import("../lib/clock.mjs");
  const { runTieredImage } = await import("../lib/tierrun.mjs");

  const MASK64 = (1n << 64n) - 1n;
  let mapped;
  try {
    mapped = mapPe64State(new Uint8Array(readFileSync(payload.path)));
  } catch (error) {
    return { entry_id: payload.entry_id, file: payload.file, error: `map_failed: ${error?.message ?? error}` };
  }
  const importSet = new Map();
  for (const entry of mapped.import ?? []) {
    importSet.set((mapped.load_base + BigInt(entry.iat_slot_rva)) & MASK64, entry);
  }
  const stackLow = 0x7ff000000000 & 0xffffffff;
  const layout = createHleLayout({
    load_base: Number(mapped.load_base & MASK64),
    image_size_byte: mapped.image_size_byte ?? mapped.image.length,
    stack_base: stackLow,
    stack_end: stackLow + 0x40000,
  });
  let tiered;
  try {
    tiered = runTieredImage({
      image: mapped.image,
      loadBase: mapped.load_base,
      entryRva: mapped.entry_rva,
      budget,
      importSet,
      resourceRva: mapped.directory?.[2]?.rva ?? 0,
      hle: { layout, executableName: payload.file, clock: createGuestClock({ mode: "virtual_monotonic" }) },
    });
  } catch (error) {
    return { entry_id: payload.entry_id, file: payload.file, error: `run_failed: ${error?.message ?? error}` };
  }
  const report = tiered.tier_report ?? {};
  const wasmInstruction = Number(report.wasm_tier_instruction ?? 0);
  const interpInstruction = Number(report.interpreter_tier_instruction ?? 0);
  const total = wasmInstruction + interpInstruction;
  const stopReason = tiered.stop_reason;
  return {
    entry_id: payload.entry_id,
    file: payload.file,
    wasm_tier_instruction: wasmInstruction,
    interpreter_tier_instruction: interpInstruction,
    wasm_tier_function: Number(report.wasm_tier_function ?? 0),
    wasm_tier_entry_count: (report.wasm_tier_entry ?? []).length,
    tier_compile: Number(report.tier_compile ?? 0),
    residency: total === 0 ? 1 : interpInstruction / total,
    stop_reason: stopReason,
    is_settled: !UNSETTLED_STOP.has(stopReason),
  };
}

export async function measureResidency(option = {}) {
  const stageDir = option.stage ?? resolveStageDir();
  const budget = option.budget ?? 2_000_000;
  const ceiling = option.ceiling ?? 0.01;
  const payload = await stageX64Payload(stageDir);
  const measurement = [];
  for (const item of payload) measurement.push(await measureOneResidency(item, budget));

  const resident = measurement.filter(
    (item) => item.error === undefined
      && item.is_settled === true
      && item.wasm_tier_function >= 1
      && item.residency <= ceiling,
  );
  const unsettled = measurement.filter((item) => item.error === undefined && item.is_settled === false);
  const missed = measurement.filter((item) => !resident.includes(item));

  return {
    schema_version: 1,
    tool: "tool/residency.mjs",
    scope_note: SCOPE_NOTE,
    stage_dir: stageDir,
    budget,
    ceiling,
    payload_count: payload.length,
    resident_count: resident.length,
    measurement,
    // Zero payloads is not green: the leg would then have no evidence at all, and
    // a corpus that lost its images would scan as a full tier.
    is_resident: payload.length > 0 && resident.length === payload.length,
    unsettled: unsettled.map((item) => ({ entry_id: item.entry_id, file: item.file, stop_reason: item.stop_reason })),
    missed: missed.map((item) => ({ entry_id: item.entry_id, file: item.file, residency: item.residency, error: item.error })),
  };
}

function formatReport(report) {
  const lines = [
    `WASM residency: ${report.is_resident ? "RESIDENT" : "NOT RESIDENT"}`,
    `Stage: ${report.stage_dir}`,
    `Budget ${report.budget} instruction, ceiling ${(report.ceiling * 100).toFixed(2)}% interpreter`,
    `Payloads ${report.payload_count}, resident ${report.resident_count}`,
  ];
  for (const item of report.measurement) {
    if (item.error !== undefined) {
      lines.push(`  MISS: ${item.entry_id} ${item.file}: ${item.error}`);
      continue;
    }
    const flag = item.is_settled ? (item.residency <= report.ceiling ? "ok  " : "HIGH") : "UNSET";
    lines.push(
      `  ${flag} ${item.entry_id} ${item.file}: ${(item.residency * 100).toFixed(2)}% interp`
      + ` (wasm ${item.wasm_tier_instruction}, interp ${item.interpreter_tier_instruction},`
      + ` ${item.wasm_tier_function} function, ${item.tier_compile} compile, stop ${item.stop_reason})`,
    );
  }
  if (report.unsettled.length > 0) {
    lines.push(`  UNSETTLED (not evidence about steady state): ${report.unsettled.map((item) => `${item.entry_id} ${item.stop_reason}`).join(", ")}`);
  }
  lines.push(report.is_resident
    ? "Every staged x86-64 payload ran WASM-tier with the interpreter at or under the ceiling."
    : `Missed: ${report.missed.map((item) => item.entry_id).join(", ") || "(none named)"}`);
  lines.push(report.scope_note);
  return lines.join("\n");
}

async function main() {
  let option;
  try {
    option = parseArgument(process.argv.slice(2));
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    process.stderr.write(`residency: ${error.message}\n`);
    return 2;
  }
  if (option.isHelp) {
    process.stdout.write([
      "Usage: node tool/residency.mjs [option]",
      "  --json             machine-readable report on stdout",
      "  --stage <path>     corpus stage directory (default: resolveStageDir())",
      "  --budget <count>   guest instruction budget per payload (default: 2000000)",
      "  --ceiling <ratio>  interpreter residency ceiling (default: 0.01)",
      "  --help             this text",
      "",
      "Question: Is the WASM tier carrying every staged x86-64 run, with the interpreter off the hot path?",
      "The denominator is measured by walking the stage directory and header-peeking each payload,",
      "not a remembered count. Interpreter residency is the fraction of guest instruction the interpreter carried.",
      "Exit 0 when every settled payload is resident, 1 when one missed, 2 on usage or a thrown surface.",
      "",
    ].join("\n"));
    return 0;
  }
  let report;
  try {
    report = await measureResidency(option);
  } catch (error) {
    process.stderr.write(`residency: the product surface threw: ${error?.message ?? error}\n`);
    return 2;
  }
  if (option.isJson) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else process.stdout.write(`${formatReport(report)}\n`);
  return report.is_resident ? 0 : 1;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => { process.exitCode = code; });
}

export { stageX64Payload, measureOneResidency };
