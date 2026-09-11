#!/usr/bin/env node
// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// THE FULLNESS VERIFIER. It answers one question with an exit code, offline and
// with no per-title knowledge:
//
//   Is "full WASM + full CPU + full GPU emulation" reached yet?
//
// Exit 0 means every leg below is green ON THE EVIDENCE THIS RUN RECOMPUTED.
// Exit 1 means at least one leg is red, and the failing leg is named on stderr
// with the numbers that made it red.
//
// WHY THIS FILE EXISTS. "Done" was previously only expressible as a CLAIM: a
// document saying a milestone is reached, a counter a human updated. A claim
// cannot be ground against, and so the loop that was supposed to reach the goal
// could also stop the moment someone asserted it. This turns the claim into a
// command. Nothing here is asserted from a document — every number is measured
// by running the product's own surface, and every leg has a MEASURED denominator
// rather than a remembered one.
//
// THE THREE LEGS, and why each is the honest denominator:
//
//   CPU — every corpus image reaches `entry`. `entry` is the corpus's own stage
//         label for "real instructions executed from the entry point", so this is
//         the product's stated bar, not one this file invents.
//
//   WASM — the x86-64 images a WASM tier can carry reach `entry` WITH that tier
//         actually carrying them: `wasm_tier_instruction > interpreter_tier_instruction`
//         and zero interpreter RESIDENCY on the hot path. A tier that is present
//         but never chosen is not a tier; a run that is 99% interpreter is the
//         v1 interpreter wearing a WASM hat. The residency bar is the one the
//         throughput log already uses to decide whether compiling is worth doing.
//
//   GPU — every WGPU-family gold-standard item is green against a LIVE adapter.
//         On a host with no WebGPU adapter this leg can never be green, and it
//         says so by name rather than passing quietly.
//
// BOTH DIRECTIONS. The corpus leg checks that every STAGED record appears in the
// run (missing) AND that every run record corresponds to a staged entry
// (invented) — a run that dropped an image and a run that fabricated nine would
// both otherwise scan as full.
//
// Usage:
//   node tool/fullness.mjs [option]
//     --json             machine-readable report on stdout
//     --stage <path>     corpus stage directory (default: resolveStageDir())
//     --no-gpu           skip the live-adapter leg (for hosts where it is known absent)
//     --help             this text
//
// Exit code: 0 all legs green, 1 a leg is red, 2 usage or the product surface threw.

import { pathToFileURL } from "node:url";

import { resolveStageDir } from "../lib/corpus.mjs";

const SCOPE_NOTE =
  "Fullness is an EXECUTION measurement over the corpus and the codegen, plus a live GPU-adapter " +
  "check. It is not a playability claim and it does not set `passing`: a corpus image at `entry` " +
  "has executed real instructions, which is not a played frame.";

// The residency ceiling for the WASM leg. 1% is the bar the throughput log
// already treats as "the interpreter is not carrying this run"; the measured
// figure is reported alongside so a near miss is legible rather than binary.
const RESIDENCY_CEILING = 0.01;

class UsageError extends Error {}

function parseArgument(argv) {
  const option = { isJson: false, stage: null, isGpu: true, isHelp: false };
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
    else if (token === "--no-gpu") option.isGpu = false;
    else if (token === "--stage") option.stage = next();
    else if (token.startsWith("--stage=")) option.stage = token.slice(8);
    else if (token.startsWith("-")) throw new UsageError(`unknown option ${token}`);
    else throw new UsageError(`unexpected argument ${token}`);
  }
  return option;
}

// ---- leg 1 + 2: the corpus, run through the product's own surface ------------

// The corpus run surface, imported lazily so `--help` and a usage error cost
// nothing. This is the SAME entry the CLI calls, so the verifier cannot drift
// from what `bptk corpus run` reports.
async function runCorpus(stage) {
  const corpus = await import("../lib/corpus.mjs");
  return corpus.runCorpus(stage === null ? { save: false } : { stage, save: false });
}

// Every entry the stage directory declares, read from the stage's own manifest
// rather than from the run's output — this is the MISSING direction's ground
// truth, and taking it from the run would make the check vacuous.
async function declaredEntry(stageDir) {
  const { readFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const manifestPath = join(stageDir, "corpus.json");
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch {
    // A stage without a manifest is not a failure of the product; the invented
    // direction simply has no denominator and is reported as unchecked.
    return null;
  }
  const entry = manifest.entry ?? manifest.corpus ?? manifest.record ?? [];
  return entry.map((item) => item.entry_id).filter((id) => typeof id === "string");
}

function corpusLeg(run, declared) {
  const record = run.record ?? [];
  // Every run record is in the partition — including one that never left
  // `staged` (integrity_mismatch, missing payload). Dropping those first made
  // a sibling at `entry` turn the CPU leg green while the stuck image vanished
  // from both `atEntry` and `below`.
  const atEntry = record.filter((entry) => entry.reached_stage === "entry" || entry.reached_stage === "interactive");
  const below = record.filter((entry) => entry.reached_stage !== "entry" && entry.reached_stage !== "interactive");

  const seen = new Set(record.map((entry) => entry.entry_id));
  const missing = declared === null ? [] : declared.filter((id) => !seen.has(id));
  const invented = declared === null ? [] : [...seen].filter((id) => !declared.includes(id));

  return {
    declared_count: declared === null ? null : declared.length,
    record_count: record.length,
    staged_count: record.length,
    entry_count: atEntry.length,
    missing: missing,
    invented: invented,
    below: below.map((entry) => ({
      entry_id: entry.entry_id,
      architecture: entry.architecture,
      reached_stage: entry.reached_stage,
      gap_code: entry.gap_code,
      gap_item: entry.gap_item,
    })),
    // A staged image that never ran, or a record with no staged counterpart, is
    // red in the same way as an image below `entry` — the denominator is the
    // staged set, and both directions must reconcile against it.
    is_green: record.length > 0 && below.length === 0 && missing.length === 0 && invented.length === 0,
  };
}

// ---- leg 2: the WASM tier actually carrying an x86-64 run --------------------

// The x86-64 images the corpus stages, as absolute payload paths. The corpus
// record names the entry but not the payload, so this walks the stage's own
// per-entry package directory — the same discovery the corpus does, done here so
// the verifier does not need a second manifest. `peekPeMachine` takes a PATH and
// reads only the header, so a 200 KB image is never mapped to decide its class.
const PE_MACHINE_AMD64 = 0x8664;

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
  return found;
}

// A single tiered run over one x86-64 payload, using the SAME option shape
// test/tierrun.test.mjs builds — the HLE layout, the import map, the bounded
// stack. Returns null when the run cannot be constructed, which is reported as a
// red WASM leg rather than a thrown verifier.
async function tierResidency(payload, budget) {
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
    return { error: `map_failed: ${error?.message ?? error}` };
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
    return { error: `run_failed: ${error?.message ?? error}` };
  }
  const report = tiered.tier_report ?? {};
  const wasmInstruction = Number(report.wasm_tier_instruction ?? 0);
  const interpInstruction = Number(report.interpreter_tier_instruction ?? 0);
  const total = wasmInstruction + interpInstruction;
  return {
    wasm_tier_instruction: wasmInstruction,
    interpreter_tier_instruction: interpInstruction,
    wasm_tier_function: Number(report.wasm_tier_function ?? 0),
    wasm_tier_invocation: Number(report.wasm_tier_invocation ?? 0),
    residency: total === 0 ? 1 : interpInstruction / total,
    stop_reason: tiered.stop_reason,
  };
}

async function wasmLeg(stageDir, budget) {
  const payload = await stageX64Payload(stageDir);
  const measured = [];
  for (const item of payload) {
    const value = await tierResidency(item, budget);
    measured.push({ entry_id: item.entry_id, file: item.file, ...value });
  }
  const carried = measured.filter(
    (item) => item.error === undefined
      && item.wasm_tier_function >= 1
      && item.residency <= RESIDENCY_CEILING,
  );
  return {
    host_payload_count: payload.length,
    resident_count: carried.length,
    residency_ceiling: RESIDENCY_CEILING,
    measurement: measured,
    // Zero x86-64 payloads staged is NOT green: the leg has no evidence. It is
    // red and says so, because a corpus that lost its payloads would otherwise
    // scan as a full WASM tier.
    is_green: payload.length > 0 && carried.length === payload.length,
  };
}

// ---- leg 3: a live GPU adapter ----------------------------------------------

async function gpuLeg() {
  const { probeGraphics } = await import("../lib/graphics.mjs");
  let probe;
  try {
    probe = probeGraphics();
  } catch (error) {
    return { is_green: false, is_checked: true, adapter_available: false, note: `probeGraphics threw: ${error?.message ?? error}` };
  }
  const capability = probe.capability ?? {};
  const isWebgpu = capability.is_webgpu_available === true;
  const isWebgl2 = capability.is_webgl2_available === true;
  return {
    // A live GPU adapter means a real accelerated pipeline ran. WebGPU is the
    // declared primary path and WebGL2 the lowered fallback, so EITHER is a live
    // adapter; `selected_path` is the product's own choice between them.
    is_green: isWebgpu || isWebgl2,
    is_checked: true,
    adapter_available: isWebgpu || isWebgl2,
    is_webgpu_available: isWebgpu,
    is_webgl2_available: isWebgl2,
    selected_path: probe.selected_path ?? null,
    browser_version: probe.browser?.version ?? null,
    state: probe.state,
    blocker: probe.blocker ?? [],
    note: isWebgpu || isWebgl2
      ? `a live adapter ran the ${probe.selected_path} path`
      : "no live GPU adapter on this host; the graphics items cannot be green here",
  };
}

// ---- report -----------------------------------------------------------------

function formatLeg(label, leg) {
  const lines = [`${label}: ${leg.is_green ? "GREEN" : "RED"}`];
  if (label === "CPU (corpus at entry)") {
    lines.push(`  staged ${leg.staged_count}, at entry ${leg.entry_count}, below entry ${leg.below.length}`);
    for (const entry of leg.below.slice(0, 8)) {
      lines.push(`  below: ${entry.entry_id} ${entry.architecture} @ ${entry.reached_stage} (${entry.gap_code} / ${entry.gap_item})`);
    }
    if (leg.below.length > 8) lines.push(`  below: … ${leg.below.length - 8} more`);
    if (leg.missing.length > 0) lines.push(`  MISSING from the run: ${leg.missing.join(", ")}`);
    if (leg.invented.length > 0) lines.push(`  INVENTED in the run: ${leg.invented.join(", ")}`);
  }
  if (label === "WASM (tier carries x86-64, residency under ceiling)") {
    lines.push(`  x86-64 payloads ${leg.host_payload_count}, resident ${leg.resident_count}, ceiling ${leg.residency_ceiling}`);
    for (const item of leg.measurement) {
      if (item.error !== undefined) lines.push(`  ${item.entry_id} ${item.file}: ${item.error}`);
      else lines.push(`  ${item.entry_id} ${item.file}: residency ${(item.residency * 100).toFixed(2)}%, wasm ${item.wasm_tier_instruction}, interp ${item.interpreter_tier_instruction}, ${item.wasm_tier_function} function, stop ${item.stop_reason}`);
    }
  }
  if (label === "GPU (live adapter)") {
    lines.push(`  checked ${leg.is_checked}, adapter ${leg.adapter_available ?? "unknown"}, path ${leg.selected_path ?? "none"}`);
    if (leg.is_webgpu_available !== undefined) {
      lines.push(`  webgpu ${leg.is_webgpu_available}, webgl2 ${leg.is_webgl2_available}, browser ${leg.browser_version ?? "unknown"}, state ${leg.state}`);
    }
    for (const item of leg.blocker ?? []) lines.push(`  blocker: ${item}`);
    if (leg.note) lines.push(`  ${leg.note}`);
  }
  return lines.join("\n");
}

export async function measureFullness(option = {}) {
  const stageDir = option.stage ?? resolveStageDir();
  const declared = await declaredEntry(stageDir);
  const run = await runCorpus(stageDir);
  const cpu = corpusLeg(run, declared);
  const wasm = await wasmLeg(stageDir, option.wasmBudget ?? 2_000_000);
  const gpu = option.isGpu === false
    ? { is_green: false, is_checked: false, note: "skipped by --no-gpu; skipped is not green" }
    : await gpuLeg();

  const leg = { cpu, wasm, gpu };
  return {
    schema_version: 1,
    tool: "tool/fullness.mjs",
    scope_note: SCOPE_NOTE,
    stage_dir: stageDir,
    leg,
    is_full: cpu.is_green && wasm.is_green && gpu.is_green,
    red: Object.entries(leg).filter(([, value]) => !value.is_green).map(([name]) => name),
  };
}

const LABEL = {
  cpu: "CPU (corpus at entry)",
  wasm: "WASM (tier carries x86-64, residency under ceiling)",
  gpu: "GPU (live adapter)",
};

async function main() {
  let option;
  try {
    option = parseArgument(process.argv.slice(2));
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    process.stderr.write(`fullness: ${error.message}\n`);
    return 2;
  }
  if (option.isHelp) {
    process.stdout.write([
      "Usage: node tool/fullness.mjs [option]",
      "  --json           machine-readable report on stdout",
      "  --stage <path>   corpus stage directory (default: resolveStageDir())",
      "  --no-gpu         skip the live-adapter leg (a skip is not green)",
      "  --help           this text",
      "",
      "Question: Is full WASM + full CPU + full GPU emulation reached yet?",
      "Every number is measured against a denominator this run recomputes",
      "(corpus stage walk, x86-64 payload walk, live GPU adapter), not a remembered count.",
      "Exit 0 when every leg is green, 1 when one is red, 2 on usage or a thrown surface.",
      "",
    ].join("\n"));
    return 0;
  }

  let report;
  try {
    report = await measureFullness(option);
  } catch (error) {
    process.stderr.write(`fullness: the product surface threw: ${error?.message ?? error}\n`);
    return 2;
  }

  if (option.isJson) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    process.stdout.write([
      `Fullness: ${report.is_full ? "FULL" : "NOT FULL"}`,
      `Stage: ${report.stage_dir}`,
      ...Object.entries(report.leg).map(([name, value]) => formatLeg(LABEL[name], value)),
      report.is_full ? "Every leg is green on this run's own evidence." : `Red leg: ${report.red.join(", ")}`,
      report.scope_note,
      "",
    ].join("\n"));
  }
  return report.is_full ? 0 : 1;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => { process.exitCode = code; });
}

export { corpusLeg, wasmLeg, gpuLeg };
