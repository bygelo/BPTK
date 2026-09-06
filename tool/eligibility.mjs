#!/usr/bin/env node
// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The WASM-TIER ELIGIBILITY INSTRUMENT. It answers one measured question about a
// real PE32+ binary, reproducibly, with no per-title knowledge:
//
//   Of the candidate function entries this image contains, what fraction does
//   lib/wasm64.mjs `compileFunction` accept whole (`complete === true`)?
//
// That number has been quoted from memory across sessions with no committed way
// to recompute it. This is the way to recompute it. It measures ELIGIBILITY —
// whether the codegen can emit a function at all — which is NOT correctness, NOT
// a run, and NOT a playability claim. `passing` stays 0 either way.
//
// Method, in order:
//   1. `lib/pe64.mjs` `mapPe64State` maps the file to its loaded image bytes.
//   2. Candidate function entries come from a GENERIC sweep: every direct
//      `call rel32` (opcode 0xE8) inside an executable section whose computed
//      target also lands inside an executable section is a candidate entry, plus
//      the PE entry point itself. No hardcoded address, no title-specific list.
//   3. Each entry is compiled exactly the way lib/tier.mjs decides a tier: every
//      OTHER candidate entry is marked external and a dummy host callback is
//      bound, so a plain direct call to a neighbouring function is an import
//      boundary rather than a rejection. `compiled.complete` is the verdict.
//   4. A rejected function contributes EVERY DISTINCT reason it carries to the
//      histogram — once per function per reason, never just the first. Counting
//      only the first reason understates overlapping blockers materially.
//   5. `--solely` names a reason set and reports how many rejected functions
//      carry NOTHING BUT those reasons. That is the true ceiling if that blocker
//      alone were solved, and it is the number that predicts the win.
//
// Usage:
//   node tool/eligibility.mjs <path-to-pe32plus> [option]
//     --json                  machine-readable report on stdout
//     --solely <reason,...>   ceiling for that blocker set (repeatable)
//     --base <hex>            requested load base (default: the image base)
//     --limit <count>         stop after this many candidate entries
//     --help                  this text
//
// Exit code: 0 measured, 2 usage or unreadable input.

import { pathToFileURL } from "node:url";

import { mapPe64State } from "../lib/pe64.mjs";
import { decodeStructured } from "../lib/lift64.mjs";
import { compileFunction } from "../lib/wasm64.mjs";

const SCOPE_NOTE =
  "Eligibility is a CODEGEN measurement (can compileFunction emit this function whole), " +
  "not correctness, not a run, and not a playability claim. The corpus `passing` count stays 0.";

const EXECUTABLE_SECTION_FLAG = 0x20000000;
const CALL_REL32_OPCODE = 0xe8;
const STACK_SIZE_BYTE = 0x10000;

class UsageError extends Error {}

function parseArgument(argv) {
  const option = { path: null, isJson: false, solely: [], base: null, limit: null, isHelp: false };
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
    else if (token === "--solely") option.solely.push(...splitReason(next()));
    else if (token.startsWith("--solely=")) option.solely.push(...splitReason(token.slice(9)));
    else if (token === "--base") option.base = next();
    else if (token.startsWith("--base=")) option.base = token.slice(7);
    else if (token === "--limit") option.limit = next();
    else if (token.startsWith("--limit=")) option.limit = token.slice(8);
    else if (token.startsWith("-")) throw new UsageError(`unknown option ${token}`);
    else if (option.path === null) option.path = token;
    else throw new UsageError("only one input path is accepted");
  }
  return option;
}

function splitReason(value) {
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
}

// Every executable section of the mapped image, as [start, end) RVA range.
function executableRange(mapped) {
  return mapped.section
    .filter((entry) => (entry.characteristic & EXECUTABLE_SECTION_FLAG) !== 0 && entry.mapped_size_byte > 0)
    .map((entry) => ({
      name: entry.name,
      start: entry.virtual_address,
      end: entry.virtual_address + entry.mapped_size_byte,
    }));
}

// The GENERIC entry discovery: sweep executable bytes for `call rel32` and keep
// every target that lands in executable memory. It over-reads (a 0xE8 byte inside
// a longer instruction or inside inline data yields a target that is usually NOT
// executable and so drops out), it under-reads (a function only ever reached
// indirectly is never seen), and it knows nothing about any particular binary.
// Both biases are properties of the instrument, not of the title.
export function discoverEntry(mapped) {
  const image = mapped.image;
  const range = executableRange(mapped);
  const isExecutable = (rva) => range.some((entry) => rva >= entry.start && rva < entry.end);
  const entry = new Set();
  if (isExecutable(mapped.entry_rva)) entry.add(mapped.entry_rva);
  for (const section of range) {
    const end = Math.min(section.end, image.length) - 5;
    for (let rva = section.start; rva <= end; rva += 1) {
      if (image[rva] !== CALL_REL32_OPCODE) continue;
      const target = rva + 5 + image.readInt32LE(rva + 1);
      if (target >= 0 && target < image.length && isExecutable(target)) entry.add(target);
    }
  }
  return [...entry].sort((left, right) => left - right);
}

// The per-function verdict. Mirrors lib/tier.mjs's tier decision exactly: every
// other candidate entry is external and a dummy host callback is bound, so a
// direct call to a neighbouring function is an import boundary, not a rejection.
export function measureEligibility(mapped, entryRva, option = {}) {
  const image = mapped.image;
  const loadBase = mapped.load_base;
  const guestLen = image.length + STACK_SIZE_BYTE;
  const externalRva = option.externalRva ?? [];
  const verdict = { entry_rva: entryRva, is_complete: false, reason: [] };
  let compiled;
  try {
    compiled = compileFunction(image, {
      loadBase,
      stackSizeByte: STACK_SIZE_BYTE,
      guestLen,
      entryRva,
      decodeStructured,
      hostCall: () => 0,
      externalRva,
    });
  } catch (error) {
    // A throw is itself a rejection, named so it shows up in the histogram rather
    // than silently shrinking the denominator.
    verdict.reason = [`compile_throw:${error?.code ?? error?.name ?? "Error"}`];
    return verdict;
  }
  verdict.is_complete = compiled.complete === true;
  const reason = new Set();
  for (const item of compiled.coverage?.unsupported ?? []) reason.add(item.reason ?? "(unnamed)");
  verdict.reason = [...reason].sort();
  return verdict;
}

function percent(part, whole) {
  if (whole === 0) return 0;
  return Math.round((part / whole) * 1000) / 10;
}

export function createReport(mapped, option = {}) {
  const solely = [...new Set(option.solely ?? [])].sort();
  let entry = discoverEntry(mapped);
  const discoveredCount = entry.length;
  const limit = option.limit ?? null;
  if (limit !== null && entry.length > limit) entry = entry.slice(0, limit);

  const verdict = [];
  for (const rva of entry) {
    const externalRva = entry.filter((other) => other !== rva);
    verdict.push(measureEligibility(mapped, rva, { externalRva }));
  }

  const candidateCount = verdict.length;
  const eligible = verdict.filter((item) => item.is_complete);
  const rejected = verdict.filter((item) => !item.is_complete);

  const countByReason = new Map();
  for (const item of rejected) {
    // ONCE PER FUNCTION PER DISTINCT REASON. item.reason is already a deduped set.
    for (const name of item.reason) countByReason.set(name, (countByReason.get(name) ?? 0) + 1);
  }
  const reason = [...countByReason.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .map(([name, functionCount]) => ({
      reason: name,
      function_count: functionCount,
      percent_of_rejected: percent(functionCount, rejected.length),
    }));

  const solelySet = new Set(solely);
  const solelyBlocked = solely.length === 0
    ? []
    : rejected.filter((item) => item.reason.length > 0 && item.reason.every((name) => solelySet.has(name)));

  return {
    schema_version: 1,
    tool: "tool/eligibility.mjs",
    scope_note: SCOPE_NOTE,
    input_path: mapped.input_path,
    load_base: `0x${mapped.load_base.toString(16)}`,
    image_size_byte: mapped.image_size_byte,
    discovery: "direct call rel32 (0xE8) target landing in an executable section, plus the PE entry point",
    discovered_count: discoveredCount,
    candidate_count: candidateCount,
    eligible_count: eligible.length,
    eligible_percent: percent(eligible.length, candidateCount),
    rejected_count: rejected.length,
    reason,
    solely: {
      reason: solely,
      function_count: solelyBlocked.length,
      ceiling_count: eligible.length + solelyBlocked.length,
      ceiling_percent: percent(eligible.length + solelyBlocked.length, candidateCount),
    },
    entry_rva_sample: entry.slice(0, 16),
  };
}

function renderText(report) {
  const line = [];
  line.push(`ELIGIBILITY  ${report.input_path}`);
  line.push(`  load base           ${report.load_base}  (${report.image_size_byte} byte mapped)`);
  line.push(`  entry discovery     ${report.discovery}`);
  line.push(`  candidate entry     ${report.candidate_count}${report.candidate_count === report.discovered_count ? "" : ` (of ${report.discovered_count} discovered; --limit applied)`}`);
  line.push(`  eligible            ${report.eligible_count}  (${report.eligible_percent}% of candidate entry)`);
  line.push(`  rejected            ${report.rejected_count}`);
  line.push("");
  line.push("  rejection reason (counted ONCE PER FUNCTION; a function may carry several)");
  if (report.reason.length === 0) line.push("    (none)");
  for (const item of report.reason) {
    line.push(`    ${item.reason.padEnd(34)} ${String(item.function_count).padStart(6)}  ${item.percent_of_rejected}% of rejected`);
  }
  line.push("");
  if (report.solely.reason.length === 0) {
    line.push("  --solely <reason,...> reports the ceiling if a blocker set alone were solved");
  } else {
    line.push(`  blocked SOLELY by [${report.solely.reason.join(", ")}]: ${report.solely.function_count}`);
    line.push(`  ceiling if solved   ${report.solely.ceiling_count}  (${report.solely.ceiling_percent}% of candidate entry)`);
  }
  line.push("");
  line.push(`  NOTE: ${report.scope_note}`);
  return `${line.join("\n")}\n`;
}

const HELP = `bptk eligibility — measure WASM-tier eligibility of a PE32+ binary

  node tool/eligibility.mjs <path-to-pe32plus> [option]

    --json                  machine-readable report on stdout
    --solely <reason,...>   how many function are blocked SOLELY by that reason
                            set, and the resulting ceiling (repeatable)
    --base <hex>            requested load base (default: the image base)
    --limit <count>         stop after this many candidate entry
    --help                  this text

  ${SCOPE_NOTE}
`;

function main(argv) {
  let option;
  try {
    option = parseArgument(argv);
  } catch (error) {
    process.stderr.write(`eligibility: ${error.message}\n\n${HELP}`);
    return 2;
  }
  if (option.isHelp) {
    process.stdout.write(HELP);
    return 0;
  }
  if (option.path === null) {
    process.stderr.write(`eligibility: a path to a PE32+ binary is required\n\n${HELP}`);
    return 2;
  }
  let limit = null;
  if (option.limit !== null) {
    limit = Number(option.limit);
    if (!Number.isInteger(limit) || limit < 1) {
      process.stderr.write(`eligibility: --limit must be a positive integer, got ${option.limit}\n`);
      return 2;
    }
  }
  let base = null;
  if (option.base !== null) {
    try {
      base = BigInt(option.base);
    } catch {
      process.stderr.write(`eligibility: --base must be an integer literal, got ${option.base}\n`);
      return 2;
    }
  }

  let mapped;
  try {
    mapped = mapPe64State(option.path, base);
  } catch (error) {
    // Every failure the mapper raises is a named InputError; a missing or
    // unreadable file is one of them. Never a stack trace.
    const code = error?.input_code ? ` (${error.input_code})` : "";
    process.stderr.write(`eligibility: cannot map ${option.path}${code}: ${error?.message ?? error}\n`);
    return 2;
  }

  const report = createReport(mapped, { solely: option.solely, limit });
  process.stdout.write(option.isJson ? `${JSON.stringify(report, null, 2)}\n` : renderText(report));
  return 0;
}

// Run only when invoked as the program, so the measurement helper above stays
// importable (a test or another instrument can call createReport directly).
if (process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = main(process.argv.slice(2));
}
