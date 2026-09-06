// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The resumable, input-driven live-session suite (BPTK runtime v2, x86-64 lane
// CA). Two rails:
//
//   1. Resumability — stepping a real image in K chunks of B instructions reaches
//      the SAME architectural state (registers, rip, and every mapped memory
//      byte) as one runImage64 at K*B. This is the load-bearing proof that the
//      extracted stepContext IS the monolithic interpreter loop, split at
//      arbitrary instruction boundaries — never a re-run, never a reset.
//
//   2. Live Doom (corpus-gated) — createLiveSession runs the real Chocolate Doom
//      incrementally: step until it draws its first non-blank frame, then inject
//      a LIVE Escape keypress through sendInput and step more; the presented
//      frame's pixel hash CHANGES (Doom's menu), proving the guest reacts to
//      injected input between chunks, not to a pre-baked trace or a faked frame.
//
// The corpus cases (node:fs used only here in the test) skip cleanly when the
// corpus is not staged.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { resolveStageDir } from "../lib/corpus.mjs";
import { test } from "node:test";

import { runImage64, buildGuestContext64, stepContext } from "../lib/exec64.mjs";
import { mapPe64State } from "../lib/pe64.mjs";
import { createHleLayout } from "../lib/hle.mjs";
import { createGuestClock } from "../lib/clock.mjs";
import { createLiveSession } from "../lib/live.mjs";

const loadBase = 0x140000000n;
const stackBase = 0x00007ff000000000n;
const MASK64 = (1n << 64n) - 1n;

const puttyPath = join(resolveStageDir(), "corpus-001", "package", "putty.exe");
const corpusDoomExe = join(resolveStageDir(), "corpus-007", "package", "chocolate-doom.exe");
const corpusDoomWad = join(resolveStageDir(), "corpus-007", "wad", "freedoom1.wad");

// Read the full architectural state a step must preserve: the 16 GPRs, the 16
// XMM registers, rip, the direction flag, and every mapped memory byte.
function snapshotMachine(machine) {
  return {
    reg: machine.reg.map((v) => v & MASK64),
    xmm: machine.xmm.map((v) => v),
    rip: machine.rip & MASK64,
    df: machine.df,
    mem: machine.region.map((r) => Buffer.from(r.buf)),
  };
}

function assertMachineEqual(a, b, label) {
  for (let i = 0; i < 16; i += 1) assert.equal(a.reg[i], b.reg[i], `${label}: reg[${i}]`);
  for (let i = 0; i < 16; i += 1) assert.equal(a.xmm[i], b.xmm[i], `${label}: xmm[${i}]`);
  assert.equal(a.rip, b.rip, `${label}: rip`);
  assert.equal(a.df, b.df, `${label}: df`);
  assert.equal(a.mem.length, b.mem.length, `${label}: region count`);
  for (let i = 0; i < a.mem.length; i += 1) {
    assert.equal(a.mem[i].length, b.mem[i].length, `${label}: region[${i}] length`);
    assert.ok(a.mem[i].equals(b.mem[i]), `${label}: region[${i}] bytes differ`);
  }
}

// --- Rail 1: resumability over a synthetic image (always runs) ---------------

// A hand-assembled x86-64 loop that NEVER returns, so it runs to exactly the
// instruction budget every time and mutates both registers and memory each
// iteration — the ideal probe for chunk-boundary equivalence:
//   0: inc rax             48 ff c0
//   3: mov [rsp-8], rax    48 89 44 24 f8   (a store into the stack region)
//   8: add rbx, rax        48 01 c3
//  11: jmp 0               eb f3            (rel -13 back to the top)
const loopImage = Buffer.from([0x48, 0xff, 0xc0, 0x48, 0x89, 0x44, 0x24, 0xf8, 0x48, 0x01, 0xc3, 0xeb, 0xf3]);

function loopOption(budget) {
  return { image: loopImage, loadBase, entryRva: 0, budget };
}

test("stepping in K chunks of B reaches the same architectural state as one run of K*B (synthetic)", () => {
  // B deliberately does not divide the 4-instruction loop body, so chunk
  // boundaries fall INSIDE the loop — the strongest form of the equivalence.
  const B = 97;
  const K = 11;
  const total = B * K;

  // Reference: the monolithic runImage64 at the summed budget. Its register/rip
  // surface is the public contract stepContext must reproduce.
  const reference = runImage64(loopOption(total));
  assert.equal(reference.instruction_count, total, "the loop runs to the full budget without an early stop");
  assert.equal(reference.stop_reason, "instruction_budget_exhausted");

  // Reference memory + full machine: one-shot stepContext over a fresh context
  // (byte-identical to runImage64 because both drive the same interpreter loop).
  const contextOnce = buildGuestContext64(loopOption(total));
  const once = stepContext(contextOnce, total);
  assert.equal(once.instructionCount, total);
  assert.equal(once.done, false, "an infinite loop is not a structured stop, so the session is resumable");
  const snapOnce = snapshotMachine(contextOnce.machine);

  // Under test: K chunks of B over one persistent context.
  const contextChunked = buildGuestContext64(loopOption(total));
  let last = null;
  for (let i = 0; i < K; i += 1) {
    last = stepContext(contextChunked, B);
    assert.equal(last.stepInstructionCount, B, `chunk ${i} ran exactly B instructions`);
    assert.equal(last.instructionCount, B * (i + 1), `chunk ${i} cumulative count`);
  }
  const snapChunked = snapshotMachine(contextChunked.machine);

  // Bit-exact: the chunked run equals the one-shot run in every byte, and its
  // register/rip surface equals the monolithic runImage64.
  assertMachineEqual(snapChunked, snapOnce, "K*B chunked vs one-shot");
  for (const name of ["rax", "rbx", "rcx", "rsp", "rip"]) {
    const value = name === "rip" ? reference.rip : reference.register[name];
    const mine = name === "rip" ? (contextChunked.machine.rip & MASK64) : (contextChunked.machine.reg[["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"].indexOf(name)] & MASK64);
    assert.equal(mine, value, `chunked ${name} matches runImage64`);
  }
  assert.equal(last.instructionCount, total, "the chunked session's cumulative count equals the monolithic budget");
});

test("a structured stop mid-session makes further steps no-ops (done latches)", () => {
  // `ret` at entry returns to the sentinel: an entry_return structured stop on
  // the very first instruction. After that the session is done and steps idle.
  const context = buildGuestContext64({ image: Buffer.from([0xc3]), loadBase, entryRva: 0, budget: 4096 });
  const first = stepContext(context, 100);
  assert.equal(first.done, true, "the entry ret is a structured stop");
  assert.equal(first.stopReason, "entry_return");
  const countAfterStop = first.instructionCount;
  const second = stepContext(context, 100);
  assert.equal(second.done, true, "done latches");
  assert.equal(second.stepInstructionCount, 0, "a done session runs no further instructions");
  assert.equal(second.instructionCount, countAfterStop, "the cumulative count does not advance past the stop");
});

// --- Rail 1b: resumability over the real PuTTY x64 image (corpus-gated) -------

test("stepping the real PuTTY x64 in chunks matches a monolithic runImage64 exactly", { skip: existsSync(puttyPath) ? false : "corpus-001 not staged" }, () => {
  const bytes = new Uint8Array(readFileSync(puttyPath));
  const mapped = mapPe64State(bytes, null);
  const importSet = new Map();
  for (const entry of mapped.import ?? []) importSet.set((mapped.load_base + BigInt(entry.iat_slot_rva)) & MASK64, entry);
  const stackSizeByte = 0x00100000;
  const layout = createHleLayout({ load_base: Number(mapped.load_base & MASK64), image_size_byte: mapped.image_size_byte, stack_base: Number(stackBase), stack_end: Number(stackBase) + stackSizeByte });
  // A fresh clock (thus a fresh HLE guest) per run: the guest clock is stateful,
  // so sharing it across runs would make the second run resume the first's time
  // and diverge. Each option below gets its own clock — the honest apples-to-apples.
  const makeOption = (budget) => ({
    image: mapped.image, loadBase: mapped.load_base, entryRva: mapped.entry_rva, stackSizeByte, importSet, budget,
    hle: { layout, clock: createGuestClock({ mode: "virtual_monotonic" }), executableName: "putty.exe" },
    resourceRva: mapped.directory?.[2]?.rva ?? 0,
  });

  // A budget large enough to exercise many instructions before any stop.
  const total = 500000;

  const reference = runImage64(makeOption(total));
  const contextOnce = buildGuestContext64(makeOption(total));
  stepContext(contextOnce, total);

  // 500 chunks of 1000 instructions each — many boundaries through real CRT code.
  const contextChunked = buildGuestContext64(makeOption(total));
  let last = null;
  for (let i = 0; i < 500; i += 1) {
    last = stepContext(contextChunked, 1000);
    if (last.done) break;
  }

  assert.equal(last.instructionCount, reference.instruction_count, "chunked instruction count equals the monolithic run");
  assert.equal(last.stopReason, reference.stop_reason, "chunked stop reason equals the monolithic run");
  assert.equal(contextChunked.machine.rip & MASK64, reference.rip, "chunked rip equals the monolithic run");
  for (let i = 0; i < 16; i += 1) {
    assert.equal(contextChunked.machine.reg[i] & MASK64, contextOnce.machine.reg[i] & MASK64, `reg[${i}] chunked vs one-shot`);
  }
  // Full memory equality against the one-shot context.
  assertMachineEqual(snapshotMachine(contextChunked.machine), snapshotMachine(contextOnce.machine), "PuTTY chunked vs one-shot");
});

// --- Rail 2: live, input-driven Chocolate Doom (corpus-gated) ----------------

function frameHash(frame) {
  let hash = 0x811c9dc5n;
  for (let i = 0; i < frame.rgba.length; i += 1) hash = ((hash * 0x01000193n) + BigInt(frame.rgba[i])) & MASK64;
  return hash;
}

function newDoomSession() {
  const bytes = new Uint8Array(readFileSync(corpusDoomExe));
  const wad = readFileSync(corpusDoomWad);
  return createLiveSession(bytes, {
    executableName: "chocolate-doom.exe",
    hostFile: new Map([["C:\\game\\freedoom1.wad", wad]]),
    environment: { DOOMWADDIR: "C:\\game" },
    commandLine: ["-iwad", "C:\\game\\freedoom1.wad"],
  });
}

test("live Chocolate Doom: incremental steps draw a first frame, then a live Escape changes the frame", { skip: existsSync(corpusDoomExe) && existsSync(corpusDoomWad) ? false : "corpus-007 not staged" }, (t) => {
  const stepBudget = 1000000;
  const firstFrameCap = 40; // up to 40M instructions to the first frame (it lands ~16M)
  const menuCap = 30;       // up to 30M more instructions for the menu to draw

  // Phase 1: step the SAME guest in chunks until it presents a non-blank frame.
  const session = newDoomSession();
  let stepsToFrame = 0;
  let title = null;
  for (let i = 0; i < firstFrameCap; i += 1) {
    const status = session.step(stepBudget);
    stepsToFrame += 1;
    if (status.done) assert.fail(`the guest stopped before drawing a frame: ${status.stopReason}`);
    if (session.presentCount > 0) {
      const frame = session.frame();
      if (frame !== null && frame.is_blank === false) { title = frame; break; }
    }
  }
  assert.notEqual(title, null, "Doom drew a non-blank first frame within the step budget");
  assert.equal(session.hasVideo, true, "Doom opened an SDL video surface");
  const titleHash = frameHash(title);
  t.diagnostic(`first non-blank frame after ${stepsToFrame} steps (${session.instructionCount} instructions), present_count ${session.presentCount}`);

  // Phase 2: inject a LIVE Escape keypress (not a pre-scheduled trace) and keep
  // stepping the SAME session; Doom's own poll drain consumes it and opens the
  // menu — a frame whose hash differs from the title.
  const injected = session.sendInput([
    { type: "keydown", scancode: 41 /* SDL_SCANCODE_ESCAPE */, sym: 0x1b /* SDLK_ESCAPE */ },
    { type: "keyup", scancode: 41, sym: 0x1b },
  ]);
  assert.equal(injected, 2, "both live events were accepted into the queue");

  let menuHash = titleHash;
  let stepsToMenu = 0;
  for (let i = 0; i < menuCap; i += 1) {
    session.step(stepBudget);
    stepsToMenu += 1;
    const frame = session.frame();
    assert.equal(frame.is_blank, false, "the frame stays non-blank while the menu opens");
    const hash = frameHash(frame);
    if (hash !== titleHash) { menuHash = hash; break; }
  }
  assert.ok(session.guest.sdl.input_delivered >= 2, "Doom's own poll loop consumed the injected events");
  assert.notEqual(menuHash.toString(16), titleHash.toString(16), "the live Escape changed what is on screen (menu differs from title)");
  t.diagnostic(`live Escape changed the frame after ${stepsToMenu} more steps; input_delivered ${session.guest.sdl.input_delivered}`);
});

test("createLiveSession returns a usable surface before and independent of a window", { skip: existsSync(puttyPath) ? false : "corpus-001 not staged" }, () => {
  const bytes = new Uint8Array(readFileSync(puttyPath));
  const session = createLiveSession(bytes, { executableName: "putty.exe" });
  // frame() is callable immediately (before any step): a cleared surface, never null.
  const before = session.frame();
  assert.notEqual(before, null, "frame() returns a surface before the first step");
  assert.ok(before.width > 0 && before.height > 0, "the surface has dimensions");
  assert.equal(before.rgba.length, before.width * before.height * 4, "the surface is a full RGBA buffer");
  // A bounded step advances the persistent guest and stays callable.
  const status = session.step(50000);
  assert.ok(status.instructionCount > 0, "the step ran real instructions");
  assert.notEqual(session.frame(), null, "frame() is callable after a step");
  // sendInput queues a live event into the guest's SDL queue (the HLE always
  // attaches an SDL subsystem); a guest that never polls simply leaves it
  // unconsumed — no throw, no fabricated effect.
  assert.equal(session.sendInput({ type: "keydown", scancode: 41, sym: 0x1b }), 1, "one live event accepted into the queue");
});
