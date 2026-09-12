// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The guest thread subsystem conformance suite (BPTK-025). Cycle 1 maps the
// Thread Environment Block into guest memory and resolves the fs segment
// override against it. Two layers are proven: the TEB image builder in
// isolation (every documented field at its documented displacement), and the
// live probe reading those fields through fs:[disp] on the real run surface,
// with the bare CPU-conformance probe keeping its structured refusal.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildTebImage, tebField, pebField, pebProcessParametersOffset, processParametersField, SEH_CHAIN_END, TEB_SIZE_BYTE, createThreadScheduler, threadOp, threadPriority, waitResult, INFINITE, runContentionFixture } from "../lib/thread.mjs";
import { mapPe32ForRuntime } from "../lib/pe.mjs";
import { computeImportService, createHleLayout } from "../lib/hle.mjs";
import { chooseStackBase, executeProbe, normalizeStackSize } from "../lib/runtime.mjs";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

function run(argument) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

// One flat PE with an entry .text section. When importValue is set the image
// imports kernel32!ExitProcess, which the Win32 core HLE serves, so execution
// takes the HLE path that maps the TEB. Without it the bare probe runs and the
// fs override stays a structured refusal.
function createPe32(code, importValue) {
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
  file.writeUInt32LE((0x60000020 | 0x80000000) >>> 0, sectionOffset + 36);
  file.writeUInt32LE(0x600, sectionOffset + 16);
  file.writeUInt32LE(0x200, sectionOffset + 20);
  Buffer.from(code).copy(file, 0x200);
  if (importValue) {
    file.writeUInt32LE(0x1100, 0x98 + 96 + 8);
    file.writeUInt32LE(40, 0x98 + 96 + 12);
    file.writeUInt32LE(0x1140, 0x300);
    file.writeUInt32LE(0x1180, 0x30c);
    file.writeUInt32LE(0x1150, 0x310);
    file.writeUInt32LE(0x1190, 0x200 + 0x1140 - 0x1000);
    file.writeUInt32LE(0x1190, 0x200 + 0x1150 - 0x1000);
    file.write("KERNEL32.dll", 0x200 + 0x1180 - 0x1000);
    file.writeUInt16LE(0, 0x200 + 0x1190 - 0x1000);
    file.write("ExitProcess", 0x200 + 0x1192 - 0x1000);
  }
  return file;
}

function readRun(context, code, option = {}) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-thread-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const packagePath = join(rootPath, "package");
  mkdirSync(packagePath);
  writeFileSync(join(packagePath, "game.exe"), createPe32(code, option.import_value ?? false));
  const manifest = { schema_version: 1, executable: "game.exe", execution: { profile: "i386_probe_v1", instruction_budget_count: option.instruction_budget_count ?? 100 } };
  if (option.import_value) manifest.import = [];
  writeFileSync(join(packagePath, "bptk.json"), JSON.stringify(manifest));
  const result = run(["run", packagePath, "--json"]);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

// A memory read of the TEB through fs: mov reg, fs:[disp]; the encoding is the
// fs prefix, 0x8b /r with mode 0 rm 5 (disp32 absolute), then ret.
const fsLoadEax = (disp) => [0x64, 0x8b, 0x05, disp & 0xff, (disp >>> 8) & 0xff, (disp >>> 16) & 0xff, (disp >>> 24) & 0xff];

test("teb builder places every documented field at its documented displacement", () => {
  const built = buildTebImage({
    tebBase: 0xf0000000,
    pebBase: 0xf0001000,
    stackHighAddress: 0x70010000,
    stackLowAddress: 0x70000000,
    imageBase: 0x00400000,
    processId: 0x111,
    threadId: 0x222,
  });
  assert.equal(built.teb.length, TEB_SIZE_BYTE);
  assert.equal(built.teb.readUInt32LE(tebField.seh_head), SEH_CHAIN_END);
  assert.equal(built.teb.readUInt32LE(tebField.stack_base), 0x70010000);
  assert.equal(built.teb.readUInt32LE(tebField.stack_limit), 0x70000000);
  assert.equal(built.teb.readUInt32LE(tebField.self), 0xf0000000);
  assert.equal(built.teb.readUInt32LE(tebField.process_environment_block), 0xf0001000);
  assert.equal(built.teb.readUInt32LE(tebField.process_id), 0x111);
  assert.equal(built.teb.readUInt32LE(tebField.thread_id), 0x222);
  assert.equal(built.teb.readUInt32LE(tebField.tls_slot), 0, "the inline TLS slot array starts zeroed");
  assert.equal(built.teb.readUInt32LE(tebField.thread_local_storage_pointer), 0, "PE TLS array pointer stays unset without a declared base");
  assert.equal(built.peb.readUInt32LE(pebField.image_base_address), 0x00400000);
  assert.equal(built.peb.readUInt32LE(pebField.process_parameters), 0xf0001000 + pebProcessParametersOffset);
  assert.equal(built.peb.readUInt32LE(pebProcessParametersOffset + processParametersField.flags), 0);
  assert.equal(built.peb.readUInt8(pebField.being_debugged), 0);
  assert.equal(built.fs_base, 0xf0000000);
  assert.equal(built.gs_base, 0);
});

test("fs:[0] reads the empty SEH chain head through the mapped TEB", (context) => {
  const report = readRun(context, [...fsLoadEax(tebField.seh_head), 0xc3], { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.notEqual(report.thread, null);
  assert.equal(report.register.eax >>> 0, 0xffffffff);
});

test("fs:[0x18] self pointer is the TEB linear address and dereferences to itself", (context) => {
  // mov eax, fs:[0x18]; mov ecx, [eax]; ret — eax is the TEB base, and the
  // first dword at that linear address is the SEH chain head.
  const report = readRun(context, [...fsLoadEax(tebField.self), 0x8b, 0x08, 0xc3], { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.eax >>> 0, report.thread.teb_base >>> 0);
  assert.equal(report.register.ecx >>> 0, 0xffffffff);
});

test("fs:[0x30] walks PEB.ProcessParameters so [params+8] is a mapped Flags dword", (context) => {
  // mov eax, fs:[0x30]; mov eax, [eax+0x10]; mov eax, [eax+8]; ret
  const report = readRun(context, [
    ...fsLoadEax(tebField.process_environment_block),
    0x8b, 0x40, pebField.process_parameters,
    0x8b, 0x40, processParametersField.flags,
    0xc3,
  ], { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.eax >>> 0, 0);
});

test("fs:[0x30] walks the PEB to the image base", (context) => {
  // mov eax, fs:[0x30]; mov eax, [eax+8]; ret — PEB.ImageBaseAddress.
  const report = readRun(context, [...fsLoadEax(tebField.process_environment_block), 0x8b, 0x40, 0x08, 0xc3], { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.eax >>> 0, 0x00400000);
});

test("fs:[4] and fs:[8] carry the real stack bounds the probe runs on", (context) => {
  // mov eax, fs:[4] (StackBase); mov ebx, fs:[8] (StackLimit); ret.
  const code = [...fsLoadEax(tebField.stack_base), 0x64, 0x8b, 0x1d, tebField.stack_limit, 0x00, 0x00, 0x00, 0xc3];
  const report = readRun(context, code, { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.eax >>> 0, report.thread.stack_base >>> 0);
  assert.equal(report.register.ebx >>> 0, report.thread.stack_limit >>> 0);
  assert.ok((report.register.eax >>> 0) > (report.register.ebx >>> 0), "the stack base is above the stack limit");
});

test("fs:[0x2c] is a live PE TLS array whose slot 0 points at a mapped block", (context) => {
  // mov eax, fs:[0x2C]; mov eax, [eax]; ret — ThreadLocalStoragePointer, then slot 0.
  const report = readRun(context, [...fsLoadEax(tebField.thread_local_storage_pointer), 0x8b, 0x00, 0xc3], { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.notEqual(report.register.eax >>> 0, 0, "slot 0 must be a mapped TLS block, not a null deref");
});

test("a TLS slot written through fs reads back through fs", (context) => {
  // mov dword ptr fs:[0xE10], 0x12345678; mov eax, fs:[0xE10]; ret.
  const code = [
    0x64, 0xc7, 0x05, tebField.tls_slot & 0xff, (tebField.tls_slot >>> 8) & 0xff, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12,
    ...fsLoadEax(tebField.tls_slot),
    0xc3,
  ];
  const report = readRun(context, code, { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.eax >>> 0, 0x12345678);
});

test("LEA under an fs override ignores the segment base", (context) => {
  // lea eax, fs:[0x1000]; ret — LEA loads the effective offset itself, so the
  // TEB base must not be folded in.
  const report = readRun(context, [0x64, 0x8d, 0x05, 0x00, 0x10, 0x00, 0x00, 0xc3], { import_value: true });
  assert.equal(report.stop_reason, "entry_return", JSON.stringify(report.exception));
  assert.equal(report.register.eax >>> 0, 0x1000);
});

test("the bare probe with no thread-environment block keeps refusing the fs override", (context) => {
  const report = readRun(context, [...fsLoadEax(tebField.self), 0xc3]);
  assert.equal(report.thread, null);
  assert.equal(report.stop_reason, "unsupported_opcode");
  assert.equal(report.exception.opcode, 0x64);
  assert.match(report.exception.message, /thread-environment block/);
});

// --- The deterministic scheduler (BPTK-025) ---------------------------------

test("scheduler: a thread runs to return and reports its exit code", () => {
  const scheduler = createThreadScheduler();
  scheduler.createThread({ program: function* () { yield threadOp.setRegister(0, 0x1234); return 7; } });
  const report = scheduler.run();
  assert.equal(report.stopped, null);
  assert.equal(report.thread[0].state, "terminated");
  assert.equal(report.thread[0].exit_code, 7);
});

test("scheduler: per-thread register files do not bleed across threads", () => {
  const scheduler = createThreadScheduler();
  const observed = [];
  const makeProgram = (mark) => function* ({ thread_id }) {
    yield threadOp.setRegister(0, mark);
    yield threadOp.yieldQuantum(); // force an interleave with the other thread
    const readback = yield threadOp.getRegister(0);
    observed.push([thread_id, readback]);
    return 0;
  };
  const a = scheduler.createThread({ program: makeProgram(0xaaaa) });
  const b = scheduler.createThread({ program: makeProgram(0xbbbb) });
  scheduler.run();
  const byThread = new Map(observed);
  assert.equal(byThread.get(a), 0xaaaa, "thread A keeps its own register value");
  assert.equal(byThread.get(b), 0xbbbb, "thread B keeps its own register value");
});

test("scheduler: per-thread TLS shares the index but isolates the value", () => {
  const scheduler = createThreadScheduler();
  const index = scheduler.allocateTlsIndex();
  const readback = new Map();
  const makeProgram = (value) => function* ({ thread_id }) {
    yield threadOp.tlsSet(index, value);
    yield threadOp.yieldQuantum();
    readback.set(thread_id, yield threadOp.tlsGet(index));
    return 0;
  };
  const a = scheduler.createThread({ program: makeProgram(0x11) });
  const b = scheduler.createThread({ program: makeProgram(0x22) });
  scheduler.run();
  assert.equal(readback.get(a), 0x11);
  assert.equal(readback.get(b), 0x22, "the second thread never sees the first thread's slot value");
});

test("scheduler: higher priority runs before lower at the same ready instant", () => {
  const scheduler = createThreadScheduler();
  const order = [];
  scheduler.createThread({ priority: threadPriority.below_normal, program: function* ({ thread_id }) { order.push(thread_id); return 0; } });
  const high = scheduler.createThread({ priority: threadPriority.highest, program: function* ({ thread_id }) { order.push(thread_id); return 0; } });
  scheduler.run();
  assert.equal(order[0], high, "the highest-priority thread is serviced first");
});

test("scheduler: a suspended thread does not run until it is resumed", () => {
  const scheduler = createThreadScheduler();
  const order = [];
  const worker = scheduler.createThread({ suspended: true, program: function* ({ thread_id }) { order.push(thread_id); return 0; } });
  scheduler.createThread({ program: function* ({ thread_id }) {
    order.push(thread_id);
    yield threadOp.resumeThread(worker);
    return 0;
  } });
  const report = scheduler.run();
  assert.equal(report.stopped, null);
  assert.equal(order.length, 2);
  assert.equal(order[1], worker, "the worker only ran after the resume");
});

test("scheduler: a critical section serializes a read-modify-write with no lost update", () => {
  const workerCount = 8;
  const perThread = 25;
  const build = () => {
    const scheduler = createThreadScheduler();
    const lock = scheduler.createCriticalSection();
    for (let index = 0; index < workerCount; index += 1) {
      scheduler.createThread({ program: function* () {
        for (let step = 0; step < perThread; step += 1) {
          yield threadOp.lock(lock);
          const current = yield threadOp.interlocked("load", 0);
          yield threadOp.yieldQuantum(); // an interleave that would lose the update without the lock
          yield threadOp.interlocked("exchange", 0, current + 1);
          yield threadOp.unlock(lock);
        }
        return 0;
      } });
    }
    const report = scheduler.run();
    return { report, counter: scheduler.sharedWord[0] };
  };
  const first = build();
  assert.equal(first.report.stopped, null);
  assert.equal(first.counter, workerCount * perThread, "every increment survived the contention");
  // Two replays of the identical workload hash-match.
  const second = build();
  assert.equal(second.counter, workerCount * perThread);
  assert.equal(second.report.trace_sha256, first.report.trace_sha256, "the schedule is byte-reproducible across replays");
});

test("scheduler: an interlocked counter reaches the same total under 1 and under N workers", () => {
  const total = 200;
  const runWith = (workerCount) => {
    const scheduler = createThreadScheduler();
    const perThread = total / workerCount;
    for (let index = 0; index < workerCount; index += 1) {
      scheduler.createThread({ program: function* () {
        for (let step = 0; step < perThread; step += 1) { yield threadOp.interlocked("increment", 0); yield threadOp.yieldQuantum(); }
        return 0;
      } });
    }
    scheduler.run();
    return scheduler.sharedWord[0];
  };
  assert.equal(runWith(1), total, "single-thread fallback total");
  assert.equal(runWith(4), total);
  assert.equal(runWith(8), total, "the same total regardless of worker count");
});

test("scheduler: an auto-reset event wakes exactly one waiter per set with zero lost wakeup", () => {
  const scheduler = createThreadScheduler();
  const gate = scheduler.createEvent(false, false); // auto-reset, initially unset
  const woke = [];
  const consumerCount = 5;
  for (let index = 0; index < consumerCount; index += 1) {
    scheduler.createThread({ program: function* ({ thread_id }) {
      const code = yield threadOp.wait(gate);
      woke.push([thread_id, code]);
      return 0;
    } });
  }
  scheduler.createThread({ program: function* () {
    for (let index = 0; index < consumerCount; index += 1) { yield threadOp.setEvent(gate); yield threadOp.yieldQuantum(); }
    return 0;
  } });
  const report = scheduler.run();
  assert.equal(report.stopped, null, "no consumer was left stuck — every set woke exactly one");
  assert.equal(woke.length, consumerCount);
  assert.ok(woke.every(([, code]) => code === waitResult.object_0));
});

test("scheduler: a semaphore admits exactly its count of waiters", () => {
  const scheduler = createThreadScheduler();
  const slot = scheduler.createSemaphore(2, 4);
  const entered = [];
  for (let index = 0; index < 4; index += 1) {
    scheduler.createThread({ program: function* ({ thread_id }) {
      yield threadOp.wait(slot);
      entered.push(thread_id);
      return 0;
    } });
  }
  // Only two may enter before a release; the releaser lets the other two in.
  scheduler.createThread({ program: function* () {
    yield threadOp.yieldQuantum();
    yield threadOp.releaseSemaphore(slot, 2);
    return 0;
  } });
  const report = scheduler.run();
  assert.equal(report.stopped, null);
  assert.equal(entered.length, 4);
});

test("scheduler: WaitForMultipleObjects with waitAll blocks until every object signals", () => {
  const scheduler = createThreadScheduler();
  const a = scheduler.createEvent(true, false);
  const b = scheduler.createEvent(true, false);
  let code = null;
  scheduler.createThread({ program: function* () { code = yield threadOp.wait([a, b], { all: true }); return 0; } });
  scheduler.createThread({ program: function* () {
    yield threadOp.setEvent(a);
    yield threadOp.yieldQuantum();
    yield threadOp.setEvent(b);
    return 0;
  } });
  const report = scheduler.run();
  assert.equal(report.stopped, null);
  assert.equal(code, waitResult.object_0);
});

test("scheduler: a wait with a finite timeout returns WAIT_TIMEOUT over the monotonic clock", () => {
  const scheduler = createThreadScheduler();
  const gate = scheduler.createEvent(true, false); // never set
  let code = null;
  scheduler.createThread({ program: function* () { code = yield threadOp.wait(gate, { timeout: 250 }); return 0; } });
  const report = scheduler.run();
  assert.equal(report.stopped, null);
  assert.equal(code, waitResult.timeout);
  assert.equal(report.clock_ms, 250, "the clock advanced exactly to the deadline");
});

test("scheduler: a mutual wait with no timeout is reported as a structured deadlock", () => {
  const scheduler = createThreadScheduler();
  const a = scheduler.createEvent(true, false);
  const b = scheduler.createEvent(true, false);
  // Each thread waits on the event the other would set, but neither ever does.
  scheduler.createThread({ program: function* () { yield threadOp.wait(a); yield threadOp.setEvent(b); return 0; } });
  scheduler.createThread({ program: function* () { yield threadOp.wait(b); yield threadOp.setEvent(a); return 0; } });
  const report = scheduler.run();
  assert.equal(report.stopped, "deadlock");
});

test("scheduler: sleep yields the quantum and advances the clock without spinning", () => {
  const scheduler = createThreadScheduler();
  scheduler.createThread({ program: function* () { yield threadOp.sleep(100); return 0; } });
  const report = scheduler.run();
  assert.equal(report.stopped, null);
  assert.equal(report.clock_ms, 100);
  assert.ok(report.step_count < 10, "sleeping cost a handful of steps, not a spin");
});

test("scheduler: memory.atomic.wait blocks until a notify, with no lost wakeup", () => {
  const scheduler = createThreadScheduler();
  let waiterCode = null;
  scheduler.createThread({ program: function* () {
    // The word is still 0, so the wait actually blocks.
    waiterCode = yield threadOp.atomicWait(0, 0);
    return 0;
  } });
  scheduler.createThread({ program: function* () {
    yield threadOp.yieldQuantum();
    yield threadOp.interlocked("exchange", 0, 1);
    const woken = yield threadOp.atomicNotify(0, 1);
    assert.equal(woken, 1);
    return 0;
  } });
  const report = scheduler.run();
  assert.equal(report.stopped, null);
  assert.equal(waiterCode, 0, "the waiter was woken, not timed out");
});

test("scheduler: cross-thread SendMessage delivers to a blocked receiver", () => {
  const scheduler = createThreadScheduler();
  let delivered = null;
  const receiver = scheduler.createThread({ program: function* () { delivered = yield threadOp.receive(); return 0; } });
  scheduler.createThread({ program: function* () {
    yield threadOp.yieldQuantum();
    yield threadOp.send(receiver, 0xcafe);
    return 0;
  } });
  const report = scheduler.run();
  assert.equal(report.stopped, null);
  assert.equal(delivered, 0xcafe);
});

test("scheduler: a waitable timer fires at its due time", () => {
  const scheduler = createThreadScheduler();
  const timer = scheduler.createWaitableTimer(true);
  let code = null;
  scheduler.createThread({ program: function* () {
    yield threadOp.setTimer(timer, 500, 0);
    code = yield threadOp.wait(timer);
    return 0;
  } });
  const report = scheduler.run();
  assert.equal(report.stopped, null);
  assert.equal(code, waitResult.object_0);
  assert.equal(report.clock_ms, 500);
});

// BPTK-051 / GS-006 — guest SMP determinism over the worker-pool model.
test("smp: the contention fixture is guest-state deterministic across repeated runs", () => {
  const first = runContentionFixture({ worker_count: 4, total_increment: 240 });
  const second = runContentionFixture({ worker_count: 4, total_increment: 240 });
  assert.equal(first.is_consistent, true, "both counters reach the expected total under contention");
  assert.equal(first.state_sha256, second.state_sha256, "guest-visible state is byte-reproducible across runs");
  assert.equal(first.schedule_sha256, second.schedule_sha256, "the schedule itself is byte-reproducible");
});

test("smp: guest-visible state matches across worker counts with no lost wakeup", () => {
  const single = runContentionFixture({ worker_count: 1, total_increment: 240 });
  const many = runContentionFixture({ worker_count: 8, total_increment: 240 });
  assert.equal(single.state_sha256, many.state_sha256, "the same total regardless of worker count");
  assert.equal(single.lost_wakeup_count, 0);
  assert.equal(many.lost_wakeup_count, 0, "no wakeup is lost under N workers");
  assert.equal(many.is_deadlocked, false);
});

test("smp: the real cross-core worker deployment stays honestly red", () => {
  const report = runContentionFixture({ worker_count: 4 });
  assert.equal(report.is_worker_backed, false, "the deterministic model is not a real SAB Worker pool");
  assert.ok(report.blocker.length >= 1);
});

function createPe32WithImports(code, symbols) {
  const file = Buffer.alloc(0x1000);
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
  file.writeUInt32LE((0x60000020 | 0x80000000) >>> 0, sectionOffset + 36);
  file.writeUInt32LE(0x600, sectionOffset + 16);
  file.writeUInt32LE(0x200, sectionOffset + 20);
  Buffer.from(code).copy(file, 0x200);
  const importRva = 0x1100;
  file.writeUInt32LE(importRva, 0x98 + 96 + 8);
  file.writeUInt32LE(40, 0x98 + 96 + 12);
  const iltRva = 0x1140;
  const iatRva = iltRva + (symbols.length + 1) * 4;
  const dllRva = iatRva + (symbols.length + 1) * 4;
  let hintRva = dllRva + 16;
  file.writeUInt32LE(iltRva, 0x200 + importRva - 0x1000);
  file.writeUInt32LE(dllRva, 0x200 + importRva - 0x1000 + 12);
  file.writeUInt32LE(iatRva, 0x200 + importRva - 0x1000 + 16);
  file.write("KERNEL32.dll", 0x200 + dllRva - 0x1000);
  for (let index = 0; index < symbols.length; index += 1) {
    file.writeUInt32LE(hintRva, 0x200 + iltRva - 0x1000 + index * 4);
    file.writeUInt32LE(hintRva, 0x200 + iatRva - 0x1000 + index * 4);
    file.writeUInt16LE(0, 0x200 + hintRva - 0x1000);
    file.write(symbols[index], 0x200 + hintRva - 0x1000 + 2);
    hintRva += 2 + symbols[index].length + 1;
  }
  return { file, iatVa: 0x00400000 + iatRva };
}

test("CreateThread runs the start routine; WaitForSingleObject sees the event it signals", (context) => {
  // Worker: SetEvent(param); ret 4. Main: CreateEventW; CreateThread(worker, event);
  // WaitForSingleObject(event, INFINITE); ExitProcess(eax).
  const symbols = ["CreateEventW", "CreateThread", "WaitForSingleObject", "SetEvent", "ExitProcess"];
  const callIat = (slot) => [0xff, 0x15, slot & 0xff, (slot >>> 8) & 0xff, (slot >>> 16) & 0xff, (slot >>> 24) & 0xff];
  const iatVa = 0x00401140 + (symbols.length + 1) * 4;
  const slot = (index) => iatVa + index * 4;
  const worker = 0x00401040;
  const code = [
    0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00,
    ...callIat(slot(0)),
    0x89, 0xc6,
    0x6a, 0x00, 0x6a, 0x00, 0x56,
    0x68, worker & 0xff, (worker >>> 8) & 0xff, (worker >>> 16) & 0xff, (worker >>> 24) & 0xff,
    0x6a, 0x00, 0x6a, 0x00,
    ...callIat(slot(1)),
    0x85, 0xc0, 0x74, 0x10,
    0x6a, 0xff, 0x56,
    ...callIat(slot(2)),
    0x50,
    ...callIat(slot(4)),
    0x6a, 0x02,
    ...callIat(slot(4)),
    // worker @ 0x401040
  ];
  while (code.length < 0x40) code.push(0x90);
  code.push(
    0xff, 0x74, 0x24, 0x04,
    ...callIat(slot(3)),
    0xc2, 0x04, 0x00,
  );
  const { file } = createPe32WithImports(code, symbols);
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-guest-thread-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const exe = join(rootPath, "game.exe");
  writeFileSync(exe, file);
  const mapped = mapPe32ForRuntime(exe, null, null);
  const stackSizeByte = normalizeStackSize(mapped.report.stack_reserve_byte);
  const stackBase = chooseStackBase(mapped.report.load_base, mapped.report.load_base + mapped.report.image_size_byte, stackSizeByte);
  const layout = createHleLayout({ ...mapped.report, stack_base: stackBase, stack_end: stackBase + stackSizeByte });
  const service = computeImportService(mapped.report, layout);
  assert.equal(service.unserved_count, 0, JSON.stringify(service.unserved));
  const remapped = mapPe32ForRuntime(exe, null, service.import_catalog);
  const probe = executeProbe(remapped, 100000, { hle_layout: layout, executable_name: "game.exe" });
  assert.equal(probe.stop_reason, "process_exit", JSON.stringify(probe.exception));
  assert.equal(probe.exception?.exit_code, 0);
});

test("WaitOnAddress parks until the other thread WakeByAddressSingle", (context) => {
  // Shared dword at 0x401800 (in the image? better use a stack cell). Worker:
  // mov dword [addr], 1; WakeByAddressSingle(addr); ret 4.
  // Main: CreateThread; WaitOnAddress(addr, 0, 4, INFINITE); ExitProcess(eax==1?0:3).
  const symbols = ["CreateThread", "WaitOnAddress", "WakeByAddressSingle", "ExitProcess"];
  const callIat = (slotVa) => [0xff, 0x15, slotVa & 0xff, (slotVa >>> 8) & 0xff, (slotVa >>> 16) & 0xff, (slotVa >>> 24) & 0xff];
  const iatVa = 0x00401140 + (symbols.length + 1) * 4;
  const slot = (index) => iatVa + index * 4;
  const worker = 0x00401080;
  const cell = 0x004010e0;
  const zero = 0x004010e4;
  const code = [
    0xc7, 0x05, cell & 0xff, (cell >>> 8) & 0xff, (cell >>> 16) & 0xff, (cell >>> 24) & 0xff, 0x00, 0x00, 0x00, 0x00,
    0xc7, 0x05, zero & 0xff, (zero >>> 8) & 0xff, (zero >>> 16) & 0xff, (zero >>> 24) & 0xff, 0x00, 0x00, 0x00, 0x00,
    0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00,
    0x68, worker & 0xff, (worker >>> 8) & 0xff, (worker >>> 16) & 0xff, (worker >>> 24) & 0xff,
    0x6a, 0x00, 0x6a, 0x00,
    ...callIat(slot(0)),
    0x85, 0xc0, 0x74, 0x1c,
    0x6a, 0xff,
    0x6a, 0x04,
    0x68, zero & 0xff, (zero >>> 8) & 0xff, (zero >>> 16) & 0xff, (zero >>> 24) & 0xff,
    0x68, cell & 0xff, (cell >>> 8) & 0xff, (cell >>> 16) & 0xff, (cell >>> 24) & 0xff,
    ...callIat(slot(1)),
    0x83, 0xf8, 0x01, 0x74, 0x04, 0x6a, 0x03, 0xeb, 0x02, 0x6a, 0x00,
    ...callIat(slot(3)),
    0x6a, 0x02,
    ...callIat(slot(3)),
  ];
  while (code.length < 0x80) code.push(0x90);
  code.push(
    0xc7, 0x05, cell & 0xff, (cell >>> 8) & 0xff, (cell >>> 16) & 0xff, (cell >>> 24) & 0xff, 0x01, 0x00, 0x00, 0x00,
    0x68, cell & 0xff, (cell >>> 8) & 0xff, (cell >>> 16) & 0xff, (cell >>> 24) & 0xff,
    ...callIat(slot(2)),
    0xc2, 0x04, 0x00,
  );
  const { file } = createPe32WithImports(code, symbols);
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-wait-address-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const exe = join(rootPath, "game.exe");
  writeFileSync(exe, file);
  const mapped = mapPe32ForRuntime(exe, null, null);
  const stackSizeByte = normalizeStackSize(mapped.report.stack_reserve_byte);
  const stackBase = chooseStackBase(mapped.report.load_base, mapped.report.load_base + mapped.report.image_size_byte, stackSizeByte);
  const layout = createHleLayout({ ...mapped.report, stack_base: stackBase, stack_end: stackBase + stackSizeByte });
  const service = computeImportService(mapped.report, layout);
  assert.equal(service.unserved_count, 0, JSON.stringify(service.unserved));
  const remapped = mapPe32ForRuntime(exe, null, service.import_catalog);
  const probe = executeProbe(remapped, 100000, { hle_layout: layout, executable_name: "game.exe" });
  assert.equal(probe.stop_reason, "process_exit", JSON.stringify(probe.exception));
  assert.equal(probe.exception?.exit_code, 0);
});
