// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";

// The guest thread and synchronization subsystem (BPTK-025). A real Win32
// process reaches its entry with one thread already live, and that thread is
// described by a Thread Environment Block (TEB) the code reads through the fs
// segment. The compiler-emitted prologue of nearly every real binary loads
// fs:[0x18] (the self pointer), fs:[0x00] (the structured-exception head), or
// the stack-cookie guard through fs — so a probe with no TEB refuses the very
// first fs override it meets. This module maps that block generically: it is
// the shared memory floor the exception, cpu, and user/gdi lanes rebase onto,
// never a per-title patch.
//
// The field offsets are the documented NT_TIB / TEB layout for the 32-bit
// Windows process (fs-relative), so a guest that reads fs:[disp] finds the
// architecturally correct value at the architecturally correct displacement.

// One page each is enough for the minimal block: the TEB fixed fields end at
// the TLS slot array (0xE10 + 64*4 = 0xF10 < 0x1000), and the minimal PEB
// fields the guest reads (image base, heap, flags) sit well inside a page.
export const TEB_SIZE_BYTE = 0x1000;
export const PEB_SIZE_BYTE = 0x1000;

// The default per-thread TLS slot count. The TEB carries the first 64 slots
// inline (TlsSlots), matching the documented layout and the HLE handle bound.
export const TLS_SLOT_COUNT = 64;

// The fs-relative displacement of every TEB field this subsystem maps. These
// are the fixed offsets of the 32-bit TEB / NT_TIB, not chosen values: a real
// binary computes them at compile time, so they must match exactly.
export const tebField = Object.freeze({
  seh_head: 0x00, // NT_TIB.ExceptionList — the SEH frame chain head
  stack_base: 0x04, // NT_TIB.StackBase — the highest stack address
  stack_limit: 0x08, // NT_TIB.StackLimit — the lowest committed stack address
  self: 0x18, // NT_TIB.Self — the linear address of the TEB itself
  process_environment_block: 0x30, // TEB.ProcessEnvironmentBlock — the PEB pointer
  last_error: 0x34, // TEB.LastErrorValue
  process_id: 0x20, // TEB.ClientId.UniqueProcess
  thread_id: 0x24, // TEB.ClientId.UniqueThread
  tls_slot: 0xe10, // TEB.TlsSlots — the inline 64-slot array
});

// The minimal PEB. A guest that walks the PEB reads its image base and the
// debugger / global flags; anything unread stays zero, which is the honest
// value for a field this subsystem does not model.
export const pebField = Object.freeze({
  being_debugged: 0x02, // PEB.BeingDebugged — always zero (no debugger attached)
  image_base_address: 0x08, // PEB.ImageBaseAddress
  process_heap: 0x18, // PEB.ProcessHeap
  nt_global_flag: 0x68, // PEB.NtGlobalFlag — zero (no heap instrumentation)
});

// The empty SEH chain terminator: the last frame's Next pointer is 0xFFFFFFFF,
// so a guest that walks fs:[0] finds a well-formed, empty chain.
export const SEH_CHAIN_END = 0xffffffff;

// Build the initial thread's TEB and PEB image for one bounded probe run. The
// stack bounds come from the probe's own chosen stack region (the TEB must
// describe the real stack the guest runs on, not an invented one), and the
// self pointer and PEB pointer are absolute guest linear addresses so the
// guest can chase them through fs.
export function buildTebImage(option) {
  const tebBase = option.tebBase >>> 0;
  const pebBase = option.pebBase >>> 0;
  const stackHighAddress = option.stackHighAddress >>> 0; // NT_TIB.StackBase
  const stackLowAddress = option.stackLowAddress >>> 0; // NT_TIB.StackLimit
  const imageBase = (option.imageBase ?? 0) >>> 0;
  const processHeap = (option.processHeap ?? 0) >>> 0;
  const processId = (option.processId ?? 0x1000) >>> 0;
  const threadId = (option.threadId ?? 0x1004) >>> 0;
  const tlsSlotCount = option.tlsSlotCount ?? TLS_SLOT_COUNT;

  const teb = Buffer.alloc(TEB_SIZE_BYTE);
  teb.writeUInt32LE(SEH_CHAIN_END, tebField.seh_head);
  teb.writeUInt32LE(stackHighAddress, tebField.stack_base);
  teb.writeUInt32LE(stackLowAddress, tebField.stack_limit);
  teb.writeUInt32LE(tebBase, tebField.self);
  teb.writeUInt32LE(processId, tebField.process_id);
  teb.writeUInt32LE(threadId, tebField.thread_id);
  teb.writeUInt32LE(pebBase, tebField.process_environment_block);
  teb.writeUInt32LE(0, tebField.last_error);
  // The inline TLS slot array starts zeroed; TlsAlloc/TlsSetValue write into it
  // and fs:[0xE10 + index*4] reads it back through the same bytes.

  const peb = Buffer.alloc(PEB_SIZE_BYTE);
  peb.writeUInt8(0, pebField.being_debugged);
  peb.writeUInt32LE(imageBase, pebField.image_base_address);
  peb.writeUInt32LE(processHeap, pebField.process_heap);
  peb.writeUInt32LE(0, pebField.nt_global_flag);

  return {
    teb,
    peb,
    teb_base: tebBase,
    peb_base: pebBase,
    // Win32 addresses the TEB through fs (base = the TEB linear address) and
    // gives gs a base of zero in the flat user-mode model.
    fs_base: tebBase,
    gs_base: 0,
    tls_slot_count: tlsSlotCount,
    tls_slot_base: (tebBase + tebField.tls_slot) >>> 0,
    field: tebField,
  };
}

// ---------------------------------------------------------------------------
// The deterministic thread scheduler (BPTK-025). A real Win32 process runs
// many threads over one address space; the browser target maps them onto a
// Web Worker pool sharing a SharedArrayBuffer. The bounded probe cannot fork
// the host, so it models the concurrency deterministically: one cooperative
// scheduler drives every thread over a single ordered timeline, so two runs of
// the same workload produce byte-identical event traces. That determinism is
// the whole point — a lock-free counter, a producer/consumer handoff, and a
// wait with timeout must resolve the same way every replay, with no lost
// wakeup and no cross-thread register or TLS bleed.
//
// A thread's body is a generator that yields request objects (built by
// `threadOp`); each yield is a scheduling point. The scheduler services one
// request per quantum, blocks the thread when a request cannot complete, and
// wakes it deterministically when the blocking condition clears — never a
// spin-wait.

export const INFINITE = 0xffffffff;

// Win32 wait result codes.
export const waitResult = Object.freeze({
  object_0: 0x00000000,
  abandoned_0: 0x00000080,
  timeout: 0x00000102,
  failed: 0xffffffff,
});

// Thread priority, higher scheduled first (the Win32 THREAD_PRIORITY ladder
// collapsed to the values the scheduler orders on).
export const threadPriority = Object.freeze({
  idle: -15,
  lowest: -2,
  below_normal: -1,
  normal: 0,
  above_normal: 1,
  highest: 2,
  time_critical: 15,
});

const threadState = Object.freeze({
  ready: "ready",
  waiting: "waiting",
  suspended: "suspended",
  terminated: "terminated",
});

// The register-file width the probe carries: eight general registers plus eip.
const REGISTER_COUNT = 9;

// The request builders a thread generator yields. Keeping them here means a
// thread program reads as a sequence of Win32-shaped calls, and every request
// carries exactly the fields the scheduler services.
export const threadOp = Object.freeze({
  yieldQuantum: () => ({ op: "yield" }),
  sleep: (ms) => ({ op: "sleep", ms: ms >>> 0 }),
  exit: (code = 0) => ({ op: "exit", code: code >>> 0 }),
  getRegister: (index) => ({ op: "get_register", index }),
  setRegister: (index, value) => ({ op: "set_register", index, value: value >>> 0 }),
  tlsAlloc: () => ({ op: "tls_alloc" }),
  tlsFree: (index) => ({ op: "tls_free", index }),
  tlsGet: (index) => ({ op: "tls_get", index }),
  tlsSet: (index, value) => ({ op: "tls_set", index, value: value >>> 0 }),
  lock: (handle) => ({ op: "lock", handle }),
  tryLock: (handle) => ({ op: "try_lock", handle }),
  unlock: (handle) => ({ op: "unlock", handle }),
  wait: (handle, option = {}) => ({ op: "wait", handle: Array.isArray(handle) ? handle : [handle], all: option.all === true, timeout: option.timeout ?? INFINITE }),
  setEvent: (handle) => ({ op: "set_event", handle }),
  resetEvent: (handle) => ({ op: "reset_event", handle }),
  releaseMutex: (handle) => ({ op: "release_mutex", handle }),
  releaseSemaphore: (handle, count = 1) => ({ op: "release_semaphore", handle, count }),
  setTimer: (handle, dueMs, periodMs = 0) => ({ op: "set_timer", handle, dueMs: dueMs >>> 0, periodMs: periodMs >>> 0 }),
  cancelTimer: (handle) => ({ op: "cancel_timer", handle }),
  interlocked: (kind, address, value = 0, comparand = 0) => ({ op: "interlocked", kind, address, value: value | 0, comparand: comparand | 0 }),
  atomicWait: (address, expected, timeout = INFINITE) => ({ op: "atomic_wait", address, expected: expected | 0, timeout }),
  atomicNotify: (address, count = 1) => ({ op: "atomic_notify", address, count }),
  suspendThread: (handle) => ({ op: "suspend", handle }),
  resumeThread: (handle) => ({ op: "resume", handle }),
  send: (handle, message) => ({ op: "send", handle, message: message >>> 0 }),
  receive: (option = {}) => ({ op: "receive", timeout: option.timeout ?? INFINITE }),
  currentThreadId: () => ({ op: "current_thread_id" }),
});

class ThreadFault extends Error {
  constructor(code, message, detail = {}) {
    super(message);
    this.name = "ThreadFault";
    this.code = code;
    Object.assign(this, detail);
  }
}

export function createThreadScheduler(option = {}) {
  const sharedWordCount = option.shared_word_count ?? 256;
  const threadBound = option.thread_count ?? 256;
  // The shared memory the Interlocked family and the futex model operate over.
  // Backing it with a SharedArrayBuffer and driving it through Atomics keeps
  // the read-modify-write faithful to the WASM-atomic target even though the
  // cooperative scheduler never runs two steps at once.
  const sharedByte = new SharedArrayBuffer(sharedWordCount * 4);
  const sharedWord = new Int32Array(sharedByte);

  const objectTable = new Map(); // handle -> sync object
  const thread = new Map(); // handle -> thread record
  const threadOrder = []; // creation order of thread handles, for deterministic scan
  let nextHandle = 4;
  let readySequence = 0;
  let eventSequence = 0;
  let clockMs = 0;
  const futexWaiter = new Map(); // address -> [thread handle, ...]
  const traceHash = createHash("sha256");
  const event = [];
  let stopReason = null;

  function allocateHandle() {
    const handle = nextHandle;
    nextHandle += 4;
    return handle;
  }

  function recordEvent(threadHandle, opType, resultCode) {
    const entry = { sequence: eventSequence, thread_id: threadHandle, op: opType, result: resultCode >>> 0, clock_ms: clockMs };
    event.push(entry);
    const line = Buffer.from(`${entry.sequence}|${entry.thread_id}|${entry.op}|${entry.result}|${entry.clock_ms}\n`, "utf8");
    traceHash.update(line);
    eventSequence += 1;
  }

  function markReady(record) {
    record.state = threadState.ready;
    record.ready_sequence = readySequence;
    readySequence += 1;
  }

  function createThread(specification) {
    if (thread.size >= threadBound) throw new ThreadFault("thread_bound_exceeded", `The thread table is bounded at ${threadBound}`);
    const handle = allocateHandle();
    const register = new Uint32Array(REGISTER_COUNT);
    if (specification.register) register.set(specification.register.subarray(0, REGISTER_COUNT));
    const record = {
      handle,
      kind: "thread",
      program: specification.program,
      parameter: (specification.parameter ?? 0) >>> 0,
      priority: specification.priority ?? threadPriority.normal,
      register,
      tls: new Map(), // per-thread TLS: the slot INDEX comes from the shared
      // allocator, the VALUE is private to this thread — no cross-thread bleed
      state: specification.suspended === true ? threadState.suspended : threadState.ready,
      suspend_count: specification.suspended === true ? 1 : 0,
      iterator: null,
      pending_result: undefined,
      wait: null,
      deadline: null,
      exit_code: 0,
      message_queue: [],
      ready_sequence: readySequence,
      owned_mutex: new Set(),
      signaled: false, // a thread object signals when it terminates (join)
    };
    readySequence += 1;
    thread.set(handle, record);
    // The thread is itself a waitable object: a join waits on this handle and
    // it signals when the thread terminates.
    objectTable.set(handle, record);
    threadOrder.push(handle);
    return handle;
  }

  // The shared TLS index allocator: TlsAlloc reserves an index across every
  // thread, TlsFree releases it; the per-thread VALUE lives in the thread
  // record so two threads never see each other's slot value.
  const tlsAllocated = new Array(option.tls_slot_count ?? TLS_SLOT_COUNT).fill(false);
  function allocateTlsIndex() {
    const index = tlsAllocated.findIndex((used) => !used);
    if (index < 0) return -1;
    tlsAllocated[index] = true;
    return index;
  }
  function freeTlsIndex(index) {
    if (index < 0 || index >= tlsAllocated.length || !tlsAllocated[index]) return false;
    tlsAllocated[index] = false;
    for (const record of thread.values()) record.tls.delete(index);
    return true;
  }

  function createEvent(manualReset, initialState) {
    const handle = allocateHandle();
    objectTable.set(handle, { handle, kind: "event", manual_reset: manualReset === true, signaled: initialState === true });
    return handle;
  }
  function createMutex(initialOwner) {
    const handle = allocateHandle();
    objectTable.set(handle, { handle, kind: "mutex", owner: (initialOwner ?? 0) >>> 0, recursion: initialOwner ? 1 : 0, abandoned: false });
    return handle;
  }
  function createSemaphore(initialCount, maximumCount) {
    const handle = allocateHandle();
    objectTable.set(handle, { handle, kind: "semaphore", count: initialCount >>> 0, maximum: maximumCount >>> 0 });
    return handle;
  }
  function createCriticalSection() {
    const handle = allocateHandle();
    objectTable.set(handle, { handle, kind: "critical_section", owner: 0, recursion: 0 });
    return handle;
  }
  function createWaitableTimer(manualReset) {
    const handle = allocateHandle();
    objectTable.set(handle, { handle, kind: "timer", manual_reset: manualReset !== false, signaled: false, due: null, period: 0 });
    return handle;
  }

  // Is one waitable object signaled for this thread right now (no consume)?
  function isSignaled(objectValue, threadHandle) {
    if (objectValue.kind === "event" || objectValue.kind === "timer") return objectValue.signaled === true;
    if (objectValue.kind === "semaphore") return objectValue.count > 0;
    if (objectValue.kind === "mutex") return objectValue.owner === 0 || objectValue.owner === threadHandle || objectValue.abandoned;
    if (objectValue.kind === "critical_section") return objectValue.owner === 0 || objectValue.owner === threadHandle;
    if (objectValue.kind === "thread") return objectValue.signaled === true;
    return false;
  }

  // Consume the signaled state on a successful wait (auto-reset event, mutex
  // ownership, semaphore count). Returns whether the wait was abandoned.
  function consume(objectValue, threadHandle) {
    let abandoned = false;
    if (objectValue.kind === "event" && !objectValue.manual_reset) objectValue.signaled = false;
    else if (objectValue.kind === "timer" && !objectValue.manual_reset) objectValue.signaled = false;
    else if (objectValue.kind === "semaphore") objectValue.count -= 1;
    else if (objectValue.kind === "mutex") {
      if (objectValue.abandoned) { abandoned = true; objectValue.abandoned = false; }
      if (objectValue.owner === threadHandle) objectValue.recursion += 1;
      else { objectValue.owner = threadHandle; objectValue.recursion = 1; }
      thread.get(threadHandle)?.owned_mutex.add(objectValue.handle);
    } else if (objectValue.kind === "critical_section") {
      if (objectValue.owner === threadHandle) objectValue.recursion += 1;
      else { objectValue.owner = threadHandle; objectValue.recursion = 1; }
    }
    return abandoned;
  }

  function objectByHandle(handle, expectKind) {
    const objectValue = objectTable.get(handle);
    if (objectValue === undefined) throw new ThreadFault("invalid_handle", `No waitable object at handle 0x${(handle >>> 0).toString(16)}`, { handle });
    if (expectKind && objectValue.kind !== expectKind) throw new ThreadFault("handle_kind_mismatch", `Handle 0x${(handle >>> 0).toString(16)} is a ${objectValue.kind}, not a ${expectKind}`, { handle });
    return objectValue;
  }

  // Can this waiting thread's full wait be satisfied now? Returns null if not,
  // else the result code the wait returns (with the satisfied index for a
  // wait-any). Does not consume.
  function evaluateWait(record) {
    const wait = record.wait;
    const objectValue = wait.handle.map((handle) => objectByHandle(handle));
    if (wait.all) {
      if (objectValue.every((value) => isSignaled(value, record.handle))) return { code: waitResult.object_0, index: null };
      return null;
    }
    for (let index = 0; index < objectValue.length; index += 1) {
      if (isSignaled(objectValue[index], record.handle)) return { code: waitResult.object_0 + index, index };
    }
    return null;
  }

  function grantWait(record, evaluation) {
    const wait = record.wait;
    let abandoned = false;
    if (wait.all) {
      for (const handle of wait.handle) abandoned = consume(objectByHandle(handle), record.handle) || abandoned;
    } else {
      abandoned = consume(objectByHandle(wait.handle[evaluation.index]), record.handle);
    }
    const code = abandoned ? (wait.all ? waitResult.abandoned_0 : waitResult.abandoned_0 + evaluation.index) : evaluation.code;
    record.wait = null;
    record.deadline = null;
    record.pending_result = code >>> 0;
    markReady(record);
  }

  // After any state change, ready every waiting thread whose condition now
  // holds, in deterministic creation order, until a fixpoint. An auto-reset
  // event or a single semaphore count only satisfies one waiter, so the loop
  // repeats until nothing more can be granted.
  function retryWaiter() {
    let changed = true;
    while (changed) {
      changed = false;
      for (const handle of threadOrder) {
        const record = thread.get(handle);
        if (record === undefined || record.state !== threadState.waiting || record.wait === null) continue;
        const evaluation = evaluateWait(record);
        if (evaluation !== null) { grantWait(record, evaluation); changed = true; }
      }
    }
  }

  function pickReady() {
    let chosen = null;
    for (const handle of threadOrder) {
      const record = thread.get(handle);
      if (record === undefined || record.state !== threadState.ready) continue;
      if (chosen === null || record.priority > chosen.priority || (record.priority === chosen.priority && record.ready_sequence < chosen.ready_sequence)) {
        chosen = record;
      }
    }
    return chosen;
  }

  function blockOnWait(record, request) {
    record.state = threadState.waiting;
    record.wait = { handle: request.handle, all: request.all };
    record.deadline = request.timeout === INFINITE ? null : clockMs + request.timeout;
  }

  function interlockedApply(request) {
    const index = request.address;
    if (!Number.isInteger(index) || index < 0 || index >= sharedWordCount) {
      throw new ThreadFault("shared_address_out_of_range", `Interlocked address ${index} is outside the shared word space`, { address: index });
    }
    if (request.kind === "increment") return Atomics.add(sharedWord, index, 1) + 1;
    if (request.kind === "decrement") return Atomics.add(sharedWord, index, -1) - 1;
    if (request.kind === "add") return Atomics.add(sharedWord, index, request.value) + request.value;
    if (request.kind === "exchange") return Atomics.exchange(sharedWord, index, request.value);
    if (request.kind === "compare_exchange") return Atomics.compareExchange(sharedWord, index, request.comparand, request.value);
    if (request.kind === "load") return Atomics.load(sharedWord, index);
    throw new ThreadFault("interlocked_kind_unknown", `Unknown interlocked kind ${request.kind}`);
  }

  // Service exactly one request from the running thread, returning the trace
  // op label and result code so the caller records the event.
  function serviceRequest(record, request) {
    switch (request.op) {
      case "yield":
        record.pending_result = 0;
        markReady(record);
        return ["yield", 0];
      case "current_thread_id":
        record.pending_result = record.handle;
        markReady(record);
        return ["current_thread_id", record.handle];
      case "get_register":
        record.pending_result = record.register[request.index] >>> 0;
        markReady(record);
        return ["get_register", record.register[request.index] >>> 0];
      case "set_register":
        record.register[request.index] = request.value >>> 0;
        record.pending_result = 0;
        markReady(record);
        return ["set_register", 0];
      case "tls_alloc": {
        const index = allocateTlsIndex();
        record.pending_result = index >>> 0;
        markReady(record);
        return ["tls_alloc", index >>> 0];
      }
      case "tls_free": {
        const ok = freeTlsIndex(request.index);
        record.pending_result = ok ? 1 : 0;
        markReady(record);
        return ["tls_free", ok ? 1 : 0];
      }
      case "tls_get": {
        const value = record.tls.get(request.index) ?? 0;
        record.pending_result = value >>> 0;
        markReady(record);
        return ["tls_get", value >>> 0];
      }
      case "tls_set": {
        if (request.index < 0 || request.index >= tlsAllocated.length || !tlsAllocated[request.index]) {
          record.pending_result = 0;
          markReady(record);
          return ["tls_set", 0];
        }
        record.tls.set(request.index, request.value >>> 0);
        record.pending_result = 1;
        markReady(record);
        return ["tls_set", 1];
      }
      case "lock":
      case "try_lock": {
        const objectValue = objectByHandle(request.handle, "critical_section");
        if (objectValue.owner === 0 || objectValue.owner === record.handle) {
          consume(objectValue, record.handle);
          record.pending_result = 1;
          markReady(record);
          return [request.op, 1];
        }
        if (request.op === "try_lock") {
          record.pending_result = 0;
          markReady(record);
          return ["try_lock", 0];
        }
        blockOnWait(record, { handle: [request.handle], all: false, timeout: INFINITE });
        return ["lock", waitResult.object_0];
      }
      case "unlock": {
        const objectValue = objectByHandle(request.handle, "critical_section");
        if (objectValue.owner !== record.handle) throw new ThreadFault("critical_section_not_held", `Critical section 0x${request.handle.toString(16)} is not held by thread 0x${record.handle.toString(16)}`);
        objectValue.recursion -= 1;
        if (objectValue.recursion === 0) objectValue.owner = 0;
        record.pending_result = 0;
        markReady(record);
        retryWaiter();
        return ["unlock", 0];
      }
      case "set_event": {
        const objectValue = objectByHandle(request.handle, "event");
        objectValue.signaled = true;
        record.pending_result = 1;
        markReady(record);
        retryWaiter();
        return ["set_event", 1];
      }
      case "reset_event": {
        const objectValue = objectByHandle(request.handle, "event");
        objectValue.signaled = false;
        record.pending_result = 1;
        markReady(record);
        return ["reset_event", 1];
      }
      case "release_mutex": {
        const objectValue = objectByHandle(request.handle, "mutex");
        if (objectValue.owner !== record.handle) throw new ThreadFault("mutex_not_owned", `Mutex 0x${request.handle.toString(16)} is not owned by thread 0x${record.handle.toString(16)}`);
        objectValue.recursion -= 1;
        if (objectValue.recursion === 0) { objectValue.owner = 0; record.owned_mutex.delete(objectValue.handle); }
        record.pending_result = 1;
        markReady(record);
        retryWaiter();
        return ["release_mutex", 1];
      }
      case "release_semaphore": {
        const objectValue = objectByHandle(request.handle, "semaphore");
        const previous = objectValue.count;
        objectValue.count = Math.min(objectValue.maximum, objectValue.count + request.count);
        record.pending_result = previous >>> 0;
        markReady(record);
        retryWaiter();
        return ["release_semaphore", previous >>> 0];
      }
      case "set_timer": {
        const objectValue = objectByHandle(request.handle, "timer");
        objectValue.signaled = false;
        objectValue.due = clockMs + request.dueMs;
        objectValue.period = request.periodMs;
        record.pending_result = 1;
        markReady(record);
        return ["set_timer", 1];
      }
      case "cancel_timer": {
        const objectValue = objectByHandle(request.handle, "timer");
        objectValue.due = null;
        record.pending_result = 1;
        markReady(record);
        return ["cancel_timer", 1];
      }
      case "wait": {
        blockOnWait(record, request);
        const evaluation = evaluateWait(record);
        if (evaluation !== null) { grantWait(record, evaluation); return ["wait", record.pending_result]; }
        return ["wait", 0];
      }
      case "sleep": {
        if (request.ms === 0) { record.pending_result = 0; markReady(record); return ["sleep", 0]; }
        record.state = threadState.waiting;
        record.wait = null;
        record.deadline = clockMs + request.ms;
        return ["sleep", 0];
      }
      case "interlocked": {
        const value = interlockedApply(request) | 0;
        record.pending_result = value >>> 0;
        markReady(record);
        return ["interlocked", value >>> 0];
      }
      case "atomic_wait": {
        const current = Atomics.load(sharedWord, request.address);
        if (current !== request.expected) { record.pending_result = 1; markReady(record); return ["atomic_wait", 1]; } // not-equal
        record.state = threadState.waiting;
        record.wait = null;
        record.deadline = request.timeout === INFINITE ? null : clockMs + request.timeout;
        record.futex_address = request.address;
        if (!futexWaiter.has(request.address)) futexWaiter.set(request.address, []);
        futexWaiter.get(request.address).push(record.handle);
        return ["atomic_wait", 0];
      }
      case "atomic_notify": {
        const list = futexWaiter.get(request.address) ?? [];
        let woken = 0;
        while (woken < request.count && list.length > 0) {
          const handle = list.shift();
          const target = thread.get(handle);
          if (target && target.state === threadState.waiting && target.futex_address === request.address) {
            target.futex_address = null;
            target.deadline = null;
            target.pending_result = 0; // woken
            markReady(target);
            woken += 1;
          }
        }
        record.pending_result = woken >>> 0;
        markReady(record);
        return ["atomic_notify", woken >>> 0];
      }
      case "suspend": {
        const target = thread.get(request.handle);
        if (target === undefined) throw new ThreadFault("invalid_handle", `No thread at handle 0x${request.handle.toString(16)}`);
        const previous = target.suspend_count;
        target.suspend_count += 1;
        if (target.state === threadState.ready) target.state = threadState.suspended;
        record.pending_result = previous >>> 0;
        markReady(record);
        return ["suspend", previous >>> 0];
      }
      case "resume": {
        const target = thread.get(request.handle);
        if (target === undefined) throw new ThreadFault("invalid_handle", `No thread at handle 0x${request.handle.toString(16)}`);
        const previous = target.suspend_count;
        if (target.suspend_count > 0) target.suspend_count -= 1;
        if (target.suspend_count === 0 && target.state === threadState.suspended) markReady(target);
        record.pending_result = previous >>> 0;
        markReady(record);
        return ["resume", previous >>> 0];
      }
      case "send": {
        const target = thread.get(request.handle);
        if (target === undefined) throw new ThreadFault("invalid_handle", `No thread at handle 0x${request.handle.toString(16)}`);
        target.message_queue.push(request.message >>> 0);
        record.pending_result = 1;
        markReady(record);
        if (target.state === threadState.waiting && target.wait === null && target.receive_pending === true) {
          target.receive_pending = false;
          target.deadline = null;
          target.pending_result = target.message_queue.shift() >>> 0;
          markReady(target);
        }
        return ["send", 1];
      }
      case "receive": {
        if (record.message_queue.length > 0) {
          record.pending_result = record.message_queue.shift() >>> 0;
          markReady(record);
          return ["receive", record.pending_result];
        }
        record.state = threadState.waiting;
        record.wait = null;
        record.receive_pending = true;
        record.deadline = request.timeout === INFINITE ? null : clockMs + request.timeout;
        return ["receive", 0];
      }
      case "exit":
        return ["exit", request.code >>> 0];
      default:
        throw new ThreadFault("thread_op_unknown", `Unknown thread request ${request.op}`);
    }
  }

  function terminate(record, code) {
    record.state = threadState.terminated;
    record.exit_code = code >>> 0;
    record.signaled = true; // the thread object now satisfies a join wait
    // A mutex still held at exit is abandoned; the next waiter is told so.
    for (const mutexHandle of record.owned_mutex) {
      const objectValue = objectTable.get(mutexHandle);
      if (objectValue && objectValue.owner === record.handle) { objectValue.owner = 0; objectValue.recursion = 0; objectValue.abandoned = true; }
    }
    record.owned_mutex.clear();
    // Threads join on a thread handle through the object table.
    if (!objectTable.has(record.handle)) objectTable.set(record.handle, record);
    retryWaiter();
  }

  // No thread is ready: advance the clock to the nearest deadline and fire the
  // timeouts and timers there. Returns whether the clock made progress.
  function advanceClock() {
    let nearest = null;
    for (const record of thread.values()) {
      if (record.state === threadState.waiting && record.deadline !== null) nearest = nearest === null ? record.deadline : Math.min(nearest, record.deadline);
    }
    for (const objectValue of objectTable.values()) {
      if (objectValue.kind === "timer" && objectValue.due !== null && !objectValue.signaled) nearest = nearest === null ? objectValue.due : Math.min(nearest, objectValue.due);
    }
    if (nearest === null) return false;
    clockMs = nearest;
    // Fire every timer due at this instant.
    for (const objectValue of objectTable.values()) {
      if (objectValue.kind === "timer" && objectValue.due !== null && objectValue.due <= clockMs && !objectValue.signaled) {
        objectValue.signaled = true;
        objectValue.due = objectValue.period > 0 ? clockMs + objectValue.period : null;
      }
    }
    // Fire every wait/sleep/receive/futex timeout due at this instant.
    for (const handle of threadOrder) {
      const record = thread.get(handle);
      if (record === undefined || record.state !== threadState.waiting || record.deadline === null || record.deadline > clockMs) continue;
      if (record.wait !== null) { record.wait = null; record.pending_result = waitResult.timeout; }
      else if (record.receive_pending === true) { record.receive_pending = false; record.pending_result = waitResult.timeout; }
      else if (record.futex_address !== null && record.futex_address !== undefined) {
        const list = futexWaiter.get(record.futex_address);
        if (list) { const at = list.indexOf(record.handle); if (at >= 0) list.splice(at, 1); }
        record.futex_address = null;
        record.pending_result = 2; // timed-out
      } else record.pending_result = 0; // a sleep expiry returns 0
      record.deadline = null;
      markReady(record);
    }
    retryWaiter();
    return true;
  }

  function anyLive() {
    for (const record of thread.values()) if (record.state !== threadState.terminated) return true;
    return false;
  }

  function run(runOption = {}) {
    const budget = runOption.step_budget ?? 1_000_000;
    let step = 0;
    stopReason = null;
    while (anyLive()) {
      if (step >= budget) { stopReason = "step_budget_exhausted"; break; }
      const record = pickReady();
      if (record === null) {
        if (!advanceClock()) {
          // Nothing ready and no deadline to advance to: either every live
          // thread is blocked on another (deadlock) or all are suspended.
          const suspendedOnly = [...thread.values()].every((value) => value.state === threadState.terminated || value.state === threadState.suspended);
          stopReason = suspendedOnly ? "all_thread_suspended" : "deadlock";
          break;
        }
        continue;
      }
      step += 1;
      if (record.iterator === null) record.iterator = record.program({ thread_id: record.handle, parameter: record.parameter, scheduler_now: () => clockMs });
      let next;
      try {
        next = record.iterator.next(record.pending_result);
      } catch (error) {
        throw error instanceof ThreadFault ? error : new ThreadFault("thread_program_fault", error instanceof Error ? error.message : String(error), { thread_id: record.handle });
      }
      record.pending_result = undefined;
      if (next.done) { recordEvent(record.handle, "return", record.exit_code); terminate(record, next.value >>> 0 || 0); continue; }
      const request = next.value;
      const [label, resultCode] = serviceRequest(record, request);
      recordEvent(record.handle, label, resultCode);
      if (request.op === "exit") terminate(record, request.code);
    }
    return summarize(step);
  }

  function summarize(step) {
    return {
      stopped: stopReason,
      step_count: step,
      event_count: event.length,
      clock_ms: clockMs,
      trace_sha256: traceHash.copy().digest("hex"),
      thread: threadOrder.map((handle) => {
        const record = thread.get(handle);
        return { handle, state: record.state, exit_code: record.exit_code, priority: record.priority };
      }),
    };
  }

  return {
    createThread,
    createEvent,
    createMutex,
    createSemaphore,
    createCriticalSection,
    createWaitableTimer,
    allocateTlsIndex,
    freeTlsIndex,
    run,
    sharedWord,
    now: () => clockMs,
    threadRecord: (handle) => thread.get(handle) ?? null,
    objectRecord: (handle) => objectTable.get(handle) ?? null,
    INFINITE,
  };
}

// Guest SMP determinism harness (BPTK-051 / GS-006). The deterministic
// cooperative scheduler above is the reproducible model of a worker pool over a
// shared address space: this fixture runs N workers that contend on an
// interlocked counter and a critical-section-guarded counter, and hands a token
// around an auto-reset event so every wakeup is accounted for. Guest-visible
// state (the two counters) is deterministic across repeated runs and across
// worker counts, and no wakeup is lost. The production target is a real
// SharedArrayBuffer-backed Worker pool; that cross-core deployment is not what
// runs here, so the benchmark stays honestly red on the deployment leg while
// the determinism and no-lost-wakeup invariants are proven.
export function runContentionFixture(option = {}) {
  const workerCount = Number.isSafeInteger(option.worker_count) && option.worker_count > 0 ? option.worker_count : 4;
  const totalIncrement = Number.isSafeInteger(option.total_increment) && option.total_increment > 0 ? option.total_increment : 240;
  const perWorker = Math.max(1, Math.floor(totalIncrement / workerCount));
  const effectiveTotal = perWorker * workerCount;

  const scheduler = createThreadScheduler();
  const lock = scheduler.createCriticalSection();
  const gate = scheduler.createEvent(false, false); // auto-reset, initially unset
  let wokenCount = 0;

  // Contention workers: interlocked increment on word 0, and a lock-guarded
  // read-modify-write on word 1 with an interleave that would lose an update
  // without the lock.
  for (let index = 0; index < workerCount; index += 1) {
    scheduler.createThread({ program: function* () {
      for (let step = 0; step < perWorker; step += 1) {
        yield threadOp.interlocked("increment", 0);
        yield threadOp.lock(lock);
        const current = yield threadOp.interlocked("load", 1);
        yield threadOp.yieldQuantum();
        yield threadOp.interlocked("exchange", 1, current + 1);
        yield threadOp.unlock(lock);
      }
      return 0;
    } });
  }

  // Wakeup accounting: one consumer per worker waits once on the auto-reset
  // event; a producer sets it exactly workerCount times. No set may be lost.
  for (let index = 0; index < workerCount; index += 1) {
    scheduler.createThread({ program: function* () {
      const code = yield threadOp.wait(gate);
      if (code === waitResult.object_0) wokenCount += 1;
      return 0;
    } });
  }
  scheduler.createThread({ program: function* () {
    for (let index = 0; index < workerCount; index += 1) { yield threadOp.setEvent(gate); yield threadOp.yieldQuantum(); }
    return 0;
  } });

  const report = scheduler.run();
  const interlockedTotal = scheduler.sharedWord[0] >>> 0;
  const guardedTotal = scheduler.sharedWord[1] >>> 0;
  // The guest-visible state is the two shared counters; it must be identical
  // across worker counts. The wakeup tally is accounted separately.
  const stateDigest = createHash("sha256");
  const buffer = Buffer.alloc(8);
  buffer.writeUInt32LE(interlockedTotal, 0);
  buffer.writeUInt32LE(guardedTotal, 4);
  stateDigest.update(buffer);

  return {
    schema_version: 1,
    command: "thread --profile contention",
    worker_count: workerCount,
    per_worker_increment: perWorker,
    expected_total: effectiveTotal,
    interlocked_total: interlockedTotal,
    guarded_total: guardedTotal,
    is_consistent: interlockedTotal === effectiveTotal && guardedTotal === effectiveTotal,
    lost_wakeup_count: workerCount - wokenCount,
    is_deadlocked: report.stopped !== null,
    schedule_sha256: report.trace_sha256,
    state_sha256: stateDigest.digest("hex"),
    is_worker_backed: false,
    blocker: [
      "The reproducible schedule is a deterministic cooperative model; a real SharedArrayBuffer-backed Worker pool (true cross-core parallelism) is not deployed here",
    ],
  };
}
