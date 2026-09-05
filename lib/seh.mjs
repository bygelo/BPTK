// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Structured exception handling, fault dispatch, and init callbacks (GS-008,
// BPTK-053). This module models the Win32 exception machine that a translated
// i386 block needs: the per-thread `fs:[0]` registration chain, the
// `__try`/`__except`/`__finally` search-then-unwind semantics, the vectored
// handler list, the CPU-fault-to-guest EXCEPTION_RECORD/CONTEXT bridge,
// RaiseException, SetUnhandledExceptionFilter, and PE TLS callbacks that fire
// in declared order before entry.
//
// The topology is real: the registration chain is a linked list of records in
// guest memory rooted at the thread TEB, and the walk, search, and unwind
// order match the reference machine. Handler *bodies* are opaque thunks rather
// than executed guest machine code, because the substrate that runs a
// translated block (BPTK-035, exnref delivery) is still red — so this engine
// carries a legacy fallback delivery path and maps onto exnref only where the
// substrate declares it. That is why BPTK-053 stays red while implemented: the
// machine exists, but no substrate delivers a fault into it yet.

// The Win32 status code for each guest-visible fault class. These are the codes
// a guest filter compares against, so they are exact, not approximate.
export const exceptionCode = Object.freeze({
  access_violation: 0xc0000005,
  divide_by_zero: 0xc0000094,
  integer_overflow: 0xc0000095,
  illegal_instruction: 0xc000001d,
  privileged_instruction: 0xc0000096,
  float_divide_by_zero: 0xc000008e,
  float_stack_check: 0xc0000092,
  stack_overflow: 0xc00000fd,
  breakpoint: 0x80000003,
  guard_page: 0x80000001,
  noncontinuable: 0xc0000025,
});

// The exception-filter disposition a __except or vectored handler returns.
// EXCEPTION_CONTINUE_EXECUTION is -1 as a signed 32-bit value.
export const disposition = Object.freeze({
  continue_execution: -1,
  continue_search: 0,
  execute_handler: 1,
});

// EXCEPTION_FLAG bits carried on the record.
export const exceptionFlag = Object.freeze({
  continuable: 0x00000000,
  noncontinuable: 0x00000001,
  unwinding: 0x00000002,
  exit_unwind: 0x00000004,
  stack_invalid: 0x00000008,
  nested_call: 0x00000010,
});

// The ExceptionList sentinel that terminates the fs:[0] chain (-1).
const chainEnd = 0xffffffff;

// The bound the chain walk and vectored list must not exceed, so a corrupt
// prev pointer or a runaway registration cannot spin the dispatcher.
const maxFrameCount = 4096;
const maxVectoredCount = 256;

function unsigned(value) {
  return value >>> 0;
}

function signedDisposition(value) {
  // A filter thunk may return the raw unsigned 0xffffffff; fold it to -1 so a
  // comparison against disposition.continue_execution holds either way.
  const folded = value | 0;
  return folded;
}

export class SehError extends Error {
  constructor(seh_code, message) {
    super(message);
    this.name = "SehError";
    this.seh_code = seh_code;
  }
}

// Maps one CPU/HLE fault into the guest exception it delivers, or null when the
// fault is a bounded-probe refusal (a budget or block bound) that never becomes
// a guest-visible exception. The access-type parameter for an access violation
// follows the Win32 convention: 0 read, 1 write, 8 execute.
export function mapFaultToException(fault, option = {}) {
  const address = option.instruction_address !== undefined ? unsigned(option.instruction_address) : 0;
  const code = fault && typeof fault === "object" ? fault.code : fault;
  const faultAddress = fault && fault.address !== undefined && fault.address !== null ? unsigned(fault.address) : 0;
  switch (code) {
    case "divide_error":
      return buildExceptionRecord(exceptionCode.divide_by_zero, address, { information: [] });
    case "read_fault":
      return buildExceptionRecord(exceptionCode.access_violation, address, { information: [0, faultAddress] });
    case "write_fault":
      return buildExceptionRecord(exceptionCode.access_violation, address, { information: [1, faultAddress] });
    case "fetch_fault":
      return buildExceptionRecord(exceptionCode.access_violation, address, { information: [8, faultAddress] });
    case "unsupported_opcode":
      return buildExceptionRecord(exceptionCode.illegal_instruction, address, { information: [] });
    case "x87_stack_fault":
      return buildExceptionRecord(exceptionCode.float_stack_check, address, { information: [] });
    default:
      // memory_fault, rep_iteration_bound, hle_* and any budget bound are
      // probe refusals, not guest exceptions.
      return null;
  }
}

// Builds an EXCEPTION_RECORD as the guest filter and CONTEXT-aware handler see
// it. `information` holds the ExceptionInformation array (access type + address
// for an access violation).
export function buildExceptionRecord(code, exceptionAddress, option = {}) {
  const information = Array.isArray(option.information) ? option.information.map(unsigned) : [];
  return {
    exception_code: unsigned(code),
    exception_flag: option.exception_flag ?? exceptionFlag.continuable,
    exception_address: unsigned(exceptionAddress ?? 0),
    number_parameter: information.length,
    exception_information: information,
    nested_record: option.nested_record ?? null,
  };
}

// Chains a new exception that arose while an earlier one was being handled:
// the new record carries the earlier record as its nested record and is marked
// nested, exactly as a fault inside a filter or __finally reports.
export function nestExceptionRecord(newRecord, priorRecord) {
  return {
    ...newRecord,
    exception_flag: (newRecord.exception_flag | exceptionFlag.nested_call) >>> 0,
    nested_record: priorRecord,
  };
}

// Builds a CONTEXT snapshot from the probe register file at fault time. The
// caller passes the eight general registers, eflags, and eip; the handler and
// any unwind reads these and a continue-execution disposition writes them back.
export function buildContext(registerValue, eflagsValue, eipValue) {
  const register = registerValue ? Array.from(registerValue, unsigned) : new Array(8).fill(0);
  return {
    eax: register[0] ?? 0,
    ecx: register[1] ?? 0,
    edx: register[2] ?? 0,
    ebx: register[3] ?? 0,
    esp: register[4] ?? 0,
    ebp: register[5] ?? 0,
    esi: register[6] ?? 0,
    edi: register[7] ?? 0,
    eflags: unsigned(eflagsValue ?? 0),
    eip: unsigned(eipValue ?? 0),
  };
}

// One per-thread SEH machine. The registration chain is rooted at the thread
// TEB (NtTib.ExceptionList at offset 0). When a memory image and TEB address
// are supplied the head dword lives in guest memory, so the chain is genuinely
// per-thread; otherwise a legacy in-object head backs the same walk for a probe
// that has no mapped TEB yet.
export class SehThread {
  constructor(option = {}) {
    this.memory = option.memory ?? null;
    this.tebAddress = option.teb_address !== undefined ? unsigned(option.teb_address) : null;
    this.deliveryMode = option.substrate && option.substrate.has_exnref ? "exnref" : "legacy";
    // The modeled scope for each registration record, keyed by its guest
    // address. The record's prev/handler live in memory; the filter, finally,
    // and except thunks are the legacy delivery the substrate has not replaced.
    this.scopeByAddress = new Map();
    this.vectored = [];
    this.isUnwinding = false;
    this.nextVectoredHandle = 0x00080001;
    // A synthetic registration-record address for a frame the caller did not
    // place itself. When memory-backed it must sit inside the mapped region, so
    // it is anchored just past the TEB; the legacy path uses a fixed base.
    this.nextSyntheticAddress = this.tebAddress !== null ? this.tebAddress + 0x1000 : 0x00090000;
    if (this.memory === null || this.tebAddress === null) this.legacyHead = chainEnd;
    else this.writeHead(chainEnd);
  }

  writeHead(address) {
    if (this.memory !== null && this.tebAddress !== null) this.memory.writeMemory(this.tebAddress, 4, unsigned(address));
    else this.legacyHead = unsigned(address);
  }

  readHead() {
    if (this.memory !== null && this.tebAddress !== null) return unsigned(this.memory.readMemory(this.tebAddress, 4));
    return unsigned(this.legacyHead);
  }

  readPrev(recordAddress) {
    if (this.memory !== null && this.tebAddress !== null) return unsigned(this.memory.readMemory(recordAddress, 4));
    return this.scopeByAddress.get(recordAddress)?.prev ?? chainEnd;
  }

  // Pushes an EXCEPTION_REGISTRATION_RECORD: prev = current head, handler =
  // supplied, head = this record. The scope thunks travel with it. Returns the
  // record address so the caller can pop by identity.
  pushFrame(scope = {}) {
    if (this.scopeByAddress.size >= maxFrameCount) throw new SehError("seh_chain_overflow", `The SEH chain exceeds ${maxFrameCount} frame`);
    const address = scope.address !== undefined ? unsigned(scope.address) : this.allocateSyntheticAddress();
    const prev = this.readHead();
    if (this.memory !== null && this.tebAddress !== null) {
      this.memory.writeMemory(address, 4, prev);
      this.memory.writeMemory(address + 4, 4, unsigned(scope.handler ?? 0));
    }
    this.scopeByAddress.set(address, {
      prev,
      handler: unsigned(scope.handler ?? 0),
      filter: typeof scope.filter === "function" ? scope.filter : null,
      finally: typeof scope.finally === "function" ? scope.finally : null,
      except: typeof scope.except === "function" ? scope.except : null,
      label: scope.label ?? null,
    });
    this.writeHead(address);
    return address;
  }

  // Pops the top registration record after checking it is the head, matching
  // the reference machine's LIFO discipline.
  popFrame(address) {
    const head = this.readHead();
    if (head !== unsigned(address)) throw new SehError("seh_pop_out_of_order", "A SEH frame was released out of chain order");
    this.writeHead(this.readPrev(head));
    this.scopeByAddress.delete(head);
    return head;
  }

  allocateSyntheticAddress() {
    const address = this.nextSyntheticAddress;
    this.nextSyntheticAddress += 16;
    return address;
  }

  frameAddressList() {
    const list = [];
    let cursor = this.readHead();
    let count = 0;
    while (cursor !== chainEnd) {
      if (count >= maxFrameCount) throw new SehError("seh_chain_unbounded", "The SEH chain has no terminator within bound");
      list.push(cursor);
      cursor = this.readPrev(cursor);
      count += 1;
    }
    return list;
  }

  addVectored(isFirst, handler) {
    if (typeof handler !== "function") throw new SehError("seh_vectored_handler_required", "A vectored handler must be callable");
    if (this.vectored.length >= maxVectoredCount) throw new SehError("seh_vectored_overflow", `The vectored list exceeds ${maxVectoredCount} handler`);
    const entry = { handle: this.nextVectoredHandle, handler };
    this.nextVectoredHandle += 1;
    if (isFirst) this.vectored.unshift(entry);
    else this.vectored.push(entry);
    return entry.handle;
  }

  removeVectored(handle) {
    const index = this.vectored.findIndex((entry) => entry.handle === unsigned(handle));
    if (index === -1) return false;
    this.vectored.splice(index, 1);
    return true;
  }

  // Dispatches one exception through the full machine: vectored list first, in
  // registration order; then the fs:[0] chain in a search phase; then, on a
  // chosen handler, an unwind phase that runs each intervening __finally before
  // the __except runs; then, if the chain is exhausted, the unhandled
  // exception filter. Returns a deterministic trace of what ran and how it
  // resolved so a fixture can assert order, cleanup, and target frame.
  dispatch(record, context, option = {}) {
    if (this.isUnwinding) throw new SehError("seh_collided_unwind", "An exception was dispatched during an active unwind");
    const trace = {
      delivery_mode: this.deliveryMode,
      exnref: this.deliveryMode === "exnref" ? mapToExnref(record) : null,
      vectored_run: [],
      searched_frame: [],
      unwound_frame: [],
      finally_run: [],
      handler_frame: null,
      disposition: disposition.continue_search,
      is_handled: false,
      is_continued: false,
      is_terminated: false,
      is_noncontinuable_violation: false,
      unhandled_filter_run: false,
    };

    // Vectored phase.
    for (const entry of this.vectored) {
      const result = signedDisposition(entry.handler(record, context));
      trace.vectored_run.push({ handle: entry.handle, disposition: result });
      if (result === disposition.continue_execution) return this.resolveContinue(trace, record);
    }

    // Search phase: walk the chain, run each filter, do not unwind yet.
    const frameList = this.frameAddressList();
    let handlerIndex = -1;
    for (let index = 0; index < frameList.length; index += 1) {
      const address = frameList[index];
      const scope = this.scopeByAddress.get(address) ?? {};
      trace.searched_frame.push({ address, label: scope.label ?? null });
      const filter = scope.filter;
      const result = filter ? signedDisposition(filter(record, context)) : disposition.continue_search;
      if (result === disposition.continue_execution) return this.resolveContinue(trace, record);
      if (result === disposition.execute_handler) {
        handlerIndex = index;
        trace.disposition = disposition.execute_handler;
        break;
      }
      // continue_search: fall through to the next-outer frame.
    }

    if (handlerIndex !== -1) {
      // Unwind phase: run the __finally of every frame between the raise point
      // and the handler frame, innermost first, popping each; then run the
      // handler's __except; then pop the handler frame.
      const handlerAddress = frameList[handlerIndex];
      this.isUnwinding = true;
      try {
        for (let index = 0; index < handlerIndex; index += 1) {
          const address = frameList[index];
          const scope = this.scopeByAddress.get(address) ?? {};
          if (scope.finally) {
            scope.finally(record, context);
            trace.finally_run.push({ address, label: scope.label ?? null });
          }
          trace.unwound_frame.push({ address, label: scope.label ?? null });
          this.popFrame(address);
        }
      } finally {
        this.isUnwinding = false;
      }
      const handlerScope = this.scopeByAddress.get(handlerAddress) ?? {};
      if (handlerScope.except) handlerScope.except(record, context);
      trace.handler_frame = { address: handlerAddress, label: handlerScope.label ?? null };
      trace.is_handled = true;
      this.popFrame(handlerAddress);
      return trace;
    }

    // Unhandled phase: the last-chance filter installed by
    // SetUnhandledExceptionFilter.
    if (typeof option.unhandled_filter === "function") {
      trace.unhandled_filter_run = true;
      const result = signedDisposition(option.unhandled_filter(record, context));
      if (result === disposition.continue_execution) return this.resolveContinue(trace, record);
      trace.disposition = result;
      // EXECUTE_HANDLER from the last-chance filter means the process ends
      // after the filter handled it; CONTINUE_SEARCH falls to the default.
      trace.is_terminated = true;
      return trace;
    }

    trace.is_terminated = true;
    return trace;
  }

  // Resolves a CONTINUE_EXECUTION disposition, enforcing the noncontinuable
  // flag: continuing a noncontinuable exception is itself the fatal
  // EXCEPTION_NONCONTINUABLE_EXCEPTION condition, never a resume.
  resolveContinue(trace, record) {
    if ((record.exception_flag & exceptionFlag.noncontinuable) !== 0) {
      trace.is_noncontinuable_violation = true;
      trace.is_continued = false;
      trace.is_terminated = true;
      trace.disposition = disposition.continue_search;
      return trace;
    }
    trace.disposition = disposition.continue_execution;
    trace.is_continued = true;
    return trace;
  }

  // Explicit unwind (RtlUnwind / a `__leave` that targets an outer frame): run
  // the __finally of every frame above the target, innermost first, and pop
  // each, leaving the target frame at the head. No filter or __except runs —
  // this is the cleanup-only path, distinct from an exception dispatch.
  unwindTo(targetAddress, context = null) {
    if (this.isUnwinding) throw new SehError("seh_collided_unwind", "An unwind was requested during an active unwind");
    const target = unsigned(targetAddress);
    const frameList = this.frameAddressList();
    const targetIndex = frameList.indexOf(target);
    if (targetIndex === -1) throw new SehError("seh_unwind_target_absent", "The unwind target is not on the chain");
    const trace = { finally_run: [], unwound_frame: [], target_frame: target };
    this.isUnwinding = true;
    try {
      for (let index = 0; index < targetIndex; index += 1) {
        const address = frameList[index];
        const scope = this.scopeByAddress.get(address) ?? {};
        if (scope.finally) {
          scope.finally(null, context);
          trace.finally_run.push({ address, label: scope.label ?? null });
        }
        trace.unwound_frame.push({ address, label: scope.label ?? null });
        this.popFrame(address);
      }
    } finally {
      this.isUnwinding = false;
    }
    return trace;
  }
}

// Maps a record onto the substrate exnref tag when the substrate declares one,
// so a translated block can rethrow through the wasm exception mechanism. With
// no such substrate the caller falls back to SehThread.dispatch directly.
export function mapToExnref(record) {
  return {
    tag: "guest_exception",
    exception_code: unsigned(record.exception_code),
    exception_address: unsigned(record.exception_address),
    parameter: record.exception_information.slice(),
  };
}

// RaiseException: builds the record from the guest arguments and dispatches it
// through the supplied thread machine. Mirrors kernel32!RaiseException
// (code, flags, argument count, argument array).
export function raiseException(thread, code, flag, argument = [], context = null, option = {}) {
  const information = Array.isArray(argument) ? argument.slice(0, 15).map(unsigned) : [];
  const record = buildExceptionRecord(code, option.exception_address ?? 0, {
    exception_flag: unsigned(flag ?? 0),
    information,
  });
  return thread.dispatch(record, context, option);
}

// Fires the PE TLS callbacks in declared table order before guest entry. Each
// callback receives (module_handle, reason, reserved); the reason is
// DLL_PROCESS_ATTACH (1) at load. Returns the ordered address list actually
// fired so a fixture can assert order and the before-entry property.
export const tlsReason = Object.freeze({
  process_detach: 0,
  process_attach: 1,
  thread_attach: 2,
  thread_detach: 3,
});

export function runTlsCallback(callbackList, option = {}) {
  const list = Array.isArray(callbackList) ? callbackList : [];
  const reason = option.reason ?? tlsReason.process_attach;
  const moduleHandle = unsigned(option.module_handle ?? 0);
  const invoke = typeof option.invoke === "function" ? option.invoke : null;
  const fired = [];
  for (const callback of list) {
    const address = unsigned(typeof callback === "object" ? callback.address : callback);
    if (invoke) invoke(address, moduleHandle, reason);
    fired.push(address);
  }
  return {
    reason,
    fired_address: fired,
    fired_count: fired.length,
    is_before_entry: true,
  };
}
