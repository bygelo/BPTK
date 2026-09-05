// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  SehThread,
  buildContext,
  buildExceptionRecord,
  disposition,
  exceptionCode,
  exceptionFlag,
  mapFaultToException,
  mapToExnref,
  nestExceptionRecord,
  raiseException,
  runTlsCallback,
  tlsReason,
} from "../lib/seh.mjs";

// A minimal flat guest memory that reads and writes little-endian dword so the
// fs:[0] chain lives in real memory, exactly as a mapped TEB would carry it.
function createMemory(sizeByte = 0x00100000, base = 0x00200000) {
  const buffer = Buffer.alloc(sizeByte);
  const offsetOf = (address) => address - base;
  return {
    base,
    readMemory(address, size) {
      const offset = offsetOf(address);
      if (size === 1) return buffer.readUInt8(offset);
      if (size === 2) return buffer.readUInt16LE(offset);
      return buffer.readUInt32LE(offset);
    },
    writeMemory(address, size, value) {
      const offset = offsetOf(address);
      if (size === 1) buffer.writeUInt8(value & 0xff, offset);
      else if (size === 2) buffer.writeUInt16LE(value & 0xffff, offset);
      else buffer.writeUInt32LE(value >>> 0, offset);
    },
  };
}

test("a CPU access violation and a divide error map to the exact guest exception code", () => {
  const av = mapFaultToException({ code: "write_fault", address: 0xdeadbeef }, { instruction_address: 0x00401000 });
  assert.equal(av.exception_code, exceptionCode.access_violation);
  assert.equal(av.exception_address, 0x00401000);
  assert.deepEqual(av.exception_information, [1, 0xdeadbeef]);

  const de = mapFaultToException({ code: "divide_error" }, { instruction_address: 0x00401010 });
  assert.equal(de.exception_code, exceptionCode.divide_by_zero);

  const ud = mapFaultToException({ code: "unsupported_opcode" }, { instruction_address: 0x00401020 });
  assert.equal(ud.exception_code, exceptionCode.illegal_instruction);

  // A bounded-probe refusal is not a guest exception.
  assert.equal(mapFaultToException({ code: "rep_iteration_bound" }), null);
});

test("a fixture catches an access violation, runs __finally, and unwinds to the correct frame", () => {
  const memory = createMemory();
  const tebAddress = 0x00200000;
  const thread = new SehThread({ memory, teb_address: tebAddress });
  const order = [];

  // Outer __try/__except that accepts the access violation.
  const outer = thread.pushFrame({
    label: "outer",
    handler: 0x00401100,
    filter: (record) => (record.exception_code === exceptionCode.access_violation ? disposition.execute_handler : disposition.continue_search),
    except: () => order.push("outer_except"),
  });
  // Inner __try/__finally that must clean up as the unwind passes through it.
  const inner = thread.pushFrame({
    label: "inner",
    handler: 0x00401200,
    filter: () => disposition.continue_search,
    finally: () => order.push("inner_finally"),
  });

  // The chain head is the inner frame, in real memory.
  assert.equal(thread.readHead(), inner);

  const record = mapFaultToException({ code: "read_fault", address: 0x00000000 }, { instruction_address: 0x00401234 });
  const context = buildContext([1, 2, 3, 4, 0x0018ff00, 0x0018ff40, 5, 6], 0x202, 0x00401234);
  const trace = thread.dispatch(record, context);

  assert.equal(trace.is_handled, true);
  assert.equal(trace.handler_frame.label, "outer");
  assert.deepEqual(order, ["inner_finally", "outer_except"]);
  // Both frames unwound: the chain is empty again.
  assert.equal(thread.readHead(), 0xffffffff);
  assert.equal(thread.frameAddressList().length, 0);
});

test("a divide error unwinds through nested __finally to the catching frame in order", () => {
  const thread = new SehThread();
  const order = [];
  thread.pushFrame({ label: "a", filter: () => (order.push("a_filter"), disposition.execute_handler), except: () => order.push("a_except") });
  thread.pushFrame({ label: "b", filter: () => (order.push("b_filter"), disposition.continue_search), finally: () => order.push("b_finally") });
  thread.pushFrame({ label: "c", filter: () => (order.push("c_filter"), disposition.continue_search), finally: () => order.push("c_finally") });

  const record = mapFaultToException({ code: "divide_error" }, { instruction_address: 0x00402000 });
  const trace = thread.dispatch(record, buildContext());

  assert.equal(trace.handler_frame.label, "a");
  // Search runs innermost-first (c, b, a); unwind runs finally innermost-first
  // (c, b) then the a handler.
  assert.deepEqual(order, ["c_filter", "b_filter", "a_filter", "c_finally", "b_finally", "a_except"]);
});

test("a vectored handler resolves before the SEH chain and can continue execution", () => {
  const thread = new SehThread();
  const order = [];
  thread.pushFrame({ label: "frame", filter: () => (order.push("frame_filter"), disposition.execute_handler), except: () => order.push("frame_except") });

  const first = thread.addVectored(true, () => (order.push("vectored_first"), disposition.continue_search));
  thread.addVectored(false, () => (order.push("vectored_last"), disposition.continue_execution));

  const record = buildExceptionRecord(exceptionCode.access_violation, 0x00403000, { information: [0, 0] });
  const trace = thread.dispatch(record, buildContext());

  // The second vectored handler continued execution, so the SEH filter never ran.
  assert.deepEqual(order, ["vectored_first", "vectored_last"]);
  assert.equal(trace.is_continued, true);
  assert.equal(trace.is_handled, false);

  // Removing the continuing handler lets the chain take over.
  thread.removeVectored(thread.vectored[1].handle);
  assert.equal(thread.removeVectored(first), true);
  const second = thread.dispatch(record, buildContext());
  assert.equal(second.is_handled, true);
  assert.deepEqual(order.slice(-2), ["frame_filter", "frame_except"]);
});

test("an unhandled exception falls to the last-chance filter, then terminates", () => {
  const thread = new SehThread();
  thread.pushFrame({ label: "search_only", filter: () => disposition.continue_search });
  let filterSeen = null;
  const record = buildExceptionRecord(exceptionCode.illegal_instruction, 0x00404000);
  const trace = thread.dispatch(record, buildContext(), {
    unhandled_filter: (seen) => {
      filterSeen = seen.exception_code;
      return disposition.continue_search;
    },
  });
  assert.equal(trace.unhandled_filter_run, true);
  assert.equal(filterSeen, exceptionCode.illegal_instruction);
  assert.equal(trace.is_terminated, true);
  assert.equal(trace.is_handled, false);
});

test("RaiseException flows guest arguments into the dispatched record", () => {
  const thread = new SehThread();
  let seen = null;
  thread.pushFrame({ label: "catch", filter: (record) => { seen = record; return disposition.execute_handler; }, except: () => {} });
  const trace = raiseException(thread, 0xe06d7363, 0, [0x19930520, 3, 0x00410000]);
  assert.equal(trace.is_handled, true);
  assert.equal(seen.exception_code, 0xe06d7363);
  assert.deepEqual(seen.exception_information, [0x19930520, 3, 0x00410000]);
});

test("the SEH chain is per-thread: two threads keep independent fs:[0] heads", () => {
  const memoryA = createMemory(0x10000, 0x00300000);
  const memoryB = createMemory(0x10000, 0x00400000);
  const threadA = new SehThread({ memory: memoryA, teb_address: 0x00300000 });
  const threadB = new SehThread({ memory: memoryB, teb_address: 0x00400000 });

  const frameA = threadA.pushFrame({ label: "a" });
  assert.equal(threadA.readHead(), frameA);
  // Thread B saw no registration; its head is still the chain terminator.
  assert.equal(threadB.readHead(), 0xffffffff);
  assert.equal(threadB.frameAddressList().length, 0);

  const frameB = threadB.pushFrame({ label: "b" });
  assert.notEqual(threadA.readHead(), threadB.readHead());
  assert.equal(threadB.readHead(), frameB);
});

test("out-of-order frame release is refused", () => {
  const thread = new SehThread();
  thread.pushFrame({ label: "outer" });
  const inner = thread.pushFrame({ label: "inner" });
  assert.throws(() => thread.popFrame(inner + 0x1000), /out of chain order|SehError/);
  // Releasing the true head succeeds.
  assert.equal(thread.popFrame(inner), inner);
});

test("PE TLS callbacks fire in declared order before entry", () => {
  const fired = [];
  const report = runTlsCallback(
    [{ address: 0x00401500 }, { address: 0x00401600 }, { address: 0x00401700 }],
    { reason: tlsReason.process_attach, module_handle: 0x00400000, invoke: (address) => fired.push(address) },
  );
  assert.deepEqual(report.fired_address, [0x00401500, 0x00401600, 0x00401700]);
  assert.deepEqual(fired, [0x00401500, 0x00401600, 0x00401700]);
  assert.equal(report.reason, tlsReason.process_attach);
  assert.equal(report.is_before_entry, true);
});

test("continuing a noncontinuable exception is the fatal noncontinuable violation, not a resume", () => {
  const thread = new SehThread();
  thread.pushFrame({ label: "resumer", filter: () => disposition.continue_execution });
  const record = buildExceptionRecord(exceptionCode.access_violation, 0x00406000, {
    exception_flag: exceptionFlag.noncontinuable,
    information: [0, 0],
  });
  const trace = thread.dispatch(record, buildContext());
  assert.equal(trace.is_continued, false);
  assert.equal(trace.is_noncontinuable_violation, true);
  assert.equal(trace.is_terminated, true);
});

test("an explicit unwind runs __finally down to the target frame without running a handler", () => {
  const thread = new SehThread();
  const order = [];
  const target = thread.pushFrame({ label: "target", finally: () => order.push("target_finally"), except: () => order.push("target_except") });
  thread.pushFrame({ label: "mid", finally: () => order.push("mid_finally") });
  thread.pushFrame({ label: "inner", finally: () => order.push("inner_finally") });

  const trace = thread.unwindTo(target);
  // inner and mid clean up innermost-first; the target survives as the head and
  // its own __except never runs — this is the cleanup-only path.
  assert.deepEqual(order, ["inner_finally", "mid_finally"]);
  assert.equal(thread.readHead(), target);
  assert.equal(trace.finally_run.length, 2);
  assert.throws(() => thread.unwindTo(0x00abcdef), /target is not on the chain|SehError/);
});

test("a nested exception carries the prior record and is marked nested", () => {
  const prior = buildExceptionRecord(exceptionCode.access_violation, 0x00407000, { information: [0, 0x10] });
  const inner = buildExceptionRecord(exceptionCode.divide_by_zero, 0x00407100);
  const nested = nestExceptionRecord(inner, prior);
  assert.equal(nested.exception_code, exceptionCode.divide_by_zero);
  assert.equal((nested.exception_flag & exceptionFlag.nested_call) !== 0, true);
  assert.equal(nested.nested_record, prior);
});

test("a re-entrant dispatch during an unwind is refused as a collided unwind", () => {
  const thread = new SehThread();
  let reentryError = null;
  thread.pushFrame({
    label: "catch",
    filter: () => disposition.execute_handler,
    except: () => {},
  });
  thread.pushFrame({
    label: "unwound",
    filter: () => disposition.continue_search,
    finally: () => {
      // A fault raised inside a __finally during the unwind must be refused.
      try {
        thread.dispatch(buildExceptionRecord(exceptionCode.access_violation, 0), buildContext());
      } catch (error) {
        reentryError = error;
      }
    },
  });
  thread.dispatch(mapFaultToException({ code: "divide_error" }), buildContext());
  assert.equal(reentryError?.seh_code, "seh_collided_unwind");
});

test("a legacy delivery maps onto an exnref tag when the substrate declares one", () => {
  const legacy = new SehThread();
  assert.equal(legacy.deliveryMode, "legacy");

  const withExnref = new SehThread({ substrate: { has_exnref: true } });
  assert.equal(withExnref.deliveryMode, "exnref");
  withExnref.pushFrame({ filter: () => disposition.execute_handler, except: () => {} });
  const record = buildExceptionRecord(exceptionCode.access_violation, 0x00405000, { information: [0, 0x1234] });
  const trace = withExnref.dispatch(record, buildContext());
  assert.equal(trace.delivery_mode, "exnref");
  assert.deepEqual(trace.exnref, mapToExnref(record));
  assert.equal(trace.exnref.tag, "guest_exception");
});
