// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

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
