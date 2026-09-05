# Lane H log — widening the HLE on both ABIs

## Cycle 1 — Win64 ABI dispatch for x86-64 (Goal 1, the priority)

Wired the existing Win32 core HLE (`lib/hle.mjs`) to the x86-64 calling
convention inside the bounded x86-64 probe (`lib/exec64.mjs`).

- Integer arguments marshal from RCX/RDX/R8/R9 then the caller stack above the
  32-byte shadow space; the 32-bit result zero-extends into RAX; the call
  returns under caller-cleanup (RSP untouched for a call-site intercept, the
  return address popped for a jmp-thunk intercept).
- A reached import now dispatches through the HLE when the core serves it, so
  execution continues; an import with no HLE row stays the honest
  `import_present` stop. HLE exit/exception/fault map to structured stops
  (`process_exit`, `guest_exception`, `hle_fault`).
- The HLE arena/virtual/thunk pages join the guest address space through a
  memory adapter over the multi-region 64-bit machine; the layout scan places
  them in the 32-bit range, disjoint from the PE32+ image (mapped above 4 GiB)
  and the high-address guest stack/TEB.

Measured — staged PuTTY x64 (corpus-001, MIT freeware):

| metric | before | after |
| --- | --- | --- |
| instruction_count | 13 | 62 |
| stop_reason | import_present (kernel32!GetSystemTimeAsFileTime) | unsupported_opcode 0xfa2 (CPUID, outside the read-only lift subset) |

The first import is served and execution runs the rest of the CRT prologue
(GetSystemTimeAsFileTime, then further init calls) until an opcode outside the
lift64 subset — an honest bounded stop, never a faked return.

Gate: green (`npm run gate`, 487 pass / 1 skip).
