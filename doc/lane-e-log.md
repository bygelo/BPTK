# Lane E log — the x86-64 execution frontier

## Cycle 1 — drive a real PE32+ image to `entry` executing (BPTK-031)

Before this cycle an x86-64 (PE32+) image only LOADED: `lib/pe64.mjs` mapped the
image and the run surface returned `machine_x86_64_loaded`, executing nothing.
This cycle drives the mapped entry point through the existing x86-64 lifter and a
bounded interpreter until the first structured stop — the x86-64 analog of the
i386 bounded probe.

### What landed

- `lib/exec64.mjs` (new): a bounded x86-64 execution harness.
  - `runImage64(option)` interprets an image buffer from an entry RVA over a
    fresh 16-entry 64-bit register file and a three-region guest address space:
    the mapped image at its load base, a bounded guest stack, and a minimal
    gs-based TEB/PEB. rsp starts at a 16-aligned stack top with a return sentinel
    pushed; rip starts at the entry.
  - It drives the `lib/lift64.mjs` lifter (`decodeStructured`) block by block,
    following branches, calls, and returns. Segment overrides (fs/gs) — which the
    M2 lifter refuses — are handled here by stripping the one segment byte,
    lifting the remainder, and resolving the memory operand through the segment
    base, so `gs:[0x30]` (TEB self) and `gs:[0x60]` (PEB) read the TEB region.
  - It STOPS structured on: an import reached through its IAT slot
    (`import_present`, no Win64 HLE invented — that is milestone M4), an
    unsupported opcode (named), a memory/decode fault (named), or budget
    exhaustion. The interpreter semantics are ported faithfully from the
    `lib/lift64.mjs` oracle; that file stays read-only.
  - `executeProbe64(mapped, budget)` wraps a `mapPe64State(...)` result into a
    run-surface result: `probe_executed` the moment one instruction runs,
    `probe_blocked` otherwise. `instruction_count`/`is_executed` reflect
    instructions the interpreter actually ran.
- `lib/run.mjs`: the x86-64 branch now runs `executeProbe64` when an execution
  profile is present and returns its result; the mapped-only path stays when no
  execution is requested. `formatRun` gains an executed-x64 case.
- `test/exec64.test.mjs` (new): hand-assembled microprograms proving a
  three-block call/loop/return to `eax=15`, gs-relative TEB/PEB reads, an
  IAT-slot indirect call stopping as `import_present`, an unsupported-opcode stop
  whose count reflects only what ran, and a named out-of-region fault — plus the
  real PuTTY x64 image driven to its first import.

### Result — PuTTY x64 (MIT freeware, staged, read-only)

`runPackage` on the staged PuTTY x64 package with an execution profile:

- state `probe_executed`, is_executed `true`
- 13 x86-64 instructions executed from the CRT entry (RVA 0xbe504)
- stop_reason `import_present` at `kernel32.dll!GetSystemTimeAsFileTime`, reached
  through its IAT slot (the `__security_init_cookie` prologue path)

The stop is honest: no import is served, so reaching the first IAT call is a
structured stop, not a faked return. `passing` stays 0.

Gate: `npm run gate` exits 0 (validate.py + 478 test pass / 1 skipped + package
content check). `lib/exec64.mjs` and `test/exec64.test.mjs` registered in the
three gate surfaces.
