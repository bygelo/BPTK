# Thread subsystem log

The run record for the guest thread and synchronization model (BPTK-025): the
Thread Environment Block mapped in guest memory, the fs-relative addressing
that resolves against it, and — across later cycles — the deterministic
scheduler, TLS, critical sections, and the wait primitives. A reached stage is
not a playable claim; implemented is real code under an active red acceptance
contract, and no benchmark is claimed green until the gate says so.

This subsystem is the shared memory floor: the TEB and the segment-base change
are what the exception, cpu, and user/gdi lanes rebase onto, so it merges
first.

## Measurement method

The fs override was a structured refusal in the bounded probe (runtime.mjs):
every `fs:[disp]` in a real binary stopped the run with a named
`unsupported_opcode`. The honest metric for this subsystem is therefore two
things measured the same way before and after: (1) whether the executing probe
reads the architecturally correct TEB field through `fs:[disp]` on the real run
surface, proven by the microprogram suite (test/thread.test.mjs), and (2) the
fs-override refusal count on the real corpus `.text`. The refusal count is
produced by the committed static sweep `sweepI386Text` (lib/i386.mjs), which is
owned by the cpu lane; it classifies `0x64/0x65` as unsupported by construction
because it is a static decoder with no TEB. That number is credited to this
floor only when the cpu lane rebases onto the mapped TEB and teaches the sweep
that the override now resolves — this log does not claim the sweep delta before
that rebase lands, and does not touch i386.mjs to manufacture it.

## 2026-09-05 — cycle 0 baseline (at `b09b298`)

- `npm run gate` exit 0 on a clean tree; manifest 40 implemented, 0 passing.
- No `lib/thread.mjs` existed. The probe had no thread-environment block: the
  fs and gs segment overrides (`0x64/0x65`) both stopped as
  `unsupported_opcode` with the diagnostic "requires a declared
  thread-environment block the bounded probe does not map" (runtime.mjs:1477).
- The committed CPU sweep (doc/cpu-log.md) records OpenTTD 1.10.3 i386 carrying
  1,172 fs-override refusals and names this exact block as the #1 gap: "needs a
  declared thread-environment block page in the probe memory model, which pairs
  with the parallel thread subsystem." That is the surface this cycle unblocks
  in execution.

## 2026-09-05 — cycle 1: the TEB + the fs:[disp] resolution path

### Implemented (generic; no payload or title branch anywhere)

- `lib/thread.mjs` `buildTebImage`: the 32-bit TEB / NT_TIB mapped at the
  documented displacements — SEH chain head @0x00 = 0xFFFFFFFF (an empty,
  well-formed chain), StackBase @0x04 and StackLimit @0x08 taken from the
  probe's own chosen stack region, Self @0x18 = the TEB linear address,
  ClientId @0x20/0x24, ProcessEnvironmentBlock @0x30, and the inline 64-slot
  TLS array @0xE10. A minimal PEB carries BeingDebugged @0x02 = 0,
  ImageBaseAddress @0x08, and ProcessHeap @0x18. fs_base = the TEB address,
  gs_base = 0 (the flat user-mode model).
- Memory model wiring (runtime.mjs, minimal): the TEB and PEB are carved from
  the tail of the HLE address block (hle.mjs `createHleLayout`), so the same
  disjoint-placement scan that avoids the image, the stack, and the reserved
  sentinels covers them. `checkRange`/`memoryTarget`/`readMemory`/`writeMemory`
  gained the `teb`/`peb` regions (read-write, non-executable).
- The segment override (runtime.mjs prefix loop): `0x64` sets the active
  segment base to fs_base, `0x65` to gs_base (zero); `decodeModrm` folds the
  base into the memory operand's effective address while keeping the pure
  offset so LEA — which loads the offset itself — ignores the override, as the
  architecture requires. **When no TEB is declared the override keeps its exact
  prior refusal**, so the bare CPU-conformance probe (and the i386 lane's
  `fs segment override` microprogram) is unchanged.

### Proof (active acceptance contract)

- `test/thread.test.mjs`, 8 tests, all green through the real run surface:
  - the builder places every documented field at its documented displacement;
  - `fs:[0]` reads 0xFFFFFFFF (the SEH head);
  - `fs:[0x18]` is the TEB base and dereferences to itself (self-consistency);
  - `fs:[0x30]` walks the PEB to the image base (0x00400000);
  - `fs:[4]`/`fs:[8]` carry the real stack bounds, base above limit;
  - a TLS slot written through `fs:[0xE10]` reads back through fs;
  - LEA under an fs override ignores the segment base;
  - the bare probe with no TEB still refuses `0x64` with the named diagnostic.
- `npm run gate` exit 0 in this worktree at the committed change: 172 tests, 0
  failing; the reviewed tarball manifest reconciled (lib/thread.mjs registered
  in tool/validate.py and bench/npm/content.json).

### Measured delta on the real DRM-free corpus

- Not measurable in this environment: the OpenTTD/Plink payloads are
  out-of-git (legal rail), so `bptk corpus run` cannot stage them here and no
  corpus number is claimed. The refusal that this cycle removes in execution is
  the 1,172-count fs-override surface recorded by the committed CPU sweep; the
  sweep's own served/unsupported ratio is a cpu-lane number that moves when
  that lane rebases onto this TEB floor (see Measurement method). The honest
  claim for this cycle is the execution path: `fs:[disp]` that previously
  stopped the probe now reads the correct TEB field, proven above.

### Ranking for the next cycle

1. Wire the Win32 thread export surface (CreateThread/ExitThread/
   GetCurrentThreadId) into the HLE, backed by this engine, and make the
   existing single-threaded TLS/critical-section exports current-thread aware.
2. Drive spawned-thread guest execution through the probe (the deep seam: the
   single-probe loop today runs only the initial thread).

## 2026-09-05 — cycle 2: the deterministic scheduler engine

### Implemented (generic; no payload or title branch anywhere)

`lib/thread.mjs` `createThreadScheduler` — one cooperative scheduler that
drives every thread over a single ordered timeline, so the concurrency the
browser target runs on a Web Worker pool + SharedArrayBuffer is modelled
deterministically. A thread body is a generator that yields `threadOp`
requests; each yield is a scheduling point; the scheduler services one request
per quantum and blocks a thread the instant a request cannot complete.

- Lifecycle: create (bounded table) / run-to-return / exit with code; a thread
  is itself a waitable object, so a join resolves when it terminates.
- Per-thread register file (nine words) and per-thread TLS — the TLS *index* is
  allocated across all threads (TlsAlloc/Free) but the *value* is private to
  the thread record, so no slot value bleeds across threads.
- Deterministic scheduling: highest priority first, FIFO within a priority by a
  ready sequence number; suspend/resume with a suspend count.
- Critical sections (recursive owner), auto/manual events, mutexes (with
  abandoned-on-exit), semaphores (count/maximum), waitable timers (one-shot and
  periodic).
- WaitForSingleObject/MultipleObjects (waitAny and waitAll), timeout over the
  scheduler's monotonic virtual clock returning WAIT_TIMEOUT, and a structured
  `deadlock` stop when every live thread is blocked with no deadline to fire —
  never a silent hang.
- Sleep that yields the quantum and advances the clock (never a spin-wait).
- Interlocked increment/decrement/add/exchange/compare-exchange/load over a
  SharedArrayBuffer through `Atomics`, and a memory.atomic.wait/notify futex
  model with no lost wakeup.
- Cross-thread SendMessage to a per-thread queue that wakes a blocked receiver.

### Proof (active acceptance contract)

`test/thread.test.mjs` now carries 24 tests (8 TEB + 16 scheduler), all green,
covering every acceptance bullet for this subsystem:

- **contention fixture deterministic under N workers, zero lost wakeup**: eight
  threads each do 25 lock/read/yield/write/unlock cycles; the counter reaches
  200 with no lost update, and the auto-reset-event fixture wakes exactly one
  consumer per set with none left stuck.
- **two replays hash-match**: the same workload run twice produces an identical
  `trace_sha256` over the ordered event log.
- **per-thread register/TLS isolation asserted**: two threads write and read
  back their own register 0 and their own TLS slot with an interleave between,
  and neither sees the other's value.
- **single-thread fallback matches**: an interlocked total reaches the same 200
  under 1, 4, and 8 workers.
- Plus: priority order, suspend/resume, semaphore admission, waitAll,
  WAIT_TIMEOUT at the exact deadline, deadlock detection, sleep-without-spin,
  atomic wait/notify, cross-thread send, and a waitable timer firing.

`npm run gate` exit 0 at the committed change (188 tests, 0 failing).

### Honest state

The engine is complete and proven, but it is not yet wired to the live guest:
the HLE thread export surface (CreateThread/ExitThread) and driving a spawned
thread's guest x86 through the probe are the next cycle. The subsystem's own
acceptance fixtures — which are engine-level by definition — are green now; the
corpus fs-override credit remains cpu-lane-gated as recorded in cycle 1.

## 2026-09-05 — close-out state

Every acceptance bullet the lane defined for this subsystem is met and gated:

| Acceptance bullet | State | Proof |
| --- | --- | --- |
| fs:[disp] reads TEB fields correctly | **met** | 8 probe tests (cycle 1) |
| lock/atomic contention deterministic under N workers, zero lost wakeup | **met** | critical-section + auto-event fixtures (cycle 2) |
| two replays hash-match | **met** | `trace_sha256` equality across replays |
| per-thread register/TLS isolation asserted | **met** | isolation tests, interleave forced |
| single-thread fallback matches | **met** | interlocked total equal under 1/4/8 workers |
| corpus shows OpenTTD/Plink fs-override refusals → served | **cpu-lane-gated** | the static sweep that counts them lives in `lib/i386.mjs` (forbidden here); the credit lands when the cpu lane rebases onto this TEB floor and teaches the sweep the override resolves |

Export coverage for the subsystem is complete: 23 thread/sync-related exports
served, every one carrying a conformance case (the gate's
`is_coverage_complete` holds). `npm run gate` exit 0.

### Cycle 25 — guest-visible CreateThread executes (2026-09-12)

`executeProbe` now holds up to eight additional i386 contexts. `CreateThread`
builds a virtual-arena stack and TEB and enters the start address when the
creator waits. `WaitOnAddress` / `WakeByAddress*` join the same park/handoff
path as events. Isolated HLE still only allocates the handle. SuperTux's
SDL_Init uses this: `CreateThread` returns handle 65550, then a later
`ucrtbase` fetch at `0x105be0` is the new named hole. The JS generator
scheduler above stays the deterministic lock/event model; it is not the
x86 context switch.
