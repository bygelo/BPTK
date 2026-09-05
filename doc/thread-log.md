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

1. CreateThread/ExitThread + the handle table, and the deterministic scheduler
   over a per-thread register file + per-thread TLS (no cross-thread bleed) —
   the isolation and replay-hash-match acceptance.
2. TlsAlloc/Get/Set/Free wired to the inline TEB slot array so the HLE export
   and the guest's own `fs:[0xE10+i*4]` read the same bytes.
3. Critical sections, WaitForSingleObject/MultipleObjects over the monotonic
   clock with a structured deadlock stop, events/mutexes/semaphores/waitable
   timers, Sleep/SleepEx that yield.
4. Interlocked* over WASM atomics and memory.atomic.wait/notify; the
   lock/atomic-contention fixture that must be deterministic under N workers
   with zero lost wakeup and two replays that hash-match.
