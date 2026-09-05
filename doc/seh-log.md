<!-- Copyright 2026 Maphy Technologies -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SEH subsystem log (GS-008 · BPTK-053)

Structured exceptions, fault dispatch, and init callbacks. This log records
each build cycle, the coverage delta on the real corpus, and the honest state
of the acceptance contract. `npm run gate` is the only judge; a green gate here
does not mean a binary runs.

## Acceptance contract (doc requirement)

`bench/roadmap/spec/bptk-053.json` is `state: red, gate: active` — **implemented
but red**. Implemented means the machine is real code with an active red
acceptance contract; red because BPTK-053 depends on BPTK-035, and no substrate
delivers a translated-block fault into the chain yet. The self-contained engine
and its fixtures are green; the whole-guest exception path is not reachable.

Acceptance fixtures (`test/seh.test.mjs`, all green):

| Requirement | Fixture |
| --- | --- |
| Catch an access violation, run `__finally`, unwind to the correct frame | `a fixture catches an access violation, runs __finally, and unwinds to the correct frame` |
| Catch a `#DE`, unwind through nested `__finally` in order | `a divide error unwinds through nested __finally to the catching frame in order` |
| Vectored handler resolves in the right order, before the SEH chain | `a vectored handler resolves before the SEH chain and can continue execution` |
| CPU fault → EXCEPTION_RECORD for AV / `#DE` / `#UD` | `a CPU access violation and a divide error map to the exact guest exception code` |
| RaiseException | `RaiseException flows guest arguments into the dispatched record` |
| SetUnhandledExceptionFilter (last-chance) | `an unhandled exception falls to the last-chance filter, then terminates` |
| TLS callbacks fire in declared order before entry | `PE TLS callbacks fire in declared order before entry` |
| SEH chain is per-thread (fs:[0]) | `the SEH chain is per-thread: two threads keep independent fs:[0] heads` |
| Map to exnref where available, legacy fallback | `a legacy delivery maps onto an exnref tag when the substrate declares one` |

## Cycle 1 — the SEH machine (2026-09-05)

**Implemented** (`lib/seh.mjs`, generic, no per-title branch):

- Per-thread `fs:[0]` registration chain rooted at the thread TEB
  (`NtTib.ExceptionList`, offset 0). Memory-backed when a TEB address is
  supplied; a legacy in-object head backs the identical walk while the thread
  lane's TEB is unmerged. Push/pop enforce LIFO discipline and refuse an
  out-of-order release.
- `__try/__except/__finally` semantics as a real search-then-unwind machine:
  the search phase runs each filter without unwinding; on `EXECUTE_HANDLER` the
  unwind phase runs every intervening `__finally` innermost-first, pops each
  frame, then runs the catching `__except`. `CONTINUE_EXECUTION` resumes
  without unwind; `CONTINUE_SEARCH` walks to the next-outer frame.
- Vectored exception handlers: `addVectored(first, …)` / `removeVectored`,
  dispatched in registration order **before** the SEH chain, first-flag
  handlers prepended.
- CPU fault → guest dispatch: `mapFaultToException` turns the runtime fault
  codes (`read_fault`/`write_fault`/`fetch_fault` → `ACCESS_VIOLATION` with the
  0/1/8 access type and faulting address; `divide_error` → `INT_DIVIDE_BY_ZERO`;
  `unsupported_opcode` → `ILLEGAL_INSTRUCTION`; `x87_stack_fault` →
  `FLOAT_STACK_CHECK`) into an `EXCEPTION_RECORD`, with `buildContext` for the
  register/eflags/eip snapshot. Bounded-probe refusals (budget/block bounds)
  return `null` — they are never guest-visible exceptions.
- `raiseException` (kernel32!RaiseException) builds the record from guest
  arguments and dispatches; the last-chance filter models
  `SetUnhandledExceptionFilter`.
- `runTlsCallback` fires each PE TLS callback in declared table order, returns
  the fired address order and the before-entry property.
- exnref mapping: `mapToExnref` yields the substrate exception tag when the
  substrate declares one; delivery falls back to the legacy chain walk
  otherwise.

**Wiring** (minimal, SHARED files):

- `lib/hle.mjs`: each guest owns a per-thread `SehThread`; kernel32!RaiseException
  routes through it. With no served guest handler the dispatch terminates,
  preserving the existing `guest_exception` structured stop (no regression —
  `test/hle.test.mjs` RaiseException case unchanged). The vectored kernel32
  exports are **deferred**, not wired into the shared export table, because a
  new served export requires a conformance case in a test this lane does not
  own; the machine is fully covered by `test/seh.test.mjs`.

**Coverage delta (real corpus):** none. `bptk corpus run` needs the staged
DRM-free corpus (`bptk-corpus/stage/corpus-run.json`), absent on this machine
(payloads stay out of git per the legal rails), so no OpenTTD/Plink coverage
number moved. This is expected: a real `.exe` stage does not advance until the
whole thread → seh → cpu → user/gdi block lands and a substrate delivers a
fault into this chain. **0 passing stays 0.**

**Gate:** `npm run gate` exits 0. Test count 164 → 174 (+10 SEH fixtures).
Implemented count 40 → 41 (manifest, status.json, README, ROADMAP, cli test
reconciled).

## Next cycles

- Rebase onto the thread lane's per-thread TEB and point `SehThread` at
  `fs:[0]` in mapped memory instead of the legacy in-object head.
- When BPTK-035 lands an exnref delivery surface, route a real translated-block
  fault (`executeProbe`) into `SehThread.dispatch` so a whole-guest exception
  path runs — the promotion trigger for BPTK-053 → passing.
- Expose the vectored kernel32 exports with conformance cases once the shared
  conformance table is coordinated at the merge tip.
