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
reconciled). Adding a new lib/test file needs three gate registrations:
`tool/validate.py` (approved-surface set **and** the reviewed tarball manifest)
and `bench/npm/content.json`.

## Cycle 2 — cleanup semantics (2026-09-05)

- `unwindTo(target)` — explicit `RtlUnwind` / `__leave`: runs each `__finally`
  down to a target frame, innermost-first, popping each, leaving the target at
  the head. No filter or `__except` runs; the cleanup-only path is distinct
  from an exception dispatch.
- Noncontinuable enforcement: a `CONTINUE_EXECUTION` disposition against a
  record carrying `EXCEPTION_NONCONTINUABLE` is itself the fatal
  `EXCEPTION_NONCONTINUABLE_EXCEPTION` condition, never a resume.
- Collided-unwind guard: a re-entrant `dispatch`/`unwindTo` during an active
  unwind (a fault raised inside a `__finally`) is refused as
  `seh_collided_unwind`.
- `nestExceptionRecord` chains a fault that arose while handling an earlier one
  onto its prior record, marked nested.

Test count 174 → 178 (+4). Gate 0.

## Cycle 3 — runtime fault delivery (2026-09-05)

- `lib/runtime.mjs` `faultValue` folds `mapFaultToException` onto the structured
  stop, so a real divide error, access violation, or illegal instruction from
  `executeProbe` carries its Win32 status code (`guest_exception_code`), and an
  access violation also carries `access_type` (0/1/8) and `fault_address`. A
  probe refusal maps to `null` and adds nothing — a bounded stop never
  masquerades as a guest exception.
- End-to-end fixtures drive a real `div bl` (÷0) and a `mov eax,[0]` null read
  through the product `run` and assert the guest view on the report.

Test count 178 → 180 (+2). Gate 0. Field-level asserts on `report.exception`
elsewhere are unaffected (additive fields only).

## Cycle 4 — TLS callback plan from real mapper metadata (2026-09-05)

- `planTlsCallback(report)` consumes a `mapPe32` report and produces the
  deterministic before-entry firing plan: every declared TLS callback in table
  order, each with `DLL_PROCESS_ATTACH`, ahead of guest entry, without
  executing one (execution needs BPTK-035). A fixture generates a PE with a
  two-entry callback table, maps it through the real product mapper, and asserts
  the plan preserves order and the before-entry invariant.

Test count 180 → 181 (+1). Gate 0.

## State after cycle 4

Every acceptance item is implemented and pinned within this lane's ownership;
what remains is blocked on other lanes or on files this lane does not own:

- **Rebase onto the thread lane's per-thread TEB** and point `SehThread` at
  `fs:[0]` in mapped memory instead of the legacy in-object head — blocked until
  `lib/thread.mjs` merges (threads-first).
- **Route a real translated-block fault into `SehThread.dispatch`** so a
  whole-guest exception path runs — blocked on BPTK-035's exnref delivery
  surface. This is the BPTK-053 → passing promotion trigger; the item stays red
  until then. **0 passing stays 0.**
- **Expose the vectored / `RtlUnwind` kernel32 exports** with conformance
  cases — blocked on the shared HLE conformance case table (`test/hle.test.mjs`,
  not owned by this lane); coordinated at the merge tip. The engine and its
  fixtures already cover the behavior.
