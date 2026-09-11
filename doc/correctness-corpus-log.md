# Correctness & compatibility lane (Pillar 3) — build log

Lane `lane/correctness-corpus`, off `build/product-first`. Verifier: `npm run gate` exit 0 after every commit; `passing` stays 0 (no real benchmark passes).

## Cycle 1 — Pillar 3 planned items promoted to implemented

Started: 43 implemented / 0 passing. Ended: **50 implemented / 0 passing**, gate green.
Every Pillar-3 gold-standard item is now `implemented` (real generic apparatus + active red contract). All stay red because the real inputs (captured traces, recorded runs, live ratings) come from the absent Win32 runtime (BPTK-010); the apparatus is exercised against synthetic fixtures only.

| Item | GS | Deliverable | Where |
| --- | --- | --- | --- |
| BPTK-077 | GS-037 | Captured API-trace corpus admission gate: provenance + redaction proof + byte-stable canonical form | `lib/conformance.mjs` (`verifyTrace`, `verifyTraceCorpus`, `canonicalizeTrace`) |
| BPTK-078 | GS-038 | Compatibility rating ladder broken→…→complete, rung only on a passing evidence-backed predicate, no rating above highest contiguously-passing rung | `lib/report.mjs` (`computeCompatibilityRating`) |
| BPTK-079 | GS-039 | Deterministic reference/replay artifact: hash-only checkpoints, byte-stable artifact hash, first-divergence comparator, no embedded asset/PII | `lib/report.mjs` (`buildReplayArtifact`, `compareReplay`, `verifyReplayArtifact`) |
| BPTK-080 / BPTK-123 | GS-040 / GS-080 | Public compatibility database: every row regenerates from evidence, revision-pinned, byte-stable export, no unbacked/stale/PII row | `lib/report.mjs` (`buildCompatibilityDatabase`, `exportCompatibilityDatabase`, `verifyCompatibilityRow`, `regenerateRow`) |
| BPTK-119 | GS-075 | Compatibility-ratings site display rule: shown only when a reproducible recorded run backs it at the current browser+revision, greys out when stale, hidden when unbacked | `lib/report.mjs` (`resolveRatingDisplay`) |
| BPTK-082 | GS-042 | No-false-green promotion self-audit: five sabotage fixtures (wrong return, out-of-tolerance frame, inflated rating, stale provenance, non-deterministic replay) each rejected by its real predicate | `lib/benchmark.mjs` (`runPromotionSelfAudit`) |

Already implemented before this lane (verified green): BPTK-076 (conformance suite), BPTK-081 (export-coverage ledger), BPTK-083/084/085 (corpus acquire/run/generalize).

Tests: added `test/report.test.mjs` (16 tests) + trace tests in `test/corpus.test.mjs` + self-audit tests in `test/benchmark.test.mjs`. New exports registered in `lib/index.mjs` and `data/sdk-api.json`; `test/report.test.mjs` registered in `tool/validate.py`.

## Cycle 2 — corpus growth (GS-104 scoreboard)

`data/corpus.json`: 9 → **11** lawful DRM-free entries. Added two real, project-official-served **i386** PE32 binaries with verified pins (payloads never enter git):
- CORPUS-010 jq 1.7.1 win32 i386 (MIT, console) — sha256 `e4efdd6a…5166df`, 1027584 B, jqlang GitHub release.
- CORPUS-011 PuTTYgen 0.81 win32 i386 (MIT, GUI) — sha256 `577de7e2…072480`, 883480 B, the.earth.li official mirror. GUI binary broadens the user32/gdi32 import surface in the export-coverage ledger.

## Cycle 3 — corpus growth + generic HLE/api-set (2026-09-12)

`data/corpus.json`: 11 → **14** lawful DRM-free entries. Added three project-official-served binaries with verified pins (payloads never enter git):
- CORPUS-012 curl 8.22.0 win64 (curl license, console) — sha256 `7f23b039…efb714`, 8691604 B, curl.se official Windows zip. Ingest now reports the selected executable's machine, so this archive is `x86_64` at `entry` (BPTK-031), not a false i386.
- CORPUS-013 ripgrep 14.1.1 win32 i386 (MIT OR Unlicense, console) — sha256 `1e5c99e4…185f8e`, 1918749 B, GitHub release. Reaches `entry` after the kernel32/ntdll/userenv/bcryptprimitives widening; stops on unsupported `0x0f 0xc7` (CMPXCHG8B / rdrand group).
- CORPUS-014 SuperTux 0.7.0 win32 (GPL-3.0-or-later, SDL platformer) — sha256 `0207949f…dfc9eb`, 307358208 B, project portable zip. Ingest required a distinct `archive_input_byte` (512 MiB) so a zip is not mistaken for one inflate chunk. Loaded; 190 of 722 import served. Remaining unserved are bundled game DLLs (msvcp140, sdl2 leftovers, glew, physfs, opengl, openal) plus C++ CRT — the BottleShip-class next work is mapping sidecar PE modules, not more kernel32 rows.

The archive-vs-chunk bound split, inspect/security file-size alignment to the 512 MiB download bound, and api-set/ntdll name-forward in `computeImportService` are generic (they change every title, not one).

## Remaining

`passing` stays 1 (BPTK-001 only). No corpus entry is interactive. SuperTux and OpenTTD 1.10.3 stay at `loaded` on unserved imports. Ripgrep's next named gap is `0x0f 0xc7` on the i386 probe. Grow more lawful i386 **game** binaries only after sidecar DLL mapping exists, otherwise they pile up at the same bundled-DLL frontier.

## Known x86 fidelity gap: DIV/IDIV quotient overflow

Found while compiling `div`/`idiv` into the WASM tier, and worth recording
because it is a **wrong-answer** gap, not a missing feature.

On real x86, `div`/`idiv` raise **#DE** when the quotient does not fit the
destination width — the same vector as divide-by-zero. `lib/exec64.mjs` raises a
structured fault for a zero divisor, but for quotient overflow it does not: it
computes the quotient and writes it **masked**:

```js
writeAccumulatorPair(machine, size, quotient & mask, remainder & mask);
```

so an overflowing quotient is silently truncated where hardware would fault.

### Why the tier reproduces the gap rather than fixing it

The tier's contract is bit-exactness **against this interpreter**, not against
hardware. Emitting the architectural #DE in the compiled path would have made the
tier disagree with the oracle and broken the 1:1 test on a real binary. So the
codegen reproduces the masking exactly, and the gap stays where it belongs — in
the oracle.

### What it costs

A guest that relies on #DE for a range check, or that faults deliberately, gets a
truncated quotient and keeps running instead of trapping. No corpus binary is
known to depend on it, and none of the recorded run reach it, so this is a latent
divergence rather than an observed failure. Fixing it means changing `exec64`'s
`div`/`idiv` to raise the fault **and** re-proving every 1:1 case at once, since
both engine must move together — the tier's masking would then be the bug.

Recorded rather than fixed: a one-sided change here would silently break the
tier's equivalence proof, which is the more valuable property.
