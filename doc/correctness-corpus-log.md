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

## Remaining

None in scope. Every Pillar-3 item is implemented and gate-green. `passing` is honestly 0 — no real .exe reaches an interactive stage because the runtime (BPTK-010) is red. The corpus and export-coverage ledger remain the scoreboard other lanes measure against; growing it further means acquiring more lawful i386 binaries with real pins.
