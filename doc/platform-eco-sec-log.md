# Platform / library / governance / security lane log

Lane `lane/platform-eco-sec` — pillars 6+7+8+9. Converge-to-completion run.
Each item advances `planned → implemented`: real generic code + CLI surface + an
active RED acceptance contract (spec `gate: active`, `state: red`), with
`npm run gate` exit 0 after every commit. `passing` stays 0 by design.

## Done this run (each gate-green, committed)

| Item | Pillar | What landed |
| --- | --- | --- |
| BPTK-105 | P6 | Per-chunk gzip content-addressed streaming + `package --verify` (decode + double-hash, tamper rejected) |
| BPTK-106 | P6 | Deterministic `package --stream-plan` (prefetch/deferred split, non-blocking absent-block read) |
| BPTK-107 | P6 | Web component + iframe host shapes (4 shapes, one identity, release path, sandboxed frame) |
| BPTK-108 | P6 | `package --pwa` service worker precaching chunk hashes + minimal-invalidation diff |
| BPTK-110 | P6 | `package --publish-cdn` content-addressed dedup store, cross-title cache hit, differing hash never merged |
| BPTK-111 | P6 | `save sync` overlay-diff upload + `save resolve` deterministic conflict resolution |
| BPTK-112 | P7 | `library catalog` frozen metadata schema + instant-play/BYO gating |
| BPTK-113 | P7 | `library publish` gated by license/grant provenance graph (expired grant refused) |
| BPTK-114 | P7 | `library import` local staging, zero network, never published |
| BPTK-118 | P7 | `library preserve`/`preserve-export` append-only catalog, reproducible PII-free export |

Pillar 6 (P6, GS-061..067 = BPTK-105..111) COMPLETE.

## Counts
- implemented: 43 → 53 (start of run → now). passing: 0 (unchanged, by design).

## Remaining planned in scope
- P7: BPTK-115 (first-party demo), 117 (submission), 119 (ratings), 120 (modding)
- P8: BPTK-122 (issue tracker), 123 (compat db export), 126 (contributor pipeline), 128 (governance/analytics)
- P9: BPTK-131 (cross-lane resource-exhaustion bounds)

## Notes
- New lib logic for library/save/catalog lives in `lib/platform.mjs` (owned).
  Streaming/CDN/PWA in `lib/package.mjs` (owned).
- New test file `test/library.test.mjs` registered in `tool/validate.py` ALLOWED_MJS_PATH.
- CLI wiring in `lib/cli.mjs` (platform-lane surface; merges last).
- Promotion reconciliation done by scratchpad `promote-helper.mjs` (not committed).
