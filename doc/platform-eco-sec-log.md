# Platform / library / governance / security lane log

Lane `lane/platform-eco-sec` — pillars 6+7+8+9. Converge-to-completion run: **COMPLETE**.
Each item advanced `planned → implemented`: real generic code + CLI surface + an
active RED acceptance contract (spec `gate: active`, `state: red`), with
`npm run gate` exit 0 after every commit. `passing` stays 0 by design (no real
benchmark passes until a browser game runtime exists).

## Scope result

All 31 items in scope (BPTK-105..135, GS-061..067 / 068..076 / 078..085+101 / 086..091)
are `implemented`. 19 advanced this run; 12 were already implemented at branch point.

| Item | Pillar | What landed |
| --- | --- | --- |
| BPTK-105 | P6 | Per-chunk gzip content-addressed streaming + `package --verify` (decode + double-hash, tamper rejected) |
| BPTK-106 | P6 | `package --stream-plan` deterministic prefetch/deferred split, non-blocking absent-block read |
| BPTK-107 | P6 | Web component + iframe host shapes (4 shapes, one identity, release path, sandboxed frame) |
| BPTK-108 | P6 | `package --pwa` service worker precaching chunk hashes + minimal-invalidation diff |
| BPTK-110 | P6 | `package --publish-cdn` content-addressed dedup store, cross-title cache hit, differing hash never merged |
| BPTK-111 | P6 | `save sync` overlay-diff upload + `save resolve` deterministic conflict resolution |
| BPTK-112 | P7 | `library catalog` frozen metadata schema + instant-play/BYO gating |
| BPTK-113 | P7 | `library publish` gated by license/grant provenance graph (expired grant refused) |
| BPTK-114 | P7 | `library import` local staging, zero network, never published |
| BPTK-115 | P7 | `library demo` deterministic first-party tech-demo, honest not-passing capability evidence |
| BPTK-117 | P7 | `library submit` community pipeline, proprietary/PII refusal, attestation gate |
| BPTK-118 | P7 | `library preserve`/`preserve-export` append-only catalog, reproducible PII-free export |
| BPTK-119 | P7 | `library rating` shows only reproducible-replay-backed ratings, stale revisions grey out |
| BPTK-120 | P7 | `library mod` COW overlay, base immutability, containment, size bound |
| BPTK-122 | P8 | `tracker submit` completeness gate + published triage freshness level |
| BPTK-123 | P8 | `tracker export` byte-stable compatibility DB, evidence + PII refusal |
| BPTK-126 | P8 | `governance contribution` unified human/agent pipeline, AI-disclosure gate |
| BPTK-128 | P8 | `governance change` decision-record gate + analytics honesty property audit |
| BPTK-131 | P9 | `bound flood` cross-lane resource-exhaustion bounds, fail-closed fixtures, execution budgets |

Pillars 6, 7, 8, 9 all COMPLETE within this lane's ownership.

## Counts (this run)
- implemented: 43 → 62. passing: 0 (unchanged, by design).
- test total: 285 → 309, all pass. `npm run gate` exit 0.

## Where the code lives (owned files)
- `lib/package.mjs` — streaming (compress/verify), stream-plan, PWA, CDN dedup.
- `lib/platform.mjs` — cloud save, catalog, publish, BYO import, first-party demo,
  submission, preservation, ratings, modding; shared `scanPersonalData` / `stableStringify`.
- `lib/doctor.mjs` — tracker, compatibility export, contribution pipeline, governance change.
- `lib/bound.mjs` — cross-lane flood bounds + execution time budget.
- `lib/legal.mjs`, `lib/security.mjs` — reused (license/grant graph, threat scan, trust tier).

## Registries touched (shared, additive only)
- `lib/cli.mjs` — platform-lane command surface (merges last).
- `tool/validate.py` ALLOWED_MJS_PATH — added `test/library.test.mjs`, `test/governance.test.mjs`.
- New tests: `test/library.test.mjs` (11), `test/governance.test.mjs` (4), plus additions to
  `test/package.test.mjs`, `test/policy.test.mjs`, `test/boundary.test.mjs`.
- Roadmap reconciliation (manifest count, spec gate, README/ROADMAP/status/cli.test) via
  scratchpad `promote-helper.mjs` (not committed).

## Honesty
Every promoted item states "implemented but red because…" — the missing piece is
always the absent browser game runtime or a live hosting/edge environment. No false
green: `passing` is still 0, and the gate is the judge.
