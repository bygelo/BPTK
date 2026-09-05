# Lane log — lanes-formats (Pillar 4)

Converge-to-completion run over the P4 lane/routing/format scope. Verifier:
`npm run gate` exit 0 after every commit; `passing` stays 0.

## Scope status

| GS | BPTK | Item | State |
|----|------|------|-------|
| GS-043 | BPTK-088 | Diagnose-and-route front door | implemented (pre-run) |
| GS-044 | BPTK-089 | Universal `.bptk` bundle envelope | implemented (pre-run) |
| GS-045 | BPTK-090 | Source lane build autodetect + patch-set | **implemented** |
| GS-046 | BPTK-091 | Engine lane open-reimpl host | planned |
| GS-048 | BPTK-093 | Web-native ingest under capability | implemented (pre-run) |
| GS-049 | BPTK-094 | DOS/Win16/Win9x emulator lane | **implemented** |
| GS-050 | BPTK-095 | Cross-lane fallback + confidence chain | **implemented** |
| GS-057 | BPTK-101 | Win32 module breadth | **implemented** |
| GS-072 | BPTK-116 | Authoring SDK / runtime-target API | implemented (pre-run) |

## Cycle 1 — GS-045 / BPTK-090 (source build-system autodetect)

- `lib/port.mjs`: generic marker-driven build-system detection (cmake, meson,
  autotools, premake, scons, msbuild, make), specificity ranking, pinned
  Emscripten patch set per system, and a reproducibility digest over the sorted
  file inventory + pinned patch set. No `if (project === …)`.
- `test/port.test.mjs`: asserts CMake/Make/Meson detection, specificity ranking
  (cmake > make), digest stability across runs + sensitivity to the tree, and
  the honest blocked terminal state (no package emitted). Registered in
  `tool/validate.py`.
- Spec `bptk-090.json`: gate excluded → active; red because the clean-env
  browser build cannot be produced/byte-compared until emcc + the SDL/OpenGL
  adapter land under the BPTK-002 denominator.
- Counts: implemented 43 → 44 (manifest, status.json, README, ROADMAP,
  cli.test). passing 0. Gate exit 0.

## Cycle 2 — GS-049 / BPTK-094 (pre-Win32 emulator lane)

- `lib/emulator.mjs` (new): header-signature era classifier (DOS / NE Win16 /
  LE-LX / PE Win32 / not-executable) and `admitEmulatorLane` — DOS/Win16/LE
  admitted to `emulator_legacy` under a sandbox confinement contract (all host
  reach denied, bounded memory/instruction budget, not persisted); PE32/PE32+
  refused onto the binary lane so the emulator lane never swallows a Win32
  title. Nothing runs; `bptk emulator admit <input>` wired into the CLI.
- `test/emulator.test.mjs` (new): era classification, DOS/Win16/LE admission,
  PE32 refusal, never-executed blocked terminal state, real-CLI reachability.
- Registered new lib + test in `tool/validate.py` (3 places), `content.json`,
  and the GS-072 `data/sdk-api.json` export manifest (+3 exports).
- Spec `bptk-094.json`: gate excluded → active; red until an emulator core is
  embedded. Counts: implemented 44 → 45. passing 0. Gate exit 0.

## Cycle 3 — GS-050 / BPTK-095 (cross-lane fallback chain)

- `lib/ingest.mjs`: `resolveFallbackChain` consumes the front-door ranking and
  walks candidate lanes in confidence order, applying a per-lane structural
  precondition table (reusing `diagnoseSourcePort` and `admitEmulatorLane`).
  First lane whose precondition holds becomes the carried candidate; skipped
  lanes record a per-hop reason; an exhausted chain terminates in a bounded
  `no_lane` state. `bptk route --fallback <input>` wired into the CLI. A
  carried candidate is a structural match — it never asserts the title runs.
- Tests in `test/ingest.test.mjs`: PE32 carried as binary candidate; a
  protection-refused binary with an engine asset falls binary → engine with a
  recorded hop; unroutable input terminates bounded no-lane; CLI reachability.
- Spec `bptk-095.json`: gate excluded → active; red because no candidate lane
  has a passing runtime. Counts: implemented 45 → 46; +2 SDK exports. Gate 0.

## Cycle 4 — GS-057 / BPTK-101 (Win32 module coverage census)

- `lib/import.mjs`: `classifyWin32Modules` (pure) tiers a set of imported
  module names against the declared Win32 module catalog (kernel32/user32/gdi32
  hosted; ole32/oleaut32/COM/CRT/msvbvm/… planned; else unrecognized) with a
  ledger; `censusWin32Modules` parses a PE's import table (reusing census's
  exported `parsePeImportNames`) and reports the coverage. `bptk modules
  <input>` wired into the CLI. A hosted slice is necessary but not sufficient;
  the census never claims a title starts.
- `test/import.test.mjs` (new): tiering + ledger totals, not-fully-hosted for a
  broader-module title, dedup/lowercase/order-independence, a real PE import
  census (blocked), and CLI reachability. Registered in `tool/validate.py`.
- Spec `bptk-101.json`: gate excluded → active; red until every imported module
  carries a passing conformance slice. Counts: implemented 46 → 47; +3 SDK
  exports. passing 0. Gate exit 0.
