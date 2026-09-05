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
| GS-050 | BPTK-095 | Cross-lane fallback + confidence chain | planned |
| GS-057 | BPTK-101 | Win32 module breadth | planned |
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
