# Browser Porting Toolkit

Browser Porting Toolkit (BPTK) is a proposed Maphy Technologies toolkit for evaluating, adapting, testing, and packaging Windows games for the browser.

This repository contains the research-backed roadmap and a dependency-free pre-alpha npm CLI for local license, corpus, security, input analysis, bounded PE32 mapping, and an opt-in deterministic i386 entry probe. It does **not** contain a supported Windows game runtime, and no Windows game has been shown to run through BPTK yet.

## Quick start

Install the public roadmap-tooling preview with Node.js 22 or later:

```sh
npm install --global @bygelo/bptk@0.1.0-alpha.0
bptk status
bptk doctor
bptk doctor --graphics
bptk legal ./project
bptk corpus status
bptk security ./game
bptk inspect ./game
bptk inspect ./game --target x86_64
bptk inspect ./game --target d3d11
bptk inspect ./game --target modern
bptk benchmark
bptk benchmark ./project.bptk-package --profile performance
bptk foundation compare ./game
bptk port --source ./project
bptk port --engine opensa ./project/game.dat
bptk run ./package
bptk run ./project.bptk-package --save slot-1
bptk run ./project.bptk-package --network off
bptk run ./project.bptk-package --control default
bptk package ./project --asset-mode stream
bptk package ./project.bptk-package --host html
bptk package ./project.bptk-package --host react
bptk package ./project.bptk-package --thread auto
bptk compatibility ./project.bptk-package --browser chrome
bptk import ./project.bptk-package --run
bptk report ./project.bptk-package --record off
```

`status` reads a bundled, content-addressed roadmap snapshot. `doctor` reports Node and operating-system facts; `doctor --graphics` launches the installed Chrome against an ephemeral data document and reports observed browser capabilities. `legal` scans declared license and provenance signals without granting approval. `corpus status` reports whether a local denominator is present and reviewed. `security` performs a bounded, read-only threat scan. `inspect` classifies supported local input without executing or uploading it; its research targets combine bounded input signals with live ephemeral browser capability and return a defer decision while prototypes are absent. `benchmark` runs an ephemeral tooling self-check; the performance profile verifies package chunk integrity on cold and warm reads but cannot measure a game. `foundation compare` measures locally available routes. `port --source` and `port --engine` report toolchain, adapter, and rights blockers without emitting a port. `run` maps PE32 section, HIGHLOW relocation, ordinary named or ordinal import, TLS metadata, memory reserve, and executable entry-point state. A package may opt into the deterministic `i386_probe_v1` profile to execute a bounded integer instruction subset at the mapped entry point; imports, TLS callback, x87, unsupported instruction, and memory fault stop or refuse the probe with a structured reason. Raw executable and package without that profile remain static. Save, network, and control options validate boundaries only. `import --run` classifies and diagnoses a package without staging or executing it. `package --asset-mode stream` writes content-addressed chunks through an atomic staging directory. `package --host` emits HTML or React source bound to the same package identity. `package --thread` uses a live capability observation to select or block a configuration, not a worker runtime. `compatibility --browser` observes Chrome or reports another profile's local availability without making a support claim. `report --record off` writes nothing; `consent` writes one minimized local report.

A PE32 package is a local directory with the executable and a strict `bptk.json`. The optional singular `import` array declares exact static bindings for the package; an omitted or unmatched binding remains a named blocker. Binding never invokes the imported function. Execution is separately opt-in and currently requires zero import and zero TLS callback.

```json
{
  "schema_version": 1,
  "executable": "game.exe",
  "load_base": 5242880,
  "import": [
    {
      "library": "demo.dll",
      "symbol": "NamedCall",
      "address": 4293918720
    }
  ]
}
```

To run the bounded entry probe instead, use a package with no import and this execution profile:

```json
{
  "schema_version": 1,
  "executable": "probe.exe",
  "execution": {
    "profile": "i386_probe_v1",
    "instruction_budget_count": 1000
  }
}
```

Run `bptk run ./package --json` to inspect the mapped image, deterministic image hash, resolution blocker, runtime blocker, and execution state. The opt-in profile reports register, flag, trace hash, memory hash, instruction count, stop reason, and structured exception. Its instruction budget is the deciding bound; this is an entry-probe surface, not evidence that a game runs.

To validate the source repository, install its dependency-free lockfile and run the complete gate:

```sh
git clone https://github.com/bygelo/BPTK.git
cd BPTK
npm ci --ignore-scripts
npm run gate
```

The source gate requires Node.js 22 or later and Python 3. The product-and-roadmap validator remains available as `python3 tool/validate.py`.

## Product thesis

The useful promise is not “every Windows game magically becomes React.” The useful promise is:

> Import broadly, diagnose precisely, and make the supported path to a browser build repeatable.

BPTK is planned as one workbench with three compatibility lane:

1. **Binary lane** — load eligible unmodified 32-bit PE game executable, execute x86 code, and translate a measured Win32 and DirectX subset to WebAssembly, WebGPU or WebGL, WebAudio, browser input, and OPFS.
2. **Source lane** — compile available C or C++ game source through Emscripten, then adapt graphics, audio, input, file, thread, and network behavior to browser constraints.
3. **Engine lane** — plug in a game-family engine replacement when a compatible open implementation already exists and the player supplies legally obtained asset.

Plain HTML and canvas are host targets. A React adapter is an optional integration shell; React is not the execution substrate.

## Initial compatibility contract

The first product boundary is deliberately narrow:

- Target: DRM-free, 32-bit x86 Windows game from roughly the DirectDraw through Direct3D 9 era.
- Input: local folder, ZIP, selected installer, executable, or source tree.
- Output: a compatibility report in every case; a runnable browser package only when the required capability is implemented and proven.
- Execution: imported game code and asset remain client-side; an explicit network relay may mediate multiplayer traffic but never runs the game.
- Explicit early non-support: kernel driver, kernel anti-cheat, DRM circumvention, x86-64, Direct3D 10–12, and arbitrary native socket behavior.

“Import” means the toolkit accepts and safely inspects an input. It does not mean every input is executable.

## Why this is feasible—and why it is hard

The component technology is demonstrated: PE loading and Win32 high-level emulation in the browser, x86-to-Wasm execution, Direct3D translation, source compilation to Wasm, browser file storage, and browser game ports all exist in prior art. The closest precedent, [BottleShip](https://github.com/jenissimo/bottleship), already combines several of these pieces.

The hard part is compatibility breadth. A Windows game can depend on a unique mixture of CPU instruction, undocumented behavior, Win32 call, graphics state, codec, installer, network protocol, timing assumption, middleware, DRM, or driver feature. BPTK therefore treats compatibility as a measured corpus and a growing generic shim set, not a marketing absolute.

## Current state

- Roadmap candidate frozen: **159**
- Accepted item with benchmark specification: **145**
- Gold-standard item promoted as planned work: **100**
- Rejected candidate: **8**
- Deferred candidate: **6**
- Implemented item: **58**
- Passing roadmap benchmark: **0 / 145 (0%)**
- Published-package source surface: **`@bygelo/bptk@0.1.0-alpha.0`**, roadmap diagnostics, bounded local analysis and research, live self-check, toolchain comparison, PE32 mapping and declared import resolution, an opt-in deterministic i386 entry probe, bounded installer extraction, declared resource bound, middleware and engine census routing, ephemeral Chrome capability probing, asset packaging, host emission, local policy diagnosis, safe import diagnosis, and local reporting; a new registry release has not been made from this branch

Start with [ROADMAP.md](https://github.com/bygelo/BPTK/blob/main/ROADMAP.md), then read the [architecture](https://github.com/bygelo/BPTK/blob/main/doc/ARCHITECTURE.md), [source audit](https://github.com/bygelo/BPTK/blob/main/doc/source-audit.md), [legal boundary](https://github.com/bygelo/BPTK/blob/main/doc/legal-boundary.md), [third-party inventory](https://github.com/bygelo/BPTK/blob/main/doc/third-party.md), [test contract](https://github.com/bygelo/BPTK/blob/main/doc/TESTING.md), [release procedure](https://github.com/bygelo/BPTK/blob/main/doc/RELEASE.md), and [contribution guide](https://github.com/bygelo/BPTK/blob/main/CONTRIBUTING.md).

## Validation

The repository package is machine-checkable with one command:

```sh
npm run gate
```

The gate checks roadmap count, dependency integrity, item-to-benchmark mapping, promotion state, local link, singular naming, the exact dependency-free npm package surface, the content-addressed status snapshot, CLI behavior, safe-inspection checks, and the intended tarball file list.

The same command runs on Node.js 22 and 24 for every push and pull request through the repository's GitHub Actions gate.

## Naming and affiliation

Browser Porting Toolkit is a working name for a Maphy Technologies project. It is not affiliated with or endorsed by Apple, Microsoft, Valve, CodeWeavers, or any game publisher. This public planning repository and its scoped roadmap-tooling package are not public-product-name clearance and remain rename-ready. Naming and trade dress require review before a runtime or product launch; the project must not copy Apple source code, icon, screenshot, or interface treatment. The unscoped npm name `bptk` is not used by this project.

## License state

BPTK-authored material in this repository and the `@bygelo/bptk` tarball is licensed under the [Apache License 2.0](https://github.com/bygelo/BPTK/blob/main/LICENSE), with copyright and repository status recorded in [NOTICE](https://github.com/bygelo/BPTK/blob/main/NOTICE). The package remains dependency-free and uses only Node.js built-in modules; it incorporates no third-party software or game content. Local analysis reads bounded metadata and prefixes only. Factual prior-art references are not bundled dependencies.

Apache-2.0 does not relicense a future dependency, user-supplied game, trademark, proprietary asset, or restricted SDK. The [third-party policy](https://github.com/bygelo/BPTK/blob/main/doc/third-party.md) and [legal boundary](https://github.com/bygelo/BPTK/blob/main/doc/legal-boundary.md) require component-level provenance and obligation review before upstream material enters the repository. BPTK-001 remains planned until the runtime reuse graph and public-name path receive their required review.
