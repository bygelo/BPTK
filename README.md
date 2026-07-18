# Browser Porting Toolkit

Browser Porting Toolkit (BPTK) is a proposed Maphy Technologies toolkit for evaluating, adapting, testing, and packaging Windows games for the browser.

This repository currently contains the research-backed roadmap and its validation harness. It does **not** contain a working game runtime, and no Windows game has been shown to run through BPTK yet.

## Quick start

```sh
git clone https://github.com/bygelo/BPTK.git
cd BPTK
python3 tool/validate.py
```

Python 3 is the only local requirement for the current planning gate.

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

- Roadmap candidate frozen: **46**
- Accepted item with benchmark specification: **33**
- Rejected candidate: **8**
- Deferred candidate: **5**
- Implemented item: **0**
- Passing roadmap benchmark: **0 / 33 (0%)**

Start with [ROADMAP.md](ROADMAP.md), then read the [architecture](doc/ARCHITECTURE.md), [source audit](doc/source-audit.md), [legal boundary](doc/legal-boundary.md), [third-party inventory](doc/third-party.md), [test contract](doc/TESTING.md), and [contribution guide](CONTRIBUTING.md).

## Validation

The planning package is machine-checkable with Python’s standard library:

```sh
python3 tool/validate.py
```

The validator checks roadmap count, dependency integrity, item-to-benchmark mapping, promotion state, local link, singular naming, and the current planning-only boundary.

The same command runs for every push and pull request through the repository's GitHub Actions roadmap gate.

## Naming and affiliation

Browser Porting Toolkit is a working name for a Maphy Technologies project. It is not affiliated with or endorsed by Apple, Microsoft, Valve, CodeWeavers, or any game publisher. This public planning repository is not public-product-name clearance and remains rename-ready. Naming and trade dress require review before a runtime or product launch; the project must not copy Apple source code, icon, screenshot, or interface treatment.

## License state

BPTK-authored material in this repository is licensed under the [Apache License 2.0](LICENSE), with copyright and repository status recorded in [NOTICE](NOTICE). The current repository incorporates no third-party software or game content; factual prior-art references are not bundled dependencies.

Apache-2.0 does not relicense a future dependency, user-supplied game, trademark, proprietary asset, or restricted SDK. The [third-party policy](doc/third-party.md) and [legal boundary](doc/legal-boundary.md) require component-level provenance and obligation review before upstream material enters the repository. BPTK-001 remains planned until the runtime reuse graph and public-name path receive their required review.
