# Browser Porting Toolkit roadmap

## Decision summary

BPTK is feasible as a staged compatibility workbench. The browser building block already exist, and BottleShip now demonstrates a remarkably close binary-runtime architecture. What is not feasible is an unrestricted execution guarantee across arbitrary Windows game, hardware era, middleware, DRM, driver, and network model.

The product should therefore compete on the full porting workflow:

```text
import -> inspect -> choose lane -> adapt -> benchmark -> diagnose -> package -> embed -> publish evidence
```

The differentiator is one workbench joining binary compatibility, source-assisted porting, engine-family adapter, truthful compatibility reporting, and framework-neutral packaging. The P0 decision may lead to collaboration with or adaptation of BottleShip; rebuilding its demonstrated surface without measured cause is not the strategy.

## Current truth

- Initial repository state: empty directory with no git repository, license, runtime, test, or documentation.
- Current repository state: public Apache-2.0 roadmap package, validation harness, and dependency-free `@bygelo/bptk@0.1.0-alpha.0` status and environment-diagnostic CLI.
- Product implementation: BPTK-003 live benchmark and promotion checks plus BPTK-007 safe local inspection are implemented but red; no game-runtime item passes.
- CLI boundary: `legal`, `corpus status`, `security`, `inspect`, `benchmark`, `foundation compare`, `port --source`, and `run` are reachable. They perform bounded local analysis, live self-check, toolchain diagnosis, or PE32 image mapping without executing or uploading game code. `status` and `doctor` remain diagnostic surfaces.
- Foundation state: legal and security command output explicitly requires named review, corpus status publishes no denominator without approval, foundation comparison measures only locally available options, and source porting reports the missing Emscripten and adapter step without emitting a scaffold. The PE32 mapper validates header, section, relocation, import-directory, TLS-directory, stack, heap, and entry-point boundary but does not resolve Win32 import or execute the entry point. BPTK-001, BPTK-002, and BPTK-004 remain planned because command output cannot manufacture approval. BPTK-003 and BPTK-007 are implemented but red because their prerequisite remain red. Full source compilation, i386 execution, and Win32 HLE are weeks-scale and remain planned.
- Current benchmark coverage: **0 / 33 (0%)**.
- Compatibility corpus coverage: not publishable until BPTK-002 freezes the runtime denominator.
- Closest prior art: BottleShip for unmodified PE32 game; Emscripten for source-assisted game; OpenSA, WebXash, Qwasm2, and ScummVM for engine-family or asset-driven path.

## Product contract

### Minimum promise

BPTK accepts a supported local input form, inspects it without execution, and returns a precise compatibility report. A runnable package is emitted only if its capability path passes an active benchmark.

### First execution target

- DRM-free PE32 and i386 game from the DirectDraw through Direct3D 9 era;
- client-side execution;
- GDI, DirectDraw, selected D3D7/8/9, waveOut or DirectSound, Win32 file and registry behavior;
- WebGPU primary profile with declared WebGL2 fallback where the required feature maps safely;
- local folder, ZIP, BPTK bundle, and explicitly supported installer import;
- plain HTML canvas host plus a thin React lifecycle adapter.

### Early exclusion

- DRM circumvention and kernel anti-cheat;
- kernel driver and arbitrary native device access;
- x86-64 and Direct3D 10–12 outside P4 research;
- server-side native game streaming as a compatibility substitute;
- bundled commercial game executable or asset;
- a title status without toolkit revision and environment evidence.

## Discovery denominator

The raw candidate denominator was frozen after deduplication on 2026-07-18.

| Candidate source | Count | Example signal |
|---|---:|---|
| Initial repository state | 4 | License, implementation, test, and documentation were absent |
| User and product objective | 7 | Broad import, Windows input, browser output, canvas, React host, Maphy ownership, Apple-like workflow |
| Prior-art capability and limitation | 23 | CPU, PE, Win32, DirectX, source toolchain, engine adapter, package, compatibility evidence |
| Browser, distribution, and security constraint | 12 | GPU availability, thread isolation, socket limit, storage, user content, copyleft, trademark, hostile import |
| **Raw** | **46** | Frozen denominator |

| Decision | Count |
|---|---:|
| Accepted into this roadmap | 33 |
| Rejected | 8 |
| Deferred | 5 |
| Implemented | 2 |
| Passing | 0 |

The complete identity, origin, dedupe key, decision, and target mapping is frozen in [the candidate ledger](bench/roadmap/candidate.json); [the rejection and defer ledger](doc/roadmap-rejected.md) explains the non-accepted decisions. A future change may alter the denominator only by adding a newly discovered raw candidate and classifying it in the same change.

## Benchmark contract

Each accepted item now uses one quadruple: **Behavior**, **Surface**, **Benchmark**, and **Tier**. Behavior names what a user gets. Surface is the literal invocation the product must expose; an invocation shown here is a planned contract, not a claim that it exists today. Benchmark names the evidence that protects the behavior. Tier sets how often and how strongly that evidence gates change:

- **Tier 1** — release-blocking regression coverage for a named failure that could silently corrupt, escape, disclose, or invalidate a supported user result;
- **Tier 2** — reserved for a future intermediate gate when a concrete project need justifies it;
- **Tier 3** — the default for planning evidence, bounded research, review, and behavior not yet exposed as a supported product contract.

The specifications under [bench/roadmap/spec](bench/roadmap/README.md) remain acceptance contracts, but `bench/` is not the deliverable. Tier 3 uses a written falsifiable acceptance line only. Tier 1 may use a live or temporary generated check, but no committed baseline, retained-evidence JSON, or golden fixture. A benchmark promotes only the user behavior named in its roadmap row, and command existence cannot satisfy an operational prerequisite. All 33 remain red today; BPTK-003 and BPTK-007 are active and implemented, while the other 31 are gate-excluded. [The test contract](doc/TESTING.md) defines promotion.

[bench/roadmap/manifest.json](bench/roadmap/manifest.json) remains the machine-readable source for identity, prerequisite, and promotion state. This roadmap owns the user behavior, literal surface, and benchmark tier.

## Critical path

```mermaid
flowchart LR
    legal["P0 license and provenance"] --> corpus["P0 corpus"]
    corpus --> runner["P0 benchmark runner"]
    legal --> threat["P0 threat model"]
    runner --> binary["P0 binary spike"]
    runner --> source["P0 source spike"]
    threat --> binary
    threat --> source
    binary --> inspect["P0 importer and report"]
    source --> inspect
    inspect --> p1["P1 PE32 and 2D first playable"]
    p1 --> p2["P2 D3D9 and package"]
    p2 --> p3["P3 breadth and browser matrix"]
    p3 --> p4["P4 modern-game research"]
```

P0 is a funding and architecture gate. If neither binary option meets the frozen budget, the honest outcome is a source-first toolkit, not an unbounded rewrite.

## P0 — Prove the product and choose the foundation

P0 ends when the legal, evidence, security, binary, source, and import premise is proven on one denominator.

| ID | Behavior | Surface | Benchmark | Source | Tier | Dependency · Owner |
|---|---|---|---|---|---|---|
| BPTK-001 | Know whether a project can be published and which upstream component may be reused | `bptk legal <project>` | [BENCH-001](bench/roadmap/spec/bptk-001.json): returns an approved, revisioned license, provenance, naming, and reuse decision; approval remains open | SRC-001–006/008/009/012–015 | Tier 3 | — · Product + legal |
| BPTK-002 | See compatibility claims against a stable, representative denominator | `bptk corpus status` | [BENCH-002](bench/roadmap/spec/bptk-002.json): freezes lawful fixture, environment profile, and threshold before any percentage is published; corpus review remains open | SRC-002/003/004/006/010/011 | Tier 3 | 001 · Compatibility |
| BPTK-003 | Trust that roadmap status changes only when live evidence passes | `bptk benchmark` | [BENCH-003](bench/roadmap/spec/bptk-003.json): runs deterministic in-memory checks and enforces content-addressed promotion state without retaining a result; passing remains blocked by legal and corpus prerequisite | SRC-002/003/011/013 | **Tier 1** — regression risk: a false-green result promotes unsupported behavior | 001, 002 · Tooling |
| BPTK-004 | Know how an imported game is isolated before opening it | `bptk security <input>` | [BENCH-004](bench/roadmap/spec/bptk-004.json): reviews archive, parser, memory, permission, network, storage, privacy, and hostile-code control; named review remains open | SRC-002/003/009/019/020/023–026 | Tier 3 | 001 · Security |
| BPTK-005 | Get a measured recommendation for the binary-runtime foundation | `bptk foundation compare <input>` | [BENCH-005](bench/roadmap/spec/bptk-005.json): compares adaptation, composition, and new-runtime option on one frozen fixture; no option is selected | SRC-002–005/012/013 | Tier 3 | 001–004 · Runtime |
| BPTK-006 | Turn a supported SDL/OpenGL source project into a runnable browser package | `bptk port --source <project>` | [BENCH-006](bench/roadmap/spec/bptk-006.json): builds from clean source and runs the declared browser profile; no Wasm browser package exists | SRC-006/007/010/016–018 | Tier 3 | 001–004 · Source port |
| BPTK-007 | Drop in a local project and get a safe route or precise blocked reason | `bptk inspect <input>` | [BENCH-007](bench/roadmap/spec/bptk-007.json): classifies folder, archive, installer, PE, source, and engine asset without execution or upload; classifier implemented, prerequisite and full matrix remain red | SRC-002/003/008–011 | **Tier 1** — regression risk: inspection executes input, escapes a path boundary, or selects the wrong lane | 002–006 · Workbench |

### P0 exit gate

- BPTK-001 through BPTK-007 are active and passing.
- One binary option runs the frozen PE32 comparison fixture inside the BPTK-002 budget, or the project explicitly records source-first scope.
- The source fixture builds from a clean checkout and runs in the declared browser profile.
- Invalid and hostile import returns a bounded error without execution, upload, or partial storage.
- The name, license, reuse strategy, and threat model have named reviewer and expiry trigger.

## P1 — Reach a truthful PE32 and 2D first playable

P1 builds the minimum binary path for classic 2D and software-rendered interface. It does not claim broad title support.

| ID | Behavior | Surface | Benchmark | Source | Tier | Dependency · Owner |
|---|---|---|---|---|---|---|
| BPTK-008 | Open an eligible PE32 game into a bounded, correctly resolved memory image | `bptk run <package>` | [BENCH-008](bench/roadmap/spec/bptk-008.json): validates section, relocation, import, TLS, stack, heap, and entry point; bounded mapping exists but Win32 import and TLS execution remain unresolved | SRC-002/003/004 | Tier 3 | 005, 007 · Runtime |
| BPTK-009 | Run supported i386 game code with stable register, FPU, memory, and exception behavior | `bptk run <package>` | [BENCH-009](bench/roadmap/spec/bptk-009.json): matches the frozen instruction and exception oracle; no CPU core exists | SRC-002–005 | **Tier 1** — regression risk: silent CPU divergence changes game state or crashes later in an unrelated subsystem | 005, 008 · Runtime |
| BPTK-010 | Start and keep a supported Win32 game loop running in the browser | `bptk run <package>` | [BENCH-010](bench/roadmap/spec/bptk-010.json): verifies required Kernel32, NTDLL, CRT, synchronization, time, process, memory, and COM behavior; no Win32 HLE exists | SRC-002/003/012/013 | Tier 3 | 009 · Compatibility |
| BPTK-011 | Control a game through browser focus, keyboard, pointer, cursor, timer, and window lifecycle | `bptk run <package>` | [BENCH-011](bench/roadmap/spec/bptk-011.json): replays deterministic USER32 message and input order; no browser bridge exists | SRC-002/003/009 | Tier 3 | 010 · Browser runtime |
| BPTK-012 | See launchers, menus, text, and software-rendered output correctly | `bptk run <package>` | [BENCH-012](bench/roadmap/spec/bptk-012.json): compares GDI image and trace evidence within declared tolerance; no GDI output exists | SRC-003/012 | Tier 3 | 011 · Graphics |
| BPTK-013 | See a supported DirectDraw game render and present a correct 2D frame | `bptk run <package>` | [BENCH-013](bench/roadmap/spec/bptk-013.json): verifies surface, lock, blit, flip, palette, color-key, pitch, and presentation semantics; no browser frame exists | SRC-002/003 | Tier 3 | 010, 011 · Graphics |
| BPTK-014 | Hear supported waveOut and DirectSound audio in sync with play | `bptk run <package>` | [BENCH-014](bench/roadmap/spec/bptk-014.json): checks PCM, buffer, loop, volume, pan, callback, pause, and underrun behavior; no Web Audio bridge exists | SRC-002–004/019/021 | Tier 3 | 010 · Audio |
| BPTK-015 | Save settings and progress across reload without changing the original game files | `bptk run <package> --save <profile>` | [BENCH-015](bench/roadmap/spec/bptk-015.json): proves read-only base, copy-on-write overlay, path normalization, quota rollback, registry, and reload persistence; no OPFS bridge exists | SRC-002/009/010/022/023 | **Tier 1** — regression risk: a save is lost, aliased to another path, corrupted, or written outside its sandbox | 004, 010 · Storage |
| BPTK-016 | Import a supported package and reach one interactive, persistent 2D session | `bptk import <input> --run` | [BENCH-016](bench/roadmap/spec/bptk-016.json): runs loading, CPU, Win32, input, graphics, audio, storage, save, and reload together; no integrated first playable exists | SRC-002/003/010/022/023 | **Tier 1** — regression risk: individually passing components stop working as one launchable session | 004, 007–015 · Integration |

### P1 exit gate

- The synthetic PE32 2D fixture reaches `interactive` with correct visual, input, audio, and API artifact.
- Save and registry mutation survive reload without modifying the read-only base.
- Malformed executable and package corpus fail closed under resource limit.
- One user-owned, metadata-only pilot may be evaluated locally, but its asset is not retained or published and its status is not generalized.

## P2 — Deliver Direct3D 9, source SDK, performance, and package output

P2 produces the first package that demonstrates the product’s Windows-to-browser value across both binary and source lane.

| ID | Behavior | Surface | Benchmark | Source | Tier | Dependency · Owner |
|---|---|---|---|---|---|---|
| BPTK-017 | Know whether this browser can run the package, use a safe fallback, or must block | `bptk doctor --graphics` | [BENCH-017](bench/roadmap/spec/bptk-017.json): probes WebGPU, WebGL2, limit, extension, degradation, and reason-bound blocking; no live probe exists | SRC-002/007/014–016/020 | Tier 3 | 003, 004 · Graphics |
| BPTK-018 | Play supported D3D7/8 fixed-function content on the selected browser GPU path | `bptk run <package>` | [BENCH-018](bench/roadmap/spec/bptk-018.json): compares legacy state, transform, resource, cache, and presentation behavior; no GPU translator exists | SRC-002/007/014 | Tier 3 | 013, 017 · Graphics |
| BPTK-019 | Play supported D3D9 fixed-function content through device loss and reset | `bptk run <package>` | [BENCH-019](bench/roadmap/spec/bptk-019.json): verifies resource, state block, target, scene, loss, reset, restoration, and teardown; no D3D9 device path exists | SRC-002/007/014 | Tier 3 | 018 · Graphics |
| BPTK-020 | Render supported D3D9 shader-model 1–3 content correctly and deterministically | `bptk run <package>` | [BENCH-020](bench/roadmap/spec/bptk-020.json): validates bytecode, IR, reflection, cache, precision, control flow, resource, and frame result; no translator or compiler exists | SRC-001/002/014/015/020 | **Tier 1** — regression risk: a backend-specific shader miscompile silently renders the wrong game state | 019 · Shader |
| BPTK-021 | Port a supported native source project reproducibly with a documented adapter SDK | `bptk port --source <project>` | [BENCH-021](bench/roadmap/spec/bptk-021.json): reproduces toolchain, adapter, diagnostic, package, and browser result in a clean second environment; no SDK exists | SRC-006/007/010/016 | Tier 3 | 006, 017 · Source port |
| BPTK-022 | Start a large game reliably with verified, resumable, offline-capable asset delivery | `bptk package <project> --asset-mode stream` | [BENCH-022](bench/roadmap/spec/bptk-022.json): checks content address, chunk, resume, corruption, atomic commit, cache, quota, eviction, startup, memory, and offline behavior; no asset pipeline exists | SRC-002/006/010/022 | Tier 3 | 015–017 · Asset pipeline |
| BPTK-023 | See whether a package meets its declared startup, frame, audio, CPU, and memory budget | `bptk benchmark <package> --profile performance` | [BENCH-023](bench/roadmap/spec/bptk-023.json): measures frozen cold, warm, CPU, frame, audio, memory, cache, correctness, and variance threshold; no runtime measurement exists | SRC-002–005/013/014 | Tier 3 | 009, 010, 018 · Performance |
| BPTK-024 | Embed the same package in plain HTML or React without changing runtime behavior | `bptk package <project> --host <html&#124;react>` | [BENCH-024](bench/roadmap/spec/bptk-024.json): verifies one package identity, lifecycle, path, CSP, header, remount, teardown, and game-loop ownership across both host; no emitted package exists | SRC-001/002/006/009/010/020/023/024 | **Tier 1** — regression risk: a host remount duplicates the game loop, leaks a worker, or changes package behavior | 016, 017, 021 · Packaging |

### P2 exit gate

- The D3D9 fixed-function and shader fixture passes on the primary GPU profile; fallback behavior is explicit.
- The source SDK is reproduced by a clean second environment.
- The binary and source output share one package and lifecycle contract.
- Plain HTML and React host produce the same runtime artifact, and React never owns the game loop.
- The frozen desktop fixture meets the BPTK-002 performance budget with artifact retained.

## P3 — Expand browser, control, network, evidence, and engine breadth

P3 turns the first package into an externally testable platform without weakening compatibility truth.

| ID | Behavior | Surface | Benchmark | Source | Tier | Dependency · Owner |
|---|---|---|---|---|---|---|
| BPTK-025 | Run the correct threaded or single-thread package for the current host | `bptk package <project> --thread <auto&#124;on&#124;off>` | [BENCH-025](bench/roadmap/spec/bptk-025.json): verifies build selection, isolation header, fallback, worker, memory, synchronization, proxy, timing, and explicit block; no threaded package exists | SRC-002/006/018/019/024 | Tier 3 | 021, 024 · Browser runtime |
| BPTK-026 | Connect a game only through a consented, allowlisted browser transport or disclosed proxy | `bptk run <package> --network <off&#124;prompt>` | [BENCH-026](bench/roadmap/spec/bptk-026.json): exercises consent, allowlist, transport, denial, reconnect, loss, latency, proxy disclosure, offline, and no-upload rule; no network bridge exists | SRC-006/010/017 | **Tier 1** — regression risk: a package connects or uploads without consent or outside its endpoint allowlist | 004, 010, 021, 024 · Network |
| BPTK-027 | Play with keyboard, pointer, controller, fullscreen, touch, remap, accessible controls, and safe exit | `bptk run <package> --control <profile>` | [BENCH-027](bench/roadmap/spec/bptk-027.json): verifies permission, logical action, focus recovery, remap persistence, accessible workbench, and recoverable exit; no browser control surface exists | SRC-001/009/010/025–028 | Tier 3 | 011, 024 · Experience |
| BPTK-028 | Reproduce a compatibility result without sharing the game or personal data | `bptk report <package> --record <off&#124;consent>` | [BENCH-028](bench/roadmap/spec/bptk-028.json): binds revision, minimized environment, replay, crash, screenshot, provenance, expiry, and second-environment reproduction; no revisioned catalog exists | SRC-002/003/011/013 | **Tier 1** — regression risk: a report leaks proprietary content or personal data, or replays against stale revisions | 002, 003, 007, 024 · Compatibility |
| BPTK-029 | Use a supported engine-family adapter with user-owned asset kept separate | `bptk port --engine <engine> <asset>` | [BENCH-029](bench/roadmap/spec/bptk-029.json): verifies adapter contract, engine identity, native-module diagnosis, rights attestation, save, mod, input, network, package, and generic-core boundary; no approved adapter exists | SRC-008–011 | Tier 3 | 001, 003, 007, 021, 024 · Adapter |
| BPTK-030 | Know whether the same package is supported, degraded, or blocked in each declared browser | `bptk compatibility <package> --browser <profile>` | [BENCH-030](bench/roadmap/spec/bptk-030.json): runs one package identity across Chrome, Edge, Firefox, Safari, and selected mobile profile against predeclared threshold; no runnable matrix exists | SRC-003/009/016/018–028 | Tier 3 | 017, 024, 025, 027 · Quality |

### P3 exit gate

- Every required browser profile is supported, degraded, or blocked exactly as declared.
- Threaded deployment fails explicitly when cross-origin isolation is missing and selects the correct package otherwise.
- Network access requires consent and an allowlisted endpoint; offline behavior is deterministic.
- Compatibility observation can be reproduced without sharing proprietary content or personal data.
- One engine-family adapter passes while preserving separation between open engine and user-owned asset.

## P4 — Research modern-game expansion without promising it

P4 is evidence generation. Each item must result in a bounded implementation proposal, continued defer, or rejection.

| ID | Behavior | Surface | Benchmark | Source | Tier | Dependency · Owner |
|---|---|---|---|---|---|---|
| BPTK-031 | Learn whether an x86-64 game has a credible browser execution path | `bptk inspect <input> --target x86_64` | [BENCH-031](bench/roadmap/spec/bptk-031.json): measures address space, memory64, CPU, JIT, migration, and highest-risk prototype; no 64-bit architecture is measured | SRC-002/004/005/013/019 | Tier 3 | 023, 030 · Runtime research |
| BPTK-032 | Learn whether a D3D10/11 game has a credible WebGPU translation path | `bptk inspect <input> --target d3d11` | [BENCH-032](bench/roadmap/spec/bptk-032.json): prototypes the highest-risk DXGI, DXBC, resource, shader, and synchronization gap; no credible path exists | SRC-001/013/014/020 | Tier 3 | 020, 023, 030 · Graphics research |
| BPTK-033 | Get an evidence-backed stop, defer, or next-step decision for a modern game | `bptk inspect <input> --target modern` | [BENCH-033](bench/roadmap/spec/bptk-033.json): compares D3D12 and Vulkan-era requirement with current WebGPU and x86-64 result; no modern-API mapping exists | SRC-001/013–015/020 | Tier 3 | 030–032 · Architecture research |

### P4 exit gate

- Each report pins current browser and upstream revision and includes a reproducible prototype of the highest-risk gap.
- Promotion creates a new bounded implementation item and benchmark; research text alone cannot expand the support surface.
- A negative result is acceptable and preferred over a non-evidenced compatibility promise.

## Go, narrow, or stop decision

After P0, Maphy Technologies should make one explicit decision:

| Decision | Evidence condition | Consequence |
|---|---|---|
| Go, dual lane | Binary and source spike both pass within budget | Continue P1 binary and P2 source SDK in parallel |
| Narrow, source-first | Source passes; no legally usable binary option meets budget | Build workbench, analyzer, source SDK, package, and engine adapter; keep binary lane research-only |
| Narrow, classic binary | Binary passes; source UX is not differentiated | Focus PE32 through D3D9 and integrate existing source toolchain rather than own it |
| Stop runtime build | Neither spike meets the frozen correctness and performance budget | Publish the audit and avoid funding an unbounded compatibility rewrite |

## Risk register

| Risk | Leading indicator | Mitigation | Stop condition |
|---|---|---|---|---|---|---|
| BottleShip already occupies the binary niche | Its compatibility and contributor base outpace BPTK | Collaborate, contribute, fork only with differentiation, or focus workbench/source lane | BPTK adds no measurable user value beyond a rename |
| License graph blocks desired distribution | Core option requires incompatible copyleft or proprietary component | Decide license before code, isolate process boundary where valid, retain notice and source offer | No compliant combined architecture exists |
| Compatibility surface grows title by title | Missing API count rises without generic convergence | Corpus stratification, generic benchmark, reusable quirk policy, rejection ledger | P1 pilot needs pervasive title patch |
| Browser performance misses playability | CPU, frame, audio, memory, or startup budget fails repeatedly | Profile early, reuse proven JIT, reduce scope, source lane | No option meets BPTK-002 budget after P0 spike |
| WebGPU or thread deployment narrows reach | Required profile fails on a target browser | WebGL2 or single-thread profile where behavior is correct; explicit support floor | Required title class depends on unavailable feature with no safe fallback |
| User import creates security exposure | Parser crash, origin escape, network leak, or quota abuse | Threat model before importer, bounded parser, local-first, deny network by default | Critical boundary lacks a testable control |
| Asset and game rights are conflated with open engine code | Package or fixture includes restricted content | User-supplied local asset, separate distribution state, rights audit | Required public fixture cannot be lawfully distributed |
| Public name creates Apple confusion | User or press treats BPTK as Apple-affiliated | Independent brand and legal review before launch | Counsel finds unacceptable confusion risk |

## Documentation synchronization rule

When an item changes state, update all affected truth in one change:

- `bench/roadmap/manifest.json` and the owning benchmark spec;
- ROADMAP.md count, tier row, and exit gate;
- README.md current state and compatibility boundary;
- doc/TESTING.md gate command and coverage;
- doc/ARCHITECTURE.md if the component or lane changes;
- doc/legal-boundary.md and doc/source-audit.md when upstream or distribution state changes;
- CHANGELOG.md with the user-visible or engineering outcome.

Run `python3 tool/validate.py` before claiming the roadmap package is synchronized.
