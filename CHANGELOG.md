# Changelog

All notable planning and implementation change will be recorded here.

## Unreleased

### Added

- Added `bptk ingest <input> --output <dir>` (and its plan-only form): one command accepts any executable input, classifies and census-routes it, extracts a supported installer payload, packages any plain PE into a synthesized bundle manifest, reports bounded-probe eligibility, and refuses DOS, 16-bit, and archive input with structured reason. Ingestion never executes the input.
- Added the static recompilation fourth lane to `bptk foundation compare` (BPTK-036) with an honest unavailable signal, and a dated no-marketing feasibility note recording the N64Recomp, PSXRecomp, and XenonRecomp prior art, the reusable foundation, and the missing evidence behind the deferral.
- Expanded the bounded i386 probe (BPTK-009): shift and rotate group with exact count and carry behavior, multiply and divide with exact 64-bit intermediate and structured divide_error, two-operand IMUL, setcc, string operation with bounded REP/REPE/REPNE and CLD/STD direction control, and a 64-bit precision x87 subset covering load, store, integer conversion, arithmetic, compare, and control-word service; everything outside the subset stays a structured unsupported stop.
- Added the one monotonic guest clock (BPTK-039): QPC, RDTSC, GetTickCount, timeGetTime, and vertical-blank derivation all read one monotonic base with the one-millisecond tick period, the 32-bit wrap, and a clamped delta so a stalled reader neither jumps ahead nor runs at double speed; the probe serves guest RDTSC deterministically from that base through `bptk run`.
- Added the declared guest containment policy (BPTK-045): the probe confines guest memory to the mapped image and bounded stack, denies host script, file system, network, process, and device capability by absence, reports the policy on every run, and refuses an execution manifest that declares capability outside the policy.
- Added the static middleware, copy-protection, and engine census (BPTK-037 and BPTK-043): `bptk inspect` routes middleware import and SafeDisc loader evidence into handle, warn, extract, or refuse, and fingerprints id Tech 1, id Tech 2, Build, SCUMM, Sierra AGI, and Sierra SCI assets to their named open reimplementation without bundling engine or game code. Proprietary Indeo and WMV codec evidence refuses like the video posture.
- Added `bptk import <input>` installer extraction (BPTK-038): the bounded extractor unpacks the pinned Inno Setup 6 unicode family and an MSCF cabinet with stored or MSZIP folder to a declared output directory, refuses a 16-bit setup stub, an encrypted or BZip2 or LZMA chunk, a checksum mismatch, and a payload path escape, and never executes installer code. Plan-only import reports the payload without writing.
- Added the declared resource-bound layer (BPTK-044): one frozen bound caps decompressed output, amplification ratio, entry count, nesting depth, and compressed chunk read for extraction, and the probe enforces the declared instruction budget; a decompression bomb is refused before its output is allocated.
- Added `legal`, `corpus status`, `security`, and `inspect` as bounded local-analysis commands.
- Added safe path traversal with entry, depth, and file-size limits; symbolic-link roots are rejected and nested symbolic links are never followed.
- Added PE32, source-project, archive, installer-container, engine-asset, folder, and unknown-file classification without execution or upload.
- Added temporary-input Tier 1 checks for PE32 classification, source classification, and symbolic-link refusal without committed fixtures or retained results.
- Added `benchmark` with deterministic in-memory checks and no retained result artifact.
- Added `foundation compare` with measured input and local-toolchain signals.
- Added `port --source` diagnosis that reports missing Emscripten and browser-adapter work without treating a scaffold as a port.
- Added `run` PE32 mapping for bounded header, section, relocation, import-directory, TLS-directory, stack, heap, and entry-point inspection without guest execution.
- Added deterministic PE32 static-image resolution for declared named and ordinal import, bounded TLS callback metadata, executable entry-point validation, and precise malformed-range rejection through `bptk run`.
- Added `doctor --graphics`, which launches the installed Chrome against an ephemeral data document and observes WebGPU, WebGL2, WebGL, AudioContext, isolation, SharedArrayBuffer, and renderer state.
- Added atomic content-addressed asset packaging with one-megabyte chunk deduplication and no bundled game runtime.
- Added HTML and React host source that preserves one package identity without moving a game loop into React.
- Added local report modes where `off` writes nothing and `consent` writes one privacy-minimized package/environment report.
- Added package-integrity performance timing without presenting asset I/O as game-runtime performance.
- Added live isolation-based thread selection, zero-attempt network policy, and local control-profile validation.
- Added safe engine-adapter diagnosis that copies no asset without rights and adapter approval.
- Added browser-profile diagnosis that observes installed Chrome while refusing compatibility claims without a game runtime.
- Added temporary-package Tier 1 checks proving network off and prompt modes make zero attempts.
- Added read-only save-boundary diagnosis with strict profile validation and no fabricated persistence.
- Added safe import-and-run diagnosis that neither stages nor executes an asset package.
- Added bounded x86-64, D3D11, and modern research surfaces that combine input signal with live browser capability and return an explicit defer decision.
- Added temporary-package Tier 1 checks for save path refusal and import non-execution.
- Added an opt-in `i386_probe_v1` package profile that deterministically runs a bounded integer instruction subset at the mapped PE32 entry point with structured stop state.
- Added disposable real-CLI regression checks for arithmetic and flag behavior, branch and call flow, memory access, self-modification, exact instruction budget, deterministic state, unsupported x87, import and TLS refusal, and memory fault.
- Added instruction-atomic fault rollback, faulting-address diagnostics, bounded no-follow executable and package-manifest reads, and one global import-entry allocation budget.

### Changed

- Promoted BPTK-007 to implemented-but-red while its approval, corpus, foundation, and source-pipeline prerequisite remain red.
- Replaced the self-referential git revision in `data/status.json` with a deterministic manifest content revision so a product checkpoint remains valid before and after commit.
- Promoted BPTK-003 to implemented-but-red and expanded the exact dependency-free package inventory from 10 to 21 files.
- Promoted BPTK-017 to implemented-but-red and expanded the exact dependency-free package inventory to 22 files.
- Expanded the exact dependency-free package inventory to 24 files; packaging and report surfaces remain red until their runtime prerequisite exist.
- Expanded the exact dependency-free package inventory to 27 files; platform diagnostics remain planned and red until their runtime prerequisite exist.
- Expanded the exact dependency-free package inventory to 30 files; save, integration, and research behavior remain red until their execution or prototype prerequisite exist.
- Promoted BPTK-008 to implemented-but-red after its disposable A-J product walk passed; foundation, importer, and approved corpus evidence remain red.
- Expanded the exact dependency-free package inventory to 32 files for the i386 probe checkpoint; BPTK-009 remains planned, excluded, and red.

### Known gap

- BPTK-001, BPTK-002, and BPTK-004 still require genuine named review; command output does not constitute approval.
- No Windows game is executable through BPTK, and no game-runtime or browser-package behavior passes yet; only an explicitly selected, import-free, TLS-free integer entry probe executes guest instruction.
- Full SDL/OpenGL source output, complete i386 and FPU behavior, Win32 API behavior behind declared import binding, TLS callback execution, and game-loop execution remain weeks-scale.
- The current Chrome profile exposes WebGL2 but lacks cross-origin isolation; Firefox and the remaining declared browser profile have not been observed.
- The live matrix walk observed Chrome 150 as WebGL2-only and unisolated, found Safari installed but unautomated, and found Firefox absent; no browser support state is claimed.

## 0.1.0-alpha.0 — 2026-07-19

### Added — 2026-07-18

- Established BPTK as a proposed Maphy Technologies browser-porting workbench.
- Added a fresh prior-art and browser-constraint audit with pinned upstream revision.
- Added an architecture covering binary, source-assisted, and engine-adapter lane.
- Added the legal and distribution boundary that separates technical feasibility from permitted reuse.
- Added a five-tier roadmap with 33 independently testable item.
- Added one quarantined red benchmark specification for every accepted roadmap item.
- Added a standard-library validator for count, dependency, benchmark, link, promotion, naming, and planning-scope integrity.
- Proved the validator red-to-green with a temporary benchmark-owner mismatch and restored the valid state.
- Added the complete 46-candidate origin and deduplication ledger and made the validator reconcile it with every accepted, rejected, and deferred target.
- Added authoritative browser evidence for autoplay, OPFS quota and eviction, file access, worker CSP, fullscreen, pointer lock, gamepad, and WCAG 2.2.
- Added precommitted numeric-threshold ownership to BPTK-002, an integrated P1 first-playable fixture to BPTK-016, and a shared binary/source package gate to BPTK-024.
- Separated compatibility state from evidence provenance and made client-side imported-game execution an explicit product boundary.
- Added validator checks for ROADMAP source scope, candidate deduplication, threshold consumer, and integration-gate ownership.
- Proved the new source-scope and candidate-target checks red-to-green with temporary mutations and restored the valid state.
- Made BPTK-002 threshold ownership explicit on every runtime specification and added a red-to-green validator mutation proving the rule is enforced.
- Clarified that runtime specifications are future acceptance contracts, not executable benchmark evidence until their runner and fixture land.

### Added — 2026-07-19

- Licensed BPTK-authored repository material under Apache-2.0 and added the Maphy Technologies `NOTICE`.
- Added a third-party inventory and incorporation rule that prevents the project license from being misapplied to upstream component or user-supplied game content.
- Updated BPTK-001 truthfully: repository licensing is recorded, while runtime-component and public-name approval remain open.
- Added contribution licensing and provenance rules for public pull requests.
- Added a least-privilege GitHub Actions workflow for the planning validator with immutable CI-tool pins and provenance.
- Added the public, dependency-free `@bygelo/bptk` roadmap-tooling package with `status`, `doctor`, and library export.
- Added five Node.js CLI test covering truthful default help, deterministic status JSON, bounded diagnostics, text disclaimers, and invalid input.
- Added an exact 10-file npm tarball manifest that excludes source script, test, benchmark material, and `package-lock.json` from distribution.
- Extended the repository gate across Node.js 22 and 24 while retaining the Python roadmap validator.
- Recorded the scoped package-name permission separately from the still-open runtime and public-product-name review.
- Published the pre-alpha on `next`; npm also assigned `latest` during the first package publication, and an authenticated removal returned `400 Bad Request`. Both currently resolve to the exact alpha while installation documentation remains version-pinned.

### Clarified

- “Import broadly” means safe classification and a compatibility report; it is not a claim that every Windows binary runs.
- React is an optional host adapter, while WebAssembly, canvas, WebGPU or WebGL, WebAudio, and browser storage form the execution surface.

### Known gap

- No runtime implementation, executable fixture, browser package, or compatibility result exists yet.
- The future runtime component graph, upstream reuse strategy, and public product name remain P0 decisions; the current planning repository is Apache-2.0.
- The first npm release is published through the local npm CLI with account 2FA; registry provenance attestation is deferred until an OIDC trusted-publishing workflow is reviewed.
