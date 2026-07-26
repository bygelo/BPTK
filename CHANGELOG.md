# Changelog

All notable planning and implementation change will be recorded here.

## Unreleased

### Added

- Added `legal`, `corpus status`, `security`, and `inspect` as bounded local-analysis commands.
- Added safe path traversal with entry, depth, and file-size limits; symbolic-link roots are rejected and nested symbolic links are never followed.
- Added PE32, source-project, archive, installer-container, engine-asset, folder, and unknown-file classification without execution or upload.
- Added temporary-input Tier 1 checks for PE32 classification, source classification, and symbolic-link refusal without committed fixtures or retained results.
- Added `benchmark` with deterministic in-memory checks and no retained result artifact.
- Added `foundation compare` with measured input and local-toolchain signals.
- Added `port --source` diagnosis that reports missing Emscripten and browser-adapter work without treating a scaffold as a port.
- Added `run` PE32 mapping for bounded header, section, relocation, import-directory, TLS-directory, stack, heap, and entry-point inspection without guest execution.

### Changed

- Promoted BPTK-007 to implemented-but-red while its approval, corpus, foundation, and source-pipeline prerequisite remain red.
- Replaced the self-referential git revision in `data/status.json` with a deterministic manifest content revision so a product checkpoint remains valid before and after commit.
- Promoted BPTK-003 to implemented-but-red and expanded the exact dependency-free package inventory from 10 to 21 files.

### Known gap

- BPTK-001, BPTK-002, and BPTK-004 still require genuine named review; command output does not constitute approval.
- No input is executable through BPTK, and no game-runtime or browser-package behavior passes yet.
- Full SDL/OpenGL source output, i386 CPU behavior, Win32 import resolution, TLS callback execution, and game-loop execution remain weeks-scale.

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
