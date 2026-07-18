# Changelog

All notable planning and implementation change will be recorded here.

## Unreleased

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

### Clarified

- “Import broadly” means safe classification and a compatibility report; it is not a claim that every Windows binary runs.
- React is an optional host adapter, while WebAssembly, canvas, WebGPU or WebGL, WebAudio, and browser storage form the execution surface.

### Known gap

- No runtime implementation, executable fixture, browser package, or compatibility result exists yet.
- The future runtime component graph, upstream reuse strategy, and public product name remain P0 decisions; the current planning repository is Apache-2.0.
