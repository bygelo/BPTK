# Changelog

All notable planning and implementation change will be recorded here.

## Unreleased

### Added

- Extended the Win32 core HLE (BPTK-010) with module loading and the memory/time probe: LoadLibraryA/W/ExW serve the declared known-DLL set with real refcount while a no-file-system refusal names any other DLL, FreeLibrary decrements honestly, IsBadReadPtr probes the guest range the way the real API does, Sleep advances the one guest clock only, GetThreadTimes reports deterministic thread time, and system DLL file names resolve to the declared system directory. Fourteen case bring the conformance suite to 147 over all 105 served export, and the real corpus coverage ledger rose from 93 to 100 covered symbol.
- Implemented the locale, codepage, and Unicode conversion slice of the HLE core (BPTK-103, now active red): one declared locale (LCID 0x0409) with ANSI/OEM code page 1252 carrying the real 0x80-0x9F best-fit table serves byte-exact MultiByteToWideChar and WideCharToMultiByte for 1252 and real UTF-8 (65001) both directions with the required-size and insufficient-buffer contracts, plus GetACP, GetOEMCP, GetCPInfo, IsValidCodePage, GetUserDefaultLCID, GetLocaleInfoW, CompareStringW with the equal/less/greater contract, LCMapStringW with real case mapping and sortkey honestly refused, GetStringTypeW with the real CTYPE1 classification, GetTimeZoneInformation at the declared UTC bias, and deterministic GetDateFormatW and GetTimeFormatW over a real SYSTEMTIME token formatter fed by the one guest clock. The double-byte fixture and locale enumeration stay red. 23 locale case bring the conformance suite to 133 over all 96 served export, and the real corpus coverage ledger rose from 79 to 93 covered symbol.
- Implemented the Win32 storage slice of the HLE core (BPTK-015, now active red): one bounded virtual drive in guest memory with real CreateFileW, ReadFile, WriteFile, SetFilePointerEx, SetEndOfFile, FlushFileBuffers, CloseHandle, GetFileType, SetStdHandle semantics and a declared output-only console (GetConsoleMode, GetConsoleCP, ReadConsoleW refused), plus an in-memory advapi32 registry hive under the real predefined roots with RegCreateKeyA, RegOpenKeyA, RegOpenKeyExW, RegQueryValueExA with the MORE_DATA contract, RegSetValueExA, and RegCloseKey; traversal and UNC fail closed, 26 storage conformance case cover the surface, the FIX-008 storage exerciser reaches a normal exit through its golden trace with hash-stable repeats, and the real corpus coverage ledger rose from 62 to 79 covered symbol. The copy-on-write overlay, quota transaction, reload persistence, and OPFS bridge stay red because the browser runtime host does not exist.
- Implemented the Win32 core HLE (BPTK-010, now active red): 67 kernel32 and ole32 export are real emulators over the guest memory model (process and module lookup, heap and virtual memory, time from the one monotonic clock, critical sections, TLS, lock-free list, pointer encoding, standard handle with bounded output capture, environment block, and the COM apartment trio), the probe dispatches guest import call through a bounded thunk page with stdcall frame and fault rollback, TLS callback fire before the entry as their own bounded phase, an image whose every import is served now executes end to end, a partially served image is refused with the exact unserved surface named, and the coverage ledger marks 62 of the real 356 corpus import covered (was zero). All 67 export carry conformance case and the FIX-003 exerciser reaches a normal process exit through its golden call trace.

- Implemented the empirical foundation (GS-104 through GS-107 as BPTK-083 through BPTK-086, now active red): `bptk corpus acquire` verifies the nine-entry lawful freeware manifest byte-stably against its pinned hash with payload staged outside the repository, `bptk corpus run` drives every entry through the real ingest and run path and records the reached stage with a named generic gap mapped to a roadmap item (the committed record and [the empirical report](doc/empirical-corpus-report.md) rank BPTK-031 six times, BPTK-010 twice, BPTK-007 once), `bptk corpus generalize` is the merge gate that refuses a single-beneficiary fix, and `bptk ingest` now stages plain zip payload under the declared bound with path-escape and encrypted-entry refusal.
- Recorded the prototype-or-defer research verdict for every promoted P4 item (BPTK-049, BPTK-057, BPTK-058, BPTK-060, BPTK-072, BPTK-073, BPTK-092, BPTK-145) in [the P4 deferral report](doc/research-p4-deferral.md): every verdict is defer with the evidence already in the repository and the named first prototype step; no verdict expands a support surface and every owning item stays planned and red.

- Implemented the authoring SDK semver contract and the hosting-constraint emission (GS-072, GS-065 as BPTK-116 and BPTK-109, now active red): the committed API manifest is compared against the live package entry exports in the planning gate, so removing or renaming an export fails the merge, and every host emission carries the declared cross-origin header set with the single-thread fallback.

- Implemented the graphics unification core (GS-018, GS-020, GS-022, GS-024, GS-025 as BPTK-059, BPTK-061, BPTK-063, BPTK-065, BPTK-066, now active red): one unified shader representation with exactly one WGSL emitter proven by a static audit in the planning gate, a Direct3D 9 pixel-shader frontend over the real token stream for the shader-model 2 and 3 arithmetic core that names an unsupported opcode instead of dropping it, one API-blind fixed-function generator where identical state yields identical output, a capability report derived from the compiled support table where an inflated advertisement fails by construction, and a frame-diff engine that computes its reference at test time with no committed baseline.

- Implemented the governance gate (GS-078, GS-081, GS-082 as BPTK-121, BPTK-124, BPTK-125, now active red): the planning validator now fails a default branch older than the declared 45-day window, refuses a merge that lowers the frozen test floor or lands an orphan runtime module, and fails a maintainer record missing the non-self review rule, the two-signer release rule, or the recovery drill; the maintainer record and the code-owner rule are repository surface.

- Implemented the conformance apparatus and the export-coverage ledger (GS-036, GS-041 as BPTK-076 and BPTK-081, now active red): one case-table format and oracle comparison engine where a zero-case export is a coverage hole, and `bptk corpus coverage` joins the real corpus import surface against the emulated symbol set — 356 imported symbol across the nine staged entry, every one honestly absent against the declared gap budget.

- Implemented the diagnose-and-route front door, the lane bundle envelope, the web-native ingest, and the honesty label (GS-043, GS-044, GS-048, GS-101 as BPTK-088, BPTK-089, BPTK-093, BPTK-129, now active red): the inspect surface returns a ranked lane decision with evidence-weighted confidence over the eight-lane taxonomy; the run surface loads a schema-2 lane bundle and refuses a lane that mismatches its payload; a web-native export stages only under a declared least-privilege capability manifest with any grant refused; and the run report carries the lane and accuracy label with an explicit not-a-playable-claim flag and the machine-readable unsupported set.

- Implemented the security layer and license graph (GS-084, GS-086, GS-088 through GS-091 as BPTK-127 and BPTK-130, BPTK-132 through BPTK-135, now active red): the protection census covers SafeDisc, SecuROM, LaserLock, StarForce, and Tages on documented static signature and the import boundary refuses a refused-route input before any artifact is written; a bounded pre-execution threat scan quarantines a known-bad input from every staging path; every packaged bundle carries the default least-privilege capability manifest and a declared grant is refused with the surfaced capability report; a bundle naming an absent lane is refused instead of mis-run; the trust tier grades input from byte and evidence alone with no silent upgrade; and the license graph resolves every declared component through one frozen disposition table, refusing unknown, unlicensed, and expired node.

- Recalibrated the declared extraction bound from the corpus finding: the amplification guard now carries an absolute floor (1 MiB) so a lawful small high-ratio entry is not refused, and `ratio_max` moves 32 → 64 with genuine bomb input near 1000:1 still refused and the total output bound unchanged.

- Ratified the gold-standard program into the roadmap: the execution-core pillar (GS-001–013) is promoted as planned red item BPTK-046 through BPTK-058 with benchmark specification BENCH-046 through BENCH-058 in [the promoted planned scope](ROADMAP.md#gold-standard-program--promoted-planned-scope). Promotion is a work-list contract, not implementation: every promoted row stays red and gate-excluded until its behavior lands.
- Ratified the graphics pillar (GS-018–034) as planned red item BPTK-059 through BPTK-075 with benchmark specification BENCH-059 through BENCH-075: one unified shader representation with a single emitter, the fixed-function generator, honest capability report, test-time frame reference, presentation, multisample, hostile-bytecode containment, pipeline cache, and the compute and console-framebuffer research pair.
- Ratified the ecosystem pillar (GS-078–085) as planned red item BPTK-121 through BPTK-128 with benchmark specification BENCH-121 through BENCH-128: the non-stale repository and reproducible release, the public tracker and database export, the ratcheting coverage bar, the multi-maintainer recovery mechanism, the unified contributor gate, the license and provenance graph, and governance of breaking change and analytics.
- Ratified the correctness and runtime-service pillar (GS-036–042, GS-104–108, GS-052–060) as planned red item BPTK-076 through BPTK-087 and BPTK-096 through BPTK-104: the generic conformance suite, captured trace corpus, rating ladder, deterministic reference, evidence-backed database row, export-coverage ledger, false-green self-audit, the real freeware executable corpus with its run harness and generalization gate, non-game program support, the time-travel debugger, and the positional audio, full input, storage, networking, full-motion video, Win32 breadth, optical drive, locale, and frame-pacing service.
- Ratified the lane pillar (GS-043–050, GS-101) as planned red item BPTK-088 through BPTK-095 and BPTK-129: the diagnose-and-route front door, the universal bundle envelope, source build autodetection, the engine-lane runtime host, the modern-PC research lane, web-native ingest, the pre-Win32 emulator lane, cross-lane fallback with recorded reason, and the lane and accuracy honesty label with its machine-readable unsupported set.
- Ratified the platform pillar (GS-061–067) as planned red item BPTK-105 through BPTK-111 with benchmark specification BENCH-105 through BENCH-111: compressed and range-based streaming with prefetch, the four-host embedding SDK, offline install, hosting-constraint automation, cross-title asset deduplication, and overlay-only cloud save synchronization.
- Ratified the library pillar (GS-068–076) as planned red item BPTK-112 through BPTK-120 with benchmark specification BENCH-112 through BENCH-120: the schema-gated catalog, instant-play hosting with grant-gated publication, bring-your-own local import, the first-party title whose run is its evidence, the authoring SDK with its semver contract, the community submission pipeline, the append-only preservation catalog, record-backed rating display, and mod overlay support.
- Ratified the security pillar (GS-086–091) as planned red item BPTK-130 through BPTK-135 with benchmark specification BENCH-130 through BENCH-135: per-lane confinement profile, cross-lane resource bound, named copy-protection refusal with a zero-artifact guarantee, pre-execution threat scan with quarantine, capability-manifest enforcement with consent, and the legal trust-tier boundary.
- Ratified the performance pillar (GS-092–098) as planned red item BPTK-136 through BPTK-142 with benchmark specification BENCH-136 through BENCH-142: the instruction-throughput floor, the recompile-over-interpret and native-fraction speedup, per-lane frame-time budget, cold and warm start budget, memory ceiling with boundary cost, audio and latency bound, and sustained-run stability.
- Ratified the accessibility and reach item (GS-099, GS-100, GS-102) as planned red item BPTK-143 through BPTK-145 with benchmark specification BENCH-143 through BENCH-145: runtime-level accessibility injection, shell conformance at the declared level, and the dead-live-service revival research lane.
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
