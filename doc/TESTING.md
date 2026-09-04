# Testing and compatibility evidence

## Current truth

BPTK has an opt-in deterministic i386 entry probe, a bounded installer extractor, and a declared resource-bound layer, not a supported Windows game runtime. The active repository gate validates the roadmap package, bounded local-analysis surface, Tier 1 safe inspector, the probe's explicitly supported integer behavior, and the extraction bound:

```sh
npm run gate
```

All 45 product benchmark specification remains red. BPTK-003, BPTK-007, BPTK-008, BPTK-009, BPTK-017, BPTK-037, BPTK-038, BPTK-039, BPTK-043, BPTK-044, and BPTK-045 are active and implemented-but-red; the other 34 are excluded. A red specification is not evidence that a capability passes.

The gate runs three independent layer:

1. `python3 tool/validate.py` checks the roadmap, legal boundary, package metadata, deterministic status snapshot, and exact allowlist.
2. `npm test` runs sixty-two Node.js test after checking the status snapshot against its content-addressed roadmap source.
3. `npm run check:package` asks npm for the dry-run tarball inventory and compares its identity and sorted path list exactly with `bench/npm/content.json`.

The GitHub workflow uses read-only repository permission, pins each external action to an immutable revision recorded in `doc/third-party.md`, and runs the same gate on Node.js 22 and 24 for every push and pull request. `npm ci --ignore-scripts` installs the dependency-free lockfile without executing package lifecycle code.

Five general CLI checks cover truthful help, deterministic status JSON, environment diagnostics, no-runtime disclaimers, and invalid-input failure. Three BPTK-007 checks generate temporary PE32, source-project, and symbolic-link input and remove it after the run. One BPTK-003 check exercises the in-memory benchmark and verifies that it cannot promote blocked work. Two packaging checks generate temporary content, verify shared HTML/React identity for BPTK-024, and verify off/consent report writes for BPTK-028. Two BPTK-026 checks generate a temporary package and prove that off denies and prompt requires consent with zero network attempts; they do not test a runtime bridge, so BPTK-026 stays excluded and red. Three boundary checks generate a temporary package, prove the save base stays read-only, reject a path-shaped save profile, and prove import stages and executes nothing; BPTK-015 and BPTK-016 stay excluded and red because persistence and a first playable do not exist. Seventeen runtime checks use disposable input and exercise the real `bptk run <package> --json` surface. They cover static backward compatibility, arithmetic/branch/call/return including `CALL ESP`, 32-bit carry, INC flag preservation, high-byte register access, self-modification, exact instruction budget, x87 structured stop, import/TLS refusal, fault-state rollback, oversized sparse executable and manifest refusal, symlink-manifest refusal, global import accounting, and repeated-state determinism. Five more runtime check cover the expanded bounded subset: shift and rotate count and carry, exact 32-bit multiply, structured divide_error, setcc comparison, deterministic rep movsb, and deterministic x87 double arithmetic. They protect the expanded probe without promoting BPTK-009, whose full FIX-002 instruction, FPU, exception, memory, oracle, corpus, and prerequisite contract remains red. The exact 35-file tarball is checked separately. Ten BPTK-038 and BPTK-044 extraction checks build faithful installer fixture in the temporary directory and exercise the real `bptk import` surface: an Inno Setup 6.3.0 unicode archive round trip through the CLI, a plan-only import that writes nothing, a stored-chunk extraction, a 16-bit setup-stub refusal, a decompression-bomb refusal at the declared amplification bound, an encrypted-chunk refusal, a checksum-mismatch refusal, a `{app}` escape refusal, an unsupported setup-data-version refusal, and an MSCF cabinet with stored and MSZIP folder. They protect the extractor and the declared bound without promoting corpus-wide correctness, which stays blocked on BPTK-002. BPTK-008 uses a Tier 3 written acceptance plus a live disposable A-J product walk through `bptk run`: preferred and relocated base, named and ordinal import binding, unresolved import reporting, TLS metadata without execution, stack/heap boundary, malformed header/section/import rejection, and deterministic repetition. Temporary input is removed and no baseline, reference map, or evidence JSON is retained. These checks execute only the declared probe subset; Five runtime service check extend the probe: RDTSC read advance exactly the declared cycle amount from one deterministic monotonic base and stay reproducible across run, every derived time source stays on the single base with the one-millisecond tick period, the 32-bit wrap, and the clamped delta, an execution manifest declaring host capability is refused as a containment-policy violation, and every probe run reports the denied capability set. Eight BPTK-037 and BPTK-043 census checks generate temporary PE32 and directory input and exercise the real `bptk inspect` surface: middleware import warning, clean handle routing, SafeDisc loader-string refusal, SafeDisc sibling refusal, proprietary-codec refusal, Build engine routing, id Tech 1 engine routing, and honest no-match reporting. They protect the census routing without promoting corpus-wide correctness, which stays blocked on BPTK-002. They do not execute a game or prove compatibility.

## Benchmark taxonomy

Every accepted roadmap item has exactly one JSON specification under `bench/roadmap/spec/` and one matching manifest entry.

Every runtime specification declares `threshold_owner: "BPTK-002"`. BPTK-002 owns the versioned corpus and the immutable numeric correctness, startup, frame, audio, memory, variance, and sample threshold. Runtime implementation may materialize those predeclared values only from the approved corpus version; it cannot set or relax them after observing its output. BPTK-002 declares `threshold_owner: "self"`; an evidence specification uses `null` unless it consumes the same corpus threshold.

### Tier 1 runnable acceptance

Only an item already assigned Tier 1 may add a release-blocking runnable check. Input is generated in an operating-system temporary directory or supplied live by the user. No baseline artifact, retained-evidence JSON, or golden fixture is committed.

- temporary generated or live user input;
- deterministic, bounded setup and action;
- observable output, hash, image, audio, trace, timing, or package;
- supported environment and tolerance;
- exact failure meaning.

### Tier 3 written acceptance

Tier 3 uses a written falsifiable acceptance line only. An ordinary unit test may protect shared engineering code but cannot promote a Tier 3 roadmap item or count as its acceptance evidence. A written acceptance specifies:

- required decision or audit artifact;
- primary source and pinned revision;
- alternatives and decision criterion;
- reviewer and expiry condition;
- exact missing evidence when red.

Research item uses the evidence taxonomy until it graduates into a runtime implementation item.

## Quarantine contract

A planned item must have:

- `state: "red"`;
- `gate: "excluded"`;
- a non-empty `exclusion_reason`;
- its prerequisite item;
- a mechanical `promotion_trigger`;
- an `expected_failing_assertion`;
- `owner_item` equal to its roadmap item;
- a valid `threshold_owner`, including explicit BPTK-002 ownership for every runtime item;
- `active_gate_evidence` naming the check that still protects the repository.

The validator rejects missing, duplicate, orphaned, prematurely active, or passing-without-implementation specification.

## Promotion rule

A Tier 1 benchmark moves into the active gate only in the same product-bearing change that adds its implementation and runnable check:

1. implement the roadmap deliverable;
2. generate bounded temporary input or use a live observation without committing a fixture;
3. run the check and verify the independent algorithmic or browser observation;
4. keep the result ephemeral rather than retaining a baseline or evidence JSON;
5. change the manifest `promotion_state` from `planned` to `implemented`;
6. change the specification `gate` to `active`; it stays red until the full acceptance and prerequisite pass;
7. increment `implemented` and `passing` count only when the active command passes;
8. update ROADMAP.md, README.md, CHANGELOG.md, and this document in the same change.

An implemented item with a failing benchmark remains implemented but not passing. A passing count cannot exceed implemented count.

## Input policy

The planning fixture catalog remains historical specification data and is not a product deliverable. Runnable Tier 1 input must be:

- generated in a temporary directory, supplied locally by the user, public domain, or explicitly redistributable;
- minimal enough to isolate one behavior;
- removed after the check unless it is the user's own input;
- free of commercial game code, asset, firmware, ROM, key, token, or credential;
- evaluated by an independent invariant or explicit live observation rather than a committed golden output;
- runnable without an external service unless the benchmark is specifically a network integration check.

Commercial title is metadata-only and user-supplied. A title observation can guide work but cannot become an automated fixture unless its rights permit it.

## Compatibility denominator

Two denominator must stay distinct:

1. **Roadmap denominator** — frozen at 59 raw candidate: 45 accepted, 8 rejected, and 6 deferred.
2. **Runtime corpus denominator** — not yet frozen; BPTK-002 must define it before any compatibility percentage is published.

Until BPTK-002 passes, the only valid coverage number is roadmap benchmark coverage: **0 / 45 (0%)**.

A future runtime corpus must stratify at least:

- PE architecture and compiler era;
- Win32 API family;
- GDI, DirectDraw, Direct3D 7/8/9 fixed-function, and Direct3D 9 shader path;
- audio API;
- file, registry, installer, and save behavior;
- source-assisted SDL/OpenGL path;
- browser and GPU capability profile;
- thread and network requirement;
- redistributable fixture versus local user title.

## Compatibility status

`compatibility_state` is monotonic only for one toolkit revision and environment:

| Compatibility state | Required behavior |
|---|---|
| `uninspected` | No parser result |
| `classified` | Safe inspector produced a complete report |
| `blocked` | Report names a specific unsupported requirement |
| `boots` | Deterministic first-frame or process-ready artifact |
| `interactive` | Input-to-output assertion passes |
| `playable` | Defined scenario completes inside performance and correctness threshold |
| `verified` | Reproduced on the declared browser/device matrix with artifact retained |

`evidence_state` records provenance separately:

| Evidence state | Required provenance |
|---|---|
| `reported` | Community or developer assertion without a retained BPTK run |
| `observed` | One retained BPTK run with environment and artifact |
| `reproduced` | Independent second run reproduces the result or explains an environment difference |
| `audited` | Required browser matrix and provenance review pass |

Marketing word such as “supported” must resolve to both state field plus environment and revision. A reported compatibility state is not a verified result.

## Planned gate shape

The implementation repository should eventually expose a single top-level gate that runs, in order:

```text
format -> static analysis -> unit -> fixture runtime -> browser matrix -> package audit -> roadmap validator
```

Browser test must record browser version, operating system, architecture, GPU adapter, WebGPU feature, WebGL extension, isolation header, memory limit, and artifact hash.

## Failure triage

A failing compatibility benchmark must identify one boundary:

- import parser;
- PE or source classification;
- CPU instruction or memory model;
- Win32 or COM API;
- graphics state, shader, format, or presentation;
- audio timing or format;
- file, registry, storage, or installer;
- browser capability or permission;
- thread, network, or host lifecycle;
- performance threshold;
- rights or provenance stop.

“Game does not work” is not an acceptable failure meaning.

## Planning validator scope

`tool/validate.py` currently checks:

- required planning file;
- canonical Apache-2.0 license text, Maphy copyright notice, and current no-third-party inventory;
- the public contribution policy and least-privilege GitHub Actions repository gate;
- strict JSON parsing;
- singular JSON key and directory naming;
- all 59 candidate identity, origin, unique dedupe key, decision, and accepted, rejected, or deferred target mapping;
- raw, accepted, rejected, deferred, implemented, and passing count;
- item and benchmark ID uniqueness;
- one benchmark per accepted item and no orphan specification;
- prerequisite reference and cycle;
- exact ROADMAP-to-manifest source-evidence scope for every item;
- precommitted numeric threshold ownership in BPTK-002 and explicit consumer reference;
- explicit BPTK-002 threshold ownership on every runtime specification;
- integrated P1 fixture ownership in BPTK-016 and shared binary/source package ownership in BPTK-024;
- red/excluded promotion semantics;
- source-evidence reference;
- local Markdown link target;
- synchronized compatibility and evidence state field plus the client-only game-execution boundary;
- absence of game binary while permitting only the exact reviewed JavaScript product, diagnostic, package-check, runtime, and test path; repository metadata under `.git` and local `node_modules` are excluded from content validation;
- dependency-free npm metadata, absence of install lifecycle script, Node.js engine floor, scoped public access, deterministic source snapshot, executable CLI mode, mandatory unsupported-game-runtime disclaimer, and exact tarball file manifest;
- absence of an unrestricted compatibility or completed-testing implication in README.md and ROADMAP.md.

The allowlist must be revised when implementation begins; doing so is part of BPTK-003, not a way to bypass the current gate.

## Validator self-test evidence

The planning gate was proved red-to-green on 2026-07-18:

1. baseline `python3 tool/validate.py` passed;
2. `owner_item` in `bptk-033.json` was temporarily changed from `BPTK-033` to `BPTK-032`;
3. the validator exited 1 with `BPTK-033 owner_item must equal item_id`;
4. the field was restored;
5. the full validator exited 0 and reported 33 accepted item, 0 implemented, 0 passing, and 33 quarantined red specification.
6. after the independent review, BPTK-001’s ROADMAP source cell was temporarily broadened beyond its manifest evidence; the validator exited 1 with `BPTK-001 ROADMAP source scope differs from manifest`;
7. after restoration, CAND-046 was temporarily pointed at an already-used deferred target; the validator exited 1 for the duplicate target, missing defer-ledger mapping, and count mismatch;
8. both mutations were restored and the expanded full validator exited 0 with the same 33/0/0 result.
9. `threshold_owner` in `bptk-012.json` was temporarily changed from `BPTK-002` to `null`; the validator exited 1 with `BPTK-012 runtime acceptance must consume the frozen BPTK-002 threshold`;
10. the field was restored and the full validator again exited 0 with the same 33/0/0 result.
11. the Maphy Technologies copyright holder in `NOTICE` was temporarily changed; the validator exited 1 with the missing licensing-statement error;
12. the notice was restored and the full validator again exited 0 with the same 33/0/0 result.
13. the version in `bench/npm/content.json` was temporarily changed from `0.1.0-alpha.0` to `0.1.0-alpha.1`;
14. the validator exited 1 with `bench/npm/content.json package identity differs from package.json`;
15. the package manifest was restored and the complete `npm run gate` passed with 33/0/0 roadmap truth, five passing CLI test, and the exact 10-file npm content report.

Every mutation was fully reverted. These checks prove that benchmark ownership, threshold ownership, source synchronization, denominator mapping, repository-license assertions, and npm package identity are live; they do not prove any future runtime benchmark.
