# Testing and compatibility evidence

## Current truth

BPTK has no game-runtime test because it has no game-runtime implementation. The active repository gate validates the roadmap package and the bounded npm diagnostic surface:

```sh
npm run gate
```

All 33 product benchmark specification is intentionally red and quarantined from the active gate. A red specification is a future acceptance contract, not evidence that a capability works.

The gate runs three independent layer:

1. `python3 tool/validate.py` checks the roadmap, legal boundary, package metadata, deterministic status snapshot, and exact allowlist.
2. `npm test` runs five Node.js CLI test after checking the status snapshot against its committed roadmap source.
3. `npm run check:package` asks npm for the dry-run tarball inventory and compares its identity and sorted path list exactly with `bench/npm/content.json`.

The GitHub workflow uses read-only repository permission, pins each external action to an immutable revision recorded in `doc/third-party.md`, and runs the same gate on Node.js 22 and 24 for every push and pull request. `npm ci --ignore-scripts` installs the dependency-free lockfile without executing package lifecycle code.

The npm tests prove only CLI and package behavior: honest default help, deterministic status JSON, bounded environment diagnostics, no-runtime disclaimers, invalid-input failure, and the intended 10-file tarball. They do not open a browser, read a game, test WebAssembly or GPU compatibility, or prove a roadmap capability.

## Benchmark taxonomy

Every accepted roadmap item has exactly one JSON specification under `bench/roadmap/spec/` and one matching manifest entry.

Every runtime specification declares `threshold_owner: "BPTK-002"`. BPTK-002 owns the versioned corpus and the immutable numeric correctness, startup, frame, audio, memory, variance, and sample threshold. Runtime implementation may materialize those predeclared values only from the approved corpus version; it cannot set or relax them after observing its output. BPTK-002 declares `threshold_owner: "self"`; an evidence specification uses `null` unless it consumes the same corpus threshold.

### Runtime benchmark

Use when a capability must execute code or transform an artifact. A runtime benchmark specifies:

- synthetic or redistributable fixture;
- deterministic setup and action;
- observable output, hash, image, audio, trace, timing, or package;
- supported environment and tolerance;
- exact failure meaning.

### Evidence check

Use when the item is a legal, research, architecture, governance, or integration decision that cannot honestly be represented as a runtime assertion. An evidence check specifies:

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

A benchmark moves into the active gate only in the same change that adds its implementation and fixture:

1. implement the roadmap deliverable;
2. add only redistributable or synthetic fixture;
3. run the benchmark and capture the expected red result before the fix where practical;
4. run it again after the fix and capture green evidence;
5. change the manifest `promotion_state` from `planned` to `implemented`;
6. change the specification `state` to `green` and `gate` to `active`;
7. increment `implemented` and `passing` count only when the active command passes;
8. update ROADMAP.md, README.md, CHANGELOG.md, and this document in the same change.

An implemented item with a failing benchmark remains implemented but not passing. A passing count cannot exceed implemented count.

## Fixture policy

The planning fixture catalog is at `bench/roadmap/fixture/catalog.json`. Future executable fixture must be:

- authored for BPTK, public domain, or explicitly redistributable;
- minimal enough to isolate one behavior;
- pinned by content hash and generator revision;
- free of commercial game code, asset, firmware, ROM, key, token, or credential;
- deterministic or supplied with an explicit tolerance;
- runnable without an external service unless the benchmark is specifically a network integration check.

Commercial title is metadata-only and user-supplied. A title observation can guide work but cannot become an automated fixture unless its rights permit it.

## Compatibility denominator

Two denominator must stay distinct:

1. **Roadmap denominator** — frozen at 46 raw candidate: 33 accepted, 8 rejected, and 5 deferred.
2. **Runtime corpus denominator** — not yet frozen; BPTK-002 must define it before any compatibility percentage is published.

Until BPTK-002 passes, the only valid coverage number is roadmap benchmark coverage: **0 / 33 (0%)**.

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
- all 46 candidate identity, origin, unique dedupe key, decision, and accepted, rejected, or deferred target mapping;
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
- absence of game binary and product runtime code while permitting only the exact reviewed JavaScript status, diagnostic, package-check, and test path; repository metadata under `.git` and local `node_modules` are excluded from content validation;
- dependency-free npm metadata, absence of install lifecycle script, Node.js engine floor, scoped public access, deterministic source snapshot, executable CLI mode, mandatory no-runtime disclaimer, and exact tarball file manifest;
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
