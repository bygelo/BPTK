# Roadmap benchmark package

This directory turns ROADMAP.md into a mechanically checkable contract. It does not contain a working BPTK runtime.

The separate [`bench/npm/content.json`](../npm/content.json) file freezes the bounded npm tarball surface. That packaging check is repository tooling and does not implement or promote any roadmap item.

## Layout

- `manifest.json` — canonical accepted item, dependency, source evidence, state, and denominator.
- `candidate.json` — all 46 raw candidate with origin, dedupe key, decision, and accepted, rejected, or deferred target.
- `spec/` — exactly one prewritten benchmark specification per accepted item.
- `fixture/catalog.json` — metadata for planned synthetic or redistributable fixture; no executable fixture is present yet.

All collection key remain singular by repository convention: `item`, `prerequisite`, `source_evidence`, `fixture`, `procedure`, and `pass_criterion` can each contain an array.

## Current state

- Accepted roadmap item: 33
- Planned and quarantined: 33
- Implemented: 0
- Passing: 0
- Active product benchmark: 0
- Active planning gate: `python3 tool/validate.py`

Every specification is red because its deliverable does not exist. Every specification is excluded from the active gate so the repository can remain green without pretending that future capability passes.

## Required specification field

| Field | Meaning |
|---|---|
| `benchmark_id` | Unique benchmark identity |
| `item_id` | Owning roadmap item |
| `kind` | `runtime` or `evidence` |
| `threshold_owner` | `BPTK-002` for every runtime specification, `self` for BPTK-002, otherwise `null` or `BPTK-002` for evidence |
| `state` | `red` until proven, then `green` only with passing evidence |
| `gate` | `excluded` while planned, then `active` with implementation |
| `exclusion_reason` | Why the active gate does not run it yet |
| `prerequisite` | Accepted item that must land first |
| `promotion_trigger` | Mechanical condition for activation |
| `expected_failing_assertion` | The precise reason it is red today |
| `owner_item` | Must equal `item_id` |
| `active_gate_evidence` | The current protection while quarantined |
| `fixture` | Fixture ID or evidence file |
| `procedure` | Reproducible action |
| `pass_criterion` | Observable success condition |

Every runtime golden, tolerance, performance budget, variance allowance, and sample requirement consumes the immutable threshold metadata frozen by BPTK-002. A later implementation may fill the predeclared keys from that versioned corpus; it may not choose an easier threshold after seeing an implementation result. Changing a threshold requires a new corpus version and an explicit denominator change record.

## Promotion

Do not merely edit a benchmark from red to green. Promotion is one atomic implementation change:

1. add the scoped implementation;
2. add the approved fixture content and license metadata;
3. prove the expected red failure where practical;
4. prove the green result;
5. activate the benchmark in the real gate;
6. retain artifact and environment metadata;
7. update the manifest count and synchronized documentation.

The validator rejects an active benchmark whose item is still planned, an orphan spec, a missing spec, a duplicate ID, an invalid dependency, or a count that was edited without the matching state change.

## Validation

Run from the repository root:

```sh
python3 tool/validate.py
```

The expected planning result is a pass reporting 33 accepted item and 33 quarantined red specification.
