<!--
Copyright 2026 Maphy Technologies
SPDX-License-Identifier: Apache-2.0
-->

# WASM-tier eligibility — the instrument and the Chocolate Doom baseline

## Why this file exists

"Measured, not assumed" is this repository's whole discipline, and one number was
breaking it. The fraction of a real binary's function entries that the WASM
recompilation tier can compile — the number driving the recompiler roadmap — was
being quoted from session memory (14.2%, then 8.7%) with **no committed way to
recompute it**. Every other claim here has a benchmark behind it. This one now
has an instrument behind it.

## The instrument

`tool/eligibility.mjs`. Zero dependency, Node built-in only.

```
node tool/eligibility.mjs <path-to-pe32plus> [option]

  --json                  machine-readable report on stdout
  --solely <reason,...>   how many function are blocked SOLELY by that reason
                          set, and the resulting ceiling (repeatable)
  --base <hex>            requested load base (default: the image base)
  --limit <count>         stop after this many candidate entry
  --help                  usage
```

The baseline recomputation, exactly:

```
node tool/eligibility.mjs <corpus>/chocolate-doom.exe
node tool/eligibility.mjs <corpus>/chocolate-doom.exe --json > eligibility.json
node tool/eligibility.mjs <corpus>/chocolate-doom.exe --solely rotate_rol,rotate_ror
```

The reason name a `--solely` query takes are the ones the run's own histogram
prints — they are `lib/wasm64.mjs` `coverage.unsupported[].reason` verbatim, so
they move as the codegen moves. The indirect-branch ceiling query that predicted
38.7% was `--solely control_call_indirect,control_jmpIndirect`; at the current
tip those two reasons no longer occur at all, because an indirect `jmp`/`call`
now compiles as a return-to-dispatch terminator.

A missing, unreadable or non-PE32+ input is a named error on stderr and **exit
2** — never a stack trace. Exit 0 means a measurement was produced.

### Method

1. `lib/pe64.mjs` `mapPe64State` maps the file to its loaded image bytes
   (sections placed, relocation applied, imports parsed, nothing executed).
2. **Candidate function entries are discovered generically.** The instrument
   sweeps every executable section for a direct `call rel32` (opcode `0xE8`) and
   keeps each computed target that also lands inside an executable section, plus
   the PE entry point itself. No per-title knowledge, no hardcoded address, no
   symbol table. The bias is a property of the instrument and is stated up front:
   it **over-reads** (a `0xE8` byte inside a longer instruction or inside inline
   data can yield a plausible target) and it **under-reads** (a function only ever
   reached indirectly is never seen). It is reproducible on any PE32+.
3. Each entry is compiled by `lib/wasm64.mjs` `compileFunction` over
   `lib/lift64.mjs` `decodeStructured`, under exactly the conditions
   `lib/tier.mjs` uses to pick a tier: every **other** candidate entry marked
   external with a dummy host callback bound, so a plain direct call to a
   neighbouring function is an import boundary rather than a rejection.
   `compiled.complete === true` is the verdict.
4. The rejection histogram counts **once per function per distinct reason**, from
   the set of `compiled.coverage.unsupported[].reason`. A function blocked on one
   path by a rotate and on another by an unmodelled opcode contributes to
   **both**. Counting only the first reason materially understates overlapping
   blockers, and doing so is how an earlier ad-hoc measurement misled its reader.
   The reason percentages therefore sum to **more than 100%** by construction.
5. `--solely` reports how many rejected functions carry **nothing but** the named
   reason set, and the eligibility that would result if that blocker set alone
   were solved. That ceiling — not the raw histogram share — is the number that
   predicts the win.

## The Chocolate Doom baseline

Measured by the maintainer on the machine where the corpus is staged (the corpus
is never committed to this repository; see `doc/legal-boundary.md`).

| Measurement | Candidate entry | Eligible | Eligible share |
| --- | --- | --- | --- |
| Before indirect-branch support | 1304 | 113 | **8.7%** |
| After indirect-branch support | 1304 | 505 | **38.7%** |

The 38.7% was **predicted before it was implemented**: `--solely` over the
indirect-branch reason set reported that ceiling, and the landed implementation
hit exactly it. That is the instrument earning its place — a ceiling query that
turned out to be a forecast, not a retrospective.

### Remaining rejection reason, in order

Share of the **799 rejected** function entries, counted once per function per
distinct reason (so the column exceeds 100% — overlapping blockers are the norm,
not the exception).

| Reason | Share of rejected entry |
| --- | --- |
| `not_served` | 47.5% |
| `unsupported_op` | 36.7% |
| `imul64_overflow` | 15.6% |
| `rotate_rol` | 4.6% |
| `rotate_ror` | 0.8% |

Read that as a work queue: `not_served` and `unsupported_op` are the decode/emit
frontier and dominate; the arithmetic blockers (`imul64_overflow`, the two
rotates) are small, bounded and individually cheap. Run `--solely` per candidate
group before building any of them — the histogram share is an upper bound on a
blocker's value, never its actual ceiling, because a function carrying two
reasons is not unblocked by fixing one.

## Scope — what this number is NOT

**Eligibility is a codegen measurement.** It says only that
`compileFunction` can emit a whole function without hitting a fallback. It is:

- **not correctness** — an emitted function is not thereby proven bit-exact;
  that proof is `test/tierrun.test.mjs` and `doc/lane-bd-log.md`;
- **not a run** — nothing here executes a guest instruction;
- **not playability** — no frame is drawn, no input served, no title completed.

The corpus **`passing` count stays 0**, before and after this instrument, and
nothing in this file changes it. The tool prints this same note in its own
output so a pasted result cannot be read as a compatibility claim.

## Gate-surface registration

A new `.mjs` anywhere the validator scans must be registered, or `npm run gate`
fails. For `tool/eligibility.mjs` that is:

- `tool/validate.py` `ALLOWED_MJS_PATH` — otherwise "JavaScript file is outside
  the approved npm tooling surface".
- `tool/validate.py` `REQUIRED_PATH` — the instrument is now a required file, so
  deleting it is a gate failure rather than a silent loss.
- **Not** the reviewed-tarball manifest (`bench/npm/content.json` and the
  `expected_file` list beside it). This was checked empirically, not assumed:
  `package.json` `files` publishes `bin`, `data`, `lib`, `LICENSE`, `NOTICE` and
  `README.md` only, and that list is frozen by the validator. Adding a `tool/`
  path to the manifest makes `npm run check:package` fail with "package content
  differs from bench/npm/content.json", because `npm pack` never contains it.
  `script/package.mjs` and `script/status.mjs` are absent from that manifest for
  the same reason. A future instrument that must ship to npm consumers belongs
  under `lib/`, and then all three places apply.

`npm run gate` → exit 0 with the instrument committed and registered.
