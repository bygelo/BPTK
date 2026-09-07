# Why `passing` is 0 — the audit

`bptk status` reports **145 accepted / 101 implemented / 0 passing**. Zero is
easy to read as neglect. It is not: it is the correct value, and this file
records the per-item reason so a later session does not re-derive it, or worse,
"fix" it by promoting a row.

## How a row reaches `passing`

`tool/validate.py` enforces two rule and executes **no** benchmark:

1. a `passing` item must have a spec whose `state` is `green` and whose `gate` is
   `active`; and
2. **every prerequisite of a `passing` item must itself be `passing`.**

So `green` is a declaration backed by evidence a human or agent asserts. Rule 2
is what makes the count structural rather than per-item.

## The blockade

Computing the transitive prerequisite closure over all 145 item, plus each
spec's `threshold_owner`:

- **126 of 145 spec** name **BPTK-002** (*freeze a representative compatibility
  corpus*) as their `threshold_owner`. BPTK-002 is `planned`.
- BPTK-002's own prerequisite is **BPTK-001** (*approve outbound license posture
  and upstream reuse strategy*), also `planned`.
- BPTK-001 is an **approval**. ROADMAP.md states the rule directly: command
  output cannot manufacture approval.

So the count is gated on one human decision, and no amount of engineering moves
it.

## The five item NOT behind that chain

Exactly five implemented item have no blocking prerequisite and no blocking
threshold owner. Each is red for a substantive reason:

| Item | Title | Why it is honestly red |
| --- | --- | --- |
| BPTK-060 | DXBC/DXIL frontend | The container is read and the opcode surface enumerated, but **no Direct3D 10-12 program is lowered** into the unified representation. P4 research. |
| BPTK-072 | Console framebuffer resolve | The tile resolve round-trips a fixture in software; **measuring on the live adapter set does not run in the gate**. P4 research, verdict *defer*. |
| BPTK-073 | Compute and modern shader | The compute prototype computes a software reference; **bit-identity on the live adapter set is not measured**. P4 research, verdict *defer*. |
| BPTK-122 | Public issue tracker | **Two independent blocker**: no public issue template exist (`.github/ISSUE_TEMPLATE` is absent), and — the deeper one — `lib/doctor.mjs` returns the blocker *"no runtime reproduces the compatibility claim"* on every accepted report. See the note below. |
| BPTK-125 | Bus-factor removal | The two-signer release rule is enforceable only with **a second maintainer** and branch protection. Organizational, not code. |

### BPTK-122, examined closely, because it looked promotable

It is the one row that looked like it could go green today, and it is worth
recording why it cannot, so the next session does not re-open it.

It has **no prerequisite and no threshold owner**, so the BPTK-001 chain does not
reach it. Its two pass criterion are "bare report is rejected" and "complete
report is accepted and triaged within the level", and `test/governance.test.mjs`
genuinely asserts BOTH through the real CLI, not a mock: a bare report exits 1
with `is_accepted false`, and a complete one exits 0 with `is_triaged_within_level
true` and `triage_latency_hour <= triage_freshness_hour`. Its promotion trigger
also reads satisfied on both halves.

**It is still red, and correctly.** The deliverable is *public* issue and
compatibility tracker **templates**, and there are none: `.github/ISSUE_TEMPLATE`
does not exist and no repository document names a tracker. The gate proves the
report-validation LOGIC; it does not run a public tracker. Promoting on the
strength of a passing shape-validation test would be precisely the false green
this gate exists to stop — the behaviour a user would get does not exist.

**Correction, on a closer read.** An earlier revision of this file said the
missing template were "the real reason" and that the gap was closable without an
owner decision. That was wrong on the second half. `lib/doctor.mjs` already
declares `triageFreshnessHour = 72` and calls it the *published* level, so
publishing is not the gap — and every accepted report carries the blocker
*"The report maps to a tracker entry within the published freshness level, but no
runtime reproduces the compatibility claim."* The implementation states its own
obstacle: a tracker entry is only compatibility EVIDENCE if some runtime can
reproduce the claim, and no supported title runtime exists (which is what
`passing 0` means elsewhere in this ledger).

So the two blocker are independent, and adding issue template would close only
the shallower one. The item stays red until a supported runtime can reproduce a
tracked claim — which is not a template, a policy statement, or an owner
decision, but the product itself.

Three are P4 research carrying an explicit *defer* verdict in
[the P4 deferral record](research-p4-deferral.md); the roadmap's own instruction
is to leave research honestly red. One needs a runtime that does not exist. One
needs a second person.

## What would actually move the number

- **BPTK-001** — an owner decision on license posture. Releases the 126-item chain.
- **BPTK-125** — a second maintainer with branch protection configured.
- **BPTK-060 / 072 / 073** — real prototype work (lower a D3D program; run the
  tile and compute fixture on a live adapter through the graphics doctor's
  observed set), each of which is a genuine research step, not a wiring gap.

Until one of those happens, **0 is the honest number** and promoting any row
would be the false green this project's whole gate exists to prevent.
