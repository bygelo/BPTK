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
| BPTK-122 | Public issue tracker | Reproducing a tracked compatibility claim **needs the absent browser game runtime**. |
| BPTK-125 | Bus-factor removal | The two-signer release rule is enforceable only with **a second maintainer** and branch protection. Organizational, not code. |

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
