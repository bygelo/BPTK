# Roadmap rejection and defer ledger

The raw candidate denominator was frozen at 46 after deduplication on 2026-07-18. [The machine-readable candidate ledger](../bench/roadmap/candidate.json) maps every identity and dedupe key to one accepted, rejected, or deferred target. Thirty-three candidate were accepted into ROADMAP.md; every remaining candidate is explained here.

## Rejected candidate

### R-001 — Promise unrestricted execution

- Decision: Rejected
- Reason: “Any input runs” is neither technically credible nor benchmarkable. BPTK promises safe import and truthful classification, then measured execution coverage.

### R-002 — Copy Apple implementation, interface, or trade dress

- Decision: Rejected
- Reason: BPTK may learn from the evaluation-to-porting workflow, but must use independent source, name review, visual identity, documentation, and implementation.

### R-003 — Bundle commercial game, firmware, ROM, or proprietary runtime

- Decision: Rejected
- Reason: The project can ship only redistributable fixture and user-authored synthetic input. Player-owned asset remains local unless a separate right is documented.

### R-004 — Hide incompatibility behind game streaming

- Decision: Rejected
- Reason: Server-side native execution changes the product into a cloud gaming service and avoids rather than solves browser compatibility.

### R-005 — Circumvent DRM or kernel anti-cheat

- Decision: Rejected
- Reason: Browser architecture cannot reproduce kernel driver behavior safely, and circumvention creates unacceptable legal and security risk.

### R-006 — Make per-title patch the primary compatibility model

- Decision: Rejected
- Reason: Core change must implement generic API behavior or an evidence-backed reusable quirk. An isolated title patch is a last-resort adapter outside the core.

### R-007 — Treat React as the game execution target

- Decision: Rejected
- Reason: React is suitable for workbench UI and host lifecycle, not CPU execution, real-time rendering, audio mixing, or the game loop.

### R-008 — Lead with x86-64 and Direct3D 12

- Decision: Rejected
- Reason: Starting there multiplies CPU, memory, shader, GPU-capability, driver-model, and performance uncertainty before the simpler PE32 path proves product value. The capability remains P4 research.

## Deferred candidate

### D-001 — Full DOS, Win16, and Windows 9x system compatibility

- Decision: Deferred
- Revisit trigger: PE32 lane has a stable importer and a measured user demand that existing DOS or PC emulator cannot serve.

### D-002 — General .NET, WPF, and desktop application support

- Decision: Deferred
- Revisit trigger: game runtime reaches stable compatibility and a game-specific managed-runtime need is evidenced.

### D-003 — Privileged browser extension or native helper

- Decision: Deferred
- Revisit trigger: a required capability cannot be delivered through secure standard browser API and the distribution cost is justified.

### D-004 — Mobile performance as the first optimization target

- Decision: Deferred
- Revisit trigger: desktop Chrome, Edge, Firefox, and Safari profile has a reproducible first playable and mobile input benchmark is defined.

### D-005 — Hosted import processing or commercial cloud conversion

- Decision: Deferred
- Revisit trigger: local-first import proves insufficient, rights and privacy control are designed, and the cost model is independently validated.

## Count reconciliation

| State | Count |
|---|---:|
| Raw candidate | 46 |
| Accepted | 33 |
| Rejected | 8 |
| Deferred | 5 |
| Implemented | 0 |
| Passing | 0 |

The denominator changes only through a documented roadmap revision that adds a new raw candidate and classifies it in the same change.
