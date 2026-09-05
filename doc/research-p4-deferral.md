# P4 research verdicts — prototype or defer

Status: **defer recorded with first-prototype step**, 2026-09-05. The P4 item are
evidence generation: each must end in a bounded implementation proposal, a
continued defer, or a rejection, and a negative result is acceptable and
preferred over a non-evidenced compatibility promise. No prototype was built in
this pass, so every verdict below is **defer** — recorded honestly with the
evidence already in the repository and the named first step a prototype must
take. None of these verdict expands a support surface, and every owning item
stays planned and red in the manifest.

## BPTK-049 — x86-64 recompilation feasibility (GS-004)

Verdict: **defer**. The bounded i386 translator experience, the static
recompilation prior art ([research-static-recomp.md](research-static-recomp.md)),
and the memory64 WebAssembly survey
([research-2026-wasm-native.md](research-2026-wasm-native.md)) are recorded, but
no 64-bit fixture recompiled and no x64 reference comparison exists. First
prototype step: recompile the 64-bit research fixture's arithmetic subset and
compare general-purpose register state against an x64 reference interpreter
under FIX-024.

## BPTK-057 — PowerPC console lane (GS-012)

Verdict: **defer**. The Xenon desktop-only prior-art result is recorded with its
date in the static-recompilation research note; no PowerPC prototype exists.
First prototype step: recompile one PowerPC arithmetic fixture and compare
against a reference emulator trace, with console-specific hardware difference
left out of scope until the arithmetic core matches.

## BPTK-058 — MIPS console lane and the PS2 gap (GS-013)

Verdict: **defer**. No MIPS fixture or reference-emu comparison exists. First
prototype step: select a N64 fixture with a reference emulator trace, recompile
its arithmetic subset, and pin the PS2 VU/GS gap as a separate item or an
explicit deferral.

## BPTK-060 — DXBC and DXIL frontend research (GS-019)

Verdict: **defer**. The unified representation, the single WGSL emitter, and the
named-opcode refusal discipline exist for the Direct3D 9 arithmetic core; the
DXBC and DXIL reader prototype over the DXVK, dxil-spirv, and Tint prior-art
chain does not. First prototype step: decode one DXBC byte stream through the
same opcode-coverage-table discipline the Direct3D 9 frontend uses, naming every
unsupported opcode.

## BPTK-072 — embedded-memory framebuffer research (GS-031)

Verdict: **defer**. No tile-resolve prototype exists. First prototype step:
implement the tile resolve for one research fixture over the live WebGPU
adapter set the graphics doctor already observes, and measure desktop-only
portability.

## BPTK-073 — compute and modern shader research (GS-032)

Verdict: **defer**. The unified representation covers the fragment arithmetic
core only; no compute prototype exists. First prototype step: run one compute
fixture bit-identically on the declared adapter set and record the above-limit
blocking matrix.

## BPTK-092 — modern-PC lane mapping (GS-047)

Verdict: **defer**. The modern-API scan reports DXGI, D3D11, and DXBC signal
with live WebGPU observation, and the composed decision requires one hard
mapping prototype. First prototype step: prototype the Direct3D 11 constant
and descriptor mapping onto the unified representation on a research fixture,
and measure the result before any lane claim.

## BPTK-145 — live-service revival research (GS-102)

Verdict: **defer**. No capture hook or service stub exists, and the hard rail
holds: a stub never contacts the live service. First prototype step: record the
protocol of a lawfully owned, already-shutdown service from captured traffic,
implement the local stub offline, and prove the stub never opens a socket.

## Boundary statement

Every verdict here is a research record, not a capability claim. Promotion of
any item creates a new bounded implementation item and benchmark; research text
alone cannot expand the support surface, and the manifest remains the source of
promotion state.
