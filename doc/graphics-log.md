# Graphics lane log (Pillar 2 — one unified graphics layer)

Branch `lane/graphics`, off `build/product-first` @ 11afff3. The verifier is
`npm run gate` (exit 0 after every commit). Honesty rail: `passing` stays **0**
— every item is `implemented` (real code + an active red acceptance contract);
each spec states it is red because a live GPU adapter (or a live-adapter
measurement) does not run in the offline gate.

## Scope status — COMPLETE

All twelve graphics-pillar items are implemented with an active red contract.
`npm run gate` exits 0 at 145 accepted / 51 implemented / 0 passing.

| Item | GS | Tier | State | What landed |
|------|----|------|-------|-------------|
| BPTK-059 | GS-018 | T1 | implemented (pre-existing) | One unified IR, one WGSL emitter, D3D9 SM2/3 frontend |
| BPTK-063 | GS-022 | T1 | implemented (pre-existing) | API-blind fixed-function generator |
| BPTK-065 | GS-024 | T1 | implemented (pre-existing) | Honest caps (advertise ≤ compiled support) |
| BPTK-066 | GS-025 | T1 | implemented (pre-existing) | Frame-diff, test-time reference, no committed golden |
| BPTK-064 | GS-023 | T1 | implemented (this lane) | Projective texgen/shadow; projection divide fails closed |
| BPTK-067 | GS-026 | T1 | implemented (this lane) | WebGPU primary backend: IR→pipeline description |
| BPTK-068 | GS-027 | T2 | implemented (this lane) | WebGL2 GLSL ES 3.0 fallback; above-floor named-blocked |
| BPTK-069 | GS-028 | T2 | implemented (this lane) | WebGPU compatibility mode; out-of-subset caught at emit |
| BPTK-074 | GS-033 | T1 | implemented (this lane) | Hostile-bytecode containment (DarthShader class) |
| BPTK-060 | GS-019 | P4 | implemented (this lane) | DXBC/DXIL prototype: named-opcode coverage table |
| BPTK-072 | GS-031 | P4 | implemented (this lane) | EDRAM tile-resolve prototype (round-trips to linear) |
| BPTK-073 | GS-032 | P4 | implemented (this lane) | Compute/UAV dispatch prototype; above-limit named-blocked |

## Cycles

1. **BPTK-064** — added a numeric IR evaluator and an API-blind projective
   texgen generator with an explicit projective-divide instruction; the
   spotlight-cookie and planar-shadow fixture render within tolerance against an
   independent projective oracle, and dropping the divide fails the tolerance
   check closed. Red until a live WebGPU adapter renders the fixture. `+1` implemented (44).
2. **BPTK-067/068/069** — one `describePipeline` in `lib/graphics.mjs` lowers each
   unified program to a complete pipeline description per backend, reusing the
   single WGSL emitter: WebGPU primary (register-derived bind-group layout, gamma
   color target, MSAA count), WebGL2 GLSL ES 3.0 fallback (above-floor ops
   named-blocked), WebGPU compatibility mode (out-of-subset WGSL caught at emit).
   Added a content-addressed, API-blind pipeline cache. New `test/graphics.test.mjs`
   registered in the gate surface. `+3` implemented (47).
3. **BPTK-074** — every token read in the D3D9 frontend is now bounds-checked (no
   OOB read), an instruction budget is the deterministic time bound, and
   `containShaderInput` converts any malformed/truncated/over-size/over-budget or
   fuzzed stream into a structured refusal. A 2000-case deterministic fuzz sweep
   escapes zero faults. Red until DXBC/DXIL join the fuzzed surface. `+1` (48).
4. **BPTK-060** — bounded DXBC container reader emits a complete named-opcode
   coverage table (unsupported opcodes named-blocked by numeric identity, DXIL
   bitcode named as an unresolved lowering surface). Prototype-only; red because
   no D3D10-12 program lowers into the unified IR. `+1` (49).
5. **BPTK-072/073** — tile-resolve prototype round-trips a console tiled
   framebuffer to the linear layout a WebGPU texture samples; compute prototype
   models an element-wise storage-buffer dispatch, computes the software
   reference, and names above-limit content. Both prototype-only; red until
   measured on the declared live adapter set. `+2` implemented (51).

## Remaining / red-forever-until-a-device

Nothing planned in scope. Every item is red pending a live GPU adapter (or a
live-adapter measurement), which the offline gate cannot host. Promotion past
red requires the runtime host to render each fixture on a real WebGPU/WebGL2
adapter and measure it against the test-time reference — that is the honest
`implemented → passing` boundary and is out of this lane's offline scope.

The single-emitter audit (GS-018) still finds exactly one `emitWgsl`; the WebGL2
GLSL lowering is a distinct function and does not violate it.
