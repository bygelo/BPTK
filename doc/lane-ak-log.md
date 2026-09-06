# Lane AK — SSE/SSE2 in the WASM codegen (v128 SIMD)

Milestone M3, doc/runtime-v2-scope.md. Extends `lib/wasm64.mjs` to emit real
WebAssembly v128 SIMD (the `0xFD` opcode family) for the SSE/SSE2 IR `lib/lift64.mjs`
lifts, bit-exact per lane against the interpreter oracle `executeSse`. The integer,
control-flow, and direct-call paths are unchanged; all prior tests still pass.

## Model

The sixteen xmm registers live as 16-byte little-endian slots in a scratch region
of the SAME exported memory the GPR file uses (`xmmBase + index*16`). A v128 loaded
from those bytes aliases the interpreter's little-endian lane packing exactly
(i8x16 lane 0 = low byte, i32x4 lane 0 = low dword, …), so every v128 lane opcode
computes the identical 128-bit result the oracle does. `seedState` seeds the slots
from `option.xmm`; `readState` reads all 128 bits of each xmm back out.

## Emitted bit-exact as v128 (31 op kinds)

bitwise (pand/pandn/por/pxor + andps/andnps/orps/xorps), mov128 (movups/movaps/
movdqa/movdqu/lddqu), movd_load, movd_store, movddup, movhlps, movlhps, movmskps,
movq_load, movq_store, movsd, movshdup, movsldup, movss, packsswb, packssdw,
packuswb, padd (b/w/d/q), pcmpeq (b/w/d), pcmpgt (b/w/d), pextrw, pmovmskb,
pmullw, pmuludq, pshufd, pshuflw, pshufhw, psll/psrl/psra (imm and register count,
with the over-width clamp WASM's width-masked shifts require), pslldq, psrldq,
psub (b/w/d/q), punpckh, punpckl, movlp_load/movhp_load/movlp_store/movhp_store.

Notable exact-match details:
- pandn emitted as `v128.andnot(src, dst)` = `src & ~dst` = the oracle's `~a & b`.
- pmuludq uses 64-bit integer multiply of the even 32-bit lanes (lanes 0 and 2),
  matching the oracle's lane selection (WASM extmul picks lanes 0,1, not 0,2).
- pack ops: the interpreter packs only the LOW 64 bits of each operand into the
  low half (high half zero). Emitted as `narrow(shuffle(dst.low64 ‖ src.low64), 0)`.
- register-count psll/psrl zero the lanes when count ≥ width (mask via i8x16.splat);
  psra clamps the count to width-1 (i32.select) — WASM shifts otherwise wrap the count.

## Honest named fallbacks (3 op kinds)

hadd, hsub, addsub — the SSE3 float horizontal/interleaved add/subtract. WASM SIMD
cannot express their exact IEEE lane pairing 1:1 without risking a NaN-bit
divergence, so they stay `sse_hadd`/`sse_hsub`/`sse_addsub` named fallbacks
(`complete: false`), never a wrong-lane emission.

## Verification

`test/wasm64.test.mjs` adds an SSE section: each microprogram is a pure SSE run
(xmm/GPR inputs seeded through options) executed twice — once by the exported
`executeSse` (the exact interpreter dispatch, driven against a faithful machine
shim) and once by the emitted v128 module — asserting all sixteen 128-bit xmm
registers AND the sixteen GPRs bit-exact, and the flags untouched (SSE defines
none). 17 SSE microprogram tests: movd gpr↔xmm, movq, pxor-to-zero, pand/pandn/por,
paddb/w/d/q + psubd, pcmpeqd/pcmpgtb, pshufd broadcast + reverse, immediate and
register-count shifts (incl. over-width → zero/clamp), pslldq/psrldq, pmullw/
pmuludq/punpck/pack, movmskps/pmovmskb/pextrw, movhlps/movlhps + SSE3 dups, an
xmm memory round-trip (movdqa store then reload, inspecting the raw WASM bytes),
movss/movsd scalar merge, and the haddps honest-fallback assertion.

`npm run gate` exits 0 (668 tests, 667 pass, 1 skipped, 0 fail; package check PASS).
