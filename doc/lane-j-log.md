# Lane J log — extend the i386 probe past its SSE2 wall (BPTK-009)

## Cycle 1 — SSE2 128-bit packed integer subset

### Ops added (bit-exact, 0x66-prefixed 128-bit xmm forms in lib/runtime.mjs)
- Shuffle: `pshufd` (66 0f 70), `pshuflw` (f2 0f 70), `pshufhw` (f3 0f 70)
- Move: `movq` store (66 0f d6), `pmovmskb` (66 0f d7)
- Logical: `pand` (db), `pandn` (df), `por` (eb), `pxor` (ef)
- Packed add/sub: `paddb/w/d/q` (fc/fd/fe/d4), `psubb/w/d/q` (f8/f9/fa/fb)
- Compare: `pcmpeqb/w/d` (74/75/76), `pcmpgtb/w/d` (64/65/66)
- Unpack: `punpcklbw/wd/dq/qdq` (60/61/62/6c), `punpckhbw/wd/dq/qdq` (68/69/6a/6d)
- Pack: `packsswb` (63), `packuswb` (67), `packssdw` (6b)
- Multiply: `pmullw` (d5), `pmuludq` (f4)
- Shift register-form: `psrlw/d/q` (d1/d2/d3), `psraw/d` (e1/e2), `psllw/d/q` (f1/f2/f3)
- Shift immediate group: `psrl/psra/psll` (71/72/73 /2 /4 /6) and whole-register byte shifts
  `psrldq/pslldq` (73 /3 /7)

All computed two's-complement-exact through BigInt (packedLane128 / packedShift128) or
buffer-lane helpers (unpack128 / pack128 / pcmpgt128 / pcmpeq128). The no-prefix (MMX 64-bit)
form of each shared extension is unchanged and still routes to executeMmx; only the 0x66 (and
the f2/f3 pshuf) encoding is intercepted, so the declared NP decode inventory in lib/i386.mjs
and its consistency-walk stay untouched and green.

### Collateral fix (same executor, blocked the mission)
`multiplyDivide` passed a BigInt bit-count to `BigInt.asIntN` in the one-operand signed
`imul`/`idiv` paths (`asIntN(BigInt(bits), …)`), which throws "Cannot convert a BigInt value to
a number". Never reached before because Plink faulted at pshufd first; the SSE2 work exposed it
at the CRT's first one-operand signed multiply. Fixed to pass the Number bit-count. Covered by a
new microprogram test (imul overflow flags + idiv signed quotient/remainder).

### Scoreboard (Plink / CORPUS-009, 10M instruction budget)
- before: instruction_count 28,805, stop `unsupported_opcode` at 0x0f70 (pshufd, 66-prefixed)
- after SSE2 add: 35,202, stop `runtime_fault` (the asIntN BigInt bug above)
- after asIntN fix: 1,042,678, stop `read_fault` — guest read of unmapped address 0x20001
  (a memory-model / HLE boundary, not an SSE gap; owned by another lane)

### Non-regression
- `node bin/bptk.mjs corpus run` — CORPUS-009 stays at `entry` (gap deepened
  `unsupported_opcode → read_fault`, still mapped BPTK-009). passing/reached unchanged.
- `npm run gate` exits 0 (503 pass, 1 skip, 0 fail). New tests all in test/i386.test.mjs.

### Next stop
`read_fault` reading address 0x20001 at eip 0x447… — the bounded probe does not map the address
the CRT dereferences here. This is a memory-model/HLE surface, outside the SSE lane.
