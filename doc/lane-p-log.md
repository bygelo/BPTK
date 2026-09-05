# Lane P — x86-64 binaries taken deeper (x87 FPU + address-space faults)

Owned surfaces: `lib/lift64.mjs`, `lib/exec64.mjs`, `test/lift64.test.mjs`,
`test/exec64.test.mjs`. Base: `build/product-first` @ `b6404b2`.

## Cycle 1 — x87 FPU family + three address-space faults

### x87 FPU (jq corpus-003, Chocolate Doom corpus-007)
Both stopped at `unsupported_opcode 0xdb` (the x87 escape). Implemented an
80-bit-aware x87 stack model shared by the M2 oracle (`lib/lift64.mjs`) and the
bounded probe (`lib/exec64.mjs`), consistent with the i386 x87 subset
(`lib/runtime.mjs`): eight-entry register stack, top pointer, per-slot valid bit,
status word (C0–C3), control word (rounding mode). Each slot stores an IEEE
double; the m80 extended-real memory forms convert on load/store.

Decode+IR+interpret added for the full 0xD8–0xDF escape:
- FLD/FST/FSTP (m32/m64/m80/st(i)), FILD/FIST/FISTP (m16/m32/m64), FXCH, FFREE.
- FADD/FSUB/FMUL/FDIV and their reverse and pop forms, in memory, integer
  (FIADD…), 0xD8 (dest st0), 0xDC (dest st(i)), and 0xDE (…P pop) encodings.
- FCOM/FCOMP/FCOMPP/FUCOM/FUCOMP/FUCOMPP (set C0/C2/C3);
  FCOMI/FCOMIP/FUCOMI/FUCOMIP (set EFLAGS CF/ZF/PF).
- FLDCW/FNSTCW/FNSTSW(/AX), FNINIT/FNCLEX, FNOP, FCHS/FABS/FTST/FXAM,
  FLDZ/FLD1/FLDPI/FLDL2E/FLDL2T/FLDLG2/FLDLN2.
Transcendentals, FCMOVcc, FLDENV/FNSTENV/FRSTOR/FNSAVE, FBLD/FBSTP, FISTTP stay
honest `unsupported` refusals.

Shared executor `executeX87` exported from `lib/lift64.mjs` and imported by
`lib/exec64.mjs` (same pattern as `executeSse`), so oracle and probe cannot
diverge. Ten bit-exact microprograms added to each of the two test files.

### PuTTY (corpus-001): jmp/call through a bound IAT slot
Root cause: `mov rdi,[iat_slot]; …; call rdi` where the IAT slot held the on-disk
ILT RVA (0x12dc2e for kernel32!FindFirstFileA), never bound to a thunk — the
direct `call [slot]` interception never saw it. Fix: when the HLE is wired, bind
each served import's IAT slot to its HLE thunk address, and dispatch a rip that
lands on a thunk exactly like the call-site path (kind "jmp": the pushed return
address is popped and the caller resumes).

### Dwarf Fortress (corpus-006): 64-bit pointer truncated by the 32-bit HLE
Root cause: `jmp [memset_iat]` dispatched memset with rcx=0x141c33b30 (a valid
image global), but the HLE addresses memory as an unsigned 32-bit value
(`lib/hle.mjs unsigned()`), truncating the image pointer to 0x41c33b30 and
faulting. Fix: an image alias region at `load_base & 0xffffffff` (0x40000000),
sharing the same `imageBuf`, so a truncated image pointer resolves to the real
image bytes.

### OpenTTD (corpus-005): TLS pointer deref
Root cause: `mov rax,gs:[0x58]; mov rcx,[rax]; …` — TEB.ThreadLocalStoragePointer
(x64 offset 0x58) was unset, so rax=0 and the deref faulted. Fix: the TEB region
now carries a TLS array (TEB+0x58) whose slots point to one bounded, zeroed TLS
block. OpenTTD advanced past the TLS deref; its next stop is a genuine null
deref of an uninitialized C++ global (a saved/restored 0 — not an unmapped
region), a deeper HLE-init frontier outside this lane.

## Instruction-count frontier (budget 10,000,000)

| binary  | before | after | before stop            | after stop                                   |
|---------|--------|-------|------------------------|----------------------------------------------|
| jq      | 259    | 268   | unsupported_opcode 0xdb| import_present crt!malloc (unserved HLE row)  |
| Doom    | 103    | 186   | unsupported_opcode 0xdb| entry_return                                 |
| PuTTY   | 22670  | 28238 | fault (jmp to thunk)   | import_present user32!MessageBoxA            |
| OpenTTD | 30545  | 30603 | fault (gs:[0x58]=0)    | fault (null C++ global deref, deeper)        |
| DF      | 508    | 543   | fault (memset ptr trunc)| import_present crt!malloc (unserved HLE row) |

`npm run gate` exits 0 (535 pass, 1 skip). `bptk corpus run` keeps all 8 at
`entry` (no regression). `passing` stays 0. malloc / MessageBoxA are unserved
HLE rows (milestone M4), not this lane.
