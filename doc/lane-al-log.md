# Lane AL — external HLE import-call boundary in the WASM codegen

Milestone M3, doc/runtime-v2-scope.md. Extends `lib/wasm64.mjs` so a guest `call`
to a target OUTSIDE the compiled set — an HLE import — compiles to a REAL
WebAssembly import call instead of the honest `control_call_external` fallback,
whenever a host callback is bound. The integer, SSE, control-flow, and direct-call
paths are unchanged; all prior tests still pass.

## Model

At an external-call terminator the codegen emits a bounded import boundary over the
SAME single exported memory the GPR file and stack already share:

1. **Push return address** — `rsp -= 8`, `i64.store` the return VA at `[rsp]`,
   exactly as a normal direct call (the identical stale qword the interpreter's
   call writes).
2. **Spill** — `emitEpilogue` flushes the sixteen GPR i64 locals to
   `regBase + 8*i` and the six flag i32 locals to `flagBase + k`, so the host sees
   the current guest state (including the just-decremented rsp) in memory.
3. **Call host** — push the target VA (i64), then
   `call (import "env" "hostCall" (func (param i64) (result i32)))`. The import is
   function index 0, so the module's own defined function becomes index 1 (the
   `run` export). Status 0 = handled; nonzero = unhandled.
4. **Unhandled → honest fallback** — a nonzero status sets `D.status = FALLBACK`
   and branches to `$exit`; the module returns the fallback status, never a wrong
   result.
5. **Reload** — `emitPrologue` reloads the sixteen GPRs and six flags from memory
   (the host may have changed rax etc.).
6. **Pop + resume** — `rsp += 8` (matching the callee's RET), set the block index
   to the return leader, `br` back to `$loop`.

The i32 scratch local `F.i` carries the host status; `D.status` is only written on
the actual terminal branches, so it is never used as scratch.

## Host binding

`runFunction` binds `env.hostCall` to `option.hostCall` when present. The wrapper
hands the callback the guest target virtual address (unsigned 64-bit BigInt) and a
context with live, closure-shared access to the SAME memory `seedState` fills:
`readReg`/`writeReg` (rax..r15 by name over `regBase`), `readFlag`/`writeFlag`
(over `flagBase`), `readMem`/`writeMem` (guest VA ⇄ linear-memory offset), and the
raw `mem`/`view`. The callback reads args, performs the effect, writes its return
value into the shared register file, and returns 0. A missing/undefined result is
treated as unhandled (fallback). Completeness (`usesHost`) is a compile-time
property; the import is declared only when at least one external boundary is
emitted, so modules without an external call are byte-for-byte unchanged.

Without a bound `option.hostCall`, an external target stays the honest, named
`control_call_external` fallback — prior behavior is preserved exactly.

## Oracle strategy (same-image, bit-exact)

The interpreter has no host hook and is read-only. To compare bit-exact, each test
uses ONE image: the external effect is realized by an in-image guest stub (e.g.
`mov eax,100; ret`) the interpreter naturally calls, while the WASM path is given
`option.externalRva = [stubRva]` so `buildCfg` does NOT follow the call into the
stub and the terminator routes through `hostCall` instead. The stub bytes, the
pushed return addresses, and the stack layout are identical in both paths, so GPRs,
flags, AND the stale return-address stack bytes match bit-exact. The host mock
mirrors the stub's effect (and for the loop case the stub uses `lea eax,[rax+5]`,
which sets no flags, so the only flag-defining op is `dec ecx`, matched by both).

## Verification

`test/wasm64.test.mjs` adds an external-call section, each run through the
interpreter oracle and the import-emitting WASM module:
- host sets rax, caller uses it (`mov ecx,5; call ext; add eax,ecx` → eax=105),
  asserting the callback OBSERVED ecx=5 from the spilled register file.
- two import calls in sequence (distinct per-target effects; the host observes
  ecx=5 then rax=100).
- an import call inside a counted loop (host accumulates 5+5+5 → eax=15, rcx=0;
  observes eax=0 on the first iteration).
- an unhandled host call (nonzero status) returns the honest fallback.
- no host binding → stays the named `control_call_external` fallback.

`npm run gate` exits 0 (673 tests, 672 pass, 1 skipped, 0 fail; package check PASS).
