# Lane L log — Plink past the memory-model wall

## Cycle 1 — main module handle dereference

**Hypothesis (falsifiable).** The `read_fault` at guest linear 0x20001 (2-byte read,
`ecx=0x20001`, `eax=0x5A4D`) is either (a) a legitimate CRT access to a region the
bounded probe fails to serve, or (b) a pointer our execution computed wrong earlier.
`eax=0x5A4D` is the ASCII "MZ" DOS-header magic, so the faulting instruction is an
image-header validation. Trace what produced `ecx`.

**Root cause — legitimate access, mapping gap (category a).** The faulting instruction
at eip 0x447615 is `66 39 01` = `cmp word ptr [ecx], ax` with `ax=0x5A4D`, followed by
`mov eax,[ecx+0x3c]; add eax,ecx; cmp dword [eax],0x4550` — the classic "MZ" + `e_lfanew`
+ "PE" validation the CRT runs on a module base. `ecx` came from the immediately
preceding `call [0x486f58]`, which resolves to `kernel32!GetModuleHandleW`. The HLE
returns `moduleTable[0].handle = 0x00020001` for `GetModuleHandleW(NULL)`. On Win32 the
HMODULE of a module *is* the base address it is mapped at, so the CRT dereferences the
handle to read the PE headers. Our loader mapped the image at its PE image base
(0x400000) while the HLE advertises a synthetic handle (0x20001); the two disagree, so a
read through the handle fell outside every mapped region and faulted. `ecx` was not
miscomputed by our decoder — it is exactly the HLE return value — so this is a genuine
access the bounded probe failed to serve, not a hidden decode bug.

**Fix.** In `lib/runtime.mjs` the memory model now aliases the main module handle window
onto the already-mapped image: a read within `[mainModuleBase, mainModuleBase +
image.length)` translates back to the image path (`imageStart + (address -
mainModuleBase)`) and reuses the existing section-readability checks, serving the real
"MZ"/"PE" bytes. The alias is bounded to the image size, read-only (a write faults with
`write_fault`), and never executed (`fetch` faults). No new memory is reserved and no
second copy is made; `hle.mjs` is untouched. `mainModuleBase` is read once from
`hleGuest.lookupModule(null)` after the HLE is built.

**instruction_count.** before 1,042,678 (`read_fault`) → after 1,053,075
(`process_exit`, exit code 0x1 — Plink invoked with no arguments prints usage and exits
1, its own clean termination path).

**Regression.** `test/runtime.test.mjs`: (1) `push 0; call [GetModuleHandleW]; movzx eax,
word [eax]; ret` lands `eax=0x5a4d` at `entry_return` with no fault; (2) a store through
the handle stays a structured `write_fault` at 0x00020001.

**Corpus.** `corpus run` keeps CORPUS-009 at `entry`. `npm run gate` exits 0; passing 0.
