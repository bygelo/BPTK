# Lane Y — Dwarf Fortress toward SDL_SetVideoMode / first frame

x86-64-first browser runtime. Serve what Dwarf Fortress (corpus-006, SDL 1.2)
reaches next as it advances through its own `main` toward SDL video init.
Measured with `executeProbe64` (budget 10,000,000) on the staged
`Dwarf Fortress.exe`; the honesty rail forbids a stub that fakes progress.

## Cycle 1 — CRT ctype + string/number breadth (Win64 api-set)

### Before
| stop | instr |
| --- | --- |
| `api-ms-win-crt-string-l1-1-0.dll!isspace` | 4,136,098 |

The ucrt ctype/string/number family was served only on the legacy `msvcrt.dll`;
DF links these through the Universal CRT api-set forwarders, so the very first
one it reached (`isspace`) was unserved.

### What was served (all in `lib/hle.mjs`)
- **Real C-locale ctype table** (`crtCtypeMask`, a 256-entry classification with
  the actual MSVCRT bit values `_UPPER/_LOWER/_DIGIT/_SPACE/_PUNCT/_CONTROL/
  _BLANK/_HEX/_ALPHA`). Every classifier returns the masked bit — nonzero iff
  the class holds: `isupper/islower/isdigit/isspace/ispunct/iscntrl/isxdigit/
  isalpha/isalnum` and the range classifiers `isprint/isgraph/isblank`, each with
  its `_l` locale-tagged twin, plus `_isctype/_isctype_l`. Served on
  `api-ms-win-crt-string-l1-1-0.dll` and `msvcrt.dll`.
- **Case conversion** `toupper/tolower/_toupper/_tolower` + `_l` variants, served
  on the string + convert api-sets and msvcrt.
- **Number parsing** `atoi`, `strtol`, `strtoul` (full C contract: whitespace,
  sign, `0x`/`0` base detection, longest digit run, endptr write, overflow
  clamp), `_itoa`, `_ultoa`, served on `api-ms-win-crt-convert-l1-1-0.dll` +
  msvcrt; `rand`/`srand` on `api-ms-win-crt-utility-l1-1-0.dll` + msvcrt.
- The served export table and the conformance census iterate one shared
  library/symbol table (`CTYPE_LIBRARY`/`CASECONV_LIBRARY`/`NUMBER_LIBRARY`/
  `RANDOM_LIBRARY`), so the served set and census coverage cannot drift.

### Supporting fix — full-width x64 pointer returns
`vcruntime140.dll!strrchr` was the next stop after ctype. Serving it exposed a
latent truncation: `invokeExport` (`lib/hle.mjs`) and `serveImport64`
(`lib/exec64.mjs`) forced every return through `>>> 0`, so a pointer that
`strrchr`/`strstr`/`strchr` returns into a string above 4 GiB (DF's path string
lived at `0x7ff0000ffe81`) came back as a low dword the guest then dereferenced
→ fault at `0xffe89`. Both marshals now preserve a positive integer above
`0xffffffff` at full 64-bit width; every 32-bit return (incl. negative ints)
still zero-extends via `>>> 0`, so the i386 conformance ledger is untouched
(all its values are ≤ 0xffffffff). The string intrinsics read/return through
`blockAddress` (full width) and are served on `vcruntime140.dll` + msvcrt.

### After
| stop | instr | note |
| --- | --- | --- |
| `msvcp140.dll!??0?$basic_ios@...@std@@IEAA@XZ` | 4,137,243 | `basic_ios<char>` protected ctor — the MSVC C++ standard-library (iostream) ABI frontier |

DF advanced 4,136,098 → 4,137,243 (+1,145), clearing the entire CRT ctype /
string / number breadth. The new honest stop is a **different, larger
frontier**: the MSVC C++ standard library (`msvcp140.dll`), whose iostream ABI
(streambuf/locale/codecvt object layout, vtables, EH) DF constructs next. This
is not served — a no-op ctor would leave an object with no valid vtable and the
next virtual call would fault, so it is left as the exact named frontier rather
than faked.

### Not reached this cycle — file I/O
Mission item 2 (CreateFile/ReadFile/Find*/CRT fopen over the DF stage) sits
**behind** the `msvcp140` C++ iostream frontier: DF constructs a C++ stream
object before it opens any data file, so no file-I/O surface is reached in the
bounded run. Building a VFS-backed file layer now would be surface DF never
exercises (unverifiable-against-DF), so it was deliberately not added. DF never
reached `SDL_SetVideoMode` and produced no framebuffer this cycle.

### Verification
- `executeProbe64` on DF: 4,136,098 → 4,137,243, stop advanced from
  `isspace` to `msvcp140!basic_ios<char>` ctor.
- `node bin/bptk.mjs corpus run`: entry 9 / loaded 2 (no regression).
- `npm run gate`: exit 0 — 585 tests pass / 0 fail / 0 skip; conformance census
  complete; `passing` stays 0 (a frame is not proven playability).
- New behavioral tests: 4 in `test/hle.test.mjs` (ctype classification,
  toupper/tolower, strtol/strtoul/_itoa/srand, vcruntime140 strrchr/strstr) and
  1 in `test/exec64.test.mjs` (a served `strrchr` returns a full-width pointer
  above 4 GiB, not a truncated low dword).
