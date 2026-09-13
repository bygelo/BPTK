---
cursor:
  subagentId: "bc-39889031-6179-5331-afa9-14abbf857102"
---

# GS-106 generalization ledger — SuperTux present-path trio

ROADMAP **R-006** (rejected: per-title patch as the primary model) / **GS-106** (BPTK-085: a fix is accepted only when it raises `reached_stage` of ≥ N distinct corpus entry, else a declared sandboxed adapter).

This is a docs-only pass. `lib/runtime.mjs` `lib/hle.mjs` `lib/gl.mjs` `lib/user.mjs` `lib/gdi.mjs` were not edited. SuperTux was not remesured. Nothing was merged onto `build/product-first`. Interactive-freeware stays **open**. `passing` stays **1**. `interactive` stays **0**.

## Base

| Item | Value |
|---|---|
| Host | geldan-pc worktree `C:\Users\maran\Code\BPTK-lane-ledger` (Mac clone used only to read + IAT-join staged payloads) |
| Branch | `cursor/generalization-ledger` tracking `origin/build/product-first` |
| Worktree pulled | `origin/build/product-first` @ `8c509fb` (newer than the assigned `6423d6e` floor). `8c509fb` is the same continue latch with the read/GL ceiling **8× → 16×**. Product 50M cap unchanged. No title branch. Official remesure of `8c509fb` has not been run; this pass does not remesure SuperTux. |
| Docs SHA under that | `6423d6e` syncs the `b0d1421` tuple; runtime `6396652` added same-snap `< 4` |
| Official SuperTux tuple (`6423d6e` remesure, not rerun) | `instruction_budget_exhausted` at `libpng+0x20b03`, **400000000** insn (8× continue ceiling), **35330** HLE, last HLE advancing `ReadFile` of `c:\game\data\images\engine\menu\logo.png`, `SwapBuffers` **0**, IAT 722/722. |

**ID correction.** Manifest `data/corpus.json` **CORPUS-013** is ripgrep 14.1.1 win32, not OpenTTD. OpenTTD is **CORPUS-005** (13.4 x86-64, `packaged` / `machine_x86_64`) and **CORPUS-008** (1.10.3 win32, the i386 title Lane C owns). The OpenTTD half of this ledger is CORPUS-008. CORPUS-013 cannot prove these exports: it is a console `process_exit` 0 path with no GL and no INFINITE-wait continue latch.

## The three SuperTux present-path exports

These are the mechanisms the SuperTux spine used to keep presenting past atlas/font I/O. None contains a title predicate. Tests in `test/runtime.test.mjs` and `test/gl.test.mjs` assert the bodies do not match `title|executable_name|supertux|SuperTux`.

| Mechanism | Where | What it does | Generic? | Title-specific residue |
|---|---|---|---|---|
| **ReadFile continue latch** | `lib/runtime.mjs` `productiveReadContinue` / `probeContinueRunnable` | After any INFINITE waiter is seen (`deadline === null`) and a sibling thread is runnable, the probe may run past the product insn cap (4× wait-continue, **8×** read/GL-continue on `6423d6e`, **16×** on `8c509fb`) while the last recent HLE row is a productive `ReadFile` or `glTexImage2D` / `glTexSubImage2D`. A heap/CS burst that ages the row out of the 32-entry window **keeps** the live latch. | **API-generic.** Gated on HLE symbol + snap (path/size/handle/position or width/height/pixels), not on a title string. | Motivating comments name PhysFS/TTF and atlas upload. The 8× / 16× ceiling and 32-row window were sized on SuperTux remesure. That is a bound, not a title branch. The 16× bump (`8c509fb`) does not create a second-title proof. |
| **GL specify / store** | `lib/gl.mjs` `texImage2D` / `texSubImage2D`, `glBound.texture_store_byte` | NULL `glTexImage2D` specifies an RGBA store (`Buffer.alloc`). `glTexSubImage2D` writes into that store. Store cap **64 MiB**. `readBlock` admits the same 64 MiB so a 640×700×4 specify is not `hle_block_bound`. | **API-generic.** OpenGL 2.1 NULL-pointer specify is the real contract. Tests require `Buffer.alloc` and forbid a title match. | Comments name the 640×700 SuperTux font atlas as the trip. `glGetString(VERSION)` is `"2.1 BPTK"` because SuperTux sscanf-rejects 1.x — still a declared GL version, not a title `if`. |
| **same-snap streak** | same `productiveReadContinue` | Two identical snaps in a row are a probe (PhysFS 4-byte magic after seek-0, or a repeated GL upload). `sameSnapStreak < 4` stays productive; a long identical streak is a spin and drops the latch. | **API-generic.** Equality is `JSON.stringify` of the snap, not a path allow-list. | Threshold `4` and the TTF-magic comment are SuperTux-measured. The rule applies to any `ReadFile`/`glTex*` snap. |

GS-106 does **not** treat “no `if (title === …)`” as proof of generality. `computeGeneralizationDelta` only counts a **`reached_stage` raise**. SuperTux is already `entry` on the official docs; these three landings moved the stop EIP / insn ceiling, not the corpus stage. They are therefore **not yet a GS-106-accepted fix** even for SuperTux.

## Do CORPUS-011 or CORPUS-008 already move on these same exports?

**No** — not on the three named mechanisms. They do move on *other* SuperTux-era USER32/GDI rows (see sibling lane notes). That is a different surface.

### CORPUS-011 PuTTYgen (`cursor/puttygen-dialog-11eb` @ `c01dd4d`)

Unique commit vs merge-base `603602e`: case-insensitive Win32 class + stock comctl32 register + child `control_id`. That slice is **already on `6423d6e`** (`classKey` / `predefinedClass` in `lib/user.mjs`). The geldan worktree `BPTK-lane-b-puttygen` is detached at `6423d6e`; the feature branch remains unmerged as a pointer, not as extra runtime.

Live IAT join on `6423d6e` against staged `puttygen.exe`: **174/174** served. Imports `kernel32!ReadFile` and the dialog family. **Zero** `opengl32` / `glTex*` / `SwapBuffers` / `wgl*` / `WaitOnAddress`.

Lane B remesure on this HEAD (store `lane-b-puttygen.md`, SuperTux not rerun):

- Staged 2M: still `instruction_budget_exhausted` inside `WM_INITDIALOG`.
- 50M package copy: **`hle_dialog_modal_idle`**, HWND `#32770` “PuTTY Key Generator”, GDI `compositeDesktop` 640×480 from the user32 paint log. Guest GDI IAT during the run is **0** (`BitBlt`/`TextOut` not called). Last HLE `EnableMenuItem`. One `CreateFileA` of `c:\windows\putty.rnd` (miss) — not a productive same-snap ReadFile latch.

So PuTTYgen **already moves** on the generic **class / dialog / GDI-compositor** present path that SuperTux also landed. It does **not** enter the ReadFile continue latch, does **not** specify a GL texture store, and does **not** exercise same-snap `< 4`. A shown dialog is P1-2D for the parent goal and **does not** finish interactive-freeware.

### CORPUS-008 OpenTTD 1.10.3 (`cursor/openttd-imports-236d` @ `dd16ea9`)

Unique commit vs merge-base `30f6a70`: bind the remaining winmm / ws2 ordinal / gdi font / usp10 / kernel32 console+timer-queue surface so the image is fully served. **Not on `6423d6e`.** Lane C must not be merged from this pass.

Live IAT join on `6423d6e` against staged `openttd.exe` (inspect only, no SuperTux run):

| field | value |
|---|---|
| import | 302 |
| served on `6423d6e` | **225** |
| unserved | **77** (`winmm` 11, `ws2_32` 14, `gdi32` 11, `user32` 16, `kernel32` 16, `usp10` 7, …) |
| `opengl32` / `glTex*` / `SwapBuffers` / `wgl*` | **none** |
| `ReadFile` / `CreateFileW` | imported |
| `WaitOnAddress` / `SleepConditionVariableSRW` | **none** |

Official docs still say “161/302” / `loaded` / `import_present`. That is the unserved-era scoreboard, not today’s 225/302 join. SuperTux-generic USER32/GDI rows closed part of the IAT without a stage raise: `data/corpus-run.json` and the staged `corpus-run.json` still record `loaded`.

Lane C remesure on **its own** tree (`302/302`, process_exit 1 after 1869421 insn) shows CORPUS-008 can reach `entry` once those GDI/winmm/ws2 rows land. That remesure is **not** on `6423d6e`, so it cannot claim the continue latch, GL specify, or same-snap moved OpenTTD. OpenTTD 1.10.3 official win32 is a software/GDI+SDL import surface. There is no GL specify/store for it to call.

CORPUS-005 (OpenTTD 13.4) is x86-64 and stops at `machine_x86_64` before any of these i386 mechanisms.

### CORPUS-013 ripgrep (the real CORPUS-013)

`--version` / PCRE2 search are `process_exit` 0. No GL. No INFINITE-wait + productive-ReadFile latch on the official path. Not a second title for this trio.

## What would prove a second title

GS-106 proof is a pair of GS-105 run records plus `bptk corpus generalize`:

1. `before.record` and `after.record` from real `bptk corpus run` (payloads stay out of git).
2. `computeGeneralizationDelta(before, after)` → `generic_accepted` with `beneficiary_count >= 2` and no regression.
3. The improved entry’s stop/HLE tail names the **same mechanism**, not merely “also got further”:
   - **Continue latch:** INFINITE waiter seen, sibling runnable, last productive row `ReadFile` or `glTex*`, insn past the product cap without a title skip.
   - **GL specify/store:** NULL `glTexImage2D` then `glTexSubImage2D` (or a non-NULL specify that uses the 64 MiB store) on the critical path.
   - **same-snap:** two-to-three identical snaps that would have dropped the latch at streak 1 and now do not.

A second title that only consumes USER32 class lookup or GDI `compositeDesktop` (PuTTYgen today) proves **those** exports, not this trio.

Plausible next measurement — **not done here**: rebase Lane C onto `6423d6e` (or merge the generic winmm/ws2/gdi rows as their own slice) and remesure **OpenTTD only**. If OpenTTD then parks an INFINITE wait and does productive `ReadFile`, the continue latch / same-snap can gain a second beneficiary. It still cannot prove GL specify/store: the 1.10.3 IAT has no `opengl32`.

A second **i386 OpenGL** title is the only corpus-shaped way to prove GL specify/store. The current fourteen-entry manifest has one such title (SuperTux). Chocolate Doom / OpenTTD 13.4 / Dwarf Fortress are x86-64.

## When a sandboxed adapter is the only remaining path

R-006: an isolated title patch is a last-resort adapter **outside the core**, not `if (title === "SuperTux")` inside `lib/gl.mjs` / `lib/runtime.mjs`.

Adapter (`bptk corpus generalize --adapter` → `adapter_accepted`) is the remaining GS-106 door **only** when:

- the slice that would raise SuperTux toward `interactive` is one of these three mechanisms, and
- a second corpus entry cannot be shown to exercise that same contract.

| Mechanism | Adapter the only remaining path? |
|---|---|
| GL specify / store | **Yes, on the current corpus.** No other staged i386 binary imports `opengl32` / `glTex*`. Waiting on OpenTTD cannot create a GL call that is not in the IAT. The alternative to adapter is GS-104 acquisition of another i386 GL title, not a title predicate. |
| ReadFile continue latch | **Not yet.** OpenTTD imports `ReadFile` and, once fully served, reaches `entry` on Lane C. Whether it ever trips `seenInfiniteWait` + productive ReadFile is **unmeasured** on `6423d6e`. PuTTYgen’s dialog-idle path does not. Measure OpenTTD before declaring adapter. |
| same-snap streak | **Not yet**, for the same reason: it is a clause of the continue latch. OpenTTD GRF/header re-reads could be a second snap pattern; that is a hypothesis, not evidence. |

Do not encode SuperTux constants as a title check. If a bound must stay SuperTux-sized (8× / 16×, streak `< 4`, 64 MiB, `"2.1 BPTK"`), keep it a **declared generic bound** and, if GS-106 still sees one beneficiary after the OpenTTD remesure / a new i386 GL acquire, **declare the adapter** rather than special-casing the executable name.

## Interactive-freeware

Parent goal (`docs/interactive-freeware-goal.md`) criterion 3 is this ledger. Criteria 1–2 are still false: SuperTux `SwapBuffers` 0, no guest-visible input. PuTTYgen idle dialog is P1-2D only. OpenTTD is not interactive. Do not mark the goal complete because IAT is bound, because continue held to 400M, or because a dialog compositor has pixels.
