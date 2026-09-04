# Research note — WebAssembly and low-level native, 2026-09

A one-time landscape sweep for the BPTK binary and source lanes. It maps three
video/insight sources plus fresh web and X research onto the frozen roadmap,
separates what BPTK **already covers** from the **genuinely new** gaps, and
records what must stay **out of scope**. This is a dated snapshot, not a
current-state doc; when a claim here ages out, trust [ROADMAP.md](../ROADMAP.md)
and the [source audit](source-audit.md), not this file.

Verification legend: **[V]** verified via search 2026-09-04 (URL cited);
**[X]** sourced from X/social pulse (rumour unless marked shipped).

## 1. What the source material actually says

- **"WebAssembly is getting WILD"** (InfoWorld) — three demos: Numba (a full
  LLVM JIT running in-browser), **BrowserPod** (Linux userspace in WASM with
  **block-based streaming** — disk images stream progressively as data is
  needed, not all upfront), and **PGlite** (Postgres compiled to one WASM module
  with local-storage persistence). Signal for BPTK: the streaming pattern, not
  the compilers. It maps onto asset delivery, which is already
  [BPTK-022](../ROADMAP.md).
- **"Microsoft Took 20% of Your FPS"** — a Windows desktop tuning list. The one
  transferable signal is **shader-compilation stutter and the persistent shader
  cache**: first-run frame drops are shaders being built, and a durable cache is
  what stops them. In a browser port the analogue is a persistent compiled
  WebGPU pipeline cache in OPFS. Everything else (registry, AV exclusions, core
  count) is host-OS tuning with no browser analogue.
- **"Reverse-Engineering-as-a-Service" strategy brief** — **excluded.** It
  describes defeating subscription licensing on productivity software with a
  jailbroken model plus Frida/Ghidra on virus-ridden patched builds, for resale
  against competitors. That is DRM circumvention, malware handling, and piracy
  for profit. It is already refused by this project as **R-005** (circumvent DRM
  or kernel anti-cheat) and **R-003** (bundle commercial/proprietary material)
  in [roadmap-rejected.md](roadmap-rejected.md), and nothing in it is folded
  into any roadmap item. The only legitimate adjacency — static analysis of a
  binary the user legally owns — is already the safe-import posture of
  [BPTK-007](../ROADMAP.md) and the threat model of [BPTK-004](../ROADMAP.md).

## 2. The 2025-2026 landscape, verified

**WebAssembly 3.0 shipped 2025-09-17** — GC, memory64, tail calls, exnref
exception handling, multi-memory, relaxed SIMD, JS string builtins folded into
the core standard. [V] https://webassembly.org/features/

Browser shipping matrix for the features that matter to a 32-bit PE guest:

| Feature | Chrome | Firefox | Safari | BPTK relevance |
|---|---|---|---|---|
| Tail calls | shipped | shipped | 18.2 | Block-linked/threaded dispatch for the i386 engine without wasm-stack growth — the standard wasm CPU-JIT structure. Feeds [BPTK-009](../ROADMAP.md). |
| exnref EH | shipped | shipped | 18.4 | Guest C++ exceptions and Win32 SEH onto zero-cost native unwinding instead of Asyncify. |
| Relaxed SIMD | shipped | shipped | **flagged** | Recompiled MMX/SSE/SSE2. Needs a strict-SIMD fallback for Safari. |
| JSPI | 137 (2025-05) | 153 default | 27 beta (not 26 stable) | Synchronous blocking Win32 (`WaitForSingleObject`, blocking I/O, sleeps) and synchronous OPFS over async browser APIs, **without** whole-module Asyncify tax. Feature-detect `'Suspending' in WebAssembly`. |
| Memory64 | 133 | 134 | **absent** | A single 4 GB wasm32 guest does not need it, browsers cap ~16 GB, and it carries a pointer-perf tax. Correctly parked as x86-64 research in [BPTK-031](../ROADMAP.md). |
| WasmGC | shipped | shipped | 18.2 | Irrelevant to a C/PE guest; only matters if host glue is a WasmGC language. |

Sources: [V] https://webassembly.org/features/ ·
https://caniuse.com/wf-wasm-memory64 · https://v8.dev/blog/jspi ·
https://spidermonkey.dev/blog/2025/01/15/is-memory64-actually-worth-using.html
· https://platform.uno/blog/the-state-of-webassembly-2025-2026/

**WebGPU 2026** — Chrome/Edge stable since 113; Safari 26 stable (2025-09);
Firefox 141 on Windows, later on macOS, Linux/Android still rolling. New and
load-bearing: **compatibility mode** (Chrome 146, 2026-02-25) —
`requestAdapter({ featureLevel: "compatibility" })` maps onto OpenGL ES 3.1 /
D3D11, i.e. the way to reach **D3D9-class and older GPUs** on a single WebGPU
codebase. [V] https://developer.chrome.com/blog/new-in-webgpu-146 ·
https://github.com/gpuweb/gpuweb/wiki/Implementation-Status

**D3D9 → WGSL** — no turnkey compiler exists; every project rolls its own. D3D9
is SM2/3 token bytecode (not DXIL, not wgpu's HLSL frontend). Realistic paths:
decode SM2/3 → IR → WGSL yourself, lift from HLSL source if present, or D3D9 →
GL (WineD3D-style) → WebGL2 as fallback. For D3D10/11 (research
[BPTK-032](../ROADMAP.md)) a concrete offline chain exists: `DXBC/DXIL → SPIR-V
(dxil-spirv) → WGSL (Tint SPIR-V reader)`. [V]
https://github.com/HansKristian-Work/dxil-spirv ·
https://dawn.googlesource.com/dawn/+/HEAD/docs/tint/spirv-reader-overview.md

**x86-in-browser engines** — v86 (x86→WASM JIT, ~P4/SSE3, full-system) is the
only mature open engine and is what BottleShip uses; CheerpX 1.0 is a more
capable multi-tier x86→WASM JIT (commercial, Leaning Technologies) with a Wine
target promised since 2024 but unshipped through 2026-09. box86/FEX are ARM-only
with no wasm port. No static PE→WASM recompiler exists — that niche is
unoccupied. [V] https://github.com/copy/v86 ·
https://labs.leaningtech.com/blog/cx-10.html

## 3. The competitive field (BPTK is not first)

- **BottleShip** — BPTK's exact architecture, already running: unmodified 32-bit
  PE, v86 CPU, HLE Win32/COM + DirectDraw/D3D3-9 → WebGPU/WGSL, DirectSound →
  AudioWorklet over SharedArrayBuffer, OPFS copy-on-write overlay, **identical
  non-goals**. Apache-2.0, ~111★, early but playing HoMM3/StarCraft/D2/Max
  Payne/Morrowind. No successor found. [V]
  https://github.com/jenissimo/bottleship
- **NewShoes** — C&C Generals Zero Hour shipped in-browser as an Emscripten
  **source** port (D3D8 SM1.1 → GLSL ES, OPFS ~2.1 GB, WebRTC lockstep), built
  by an agent loop in ~2 weeks. [V] https://github.com/Agusx1211/NewShoes
- **GTA Vice City (reVC) → WASM** — viral Dec 2025, source-engine port,
  Rockstar DMCA then community rehosts. The legal pattern for any famous title. [V]
- **Dusk-wasm** — Twilight Princess reimplementation → WASM + WebGPU. [V]
- **Pepsiman Recompiled** (2026-07) — first WASM-first **static
  recompilation** (PS1 → wasm, not emulated), 60 fps. A different porting
  strategy from HLE. [V] https://pepsiman.ol.mr/
- **slant (@slqntdev)** — demoed Skate 3 and CoD4 MW **in-browser** on X
  (Aug-Sep 2026, one clip ~947 likes); CoD4 DMCA'd by Activision pre-release; no
  public binary and no writeup of the CPU path. Real as a demo, unverifiable as
  an artifact. **Correction to earlier session claims:** the "20 fps Skate 3
  browser port" is a slant video claim, not a reproducible artifact, and it is
  distinct from `skate3recomp` (a **native** Xbox-360 recomp, not browser). [X]
  https://github.com/mchughalex/skate3recomp
- **Entity** (Dublin) — $5.8M seed 2026-08-25 for a WebGPU+WASM
  "console-quality, no download, no cloud stream" platform, launch early 2027.
  Validates browser-as-distribution, not HLE specifically. [V]
  https://www.gamesindustry.biz/entity-raises-58-million-to-build-browser-based-console-quality-gaming-platform

Field consensus worth internalizing: **"WebGPU shipped everywhere; it's blocked
by the assets."** The bottleneck moved from GPU calls to multi-GB asset
delivery. [X] That is exactly what [BPTK-022](../ROADMAP.md) exists for.

## 4. Already covered — do not re-add

| Insight | Already in roadmap |
|---|---|
| Block-based / progressive asset streaming, OPFS cache | BPTK-022, BPTK-015 |
| Threads + SharedArrayBuffer + COOP/COEP | BPTK-025 |
| memory64 / x86-64 | BPTK-031 (P4 research) |
| D3D9 shader translation | BPTK-020 |
| D3D10/11, D3D12/Vulkan | BPTK-032, BPTK-033 (research) |
| Execution performance budget | BPTK-023 |
| Save/state persistence in OPFS | BPTK-015 |
| Cross-browser/device matrix | BPTK-030 |
| Mediated multiplayer relay | BPTK-026 |
| DRM circumvention | R-005 (rejected) |
| React as execution target | R-007 (rejected) |
| Server-side execution / cloud streaming | R-004 (rejected) |

## 5. Genuinely new — proposed roadmap additions

Cross-checked against the 33 accepted, 8 rejected, and 5 deferred items; none of
these is a restatement of the above. Each carries the roadmap's
Behavior/Surface/Benchmark/Tier quadruple when promoted.

1. **JSPI synchronous-over-async call bridge.** Service blocking Win32 and
   synchronous OPFS/file calls over async browser APIs without whole-module
   Asyncify instrumentation, with a feature-detected Asyncify fallback for
   Safari. De-risks BPTK-010/011/015. Not named anywhere today.
2. **WASM 3.0 CPU execution substrate.** Adopt tail-call dispatch, exnref
   exception handling, and relaxed SIMD as the i386 engine's substrate, with
   strict-SIMD / legacy-EH fallbacks for Safari. BPTK-009 requires "exception
   behavior" and SIMD coverage but names none of these mechanisms.
3. **Per-title static-recompilation-to-WASM lane (research).** Evaluate static
   machine-code → C/C++ → WASM recompilation (the N64Recomp / PSXRecomp /
   XenonRecomp / reVC / NewShoes model) as a distinct fourth lane for titles the
   general HLE binary lane cannot reach, where source or a clean recomp exists.
   This is the strategy the external field is actually winning with, and the one
   the sister skate3.web pilot exercises.

### Second wave — diagnose-and-route before you emulate (landed as BPTK-037–041)

A practical failure-mode sweep (postmortems, Wine AppDB, DXVK/BottleShip/Boxedwine
issue trackers) surfaced a truth the CPU/HLE/DX-shaped roadmap underplayed: the
components that decide whether a title ports at all are **pre-flight gates**, not
runtime features. Five landed as accepted items:

- **BPTK-037 — middleware & copy-protection census.** Detect from PE signals
  (`binkw32/mss32/dmusic/d3dx9_##` → handle; `CLCD32.DLL/secdrv.sys/.securom` +
  StarForce driver → **refuse**, aligning with R-005; Indeo/WMV/Glide/16-bit
  installer → warn) and route handle / warn / extract / refuse. DRM is detected
  to refuse, never circumvented.
- **BPTK-038 — client-side installer extraction** (Inno/GOG via innoextract,
  InstallShield cab via unshield; refuse 16-bit setup).
- **BPTK-039 — one monotonic clock.** The silent #1 port-killer: QPC, RDTSC,
  `timeGetTime`, `GetScanLine`/vertical-blank, rAF, and the AudioContext clock
  must derive from a single source with a 1 ms period and clamped deltas, or a
  game busy-spins at 100% or runs at 2×.
- **BPTK-040 — FMV middleware** (Bink/Smacker/VP6 via FFmpeg decode + HLE
  present; refuse WMV/Indeo bitstreams).
- **BPTK-041 — redistributable DLL kit** (exact `d3dx9_##`, `xinput1_3`, CRT,
  `msvbvm60`, DirectMusic `gm.dls`), redistributable components only.

Folded as scope notes rather than new items: cooperative-level / exclusive-mode
"lie" layer (into BPTK-011/013), and OPFS path/case/8.3/registry fidelity — note
OPFS is case-sensitive, which silently breaks `fopen("DATA.DAT")` vs `data.dat`
(into BPTK-015/010).

### Third and fourth wave — a front door per lane, then security (BPTK-042–045)

The source and engine lanes gained the same detect-and-route discipline:
**BPTK-042** pins the source-lane Emscripten build profile (isolation, native
exceptions, WASMFS+OPFS via JSPI), and **BPTK-043** fingerprints an engine
family and routes it to a matching open reimplementation (WebXash, Qwasm2,
ScummVM, dhewm3) under the BPTK-029 contract. **D-006** defers
decompilation-assisted source recovery. Security then closed the loop:
**BPTK-044** bounds extraction, streaming, and execution against
decompression-bomb and quota-exhaustion attacks, and **BPTK-045** contains guest
execution to a policy that cannot reach host script, out-of-sandbox storage, or
unmediated network. Folded rather than added: redistributable-kit supply-chain
provenance (into BPTK-041/001) and anti-debug/packer signatures (into the
BPTK-037 census).

Deferred / watch (not promoted): **WebGPU compatibility-mode fallback tier**
(Chrome 146) as a refinement of BPTK-017/030 once the primary WebGPU path
exists; **Isolated Web Apps + Direct Sockets** as a packaged-distribution option
for the BPTK-026 network bridge; **agent-loop compatibility work** as a process
note (NewShoes and BottleShip both invite generic, harnessed agent PRs).

## 6. Out of scope — recorded so it is not revisited

- DRM/anti-cheat circumvention, defeating software licensing, handling malware
  or "patched" pirated builds (the RE-as-a-Service brief). Refused; see R-005,
  R-003.
- Booting a full Windows/Wine image (BoxedWine/CheerpX-Wine model) as the
  primary path — the HLE-the-ABI approach is the honest route for no-source
  Win32; full-stack emulation is the legacy/fallback mental model, not the
  target.
- Hosting user ROMs/ISOs server-side — bring-your-own-file in the tab only,
  reinforced by the reVC and slant/CoD4 DMCA pattern.
