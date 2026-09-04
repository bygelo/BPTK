# BPTK gold-standard program

> Status: **fully ratified**, 2026-09-05. This file remains the design catalog and
> the single source of the vision text. Every `GS-###` item below is now promoted
> into the gated roadmap as a `BPTK-###` row with its benchmark specification
> (see the promoted planned scope in [ROADMAP.md](../ROADMAP.md), validated by
> `npm run gate`); the mapping lives in the `promoted_as` field of
> [the fanout index](roadmap-gold-standard.json). Promotion ratifies the
> work-list and its acceptance contract — it is not an implementation claim:
> every promoted row is planned and red until its behavior lands.

## Vision

**BPTK is the open, gold-standard runtime + workbench + library for running games
in the browser — any origin, any era — recompilation-first.** Not a porting
toolkit for old Windows games. The workflow generalizes to:

```text
ingest -> route to a lane -> recompile/adapt -> run -> benchmark -> diagnose -> package -> embed -> publish evidence -> host in a library
```

It accepts *literally any executable* (with "arbitrary executables ≠ arbitrary
trust" as a hard rail), routes each to the right lane, and — where it can —
**statically recompiles** rather than interprets, which is the one architectural
bet that beats the field.

### The thesis, in one line
The competitor (BottleShip) JIT-*interprets* x86 on a single-core v86 fork and
its own traces cap it at **14 FPS / 174 MIPS** (vs 770 needed), with no x86-64,
no SMP, an SM1.x translator that lies about advertising SM3.0, a 6500-line
spin-loop instead of JSPI, and bus-factor-1. **We do not build a faster
interpreter — we recompile ahead-of-time** (proven on Xbox 360 via XenonRecomp),
which simultaneously removes the perf wall and frees JSPI / tail-calls / SIMD.

### Adapt, don't follow — the BottleShip relationship

BottleShip is prior art to **learn from, not a template to copy**. We adopt what it
got right and design out the mistake that caps it.

| Adopt (learnings) | Avoid (mistakes) |
|---|---|
| HLE the ABI, don't boot Windows; PE → 4 GB guest → intercept imports | **Interpreting x86 (v86)** — recompile instead (GS-001) |
| No `if (game === …)` in code — generic fixes | **Not actually generalizing** — coverage still scales O(titles) by hand; the slogan is true in code but false in practice (fixes moved into per-title bundle manifests + manual bring-up) |
| OPFS CoW overlay, GOG Inno unpack, WebGPU present | **Trusting curated titles** instead of a broad measured corpus |
| Harness-driven bring-up | **Bus-factor-1, empty tracker, ~10% tests, stale branch** |

**The headline mistake is non-generalization.** BottleShip's own practice is a
per-title missing-export hunt — every new game is hand-brought-up, so breadth is
bounded by one maintainer's time. Our answer is to make **generality a measured,
gating property**, proven against a *real, downloaded* corpus, not a curated
fixture set.

### Two principles this forces into the roadmap

1. **Generalize, or it doesn't count.** A fix is only accepted when it is *generic*
   — it must demonstrably help **N distinct titles**, not one (GS-106). A per-title
   special-case is refused unless it is a documented, sandboxed last-resort adapter
   (consistent with rejected candidate R-006). The metric is coverage across the
   corpus per generic fix, not "another game booted."
2. **Download real executables and actually run them.** BPTK does not validate on
   synthetic fixtures alone. It **acquires lawfully-redistributable freeware games
   and freeware `.exe` programs online**, runs them end-to-end, and measures what
   generic gap broke — because "literally any `.exe`" is only true if we test
   against real, diverse binaries (games *and* utility programs), not a hand-picked
   demo. Payloads stay out of git (provenance-only, per BPTK-002 / R-003); the
   acquisition + run + measure loop is the corpus (GS-104/105).

### Every named BottleShip defect maps to a falsifiable BPTK gate
| BottleShip defect | BPTK gate that kills it |
|---|---|
| 174 MIPS / 14 FPS interpreter wall | GS-001 static recompiler + GS-072 ≥770 MIPS / GS-073 ≥5× interpreter |
| No x86-64, SSE2-cap, single-core | GS-004 x86-64 · GS-006 SMP · GS-007 SSE/AVX/x87 |
| Can't use JSPI (v86 block boundary) | recompiled code = normal WASM fns → BPTK-034 JSPI + GS-076 spin-wait ban |
| Three drifting shader emitters | GS-018 one unified IR (single-emitter audit) |
| Silent-wrong lighting/shadows | GS-023 texgen/shadow pixel gate + GS-025 frame-diff |
| Advertises SM3.0, implements SM1.x | GS-024 honest-caps property test (red by construction) |
| Per-title missing-export hunt / doesn't generalize | GS-036 conformance suite + GS-041 coverage ledger + **GS-106 generalization gate** (a fix must help N titles) |
| Validates on curated titles, not a broad corpus | GS-104 real freeware/.exe corpus + GS-105 run-real-.exe harness |
| 7-week-stale public branch | GS-078 freshness gate |
| Empty issue tracker | GS-079 structured tracker + GS-063 submission pipeline |
| ~10% tests | GS-081 ratcheting coverage bar |
| Bus-factor-1 | GS-082 multi-signer / CODEOWNERS |

---

## The 10 pillars and their items

Format per item: **`GS-###` · title** — benchmark essence · **T#** tier · extends `BPTK-###`.
"Reconciled" marks items ≥2 agents proposed independently (merged here).

### Pillar 1 — Execution core (recompilation-first) — the moat
- **GS-001 · Static x86-PE→WASM recompiler** — AOT `.text` → WASM; bit-exact vs the BPTK-009 interpreter oracle across the trace, no silent interpreter fallback on hot path · **T1** · extends BPTK-036/005. *Reconciled (exec+lanes).* The unoccupied niche.
- **GS-002 · CFG + indirect-branch recovery** — function/jump-table/vtable recovery; every switch/vtable arm bit-exact, unknown target → fallback not crash, code-as-data flagged · **T1** · deps GS-001.
- **GS-003 · Hybrid interpreter fallback for SMC/dynamic code** — self-modifying page detected + re-decoded; untouched blocks stay fast-path · **T1** · extends BPTK-009.
- **GS-004 · x86-64 (AMD64) recompilation** — 64-bit GPR/RIP-relative/SSE-default matches x64 reference · **T2** · extends BPTK-031 · deps GS-005. **[P4]**
- **GS-005 · memory64 guest address space** — >4 GB addressing correct, OOB traps not wraps · **T2** · extends BPTK-035.
- **GS-006 · Guest SMP / multithreading** — worker pool over SAB; lock/atomic-contention fixture deterministic under N workers, no lost wakeup · **T1** · extends BPTK-025. *Reconciled (exec+runtime).*
- **GS-007 · SSE/SSE2/AVX + x87 vectorization** — packed SIMD + 80-bit x87 bit-exact within IEEE tolerance; strict-SIMD fallback matches · **T1** · extends BPTK-035.
- **GS-008 · SEH, vectored exceptions, TLS callbacks** — `__try/__except`/`__finally` + AV/#DE via exnref; TLS callback fires before entry · **T1** · extends BPTK-035.
- **GS-009 · Benign anti-debug / timing-check satisfaction** — `IsDebuggerPresent`/RDTSC-delta guards pass; **DRM/anti-cheat refused, never bypassed** · **T2** · deps BPTK-037/039.
- **GS-010 · CPU-deterministic record & replay** — pinned RNG/input/clock/schedule → identical state hash across two runs + a second machine · **T1** · deps BPTK-039, GS-006. *Reconciled (exec+correctness).*
- **GS-011 · Guest↔host ABI / import-thunk lowering** — recompiled stdcall/cdecl/thiscall calls reach HLE directly with correct stack cleanup, under the GS-075 boundary-cost bar · **T1** · deps GS-001, BPTK-010.
- **GS-012 · Console lane — PowerPC (Xbox 360 / GC / Wii)** — PPC/VMX128 bit-exact vs reference · **T2** · deps GS-001. *(Xenon proven desktop-only 2025.)* **[P4]**
- **GS-013 · Console lane — MIPS (N64/PS1) + PS2 spike** — N64/PS1 match reference-emu trace; PS2 VU/GS gap pinned or deferred · **T3** · deps GS-001/002. **[P4]**

### Pillar 2 — Graphics (one unified layer)
- **GS-018 · One unified shader IR** — every frontend lowers to one IR, one WGSL backend; **static audit proves exactly one emitter** · **T1** · extends BPTK-020. *Kills the three-emitter drift.*
- **GS-019 · DXBC/DXIL frontend → IR** — reuse DXVK/dxil-spirv→SPIR-V→Tint reader; unsupported opcodes named not dropped · **T3** · extends BPTK-032. **[P4]**
- **GS-020 · D3D9 SM1–3 → IR** — BPTK-020 corpus emits byte-identical IR-WGSL; standalone SM emitter deleted · **T1** · extends BPTK-020.
- **GS-021 · GLSL / ARB / Glide frontend → IR** — GL + two-TMU Glide combiner render within tolerance via IR · **T3**.
- **GS-022 · Fixed-function pipeline compiled once** — N-light × M-stage-op × fog/alpha matrix from ONE generator; D3D7/8/9/GL identical-state → identical IR · **T1** · extends BPTK-018/019.
- **GS-023 · FFP texgen / projective / shadow-cookie correctness** — spotlight-cookie + planar-shadow fixture within tolerance; dropped projection divide fails closed · **T1** · deps GS-022. *The named silent-wrong-shadow bug.*
- **GS-024 · Honest capability reporting** — advertised D3DCAPS shader-model ≤ real translator support; **advertising SM3 with an SM1.x frontend is red by construction** · **T1** · extends BPTK-017.
- **GS-025 · Frame-diff regression (generated references)** — ΔE + SSIM vs a reference **computed at test time** (no committed golden — respects `doc/TESTING.md`) · **T1** · extends BPTK-003. *Reconciled (graphics+correctness); resolves the committed-baseline conflict.*
- **GS-026 · WebGPU primary backend (IR→WGSL)** — all FFP+SM1-3 fixtures render on a live adapter · **T1**.
- **GS-027 · WebGL2 GLSL-ES fallback** — same IR → GLSL ES 3.0; within-floor fixtures match WebGPU within looser tolerance, above-floor named-blocked · **T2** · extends BPTK-017.
- **GS-028 · WebGPU compatibility-mode backend** — Chrome 146 `featureLevel:"compatibility"` → GLES3.1/D3D11-class GPUs; out-of-subset WGSL caught at emit · **T2**.
- **GS-029 · Presentation / swapchain / gamma / dirty-rect** — sRGB gamma correct (mid-gray ΔE), dirty-rect region-only, present pacing in budget · **T1** · extends BPTK-013.
- **GS-030 · MSAA / multisample resolve / format conversion** — 4× edge resolves within tolerance; unsupported count → declared fallback, reported · **T2**.
- **GS-031 · EDRAM / tiling / console framebuffer (research)** — feasibility report + prototype of EDRAM-tile-resolve→WebGPU · **T3** · extends BPTK-032/033. **[P4]**
- **GS-032 · Compute / UAV-SSBO / modern shaders** — compute fixture bit-identical on live WebGPU; above-limit named-blocked (WebGPU/compat-only) · **T3**. **[P4]**
- **GS-033 · Shader-translator hostile-bytecode containment** — malformed/fuzzed DXBC/DXIL/SM/GLSL refused in time+memory bound, zero OOB/crash (DarthShader class) · **T1** · extends BPTK-004/044.
- **GS-034 · Content-addressed pipeline/shader cache** — warm cache → zero cold-compile frames over budget; content-hash keys invalidate precisely · **T2** · extends BPTK-022.

### Pillar 3 — Correctness & compatibility (the Wine-scale surface)
- **GS-036 · Generic Win32/DirectX conformance suite** — synthetic + captured traces per API; return/last-error/out-bytes/side-effects vs oracle; any runtime export with zero case = coverage hole = fail · **T1** · extends BPTK-010/003. *What BottleShip structurally lacks.*
- **GS-037 · Captured API-trace corpus** — every trace has provenance + redaction proof + byte-stability · **T1** · extends BPTK-002.
- **GS-038 · Compatibility rating scheme with provenance** — ladder broken→boots→in-game→playable→complete; each rung only on a passing predicate; no rating above highest-passing (no false green) · **T1** · extends BPTK-030.
- **GS-039 · Per-title deterministic reference/replay artifact** — two replays hash-match at all checkpoints; no embedded asset/PII · **T1** · deps BPTK-039, GS-006.
- **GS-040 · Public compatibility database** — every row regenerable from evidence + revision-pinned; stale/unprovenanced refused · **T2** · *Reconciled (correctness+ecosystem, → GS-080).*
- **GS-041 · HLE export-coverage ledger** — corpus imports ∩ HLE symbols; `absent`/`stub`-with-zero-case = tracked gap, release gate holds gap budget · **T1** · deps GS-036. *Kills the manual missing-export hunt.*
- **GS-042 · No-false-green promotion self-audit** — sabotage fixtures (wrong return, out-of-tol frame, inflated rating, stale provenance, nondeterministic replay) all rejected · **T1** · extends BPTK-003.
- **GS-104 · Real freeware/`.exe` corpus acquisition** — a versioned pipeline that **downloads lawfully-redistributable freeware games and freeware `.exe` programs** (games *and* utility programs) from named online sources, records provenance + license + hash, and stages them for testing; payload bytes stay out of git (provenance-only manifest, per R-003). Benchmark: the manifest resolves every entry to a redistribution basis + hash and rebuilds byte-stably; a non-redistributable or unlicensed entry is refused · **T1** · extends BPTK-002 · deps GS-084.
- **GS-105 · Run-real-`.exe` empirical harness** — actually execute each corpus binary end-to-end, headless, through the real `bptk ingest`/`run` path, recording reached-stage (loads / entry / interactive / crash) and, on failure, the **generic gap** that broke it (missing export, unimplemented API, unsupported instruction) — not a per-title patch. Benchmark: every corpus binary produces a reproducible run record with a stage and, on failure, a named generic gap that maps to a roadmap item · **T1** · extends BPTK-007/016 · deps GS-104, GS-041.
- **GS-106 · Generalization gate (anti-per-title metric)** — a candidate fix is accepted only when it raises the reached-stage of **≥ N distinct corpus titles**, measured by GS-105 before/after; a fix that helps exactly one title is refused unless declared a sandboxed last-resort adapter (R-006). Benchmark: the gate computes per-fix corpus-wide delta and blocks a merge whose only beneficiary is a single title · **T1** · deps GS-105, GS-041. *The direct fix for BottleShip's non-generalization.*
- **GS-107 · Non-game `.exe` program support** — the runtime targets arbitrary freeware Win32 *programs/utilities*, not only games (the "any `.exe`" half most competitors skip): console/GUI apps, no game loop, no D3D. Benchmark: a set of freeware utility `.exe` from the GS-104 corpus reach interactive/complete through generic Win32 HLE with the same conformance discipline as games · **T2** · extends BPTK-010 · deps GS-105, GS-057.
- **GS-108 · Time-travel debugger for recompiled/guest execution** — step forward **and backward** over a deterministic trace, inspecting guest memory, registers, stack, locals, and CFG at any instruction — the same debugger code running both in-browser (WASM) and as a TUI. Benchmark: on a recorded divergence, the debugger reconstructs exact guest state at any instruction index and reverse-steps to the **first instruction that differs** from the BPTK-009 reference oracle; identical results in the browser and TUI harness · **T2** · deps GS-010, GS-039. *Reverse-stepping to the first divergence is the decisive tool for the recompiler moat (GS-001/002); prior art: [qip wasm-debugger](https://github.com/royalicing/qip/blob/main/components/interactive/wasm-debugger.zig) (royalicing/qip, Zig, portable browser+TUI, time-travel).*

### Pillar 4 — Lanes beyond Windows (routing + each lane)
- **GS-043 · Diagnose-and-route front door** — ranked lane decision + confidence over the 8-lane taxonomy on a mixed corpus; mislabel = hard fail; no exec, no upload · **T1** · extends BPTK-007/037.
- **GS-044 · Universal `.bptk` bundle format** — lane-tagged envelope: decision + content-addressed payload + capability manifest + provenance; schema-pinned, lane≠payload refused; one host loads every lane · **T1** · extends BPTK-024. *Reconciled (lanes+platform).*
- **GS-045 · Source lane: build-system autodetect + patch-set** — CMake/autotools/Make/Meson detected, pinned Emscripten patch-set, reproducible in a clean env · **T3** · extends BPTK-006/021.
- **GS-046 · Engine lane: open-reimplementation runtime host** — matched title runs on its Wasm-built open engine (Xash/vkQuake/ScummVM…), assets from OPFS, zero engine/asset commingling, no-rights blocked · **T1** · extends BPTK-029/043. **[mid]**
- **GS-047 · Modern-PC lane: x86-64 + D3D10/11/12/Vulkan→WebGPU** — composed decision + prototype of one hard mapping (D3D11 binding→WGSL / Vulkan descriptor model) · **T3** · extends BPTK-031/032/033. **[P4]**
- **GS-048 · Modern web-native ingest (Unity/Godot/Unreal)** — an already-web-native export boots in the BPTK host under the capability manifest; disallowed-capability blocked · **T1** · deps GS-043/044. **[near-term — highest leverage, fastest demo].**
- **GS-049 · DOS / Win16 / Win9x lane via embedded emulator** — pre-Win32 inputs routed to a sandboxed DOSBox/86Box-class emulator; PE32 not mis-routed · **T3**.
- **GS-050 · Cross-lane fallback + confidence chain** — primary-precondition failure → declared next lane with recorded reason; no-viable → bounded `no-lane` · **T1** · extends BPTK-017.

### Pillar 5 — Runtime services
- **GS-052 · 3D/positional audio: XAudio2 · EAX · DS3D** — submix/voice-ramp/3D-geometry/EAX-reverb mix within tolerance, zero SAB underrun · **T1** · extends BPTK-014.
- **GS-053 · Full input: DirectInput · XInput · gamepad · touch · pointer-lock · rumble** — input-trace replay matches oracle incl. relative-motion + one rumble effect · **T1** · extends BPTK-011/027.
- **GS-054 · Storage & registry fidelity** — registry hive + Win32 path (case-insensitive/8.3/UNC/reserved) + quota rollback; base byte-unchanged · **T1** · extends BPTK-015.
- **GS-055 · Networking: Winsock/DirectPlay→WebRTC/WebSocket, lockstep, NAT** — session semantics + lockstep sync; only allowlisted endpoints, zero off-allowlist · **T1** · extends BPTK-026.
- **GS-056 · FMV sync & subtitles** — A/V drift in budget across seek/pause; cues on-time · **T2** · extends BPTK-040.
- **GS-057 · Win32 breadth: user32/gdi32/ole32/COM/CRT/SxS/msvbvm** — per-module conformance slice passes incl. COM marshaling, SxS activation, VB6 main window · **T1** · extends BPTK-010, deps GS-036/041.
- **GS-058 · Installer/CD/virtual optical drive** — DRM-free image mounts, sector reads hash-match, Red Book CD-audio in sync; DRM refused · **T2** · extends BPTK-038.
- **GS-059 · Locale / codepage / Unicode fidelity** — ANSI↔wide across codepages incl. DBCS byte-exact; CompareString/LCMapString match oracle · **T2**.
- **GS-060 · Frame-pacing / vblank scheduler** — cadence within jitter budget, speed host-throughput-independent, QPC/RDTSC busy-wait yields to rAF (no spin) · **T1** · extends BPTK-039. *Retires the 6500-line spin-loop.*

### Pillar 6 — Platform & delivery
- **GS-061 · Compressed content-addressed streaming** — per-chunk zstd/brotli; bytes-to-interactive ≤55% of uncompressed `.wgb`; each chunk hash-verified · **T1** · extends BPTK-022. *Beats uncompressed `.wgb`.*
- **GS-062 · Range/block streaming + prefetch + async guest I/O** — reaches interactive with payload partly unfetched; sync guest read of absent block serviced without frame stall (via BPTK-034) · **T1** · deps GS-061.
- **GS-063 · Embedding SDK: HTML / React / Web Component / iframe** — all four hosts → identical runtime artifact; remount leaks zero worker/audio/GPU; iframe sandboxed · **T1** · extends BPTK-024.
- **GS-064 · PWA / offline install** — interactive offline after one run; SW serves only hash-verified chunks; updates invalidate exactly changed chunks · **T2** · extends BPTK-022.
- **GS-065 · Hosting-constraint automation (COOP/COEP)** — emitted headers yield `crossOriginIsolated`; absent-isolation → single-thread bundle, never a broken SAB build · **T1** · extends BPTK-025.
- **GS-066 · Cross-title CDN asset dedup** — shared redistributables stored/served once; cross-title cache-hit zero re-download; never merge differing hashes · **T2** · deps GS-061, BPTK-041.
- **GS-067 · Cloud save sync** — only the overlay diff uploads, base/hash-matching files never transmitted; deterministic conflict resolution · **T1** · extends BPTK-015.

### Pillar 7 — Games, library & authoring
- **GS-068 · Game catalog UI + metadata schema** — every entry validates frozen schema; `instant-play` requires approved redistribution + passing capability profile; no-rights → BYO-only · **T3** · deps GS-063, GS-084.
- **GS-069 · Instant-play redistributable hosting** — hosted title interactive from cold browser; publish refuses any title without an in-date redistribution grant · **T1** · deps GS-061/066, GS-084.
- **GS-070 · BYO-file import into the library** — local classify+stage+launch, zero upload of game bytes, local-only entry never published · **T1** · extends BPTK-007/015.
- **GS-071 · First-party BPTK original / tech-demo games** — buildable from clean first-party source, instant-play hosted, and its passing run **is** the benchmark evidence for its capability · **T1** · deps GS-072, BPTK-003. *Real games beat synthetic fixtures.*
- **GS-072 · Authoring SDK / runtime-target API** — a new game built only on the public SDK runs in all four hosts under the same save/capability/containment invariants; semver API-stability contract · **T1** · extends BPTK-021/024. *Reconciled (lanes+platform).*
- **GS-073 · Community submission pipeline** — accepts profile+provenance (not assets); strips/refuses proprietary/PII; maps to a tracker entry; unattested claim can't promote a rating · **T2** · deps GS-079/080.
- **GS-074 · Preservation catalog with provenance** — append-only provenance (source/build-hash/redistribution-basis/attestation); export reproducible, PII-free · **T2** · deps GS-084.
- **GS-075 · Compatibility-ratings site** — rating shown only when backed by a reproducible BPTK-028 replay pinned to a browser profile + revision; stale ratings grey out · **T1** · extends BPTK-028/030.
- **GS-076 · Modding support** — mod overlay over read-only CoW base (base hash-unchanged), sandboxed to the game's containment, oversized mod refused at the bound · **T2** · extends BPTK-015/045.

### Pillar 8 — Ecosystem & governance (BottleShip loses here)
- **GS-078 · Clonable, non-stale repo + release process** — clean clone builds+gates in CI every push; **freshness gate fails if default branch older than a declared window**; releases reproducible from tag · **T1**. *vs 7-week-stale branch.*
- **GS-079 · Public issue + compatibility tracker** — templates enforce env+revision+repro-hash, bare reports rejected; triage-freshness SLA · **T3**. *vs empty tracker.*
- **GS-080 · Public compatibility database** — every row: title/build-hash + env + browser + revision + evidence; export byte-stable; no unbacked or PII rows · **T2** · deps BPTK-028. *Reconciled (→GS-040).*
- **GS-081 · Test-first + ratcheting coverage bar** — merge fails if a runtime surface lands without a linked benchmark or coverage on runtime modules drops below the floor · **T1** · extends BPTK-003. *vs ~10% tests.*
- **GS-082 · Multi-maintainer / kill bus-factor-1** — CODEOWNER review ≠ author; release needs ≥2 signers; `MAINTAINERS.md` + recovery path (mechanism testable before a 2nd human exists) · **T2**. *vs bus-factor-1.*
- **GS-083 · Human + AI-agent contributor pipeline** — human and agent PRs accepted only through the same benchmark+coverage+authorship-disclosure gate · **T3** · deps GS-079/081/082.
- **GS-084 · License / reuse / provenance graph** — resolves every component→license + every hosted title→redistribution basis; publish/host/bundle refused on unlicensed/incompatible/expired node · **T1** · extends BPTK-001. *Reconciled (lanes SBOM + ecosystem); load-bearing for GS-069/074.*
- **GS-085 · Governance/RFC + telemetry-free analytics + community** — breaking change to SDK/`.bptk`/CLI needs a merged RFC; analytics aggregate/opt-in/PII-free (byte-audited); code of conduct + community space · **T2** · deps GS-082/BPTK-028.
- **GS-101 · Lane / accuracy honesty badge + documented unsupported set** — every title and program surfaces its execution lane (*AOT-recompiled* / *interpreted-JIT* / *emulated* / *web-native*) and accuracy caveats, and the project publishes a machine-readable **unsupported set** (kernel anti-cheat, DRM classes, unproven APIs) so no capability is implied that isn't measured. Benchmark: every catalog/run surface renders the correct lane+accuracy label from the bundle's recorded lane (GS-044), and a title in the unsupported set can never be marked playable · **T2** · deps GS-044, GS-038. *Truthfulness as a feature — the anti-"we run Valorant" gate.*

### Pillar 9 — Security & safety ("any .exe ≠ any trust")
- **GS-086 · Per-lane guest containment** — every lane its own confinement profile; web-native can't reach `window.parent`, emulator can't open host FS beyond bundle; any escape fails · **T1** · extends BPTK-045.
- **GS-087 · Cross-lane resource-exhaustion bounds** — decompression-bomb / unbounded-stream / OPFS-quota / GPU-flood / worker-flood each fail closed; recomp+emulator enforce instruction/time budget · **T1** · extends BPTK-044.
- **GS-088 · DRM / copy-protection detect-and-REFUSE** — labelled protection corpus routed to `refuse` with the protection named; **zero unwrap/patch artifact emitted for any protected input** · **T1** · extends BPTK-037.
- **GS-089 · Malware / threat scan of untrusted input** — benign corpus passes, EICAR/known-bad flagged pre-exec, flagged web-native script quarantined; local-only, bounded · **T1** · extends BPTK-004.
- **GS-090 · Capability-based permission manifest + consent** — bundle declares least-privilege set; undeclared-capability use denied + surfaced; default deny-network / OPFS-scoped · **T1** · deps GS-044/086.
- **GS-091 · Trust-tier legal boundary for arbitrary executables** — attested→full lanes; unknown-untrusted→scan+inspect only, no net/persistence; DRM/anti-cheat/illegal→refused; tier can't silently upgrade · **T3** · extends BPTK-004/001.

### Pillar 10 — Performance bars (the numbers that define "gold standard")
Each is pass/fail against the reference machine profile BPTK-002 must pin.
- **GS-092 · MIPS throughput floor** — ≥ **770 MIPS** on the reference desktop for the frozen CPU-bound workload (BottleShip's own "required" figure; it reaches 174) · **T1** · deps GS-001.
- **GS-093 · Recompile-vs-interpret speedup** — recompiled ≥ **5×** the BPTK-009 interpreter AND ≥ **50%** of native · **T1**. *The moat metric.*
- **GS-094 · Frame-time budget / per-lane fps floor** — p99 ≤ **16.67 ms** (60 fps) / ≤ **33.3 ms** (30 fps console) per the lane matrix · **T1**.
- **GS-095 · Cold-start / time-to-first-frame** — ≤ declared budget (e.g. ≤5 s cold / ≤1.5 s warm) incl. WASM compile + streamed assets · **T2**.
- **GS-096 · Memory ceiling + guest-host boundary cost** — peak ≤ declared ceiling (e.g. ≤2 GB, no unbounded growth) + per-crossing cost under bound · **T1**.
- **GS-097 · Audio-underrun + input-to-photon latency** — zero underruns over a sustained run; input-to-photon ≤ declared bound (e.g. ≤50 ms) · **T2**.
- **GS-098 · Sustained-run stability / jitter** — over ≥30 min: jitter (p99.9−median) under bound, no GC/compile pause > one frame, memory returns to baseline · **T2**.

---

## Phasing

- **Near-term** (extend existing red items / integration): GS-043 router, GS-044 bundle, **GS-048 web-native ingest (fastest new-frontier demo)**, GS-045 source-autodetect, GS-049 DOS lane, GS-050 fallback, the whole security layer (GS-086–091), GS-084 license graph, GS-061/062 streaming, the governance items (GS-078/079/081/082 — cheap CI+policy, land before contributors grow), GS-018/020/022/024/025 graphics-unification core, GS-036/041 conformance apparatus, and — foundational — **GS-104/105/106 (download a real freeware/`.exe` corpus, run it, gate on generalization)**: the empirical loop that keeps the whole program honest, since generality can only be *measured* against real binaries, not asserted.
- **Mid-term (P2–P3, ambitious build):** GS-001 i386 recompiler (the moat) + GS-002/003/011, GS-006 SMP, GS-007 SIMD, GS-046 engine runtime, GS-072 authoring SDK, GS-071 first-party games, GS-052–060 runtime services, GS-063/065/067 platform, GS-068–076 library.
- **P4 multi-year research** (behind the existing reproducible-prototype-or-defer gate): GS-004 x86-64, GS-012/013 console recomp (N64 only near-credible), GS-047 modern-PC + D3D10-12/Vulkan, GS-019/031/032 modern graphics. Hard blockers: memory64 maturity, WebGPU feature gaps (bindless/sync), console recomp proven desktop-only in 2025.

## Sequencing keystones
1. **GS-084 (license/provenance graph)** lands early — nothing hosts or bundles without it; the essential rail for "any .exe / host redistributables."
2. **GS-001 (recompiler)** is the technical keystone; GS-002/003 make it *sound* on real binaries; the perf bars (GS-092/093) only measure once GS-001 + BPTK-002's reference profile exist.
3. **GS-072 (SDK) → GS-071 (first-party games) → wired into BPTK-003** gives a lawful, always-available corpus and turns synthetic fixtures into real games.
4. **Governance (GS-078/081/082)** is cheap, early, and the direct answer to every BottleShip non-technical weakness.

## Gold-standard quality contract (publish on day one)

The bar communities (Digital Foundry, ProtonDB, emulation/speedrun/preservation)
actually grade on — not "boots the ROM":

- **Frame time, not average fps:** p99 ≤ 16.67 ms @60, ≤ 8.33 ms @120 (GS-094).
- **Gameplay-timing independence:** higher fps must not change physics — a
  hard speedrunner/preservation requirement (Zelda64Recomp states it in its README).
- **Input-to-photon** treated as a feature (GS-097); "no round trip" is Entity's whole pitch.
- **Honesty labels:** every title badges its lane — *"AOT-recompiled"* vs
  *"interpreted/JIT"* vs *"emulated"* — and ships a **documented unsupported set**.
  Never a fake "we run Valorant." (New: **GS-101 · lane/accuracy honesty badge**, T2.)
- **Byte-identical identity mode:** an "enhancements off" mode reproduces the
  original bit-for-bit (PSXRecomp's 4:3 identity model) — the preservation oracle.
- **Reproducible recompilation:** same dump + same jump-table TOML → bit-identical
  WASM (already the intent behind GS-001/GS-010).
- **CheerpX ceiling check:** CheerpX JITs friendly x86 at 2–3× native; if our AOT
  path is slower than a JIT, the thesis has failed (guards GS-093).
- **Time-to-first-frame < 3 s** on a cached title (itch/Poki bar) — streaming
  `compileStreaming` + OPFS cache is table stakes (GS-062/064/095).

## Preservation-ethics contract (non-negotiable for a library/archive)

- **87% of US pre-2010 games are commercially unavailable** (Video Game History
  Foundation, 2023), and the **US Copyright Office refused to expand DMCA §1201**
  for remote library access to preserved games (2024-10-25). The legal ground is
  hostile, so the architecture must be clean by construction.
- **Never ship assets.** Hash-verify the user's own dump; **fail closed on the
  wrong revision**. Keep a rights architecture with three explicit modes:
  user-owned-file, licensed-catalog, and library/archive — Yuzu is the cautionary
  prior; Flashpoint/Ruffle the positive one. (Hardens GS-069/070/074/084/091.)
- **Split licenses** (MIT tool / GPL port, per N64Recomp) so a port never poisons
  a downstream store — a machine-checked edge in GS-084.

## Accessibility — the pillar the first ten missed (reviewers grade *platforms* now)
- **GS-099 · Runtime-level accessibility injection** — remappable input, stick
  deadzone/inversion, gyro-as-mouse, subtitle/caption injection, colorblind
  palettes, UI scale, reduced-flash, hold-to-press, extra save slots — **available
  even when the original game has none** (the Zelda64Recomp / Steam Deck bar).
  Benchmark: each feature verifiably alters the running title against a fixture ·
  **T2** · deps GS-053, GS-072.
- **GS-100 · Shell WCAG 2.2 conformance** — library, launcher, and overlays meet
  WCAG 2.2 AA (keyboard, focus, contrast, target size, motion, status). Benchmark:
  automated + manual audit passes; extends BPTK-027 · **T2** · deps GS-063/068.
  Grounded in the [Game Accessibility Guidelines](https://gameaccessibilityguidelines.com/)
  and [WCAG 2.2](https://www.w3.org/TR/WCAG22/).

## More 2026 primitives a 2024 design would miss (extensions)
- **GS-102 · Live-service revival: server reimpl + "server-dead → local stub"** —
  packet-capture hooks + a local server stub so an always-online title survives its
  shutdown (preservation's actual enemy per VGHF) · **T3** · extends GS-055. **[P4]**
- **WebCodecs** for FMV decode (fold into GS-056); **WebHID** for fight sticks/wheels
  (fold into GS-053); **IWA + Direct Sockets** as the high-trust dual-path for real
  UDP/TCP netcode, with WebTransport/WebRTC on the open web (fold into GS-055);
  **stack-switching/continuations** — not shipped in browsers yet, so **freeze the
  ABI now** (design-time note on GS-006/GS-060); **Safari 26 WebGPU is the gate**,
  not Chrome — feature-detect memory64/JSPI/relaxed-SIMD, never assume parity.

## The four-lane framing (external validation of the pillars)
The AOT-recomp lane (P1/P4 console) wins bring-up and preservation; the
source/engine-export lane (P4 web-native) wins modern/native-web quality; a
binary-virtualization lane (CheerpX-class JIT / Boxedwine 32-bit Wine / v86 for
whole machines) is the honest fallback for copy-protected/self-modifying/OS-level
software (GS-003/GS-049); and a museum/cloud fallback (IWA Direct Sockets, and
Pixel-Streaming for titles no client lane can touch) covers the rest.

**Non-goals to print so we never lie:** kernel anti-cheat, arbitrary x86-64 AOT in
2026, first-party Unreal-in-WASM, Wine 11 + DXVK inside Chrome, hardware DXR. The
closest clean-room prior worth watching is **retrowin32** (Win32-on-WebGPU,
clean-room — the right long-term vs hauling Wine into WASM, but tiny coverage today).

## Research frontier (fund as P4 *programs*, not sprint tickets)
Nobody has a general solution to any of these — they are the honest edge of the field:
general x86-64 static AOT (indirect jumps/SEH/SMC/packed retail — CheerpX exists
*because* this is unsolved); **D3D12/Vulkan → WebGPU feature-complete** (bindless,
mesh/work-graphs, hardware RT — WebGPU is a generation behind vkd3d-proton); **GPU
command processors** (N64 RDP/RSP, 360 Xenos+XMA, PS2 VU1/GS — "where recomp-the-CPU
dies"); 64-bit guest in a browser (memory64 ~16 GB cap + mobile tab-killers); PC-grade
threads (NT sync ≠ `Atomics.wait`); sockets on the open web; timing closure
(cycle-accurate vs unlocked-120 with deterministic ticks + cross-version savestates);
anti-cheat/DRM (a documented unsupported set + a v86/Boxedwine museum lane, never a
fake claim); shader/pipeline caches at library scale; SMC/overlay ISAs at PC scale;
mobile/iOS policy (no sideloaded IWAs on iPhone); security of "run any EXE"
(Spectre-class timers, malicious mods — signed catalogs, no native mod code);
and the legal/governance research itself (§1201 denial makes the archive mode a
research problem, not just code).

## Fanout readiness — promotion contract (for Z-code)

The machine-readable work-list is [roadmap-gold-standard.json](roadmap-gold-standard.json)
(one object per `GS-###`: pillar, tier, phase, `extend`, `dep`, `spec`). To promote
one `GS-###` into a ratified, gate-green `BPTK-###` item, edit these **in one atomic
change** (the same reconciliation Z-code already ran for BPTK-037–045):

1. `bench/roadmap/manifest.json` — add the item (11 fields; `promotion_state:"planned"`; `kind` runtime|evidence; `source_evidence`); bump `count.accepted` **and** `count.raw`.
2. `bench/roadmap/spec/bptk-NNN.json` — new spec (15 fields; planned ⇒ `state:"red"`, `gate:"excluded"`; runtime ⇒ `threshold_owner:"BPTK-002"`; `fixture` must exist in `bench/roadmap/fixture/catalog.json`).
3. `ROADMAP.md` — one 7-column row in the correct phase table; update the discovery-denominator + `Accepted` counts + the `0 / N (0%)` coverage strings.
4. `bench/roadmap/candidate.json` — one sequential `CAND-###` (accepted) + bump `origin_count`.
5. `doc/source-audit.md` — a `### SRC-###` block for any new source referenced by the row.
6. `README.md` — the `Roadmap candidate` / `Accepted item` / coverage-string counts.
7. `doc/roadmap-rejected.md` — the count-reconciliation table.
8. Regenerate `data/status.json` (`node script/status.mjs`) and update the hardcoded accepted count in `test/cli.test.mjs`.

**Verifier:** `npm run gate` must exit 0 after each promotion (it reconciles every count above). Recommended promotion order = the phasing section: near-term Tier-1 first (start with **GS-104/105/106** so generalization is measured, **GS-084** the legal rail, **GS-048** the fastest demo, then **GS-001** the moat), deferring `[P4]` items behind the existing research gate.

## Relationship to the ratified roadmap
The 45 `BPTK-###` items remain the gate-validated, benchmark-owning subset and map into these pillars (e.g. BPTK-009→P1, BPTK-017/020→P2, BPTK-002/028→P3, BPTK-005/006/016/029/036/043→P4, BPTK-010–015/026/037–041/044/045→P5/P9, BPTK-022/024/025/030→P6). Each `GS-###` is promoted into a `BPTK-###` row + spec when its work starts, keeping `npm run gate` the single source of ratified truth.
