# Source audit

## Method and boundary

This audit cites and summarizes prior art for factual research. No source, binary, asset, or documentation from a referenced project is incorporated into BPTK; the current inventory and future incorporation rule are recorded in [third-party.md](third-party.md).

This is a bounded, fresh audit performed on 2026-07-18. Each named prior art was checked at its authoritative project or documentation page. GitHub project is pinned to the default-branch commit observed that day; a recent commit is an activity signal, not a quality or compatibility guarantee.

Confidence describes the evidence for the stated capability:

- **High** — a standards source, authoritative platform documentation, or directly inspected repository state establishes the fact.
- **Medium** — a project reports a runtime capability or title result that this audit did not independently execute.
- **Gap** — a required fact could not be confirmed; BPTK must not rely on it.

No source was copied into BPTK during this planning pass.

## Product and runtime precedent

### SRC-001 — Apple Game Porting Toolkit 4

- Authoritative source: [Apple Game Porting Toolkit](https://developer.apple.com/games/game-porting-toolkit)
- Revision checked: live version 4 page, 2026-07-18
- License class: Apple platform tooling and terms; study the workflow, do not copy implementation or trade dress
- Demonstrated capability: evaluates an unmodified Windows executable, reports performance and shader behavior, provides porting example, shader conversion, profiling, and platform integration tool.
- Limitation for BPTK: Apple-device and Metal target; it is not a browser runtime and is not upstream source for reuse.
- Confidence: High
- Roadmap influence: separate evaluation from shipping, pair compatibility measurement with an actual porting path, and include profiler and packaging work.

### SRC-002 — BottleShip

- Authoritative source: [jenissimo/bottleship](https://github.com/jenissimo/bottleship)
- Revision checked: `a7c8543d7556`, 2026-07-14
- License class: Apache-2.0, with BSD-2 and other bundled third-party notice called out upstream
- Demonstrated capability: loads real PE32 game, executes x86 through a v86 fork, reimplements Win32 and COM, translates DirectDraw and Direct3D 3–9 to WebGPU, maps audio to WebAudio, stores file in OPFS, imports folder and selected GOG installer, and reports multiple title reaching gameplay.
- Limitation for BPTK: upstream labels itself early and rough; its current requirement includes WebGPU and SharedArrayBuffer, and its compatibility result is not a universal contract.
- Confidence: High for license, revision, and documented architecture; Medium for runtime and title result because BPTK has not independently reproduced them.
- Roadmap influence: primary binary-lane reuse candidate and the baseline to beat before a rewrite.

### SRC-003 — wemu

- Authoritative source: [44670/wemu](https://github.com/44670/wemu)
- Revision checked: `a84441c89362`, 2026-07-16
- License class: Apache-2.0
- Demonstrated capability: experimental PE32 loader, i386 interpreter, compact USER/GDI, Kernel32, WinMM, DirectDraw and runtime HLE, deterministic headless output, and browser ZIP mounting.
- Limitation for BPTK: explicitly not a general Windows emulator; compatibility is incomplete and sound output is not implemented.
- Confidence: High
- Roadmap influence: useful smaller HLE architecture comparison and evidence for deterministic fixture.

### SRC-004 — Boxedwine

- Authoritative source: [danoon2/Boxedwine](https://github.com/danoon2/Boxedwine)
- Revision checked: `15ef5bf11c5f`, 2026-06-24
- License class: GPL-2.0
- Demonstrated capability: runs 16-bit and 32-bit Windows program by combining 32-bit Wine with Linux-kernel and CPU emulation across native and Emscripten target.
- Limitation for BPTK: upstream states the web build is slow, lacks a JIT, and its multithreaded build stutters with sound; the GPL boundary is materially different from permissive reuse.
- Confidence: High
- Roadmap influence: full-stack compatibility reference and warning against carrying an entire guest environment into the first browser milestone.

### SRC-005 — v86

- Authoritative source: [copy/v86](https://github.com/copy/v86)
- Revision checked: `2f1346b0e7d8`, 2026-07-05
- License class: BSD-2-Clause
- Demonstrated capability: browser x86 PC emulation with runtime translation of machine code to WebAssembly module.
- Limitation for BPTK: missing multicore and 64-bit extension, with an instruction set around Pentium 4 and known exception gap; a full PC emulator does not itself provide a Windows game HLE.
- Confidence: High
- Roadmap influence: permissive CPU/JIT candidate and explicit boundary for x86-64 research.

### SRC-006 — Emscripten

- Authoritative source: [emscripten-core/emscripten](https://github.com/emscripten-core/emscripten)
- Revision checked: `91f02346bdc3`, 2026-07-17; project page showed release 6.0.3 on 2026-07-13
- License class: dual MIT and University of Illinois/NCSA
- Demonstrated capability: compiles C and C++ through LLVM to WebAssembly and supplies browser support for portable API such as SDL and OpenGL.
- Limitation for BPTK: requires source or recompilable dependency; desktop OS behavior, raw socket, dynamic native module, and unsupported graphics feature still require adaptation.
- Confidence: High
- Roadmap influence: canonical source-assisted lane.

### SRC-007 — d3d9-webgl

- Authoritative source: [LostMyCode/d3d9-webgl](https://github.com/LostMyCode/d3d9-webgl)
- Revision checked: `9f2543a84881`, 2026-03-16
- License class: MIT
- Demonstrated capability: a small Direct3D 9 fixed-function wrapper that maps source-level D3D9 call to WebGL2 under Emscripten.
- Limitation for BPTK: fixed-function and source-assisted scope; it is not a PE runtime, complete D3D9 implementation, or programmable-shader solution.
- Confidence: High
- Roadmap influence: fixture reference for a source-level D3D9 adapter and proof that graphics subproblem should be separated.

## Engine-family and preservation precedent

### SRC-008 — OpenSA

- Authoritative source: [AlexSergey/opensa](https://github.com/AlexSergey/opensa)
- Revision checked: `da092a337141`, 2026-07-11
- License class: AGPL-3.0
- Demonstrated capability: from-scratch TypeScript and Three.js engine compatible with a RenderWare asset family, including DFF, TXD, COL, IMG, IPL and IDE behavior in the browser.
- Limitation for BPTK: title-family engine replacement that depends on user asset; it does not execute arbitrary Windows game.
- Confidence: High
- Roadmap influence: engine-adapter lane and asset-import UX precedent.

### SRC-009 — WebXash

- Authoritative source: [x8BitRain/webXash](https://github.com/x8BitRain/webXash)
- Revision checked: `ff86609dac6f`, 2026-01-28
- License class: **Gap — no repository license file was present at audit time**
- Demonstrated capability: browser front end for a Xash3D WebAssembly build that reads a user-selected Half-Life or Counter-Strike folder into an in-memory Wasm file system.
- Limitation for BPTK: game-family scope, no persistent import in the described path, browser shortcut conflict, and no reuse permission established for this repository.
- Confidence: High for observed repository state; reuse confidence is Gap.
- Roadmap influence: study-only import UX and a hard rule that public source without a license is not reusable.

### SRC-010 — Qwasm2

- Authoritative source: [GMH-Code/Qwasm2](https://github.com/GMH-Code/Qwasm2)
- Revision checked: `c9ab09343d58`, 2026-04-18
- License class: GPL-2.0-derived and component-specific term; original game asset is separately restricted
- Demonstrated capability: Quake II engine source port with WebGL2 and software rendering, persistent browser save, gamepad, and user-provided PAK file.
- Limitation for BPTK: native game module needs separate Wasm compilation, networking is absent, engine renderer has switching limitation, and original PAK redistribution is restricted.
- Confidence: High
- Roadmap influence: source-port fixture design, asset separation, mod-module boundary, and network adaptation evidence.

### SRC-011 — ScummVM

- Authoritative source: [scummvm/scummvm](https://github.com/scummvm/scummvm)
- Revision checked: `d628bd41df34`, 2026-07-18
- License class: GPL-3.0, with component notice to verify
- Demonstrated capability: mature engine-family compatibility model for many adventure and role-playing title while keeping engine and game data separate.
- Limitation for BPTK: supported-engine reconstruction, not arbitrary Windows executable compatibility.
- Confidence: High
- Roadmap influence: compatibility catalog discipline, detector pattern, and preservation-oriented engine adapter.

## Native compatibility and graphics precedent

### SRC-012 — Wine

- Authoritative source: [wine-mirror/wine](https://github.com/wine-mirror/wine)
- Revision checked: `e8781e7c8d07`, 2026-07-17
- License class: LGPL-2.1-or-later
- Demonstrated capability: broad Windows API compatibility on POSIX system without a Windows virtual machine.
- Limitation for BPTK: native POSIX and system assumption do not map directly to the browser; linking, modification, and distribution obligations need counsel-backed review.
- Confidence: High
- Roadmap influence: behavioral reference and API test source, not an assumed browser drop-in.

### SRC-013 — Proton

- Authoritative source: [ValveSoftware/Proton](https://github.com/ValveSoftware/Proton)
- Revision checked: `d2bedfad4535`, 2026-06-18
- License class: Proton glue includes BSD-3-Clause; the distribution contains many component with separate license
- Demonstrated capability: integrates Wine and additional component into a game-focused compatibility distribution.
- Limitation for BPTK: Linux, Steam, Vulkan and native process model; whole-distribution licensing cannot be inferred from the top-level license.
- Confidence: High
- Roadmap influence: compatibility profile, component integration, regression catalog, and “distribution license is a graph” lesson.

### SRC-014 — DXVK

- Authoritative source: [doitsujin/dxvk](https://github.com/doitsujin/dxvk)
- Revision checked: `6b20f622a77b`, 2026-07-17
- License class: zlib
- Demonstrated capability: game-focused Direct3D 8–11 implementation over Vulkan for Wine.
- Limitation for BPTK: native Vulkan and Wine assumption; WebGPU is not Vulkan and lacks one-to-one feature parity.
- Confidence: High
- Roadmap influence: state translation, capability profile, shader cache, and conformance-test architecture.

### SRC-015 — vkd3d-proton

- Authoritative source: [HansKristian-Work/vkd3d-proton](https://github.com/HansKristian-Work/vkd3d-proton)
- Revision checked: `3dfc6f07d095`, 2026-07-10
- License class: LGPL-2.1
- Demonstrated capability: Direct3D 12 over Vulkan with game compatibility and performance as priorities.
- Limitation for BPTK: relies on modern Vulkan feature, descriptor capacity, native driver, DXGI integration, and recent hardware; it is research evidence, not a browser component plan.
- Confidence: High
- Roadmap influence: keeps Direct3D 12 in research until WebGPU capability and x86-64 foundation are proven.

## Browser constraint

### SRC-016 — Emscripten OpenGL support

- Authoritative source: [OpenGL support](https://emscripten.org/docs/porting/multimedia_and_graphics/OpenGL-support.html)
- Revision checked: documentation 6.0.4-git, 2026-07-18
- License class: project documentation reference
- Demonstrated capability: direct WebGL-friendly OpenGL ES subset plus optional legacy feature emulation.
- Limitation for BPTK: legacy emulation is less efficient and explicitly incomplete; desktop extension does not automatically exist in WebGL.
- Confidence: High
- Roadmap influence: source adapter must target a WebGL-compatible subset and benchmark every emulation choice.

### SRC-017 — Emscripten networking

- Authoritative source: [Networking](https://emscripten.org/docs/porting/networking.html)
- Revision checked: documentation 6.0.4-git, 2026-07-18
- License class: project documentation reference
- Demonstrated capability: WebSocket API, partial POSIX-over-WebSocket emulation, proxy option, Fetch, WebRTC and WebTransport integration path.
- Limitation for BPTK: browser page cannot open direct TCP or UDP socket; proxying can be incomplete or slow and changes deployment architecture.
- Confidence: High
- Roadmap influence: mediated network bridge is a separate P3 item rather than an implicit compatibility promise.

### SRC-018 — Emscripten pthread support

- Authoritative source: [Pthreads support](https://emscripten.org/docs/porting/pthreads.html)
- Revision checked: documentation 6.0.4-git, 2026-07-18
- License class: project documentation reference
- Demonstrated capability: stable pthread mapping through SharedArrayBuffer and worker.
- Limitation for BPTK: deployed thread build requires COOP and COEP, and a single binary cannot dynamically fall back between threaded and non-threaded execution.
- Confidence: High
- Roadmap influence: separate build profile and deployment-header test.

### SRC-019 — MDN SharedArrayBuffer

- Authoritative source: [SharedArrayBuffer](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer)
- Revision checked: page modified 2026-02-10, checked 2026-07-18
- License class: documentation reference under MDN term
- Demonstrated capability: shared JavaScript and WebAssembly memory across worker.
- Limitation for BPTK: sharing remains gated by secure, cross-origin-isolated context and associated response header.
- Confidence: High
- Roadmap influence: host and deployment capability probe.

### SRC-020 — MDN WebGPU

- Authoritative source: [WebGPU API](https://developer.mozilla.org/en-US/docs/Web/API/WebGPU_API)
- Revision checked: live page, 2026-07-18
- License class: documentation reference under MDN term
- Demonstrated capability: modern browser GPU rendering and compute API over native platform GPU API.
- Limitation for BPTK: MDN still marks it limited availability and secure-context-only; a fallback or declared browser floor remains necessary.
- Confidence: High
- Roadmap influence: WebGPU primary with an explicit WebGL2 compatibility profile, not silent feature loss.

### SRC-021 — MDN autoplay and WebAudio policy

- Authoritative source: [Autoplay guide for media and Web Audio APIs](https://developer.mozilla.org/en-US/docs/Web/Media/Guides/Autoplay)
- Revision checked: page modified 2025-09-18, checked 2026-07-18
- License class: documentation reference under MDN term
- Demonstrated capability: browsers expose WebAudio but generally gate audible playback on user interaction or an allowlisted policy.
- Limitation for BPTK: policy and exact blocking behavior vary by browser, and an AudioContext started outside user activation can remain suspended or fail to play.
- Confidence: High
- Roadmap influence: audio activation, denial, suspend, resume, and lifecycle are required benchmark cases for BPTK-014.

### SRC-022 — MDN OPFS, quota, persistence, and eviction

- Authoritative source: [Storage quotas and eviction criteria](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria)
- Revision checked: page modified 2026-01-05, checked 2026-07-18
- License class: documentation reference under MDN term
- Demonstrated capability: OPFS provides origin-private file and directory storage; browser storage is best-effort by default, exposes estimated quota, can raise `QuotaExceededError`, and can be evicted under storage pressure unless persistence is granted.
- Limitation for BPTK: quota, persistence grant, private browsing, and eviction policy vary by browser and device; data can disappear outside BPTK control.
- Confidence: High
- Roadmap influence: BPTK-015 and BPTK-022 must test quota failure, persistence state, eviction recovery, and backup or re-import behavior.

### SRC-023 — MDN File System API

- Authoritative source: [File System API](https://developer.mozilla.org/en-US/docs/Web/API/File_System_API)
- Revision checked: live page, 2026-07-18
- License class: documentation reference under MDN term
- Demonstrated capability: browser code can work with file and directory handle through permissioned user-selected access and origin-private storage.
- Limitation for BPTK: user-visible file access is permission- and browser-dependent, while OPFS is origin-scoped and not a transparent native Windows file system.
- Confidence: High
- Roadmap influence: local import must begin with explicit selection, preserve handle and permission state, and retain an OPFS-only fallback.

### SRC-024 — MDN CSP `worker-src`

- Authoritative source: [Content-Security-Policy worker-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/worker-src)
- Revision checked: live page, 2026-07-18
- License class: documentation reference under MDN term
- Demonstrated capability: Content Security Policy can constrain the origin from which Worker, SharedWorker, and ServiceWorker script is loaded.
- Limitation for BPTK: a package with an incompatible CSP or worker path can fail before Wasm execution even when the runtime itself is correct.
- Confidence: High
- Roadmap influence: BPTK-024 and BPTK-025 package tests must cover CSP, worker URL, static hosting, and isolation header together.

### SRC-025 — MDN Fullscreen API

- Authoritative source: [Fullscreen API](https://developer.mozilla.org/en-US/docs/Web/API/Fullscreen_API)
- Revision checked: page modified 2026-03-26, checked 2026-07-18
- License class: documentation reference under MDN term
- Demonstrated capability: a document can request and exit fullscreen, observe state and error, and expose an explicit user escape path.
- Limitation for BPTK: MDN marks the API limited availability; Permissions Policy can disable it, and tab or application switching exits fullscreen.
- Confidence: High
- Roadmap influence: BPTK-027 must test request denial, state change, focus recovery, and a visible exit path.

### SRC-026 — MDN Pointer Lock API

- Authoritative source: [Pointer Lock API](https://developer.mozilla.org/en-US/docs/Web/API/Pointer_Lock_API)
- Revision checked: live page, 2026-07-18
- License class: documentation reference under MDN term
- Demonstrated capability: pointer lock supplies relative mouse movement and a canvas-oriented first-person control path.
- Limitation for BPTK: MDN marks it limited availability; an engagement gesture is required, the user can exit with a browser gesture, and raw unadjusted movement is not available everywhere.
- Confidence: High
- Roadmap influence: BPTK-027 must test activation, denial, relative movement, fallback, unlock, and focus recovery.

### SRC-027 — MDN Gamepad API

- Authoritative source: [Gamepad API](https://developer.mozilla.org/en-US/docs/Web/API/Gamepad_API)
- Revision checked: live page, 2026-07-18
- License class: documentation reference under MDN term
- Demonstrated capability: browser page can detect connected controller and poll button, axis, identity, and mapping state.
- Limitation for BPTK: device layout, mapping, connection disclosure, vibration, browser behavior, and permission or engagement condition can vary.
- Confidence: High
- Roadmap influence: BPTK-027 needs a normalized logical-action layer, remap UI, dead-zone rule, hot-plug behavior, and device-specific artifact.

### SRC-028 — W3C WCAG 2.2 quick reference

- Authoritative source: [How to Meet WCAG 2.2](https://www.w3.org/WAI/WCAG22/quickref/)
- Revision checked: live W3C reference, 2026-07-18
- License class: W3C documentation reference
- Demonstrated capability: testable accessibility success criterion for keyboard operation, focus, contrast, target size, motion, status message, and related web interaction.
- Limitation for BPTK: game content can have genre-specific accessibility need beyond the workbench and host UI; conformance cannot be inferred from framework choice.
- Confidence: High
- Roadmap influence: BPTK-027 owns accessible workbench and host control, and each adapter must declare game-content accessibility support separately.

### SRC-029 — WebAssembly 3.0 feature set

- Authoritative source: [WebAssembly features](https://webassembly.org/features/)
- Revision checked: live specification reference, 2026-09-04
- License class: W3C and WebAssembly Community Group documentation reference
- Demonstrated capability: the WebAssembly 3.0 core standard (released 2025-09-17) folds tail calls, exnref exception handling, relaxed SIMD, memory64, multi-memory, garbage collection, and JavaScript string builtins into the language.
- Limitation for BPTK: per-feature browser support differs, and Safari lacks memory64 and ships relaxed SIMD behind a flag, so no feature can be assumed universally available.
- Confidence: High
- Roadmap influence: BPTK-035 owns the execution substrate that adopts tail calls, exnref, and relaxed SIMD with fallback, and BPTK-031 tracks memory64 as x86-64 research.

### SRC-030 — JavaScript Promise Integration for WebAssembly

- Authoritative source: [V8 JSPI](https://v8.dev/blog/jspi)
- Revision checked: live vendor reference, 2026-09-04
- License class: vendor engineering documentation reference
- Demonstrated capability: JSPI suspends and resumes a WebAssembly stack across a JavaScript promise, letting synchronous guest code call an asynchronous browser API without whole-module Asyncify instrumentation; shipped default in Chrome 137.
- Limitation for BPTK: Safari and Firefox stable shipping lags Chrome, so a feature-detected Asyncify fallback remains required for portability.
- Confidence: High
- Roadmap influence: BPTK-034 owns the blocking-call bridge that services a synchronous Win32 and storage call over an asynchronous browser API.

### SRC-031 — WebAssembly tail call, exception, and SIMD browser support

- Authoritative source: [Can I use WebAssembly relaxed SIMD](https://caniuse.com/wf-wasm-simd-relaxed)
- Revision checked: live compatibility reference, 2026-09-04
- License class: aggregated browser-support reference
- Demonstrated capability: tail calls and exnref exception handling are default across Chrome, Firefox, and Safari 18.2 through 18.4, and relaxed SIMD is default in Chrome and Firefox.
- Limitation for BPTK: Safari relaxed-SIMD status is unresolved and reported behind a flag, so a strict-SIMD fallback is required.
- Confidence: Medium
- Roadmap influence: BPTK-035 owns the substrate that selects these features or their fallback per browser profile.

### SRC-032 — Static recompilation to native and WebAssembly prior art

- Authoritative source: [Pepsiman Recompiled](https://pepsiman.ol.mr/)
- Revision checked: live project reference, 2026-09-04
- License class: third-party project reference
- Demonstrated capability: N64Recomp, PSXRecomp (Pepsiman Recompiled), and XenonRecomp statically recompile console machine code to C or C++ and then to a native or WebAssembly target, running at full frame rate rather than interpreting each instruction.
- Limitation for BPTK: static recompilation needs a per-title analysis pass and a legally obtained image, and it does not generalize to arbitrary no-source Win32, which remains the high-level-emulation lane.
- Confidence: Medium
- Roadmap influence: BPTK-036 evaluates per-title static recompilation to WebAssembly as a distinct fourth lane.

### SRC-033 — Browser game port prior art

- Authoritative source: [BottleShip](https://github.com/jenissimo/bottleship)
- Revision checked: live project reference, 2026-09-04
- License class: third-party project reference (Apache-2.0)
- Demonstrated capability: BottleShip runs an unmodified 32-bit PE game through a WebAssembly x86 core with high-level Win32 and DirectX emulation over WebGPU and OPFS, while NewShoes and reVC ship a large game as an Emscripten source port; both patterns run entirely client-side from a user-supplied image.
- Limitation for BPTK: these are early or single-title efforts, several famous-title ports have drawn DMCA takedown, and none supplies a reusable cross-title library.
- Confidence: High
- Roadmap influence: BPTK-034 and BPTK-036 draw on this browser-runtime and source-port evidence, and BottleShip remains the closest prior art for the binary lane.

### SRC-034 — Game middleware and copy-protection component catalog

- Authoritative source: [PCGamingWiki DRM and copy protection](https://www.pcgamingwiki.com/wiki/Category:DRM)
- Revision checked: live community reference, 2026-09-04
- License class: aggregated third-party compatibility reference
- Demonstrated capability: 1998 through 2008 Windows games ship identifiable middleware (Bink `binkw32.dll`, Smacker `smackw32.dll`, Miles `mss32.dll`, FMOD, DirectMusic, D3DX `d3dx9_##.dll`) and copy protection (SafeDisc `CLCD32.DLL`/`secdrv.sys`, SecuROM `.securom`, StarForce driver) detectable from PE import, section, overlay, and sibling-file evidence.
- Limitation for BPTK: copy protection that authenticates media geometry, decrypts a wrapper, or emulates a kernel driver is DRM and must be detected to refuse, never circumvented.
- Confidence: Medium
- Roadmap influence: BPTK-037 owns the census that routes each detected component to handle, warn, extract, or refuse.

### SRC-035 — Game timing and multicore guidance

- Authoritative source: [Game Timing and Multicore Processors](https://learn.microsoft.com/en-us/windows/win32/dxtecharts/game-timing-and-multicore-processors)
- Revision checked: live vendor reference, 2026-09-04
- License class: vendor engineering documentation reference
- Demonstrated capability: RDTSC is not a reliable clock across cores and power states; the guidance is to use QueryPerformanceCounter, pin the timing thread, and clamp a delta, and legacy games also mix GetTickCount, timeGetTime, and vertical-blank waits.
- Limitation for BPTK: a browser exposes performance.now, vertical-blank via requestAnimationFrame, and an AudioContext clock, none of which a 1999 busy-wait or beam-sync game expects, so all must derive from one source.
- Confidence: High
- Roadmap influence: BPTK-039 owns the single monotonic clock that serves every guest time source.

### SRC-036 — Installer extraction tooling

- Authoritative source: [innoextract](https://constexpr.org/innoextract/)
- Revision checked: live project reference, 2026-09-04
- License class: third-party project reference
- Demonstrated capability: an Inno Setup and GOG offline installer unpacks with innoextract and an InstallShield cabinet with unshield, without executing the installer, while a 16-bit setup stub cannot run on a 64-bit host.
- Limitation for BPTK: a GOG Galaxy binary-reassembly step and non-redistributable payload remain the responsibility of the user's legally obtained copy.
- Confidence: High
- Roadmap influence: BPTK-038 owns client-side installer extraction to the game payload.

### SRC-037 — Full-motion-video middleware decoding

- Authoritative source: [FFmpeg](https://ffmpeg.org/)
- Revision checked: live project reference, 2026-09-04
- License class: third-party project reference
- Demonstrated capability: FFmpeg decodes Bink1, Smacker, and VP6 bitstreams (ScummVM and BottleShip already use this), so a supported cutscene can be decoded and presented in the browser without the vendor codec DLL doing the bitstream work.
- Limitation for BPTK: Bink2 open decoding is incomplete, and proprietary WMV and Indeo bitstreams cannot be decoded lawfully in this scope and must be refused or pre-transcoded by the user.
- Confidence: Medium
- Roadmap influence: BPTK-040 owns supported full-motion-video decode and presentation.

### SRC-038 — Redistributable runtime component

- Authoritative source: [DirectX End-User Runtimes (D3DX redistributable)](https://www.microsoft.com/en-us/download/details.aspx?id=8109)
- Revision checked: live vendor reference, 2026-09-04
- License class: vendor redistributable component reference
- Demonstrated capability: almost every Direct3D 9 game needs an exact out-of-box D3DX redistributable (`d3dx9_24` through `d3dx9_43`), and late ports also need XInput, XAudio, Visual C++, Visual Basic 6, and DirectMusic instrument (`gm.dls`) components that ship as redistributables.
- Limitation for BPTK: only a redistributable component may ship; a non-redistributable runtime or the user's own build stays out of the repository.
- Confidence: Medium
- Roadmap influence: BPTK-041 owns the redistributable runtime kit that satisfies or reports each declared dependency.

### SRC-039 — Emscripten browser build configuration

- Authoritative source: [Emscripten pthreads](https://emscripten.org/docs/porting/pthreads.html)
- Revision checked: live project reference, 2026-09-04
- License class: third-party project reference
- Demonstrated capability: an Emscripten source build reaches SharedArrayBuffer threads only under cross-origin isolation (COOP and COEP), uses native WebAssembly exception rather than legacy handling, and drives a WASMFS OPFS backend through JSPI, which avoids the documented legacy-Asyncify OPFS incompatibility.
- Limitation for BPTK: the profile applies only to a source tree the user may lawfully compile, and JSPI shipping still lags on some browser, so an Asyncify fallback remains.
- Confidence: High
- Roadmap influence: BPTK-042 owns the pinned source-lane Emscripten build profile.

### SRC-040 — Open engine reimplementation for the browser

- Authoritative source: [ScummVM](https://www.scummvm.org/)
- Revision checked: live project reference, 2026-09-04
- License class: third-party project reference
- Demonstrated capability: an open engine reimplementation can run a supported game family in the browser from user-supplied asset — ScummVM for adventure engine, WebXash for GoldSrc, Qwasm2 for Quake, OpenSA and dhewm3 for their families — replacing the original engine binary while the player supplies legally obtained asset.
- Limitation for BPTK: each reimplementation has its own license and asset-format expectation, and an engine match does not guarantee full title compatibility.
- Confidence: Medium
- Roadmap influence: BPTK-043 fingerprints an engine family and routes it to a matching open reimplementation under the BPTK-029 adapter contract.

### SRC-041 — Resource-exhaustion and decompression-bomb defense

- Authoritative source: [CWE-409 Improper Handling of Highly Compressed Data](https://cwe.mitre.org/data/definitions/409.html)
- Revision checked: live reference, 2026-09-04
- License class: aggregated security reference
- Demonstrated capability: a compressed archive or asset stream can expand to exhaust memory or storage as a decompression bomb, and untrusted code execution can exhaust CPU and memory, so a defense must bound output size, expansion ratio, nesting depth, and a memory and time budget.
- Limitation for BPTK: a bound must admit a legitimate multi-gigabyte game yet refuse an amplification attack, which requires a per-surface budget rather than one global limit.
- Confidence: High
- Roadmap influence: BPTK-044 owns bounded-resource enforcement across extraction, streaming, and guest execution, and BPTK-045 owns guest containment.

## Synthesis

The audit supports a feasible, staged product but does not support an unrestricted compatibility claim. The highest-leverage route is:

1. measure BottleShip reuse or collaboration against a pinned fixture corpus;
2. keep Emscripten as a first-class source lane;
3. share importer, report, benchmark, package, and host adapter across lane;
4. target PE32 plus DirectDraw through Direct3D 9 before x86-64 or modern Direct3D;
5. make every compatibility statement reproducible and environment-specific.

## Unresolved source gap

- WebXash reuse permission is unconfirmed because the audited repository has no license file.
- Apple trademark and naming risk, Wine-family linking interpretation, and combined-work effect require qualified legal review before code integration or public launch.
- Prior-art feature was not independently benchmarked during this documentation-only pass; capability statement above is attributed to primary project evidence.
