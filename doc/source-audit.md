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
