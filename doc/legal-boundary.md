# Legal and distribution boundary

## Status and purpose

This is an engineering control, not legal advice. It prevents technical possibility from being confused with permission to copy, modify, link, distribute, host, or circumvent. Qualified counsel must review the public name, combined-work architecture, upstream component graph, and any commercial title program before a runtime launch.

BPTK-authored material in the current planning repository is licensed under Apache-2.0. `NOTICE` identifies the copyright holder and current third-party state, while [third-party.md](third-party.md) defines the incorporation ledger. Apache-2.0 applies only to BPTK-authored material; it does not relicense an upstream component or user-supplied game. Until BPTK-001 passes, upstream code must not be copied into this repository.

BPTK-001 remains planned because selecting an outbound license for the current repository does not approve a future runtime dependency graph, BottleShip relationship, copyleft boundary, or public-name clearance.

## Default rule

An imported game remains the user’s local content. BPTK may inspect and transform it locally only after explicit user action. BPTK does not grant a game license, does not transfer ownership, and does not make a commercial asset redistributable.

Technical status and distribution status are separate field:

- `technical_state`: whether BPTK can classify, load, boot, render, or play the input.
- `distribution_state`: whether BPTK may ship the runtime, patch, fixture, engine, asset, installer, screenshot, name, and combined package.

Neither field implies the other.

## Boundary matrix

| Boundary | Default action | Required evidence before ship | Stop condition |
|---|---|---|---|
| Source reuse | Study only until license and provenance are recorded | Exact upstream revision, file-level license, notice, author, modification ledger | Missing or conflicting license |
| Static or dynamic linking | Treat as a combined-work question | Counsel-backed interpretation for the actual link and distribution model | Copyleft obligation conflicts with chosen outbound model |
| Source patch | Keep a minimal, reviewable patch ledger | Upstream base revision, patch author, license, test, offer-of-source obligation where applicable | Patch provenance is unknown |
| Browser redistribution | Ship only BPTK runtime and redistributable fixture | Software bill of material, notice bundle, source-offer process, reproducible package | Package contains an unapproved binary or asset |
| Game executable | User-supplied executable stays local; only BPTK-authored or explicitly redistributable fixture may be hosted | Explicit distribution right for every hosted fixture | Commercial executable would be uploaded, hosted, or executed remotely |
| Game asset | User-supplied asset stays local; only BPTK-authored or explicitly redistributable fixture may be hosted | Asset license separately permits copying, transformation, and redistribution | Engine source is open but asset is not |
| Installer extraction | Local extraction of supported format only | User representation of lawful copy, bounded parser, no DRM bypass | Extraction requires circumvention or server upload |
| Firmware, BIOS, ROM, codec | Do not bundle by assumption | Independent redistributable implementation or explicit distribution right | Proprietary system image or patent-encumbered binary is required |
| DRM or anti-cheat | Do not bypass | Publisher-provided browser path or explicit authorization | Circumvention, kernel emulation, integrity defeat, or credential risk |
| Trademark and product name | Use nominative reference and independent branding | Name clearance, affiliation disclaimer, logo and trade-dress review | Likely confusion with Apple, Microsoft, Valve, publisher, or game brand |
| Patent | No implied grant beyond a source license’s actual term | Patent review for codec, shader, compression, anti-cheat, and distribution market | Required feature has unacceptable patent exposure |
| Platform-restricted tool | Use only within its permitted platform and purpose | Current term for Apple, Microsoft, console, SDK, or proprietary compiler | Tool output or component cannot be redistributed to the web target |
| Community compatibility report | Store observation with provenance | User consent, non-infringing metadata, environment, toolkit revision | Report includes uploaded proprietary file or unsupported claim |

## Prior-art reuse classification

| Source | Study | Adapt or fork | Link or combine | Browser redistribution note |
|---|---|---|---|---|
| BottleShip, Apache-2.0 | Yes | Candidate after notice and patent-term review | Candidate with third-party graph review | Preserve license, notice, modification, and bundled component obligation |
| wemu, Apache-2.0 | Yes | Candidate | Candidate | Preserve Apache notice and verify every dependency |
| v86, BSD-2-Clause | Yes | Candidate | Candidate | Preserve copyright and disclaimer |
| Emscripten, MIT/NCSA | Yes | Candidate toolchain | Candidate | Tool output and linked library still need their own review |
| d3d9-webgl, MIT | Yes | Candidate for source lane | Candidate | Preserve MIT notice; verify bundled header provenance |
| Boxedwine, GPL-2.0 | Yes | Only under compatible architecture | Material copyleft review required | Source and offer obligation may apply to distributed derivative |
| OpenSA, AGPL-3.0 | Yes | Only under compatible service and source model | Strong network-copyleft review required | Modified network service can trigger source-offer obligation |
| WebXash repository, no license found | Yes, factual study | No | No | Public visibility is not permission |
| Qwasm2, GPL-derived and mixed | Yes | Only after component graph review | Copyleft review required | Engine and original game asset have separate term |
| Wine, LGPL-2.1-or-later | Yes | Candidate only after architecture review | Linking and modification review required | Preserve source, notice, and relinking right as applicable |
| Proton, mixed distribution | Yes | Component-by-component only | Component-by-component only | Top-level license does not cover the entire distribution graph |
| DXVK, zlib | Yes | Research candidate | Candidate if technically suitable | Preserve notice; WebGPU adaptation would be substantial |
| vkd3d-proton, LGPL-2.1 | Yes | P4 research only | Linking review required | Native Vulkan dependency is not a browser permission bridge |
| ScummVM, GPL-3.0 | Yes | Engine-lane reference under compatible model | Copyleft review required | Engine support does not grant game-data redistribution |
| Apple Game Porting Toolkit | Workflow study | No proprietary implementation reuse | No | Platform term and Apple branding remain separate boundary |

## Clean-room and provenance control

If BPTK implements behavior described by a copyleft, proprietary, or unlicensed project without reusing code, the implementation record must include:

1. public behavioral requirement or black-box observation;
2. source that the implementer was permitted to inspect;
3. independent specification and benchmark fixture;
4. author and review record;
5. statement that no protected source or asset was copied;
6. comparison limited to behavior, not creative expression.

This control is especially important for Windows API, DirectX behavior, game quirk, installer format, and title-specific engine behavior.

## User-supplied content flow

The allowed default flow is:

```text
user gesture -> local read -> bounded inspection -> local transformation -> local storage -> local execution
```

Uploading proprietary game content and remotely executing imported game code are outside BPTK’s product boundary; either would be a different product and cannot be enabled by a BPTK configuration decision. Analytics, a public compatibility artifact, or a shared package requires separate consent and rights review. Hash and metadata should be preferred over file content.

## Brand boundary

“Browser Porting Toolkit” is a working name and intentionally descriptive, but it is close in structure to Apple’s product name. Public availability of this planning repository under the working name is permitted only while it retains the non-affiliation statement, uses no product logo or copied trade dress, makes no compatibility claim, and remains ready to rename.

This narrow planning-repository permission is not public-product-name clearance. Before a runtime release, hosted service, package-registry release, product launch, marketing campaign, or trademark filing:

- perform trademark and domain review;
- select independent logo, typography, color, icon, screenshot, and interface composition;
- avoid “Apple for the browser” or endorsement language;
- use Apple’s full product name only for factual comparison;
- retain the non-affiliation statement in public material.

## Runtime and product release stop check

No runtime or product release may proceed unless all of the following are true:

- outbound license recorded;
- every included file has provenance and license;
- third-party notice generated from the actual dependency graph;
- no commercial game executable or asset is included without explicit right;
- no DRM or anti-cheat circumvention path is present;
- public name and trade dress reviewed;
- source-offer and modification obligation are operational;
- technical claim is backed by a passing benchmark on a declared environment.
