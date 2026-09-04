# Research note — lawful lightweight game sources for the compatibility corpus, 2026-09

A one-time sweep of where BPTK can legally obtain lightweight Windows game
material — Purble Place style casual title, free demo, and freeware — for the
BPTK-002 corpus and the compatibility strategy. It separates source by
**redistribution right**, because a free download is not the same thing as a
lawfully redistributable one, and only the latter can become a frozen corpus
fixture. This is a dated snapshot; verification markers: **[V]** verified via
fetch or search 2026-09-04. Trust [ROADMAP.md](../ROADMAP.md) and the
[legal boundary](legal-boundary.md) over this file when a claim ages.

## 1. The rule that decides everything

Three different "free" exist, and confusing them is the corpus's biggest
legal risk:

1. **Redistributable** — the copyright holder permits the file itself to be
   copied and re-hosted. Only this class can become a committed or frozen
   BPTK fixture.
2. **Free to acquire, not redistributable** — the user pays nothing but the
   file may not be re-hosted or bundled (GOG account giveaways, freeware
   with personal-use-only wording). Fine for a local, user-supplied,
   metadata-only evaluation; never a fixture.
3. **Not actually free** — bundled-with-Windows title, abandonware, rips.
   Excluded, same posture as R-003 in [roadmap-rejected.md](roadmap-rejected.md).

## 2. Purble Place specifically

Purble Place was developed by Oberon Media under contract for Microsoft and
shipped only bundled with Windows Vista and Windows 7 **[V]**
(https://en.wikipedia.org/wiki/Purble_Place). It is class 3: the files were
never separately distributable, and site offering "Purble Place downloads"
are rips from a Windows install. It cannot be a BPTK source. The lawful
alternatives are equivalent-capability title: the small open-source
recreations inspired by it (a memory-pairs game, a cake-decoration game) and
the other casual-weight title in section 4. A decompilation exists on GitHub
**[V]** but a decompilation of copyrighted code is not a clean input and is
excluded under the same posture.

## 3. BottleShip's own download surface (the requested check)

BottleShip ([github.com/jenissimo/bottleship](https://github.com/jenissimo/bottleship),
live at [bottleship.pages.dev](https://bottleship.pages.dev/)) is the closest
prior art and its policy is the template: the site states that only demos,
shareware, and freeware are legally redistributable, and its online library
ships exactly that class **[V]**.

The library catalog (`public/games-catalog.json`) carries twelve
downloadable `.wgb` bundle — eleven official publisher demo and one
freeware **[V]**:

| Title | Class | Era relevance for BPTK |
|---|---|---|
| Re-Volt (1999) | Demo | Direct3D-era 3D racing |
| Heroes of Might & Magic III | Demo | DirectDraw-era 2D |
| StarCraft | Demo | Win32 baseline, software rendering |
| Diablo II | Demo | Win32, DirectDraw |
| Harry Potter and the Philosopher's Stone | Demo | D3D-era 3D |
| Need for Speed: Porsche Unleashed | Demo | Direct3D racing |
| Need for Speed: Underground | Demo | D3D9-era (the newest edge) |
| Max Payne | Demo | D3D8/9-era, real middleware load |
| Tony Hawk's Pro Skater 2 | Demo | DirectDraw-era 2D |
| Command & Conquer: Tiberian Sun | **Freeware** (EA's 2024 free release) | DirectDraw-era strategy |
| Unreal Tournament | Demo | Direct3D-era |
| Airfix Dogfighter | Demo | Direct3D-era |

The compatibility list adds **Nuclear Titbit** (Ядерный Титбит), a freeware
title observed playable **[V]**. Two structural finding matter to BPTK:

- The `.wgb` bundle format is an uncompressed (store-only) ZIP with a
  manifest — BPTK already refuses `.wgb` file in planning scope
  (`tool/validate.py` binary suffix) and the format is a natural
  interoperability target for the BPTK package contract (BPTK-024).
- BottleShip imports **GOG offline Inno Setup installer directly**
  (`docs/gog-import.md` **[V]**): supported range is single-file Inno
  5.2.x–6.x, "typically 5.5.x unicode"; encrypted and multi-part
  (`setup.exe` + `setup-1.bin`) installer are explicitly out of scope for
  them too. BPTK-038's extractor currently supports the Inno 6 family only —
  the real GOG fleet centers on 5.5.x unicode, so extending the BPTK
  extractor to the 5.5 unicode header is the single highest-value corpus
  follow-up. Their `BOTTLESHIP_INNO_FIXTURE` native-vs-innoextract test
  pattern is also a good model for the BPTK-038 acceptance check.

## 4. Source taxonomy with verification status

### A. Redistributable demo and shareware (class 1 — fixture eligible)

- **BottleShip library** — the twelve bundle above, each a publisher demo
  whose trial license permits redistribution **[V]**.
- **id Software / Apogee / 3D Realms shareware** — DOOM shareware, Quake
  demo, Hexen demo, Duke Nukem 3D shareware: these licenses explicitly
  permit redistribution of the shareware episode. Widely mirrored
  (archive.org, official FTP mirrors).
- **Archive.org "Classic PC Games" collection** — 16,095 item **[V]**,
  curated by DeMU as "primarily PC demos, freeware, and shareware", original
  releases, with a documented process for copyright-holder request
  (https://archive.org/details/classicpcgames). Per-item review is still
  required before any item becomes a fixture, but the collection exists
  exactly for this purpose.
- **PopCap-era trial installer** — the old Bejeweled/Zuma-class trials were
  explicitly worded for free redistribution and ship in installer wrappers,
  making them useful BPTK-038 extraction material; per-title license text
  review required before use.

### B. Open-source game with Windows builds (class 1 — fixture eligible, strongest)

License-verified **[V]**: SuperTux (GPL-3.0), Mindustry (GPL-3.0),
Freedoom (free software Doom-engine asset set). Also in this class from
prior knowledge, license to confirm per title at fixture time:
Battle for Wesnoth, Cataclysm: Dark Days Ahead, OpenTTD with OpenGFX,
OpenArena, Xonotic, Endless Sky, Shattered Pixel Dungeon. These are the
safest possible corpus input: full rights, buildable from source, and the
DirectX-era one among them are thin — most target SDL/OpenGL, so they serve
the Win32/source-lane corpus better than the DirectDraw corpus.

### C. Freeware classics with distribution permission (class 1/2 — review each)

ABA Games (rRootage, Torus Trooper and other lightweight Windows shoot
them up) remains online **[V]** and historically ships freeware with later
source release; Cave Story's original freeware edition is widely mirrored
but its redistribution wording predates the commercial rights holder and
needs legal review before fixture use. Class varies per title — treat as
class 2 until the wording is checked.

### D. Free to acquire, NOT redistributable (class 2 — local evaluation only)

GOG's free-game giveaway (account-bound, not re-hostable) and most
itch.io free download (free to take, redistribution wording varies per
developer). Useful for ad-hoc local evaluation exactly the way BottleShip's
GOG import works — bring-your-own installer — but never committed fixture.

### E. Excluded (class 3)

Abandonware archive (Home of the Underdogs and similar), Purble Place and
Windows 7 game rips, ROM site, anything without a named copyright posture.
This matches the existing exclusion of bundled commercial material.

## 5. What this buys each roadmap item

- **BPTK-002 (corpus)** — section 4A/4B is the stratified, lawfully
  redistributable denominator the item has been waiting for: DirectDraw-era
  2D (HoMM3, THPS2, Tiberian Sun), D3D7–9-era 3D (Re-Volt, NFS:PU, Max
  Payne), Win32 baseline (StarCraft, Diablo II), casual-weight (the section
  2 open alternatives).
- **BPTK-038 (installer extraction)** — GOG's Inno 5.5.x-unicode fleet is
  the dominant real-world input per BottleShip's own documentation; the
  BPTK extractor's Inno-6-only support is the recorded gap. Multi-part
  installer remain a shared open problem for both project.
- **BPTK-037 (census)** — the demo set exercises real middleware evidence
  (Bink, Miles, Smacker appear across these title), giving the signature
  catalog real material to route.
- **BPTK-009 (i386)** — publisher demo contain real compiler-era instruction
  mix, the natural next step beyond generated microprogram.
- **BPTK-024 (package contract)** — `.wgb` is a de-facto interop format for
  exactly this class of bundle; BPTK already names it in the planning
  validator.

## 6. Decision

Adopt the BottleShip posture verbatim: **demos, shareware, and open-source
title are the corpus; everything else is bring-your-own, metadata-only.**
The one engineering follow-up is the BPTK-038 Inno 5.5 unicode extension,
and the one process follow-up is a per-item license review step recorded in
the fixture catalog when BPTK-002 freezes the denominator.
