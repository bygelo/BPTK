# Decision record 001 — outbound license and upstream reuse posture

Item: **BPTK-001**. Status: **approved**. Approved on **2026-09-07** by
**Mar Angelo Revelo**, sole maintainer of this repository.

## 1. Outbound license

BPTK-authored material is licensed **Apache-2.0**, recorded in `LICENSE` and
`NOTICE`. This is unchanged by this record; it is ratified here rather than
introduced.

## 2. Upstream reuse rule

**Study is unrestricted. Incorporation is not.**

Reading, measuring, and describing any published project is factual research and
is always permitted. A link, a project name, a license summary, or a behavioural
observation does not make that project a dependency and does not relicense its
source (`doc/third-party.md`).

Before **any** third-party file, runtime dependency, build dependency, or CI tool
enters this repository or its distribution, the incorporation rule in
`doc/third-party.md` applies in the same change, and the per-source disposition
in the prior-art reuse classification of `doc/legal-boundary.md` governs.

**Copyleft is not incorporated without a completed per-component review.** No
GPL, AGPL, or LGPL source is forked into, linked with, or redistributed as part
of an Apache-2.0 BPTK artifact on the strength of this record alone. That
includes Boxedwine (GPL-2.0), OpenSA (AGPL-3.0), ScummVM (GPL-3.0), Wine and
vkd3d-proton (LGPL-2.1), and Qwasm2 (GPL-derived, mixed).

### Current incorporation state

**Zero.** As recorded in `doc/third-party.md`, this repository and the published
tarball contain no incorporated third-party software, and the npm package has no
runtime dependency. This record approves a rule for future reuse; it takes
nothing.

## 3. BottleShip posture

Study: **yes**. Fork or link: **candidate only after notice review and
patent-term review**, per the prior-art classification. Nothing from BottleShip
is present in this repository and none is taken by this record.

## 4. Provenance owner

**Mar Angelo Revelo.** Accountable for the provenance and license of every file
that enters the repository or the distribution.

## 5. Public name review

**Working name retained; public-product-name clearance deferred.**
`doc/legal-boundary.md` already permits the working name for this planning
repository and the scoped `@bygelo/bptk` package while each keeps the
non-affiliation statement, uses no product logo or copied trade dress, and makes
no compatibility claim.

That permission is explicitly **not** public-product-name clearance. Trademark
and domain review remains required before a runtime release, hosted service,
unscoped registry release, product launch, marketing campaign, or trademark
filing. No such release is in scope, so no clearance is claimed here.

## 6. Test material — what may be run, and what may ship

A distinction this record makes explicit, because the two were previously
conflated:

| | Corpus and distribution | Local testing by the maintainer |
| --- | --- | --- |
| Permitted material | **DRM-free freeware or OSS only**, hash-pinned in `data/corpus.json`, acquired outside the repository | A binary the maintainer **lawfully owns a licence for** |
| Committed to git | Never (payload and `web/payload/*` are ignored) | Never |
| Redistributed | Only where the licence permits it | Never |
| May produce a public claim | Only with recorded evidence | **No** — a local run over owned material is not published evidence |

Two limits hold regardless of ownership:

1. **Owning a licence is not permission to circumvent DRM or anti-cheat.** The
   detect-and-refuse rule stands for every input, owned or not. Nothing in this
   record authorises a circumvention path.
2. **A locally-run commercial title produces no committed artifact, no corpus
   row, and no compatibility claim.** It is a debugging aid to the maintainer,
   not evidence, and never becomes either by being run.

## 7. Expiry and re-review

This record expires, and must be re-reviewed before whichever comes first:

- the first incorporation of any third-party source into the repository or the
  distribution;
- the first runtime release, hosted service, or unscoped registry publication;
- any public product name, logo, or marketing use;
- **2027-09-07**.

## 8. Review standard — a bar that was amended, and why

BPTK-001's promotion trigger originally required a **counsel-informed** decision
record. **No legal counsel reviewed this decision.** Rather than record a
counsel review that did not happen, the bar was amended to sole-maintainer
approval and the change is recorded here and in the commit that made it.

The justification is narrow and expires with the conditions above: at the time of
approval the repository incorporates **no** third-party code, has **no** runtime
dependency, ships **no** runtime, and makes **no** public product claim, so there
is no exposure for counsel to review. The counsel requirement is not discarded —
it moves to the two moments where it actually binds, and is restated as a
condition in section 7: the first incorporation of third-party source, and the
first runtime release.

Anyone relying on this record should read section 8 first: it is a maintainer's
decision, not a legal opinion.
