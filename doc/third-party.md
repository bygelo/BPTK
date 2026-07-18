# Third-party material

## Current inventory

As of 2026-07-19, this repository and the `@bygelo/bptk` tarball contain no incorporated third-party software, executable, game asset, firmware, ROM, proprietary SDK, generated output from a restricted tool, or copied upstream documentation. Their Markdown, JSON, Python, and JavaScript content is BPTK-authored material licensed under Apache-2.0.

The npm package has zero package dependency and uses only built-in Node.js modules. Node.js 22 or later and the npm CLI are external environment tools: they are not vendored, copied into, or redistributed with the tarball. `package-lock.json` records the dependency-free source environment but is intentionally absent from the published file manifest.

The projects recorded in the [source audit](source-audit.md) are factual research references and architectural precedent. A link, project name, license summary, or behavioral observation does not make that project a dependency and does not relicense its source under BPTK's license.

### CI tool inventory

The GitHub Actions workflow invokes these external CI tools. They run on GitHub's runner, are not copied into the repository, and are not incorporated into or redistributed with BPTK. Their immutable revision is recorded so a workflow run has reproducible provenance.

| Tool | Immutable revision | License | Use and distribution disposition |
|---|---|---|---|
| [actions/checkout](https://github.com/actions/checkout) | [`9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0`](https://github.com/actions/checkout/commit/9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0) (`v7.0.0`) | MIT | CI-only checkout tool; not vendored or shipped |
| [actions/setup-node](https://github.com/actions/setup-node) | [`820762786026740c76f36085b0efc47a31fe5020`](https://github.com/actions/setup-node/commit/820762786026740c76f36085b0efc47a31fe5020) (`v7.0.0`) | MIT | CI-only Node.js setup tool; not vendored or shipped |
| [actions/setup-python](https://github.com/actions/setup-python) | [`ece7cb06caefa5fff74198d8649806c4678c61a1`](https://github.com/actions/setup-python/commit/ece7cb06caefa5fff74198d8649806c4678c61a1) (`v6.3.0`) | MIT | CI-only Python setup tool; not vendored or shipped |

## Incorporation rule

Before any third-party file, runtime dependency, build dependency, or CI tool enters the repository workflow or distribution, the same change must record:

1. exact project, upstream URL, revision, file, author, and license;
2. whether the material is copied, modified, linked, loaded, invoked as a tool, or studied only;
3. compatibility with the actual distribution and service model;
4. required copyright, attribution, modification, patent, relinking, source-offer, and network-source obligation;
5. an updated `NOTICE` and software bill of material where required;
6. approval under the [legal boundary](legal-boundary.md).

An Apache-2.0 repository does not convert an included dependency to Apache-2.0. Copyleft, mixed-license, proprietary, and unlicensed material remains governed by its own terms and may require architectural isolation or exclusion.

## User content

A user-supplied Windows game remains outside the repository and outside BPTK's license. Importing or transforming a local copy does not grant redistribution, trademark, patent, anti-circumvention, or game-content rights.
