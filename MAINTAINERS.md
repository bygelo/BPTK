# Maintainer record

The project removes the single-maintainer bus factor (GS-082 / BPTK-125) with a
mechanism that is testable before a second human joins.

## Review rule

- Review is not self-approval: a change to the roadmap package, the product
  surface, or the governance record requires review from a maintainer other
  than the author, enforced through [CODEOWNERS](.github/CODEOWNERS).
- Every pull request passes the same gate (`npm run gate`) regardless of
  authorship, human or agent, with authorship disclosed.

## Release rule

- A release tag requires two signer: the release procedure in
  [doc/RELEASE.md](doc/RELEASE.md) is executed only after a second maintainer
  approves the release record.

## Recovery drill

The recovery path is exercised, not prose. The drill, runtable for a
single-maintainer project and required before any release:

1. Clone the repository fresh into an empty directory.
2. Run `npm ci --ignore-scripts` and `npm run gate` — the gate must pass green.
3. Verify the tagged release artifact rebuilds byte-identically from the tag.
4. Restore the maintainer record and code-owner rule from this file and
   confirm the governance gate still fails a removed statement.

A drill that fails is a release blocker, exactly like a red gate.
