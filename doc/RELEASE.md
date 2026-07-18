# Release

This procedure publishes the bounded npm roadmap-tooling package. It does not authorize or describe a game-runtime release.

## Fixed identity and scope

- Package: `@bygelo/bptk`
- Access: public
- Distribution tag for pre-release publication: `next`
- License: Apache-2.0
- Runtime dependency: zero
- Install lifecycle script: none
- Published content: the exact path in `bench/npm/content.json`

The unscoped name `bptk` is outside this project. A runtime, game importer, compatibility claim, new dependency, or expanded file surface requires a new legal, security, benchmark, and package review.

The initial registry publication assigned both `next` and `latest` to `0.1.0-alpha.0`, despite the explicit `--tag next` command. An authenticated attempt to remove `latest` returned `400 Bad Request`, so the tag was left intact instead of repeating a failing registry mutation. Installation documentation pins the exact pre-release version. Future pre-release publication must continue using `next` and must not move `latest`; the first approved stable release replaces the current `latest` pointer.

## Release gate

Start from a clean commit on `main` whose GitHub Actions gate is green on every configured Node.js version:

```sh
npm ci --ignore-scripts
npm run gate
git diff --check
```

Immediately before publication, fail closed unless all identity checks return the expected account, organization role, registry, and not-yet-published version:

```sh
npm whoami --registry=https://registry.npmjs.org
npm org ls bygelo --json --registry=https://registry.npmjs.org
npm config get registry
npm view @bygelo/bptk@0.1.0-alpha.0 version --registry=https://registry.npmjs.org
```

For a new version, the last command must return a registry not-found response. If it returns a version or an unexpected error, stop and inspect; do not overwrite or guess.

## One-artifact publication

Create one final tarball outside the repository, retain its checksum in the release record, and publish that exact path:

```sh
bptk_release_dir="$(mktemp -d)"
npm pack --pack-destination "$bptk_release_dir"
shasum -a 256 "$bptk_release_dir/bygelo-bptk-0.1.0-alpha.0.tgz"
tar -tzf "$bptk_release_dir/bygelo-bptk-0.1.0-alpha.0.tgz"
npm publish "$bptk_release_dir/bygelo-bptk-0.1.0-alpha.0.tgz" --access public --tag next
```

Before `npm publish`, install the tarball into a second temporary directory with lifecycle script disabled and run `bptk --version`, `bptk status --json`, and `bptk doctor --json`. Compare the archive path with `bench/npm/content.json`; the archive adds only npm's `package/` prefix.

The publisher enters any 2FA challenge interactively. Never record an npm token, password, recovery code, or one-time password in the repository, command history, issue, log, or release artifact.

## Live verification and recovery

After the publish command, query the registry before deciding whether to retry:

```sh
npm view @bygelo/bptk@0.1.0-alpha.0 --json --registry=https://registry.npmjs.org
npm dist-tag ls @bygelo/bptk --registry=https://registry.npmjs.org
```

Then install `@bygelo/bptk@0.1.0-alpha.0` from the public registry into a fresh temporary directory with lifecycle script disabled and repeat the three CLI smoke command.

Publication is irreversible version state. If the publish command times out or returns an ambiguous error but the version is visible, treat the release as successful and do not retry. If the live package is defective, deprecate that exact version with a precise message, fix forward to the next pre-release version, rerun the entire gate, and publish a new tarball. Never unpublish as the normal recovery path.

This local 2FA release does not carry an npm provenance attestation. Add provenance only through a separately reviewed npm trusted-publishing workflow with short-lived OIDC credentials; do not simulate provenance with a long-lived token.
