# Contributing

BPTK is currently a roadmap and evidence package, not a working compatibility runtime. Contributions should preserve that distinction and make no unsupported game-compatibility claim.

## Before opening a change

1. Open an issue or discussion for a new runtime, dependency, compatibility claim, or public fixture.
2. Keep every identifier singular, including identifiers whose value is a collection, unless an external format requires otherwise.
3. Do not submit commercial game code, executable, asset, firmware, ROM, credential, proprietary SDK material, or DRM or anti-cheat bypass.
4. Do not copy source from prior art merely because its repository is public. Follow the [third-party incorporation rule](doc/third-party.md) and [legal boundary](doc/legal-boundary.md).
5. Add reproducible evidence and update the roadmap state in the same change when promoting a benchmark.

## Validate

Run the planning gate from the repository root:

```sh
python3 tool/validate.py
```

The gate must pass without converting a planned benchmark to implemented or passing unless its implementation, fixture, active command, and retained evidence land together.

## Contribution license

Unless explicitly stated otherwise, an intentional contribution submitted for inclusion in BPTK is provided under the Apache License 2.0, as described by Section 5 of [LICENSE](LICENSE). By submitting a contribution, the contributor represents that they have the right to provide it under those terms.

A contribution containing third-party material must identify that material and its license. Acceptance into this repository does not convert third-party material to Apache-2.0.
