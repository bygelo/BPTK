# Lane T — browser display, milestone 1 (bytes -> surface)

Goal: make the bounded runtime runnable from bytes in a browser — (a) zero-dep
pure-JS shims for the narrow `node:*` deps the runtime path touches, and (b) a
byte-driven entry that maps and runs a PE from a `Uint8Array` (no filesystem) and
returns the GDI RGBA surface. Fully verifiable headless in Node. The browser host
page is milestone 2 and is not built here.

## What landed

- `web/shim/buffer.mjs` — a `Buffer` over `Uint8Array` (BufferShim extends
  Uint8Array, DataView-backed). Covers exactly the runtime surface: `alloc`,
  `allocUnsafe`, `from` (string ascii/utf8/latin1/hex/base64, ArrayBuffer, typed
  array, array), `concat`, `isBuffer`, `byteLength`, `compare`; and instance
  `copy`, `subarray`/`slice` (memory-sharing), `toString`, `write`, `indexOf`,
  `includes`, `fill`, `equals`, `compare`, plus `read/writeUInt8/16LE/32LE`,
  `readInt8/16LE/32LE`, `read/writeBigUInt64LE`, `read/writeBigInt64LE`,
  `read/writeFloatLE`, `read/writeDoubleLE`. Proven byte-identical to `node:buffer`.
- `web/shim/crypto.mjs` — `createHash("sha256")` with `.update`/`.digest("hex")`
  over a pure-JS FIPS-180-4 SHA-256. Digest-exact vs `node:crypto` on empty,
  "abc", a long buffer, and chained updates.
- `web/shim/fs.mjs` — throwing stubs (`filesystem is not available in the
  browser`) for `readFileSync, openSync, readSync, closeSync, fstatSync,
  lstatSync, statSync, existsSync, mkdirSync, writeFileSync, unlinkSync,
  readdirSync, createWriteStream`, plus a shape-preserving `constants`. Never
  called on the byte path.
- `web/shim/path.mjs` — pure POSIX `basename, dirname, extname, join, resolve,
  relative, sep, delimiter`. Parse functions match `node:path.posix`.
- `lib/present.mjs` — `runImageBytes(bytes, option)` maps and runs a PE from
  memory and returns `{ machine, state, stop_reason, instruction_count,
  surface: { rgba, width, height } }`. x86-64 via `mapPe64State` + `executeProbe64`;
  i386 via `mapPe32ForRuntime` + the Win32 core HLE import service + `executeProbe`,
  wired exactly as `lib/run.mjs` does. No `resolvePackage`/`readExecutable`, no fs.
- `test/present.test.mjs` — shim byte/digest-exactness, `runImageBytes` on the
  real staged PuTTY x64 bytes (read with `node:fs` in the test only), and
  determinism across two calls.
- `tool/validate.py` + `bench/npm/content.json` — admit `web/` source and
  register `lib/present.mjs` across the three surfaces. Gate exits 0.

## PuTTY x64 result (`runImageBytes`)

machine `x86_64`, state `probe_executed`, stop_reason `import_present`,
instruction_count `30457`, surface `640x480`, rgba length `1228800`
(= 640*480*4), deterministic across calls.

## Deviations (flagged)

1. `doc/browser-display-scope.md` (named as the spec) does not exist on this
   branch or any ref; the detailed MISSION brief was used as the spec.
2. `lib/pe64.mjs` is listed READ-ONLY, but the canonical PE32+ loader is the only
   fs-free mapping path for the x64 test target and has no byte entry. A minimal,
   additive, behavior-preserving change lets `readExecutable` accept a pre-read
   `Uint8Array` (fs path untouched for string input). The same additive change
   was made to `lib/pe.mjs` (not read-only) for i386. Rationale: the alternative
   — duplicating ~230 lines of delicate PE parsing untested in owned code —
   diverges from the canonical parser and is far riskier. The full existing suite
   stays green, proving no behavior change.
3. Surface: the read-only bounded interpreters (`lib/exec64.mjs`,
   `lib/runtime.mjs`) do not expose their guest, and no BeginPaint/present path is
   served, so no window client surface is observable from an owned file. The
   honest milestone-1 surface is the mission-sanctioned cleared surface at the
   default window size (640x480) — a real zeroed RGBA buffer, never a mock, never
   null. Surfacing a painted guest bitmap requires the interpreter to expose its
   guest and a served paint path; that is milestone 2.

`passing` stays 0. No browser was launched. No merge, no push.
