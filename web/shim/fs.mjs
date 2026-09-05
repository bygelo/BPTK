// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The browser has no filesystem. Every node:fs export the runtime imports is a
// stub that throws the same message, so a code path that reaches for a file in
// the browser fails loudly instead of silently mis-reading. The byte-driven
// entry (lib/present.mjs runImageBytes) never touches these — it maps a PE from
// a Uint8Array — so on the intended path none of these is ever called.

const message = "filesystem is not available in the browser";

function unavailable() {
  throw new Error(message);
}

export function readFileSync() { return unavailable(); }
export function openSync() { return unavailable(); }
export function readSync() { return unavailable(); }
export function closeSync() { return unavailable(); }
export function fstatSync() { return unavailable(); }
export function lstatSync() { return unavailable(); }
export function statSync() { return unavailable(); }
export function existsSync() { return unavailable(); }
export function mkdirSync() { return unavailable(); }
export function writeFileSync() { return unavailable(); }
export function unlinkSync() { return unavailable(); }
export function readdirSync() { return unavailable(); }
export function createWriteStream() { return unavailable(); }

// node:fs exposes `constants` as an object of open-flag numbers. The stub keeps
// the shape (so `constants.O_RDONLY` does not throw at import-destructure time)
// while the fs operations that would consume them still refuse.
export const constants = Object.freeze({
  O_RDONLY: 0,
  O_WRONLY: 1,
  O_RDWR: 2,
  O_NONBLOCK: 0,
  O_NOFOLLOW: null,
  O_CREAT: 0,
  O_TRUNC: 0,
});

export default {
  readFileSync, openSync, readSync, closeSync, fstatSync, lstatSync, statSync,
  existsSync, mkdirSync, writeFileSync, unlinkSync, readdirSync, createWriteStream, constants,
};
