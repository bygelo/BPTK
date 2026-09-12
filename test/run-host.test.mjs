// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { mapHostDirectory } from "../lib/run.mjs";
import { InputError } from "../lib/input.mjs";
import { createIsolatedWin32Memory, createWin32Hle } from "../lib/hle.mjs";
import { createGuestClock } from "../lib/clock.mjs";

function invoke(guest, library, symbol, argument) {
  return guest.invokeExport(guest.lookupExport(library, symbol), argument);
}

test("mapHostDirectory seeds guest paths from a package-relative host tree", (context) => {
  const root = mkdtempSync(join(tmpdir(), "bptk-host-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "data", "images"), { recursive: true });
  writeFileSync(join(root, "data", "credits.stxt"), "hello\n");
  writeFileSync(join(root, "data", "images", "icon.png"), Buffer.from([1, 2, 3]));
  const map = mapHostDirectory(root, [{ guest: "C:\\game\\data", host: "data" }]);
  assert.equal(map.size, 2);
  assert.deepEqual([...map.get("c:\\game\\data\\credits.stxt")], [...Buffer.from("hello\n")]);
  assert.deepEqual([...map.get("c:\\game\\data\\images\\icon.png")], [1, 2, 3]);
});

test("mapHostDirectory refuses a host path that escapes the package", (context) => {
  const root = mkdtempSync(join(tmpdir(), "bptk-host-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  assert.throws(
    () => mapHostDirectory(root, [{ guest: "C:\\game\\data", host: ".." }]),
    (error) => error instanceof InputError && error.input_code === "package_path_escape",
  );
});

test("a mounted host_dir is CreateFile-visible on the virtual drive", (context) => {
  const root = mkdtempSync(join(tmpdir(), "bptk-host-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "data"));
  writeFileSync(join(root, "data", "config"), "ok\n");
  const hostFile = mapHostDirectory(root, [{ guest: "C:\\game\\data", host: "data" }]);
  const memory = createIsolatedWin32Memory();
  const guest = createWin32Hle(memory, memory.layout, {
    executable_name: "game.exe",
    clock: createGuestClock(),
    host_file: hostFile,
  });
  const pathPtr = guest.layout.arena_base + 0x80;
  guest.writeWideString(pathPtr, "C:\\game\\data\\config", 64);
  const handle = invoke(guest, "kernel32.dll", "CreateFileW", [pathPtr, 0x80000000, 1, 0, 3, 0, 0]);
  assert.notEqual(handle, 0xffffffff);
  assert.notEqual(handle, 0);
});

test("run.mjs host mounts are not title-branched", () => {
  const source = readFileSync(new URL("../lib/run.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /supertux|SuperTux|puttygen|openttd/i);
});
