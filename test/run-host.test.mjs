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

test("FileStandardInfo.Directory is set on a host-dir prefix", (context) => {
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
  const infoPtr = guest.layout.arena_base + 0x180;
  guest.writeWideString(pathPtr, "C:\\game\\data", 64);
  const handle = invoke(guest, "kernel32.dll", "CreateFileW", [pathPtr, 0x80000000, 1, 0, 3, 0x02000000, 0]);
  assert.notEqual(handle, 0xffffffff);
  const ok = invoke(guest, "kernel32.dll", "GetFileInformationByHandleEx", [handle, 1, infoPtr, 24]);
  assert.equal(ok, 1);
  assert.equal(memory.readMemory(infoPtr + 8, 4), 0);
  assert.equal(memory.readMemory(infoPtr + 21, 1), 1);
});

test("FileStandardInfo reports host file size and FileNameInfo writes the path", (context) => {
  const root = mkdtempSync(join(tmpdir(), "bptk-host-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "data"));
  writeFileSync(join(root, "data", "config"), "hello\n");
  const hostFile = mapHostDirectory(root, [{ guest: "C:\\game\\data", host: "data" }]);
  const memory = createIsolatedWin32Memory();
  const guest = createWin32Hle(memory, memory.layout, {
    executable_name: "game.exe",
    clock: createGuestClock(),
    host_file: hostFile,
  });
  const pathPtr = guest.layout.arena_base + 0x80;
  const infoPtr = guest.layout.arena_base + 0x180;
  guest.writeWideString(pathPtr, "C:\\game\\data\\config", 64);
  const handle = invoke(guest, "kernel32.dll", "CreateFileW", [pathPtr, 0x80000000, 1, 0, 3, 0, 0]);
  assert.notEqual(handle, 0xffffffff);
  assert.equal(invoke(guest, "kernel32.dll", "GetFileInformationByHandleEx", [handle, 1, infoPtr, 24]), 1);
  assert.equal(memory.readMemory(infoPtr + 8, 4), Buffer.byteLength("hello\n"));
  assert.equal(memory.readMemory(infoPtr + 21, 1), 0);
  assert.equal(invoke(guest, "kernel32.dll", "GetFileInformationByHandleEx", [handle, 2, infoPtr, 128]), 1);
  const nameByte = memory.readMemory(infoPtr, 4);
  assert.ok(nameByte > 0);
});

test("wine_get_version stays unbound while SetThreadDescription resolves", () => {
  const memory = createIsolatedWin32Memory();
  const guest = createWin32Hle(memory, memory.layout, {
    executable_name: "game.exe",
    clock: createGuestClock(),
  });
  const namePtr = guest.layout.arena_base + 0x80;
  guest.writeAnsiString(namePtr, "ntdll.dll", 16);
  const ntdll = invoke(guest, "kernel32.dll", "GetModuleHandleA", [namePtr]);
  guest.writeAnsiString(namePtr, "wine_get_version", 32);
  assert.equal(invoke(guest, "kernel32.dll", "GetProcAddress", [ntdll, namePtr]), 0);
  assert.equal(guest.getLastError(), 127);
  assert.ok(guest.procedure_miss.some((row) => row.library === "ntdll.dll" && row.symbol === "wine_get_version"));
  guest.writeAnsiString(namePtr, "RtlVerifyVersionInfo", 32);
  assert.notEqual(invoke(guest, "kernel32.dll", "GetProcAddress", [ntdll, namePtr]), 0);
  guest.writeAnsiString(namePtr, "kernel32.dll", 16);
  const kernel32 = invoke(guest, "kernel32.dll", "GetModuleHandleA", [namePtr]);
  guest.writeAnsiString(namePtr, "SetThreadDescription", 32);
  assert.notEqual(invoke(guest, "kernel32.dll", "GetProcAddress", [kernel32, namePtr]), 0);
  guest.writeAnsiString(namePtr, "user32.dll", 16);
  const user32 = invoke(guest, "kernel32.dll", "GetModuleHandleA", [namePtr]);
  guest.writeAnsiString(namePtr, "SetProcessDPIAware", 32);
  assert.notEqual(invoke(guest, "kernel32.dll", "GetProcAddress", [user32, namePtr]), 0);
  guest.writeAnsiString(namePtr, "GetDisplayConfigBufferSizes", 32);
  assert.notEqual(invoke(guest, "kernel32.dll", "GetProcAddress", [user32, namePtr]), 0);
});

test("GetProcAddress of an unknown export is recorded as a procedure miss", () => {
  const memory = createIsolatedWin32Memory();
  const guest = createWin32Hle(memory, memory.layout, {
    executable_name: "game.exe",
    clock: createGuestClock(),
  });
  const namePtr = guest.layout.arena_base + 0x80;
  guest.writeAnsiString(namePtr, "kernel32.dll", 16);
  const moduleHandle = invoke(guest, "kernel32.dll", "GetModuleHandleA", [namePtr]);
  assert.notEqual(moduleHandle, 0);
  guest.writeAnsiString(namePtr, "NoSuchExportForMissList", 32);
  const value = invoke(guest, "kernel32.dll", "GetProcAddress", [moduleHandle, namePtr]);
  assert.equal(value, 0);
  assert.equal(guest.getLastError(), 127);
  assert.ok(guest.procedure_miss.some((row) => row.symbol === "NoSuchExportForMissList"));
});

test("FindFirstFileW on a host_dir lists immediate children and directory attributes", (context) => {
  const root = mkdtempSync(join(tmpdir(), "bptk-host-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "data", "fonts"), { recursive: true });
  writeFileSync(join(root, "data", "credits.stxt"), "hello\n");
  writeFileSync(join(root, "data", "fonts", "face.ttf"), Buffer.from([1, 2, 3, 4]));
  const hostFile = mapHostDirectory(root, [{ guest: "C:\\game\\data", host: "data" }]);
  const memory = createIsolatedWin32Memory();
  const guest = createWin32Hle(memory, memory.layout, {
    executable_name: "game.exe",
    clock: createGuestClock(),
    host_file: hostFile,
  });
  const patternPtr = guest.layout.arena_base + 0x80;
  const findPtr = guest.layout.arena_base + 0x180;
  guest.writeWideString(patternPtr, "C:\\game\\data\\*", 64);
  const handle = invoke(guest, "kernel32.dll", "FindFirstFileW", [patternPtr, findPtr]);
  assert.notEqual(handle, 0xffffffff);
  const name = [];
  const attr = [];
  const readEntry = () => {
    attr.push(memory.readMemory(findPtr, 4));
    name.push(guest.readWideString(findPtr + 44));
  };
  readEntry();
  while (invoke(guest, "kernel32.dll", "FindNextFileW", [handle, findPtr]) === 1) readEntry();
  assert.deepEqual([...name].sort(), ["credits.stxt", "fonts"]);
  assert.equal(name.includes("fonts\\face.ttf"), false);
  assert.equal(attr[name.indexOf("fonts")], 0x10);
  assert.equal(attr[name.indexOf("credits.stxt")], 0x20);
});
