// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { createConformanceMachine } from "../lib/hle.mjs";
import { glEnum } from "../lib/gl.mjs";
import { composeGuestSurface } from "../lib/present.mjs";

function invoke(guest, symbol, argument) {
  return guest.invokeExport(guest.lookupExport("opengl32.dll", symbol), argument);
}

function floatBits(value) {
  const word = Buffer.alloc(4);
  word.writeFloatLE(value, 0);
  return word.readUInt32LE(0);
}

test("glClear fills the viewport and glReadPixels reads the same color back", () => {
  const { guest } = createConformanceMachine();
  invoke(guest, "glViewport", [0, 0, 4, 4]);
  invoke(guest, "glClearColor", [floatBits(1), floatBits(0), floatBits(0), floatBits(1)]);
  invoke(guest, "glClear", [glEnum.COLOR_BUFFER_BIT]);
  const dest = 0x00150100;
  invoke(guest, "glReadPixels", [0, 0, 1, 1, glEnum.RGBA, glEnum.UNSIGNED_BYTE, dest]);
  assert.equal(guest.memory.readMemory(dest, 1), 255);
  assert.equal(guest.memory.readMemory(dest + 1, 1), 0);
  assert.equal(guest.memory.readMemory(dest + 2, 1), 0);
  assert.equal(guest.memory.readMemory(dest + 3, 1), 255);
  assert.equal(invoke(guest, "glGetError", []), 0);
});

test("glGetString names the bounded BPTK renderer and glGenTextures issues a real name", () => {
  const { guest } = createConformanceMachine();
  const vendor = invoke(guest, "glGetString", [glEnum.VENDOR]);
  assert.equal(guest.readAnsiString(vendor), "BPTK");
  const version = invoke(guest, "glGetString", [glEnum.VERSION]);
  assert.equal(guest.readAnsiString(version), "2.1 BPTK");
  const extension = invoke(guest, "glGetString", [glEnum.EXTENSIONS]);
  assert.match(guest.readAnsiString(extension), /GL_ARB_texture_non_power_of_two/);
  const out = 0x00150040;
  invoke(guest, "glGenTextures", [1, out]);
  const id = guest.memory.readMemory(out, 4);
  assert.equal(id, 1);
  invoke(guest, "glBindTexture", [glEnum.TEXTURE_2D, id]);
  invoke(guest, "glTexImage2D", [glEnum.TEXTURE_2D, 0, glEnum.RGBA, 1, 1, 0, glEnum.RGBA, glEnum.UNSIGNED_BYTE, 0]);
  assert.equal(invoke(guest, "glGetError", []), 0);
  assert.equal(guest.gl.describe().texture_count, 1);
});

test("GetProcAddress of glBegin is non-zero and glEnd records a draw", () => {
  const { guest } = createConformanceMachine();
  const name = 0x00150020;
  const symbol = 0x00150080;
  guest.writeWideString(name, "OPENGL32.DLL", 32);
  const module = guest.invokeExport(guest.lookupExport("kernel32.dll", "LoadLibraryW"), [name]);
  assert.equal(module, 0x0002000c);
  guest.writeAnsiString(symbol, "glBegin", 16);
  const thunk = guest.invokeExport(guest.lookupExport("kernel32.dll", "GetProcAddress"), [module, symbol]);
  assert.notEqual(thunk, 0);
  invoke(guest, "glBegin", [0]);
  invoke(guest, "glVertex2f", [floatBits(0), floatBits(0)]);
  invoke(guest, "glEnd", []);
  assert.equal(guest.gl.describe().draw_count, 1);
  assert.equal(guest.gl.describe().is_begin, false);
  assert.equal(invoke(guest, "glGetError", []), 0);
});

test("wglCreateContext issues a handle GetProcAddress can resolve after LoadLibrary", () => {
  const { guest } = createConformanceMachine();
  const name = 0x00150020;
  const symbol = 0x00150080;
  guest.writeWideString(name, "OPENGL32.DLL", 32);
  const module = guest.invokeExport(guest.lookupExport("kernel32.dll", "LoadLibraryW"), [name]);
  assert.equal(module, 0x0002000c);
  guest.writeAnsiString(symbol, "wglCreateContext", 20);
  const thunk = guest.invokeExport(guest.lookupExport("kernel32.dll", "GetProcAddress"), [module, symbol]);
  assert.notEqual(thunk, 0);
  const dc = guest.invokeExport(guest.lookupExport("user32.dll", "GetDC"), [0]);
  const context = guest.invokeExport(guest.exportAt(thunk), [dc]);
  assert.equal(context, 0x00050000);
  assert.equal(invoke(guest, "wglMakeCurrent", [dc, context]), 1);
  assert.equal(invoke(guest, "wglGetCurrentDC", []), dc);
  assert.equal(invoke(guest, "wglGetCurrentContext", []), context);
  assert.equal(invoke(guest, "wglShareLists", [context, context]), 1);
  assert.equal(invoke(guest, "wglMakeCurrent", [0, 0]), 1);
  assert.equal(invoke(guest, "wglDeleteContext", [context]), 1);
});

test("wglGetExtensionsStringARB returns the declared WGL ARB token", () => {
  const { guest } = createConformanceMachine();
  const dc = guest.invokeExport(guest.lookupExport("user32.dll", "GetDC"), [0]);
  const pointer = invoke(guest, "wglGetExtensionsStringARB", [dc]);
  assert.notEqual(pointer, 0);
  assert.match(guest.readAnsiString(pointer), /WGL_ARB_extensions_string/);
  const name = 0x00150080;
  guest.writeAnsiString(name, "wglGetExtensionsStringARB", 32);
  const thunk = invoke(guest, "wglGetProcAddress", [name]);
  assert.notEqual(thunk, 0);
});

function writePfd(guest, address) {
  const block = Buffer.alloc(40);
  block.writeUInt16LE(40, 0);
  block.writeUInt16LE(1, 2);
  guest.memory.writeBlock(address, block);
}

function preparePresentDc(guest) {
  const dc = guest.invokeExport(guest.lookupExport("user32.dll", "GetDC"), [0]);
  const pfd = 0x00160000;
  writePfd(guest, pfd);
  assert.equal(guest.invokeExport(guest.lookupExport("gdi32.dll", "ChoosePixelFormat"), [dc, pfd]), 1);
  assert.equal(guest.invokeExport(guest.lookupExport("gdi32.dll", "SetPixelFormat"), [dc, 1, 0]), 1);
  const context = invoke(guest, "wglCreateContext", [dc]);
  assert.notEqual(context, 0);
  assert.equal(invoke(guest, "wglMakeCurrent", [dc, context]), 1);
  return dc;
}

test("SwapBuffers publishes the GL color buffer as a presentable frame", () => {
  const { guest } = createConformanceMachine();
  const dc = preparePresentDc(guest);
  invoke(guest, "glViewport", [0, 0, 4, 4]);
  invoke(guest, "glClearColor", [floatBits(0), floatBits(1), floatBits(0), floatBits(1)]);
  invoke(guest, "glClear", [glEnum.COLOR_BUFFER_BIT]);
  assert.equal(guest.gl.presentFramebuffer(), null, "no front buffer until SwapBuffers");
  assert.equal(guest.invokeExport(guest.lookupExport("gdi32.dll", "SwapBuffers"), [dc]), 1);
  const frame = guest.gl.presentFramebuffer();
  assert.notEqual(frame, null);
  assert.equal(frame.present_count, 1);
  assert.equal(frame.is_blank, false);
  assert.equal(frame.rgba[0], 0);
  assert.equal(frame.rgba[1], 255);
  assert.equal(frame.rgba[2], 0);
  assert.equal(frame.rgba[3], 255);
  const surface = composeGuestSurface(guest);
  assert.equal(surface.width, frame.width);
  assert.equal(surface.height, frame.height);
  assert.deepEqual(Array.from(surface.rgba.subarray(0, 4)), [0, 255, 0, 255]);
});

test("SwapBuffers is generic: two DCs present with no title branch", () => {
  const gdiSource = readFileSync(new URL("../lib/gdi.mjs", import.meta.url), "utf8");
  const swapStart = gdiSource.indexOf('define("SwapBuffers"');
  assert.ok(swapStart >= 0, "gdi32!SwapBuffers is defined");
  const swapBody = gdiSource.slice(swapStart, gdiSource.indexOf("return table;", swapStart));
  assert.doesNotMatch(swapBody, /title|executable_name|supertux|SuperTux/i);
  const glSource = readFileSync(new URL("../lib/gl.mjs", import.meta.url), "utf8");
  const glStart = glSource.indexOf("swapBuffers(");
  const glBody = glSource.slice(glStart, glSource.indexOf("presentFramebuffer", glStart));
  assert.doesNotMatch(glBody, /title|executable_name|supertux|SuperTux/i);

  const { guest } = createConformanceMachine();
  const dcA = preparePresentDc(guest);
  const dcB = guest.invokeExport(guest.lookupExport("user32.dll", "GetDC"), [0]);
  writePfd(guest, 0x00160000);
  assert.equal(guest.invokeExport(guest.lookupExport("gdi32.dll", "SetPixelFormat"), [dcB, 1, 0]), 1);
  assert.equal(guest.invokeExport(guest.lookupExport("gdi32.dll", "SwapBuffers"), [dcA]), 1);
  assert.equal(guest.invokeExport(guest.lookupExport("gdi32.dll", "SwapBuffers"), [dcB]), 1);
  assert.equal(guest.gl.describe().present_count, 2);
  assert.equal(guest.gl.is_presented, true);
});

test("wglSwapLayerBuffers is the WGL twin of SwapBuffers", () => {
  const { guest } = createConformanceMachine();
  const dc = preparePresentDc(guest);
  invoke(guest, "glClearColor", [floatBits(1), floatBits(0), floatBits(0), floatBits(1)]);
  invoke(guest, "glClear", [glEnum.COLOR_BUFFER_BIT]);
  assert.equal(invoke(guest, "wglSwapLayerBuffers", [dc, 1]), 1);
  const frame = guest.gl.presentFramebuffer();
  assert.notEqual(frame, null);
  assert.equal(frame.rgba[0], 255);
  assert.equal(frame.rgba[1], 0);
  assert.equal(frame.is_blank, false);
});
