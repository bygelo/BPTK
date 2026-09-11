// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";
import { createConformanceMachine } from "../lib/hle.mjs";
import { glEnum } from "../lib/gl.mjs";

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
  const out = 0x00150040;
  invoke(guest, "glGenTextures", [1, out]);
  const id = guest.memory.readMemory(out, 4);
  assert.equal(id, 1);
  invoke(guest, "glBindTexture", [glEnum.TEXTURE_2D, id]);
  invoke(guest, "glTexImage2D", [glEnum.TEXTURE_2D, 0, glEnum.RGBA, 1, 1, 0, glEnum.RGBA, glEnum.UNSIGNED_BYTE, 0]);
  assert.equal(invoke(guest, "glGetError", []), 0);
  assert.equal(guest.gl.describe().texture_count, 1);
});
