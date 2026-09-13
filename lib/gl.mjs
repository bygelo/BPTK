// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Bounded OpenGL 2.1-compatibility HLE (the SuperTux / BottleShip-class
// slice). One context per guest: a real color buffer, texture name table,
// matrix stacks, and client-array pointers. glGetString VERSION is "2.1 BPTK"
// so a guest that sscanf's the major does not reject 1.x. glClear / glReadPixels /
// glTexImage2D / glGetString are real operations over that state. Client-array
// rasterization (glDrawArrays) is recorded and does not yet emit a playable
// frame — that gap stays named, not silently painted.

export const glEnum = Object.freeze({
  NO_ERROR: 0,
  INVALID_ENUM: 0x0500,
  INVALID_VALUE: 0x0501,
  INVALID_OPERATION: 0x0502,
  VENDOR: 0x1f00,
  RENDERER: 0x1f01,
  VERSION: 0x1f02,
  EXTENSIONS: 0x1f03,
  MAX_TEXTURE_SIZE: 0x0d33,
  VIEWPORT: 0x0ba2,
  MODELVIEW: 0x1700,
  PROJECTION: 0x1701,
  TEXTURE: 0x1702,
  COLOR_BUFFER_BIT: 0x00004000,
  DEPTH_BUFFER_BIT: 0x00000100,
  VERTEX_ARRAY: 0x8074,
  TEXTURE_COORD_ARRAY: 0x8078,
  COLOR_ARRAY: 0x8076,
  TEXTURE_2D: 0x0de1,
  BLEND: 0x0be2,
  SCISSOR_TEST: 0x0c11,
  RGBA: 0x1908,
  UNSIGNED_BYTE: 0x1401,
  MODELVIEW_MATRIX: 0x0ba6,
  PROJECTION_MATRIX: 0x0ba7,
  LINE_WIDTH: 0x0b21,
  POINT_SIZE: 0x0b11,
  CURRENT_COLOR: 0x0b00,
  VERTEX_ARRAY_POINTER: 0x808e,
  COLOR_ARRAY_POINTER: 0x8090,
  TEXTURE_COORD_ARRAY_POINTER: 0x8092,
  LESS: 0x0201,
  LEQUAL: 0x0203,
  SMOOTH: 0x1d01,
  FRONT: 0x0404,
  FUNC_ADD: 0x8006,
});
