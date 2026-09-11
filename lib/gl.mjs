// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Bounded OpenGL 1.1 immediate-mode HLE (the SuperTux / BottleShip-class
// slice). One context per guest: a real color buffer, texture name table,
// matrix stacks, and client-array pointers. glClear / glReadPixels /
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
});

export const glBound = Object.freeze({
  dimension_max: 2048,
  default_width: 640,
  default_height: 480,
  texture_count: 4096,
  texture_store_byte: 4 * 1024 * 1024,
});

function bitsToFloat(bits) {
  const word = Buffer.alloc(4);
  word.writeUInt32LE(bits >>> 0, 0);
  return word.readFloatLE(0);
}

function identityMatrix() {
  return new Float64Array([1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]);
}

function multiplyMatrix(left, right) {
  const result = new Float64Array(16);
  for (let column = 0; column < 4; column += 1) {
    for (let row = 0; row < 4; row += 1) {
      result[column * 4 + row] =
        left[0 * 4 + row] * right[column * 4 + 0] +
        left[1 * 4 + row] * right[column * 4 + 1] +
        left[2 * 4 + row] * right[column * 4 + 2] +
        left[3 * 4 + row] * right[column * 4 + 3];
    }
  }
  return result;
}

export function createGlSubsystem({ allocate, memory }) {
  // Identity strings intern on first glGetString so constructing the HLE does
  // not slide the arena cursor out from under GetCommandLine and the rest of
  // the pinned conformance addresses.
  let vendorAddress = 0;
  let rendererAddress = 0;
  let versionAddress = 0;
  let extensionAddress = 0;
  function internIdentity() {
    if (vendorAddress !== 0) return;
    vendorAddress = allocate(8);
    rendererAddress = allocate(16);
    versionAddress = allocate(24);
    extensionAddress = allocate(4);
    memory.writeBlock(vendorAddress, Buffer.from("BPTK\0"));
    memory.writeBlock(rendererAddress, Buffer.from("BPTK-GL\0"));
    memory.writeBlock(versionAddress, Buffer.from("1.1 BPTK\0"));
    memory.writeBlock(extensionAddress, Buffer.from("\0"));
  }

  let width = glBound.default_width;
  let height = glBound.default_height;
  let pixel = new Uint8ClampedArray(width * height * 4);
  let error = glEnum.NO_ERROR;
  let clearColor = [0, 0, 0, 0];
  let viewport = [0, 0, width, height];
  let scissor = [0, 0, width, height];
  let matrixMode = glEnum.MODELVIEW;
  const matrix = {
    [glEnum.MODELVIEW]: identityMatrix(),
    [glEnum.PROJECTION]: identityMatrix(),
    [glEnum.TEXTURE]: identityMatrix(),
  };
  const enable = new Set();
  const clientState = new Set();
  const texture = new Map();
  let nextTexture = 1;
  let boundTexture = 0;
  let unpackAlignment = 4;
  let color = [1, 1, 1, 1];
  let blend = [0, 0];
  let vertexPointer = null;
  let texCoordPointer = null;
  let colorPointer = null;
  let drawCount = 0;
  let textureStoreByte = 0;

  function setError(code) {
    if (error === glEnum.NO_ERROR) error = code;
  }

  function currentMatrix() {
    return matrix[matrixMode] ?? matrix[glEnum.MODELVIEW];
  }

  function setCurrentMatrix(value) {
    matrix[matrixMode] = value;
  }

  function ensureSurface(nextWidth, nextHeight) {
    const boundedWidth = Math.min(glBound.dimension_max, Math.max(1, nextWidth | 0));
    const boundedHeight = Math.min(glBound.dimension_max, Math.max(1, nextHeight | 0));
    if (boundedWidth <= width && boundedHeight <= height) return;
    const grown = new Uint8ClampedArray(boundedWidth * boundedHeight * 4);
    for (let y = 0; y < height; y += 1) {
      grown.set(pixel.subarray(y * width * 4, y * width * 4 + width * 4), y * boundedWidth * 4);
    }
    pixel = grown;
    width = boundedWidth;
    height = boundedHeight;
  }

  function fillRect(x, y, w, h, rgba) {
    const left = Math.max(0, x | 0);
    const top = Math.max(0, y | 0);
    const right = Math.min(width, left + Math.max(0, w | 0));
    const bottom = Math.min(height, top + Math.max(0, h | 0));
    const r = Math.max(0, Math.min(255, Math.round(rgba[0] * 255)));
    const g = Math.max(0, Math.min(255, Math.round(rgba[1] * 255)));
    const b = Math.max(0, Math.min(255, Math.round(rgba[2] * 255)));
    const a = Math.max(0, Math.min(255, Math.round(rgba[3] * 255)));
    for (let row = top; row < bottom; row += 1) {
      let offset = (row * width + left) * 4;
      for (let column = left; column < right; column += 1) {
        pixel[offset] = r;
        pixel[offset + 1] = g;
        pixel[offset + 2] = b;
        pixel[offset + 3] = a;
        offset += 4;
      }
    }
  }

  return {
    vendor_address: vendorAddress,
    renderer_address: rendererAddress,
    version_address: versionAddress,
    getError() {
      const value = error;
      error = glEnum.NO_ERROR;
      return value;
    },
    getString(name) {
      internIdentity();
      if (name === glEnum.VENDOR) return vendorAddress;
      if (name === glEnum.RENDERER) return rendererAddress;
      if (name === glEnum.VERSION) return versionAddress;
      if (name === glEnum.EXTENSIONS) return extensionAddress;
      setError(glEnum.INVALID_ENUM);
      return 0;
    },
    getIntegerv(name, outPointer) {
      if (outPointer === 0) {
        setError(glEnum.INVALID_VALUE);
        return 0;
      }
      if (name === glEnum.MAX_TEXTURE_SIZE) {
        memory.writeMemory(outPointer, 4, glBound.dimension_max);
        return 1;
      }
      if (name === glEnum.VIEWPORT) {
        memory.writeMemory(outPointer, 4, viewport[0]);
        memory.writeMemory(outPointer + 4, 4, viewport[1]);
        memory.writeMemory(outPointer + 8, 4, viewport[2]);
        memory.writeMemory(outPointer + 12, 4, viewport[3]);
        return 1;
      }
      setError(glEnum.INVALID_ENUM);
      return 0;
    },
    clearColor(red, green, blue, alpha) {
      clearColor = [red, green, blue, alpha];
    },
    clear(mask) {
      if ((mask & glEnum.COLOR_BUFFER_BIT) !== 0) {
        fillRect(viewport[0], viewport[1], viewport[2], viewport[3], clearColor);
      }
    },
    viewport(x, y, w, h) {
      if (w < 0 || h < 0) {
        setError(glEnum.INVALID_VALUE);
        return;
      }
      ensureSurface(x + w, y + h);
      viewport = [x | 0, y | 0, w | 0, h | 0];
    },
    scissor(x, y, w, h) {
      if (w < 0 || h < 0) {
        setError(glEnum.INVALID_VALUE);
        return;
      }
      scissor = [x | 0, y | 0, w | 0, h | 0];
    },
    enable(cap) {
      enable.add(cap >>> 0);
    },
    disable(cap) {
      enable.delete(cap >>> 0);
    },
    enableClientState(cap) {
      clientState.add(cap >>> 0);
    },
    disableClientState(cap) {
      clientState.delete(cap >>> 0);
    },
    matrixMode(mode) {
      if (mode !== glEnum.MODELVIEW && mode !== glEnum.PROJECTION && mode !== glEnum.TEXTURE) {
        setError(glEnum.INVALID_ENUM);
        return;
      }
      matrixMode = mode;
    },
    loadIdentity() {
      setCurrentMatrix(identityMatrix());
    },
    translatef(x, y, z) {
      const translation = identityMatrix();
      translation[12] = x;
      translation[13] = y;
      translation[14] = z;
      setCurrentMatrix(multiplyMatrix(currentMatrix(), translation));
    },
    ortho(left, right, bottom, top, near, far) {
      const dx = right - left;
      const dy = top - bottom;
      const dz = far - near;
      if (dx === 0 || dy === 0 || dz === 0) {
        setError(glEnum.INVALID_VALUE);
        return;
      }
      const projection = identityMatrix();
      projection[0] = 2 / dx;
      projection[5] = 2 / dy;
      projection[10] = -2 / dz;
      projection[12] = -(right + left) / dx;
      projection[13] = -(top + bottom) / dy;
      projection[14] = -(far + near) / dz;
      setCurrentMatrix(multiplyMatrix(currentMatrix(), projection));
    },
    color4f(red, green, blue, alpha) {
      color = [red, green, blue, alpha];
    },
    blendFunc(source, destination) {
      blend = [source >>> 0, destination >>> 0];
    },
    pixelStorei(_name, value) {
      unpackAlignment = value | 0;
    },
    genTextures(count, outPointer) {
      if (count < 0 || outPointer === 0) {
        setError(glEnum.INVALID_VALUE);
        return;
      }
      for (let index = 0; index < count; index += 1) {
        if (texture.size >= glBound.texture_count) {
          setError(glEnum.INVALID_OPERATION);
          return;
        }
        const id = nextTexture;
        nextTexture += 1;
        texture.set(id, { width: 0, height: 0, pixel: null });
        memory.writeMemory(outPointer + index * 4, 4, id);
      }
    },
    deleteTextures(count, inPointer) {
      if (count < 0 || inPointer === 0) {
        setError(glEnum.INVALID_VALUE);
        return;
      }
      for (let index = 0; index < count; index += 1) {
        const id = memory.readMemory(inPointer + index * 4, 4);
        const record = texture.get(id);
        if (record?.pixel) textureStoreByte = Math.max(0, textureStoreByte - record.pixel.length);
        texture.delete(id);
        if (boundTexture === id) boundTexture = 0;
      }
    },
    bindTexture(target, id) {
      if (target !== glEnum.TEXTURE_2D) {
        setError(glEnum.INVALID_ENUM);
        return;
      }
      if (id !== 0 && !texture.has(id >>> 0)) texture.set(id >>> 0, { width: 0, height: 0, pixel: null });
      boundTexture = id >>> 0;
    },
    texParameteri(_target, _name, _value) {
      // Filter / wrap state is accepted; sampling is not yet a presented frame.
    },
    texImage2D(_target, _level, _internal, w, h, border, _format, _type, pixels) {
      if (border !== 0 || w < 0 || h < 0) {
        setError(glEnum.INVALID_VALUE);
        return;
      }
      if (boundTexture === 0) {
        setError(glEnum.INVALID_OPERATION);
        return;
      }
      const byteCount = (w | 0) * (h | 0) * 4;
      if (byteCount > glBound.texture_store_byte || textureStoreByte + byteCount > glBound.texture_store_byte) {
        setError(glEnum.INVALID_VALUE);
        return;
      }
      const record = texture.get(boundTexture) ?? { width: 0, height: 0, pixel: null };
      if (record.pixel) textureStoreByte -= record.pixel.length;
      const stored = pixels === 0 ? null : Buffer.from(memory.readBlock(pixels, byteCount));
      if (stored) textureStoreByte += stored.length;
      texture.set(boundTexture, { width: w | 0, height: h | 0, pixel: stored });
    },
    copyTexSubImage2D(_target, _level, _xoffset, _yoffset, _x, _y, w, h) {
      if (w < 0 || h < 0) setError(glEnum.INVALID_VALUE);
    },
    vertexPointer(size, type, stride, pointer) {
      vertexPointer = { size, type, stride, pointer };
    },
    texCoordPointer(size, type, stride, pointer) {
      texCoordPointer = { size, type, stride, pointer };
    },
    colorPointer(size, type, stride, pointer) {
      colorPointer = { size, type, stride, pointer };
    },
    drawArrays(_mode, first, count) {
      if (count < 0 || first < 0) {
        setError(glEnum.INVALID_VALUE);
        return;
      }
      drawCount += 1;
    },
    readPixels(x, y, w, h, format, type, outPointer) {
      if (outPointer === 0 || w < 0 || h < 0) {
        setError(glEnum.INVALID_VALUE);
        return;
      }
      if (format !== glEnum.RGBA || type !== glEnum.UNSIGNED_BYTE) {
        setError(glEnum.INVALID_ENUM);
        return;
      }
      const block = Buffer.alloc((w | 0) * (h | 0) * 4);
      let cursor = 0;
      for (let row = 0; row < (h | 0); row += 1) {
        const sourceY = (y | 0) + row;
        for (let column = 0; column < (w | 0); column += 1) {
          const sourceX = (x | 0) + column;
          if (sourceX >= 0 && sourceY >= 0 && sourceX < width && sourceY < height) {
            const offset = (sourceY * width + sourceX) * 4;
            block[cursor] = pixel[offset];
            block[cursor + 1] = pixel[offset + 1];
            block[cursor + 2] = pixel[offset + 2];
            block[cursor + 3] = pixel[offset + 3];
          }
          cursor += 4;
        }
      }
      memory.writeBlock(outPointer, block);
    },
    describe() {
      return {
        width,
        height,
        viewport: [...viewport],
        scissor: [...scissor],
        matrix_mode: matrixMode,
        bound_texture: boundTexture,
        texture_count: texture.size,
        draw_count: drawCount,
        unpack_alignment: unpackAlignment,
        blend,
        color: [...color],
        enable_count: enable.size,
        client_state_count: clientState.size,
        vertex_pointer: vertexPointer,
        texcoord_pointer: texCoordPointer,
        color_pointer: colorPointer,
      };
    },
  };
}

export function buildGlExportTable() {
  const table = [];
  function define(symbol, argumentCount, emulate) {
    table.push(Object.freeze({ library: "opengl32.dll", symbol, argument_count: argumentCount, emulate }));
  }

  define("glGetError", 0, (guest) => guest.gl.getError());
  define("glGetString", 1, (guest, argument) => guest.gl.getString(argument[0]));
  define("glGetIntegerv", 2, (guest, argument) => guest.gl.getIntegerv(argument[0], argument[1]));
  define("glClearColor", 4, (guest, argument) => guest.gl.clearColor(bitsToFloat(argument[0]), bitsToFloat(argument[1]), bitsToFloat(argument[2]), bitsToFloat(argument[3])));
  define("glClear", 1, (guest, argument) => guest.gl.clear(argument[0]));
  define("glViewport", 4, (guest, argument) => guest.gl.viewport(argument[0] | 0, argument[1] | 0, argument[2] | 0, argument[3] | 0));
  define("glScissor", 4, (guest, argument) => guest.gl.scissor(argument[0] | 0, argument[1] | 0, argument[2] | 0, argument[3] | 0));
  define("glEnable", 1, (guest, argument) => guest.gl.enable(argument[0]));
  define("glDisable", 1, (guest, argument) => guest.gl.disable(argument[0]));
  define("glEnableClientState", 1, (guest, argument) => guest.gl.enableClientState(argument[0]));
  define("glDisableClientState", 1, (guest, argument) => guest.gl.disableClientState(argument[0]));
  define("glMatrixMode", 1, (guest, argument) => guest.gl.matrixMode(argument[0]));
  define("glLoadIdentity", 0, (guest) => guest.gl.loadIdentity());
  define("glTranslatef", 3, (guest, argument) => guest.gl.translatef(bitsToFloat(argument[0]), bitsToFloat(argument[1]), bitsToFloat(argument[2])));
  define("glOrtho", 6, (guest, argument) => guest.gl.ortho(bitsToFloat(argument[0]), bitsToFloat(argument[1]), bitsToFloat(argument[2]), bitsToFloat(argument[3]), bitsToFloat(argument[4]), bitsToFloat(argument[5])));
  define("glColor4f", 4, (guest, argument) => guest.gl.color4f(bitsToFloat(argument[0]), bitsToFloat(argument[1]), bitsToFloat(argument[2]), bitsToFloat(argument[3])));
  define("glBlendFunc", 2, (guest, argument) => guest.gl.blendFunc(argument[0], argument[1]));
  define("glPixelStorei", 2, (guest, argument) => guest.gl.pixelStorei(argument[0], argument[1]));
  define("glGenTextures", 2, (guest, argument) => guest.gl.genTextures(argument[0] | 0, argument[1]));
  define("glDeleteTextures", 2, (guest, argument) => guest.gl.deleteTextures(argument[0] | 0, argument[1]));
  define("glBindTexture", 2, (guest, argument) => guest.gl.bindTexture(argument[0], argument[1]));
  define("glTexParameteri", 3, (guest, argument) => guest.gl.texParameteri(argument[0], argument[1], argument[2]));
  define("glTexImage2D", 9, (guest, argument) => guest.gl.texImage2D(argument[0], argument[1], argument[2], argument[3] | 0, argument[4] | 0, argument[5] | 0, argument[6], argument[7], argument[8]));
  define("glCopyTexSubImage2D", 8, (guest, argument) => guest.gl.copyTexSubImage2D(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6] | 0, argument[7] | 0));
  define("glVertexPointer", 4, (guest, argument) => guest.gl.vertexPointer(argument[0], argument[1], argument[2], argument[3]));
  define("glTexCoordPointer", 4, (guest, argument) => guest.gl.texCoordPointer(argument[0], argument[1], argument[2], argument[3]));
  define("glColorPointer", 4, (guest, argument) => guest.gl.colorPointer(argument[0], argument[1], argument[2], argument[3]));
  define("glDrawArrays", 3, (guest, argument) => guest.gl.drawArrays(argument[0], argument[1] | 0, argument[2] | 0));
  define("glReadPixels", 7, (guest, argument) => guest.gl.readPixels(argument[0] | 0, argument[1] | 0, argument[2] | 0, argument[3] | 0, argument[4], argument[5], argument[6]));
  return table;
}

export const glExportTable = Object.freeze(buildGlExportTable());
