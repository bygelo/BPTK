// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The 2D GDI slice (BPTK-012). One generic device-context model over a bounded
// RGBA surface: stock and created objects (pen, brush, font), rectangle and
// line primitives, TextOut with a deterministic stock bitmap font, BitBlt and
// StretchBlt raster operations, GetPixel/SetPixel, and the 555/565 packed
// pixel-format conversions a DirectDraw-era title round-trips through. Nothing
// branches on a title identity — a surface is a surface, a DC is a DC.
//
// The surface is host memory bounded by gdiBound; it is the buffer the browser
// present path reads. The draw fixture compares a rendered surface against a
// reference computed at test time (see computeFrameDiff in lib/shader.mjs), so
// no golden pixel is ever committed (doc/TESTING.md).

import { InputError } from "./input.mjs";

function gdiFault(code, message) {
  return new InputError(code, message);
}

export const gdiBound = Object.freeze({
  dimension_max: 4096,
  surface_count: 256,
  object_count: 4096,
  string_byte: 4096,
});

// The raster operation the BitBlt path honors, keyed by the Win32 ternary ROP
// code. Only the codes the corpus actually issues are named; an unknown ROP is
// refused, never silently mapped to SRCCOPY.
export const rasterOp = Object.freeze({
  SRCCOPY: 0x00cc0020,
  SRCPAINT: 0x00ee0086,
  SRCAND: 0x008800c6,
  SRCINVERT: 0x00660046,
  BLACKNESS: 0x00000042,
  WHITENESS: 0x00ff0062,
  PATCOPY: 0x00f00021,
});

// The background mode SetBkMode selects.
export const backgroundMode = Object.freeze({ TRANSPARENT: 1, OPAQUE: 2 });

// The stock objects GetStockObject serves, at fixed handles so a fixture reads
// the same handle across runs.
const stockHandle = Object.freeze({
  WHITE_BRUSH: 0x80000000,
  LTGRAY_BRUSH: 0x80000001,
  GRAY_BRUSH: 0x80000002,
  DKGRAY_BRUSH: 0x80000003,
  BLACK_BRUSH: 0x80000004,
  NULL_BRUSH: 0x80000005,
  WHITE_PEN: 0x80000006,
  BLACK_PEN: 0x80000007,
  NULL_PEN: 0x80000008,
  SYSTEM_FONT: 0x8000000d,
  DEFAULT_PALETTE: 0x8000000f,
});
export const stockObject = stockHandle;

// COLORREF is 0x00BBGGRR. RGB packs, and the channel accessors read back the
// component the surface stores as RGBA.
export function rgb(r, g, b) {
  return ((b & 0xff) << 16 | (g & 0xff) << 8 | (r & 0xff)) >>> 0;
}
function colorRed(colorRef) {
  return colorRef & 0xff;
}
function colorGreen(colorRef) {
  return (colorRef >> 8) & 0xff;
}
function colorBlue(colorRef) {
  return (colorRef >> 16) & 0xff;
}

// --- packed pixel-format conversion ---------------------------------------
// The 8-bit channels expand from the high bits so white stays white (the
// standard bit-replication expansion, not a zero-fill that darkens).
export function pack565(r, g, b) {
  return ((r >> 3) << 11 | (g >> 2) << 5 | (b >> 3)) & 0xffff;
}
export function unpack565(value) {
  const r5 = (value >> 11) & 0x1f;
  const g6 = (value >> 5) & 0x3f;
  const b5 = value & 0x1f;
  return { r: (r5 << 3) | (r5 >> 2), g: (g6 << 2) | (g6 >> 4), b: (b5 << 3) | (b5 >> 2) };
}
export function pack555(r, g, b) {
  return ((r >> 3) << 10 | (g >> 3) << 5 | (b >> 3)) & 0x7fff;
}
export function unpack555(value) {
  const r5 = (value >> 10) & 0x1f;
  const g5 = (value >> 5) & 0x1f;
  const b5 = value & 0x1f;
  return { r: (r5 << 3) | (r5 >> 2), g: (g5 << 3) | (g5 >> 2), b: (b5 << 3) | (b5 >> 2) };
}

// --- the stock bitmap font -------------------------------------------------
// A deterministic 8x8 glyph table for the printable subset the fixture draws.
// Each glyph is eight bytes, one row of eight pixels from the high bit. A
// missing glyph renders as the blank cell, exactly as a stock font falls back.
const glyphRow = Object.freeze({
  " ": [0, 0, 0, 0, 0, 0, 0, 0],
  "A": [0x18, 0x3c, 0x66, 0x66, 0x7e, 0x66, 0x66, 0x00],
  "B": [0x7c, 0x66, 0x66, 0x7c, 0x66, 0x66, 0x7c, 0x00],
  "H": [0x66, 0x66, 0x66, 0x7e, 0x66, 0x66, 0x66, 0x00],
  "I": [0x3c, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3c, 0x00],
  "O": [0x3c, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3c, 0x00],
  "0": [0x3c, 0x66, 0x6e, 0x76, 0x66, 0x66, 0x3c, 0x00],
  "1": [0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7e, 0x00],
  "2": [0x3c, 0x66, 0x06, 0x0c, 0x30, 0x60, 0x7e, 0x00],
});
const glyphWidth = 8;
const glyphHeight = 8;

// ---------------------------------------------------------------------------
// The GDI subsystem. One instance per guest process; owns the DC table, the
// object table, and the stock objects.
// ---------------------------------------------------------------------------

export function createGdiSubsystem() {
  const dcByHandle = new Map();
  const objectByHandle = new Map();
  let nextHandle = 0x00040000;
  let lastError = 0;

  function setLastError(value) {
    lastError = value >>> 0;
  }

  const stockObjectByHandle = new Map([
    [stockHandle.WHITE_BRUSH, { kind: "brush", color: rgb(255, 255, 255), is_null: false }],
    [stockHandle.LTGRAY_BRUSH, { kind: "brush", color: rgb(192, 192, 192), is_null: false }],
    [stockHandle.GRAY_BRUSH, { kind: "brush", color: rgb(128, 128, 128), is_null: false }],
    [stockHandle.DKGRAY_BRUSH, { kind: "brush", color: rgb(64, 64, 64), is_null: false }],
    [stockHandle.BLACK_BRUSH, { kind: "brush", color: rgb(0, 0, 0), is_null: false }],
    [stockHandle.NULL_BRUSH, { kind: "brush", color: 0, is_null: true }],
    [stockHandle.WHITE_PEN, { kind: "pen", color: rgb(255, 255, 255), width: 1, is_null: false }],
    [stockHandle.BLACK_PEN, { kind: "pen", color: rgb(0, 0, 0), width: 1, is_null: false }],
    [stockHandle.NULL_PEN, { kind: "pen", color: 0, width: 1, is_null: true }],
    [stockHandle.SYSTEM_FONT, { kind: "font", height: glyphHeight }],
    [stockHandle.DEFAULT_PALETTE, { kind: "palette" }],
  ]);

  function lookupObject(handle) {
    return objectByHandle.get(handle >>> 0) ?? stockObjectByHandle.get(handle >>> 0) ?? null;
  }

  function allocateObject(object) {
    if (objectByHandle.size >= gdiBound.object_count) {
      throw gdiFault("gdi_object_exhausted", `The object table exceeds ${gdiBound.object_count} object`);
    }
    const handle = nextHandle;
    nextHandle += 4;
    objectByHandle.set(handle, object);
    return handle;
  }

  function getStockObject(index) {
    // The index enum equals the handle low bits, so the fixed handle is direct.
    const handle = (0x80000000 | index) >>> 0;
    return stockObjectByHandle.has(handle) ? handle : 0;
  }

  function createSolidBrush(colorRef) {
    return allocateObject({ kind: "brush", color: colorRef >>> 0, is_null: false });
  }
  function createPen(style, width, colorRef) {
    return allocateObject({ kind: "pen", color: colorRef >>> 0, width: Math.max(1, width | 0), is_null: style === 5 });
  }
  function deleteObject(handle) {
    if (stockObjectByHandle.has(handle >>> 0)) return 0; // a stock object cannot be deleted
    return objectByHandle.delete(handle >>> 0) ? 1 : 0;
  }

  function makeSurface(width, height) {
    if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0) {
      throw gdiFault("gdi_dimension_invalid", "A surface requires a positive integer dimension");
    }
    if (width > gdiBound.dimension_max || height > gdiBound.dimension_max) {
      throw gdiFault("gdi_dimension_bound", `A surface dimension exceeds ${gdiBound.dimension_max}`);
    }
    return { width, height, pixel: new Uint8ClampedArray(width * height * 4) };
  }

  // A DC always owns a surface. CreateCompatibleDC without a source makes a
  // 1x1 scratch surface until a bitmap is selected, matching the Win32 default.
  function createDC(width, height) {
    if (dcByHandle.size >= gdiBound.surface_count) {
      throw gdiFault("gdi_surface_exhausted", `The DC table exceeds ${gdiBound.surface_count} surface`);
    }
    const surface = makeSurface(width ?? 1, height ?? 1);
    const handle = nextHandle;
    nextHandle += 4;
    dcByHandle.set(handle, {
      handle,
      surface,
      pen: stockObjectByHandle.get(stockHandle.BLACK_PEN),
      brush: stockObjectByHandle.get(stockHandle.WHITE_BRUSH),
      font: stockObjectByHandle.get(stockHandle.SYSTEM_FONT),
      text_color: rgb(0, 0, 0),
      bk_color: rgb(255, 255, 255),
      bk_mode: backgroundMode.OPAQUE,
      cur_x: 0,
      cur_y: 0,
    });
    return handle;
  }

  function deleteDC(handle) {
    return dcByHandle.delete(handle >>> 0) ? 1 : 0;
  }

  function requireDC(handle) {
    const dc = dcByHandle.get(handle >>> 0);
    if (dc === undefined) throw gdiFault("gdi_dc_invalid", "The DC handle is not a live device context");
    return dc;
  }

  // SelectObject swaps in a pen, brush, or font and returns the previous
  // handle of the same kind, as Win32 does.
  function selectObject(dcHandle, objectHandle) {
    const dc = requireDC(dcHandle);
    const object = lookupObject(objectHandle);
    if (object === null) {
      setLastError(0x57);
      return 0;
    }
    const previousByKind = { pen: dc.pen, brush: dc.brush, font: dc.font };
    const previous = previousByKind[object.kind];
    if (previous === undefined) return 0;
    dc[object.kind] = object;
    return previousHandleOf(previous);
  }

  function previousHandleOf(object) {
    for (const [handle, value] of stockObjectByHandle.entries()) if (value === object) return handle;
    for (const [handle, value] of objectByHandle.entries()) if (value === object) return handle;
    return 0;
  }

  // --- pixel access --------------------------------------------------------
  function setPixel(dc, x, y, colorRef) {
    if (x < 0 || y < 0 || x >= dc.surface.width || y >= dc.surface.height) return false;
    const offset = (y * dc.surface.width + x) * 4;
    dc.surface.pixel[offset] = colorRed(colorRef);
    dc.surface.pixel[offset + 1] = colorGreen(colorRef);
    dc.surface.pixel[offset + 2] = colorBlue(colorRef);
    dc.surface.pixel[offset + 3] = 255;
    return true;
  }
  function getPixel(dc, x, y) {
    if (x < 0 || y < 0 || x >= dc.surface.width || y >= dc.surface.height) return 0xffffffff;
    const offset = (y * dc.surface.width + x) * 4;
    return rgb(dc.surface.pixel[offset], dc.surface.pixel[offset + 1], dc.surface.pixel[offset + 2]);
  }

  function setPixelExport(dcHandle, x, y, colorRef) {
    const dc = requireDC(dcHandle);
    return setPixel(dc, x | 0, y | 0, colorRef >>> 0) ? colorRef >>> 0 : 0xffffffff;
  }
  function getPixelExport(dcHandle, x, y) {
    return getPixel(requireDC(dcHandle), x | 0, y | 0);
  }

  // --- primitives ----------------------------------------------------------
  // FillRect paints [left,right) x [top,bottom) with the brush color; a null
  // brush leaves the region untouched.
  function fillRect(dcHandle, rect, brushHandle) {
    const dc = requireDC(dcHandle);
    const brush = brushHandle === undefined ? dc.brush : lookupObject(brushHandle);
    if (brush === null || brush.kind !== "brush" || brush.is_null) return brush === null ? 0 : 1;
    for (let y = Math.max(0, rect.top); y < Math.min(dc.surface.height, rect.bottom); y += 1) {
      for (let x = Math.max(0, rect.left); x < Math.min(dc.surface.width, rect.right); x += 1) {
        setPixel(dc, x, y, brush.color);
      }
    }
    return 1;
  }

  // Rectangle strokes the border with the pen and fills the interior with the
  // brush, matching the Win32 outline+fill semantics.
  function rectangle(dcHandle, left, top, right, bottom) {
    const dc = requireDC(dcHandle);
    if (!dc.brush.is_null) {
      for (let y = top + 1; y < bottom - 1; y += 1) for (let x = left + 1; x < right - 1; x += 1) setPixel(dc, x, y, dc.brush.color);
    }
    if (!dc.pen.is_null) {
      for (let x = left; x < right; x += 1) {
        setPixel(dc, x, top, dc.pen.color);
        setPixel(dc, x, bottom - 1, dc.pen.color);
      }
      for (let y = top; y < bottom; y += 1) {
        setPixel(dc, left, y, dc.pen.color);
        setPixel(dc, right - 1, y, dc.pen.color);
      }
    }
    return 1;
  }

  function moveToEx(dcHandle, x, y) {
    const dc = requireDC(dcHandle);
    const previous = { x: dc.cur_x, y: dc.cur_y };
    dc.cur_x = x | 0;
    dc.cur_y = y | 0;
    return previous;
  }

  // LineTo strokes from the current position to (x,y) with the pen color using
  // the integer Bresenham line, then updates the current position.
  function lineTo(dcHandle, x, y) {
    const dc = requireDC(dcHandle);
    if (!dc.pen.is_null) drawLine(dc, dc.cur_x, dc.cur_y, x | 0, y | 0, dc.pen.color);
    dc.cur_x = x | 0;
    dc.cur_y = y | 0;
    return 1;
  }

  function drawLine(dc, x0, y0, x1, y1, colorRef) {
    let sx0 = x0;
    let sy0 = y0;
    const dx = Math.abs(x1 - x0);
    const dy = -Math.abs(y1 - y0);
    const stepX = x0 < x1 ? 1 : -1;
    const stepY = y0 < y1 ? 1 : -1;
    let error = dx + dy;
    for (;;) {
      setPixel(dc, sx0, sy0, colorRef);
      if (sx0 === x1 && sy0 === y1) break;
      const doubleError = 2 * error;
      if (doubleError >= dy) {
        error += dy;
        sx0 += stepX;
      }
      if (doubleError <= dx) {
        error += dx;
        sy0 += stepY;
      }
    }
  }

  // --- text ----------------------------------------------------------------
  // TextOut renders each character from the stock 8x8 glyph table at the
  // baseline origin, foreground in the text color, and in OPAQUE mode fills
  // the cell background first.
  function textOut(dcHandle, x, y, text) {
    const dc = requireDC(dcHandle);
    let penX = x | 0;
    for (const character of String(text)) {
      const glyph = glyphRow[character] ?? glyphRow[character.toUpperCase()] ?? glyphRow[" "];
      for (let row = 0; row < glyphHeight; row += 1) {
        for (let column = 0; column < glyphWidth; column += 1) {
          const isSet = (glyph[row] & (0x80 >> column)) !== 0;
          if (isSet) setPixel(dc, penX + column, (y | 0) + row, dc.text_color);
          else if (dc.bk_mode === backgroundMode.OPAQUE) setPixel(dc, penX + column, (y | 0) + row, dc.bk_color);
        }
      }
      penX += glyphWidth;
    }
    return 1;
  }

  function setTextColor(dcHandle, colorRef) {
    const dc = requireDC(dcHandle);
    const previous = dc.text_color;
    dc.text_color = colorRef >>> 0;
    return previous;
  }
  function setBkColor(dcHandle, colorRef) {
    const dc = requireDC(dcHandle);
    const previous = dc.bk_color;
    dc.bk_color = colorRef >>> 0;
    return previous;
  }
  function setBkMode(dcHandle, mode) {
    const dc = requireDC(dcHandle);
    const previous = dc.bk_mode;
    dc.bk_mode = mode;
    return previous;
  }

  // --- raster operations ---------------------------------------------------
  function applyRop(rop, source, destination) {
    switch (rop) {
      case rasterOp.SRCCOPY:
        return source;
      case rasterOp.SRCPAINT:
        return [source[0] | destination[0], source[1] | destination[1], source[2] | destination[2]];
      case rasterOp.SRCAND:
        return [source[0] & destination[0], source[1] & destination[1], source[2] & destination[2]];
      case rasterOp.SRCINVERT:
        return [source[0] ^ destination[0], source[1] ^ destination[1], source[2] ^ destination[2]];
      case rasterOp.BLACKNESS:
        return [0, 0, 0];
      case rasterOp.WHITENESS:
        return [255, 255, 255];
      case rasterOp.PATCOPY:
        return source;
      default:
        return null;
    }
  }

  function writePixelRaw(surface, x, y, channel) {
    if (x < 0 || y < 0 || x >= surface.width || y >= surface.height) return;
    const offset = (y * surface.width + x) * 4;
    surface.pixel[offset] = channel[0];
    surface.pixel[offset + 1] = channel[1];
    surface.pixel[offset + 2] = channel[2];
    surface.pixel[offset + 3] = 255;
  }
  function readPixelRaw(surface, x, y) {
    const offset = (y * surface.width + x) * 4;
    return [surface.pixel[offset], surface.pixel[offset + 1], surface.pixel[offset + 2]];
  }

  // BitBlt copies a width x height block from the source DC to the destination
  // under the ternary ROP. An unknown ROP is refused.
  function bitBlt(dstHandle, dstX, dstY, width, height, srcHandle, srcX, srcY, rop) {
    const destination = requireDC(dstHandle);
    const source = srcHandle === 0 ? null : requireDC(srcHandle);
    if (applyRop(rop, [0, 0, 0], [0, 0, 0]) === null) {
      setLastError(0x57);
      return 0;
    }
    for (let row = 0; row < height; row += 1) {
      for (let column = 0; column < width; column += 1) {
        const sourceChannel = source === null ? [0, 0, 0] : readPixelRaw(source.surface, srcX + column, srcY + row);
        const destinationChannel = readPixelRaw(destination.surface, dstX + column, dstY + row);
        const result = applyRop(rop, sourceChannel, destinationChannel);
        writePixelRaw(destination.surface, dstX + column, dstY + row, result);
      }
    }
    return 1;
  }

  // StretchBlt scales a source block into a destination block with
  // nearest-neighbor sampling under the ROP.
  function stretchBlt(dstHandle, dstX, dstY, dstWidth, dstHeight, srcHandle, srcX, srcY, srcWidth, srcHeight, rop) {
    const destination = requireDC(dstHandle);
    const source = requireDC(srcHandle);
    if (dstWidth <= 0 || dstHeight <= 0 || srcWidth <= 0 || srcHeight <= 0) {
      setLastError(0x57);
      return 0;
    }
    if (applyRop(rop, [0, 0, 0], [0, 0, 0]) === null) {
      setLastError(0x57);
      return 0;
    }
    for (let row = 0; row < dstHeight; row += 1) {
      const sampleRow = srcY + Math.floor((row * srcHeight) / dstHeight);
      for (let column = 0; column < dstWidth; column += 1) {
        const sampleColumn = srcX + Math.floor((column * srcWidth) / dstWidth);
        const sourceChannel = readPixelRaw(source.surface, sampleColumn, sampleRow);
        const destinationChannel = readPixelRaw(destination.surface, dstX + column, dstY + row);
        const result = applyRop(rop, sourceChannel, destinationChannel);
        writePixelRaw(destination.surface, dstX + column, dstY + row, result);
      }
    }
    return 1;
  }

  // The present readout: the surface as an array of [r,g,b,a] pixel, the shape
  // computeFrameDiff and the browser present path both consume.
  function surfacePixel(dcHandle) {
    const dc = requireDC(dcHandle);
    const pixel = [];
    for (let index = 0; index < dc.surface.width * dc.surface.height; index += 1) {
      const offset = index * 4;
      pixel.push([dc.surface.pixel[offset], dc.surface.pixel[offset + 1], dc.surface.pixel[offset + 2], dc.surface.pixel[offset + 3]]);
    }
    return pixel;
  }

  function surfaceInfo(dcHandle) {
    const dc = requireDC(dcHandle);
    return { width: dc.surface.width, height: dc.surface.height };
  }

  return {
    getLastError: () => lastError,
    setLastError,
    createDC,
    createCompatibleDC: (sourceHandle) => {
      if (sourceHandle === undefined || sourceHandle === 0) return createDC(1, 1);
      const source = requireDC(sourceHandle);
      return createDC(source.surface.width, source.surface.height);
    },
    deleteDC,
    getStockObject,
    createSolidBrush,
    createPen,
    deleteObject,
    selectObject,
    fillRect,
    rectangle,
    moveToEx,
    lineTo,
    textOut,
    setTextColor,
    setBkColor,
    setBkMode,
    bitBlt,
    stretchBlt,
    setPixel: setPixelExport,
    getPixel: getPixelExport,
    surfacePixel,
    surfaceInfo,
    dcCount: () => dcByHandle.size,
    objectCount: () => objectByHandle.size,
  };
}

// ---------------------------------------------------------------------------
// The GDI32 export table. Thin data rows delegating to the subsystem attached
// to the guest — the surface lib/hle.mjs registers.
// ---------------------------------------------------------------------------

export function buildGdiExportTable() {
  const table = [];
  function define(symbol, argumentCount, emulate) {
    table.push(Object.freeze({ library: "gdi32.dll", symbol, argument_count: argumentCount, emulate }));
  }

  define("CreateCompatibleDC", 1, (guest, argument) => guest.gdi.createCompatibleDC(argument[0]));
  define("DeleteDC", 1, (guest, argument) => guest.gdi.deleteDC(argument[0]));
  define("GetStockObject", 1, (guest, argument) => guest.gdi.getStockObject(argument[0]));
  define("CreateSolidBrush", 1, (guest, argument) => guest.gdi.createSolidBrush(argument[0]));
  define("CreatePen", 3, (guest, argument) => guest.gdi.createPen(argument[0], argument[1], argument[2]));
  define("DeleteObject", 1, (guest, argument) => guest.gdi.deleteObject(argument[0]));
  define("SelectObject", 2, (guest, argument) => guest.gdi.selectObject(argument[0], argument[1]));
  define("Rectangle", 5, (guest, argument) => guest.gdi.rectangle(argument[0], argument[1], argument[2], argument[3], argument[4]));
  define("MoveToEx", 4, (guest, argument) => {
    const previous = guest.gdi.moveToEx(argument[0], argument[1], argument[2]);
    if (argument[3] !== 0) {
      guest.memory.writeMemory(argument[3], 4, previous.x >>> 0);
      guest.memory.writeMemory(argument[3] + 4, 4, previous.y >>> 0);
    }
    return 1;
  });
  define("LineTo", 3, (guest, argument) => guest.gdi.lineTo(argument[0], argument[1], argument[2]));
  // TextOutW carries an explicit, non-terminated character count, so the wide
  // string is read exactly cchString units rather than to a null terminator.
  define("TextOutW", 5, (guest, argument) => {
    const base = argument[3];
    const count = argument[4] >>> 0;
    let text = "";
    for (let index = 0; index < count; index += 1) text += String.fromCharCode(guest.memory.readMemory(base + index * 2, 2));
    return guest.gdi.textOut(argument[0], argument[1], argument[2], text);
  });
  define("SetTextColor", 2, (guest, argument) => guest.gdi.setTextColor(argument[0], argument[1]));
  define("SetBkColor", 2, (guest, argument) => guest.gdi.setBkColor(argument[0], argument[1]));
  define("SetBkMode", 2, (guest, argument) => guest.gdi.setBkMode(argument[0], argument[1]));
  define("SetPixel", 4, (guest, argument) => guest.gdi.setPixel(argument[0], argument[1], argument[2], argument[3]));
  define("GetPixel", 3, (guest, argument) => guest.gdi.getPixel(argument[0], argument[1], argument[2]));
  define("BitBlt", 9, (guest, argument) => guest.gdi.bitBlt(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8]));
  define("StretchBlt", 11, (guest, argument) => guest.gdi.stretchBlt(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8], argument[9], argument[10]));

  return table;
}

export const gdiExportTable = Object.freeze(buildGdiExportTable());
