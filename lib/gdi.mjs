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

// The binary raster op SetROP2 selects. Only the copy default is realized on
// the surface; the mode is stored so GetROP2 round-trips it.
export const rasterOp2 = Object.freeze({ R2_BLACK: 1, R2_WHITE: 16, R2_COPYPEN: 13, R2_NOTCOPYPEN: 4 });

// One declared OpenGL-capable pixel format (BPTK-012 / present path).
// ChoosePixelFormat / SetPixelFormat / GetPixelFormat / DescribePixelFormat
// talk about this table; there is no host PFD enumerator.
export const pixelFormatFlag = Object.freeze({
  double_buffer: 0x00000001,
  draw_to_window: 0x00000004,
  support_opengl: 0x00000020,
  generic_format: 0x00000040,
});
export const declaredPixelFormat = Object.freeze({
  index: 1,
  size_byte: 40,
  version: 1,
  flag: 0x00000001 | 0x00000004 | 0x00000020 | 0x00000040,
  pixel_type: 0,
  color_bit: 32,
  red_bit: 8,
  red_shift: 0,
  green_bit: 8,
  green_shift: 8,
  blue_bit: 8,
  blue_shift: 16,
  alpha_bit: 8,
  alpha_shift: 24,
  depth_bit: 24,
  stencil_bit: 8,
  layer_type: 0,
});
const errorInvalidPixelFormat = 2000;

// The declared virtual-display capability profile GetDeviceCaps reports. One
// deterministic screen, independent of any host display, keyed by the Win32
// index constant.
export const deviceCap = Object.freeze({
  2: 1, // TECHNOLOGY: DT_RASDISPLAY
  4: 508, // HORZSIZE mm
  6: 285, // VERTSIZE mm
  8: 1920, // HORZRES
  10: 1080, // VERTRES
  12: 32, // BITSPIXEL
  14: 1, // PLANES
  88: 96, // LOGPIXELSX
  90: 96, // LOGPIXELSY
  104: 1, // SIZEPALETTE is not paletted at 32bpp
  38: 0, // NUMBRUSHES (device brushes) not enumerated
});

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
  "C": [0x3c, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3c, 0x00],
  "D": [0x78, 0x6c, 0x66, 0x66, 0x66, 0x6c, 0x78, 0x00],
  "E": [0x7e, 0x60, 0x60, 0x7c, 0x60, 0x60, 0x7e, 0x00],
  "F": [0x7e, 0x60, 0x60, 0x7c, 0x60, 0x60, 0x60, 0x00],
  "G": [0x3c, 0x66, 0x60, 0x6e, 0x66, 0x66, 0x3c, 0x00],
  "H": [0x66, 0x66, 0x66, 0x7e, 0x66, 0x66, 0x66, 0x00],
  "I": [0x3c, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3c, 0x00],
  "J": [0x1e, 0x0c, 0x0c, 0x0c, 0x0c, 0x6c, 0x38, 0x00],
  "K": [0x66, 0x6c, 0x78, 0x70, 0x78, 0x6c, 0x66, 0x00],
  "L": [0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7e, 0x00],
  "M": [0x63, 0x77, 0x7f, 0x6b, 0x63, 0x63, 0x63, 0x00],
  "N": [0x66, 0x76, 0x7e, 0x7e, 0x6e, 0x66, 0x66, 0x00],
  "O": [0x3c, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3c, 0x00],
  "P": [0x7c, 0x66, 0x66, 0x7c, 0x60, 0x60, 0x60, 0x00],
  "Q": [0x3c, 0x66, 0x66, 0x66, 0x66, 0x3c, 0x0e, 0x00],
  "R": [0x7c, 0x66, 0x66, 0x7c, 0x78, 0x6c, 0x66, 0x00],
  "S": [0x3c, 0x66, 0x60, 0x3c, 0x06, 0x66, 0x3c, 0x00],
  "T": [0x7e, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00],
  "U": [0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3c, 0x00],
  "V": [0x66, 0x66, 0x66, 0x66, 0x66, 0x3c, 0x18, 0x00],
  "W": [0x63, 0x63, 0x63, 0x6b, 0x7f, 0x77, 0x63, 0x00],
  "X": [0x66, 0x66, 0x3c, 0x18, 0x3c, 0x66, 0x66, 0x00],
  "Y": [0x66, 0x66, 0x66, 0x3c, 0x18, 0x18, 0x18, 0x00],
  "Z": [0x7e, 0x06, 0x0c, 0x18, 0x30, 0x60, 0x7e, 0x00],
  "0": [0x3c, 0x66, 0x6e, 0x76, 0x66, 0x66, 0x3c, 0x00],
  "1": [0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7e, 0x00],
  "2": [0x3c, 0x66, 0x06, 0x0c, 0x30, 0x60, 0x7e, 0x00],
  "3": [0x3c, 0x66, 0x06, 0x1c, 0x06, 0x66, 0x3c, 0x00],
  "4": [0x0c, 0x1c, 0x3c, 0x6c, 0x7e, 0x0c, 0x0c, 0x00],
  "5": [0x7e, 0x60, 0x7c, 0x06, 0x06, 0x66, 0x3c, 0x00],
  "6": [0x1c, 0x30, 0x60, 0x7c, 0x66, 0x66, 0x3c, 0x00],
  "7": [0x7e, 0x06, 0x0c, 0x18, 0x30, 0x30, 0x30, 0x00],
  "8": [0x3c, 0x66, 0x66, 0x3c, 0x66, 0x66, 0x3c, 0x00],
  "9": [0x3c, 0x66, 0x66, 0x3e, 0x06, 0x0c, 0x38, 0x00],
  ".": [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00],
  ",": [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30],
  ":": [0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00],
  ";": [0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x30, 0x00],
  "-": [0x00, 0x00, 0x00, 0x7e, 0x00, 0x00, 0x00, 0x00],
  "_": [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e],
  "+": [0x00, 0x18, 0x18, 0x7e, 0x18, 0x18, 0x00, 0x00],
  "=": [0x00, 0x00, 0x7e, 0x00, 0x7e, 0x00, 0x00, 0x00],
  "!": [0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x00],
  "?": [0x3c, 0x66, 0x06, 0x0c, 0x18, 0x00, 0x18, 0x00],
  "/": [0x06, 0x0c, 0x0c, 0x18, 0x30, 0x30, 0x60, 0x00],
  "\\": [0x60, 0x30, 0x30, 0x18, 0x0c, 0x0c, 0x06, 0x00],
  "(": [0x0c, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0c, 0x00],
  ")": [0x30, 0x18, 0x0c, 0x0c, 0x0c, 0x18, 0x30, 0x00],
  "&": [0x38, 0x6c, 0x6c, 0x38, 0x6d, 0x66, 0x3b, 0x00],
  "*": [0x00, 0x66, 0x3c, 0xff, 0x3c, 0x66, 0x00, 0x00],
  "'": [0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00],
  "\"": [0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
  "@": [0x3c, 0x66, 0x6e, 0x6a, 0x6e, 0x60, 0x3c, 0x00],
});
const glyphWidth = 8;
const glyphHeight = 8;

// --- the desktop compositor palette and metric ----------------------------
// The system colors the window/control paint path uses, and the frame metric
// the compositor and its fixture both read so a control's painted position is
// the geometry the window manager stored, offset by the caption band. No color
// or metric is keyed on a title — a dialog is a dialog, a button is a button.
export const systemColor = Object.freeze({
  desktop: rgb(58, 110, 165), // the cleared background behind every top-level window
  btnFace: rgb(192, 192, 192), // COLOR_BTNFACE: the dialog client and button face
  btnHighlight: rgb(255, 255, 255), // the light bevel edge (top/left of a raised control)
  btnShadow: rgb(128, 128, 128), // the dark bevel edge (bottom/right of a raised control)
  btnText: rgb(0, 0, 0), // control caption ink
  frame: rgb(0, 0, 0), // the window's outer border
  captionActive: rgb(0, 0, 128), // the active title bar band
  captionText: rgb(255, 255, 255), // the title text on the caption band
  windowWhite: rgb(255, 255, 255), // an EDIT control's sunken client
});

export const compositorMetric = Object.freeze({
  caption_height: 14, // the title-bar band height, and the client-area top offset
  frame_border: 1, // the outer window border thickness
  desktop_width: 640, // the deterministic virtual desktop the present path reads
  desktop_height: 480,
});

// The ICC profile GetICMProfile reports for the virtual display. No host
// color device exists, so every DC shares this one declared sRGB path.
export const icmProfilePath = "C:\\Windows\\System32\\spool\\drivers\\color\\sRGB Color Space Profile.icm";

// Reduce a Win32 class name to the generic control kind the compositor paints.
// Case-insensitive, atom-name aware; an unrecognized class paints as static
// text, exactly as an unstyled child window shows only its caption.
function controlKindOf(className) {
  const name = String(className ?? "").toLowerCase();
  if (name.startsWith("button")) return "button";
  if (name.startsWith("edit")) return "edit";
  if (name.startsWith("static")) return "static";
  return "static";
}

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
    const bitmap = { kind: "bitmap", surface, width: surface.width, height: surface.height, bits_pixel: 32 };
    dcByHandle.set(handle, {
      handle,
      surface,
      bitmap,
      pen: stockObjectByHandle.get(stockHandle.BLACK_PEN),
      brush: stockObjectByHandle.get(stockHandle.WHITE_BRUSH),
      font: stockObjectByHandle.get(stockHandle.SYSTEM_FONT),
      text_color: rgb(0, 0, 0),
      bk_color: rgb(255, 255, 255),
      bk_mode: backgroundMode.OPAQUE,
      cur_x: 0,
      cur_y: 0,
      rop2: rasterOp2.R2_COPYPEN,
      map_mode: 1,
      pixel_format_index: 0,
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
    const previousByKind = { pen: dc.pen, brush: dc.brush, font: dc.font, bitmap: dc.bitmap };
    const previous = previousByKind[object.kind];
    if (previous === undefined) return 0;
    dc[object.kind] = object;
    if (object.kind === "bitmap" && object.surface !== undefined) dc.surface = object.surface;
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

  // PatBlt paints a w x h region from (x,y) with the current brush for the
  // pattern-copy op, or solid black/white for the degenerate ops. A negative
  // extent normalizes like the Win32 signed-rect contract.
  function patBlt(dcHandle, x, y, width, height, rop) {
    const dc = requireDC(dcHandle);
    const left = width < 0 ? x + width : x;
    const top = height < 0 ? y + height : y;
    const rect = { left, top, right: left + Math.abs(width), bottom: top + Math.abs(height) };
    let color;
    if (rop === rasterOp.BLACKNESS) color = rgb(0, 0, 0);
    else if (rop === rasterOp.WHITENESS) color = rgb(255, 255, 255);
    else if (rop === rasterOp.PATCOPY) color = dc.brush.is_null ? null : dc.brush.color;
    else return 0; // an unrealized ternary op is refused, never faked
    if (color === null) return 1;
    for (let py = Math.max(0, rect.top); py < Math.min(dc.surface.height, rect.bottom); py += 1) {
      for (let px = Math.max(0, rect.left); px < Math.min(dc.surface.width, rect.right); px += 1) setPixel(dc, px, py, color);
    }
    return 1;
  }

  // GetDeviceCaps reports the declared virtual-display profile. The value is
  // display-global, so it does not depend on the specific DC.
  function getDeviceCaps(dcHandle, index) {
    return deviceCap[index] ?? 0;
  }

  function setRop2(dcHandle, mode) {
    const dc = requireDC(dcHandle);
    const previous = dc.rop2;
    dc.rop2 = mode >>> 0;
    return previous;
  }

  function getRop2(dcHandle) {
    return requireDC(dcHandle).rop2;
  }

  function setMapMode(dcHandle, mode) {
    const dc = requireDC(dcHandle);
    const previous = dc.map_mode ?? 1;
    dc.map_mode = mode | 0;
    return previous;
  }

  function createRegion(rect) {
    return allocateObject({ kind: "region", ...(rect ?? { left: 0, top: 0, right: 0, bottom: 0 }) });
  }

  // Stock 8x8 face: one Latin family, no TrueType tables. Enum reports success
  // when a callback is present (the interpreter may re-enter it); glyph indices
  // are the BMP code points; outline/font-table queries return GDI_ERROR.
  const gdiError = 0xffffffff;
  function enumFontFamily(hasCallback) {
    if (!hasCallback) {
      setLastError(87);
      return 0;
    }
    setLastError(0);
    return 1;
  }
  function getTextCharsetInfo() {
    return 0; // ANSI_CHARSET
  }
  function addFontResource(hasName) {
    if (!hasName) {
      setLastError(87);
      return 0;
    }
    setLastError(0);
    return 1;
  }
  function getFontData() {
    return gdiError;
  }
  function getOutlineTextMetrics() {
    return 0;
  }
  function getGlyphOutline(hasMetrics, format) {
    if (!hasMetrics) {
      setLastError(87);
      return gdiError;
    }
    return (format >>> 0) === 0 ? 0 : gdiError;
  }
  function getGlyphIndices(hasBuffer, count) {
    if (!hasBuffer || (count | 0) < 0) {
      setLastError(87);
      return gdiError;
    }
    return count | 0;
  }
  function setDibColorTable(dcHandle, start, entry) {
    const dc = dcByHandle.get(dcHandle >>> 0);
    if (dc === undefined) {
      setLastError(6);
      return 0;
    }
    const table = dc.bitmap.color_table ?? [];
    for (let index = 0; index < entry.length; index += 1) table[(start + index) >>> 0] = entry[index];
    dc.bitmap.color_table = table;
    return entry.length;
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

  // --- the desktop compositor ----------------------------------------------
  // Paint the window manager's paint log into a fresh RGBA surface using the
  // subsystem's own primitives (fillRect, TextOut), then read the surface out.
  // The desktop clears, then each logged snapshot paints in order (back-to-front
  // by paint time, so a frame precedes the controls shown after it): a top-level
  // snapshot as a window frame + caption, a child snapshot as a control by its
  // class — STATIC as caption text, BUTTON as a beveled face, EDIT as a sunken
  // white client. A snapshot persists after the window's destruction, so the
  // painted pixels remain exactly as a real screen keeps them. No branch keys on
  // a window title; a control is painted by its class. Returns { rgba, width,
  // height, window_painted }.
  function compositeDesktop(snapshot, widthArg, heightArg) {
    const width = widthArg ?? compositorMetric.desktop_width;
    const height = heightArg ?? compositorMetric.desktop_height;
    const dcHandle = createDC(width, height);
    const brushCache = new Map();
    const brushFor = (color) => {
      const key = color >>> 0;
      let handle = brushCache.get(key);
      if (handle === undefined) {
        handle = createSolidBrush(key);
        brushCache.set(key, handle);
      }
      return handle;
    };
    const fillColor = (left, top, right, bottom, color) => {
      fillRect(dcHandle, { left: left | 0, top: top | 0, right: right | 0, bottom: bottom | 0 }, brushFor(color));
    };
    const drawText = (x, y, text, color) => {
      setTextColor(dcHandle, color);
      setBkMode(dcHandle, backgroundMode.TRANSPARENT);
      textOut(dcHandle, x | 0, y | 0, text);
    };
    const strokeRect = (left, top, right, bottom, color) => {
      fillColor(left, top, right, top + 1, color);
      fillColor(left, bottom - 1, right, bottom, color);
      fillColor(left, top, left + 1, bottom, color);
      fillColor(right - 1, top, right, bottom, color);
    };

    const frameRect = [];
    const paintFrame = (win) => {
      const left = win.x | 0;
      const top = win.y | 0;
      const right = left + (win.width | 0);
      const bottom = top + (win.height | 0);
      frameRect.push({ handle: win.handle >>> 0, text: typeof win.text === "string" ? win.text : "", left, top, right, bottom });
      fillColor(left, top, right, bottom, systemColor.btnFace); // COLOR_BTNFACE client
      strokeRect(left, top, right, bottom, systemColor.frame); // outer border
      const capBottom = Math.min(bottom, top + compositorMetric.caption_height);
      fillColor(left + 1, top + 1, right - 1, capBottom, systemColor.captionActive);
      if (typeof win.text === "string" && win.text.length > 0) drawText(left + 3, top + 3, win.text, systemColor.captionText);
    };

    const controlRect = [];
    const paintControl = (originX, originY, control) => {
      // Control geometry is parent-client-relative; the client origin (passed in)
      // sits below the parent's caption band.
      const left = originX + (control.x | 0);
      const top = originY + (control.y | 0);
      const right = left + (control.width | 0);
      const bottom = top + (control.height | 0);
      const text = typeof control.text === "string" ? control.text : "";
      const kind = controlKindOf(control.class_name);
      // Record the painted screen rectangle so a fixture can assert control
      // placement (non-overlap, size) directly, without re-deriving it from the
      // pixel buffer. The rect is the geometry the compositor actually painted.
      controlRect.push({ handle: control.handle >>> 0, kind, text, left, top, right, bottom });
      if (kind === "button") {
        fillColor(left, top, right, bottom, systemColor.btnFace);
        fillColor(left, top, right, top + 1, systemColor.btnHighlight);
        fillColor(left, top, left + 1, bottom, systemColor.btnHighlight);
        fillColor(left, bottom - 1, right, bottom, systemColor.btnShadow);
        fillColor(right - 1, top, right, bottom, systemColor.btnShadow);
        const textWidth = text.length * glyphWidth;
        const tx = left + Math.max(1, Math.floor(((right - left) - textWidth) / 2));
        const ty = top + Math.max(1, Math.floor(((bottom - top) - glyphHeight) / 2));
        if (text.length > 0) drawText(tx, ty, text, systemColor.btnText);
      } else if (kind === "edit") {
        fillColor(left, top, right, bottom, systemColor.windowWhite);
        fillColor(left, top, right, top + 1, systemColor.btnShadow);
        fillColor(left, top, left + 1, bottom, systemColor.btnShadow);
        fillColor(left, bottom - 1, right, bottom, systemColor.btnHighlight);
        fillColor(right - 1, top, right, bottom, systemColor.btnHighlight);
        if (text.length > 0) drawText(left + 2, top + 2, text, systemColor.btnText);
      } else if (text.length > 0) {
        drawText(left + 1, top + 1, text, systemColor.btnText); // STATIC caption
      }
    };

    fillColor(0, 0, width, height, systemColor.desktop);
    const source = Array.isArray(snapshot) ? snapshot : [];
    // The frame origin for each handle, so a child snapshot resolves its parent's
    // screen position even after the parent window is destroyed. The last logged
    // geometry for a handle wins (a moved/resized frame repaints where it ended).
    const originByHandle = new Map();
    for (const entry of source) originByHandle.set(entry.handle >>> 0, entry);
    let framePainted = 0;
    for (const entry of source) {
      if ((entry.width | 0) <= 0 || (entry.height | 0) <= 0) continue;
      if ((entry.x | 0) <= -0x40000000 || (entry.y | 0) <= -0x40000000) continue; // an off-screen CW_USEDEFAULT window
      if ((entry.parent >>> 0) === 0) {
        paintFrame(entry);
        framePainted += 1;
        continue;
      }
      // A child whose parent snapshot is present uses the parent client origin
      // (below the caption band); an orphan control (its parent was never shown)
      // paints at its own logged coordinate, so a control the runtime created is
      // never silently dropped.
      const parent = originByHandle.get(entry.parent >>> 0);
      const originX = parent === undefined ? 0 : (parent.x | 0);
      const originY = parent === undefined ? 0 : (parent.y | 0) + compositorMetric.caption_height;
      paintControl(originX, originY, entry);
    }

    const dc = requireDC(dcHandle);
    const rgba = new Uint8Array(dc.surface.pixel.length);
    rgba.set(dc.surface.pixel);
    deleteDC(dcHandle);
    return { rgba, width, height, window_painted: framePainted, frame_rect: frameRect, control_rect: controlRect };
  }

  // --- palette -------------------------------------------------------------
  // A logical palette is an ordered color table; a palettized (8-bit) title
  // draws through an index into it. The palette object holds the entry list,
  // SelectPalette binds it to a DC, and GetNearestPaletteIndex resolves a
  // COLORREF to the closest entry by squared distance.
  function createPalette(entry) {
    return allocateObject({ kind: "palette", entry: entry.map((value) => [value[0] & 0xff, value[1] & 0xff, value[2] & 0xff]) });
  }
  function selectPalette(dcHandle, paletteHandle) {
    const dc = requireDC(dcHandle);
    const palette = lookupObject(paletteHandle);
    if (palette === null || palette.kind !== "palette") {
      setLastError(0x57);
      return 0;
    }
    const previous = dc.palette;
    dc.palette = palette;
    return previous === undefined ? 0 : previousHandleOf(previous);
  }
  function realizePalette(dcHandle) {
    const dc = requireDC(dcHandle);
    return dc.palette === undefined || dc.palette.entry === undefined ? 0 : dc.palette.entry.length;
  }
  function getNearestPaletteIndex(paletteHandle, colorRef) {
    const palette = lookupObject(paletteHandle);
    if (palette === null || palette.kind !== "palette" || palette.entry === undefined || palette.entry.length === 0) {
      setLastError(0x57);
      return 0;
    }
    const target = [colorRed(colorRef), colorGreen(colorRef), colorBlue(colorRef)];
    let bestIndex = 0;
    let bestDistance = Infinity;
    for (let index = 0; index < palette.entry.length; index += 1) {
      const entry = palette.entry[index];
      const distance = (entry[0] - target[0]) ** 2 + (entry[1] - target[1]) ** 2 + (entry[2] - target[2]) ** 2;
      if (distance < bestDistance) {
        bestDistance = distance;
        bestIndex = index;
      }
    }
    return bestIndex;
  }
  function paletteEntry(paletteHandle, index) {
    const palette = lookupObject(paletteHandle);
    if (palette === null || palette.kind !== "palette" || palette.entry === undefined) return null;
    return palette.entry[index] ?? null;
  }

  return {
    getLastError: () => lastError,
    setLastError,
    createDC,
    createDisplayDC: () => createDC(deviceCap[8], deviceCap[10]),
    createCompatibleDC: (sourceHandle) => {
      if (sourceHandle === undefined || sourceHandle === 0) return createDC(1, 1);
      const source = requireDC(sourceHandle);
      return createDC(source.surface.width, source.surface.height);
    },
    createBitmap: (width, height, planes, bitCount, bitsAddress, readByte) => {
      if (planes !== 1 || (bitCount !== 1 && bitCount !== 24 && bitCount !== 32) || width <= 0 || height <= 0) {
        setLastError(87);
        return 0;
      }
      const surface = makeSurface(width, height);
      if (bitsAddress !== 0 && typeof readByte === "function") {
        const stride = ((width * bitCount + 31) >> 5) << 2;
        for (let y = 0; y < height; y += 1) {
          const row = bitsAddress + y * stride;
          for (let x = 0; x < width; x += 1) {
            const dest = (y * width + x) * 4;
            if (bitCount === 32) {
              surface.pixel[dest] = readByte(row + x * 4 + 2);
              surface.pixel[dest + 1] = readByte(row + x * 4 + 1);
              surface.pixel[dest + 2] = readByte(row + x * 4 + 0);
              surface.pixel[dest + 3] = 255;
            } else if (bitCount === 24) {
              surface.pixel[dest] = readByte(row + x * 3 + 2);
              surface.pixel[dest + 1] = readByte(row + x * 3 + 1);
              surface.pixel[dest + 2] = readByte(row + x * 3 + 0);
              surface.pixel[dest + 3] = 255;
            } else {
              const byte = readByte(row + (x >> 3));
              const bit = (byte >> (7 - (x & 7))) & 1;
              const tone = bit === 0 ? 0 : 255;
              surface.pixel[dest] = tone;
              surface.pixel[dest + 1] = tone;
              surface.pixel[dest + 2] = tone;
              surface.pixel[dest + 3] = 255;
            }
          }
        }
      }
      return allocateObject({ kind: "bitmap", surface, width, height, bits_pixel: bitCount });
    },
    createCompatibleBitmap: (dcHandle, width, height) => {
      const dc = dcHandle === 0 ? null : requireDC(dcHandle);
      const surface = makeSurface(Math.max(width | 0, 1), Math.max(height | 0, 1));
      return allocateObject({ kind: "bitmap", surface, width: surface.width, height: surface.height, bits_pixel: 32, dc });
    },
    createDibSection: ({ width, height, bits_pixel, top_down, bits_address, stride }) => {
      const surface = makeSurface(width, height);
      return allocateObject({
        kind: "bitmap",
        surface,
        width,
        height,
        bits_pixel,
        top_down: top_down === true,
        bits_address: (bits_address ?? 0) >>> 0,
        stride: stride >>> 0,
      });
    },
    currentBitmap: (dcHandle) => {
      const dc = dcByHandle.get(dcHandle >>> 0);
      return dc === undefined ? null : dc.bitmap;
    },
    isDc: (handle) => (handle >>> 0) === 0 || dcByHandle.has(handle >>> 0),
    choosePixelFormat(hdc) {
      if ((hdc >>> 0) === 0 || !dcByHandle.has(hdc >>> 0)) {
        setLastError(6);
        return 0;
      }
      return declaredPixelFormat.index;
    },
    setPixelFormat(hdc, index) {
      const dc = dcByHandle.get(hdc >>> 0);
      if ((hdc >>> 0) === 0 || dc === undefined) {
        setLastError(6);
        return 0;
      }
      if ((index >>> 0) !== declaredPixelFormat.index) {
        setLastError(errorInvalidPixelFormat);
        return 0;
      }
      if (dc.pixel_format_index !== 0) {
        setLastError(errorInvalidPixelFormat);
        return 0;
      }
      dc.pixel_format_index = declaredPixelFormat.index;
      return 1;
    },
    getPixelFormat(hdc) {
      const dc = dcByHandle.get(hdc >>> 0);
      if ((hdc >>> 0) === 0 || dc === undefined) {
        setLastError(6);
        return 0;
      }
      return dc.pixel_format_index;
    },
    describePixelFormat(hdc, index) {
      if ((hdc >>> 0) === 0 || !dcByHandle.has(hdc >>> 0)) {
        setLastError(6);
        return 0;
      }
      if ((index >>> 0) === 0) return declaredPixelFormat.index;
      if ((index >>> 0) !== declaredPixelFormat.index) {
        setLastError(errorInvalidPixelFormat);
        return 0;
      }
      return declaredPixelFormat.index;
    },
    // SwapBuffers is the GDI gate: a live DC that already holds the declared
    // double-buffered OpenGL format. The color-buffer snapshot lives on the GL
    // subsystem (guest.gl.swapBuffers); this method never looks at a title.
    swapBuffers(hdc) {
      const dc = dcByHandle.get(hdc >>> 0);
      if ((hdc >>> 0) === 0 || dc === undefined) {
        setLastError(6);
        return 0;
      }
      if (dc.pixel_format_index !== declaredPixelFormat.index) {
        setLastError(errorInvalidPixelFormat);
        return 0;
      }
      return 1;
    },
    lookupBitmap: (handle) => {
      const object = lookupObject(handle);
      return object !== null && object.kind === "bitmap" ? object : null;
    },
    copyBitmap: (handle) => {
      const object = lookupObject(handle);
      if (object === null || object.kind !== "bitmap") {
        setLastError(6);
        return 0;
      }
      const surface = makeSurface(object.width, object.height);
      surface.pixel.set(object.surface.pixel);
      return allocateObject({
        kind: "bitmap",
        surface,
        width: object.width,
        height: object.height,
        bits_pixel: object.bits_pixel,
      });
    },
    releaseDibBits: (handle) => {
      const object = lookupObject(handle);
      if (object === null || object.kind !== "bitmap" || (object.bits_address ?? 0) === 0) return 0;
      const address = object.bits_address >>> 0;
      object.bits_address = 0;
      return address;
    },
    getCurrentObject: (dcHandle, kind) => {
      const dc = requireDC(dcHandle);
      if (kind === 1) return previousHandleOf(dc.pen);
      if (kind === 2) return previousHandleOf(dc.brush);
      if (kind === 6) return previousHandleOf(dc.font);
      if (kind === 7) return previousHandleOf(dc.bitmap);
      return 0;
    },
    getObject: (objectHandle) => {
      const object = lookupObject(objectHandle);
      if (object === null || object.kind !== "bitmap") return null;
      return { type: 0, width: object.width, height: object.height, width_bytes: object.width * 4, planes: 1, bits_pixel: object.bits_pixel };
    },
    getDIBits: (dcHandle, bitmapHandle, start, lineCount, bitsPointer, writeBits) => {
      const object = lookupObject(bitmapHandle);
      if (object === null || object.kind !== "bitmap") return 0;
      if (!writeBits) return object.height;
      const startLine = start >>> 0;
      const count = Math.min(lineCount >>> 0, Math.max(object.height - startLine, 0));
      if (bitsPointer !== 0 && typeof writeBits === "function") writeBits(object, startLine, count);
      return count;
    },
    deleteDC,
    getStockObject,
    createSolidBrush,
    createPen,
    deleteObject,
    selectObject,
    fillRect,
    patBlt,
    getDeviceCaps,
    setRop2,
    getRop2,
    setMapMode,
    createRegion,
    enumFontFamily,
    getTextCharsetInfo,
    addFontResource,
    getFontData,
    getOutlineTextMetrics,
    getGlyphOutline,
    getGlyphIndices,
    setDibColorTable,
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
    createPalette,
    selectPalette,
    realizePalette,
    getNearestPaletteIndex,
    paletteEntry,
    surfacePixel,
    surfaceInfo,
    compositeDesktop,
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

  function isDisplayName(value) {
    const name = String(value ?? "").toLowerCase();
    return name === "" || name === "display" || name === "\\\\.\\display1";
  }
  function createDisplayDeviceContext(guest, driverPointer, devicePointer, isWide) {
    const read = (pointer) => pointer === 0 ? "" : (isWide ? guest.readWideString(pointer) : guest.readAnsiString(pointer));
    const driver = read(driverPointer);
    const device = read(devicePointer);
    // Win32 accepts CreateDC("DISPLAY", NULL, …), CreateDC(NULL, "\\.\DISPLAY1", …),
    // and CreateDC("\\.\DISPLAY1", NULL, …). A printer or unknown device is refused.
    if (!isDisplayName(driver) || !isDisplayName(device)) {
      guest.setLastError(87);
      guest.gdi.setLastError(87);
      return 0;
    }
    return guest.gdi.createDisplayDC();
  }
  define("CreateCompatibleDC", 1, (guest, argument) => guest.gdi.createCompatibleDC(argument[0]));
  define("CreateDCW", 4, (guest, argument) => createDisplayDeviceContext(guest, argument[0], argument[1], true));
  define("CreateDCA", 4, (guest, argument) => createDisplayDeviceContext(guest, argument[0], argument[1], false));
  define("DeleteDC", 1, (guest, argument) => guest.gdi.deleteDC(argument[0]));
  define("GetStockObject", 1, (guest, argument) => guest.gdi.getStockObject(argument[0]));
  define("CreateSolidBrush", 1, (guest, argument) => guest.gdi.createSolidBrush(argument[0]));
  define("CreatePen", 3, (guest, argument) => guest.gdi.createPen(argument[0], argument[1], argument[2]));
  define("DeleteObject", 1, (guest, argument) => {
    const bits = guest.gdi.releaseDibBits(argument[0]);
    if (bits !== 0) guest.virtualFree(bits, 0, 0x8000);
    return guest.gdi.deleteObject(argument[0]);
  });
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
  define("SetPixel", 4, (guest, argument) => {
    syncDibFromGuest(guest, guest.gdi.currentBitmap(argument[0]));
    const result = guest.gdi.setPixel(argument[0], argument[1], argument[2], argument[3]);
    syncDibToGuest(guest, guest.gdi.currentBitmap(argument[0]));
    return result;
  });
  define("GetPixel", 3, (guest, argument) => {
    syncDibFromGuest(guest, guest.gdi.currentBitmap(argument[0]));
    return guest.gdi.getPixel(argument[0], argument[1], argument[2]);
  });
  define("BitBlt", 9, (guest, argument) => {
    syncDibFromGuest(guest, guest.gdi.currentBitmap(argument[0]));
    syncDibFromGuest(guest, guest.gdi.currentBitmap(argument[5]));
    const result = guest.gdi.bitBlt(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8]);
    syncDibToGuest(guest, guest.gdi.currentBitmap(argument[0]));
    return result;
  });
  define("StretchBlt", 11, (guest, argument) => {
    syncDibFromGuest(guest, guest.gdi.currentBitmap(argument[0]));
    syncDibFromGuest(guest, guest.gdi.currentBitmap(argument[5]));
    const result = guest.gdi.stretchBlt(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8], argument[9], argument[10]);
    syncDibToGuest(guest, guest.gdi.currentBitmap(argument[0]));
    return result;
  });
  // CreatePalette reads a LOGPALETTE: palVersion (WORD), palNumEntries (WORD),
  // then one PALETTEENTRY (peRed, peGreen, peBlue, peFlags) per entry.
  define("CreatePalette", 1, (guest, argument) => {
    const base = argument[0];
    const count = guest.memory.readMemory(base + 2, 2);
    const entry = [];
    for (let index = 0; index < count; index += 1) {
      const record = base + 4 + index * 4;
      entry.push([guest.memory.readMemory(record, 1), guest.memory.readMemory(record + 1, 1), guest.memory.readMemory(record + 2, 1)]);
    }
    return guest.gdi.createPalette(entry);
  });
  define("SelectPalette", 3, (guest, argument) => guest.gdi.selectPalette(argument[0], argument[1]));
  define("RealizePalette", 1, (guest, argument) => guest.gdi.realizePalette(argument[0]));
  define("GetNearestPaletteIndex", 2, (guest, argument) => guest.gdi.getNearestPaletteIndex(argument[0], argument[1]));

  // --- rect fill, pattern blit, raster op, device caps (BPTK-012) ---------------
  // FillRect reads the RECT (left, top, right, bottom dword) from guest memory.
  define("FillRect", 3, (guest, argument) => {
    const base = argument[1];
    const rect = {
      left: guest.memory.readMemory(base + 0, 4) | 0,
      top: guest.memory.readMemory(base + 4, 4) | 0,
      right: guest.memory.readMemory(base + 8, 4) | 0,
      bottom: guest.memory.readMemory(base + 12, 4) | 0,
    };
    return guest.gdi.fillRect(argument[0], rect, argument[2]);
  });
  define("PatBlt", 6, (guest, argument) => guest.gdi.patBlt(argument[0], argument[1] | 0, argument[2] | 0, argument[3] | 0, argument[4] | 0, argument[5] >>> 0));
  define("GetDeviceCaps", 2, (guest, argument) => guest.gdi.getDeviceCaps(argument[0], argument[1] | 0));
  function getIcmProfile(guest, argument, isWide) {
    const sizeAddress = argument[1] >>> 0;
    const dest = argument[2] >>> 0;
    if (sizeAddress === 0) {
      guest.setLastError(87);
      guest.gdi.setLastError(87);
      return 0;
    }
    if (!guest.gdi.isDc(argument[0])) {
      guest.setLastError(6);
      guest.gdi.setLastError(6);
      return 0;
    }
    const need = icmProfilePath.length + 1;
    const have = guest.memory.readMemory(sizeAddress, 4) >>> 0;
    guest.memory.writeMemory(sizeAddress, 4, need);
    if (dest === 0 || have < need) {
      guest.setLastError(122);
      guest.gdi.setLastError(122);
      return 0;
    }
    if (isWide) guest.writeWideString(dest, icmProfilePath, have);
    else guest.writeAnsiString(dest, icmProfilePath, have);
    return 1;
  }
  define("GetICMProfileW", 3, (guest, argument) => getIcmProfile(guest, argument, true));
  define("GetICMProfileA", 3, (guest, argument) => getIcmProfile(guest, argument, false));
  define("SetROP2", 2, (guest, argument) => guest.gdi.setRop2(argument[0], argument[1]));
  define("GetROP2", 1, (guest, argument) => guest.gdi.getRop2(argument[0]));
  define("CreateBitmap", 5, (guest, argument) => {
    const handle = guest.gdi.createBitmap(
      argument[0] | 0,
      argument[1] | 0,
      argument[2] >>> 0,
      argument[3] >>> 0,
      argument[4] >>> 0,
      (address) => guest.memory.readMemory(address, 1),
    );
    if (handle === 0) guest.setLastError(guest.gdi.getLastError());
    return handle;
  });
  define("CreateCompatibleBitmap", 3, (guest, argument) => guest.gdi.createCompatibleBitmap(argument[0], argument[1], argument[2]));
  function dibStride(width, bitsPixel) {
    return ((width * bitsPixel + 31) >> 5) << 2;
  }
  function syncDibFromGuest(guest, bitmap) {
    if (bitmap === null || (bitmap.bits_address ?? 0) === 0) return;
    const { width, height, stride, top_down, bits_pixel, bits_address, surface } = bitmap;
    for (let y = 0; y < height; y += 1) {
      const guestY = top_down ? y : height - 1 - y;
      const row = bits_address + guestY * stride;
      for (let x = 0; x < width; x += 1) {
        const dest = (y * width + x) * 4;
        if (bits_pixel === 32) {
          surface.pixel[dest] = guest.memory.readMemory(row + x * 4 + 2, 1);
          surface.pixel[dest + 1] = guest.memory.readMemory(row + x * 4 + 1, 1);
          surface.pixel[dest + 2] = guest.memory.readMemory(row + x * 4 + 0, 1);
          surface.pixel[dest + 3] = 255;
        } else if (bits_pixel === 24) {
          surface.pixel[dest] = guest.memory.readMemory(row + x * 3 + 2, 1);
          surface.pixel[dest + 1] = guest.memory.readMemory(row + x * 3 + 1, 1);
          surface.pixel[dest + 2] = guest.memory.readMemory(row + x * 3 + 0, 1);
          surface.pixel[dest + 3] = 255;
        }
      }
    }
  }
  function syncDibToGuest(guest, bitmap) {
    if (bitmap === null || (bitmap.bits_address ?? 0) === 0) return;
    const { width, height, stride, top_down, bits_pixel, bits_address, surface } = bitmap;
    for (let y = 0; y < height; y += 1) {
      const guestY = top_down ? y : height - 1 - y;
      const row = bits_address + guestY * stride;
      for (let x = 0; x < width; x += 1) {
        const src = (y * width + x) * 4;
        if (bits_pixel === 32) {
          guest.memory.writeMemory(row + x * 4 + 0, 1, surface.pixel[src + 2]);
          guest.memory.writeMemory(row + x * 4 + 1, 1, surface.pixel[src + 1]);
          guest.memory.writeMemory(row + x * 4 + 2, 1, surface.pixel[src + 0]);
          guest.memory.writeMemory(row + x * 4 + 3, 1, 0);
        } else if (bits_pixel === 24) {
          guest.memory.writeMemory(row + x * 3 + 0, 1, surface.pixel[src + 2]);
          guest.memory.writeMemory(row + x * 3 + 1, 1, surface.pixel[src + 1]);
          guest.memory.writeMemory(row + x * 3 + 2, 1, surface.pixel[src + 0]);
        }
      }
    }
  }
  define("CreateDIBSection", 6, (guest, argument) => {
    const info = argument[1] >>> 0;
    const usage = argument[2] >>> 0;
    const bitsOut = argument[3] >>> 0;
    const section = argument[4] >>> 0;
    if (info === 0 || usage !== 0) {
      guest.setLastError(87);
      guest.gdi.setLastError(87);
      return 0;
    }
    if (section !== 0) {
      guest.setLastError(50);
      guest.gdi.setLastError(50);
      return 0;
    }
    const headerSize = guest.memory.readMemory(info, 4) >>> 0;
    if (headerSize < 40) {
      guest.setLastError(87);
      guest.gdi.setLastError(87);
      return 0;
    }
    const width = guest.memory.readMemory(info + 4, 4) | 0;
    const heightRaw = guest.memory.readMemory(info + 8, 4) | 0;
    const planes = guest.memory.readMemory(info + 12, 2);
    const bitCount = guest.memory.readMemory(info + 14, 2);
    const compression = guest.memory.readMemory(info + 16, 4) >>> 0;
    if (width <= 0 || heightRaw === 0 || planes !== 1 || (bitCount !== 32 && bitCount !== 24) || (compression !== 0 && compression !== 3)) {
      guest.setLastError(87);
      guest.gdi.setLastError(87);
      return 0;
    }
    const height = Math.abs(heightRaw);
    const stride = dibStride(width, bitCount);
    const bits = guest.virtualAllocate(0, stride * height, 0x3000, 0x04);
    if (bits === 0) {
      guest.setLastError(14);
      guest.gdi.setLastError(14);
      return 0;
    }
    if (bitsOut !== 0) guest.memory.writeMemory(bitsOut, 4, bits);
    return guest.gdi.createDibSection({
      width,
      height,
      bits_pixel: bitCount,
      top_down: heightRaw < 0,
      bits_address: bits,
      stride,
    });
  });
  define("GetCurrentObject", 2, (guest, argument) => guest.gdi.getCurrentObject(argument[0], argument[1]));
  define("GetObjectA", 3, (guest, argument) => {
    const info = guest.gdi.getObject(argument[0]);
    if (info === null) return 0;
    const needed = 24;
    if (argument[1] === 0 || argument[2] === 0) return needed;
    const count = Math.min(argument[1] >>> 0, needed);
    const buffer = Buffer.alloc(needed);
    buffer.writeInt32LE(info.type, 0);
    buffer.writeInt32LE(info.width, 4);
    buffer.writeInt32LE(info.height, 8);
    buffer.writeInt32LE(info.width_bytes, 12);
    buffer.writeUInt16LE(info.planes, 16);
    buffer.writeUInt16LE(info.bits_pixel, 18);
    guest.memory.writeBlock(argument[2], buffer.subarray(0, count));
    return count;
  });
  define("GetDIBits", 7, (guest, argument) => {
    syncDibFromGuest(guest, guest.gdi.lookupBitmap(argument[1]));
    const info = guest.gdi.getObject(argument[1]);
    if (info === null) return 0;
    if (argument[5] !== 0) {
      guest.memory.writeMemory(argument[5] + 0, 4, 40);
      guest.memory.writeMemory(argument[5] + 4, 4, info.width);
      guest.memory.writeMemory(argument[5] + 8, 4, info.height);
      guest.memory.writeMemory(argument[5] + 12, 2, 1);
      guest.memory.writeMemory(argument[5] + 14, 2, 32);
      guest.memory.writeMemory(argument[5] + 16, 4, 0);
    }
    if (argument[4] === 0) return info.height;
    return guest.gdi.getDIBits(argument[0], argument[1], argument[2], argument[3], argument[4], (bitmap, startLine, count) => {
      const width = bitmap.width;
      for (let line = 0; line < count; line += 1) {
        const srcY = bitmap.height - 1 - (startLine + line);
        const dest = argument[4] + line * width * 4;
        for (let x = 0; x < width; x += 1) {
          const offset = (srcY * width + x) * 4;
          guest.memory.writeMemory(dest + x * 4 + 0, 1, bitmap.surface.pixel[offset + 2]);
          guest.memory.writeMemory(dest + x * 4 + 1, 1, bitmap.surface.pixel[offset + 1]);
          guest.memory.writeMemory(dest + x * 4 + 2, 1, bitmap.surface.pixel[offset + 0]);
          guest.memory.writeMemory(dest + x * 4 + 3, 1, 0);
        }
      }
    });
  });
  define("ChoosePixelFormat", 2, (guest, argument) => {
    const pfd = argument[1] >>> 0;
    if (pfd === 0) {
      guest.setLastError(87);
      guest.gdi.setLastError(87);
      return 0;
    }
    const size = guest.memory.readMemory(pfd, 2);
    const version = guest.memory.readMemory(pfd + 2, 2);
    if (size < declaredPixelFormat.size_byte || version !== declaredPixelFormat.version) {
      guest.setLastError(87);
      guest.gdi.setLastError(87);
      return 0;
    }
    const format = guest.gdi.choosePixelFormat(argument[0]);
    if (format === 0) guest.setLastError(guest.gdi.getLastError());
    return format;
  });
  define("SetPixelFormat", 3, (guest, argument) => {
    const value = guest.gdi.setPixelFormat(argument[0], argument[1]);
    if (value === 0) guest.setLastError(guest.gdi.getLastError());
    return value;
  });
  define("GetPixelFormat", 1, (guest, argument) => {
    const value = guest.gdi.getPixelFormat(argument[0]);
    if (value === 0 && guest.gdi.getLastError() === 6) guest.setLastError(6);
    return value;
  });
  function writeDeclaredPixelFormat(guest, dest, nBytes) {
    const count = Math.min(nBytes >>> 0, declaredPixelFormat.size_byte);
    if (dest === 0 || count === 0) return;
    const block = Buffer.alloc(declaredPixelFormat.size_byte);
    block.writeUInt16LE(declaredPixelFormat.size_byte, 0);
    block.writeUInt16LE(declaredPixelFormat.version, 2);
    block.writeUInt32LE(declaredPixelFormat.flag, 4);
    block[8] = declaredPixelFormat.pixel_type;
    block[9] = declaredPixelFormat.color_bit;
    block[10] = declaredPixelFormat.red_bit;
    block[11] = declaredPixelFormat.red_shift;
    block[12] = declaredPixelFormat.green_bit;
    block[13] = declaredPixelFormat.green_shift;
    block[14] = declaredPixelFormat.blue_bit;
    block[15] = declaredPixelFormat.blue_shift;
    block[16] = declaredPixelFormat.alpha_bit;
    block[17] = declaredPixelFormat.alpha_shift;
    block[23] = declaredPixelFormat.depth_bit;
    block[24] = declaredPixelFormat.stencil_bit;
    block[26] = declaredPixelFormat.layer_type;
    guest.memory.writeBlock(dest, block.subarray(0, count));
  }
  define("DescribePixelFormat", 4, (guest, argument) => {
    const index = argument[1] >>> 0;
    const dest = argument[3] >>> 0;
    const maxIndex = guest.gdi.describePixelFormat(argument[0], dest === 0 ? 0 : index);
    if (maxIndex === 0) {
      guest.setLastError(guest.gdi.getLastError());
      return 0;
    }
    if (dest !== 0 && index === declaredPixelFormat.index) writeDeclaredPixelFormat(guest, dest, argument[2]);
    return maxIndex;
  });
  define("SwapBuffers", 1, (guest, argument) => {
    const value = guest.gdi.swapBuffers(argument[0]);
    if (value === 0) {
      guest.setLastError(guest.gdi.getLastError());
      return 0;
    }
    if (guest.gl !== undefined && typeof guest.gl.swapBuffers === "function") guest.gl.swapBuffers(argument[0] >>> 0);
    return 1;
  });
  define("GdiFlush", 0, () => 1);
  define("SetMapMode", 2, (guest, argument) => guest.gdi.setMapMode(argument[0], argument[1]));
  define("CreateRectRgnIndirect", 1, (guest, argument) => {
    const base = argument[0] >>> 0;
    if (base === 0) {
      guest.setLastError(87);
      guest.gdi.setLastError(87);
      return 0;
    }
    return guest.gdi.createRegion({
      left: guest.memory.readMemory(base, 4) | 0,
      top: guest.memory.readMemory(base + 4, 4) | 0,
      right: guest.memory.readMemory(base + 8, 4) | 0,
      bottom: guest.memory.readMemory(base + 12, 4) | 0,
    });
  });
  define("CreateFontIndirectW", 1, (guest, argument) => {
    if (argument[0] === 0) {
      guest.setLastError(87);
      guest.gdi.setLastError(87);
      return 0;
    }
    return guest.gdi.getStockObject(0x0d);
  });
  define("EnumFontFamiliesExW", 5, (guest, argument) => {
    const value = guest.gdi.enumFontFamily(argument[2] !== 0);
    guest.setLastError(guest.gdi.getLastError());
    return value;
  });
  define("GetTextCharsetInfo", 3, (guest, argument) => {
    const signature = argument[1] >>> 0;
    if (signature !== 0) {
      for (let offset = 0; offset < 24; offset += 4) guest.memory.writeMemory(signature + offset, 4, offset === 0 ? 1 : 0);
    }
    return guest.gdi.getTextCharsetInfo();
  });
  define("AddFontResourceExW", 3, (guest, argument) => {
    const value = guest.gdi.addFontResource(argument[0] !== 0);
    guest.setLastError(guest.gdi.getLastError());
    return value;
  });
  define("GetFontData", 5, (guest) => guest.gdi.getFontData());
  define("GetOutlineTextMetricsW", 3, (guest) => guest.gdi.getOutlineTextMetrics());
  define("GetGlyphOutlineW", 7, (guest, argument) => {
    const metrics = argument[3] >>> 0;
    const value = guest.gdi.getGlyphOutline(metrics !== 0, argument[2]);
    if (metrics !== 0) {
      guest.memory.writeMemory(metrics + 0, 4, 8);
      guest.memory.writeMemory(metrics + 4, 4, 8);
      guest.memory.writeMemory(metrics + 8, 4, 0);
      guest.memory.writeMemory(metrics + 12, 4, 8);
      guest.memory.writeMemory(metrics + 16, 2, 8);
      guest.memory.writeMemory(metrics + 18, 2, 0);
    }
    if (value === 0xffffffff) guest.setLastError(guest.gdi.getLastError());
    return value;
  });
  define("GetGlyphIndicesW", 5, (guest, argument) => {
    const source = argument[1] >>> 0;
    const count = argument[2] | 0;
    const dest = argument[3] >>> 0;
    const value = guest.gdi.getGlyphIndices(source !== 0 && dest !== 0, count);
    if ((value >>> 0) === 0xffffffff) {
      guest.setLastError(guest.gdi.getLastError());
      return value;
    }
    for (let index = 0; index < count; index += 1) {
      guest.memory.writeMemory(dest + index * 2, 2, guest.memory.readMemory(source + index * 2, 2));
    }
    return value;
  });
  define("SetDIBColorTable", 4, (guest, argument) => {
    const count = argument[2] >>> 0;
    const table = argument[3] >>> 0;
    const entry = [];
    if (table !== 0) {
      for (let index = 0; index < count; index += 1) {
        const quad = guest.memory.readMemory(table + index * 4, 4);
        entry.push({ blue: quad & 0xff, green: (quad >>> 8) & 0xff, red: (quad >>> 16) & 0xff });
      }
    }
    const value = guest.gdi.setDibColorTable(argument[0], argument[1] >>> 0, entry);
    if (value === 0) guest.setLastError(guest.gdi.getLastError());
    return value;
  });

  return table;
}

export const gdiExportTable = Object.freeze(buildGdiExportTable());
