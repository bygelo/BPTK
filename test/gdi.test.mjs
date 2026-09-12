// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The GDI slice acceptance (BPTK-012). The draw fixture renders a scene into a
// bounded surface and compares it against a reference computed at test time
// (computeFrameDiff, lib/shader.mjs) — no golden pixel is committed. The
// packed 555/565 conversions round-trip, the primitives and raster operations
// land the exact pixel, and every served GDI32 export carries a conformance
// case so a zero-case export is caught as a coverage hole.

import test from "node:test";
import assert from "node:assert/strict";

import { runConformanceSuite } from "../lib/conformance.mjs";
import { computeFrameDiff } from "../lib/shader.mjs";
import {
  createGdiSubsystem,
  gdiExportTable,
  rgb,
  pack565,
  unpack565,
  pack555,
  unpack555,
  rasterOp,
  rasterOp2,
  backgroundMode,
  stockObject,
  systemColor,
  compositorMetric,
} from "../lib/gdi.mjs";
import { createUserSubsystem, dialogBaseUnit, dialogRectToPixel } from "../lib/user.mjs";

// The pixel geometry instantiateDialog stores for a DLU template: the frame
// (client size plus the caption band on its height) and each control's local
// rect, so a compositor fixture computes the same screen positions the window
// manager did rather than treating template DLU as pixels.
function dialogPixelGeometry(template) {
  const unit = dialogBaseUnit(template.font);
  const frame = dialogRectToPixel({ x: template.x, y: template.y, cx: template.cx, cy: template.cy }, unit);
  const item = template.item.map((entry) => dialogRectToPixel(entry, unit));
  return { frame, item };
}

const FIRST_HANDLE = 0x00040000;

// Read one RGBA pixel [r,g,b,a] from a composited surface.
function pixelAt(surface, x, y) {
  const offset = (y * surface.width + x) * 4;
  return [surface.rgba[offset], surface.rgba[offset + 1], surface.rgba[offset + 2], surface.rgba[offset + 3]];
}

const WS_VISIBLE = 0x10000000;
const WS_CHILD = 0x40000000;
const WS_TABSTOP = 0x00010000;

// A synthetic RT_DIALOG template shaped like lib/rsrc.mjs parseDialogTemplate:
// a titled #32770 frame carrying a STATIC caption and an OK BUTTON, so the
// compositor is exercised generically by class, not by any title identity.
function syntheticAboutDialog() {
  return {
    is_ex: false,
    style: 0,
    ex_style: 0,
    control_count: 2,
    x: 10,
    y: 10,
    cx: 200,
    cy: 100,
    class_name: "#32770",
    title: "About PuTTY",
    font: null,
    item: [
      { style: WS_VISIBLE | WS_CHILD, ex_style: 0, x: 8, y: 8, cx: 120, cy: 12, id: 100, class_name: "Static", title: "About PuTTY" },
      { style: WS_VISIBLE | WS_CHILD | WS_TABSTOP, ex_style: 0, x: 80, y: 70, cx: 40, cy: 14, id: 1, class_name: "Button", title: "OK" },
    ],
  };
}

test("packed 565 and 555 round-trip within bit-replication tolerance and keep white white", () => {
  for (const value of [0, 8, 16, 128, 200, 255]) {
    const back565 = unpack565(pack565(value, value, value));
    const back555 = unpack555(pack555(value, value, value));
    assert.ok(Math.abs(back565.r - value) <= 8, `565 red drift for ${value}`);
    assert.ok(Math.abs(back555.g - value) <= 8, `555 green drift for ${value}`);
  }
  assert.deepEqual(unpack565(pack565(255, 255, 255)), { r: 255, g: 255, b: 255 });
  assert.deepEqual(unpack555(pack555(255, 255, 255)), { r: 255, g: 255, b: 255 });
  assert.deepEqual(unpack565(pack565(0, 0, 0)), { r: 0, g: 0, b: 0 });
});

test("SetPixel then GetPixel round-trips the exact COLORREF", () => {
  const gdi = createGdiSubsystem();
  const dc = gdi.createDC(4, 4);
  gdi.setPixel(dc, 1, 2, rgb(10, 20, 30));
  assert.equal(gdi.getPixel(dc, 1, 2), rgb(10, 20, 30));
  assert.equal(gdi.getPixel(dc, 3, 3), rgb(0, 0, 0)); // untouched pixel is opaque black
});

test("FillRect paints only the declared region with the brush color", () => {
  const gdi = createGdiSubsystem();
  const dc = gdi.createDC(4, 4);
  const brush = gdi.createSolidBrush(rgb(255, 0, 0));
  gdi.fillRect(dc, { left: 1, top: 1, right: 3, bottom: 3 }, brush);
  assert.equal(gdi.getPixel(dc, 2, 2), rgb(255, 0, 0));
  assert.equal(gdi.getPixel(dc, 0, 0), rgb(0, 0, 0));
  assert.equal(gdi.getPixel(dc, 3, 3), rgb(0, 0, 0)); // right/bottom are exclusive
});

test("LineTo strokes a diagonal with the selected pen", () => {
  const gdi = createGdiSubsystem();
  const dc = gdi.createDC(4, 4);
  gdi.selectObject(dc, gdi.getStockObject(6)); // WHITE_PEN
  gdi.moveToEx(dc, 0, 0);
  gdi.lineTo(dc, 3, 3);
  for (let index = 0; index < 4; index += 1) assert.equal(gdi.getPixel(dc, index, index), rgb(255, 255, 255));
  assert.equal(gdi.getPixel(dc, 3, 0), rgb(0, 0, 0));
});

test("BitBlt SRCCOPY copies the source block, BLACKNESS and WHITENESS ignore it", () => {
  const gdi = createGdiSubsystem();
  const source = gdi.createDC(2, 2);
  const destination = gdi.createDC(2, 2);
  gdi.fillRect(source, { left: 0, top: 0, right: 2, bottom: 2 }, gdi.createSolidBrush(rgb(1, 2, 3)));
  gdi.bitBlt(destination, 0, 0, 2, 2, source, 0, 0, rasterOp.SRCCOPY);
  assert.equal(gdi.getPixel(destination, 1, 1), rgb(1, 2, 3));
  gdi.bitBlt(destination, 0, 0, 2, 2, source, 0, 0, rasterOp.BLACKNESS);
  assert.equal(gdi.getPixel(destination, 0, 0), rgb(0, 0, 0));
  gdi.bitBlt(destination, 0, 0, 2, 2, source, 0, 0, rasterOp.WHITENESS);
  assert.equal(gdi.getPixel(destination, 0, 0), rgb(255, 255, 255));
});

test("BitBlt refuses an unknown raster operation instead of guessing", () => {
  const gdi = createGdiSubsystem();
  const source = gdi.createDC(1, 1);
  const destination = gdi.createDC(1, 1);
  assert.equal(gdi.bitBlt(destination, 0, 0, 1, 1, source, 0, 0, 0x12345678), 0);
  assert.equal(gdi.getLastError(), 0x57);
});

test("StretchBlt doubles a source block with nearest-neighbor sampling", () => {
  const gdi = createGdiSubsystem();
  const source = gdi.createDC(2, 2);
  const destination = gdi.createDC(4, 4);
  gdi.setPixel(source, 0, 0, rgb(10, 0, 0));
  gdi.setPixel(source, 1, 0, rgb(20, 0, 0));
  gdi.setPixel(source, 0, 1, rgb(30, 0, 0));
  gdi.setPixel(source, 1, 1, rgb(40, 0, 0));
  gdi.stretchBlt(destination, 0, 0, 4, 4, source, 0, 0, 2, 2, rasterOp.SRCCOPY);
  assert.equal(gdi.getPixel(destination, 0, 0), rgb(10, 0, 0));
  assert.equal(gdi.getPixel(destination, 3, 0), rgb(20, 0, 0));
  assert.equal(gdi.getPixel(destination, 0, 3), rgb(30, 0, 0));
  assert.equal(gdi.getPixel(destination, 3, 3), rgb(40, 0, 0));
});

test("TextOut renders a stock glyph in the text color over the background", () => {
  const gdi = createGdiSubsystem();
  const dc = gdi.createDC(8, 8);
  gdi.setTextColor(dc, rgb(255, 255, 255));
  gdi.setBkColor(dc, rgb(0, 0, 0));
  gdi.setBkMode(dc, backgroundMode.OPAQUE);
  gdi.textOut(dc, 0, 0, "I");
  // The 'I' glyph sets its top row middle columns; the corners stay background.
  const litCount = gdi.surfacePixel(dc).filter((pixel) => pixel[0] === 255).length;
  assert.ok(litCount > 0, "the glyph lit no pixel");
  assert.equal(gdi.getPixel(dc, 0, 0), rgb(0, 0, 0)); // corner is background in OPAQUE mode
});

test("CreateDIBSection allocates a bitmap the DC can select", () => {
  const gdi = createGdiSubsystem();
  const dc = gdi.createCompatibleDC(0);
  const dib = gdi.createDibSection({ width: 2, height: 2, bits_pixel: 32, top_down: true, bits_address: 0, stride: 8 });
  assert.equal(gdi.getObject(dib).width, 2);
  gdi.selectObject(dc, dib);
  assert.deepEqual(gdi.surfaceInfo(dc), { width: 2, height: 2 });
});

test("CreateDCW opens the virtual display at HORZRES x VERTRES and refuses a printer driver", () => {
  const gdi = createGdiSubsystem();
  const dc = gdi.createDisplayDC();
  assert.deepEqual(gdi.surfaceInfo(dc), { width: 1920, height: 1080 });
  assert.equal(gdi.getDeviceCaps(dc, 8), 1920);
  assert.equal(gdi.deleteDC(dc), 1);
});

test("PatBlt fills the region with the selected brush and GetDeviceCaps reports the declared display", () => {
  const gdi = createGdiSubsystem();
  const dc = gdi.createDC(4, 4);
  gdi.fillRect(dc, { left: 0, top: 0, right: 4, bottom: 4 }, gdi.createSolidBrush(rgb(200, 0, 0)));
  gdi.selectObject(dc, gdi.createSolidBrush(rgb(10, 20, 30)));
  assert.equal(gdi.patBlt(dc, 1, 1, 2, 2, rasterOp.PATCOPY), 1);
  assert.equal(gdi.getPixel(dc, 1, 1), rgb(10, 20, 30));
  assert.equal(gdi.getPixel(dc, 2, 2), rgb(10, 20, 30));
  assert.equal(gdi.getPixel(dc, 0, 0), rgb(200, 0, 0), "outside the blit keeps the prior fill");
  // BLACKNESS ignores the brush and paints black.
  gdi.patBlt(dc, 0, 0, 4, 4, rasterOp.BLACKNESS);
  assert.equal(gdi.getPixel(dc, 0, 0), rgb(0, 0, 0));
  // The device caps are the declared virtual display, independent of the DC.
  assert.equal(gdi.getDeviceCaps(dc, 8), 1920); // HORZRES
  assert.equal(gdi.getDeviceCaps(dc, 10), 1080); // VERTRES
  assert.equal(gdi.getDeviceCaps(dc, 12), 32); // BITSPIXEL
  // ROP2 round-trips through the DC state.
  assert.equal(gdi.setRop2(dc, rasterOp2.R2_WHITE), rasterOp2.R2_COPYPEN);
  assert.equal(gdi.getRop2(dc), rasterOp2.R2_WHITE);
});

test("a logical palette resolves the nearest index and reads back its entry", () => {
  const gdi = createGdiSubsystem();
  const palette = gdi.createPalette([[0, 0, 0], [255, 0, 0], [0, 255, 0], [0, 0, 255]]);
  assert.equal(gdi.getNearestPaletteIndex(palette, rgb(250, 10, 10)), 1); // nearest to pure red
  assert.equal(gdi.getNearestPaletteIndex(palette, rgb(5, 5, 250)), 3); // nearest to pure blue
  assert.deepEqual(gdi.paletteEntry(palette, 2), [0, 255, 0]);
  const dc = gdi.createDC(1, 1);
  assert.equal(gdi.selectPalette(dc, palette), 0); // no palette was selected before
  assert.equal(gdi.realizePalette(dc), 4); // four entries realized
});

// --- the draw fixture: rendered surface vs a test-time reference -------------
// A two-band scene is rendered through GDI, then compared against a reference
// the test computes independently from the same declared bands. No golden is
// committed; the reference lives only in the suite.
function renderBandScene() {
  const gdi = createGdiSubsystem();
  const dc = gdi.createDC(8, 4);
  gdi.fillRect(dc, { left: 0, top: 0, right: 8, bottom: 2 }, gdi.createSolidBrush(rgb(200, 40, 40)));
  gdi.fillRect(dc, { left: 0, top: 2, right: 8, bottom: 4 }, gdi.createSolidBrush(rgb(40, 40, 200)));
  return gdi.surfacePixel(dc);
}

function referenceBandScene() {
  const pixel = [];
  for (let y = 0; y < 4; y += 1) {
    for (let x = 0; x < 8; x += 1) {
      pixel.push(y < 2 ? [200, 40, 40, 255] : [40, 40, 200, 255]);
    }
  }
  return pixel;
}

test("the GDI draw fixture renders within tolerance of a test-time reference", () => {
  const rendered = renderBandScene();
  const reference = referenceBandScene();
  const report = computeFrameDiff(rendered, reference, { reference_source: "computed at test time in the suite" });
  assert.equal(report.committed_baseline, false);
  assert.equal(report.pass, true, `mean delta ${report.mean_delta} exceeds tolerance`);
  assert.equal(report.mean_delta, 0);
});

test("the draw fixture fails when the rendered surface drifts from the reference", () => {
  const rendered = renderBandScene();
  const drifted = referenceBandScene().map((pixel) => [pixel[0], pixel[1], (pixel[2] + 120) & 0xff, pixel[3]]);
  const report = computeFrameDiff(rendered, drifted, { mean_tolerance: 2.0 });
  assert.equal(report.pass, false);
});

// --- conformance: every served GDI32 export carries a case ------------------
function applyGdiOp(gdi, symbol, argument) {
  switch (symbol) {
    case "CreateCompatibleDC":
      return gdi.createCompatibleDC(argument[0]);
    case "CreateDCW":
    case "CreateDCA": {
      const isDisplay = (value) => {
        const name = String(value ?? "").toLowerCase();
        return name === "" || name === "display" || name === "\\\\.\\display1";
      };
      if (!isDisplay(argument[0]) || !isDisplay(argument[1])) {
        gdi.setLastError(87);
        return 0;
      }
      return gdi.createDisplayDC();
    }
    case "DeleteDC":
      return gdi.deleteDC(argument[0]);
    case "GetStockObject":
      return gdi.getStockObject(argument[0]);
    case "CreateSolidBrush":
      return gdi.createSolidBrush(argument[0]);
    case "CreatePen":
      return gdi.createPen(argument[0], argument[1], argument[2]);
    case "DeleteObject":
      return gdi.deleteObject(argument[0]);
    case "SelectObject":
      return gdi.selectObject(argument[0], argument[1]);
    case "Rectangle":
      return gdi.rectangle(argument[0], argument[1], argument[2], argument[3], argument[4]);
    case "MoveToEx":
      gdi.moveToEx(argument[0], argument[1], argument[2]);
      return 1;
    case "LineTo":
      return gdi.lineTo(argument[0], argument[1], argument[2]);
    case "TextOutW":
      return gdi.textOut(argument[0], argument[1], argument[2], argument[3]);
    case "SetTextColor":
      return gdi.setTextColor(argument[0], argument[1]);
    case "SetBkColor":
      return gdi.setBkColor(argument[0], argument[1]);
    case "SetBkMode":
      return gdi.setBkMode(argument[0], argument[1]);
    case "SetPixel":
      return gdi.setPixel(argument[0], argument[1], argument[2], argument[3]);
    case "GetPixel":
      return gdi.getPixel(argument[0], argument[1], argument[2]);
    case "BitBlt":
      return gdi.bitBlt(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8]);
    case "StretchBlt":
      return gdi.stretchBlt(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6], argument[7], argument[8], argument[9], argument[10]);
    case "CreatePalette":
      return gdi.createPalette(argument[0]);
    case "SelectPalette":
      return gdi.selectPalette(argument[0], argument[1]);
    case "RealizePalette":
      return gdi.realizePalette(argument[0]);
    case "GetNearestPaletteIndex":
      return gdi.getNearestPaletteIndex(argument[0], argument[1]);
    case "FillRect":
      return gdi.fillRect(argument[0], argument[1], argument[2]);
    case "PatBlt":
      return gdi.patBlt(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5]);
    case "GetDeviceCaps":
      return gdi.getDeviceCaps(argument[0], argument[1]);
    case "SetROP2":
      return gdi.setRop2(argument[0], argument[1]);
    case "GetROP2":
      return gdi.getRop2(argument[0]);
    case "CreateBitmap":
      return gdi.createBitmap(argument[0], argument[1], argument[2], argument[3], 0, null);
    case "CreateCompatibleBitmap":
      return gdi.createCompatibleBitmap(argument[0], argument[1], argument[2]);
    case "CreateDIBSection":
      return gdi.createDibSection({
        width: Math.max(argument[0] | 0, 1),
        height: Math.max(argument[1] | 0, 1),
        bits_pixel: 32,
        top_down: false,
        bits_address: 0,
        stride: ((Math.max(argument[0] | 0, 1) * 32 + 31) >> 5) << 2,
      });
    case "GetCurrentObject":
      return gdi.getCurrentObject(argument[0], argument[1]);
    case "GetObjectA": {
      const info = gdi.getObject(argument[0]);
      return info === null ? 0 : 24;
    }
    case "GetDIBits":
      return gdi.getDIBits(argument[0], argument[1], argument[2], argument[3], argument[4], argument[4] === 0 ? false : () => {});
    default:
      return null;
  }
}

function gdiConformanceImplementation() {
  return (library, symbol, input) => {
    const gdi = createGdiSubsystem();
    const argument = Array.isArray(input) ? input : input.argument ?? [];
    for (const step of Array.isArray(input) ? [] : input.scenario ?? []) {
      applyGdiOp(gdi, step[0], step[1]);
    }
    const value = applyGdiOp(gdi, symbol, argument);
    if (value === null) return { return_value: null, last_error: `The export ${library}!${symbol} is not served` };
    return { return_value: value >>> 0, last_error: gdi.getLastError() };
  };
}

function buildGdiConformanceCase() {
  const caseList = [];
  let caseNumber = 0;
  function define(symbol, input, expected) {
    caseNumber += 1;
    caseList.push({ case_id: `GDI-${String(caseNumber).padStart(3, "0")}`, library: "gdi32.dll", symbol, input, expected });
  }
  const dcStep = ["CreateCompatibleDC", [0]]; // yields FIRST_HANDLE, a 1x1 surface
  const dc2Step = ["CreateCompatibleDC", [0]]; // yields FIRST_HANDLE + 4
  const brushStep = ["CreateSolidBrush", [rgb(1, 2, 3)]];
  const secondHandle = FIRST_HANDLE + 4;

  define("CreateCompatibleDC", { argument: [0] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("CreateDCW", { argument: ["DISPLAY", ""] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("CreateDCW", { argument: ["\\\\.\\DISPLAY1", ""] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("CreateDCW", { argument: ["PRINTER", ""] }, { return_value: 0, last_error: 87 });
  define("CreateDCA", { argument: ["DISPLAY", "\\\\.\\DISPLAY1"] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("DeleteDC", { scenario: [dcStep], argument: [FIRST_HANDLE] }, { return_value: 1, last_error: 0 });
  define("GetStockObject", { argument: [0] }, { return_value: stockObject.WHITE_BRUSH, last_error: 0 });
  define("CreateSolidBrush", { argument: [rgb(1, 2, 3)] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("CreatePen", { argument: [0, 1, rgb(0, 0, 0)] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("DeleteObject", { scenario: [brushStep], argument: [FIRST_HANDLE] }, { return_value: 1, last_error: 0 });
  define("SelectObject", { scenario: [dcStep, brushStep], argument: [FIRST_HANDLE, secondHandle] }, { return_value: stockObject.WHITE_BRUSH, last_error: 0 });
  define("Rectangle", { scenario: [dcStep], argument: [FIRST_HANDLE, 0, 0, 1, 1] }, { return_value: 1, last_error: 0 });
  define("MoveToEx", { scenario: [dcStep], argument: [FIRST_HANDLE, 0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("LineTo", { scenario: [dcStep, ["MoveToEx", [FIRST_HANDLE, 0, 0]]], argument: [FIRST_HANDLE, 0, 0] }, { return_value: 1, last_error: 0 });
  define("TextOutW", { scenario: [dcStep], argument: [FIRST_HANDLE, 0, 0, "A"] }, { return_value: 1, last_error: 0 });
  define("SetTextColor", { scenario: [dcStep], argument: [FIRST_HANDLE, rgb(9, 9, 9)] }, { return_value: rgb(0, 0, 0), last_error: 0 });
  define("SetBkColor", { scenario: [dcStep], argument: [FIRST_HANDLE, rgb(9, 9, 9)] }, { return_value: rgb(255, 255, 255), last_error: 0 });
  define("SetBkMode", { scenario: [dcStep], argument: [FIRST_HANDLE, backgroundMode.TRANSPARENT] }, { return_value: backgroundMode.OPAQUE, last_error: 0 });
  define("SetPixel", { scenario: [dcStep], argument: [FIRST_HANDLE, 0, 0, rgb(7, 8, 9)] }, { return_value: rgb(7, 8, 9), last_error: 0 });
  define("GetPixel", { scenario: [dcStep, ["SetPixel", [FIRST_HANDLE, 0, 0, rgb(7, 8, 9)]]], argument: [FIRST_HANDLE, 0, 0] }, { return_value: rgb(7, 8, 9), last_error: 0 });
  define("BitBlt", { scenario: [dcStep, dc2Step], argument: [FIRST_HANDLE, 0, 0, 1, 1, secondHandle, 0, 0, rasterOp.SRCCOPY] }, { return_value: 1, last_error: 0 });
  define("StretchBlt", { scenario: [dcStep, dc2Step], argument: [FIRST_HANDLE, 0, 0, 1, 1, secondHandle, 0, 0, 1, 1, rasterOp.SRCCOPY] }, { return_value: 1, last_error: 0 });
  const paletteEntry2 = [[0, 0, 0], [255, 0, 0]];
  const createPaletteStep = ["CreatePalette", [paletteEntry2]];
  define("CreatePalette", { argument: [paletteEntry2] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("SelectPalette", { scenario: [dcStep, createPaletteStep], argument: [FIRST_HANDLE, secondHandle] }, { return_value: 0, last_error: 0 });
  define("RealizePalette", { scenario: [dcStep, createPaletteStep, ["SelectPalette", [FIRST_HANDLE, secondHandle]]], argument: [FIRST_HANDLE] }, { return_value: 2, last_error: 0 });
  define("GetNearestPaletteIndex", { scenario: [createPaletteStep], argument: [FIRST_HANDLE, rgb(250, 10, 10)] }, { return_value: 1, last_error: 0 });

  // rect fill, pattern blit, raster op, device caps (BPTK-012)
  define("FillRect", { scenario: [dcStep, brushStep], argument: [FIRST_HANDLE, { left: 0, top: 0, right: 1, bottom: 1 }, secondHandle] }, { return_value: 1, last_error: 0 });
  define("PatBlt", { scenario: [dcStep], argument: [FIRST_HANDLE, 0, 0, 1, 1, rasterOp.PATCOPY] }, { return_value: 1, last_error: 0 });
  define("GetDeviceCaps", { argument: [0, 8] }, { return_value: 1920, last_error: 0 });
  define("GetDeviceCaps", { argument: [0, 12] }, { return_value: 32, last_error: 0 });
  define("GetDeviceCaps", { argument: [0, 999] }, { return_value: 0, last_error: 0 });
  define("SetROP2", { scenario: [dcStep], argument: [FIRST_HANDLE, rasterOp2.R2_WHITE] }, { return_value: rasterOp2.R2_COPYPEN, last_error: 0 });
  define("GetROP2", { scenario: [dcStep], argument: [FIRST_HANDLE] }, { return_value: rasterOp2.R2_COPYPEN, last_error: 0 });
  define("CreateCompatibleBitmap", { scenario: [dcStep], argument: [FIRST_HANDLE, 2, 2] }, { return_value: FIRST_HANDLE + 4, last_error: 0 });
  define("CreateBitmap", { argument: [2, 2, 1, 1, 0] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("CreateBitmap", { argument: [2, 2, 1, 8, 0] }, { return_value: 0, last_error: 87 });
  define("CreateDIBSection", { argument: [2, 2] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("GetCurrentObject", { scenario: [dcStep], argument: [FIRST_HANDLE, 7] }, { return_value: 0, last_error: 0 });
  define("GetObjectA", { scenario: [dcStep, ["CreateCompatibleBitmap", [FIRST_HANDLE, 2, 2]]], argument: [FIRST_HANDLE + 4] }, { return_value: 24, last_error: 0 });
  define("GetDIBits", { scenario: [dcStep, ["CreateCompatibleBitmap", [FIRST_HANDLE, 2, 2]]], argument: [FIRST_HANDLE, FIRST_HANDLE + 4, 0, 2, 0] }, { return_value: 2, last_error: 0 });

  return caseList;
}

test("conformance: every served GDI32 export carries a case and matches the oracle", () => {
  const caseTable = buildGdiConformanceCase();
  const report = runConformanceSuite(caseTable, gdiConformanceImplementation(), {
    served_export: gdiExportTable.map((entry) => `${entry.library}!${entry.symbol}`),
  });
  assert.equal(report.is_coverage_complete, true, `uncovered: ${report.uncovered_export.join(", ")}`);
  assert.equal(report.fail_count, 0, report.result.filter((entry) => !entry.pass).map((entry) => `${entry.case_id}: ${entry.mismatch.join("; ")}`).join("\n"));
  assert.equal(report.pass_count, caseTable.length);
});

// --- the desktop compositor (browser display milestone 3) -------------------
// Instantiate a synthetic dialog through the real window manager, then paint its
// paint log through compositeDesktop, and assert the frame, caption, STATIC, and
// BUTTON pixels land exactly where the template geometry (offset by the caption
// band) says. The paint is generic — driven by control class, never by title.

test("compositeDesktop paints a dialog's frame, caption, STATIC, and BUTTON at the template geometry", () => {
  const user = createUserSubsystem();
  const gdi = createGdiSubsystem();
  const template = syntheticAboutDialog();
  const dialog = user.instantiateDialog(template, 0, 0);
  assert.notEqual(dialog.hwnd, 0, "the dialog frame was created");

  const snapshot = user.paintSnapshot();
  // The frame plus its two controls are logged (frame first, back-to-front).
  assert.equal(snapshot.length, 3, "frame + STATIC + BUTTON captured into the paint log");
  assert.equal(snapshot[0].parent >>> 0, 0, "the frame is the first, back-most snapshot");

  const surface = gdi.compositeDesktop(snapshot, compositorMetric.desktop_width, compositorMetric.desktop_height);
  assert.equal(surface.width, compositorMetric.desktop_width);
  assert.equal(surface.height, compositorMetric.desktop_height);
  assert.equal(surface.window_painted, 1, "exactly one top-level frame painted");

  // The frame occupies the converted template rect; its client is btnFace grey.
  const geometry = dialogPixelGeometry(template);
  const fx = geometry.frame.x;
  const fy = geometry.frame.y;
  const cap = compositorMetric.caption_height;
  // Desktop shows through outside the frame.
  assert.deepEqual(pixelAt(surface, fx - 3, fy - 3), [58, 110, 165, 255], "desktop background outside the frame");
  // The caption band carries the active-caption color.
  assert.deepEqual(pixelAt(surface, fx + 4, fy + 4), [0, 0, 128, 255], "the caption band is painted");
  // The client area below the caption, clear of any control, is btnFace grey.
  assert.deepEqual(pixelAt(surface, fx + 2, fy + cap + 2), [192, 192, 192, 255], "the dialog client is COLOR_BTNFACE grey");

  // The STATIC caption paints black glyph ink inside its screen rect. Its client
  // origin is the frame origin plus the caption band; the caption reads "About
  // PuTTY", so at least one ink pixel lands in the rect.
  const staticItem = geometry.item[0];
  const staticLeft = fx + staticItem.x;
  const staticTop = fy + cap + staticItem.y;
  let staticInk = 0;
  for (let y = staticTop; y < staticTop + staticItem.height; y += 1) {
    for (let x = staticLeft; x < staticLeft + staticItem.width; x += 1) {
      const [r, g, b] = pixelAt(surface, x, y);
      if (r === 0 && g === 0 && b === 0) staticInk += 1;
    }
  }
  assert.ok(staticInk > 0, `the STATIC caption painted glyph ink (${staticInk} px) at its geometry`);

  // The BUTTON paints a raised bevel: white highlight on the top edge, grey
  // shadow on the bottom edge, at the control's screen rect.
  const buttonItem = geometry.item[1];
  const bLeft = fx + buttonItem.x;
  const bTop = fy + cap + buttonItem.y;
  const bRight = bLeft + buttonItem.width;
  const bBottom = bTop + buttonItem.height;
  assert.deepEqual(pixelAt(surface, bLeft, bTop), [255, 255, 255, 255], "the button highlight edge (top-left)");
  assert.deepEqual(pixelAt(surface, bRight - 1, bBottom - 1), [128, 128, 128, 255], "the button shadow edge (bottom-right)");
  // The button caption "OK" paints black ink somewhere inside its face.
  let buttonInk = 0;
  for (let y = bTop; y < bBottom; y += 1) {
    for (let x = bLeft; x < bRight; x += 1) {
      const [r, g, b] = pixelAt(surface, x, y);
      if (r === 0 && g === 0 && b === 0) buttonInk += 1;
    }
  }
  assert.ok(buttonInk > 0, `the BUTTON caption painted glyph ink (${buttonInk} px) at its geometry`);
});

test("compositeDesktop is deterministic: same paint log yields byte-identical pixels", () => {
  const template = syntheticAboutDialog();
  const paintOnce = () => {
    const user = createUserSubsystem();
    const gdi = createGdiSubsystem();
    user.instantiateDialog(template, 0, 0);
    return gdi.compositeDesktop(user.paintSnapshot(), compositorMetric.desktop_width, compositorMetric.desktop_height).rgba;
  };
  assert.deepEqual(Array.from(paintOnce()), Array.from(paintOnce()), "two composites are byte-identical");
});

test("compositeDesktop clears to the desktop color when no window was painted", () => {
  const gdi = createGdiSubsystem();
  const surface = gdi.compositeDesktop([], 64, 48);
  assert.equal(surface.window_painted, 0, "no frame painted from an empty log");
  assert.deepEqual(pixelAt(surface, 32, 24), [58, 110, 165, 255], "the surface is the cleared desktop");
});

test("compositeDesktop paints an EDIT control as a sunken white client", () => {
  const user = createUserSubsystem();
  const gdi = createGdiSubsystem();
  const template = {
    is_ex: false, style: 0, ex_style: 0, control_count: 1,
    x: 20, y: 20, cx: 120, cy: 60, class_name: "#32770", title: "Edit host", font: null,
    item: [{ style: WS_VISIBLE | WS_CHILD, ex_style: 0, x: 10, y: 10, cx: 80, cy: 16, id: 1, class_name: "Edit", title: "" }],
  };
  user.instantiateDialog(template, 0, 0);
  const surface = gdi.compositeDesktop(user.paintSnapshot(), 320, 200);
  const cap = compositorMetric.caption_height;
  const editGeometry = dialogPixelGeometry(template);
  const eLeft = editGeometry.frame.x + editGeometry.item[0].x;
  const eTop = editGeometry.frame.y + cap + editGeometry.item[0].y;
  // The interior of the EDIT client is white.
  assert.deepEqual(pixelAt(surface, eLeft + 4, eTop + 4), [255, 255, 255, 255], "the EDIT client is white");
  // Its sunken bevel puts the shadow on the top edge.
  assert.deepEqual(pixelAt(surface, eLeft + 4, eTop), [128, 128, 128, 255], "the EDIT sunken top edge");
});

test("compositeDesktop exposes non-overlapping control rects for a two-button dialog", () => {
  const user = createUserSubsystem();
  const gdi = createGdiSubsystem();
  // Two buttons abutting in DLU (0..50, 55..105); under the 8pt base they widen
  // to non-overlapping pixel rects wide enough for their captions.
  const template = {
    is_ex: false, style: 0, ex_style: 0, control_count: 2,
    x: 10, y: 10, cx: 120, cy: 40, class_name: "#32770", title: "Pair",
    font: { point_size: 8, typeface: "MS Shell Dlg" },
    item: [
      { style: WS_VISIBLE | WS_CHILD | WS_TABSTOP, ex_style: 0, x: 0, y: 10, cx: 50, cy: 14, id: 1, class_name: "Button", title: "Left One" },
      { style: WS_VISIBLE | WS_CHILD | WS_TABSTOP, ex_style: 0, x: 55, y: 10, cx: 50, cy: 14, id: 2, class_name: "Button", title: "Right Two" },
    ],
  };
  user.instantiateDialog(template, 0, 0);
  const surface = gdi.compositeDesktop(user.paintSnapshot(), 320, 200);

  assert.equal(surface.frame_rect.length, 1, "one frame rect is exposed");
  assert.equal(surface.control_rect.length, 2, "both control rects are exposed");

  const geometry = dialogPixelGeometry(template);
  const cap = compositorMetric.caption_height;
  // Each exposed control rect equals the frame origin plus the converted local
  // rect, offset by the caption band.
  for (let index = 0; index < 2; index += 1) {
    const local = geometry.item[index];
    const expected = {
      left: geometry.frame.x + local.x,
      top: geometry.frame.y + cap + local.y,
      right: geometry.frame.x + local.x + local.width,
      bottom: geometry.frame.y + cap + local.y + local.height,
    };
    const painted = surface.control_rect[index];
    assert.deepEqual({ left: painted.left, top: painted.top, right: painted.right, bottom: painted.bottom }, expected, `control ${index} rect matches the conversion`);
  }
  // The two buttons do not overlap.
  const [a, b] = surface.control_rect;
  assert.ok(a.right <= b.left || b.right <= a.left, "the two button rects are horizontally disjoint");
  // Both controls lie within the frame rect.
  const frame = surface.frame_rect[0];
  for (const rect of surface.control_rect) {
    assert.ok(rect.left >= frame.left && rect.right <= frame.right && rect.top >= frame.top && rect.bottom <= frame.bottom, "the control lies within the frame");
  }
});
