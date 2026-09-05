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
  backgroundMode,
  stockObject,
} from "../lib/gdi.mjs";

const FIRST_HANDLE = 0x00040000;

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
    caseList.push({ case_id: `GDI-${String(caseNumber).padStart(3, "0")}`, library: "GDI32.dll", symbol, input, expected });
  }
  const dcStep = ["CreateCompatibleDC", [0]]; // yields FIRST_HANDLE, a 1x1 surface
  const dc2Step = ["CreateCompatibleDC", [0]]; // yields FIRST_HANDLE + 4
  const brushStep = ["CreateSolidBrush", [rgb(1, 2, 3)]];
  const secondHandle = FIRST_HANDLE + 4;

  define("CreateCompatibleDC", { argument: [0] }, { return_value: FIRST_HANDLE, last_error: 0 });
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
