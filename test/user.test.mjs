// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The USER32 slice acceptance (BPTK-011). The message-order fixture replays
// deterministically, the create/destroy lifecycle delivers the exact WM_*
// pair, an input trace yields the exact message sequence, and every served
// USER32 export carries a conformance case so a zero-case export is caught as
// a coverage hole — the same discipline the core HLE surface holds.

import test from "node:test";
import assert from "node:assert/strict";

import { runConformanceSuite } from "../lib/conformance.mjs";
import {
  createUserSubsystem,
  userExportTable,
  windowMessage,
  showCommand,
  systemMetric,
  mulDiv,
  dialogBaseUnit,
  dialogRectToPixel,
  defaultDialogBaseUnit,
  mapVirtualKey,
  toUnicode,
  virtualKeyFromDomCode,
  pointerButtonFromDom,
} from "../lib/user.mjs";
import { createConformanceMachine } from "../lib/hle.mjs";

const FIRST_ATOM = 0xc000;
const FIRST_HANDLE = 0x00010010;

// A WndProc that records nothing of its own but defers to DefWindowProc, so a
// fixture measures the manager's delivery order rather than app behavior.
function defaultProc(handle, message, wParam, lParam, defWindowProc) {
  return defWindowProc(handle, message, wParam, lParam);
}

test("mapVirtualKey translates US set-1 scan codes and refuses an unknown code", () => {
  assert.equal(mapVirtualKey(0x1e, 1), 0x41);
  assert.equal(mapVirtualKey(0x41, 0), 0x1e);
  assert.equal(mapVirtualKey(0x41, 2), 0x41);
  assert.equal(mapVirtualKey(0xff, 1), 0);
});

test("toUnicode translates a US virtual key under shift and caps", () => {
  const up = new Uint8Array(256);
  assert.equal(toUnicode(0x20, 0x39, up), 0x20);
  assert.equal(toUnicode(0x41, 0x1e, up), 0x61);
  assert.equal(toUnicode(0xff, 0, up), 0);
  const shift = new Uint8Array(256);
  shift[0x10] = 0x80;
  assert.equal(toUnicode(0x41, 0x1e, shift), 0x41);
  assert.equal(toUnicode(0x31, 0x02, shift), 0x21);
  const caps = new Uint8Array(256);
  caps[0x14] = 0x01;
  assert.equal(toUnicode(0x41, 0x1e, caps), 0x41);
});

test("RegisterClass then CreateWindowEx delivers the exact WM_NCCREATE, WM_CREATE creation pair", () => {
  const user = createUserSubsystem();
  const atom = user.registerClass("AppClass", defaultProc);
  assert.equal(atom, FIRST_ATOM);
  const handle = user.createWindowEx({ class_name: "AppClass" });
  assert.equal(handle, FIRST_HANDLE);
  const message = user.deliveredFor(handle).map((entry) => entry.message);
  assert.deepEqual(message, [windowMessage.WM_NCCREATE, windowMessage.WM_CREATE]);
});

test("CreateWindowEx for an unregistered class fails with cannot-find-class", () => {
  const user = createUserSubsystem();
  const handle = user.createWindowEx({ class_name: "Missing" });
  assert.equal(handle, 0);
  assert.equal(user.getLastError(), 0x57f);
});

test("acceptDropFiles records whether a live window accepts dropped files", () => {
  const user = createUserSubsystem();
  user.registerClass("AppClass", defaultProc);
  const handle = user.createWindowEx({ class_name: "AppClass" });
  assert.equal(user.isDropAccepted(handle), false);
  assert.equal(user.acceptDropFiles(0, true), 0);
  assert.equal(user.getLastError(), 0x578);
  assert.equal(user.acceptDropFiles(handle, true), 0);
  assert.equal(user.isDropAccepted(handle), true);
  assert.equal(user.acceptDropFiles(handle, false), 0);
  assert.equal(user.isDropAccepted(handle), false);
});

test("getClassInfo reports a registered class and refuses an unknown name", () => {
  const user = createUserSubsystem();
  user.registerClass("AppClass", defaultProc, 0x00000003);
  assert.equal(user.getClassInfo(""), null);
  assert.equal(user.getLastError(), 87);
  assert.equal(user.getClassInfo("Missing"), null);
  assert.equal(user.getLastError(), 0x583);
  const klass = user.getClassInfo("AppClass");
  assert.equal(klass.name, "AppClass");
  assert.equal(klass.style, 0x00000003);
});

test("a WM_NCCREATE that returns FALSE aborts creation and yields NULL", () => {
  const user = createUserSubsystem();
  user.registerClass("Reject", (handle, message) => (message === windowMessage.WM_NCCREATE ? 0 : 1));
  const handle = user.createWindowEx({ class_name: "Reject" });
  assert.equal(handle, 0);
  assert.equal(user.windowCount(), 0);
});

// The full lifecycle fixture: register, create, show, update, pump the loop
// until WM_QUIT. The expectation is the exact ordered sequence WndProc sees.
function runLifecycleFixture() {
  const user = createUserSubsystem();
  const seen = [];
  const recordingProc = (handle, message, wParam, lParam, defWindowProc) => {
    seen.push({ handle, message, w_param: wParam, l_param: lParam });
    // The app posts a quit as soon as it paints, so the loop terminates.
    if (message === windowMessage.WM_PAINT) user.postQuitMessage(0);
    return defWindowProc(handle, message, wParam, lParam);
  };
  user.registerClass("AppClass", recordingProc);
  const handle = user.createWindowEx({ class_name: "AppClass" });
  user.showWindow(handle, showCommand.SW_SHOWNORMAL);

  const loop = [];
  const sink = {};
  for (;;) {
    const status = user.getMessage(sink);
    if (status === -1) break; // idle: nothing pending
    loop.push({ message: sink.message.message, handle: sink.message.handle });
    if (status === 0) break; // WM_QUIT
    user.translateMessage(sink.message);
    user.dispatchMessage(sink.message);
  }
  return { seen, loop, handle };
}

test("the lifecycle fixture delivers create, show cascade, paint, and quit in exact order", () => {
  const { seen, loop, handle } = runLifecycleFixture();
  const message = seen.map((entry) => entry.message);
  assert.deepEqual(message, [
    windowMessage.WM_NCCREATE,
    windowMessage.WM_CREATE,
    windowMessage.WM_SHOWWINDOW,
    windowMessage.WM_ACTIVATEAPP,
    windowMessage.WM_ACTIVATE,
    windowMessage.WM_SETFOCUS,
    windowMessage.WM_PAINT,
  ]);
  assert.deepEqual(loop, [
    { message: windowMessage.WM_PAINT, handle },
    { message: windowMessage.WM_QUIT, handle: 0 },
  ]);
});

test("the message-order fixture replays identically across two runs", () => {
  const first = runLifecycleFixture();
  const second = runLifecycleFixture();
  assert.deepEqual(first.seen, second.seen);
  assert.deepEqual(first.loop, second.loop);
});

test("DestroyWindow order is WM_SHOWWINDOW, kill focus, deactivate, WM_DESTROY, WM_NCDESTROY", () => {
  const user = createUserSubsystem();
  const seen = [];
  user.registerClass("AppClass", (handle, message, wParam, lParam, defWindowProc) => {
    seen.push(message);
    return defWindowProc(handle, message, wParam, lParam);
  });
  const handle = user.createWindowEx({ class_name: "AppClass" });
  user.showWindow(handle, showCommand.SW_SHOWNORMAL);
  seen.length = 0;
  user.destroyWindow(handle);
  assert.deepEqual(seen, [
    windowMessage.WM_SHOWWINDOW,
    windowMessage.WM_KILLFOCUS,
    windowMessage.WM_ACTIVATE,
    windowMessage.WM_ACTIVATEAPP,
    windowMessage.WM_DESTROY,
    windowMessage.WM_NCDESTROY,
  ]);
});

test("DefWindowProc turns WM_CLOSE into a self-destroy", () => {
  const user = createUserSubsystem();
  user.registerClass("AppClass", defaultProc);
  const handle = user.createWindowEx({ class_name: "AppClass" });
  assert.equal(user.isWindow(handle), true);
  user.sendMessage(handle, windowMessage.WM_CLOSE, 0, 0);
  assert.equal(user.isWindow(handle), false);
});

// The input trace: a scripted key and pointer sequence yields the exact
// ordered WM_* the queue receives. The target is always the focused window,
// so the trace never names a window.
test("an input trace yields the exact WM_* message sequence", () => {
  const user = createUserSubsystem();
  user.registerClass("AppClass", defaultProc);
  const handle = user.createWindowEx({ class_name: "AppClass" });
  user.showWindow(handle, showCommand.SW_SHOWNORMAL);

  const trace = [
    { kind: "key", virtual_key: 0x41, is_down: true }, // 'A' down
    { kind: "key", virtual_key: 0x41, is_down: false }, // 'A' up
    { kind: "mouse", x: 10, y: 20 }, // move
    { kind: "mouse", x: 10, y: 20, button: "left", is_down: true },
    { kind: "mouse", x: 10, y: 20, button: "left", is_down: false },
  ];
  const posted = user.replayInput(trace);
  const message = posted.map((entry) => entry.message);
  assert.deepEqual(message, [
    windowMessage.WM_KEYDOWN,
    windowMessage.WM_KEYUP,
    windowMessage.WM_MOUSEMOVE,
    windowMessage.WM_LBUTTONDOWN,
    windowMessage.WM_LBUTTONUP,
  ]);
  // The pointer messages carry the packed position in lParam.
  const move = posted.find((entry) => entry.message === windowMessage.WM_MOUSEMOVE);
  assert.equal(move.l_param, (20 << 16 | 10) >>> 0);
  assert.equal(move.handle, handle);
});

test("TranslateMessage posts WM_CHAR for a mapped key and nothing for an unmapped one", () => {
  const user = createUserSubsystem();
  user.registerClass("AppClass", defaultProc);
  const handle = user.createWindowEx({ class_name: "AppClass" });
  user.showWindow(handle, showCommand.SW_SHOWNORMAL);

  assert.equal(user.translateMessage({ handle, message: windowMessage.WM_KEYDOWN, w_param: 0x41, l_param: 1 }), 1);
  assert.equal(user.translateMessage({ handle, message: windowMessage.WM_KEYDOWN, w_param: 0x14, l_param: 1 }), 0); // VK_CAPITAL: unmapped
  const sink = {};
  assert.equal(user.peekMessage(sink), 1);
  assert.equal(sink.message.message, windowMessage.WM_CHAR);
  assert.equal(sink.message.w_param, 0x61); // 'a'
});

test("virtualKeyFromDomCode maps a generic US 101 KeyboardEvent.code", () => {
  assert.equal(virtualKeyFromDomCode("KeyA"), 0x41);
  assert.equal(virtualKeyFromDomCode("Digit1"), 0x31);
  assert.equal(virtualKeyFromDomCode("Escape"), 0x1b);
  assert.equal(virtualKeyFromDomCode("ArrowLeft"), 0x25);
  assert.equal(virtualKeyFromDomCode("ShiftLeft"), 0xa0);
  assert.equal(virtualKeyFromDomCode("F1"), 0x70);
  assert.equal(virtualKeyFromDomCode("Nope"), 0);
  assert.equal(pointerButtonFromDom(0), "left");
  assert.equal(pointerButtonFromDom(2), "right");
  assert.equal(pointerButtonFromDom(9), null);
});

test("injectKey updates GetKeyState without a window and posts WM_KEYDOWN when one has focus", () => {
  const user = createUserSubsystem();
  assert.equal(user.getKeyState(0x41), 0);
  assert.equal(user.injectKey(virtualKeyFromDomCode("KeyA"), true), 1);
  assert.equal(user.getKeyState(0x41), 0x8000);
  assert.equal(user.keyboardState()[0x41], 0x80);
  assert.equal(user.getAsyncKeyState(0x41), 0x8001);
  assert.equal(user.getAsyncKeyState(0x41), 0x8000);

  user.registerClass("AppClass", defaultProc);
  const handle = user.createWindowEx({ class_name: "AppClass" });
  user.showWindow(handle, showCommand.SW_SHOWNORMAL);
  user.injectKey(0x20, true);
  const sink = {};
  assert.equal(user.getMessage(sink), 1);
  assert.equal(sink.message.message, windowMessage.WM_KEYDOWN);
  assert.equal(sink.message.w_param, 0x20);
  assert.equal(sink.message.handle, handle);
  assert.equal(user.translateMessage(sink.message), 1);
  user.dispatchMessage(sink.message);
  assert.equal(user.peekMessage(sink), 1);
  assert.equal(sink.message.message, windowMessage.WM_CHAR);
  assert.equal(sink.message.w_param, 0x20);
});

test("injectMouse left button is visible to GetKeyState and posts WM_LBUTTONDOWN", () => {
  const user = createUserSubsystem();
  user.registerClass("AppClass", defaultProc);
  const handle = user.createWindowEx({ class_name: "AppClass" });
  user.showWindow(handle, showCommand.SW_SHOWNORMAL);
  assert.equal(user.injectMouse({ x: 12, y: 34, button: pointerButtonFromDom(0), is_down: true }), 1);
  assert.equal(user.getKeyState(0x01), 0x8000);
  const sink = {};
  assert.equal(user.peekMessage(sink), 1);
  assert.equal(sink.message.message, windowMessage.WM_LBUTTONDOWN);
  assert.equal(sink.message.handle, handle);
  assert.equal(sink.message.l_param, (34 << 16 | 12) >>> 0);
});

test("a live injectKey is visible through user32!GetKeyboardState", () => {
  const { guest, memory } = createConformanceMachine();
  const dest = guest.layout.arena_base + 0x40;
  guest.user.injectKey(0x41, true);
  assert.equal(guest.invokeExport(guest.lookupExport("user32.dll", "GetKeyState"), [0x41]), 0x8000);
  assert.equal(guest.invokeExport(guest.lookupExport("user32.dll", "GetKeyboardState"), [dest]), 1);
  assert.equal(memory.readMemory(dest + 0x41, 1), 0x80);
  assert.equal(memory.readMemory(dest + 0x20, 1), 0);
});

test("instantiateDialog creates the frame and every control, carrying the guest DlgProc", () => {
  const user = createUserSubsystem();
  const template = {
    style: 0x80c800c0,
    ex_style: 0,
    x: 0, y: 0, cx: 200, cy: 100,
    class_name: null, // the default dialog class
    title: "Config",
    item: [
      { style: 0x50010001, ex_style: 0, x: 5, y: 5, cx: 40, cy: 14, id: 1, class_name: "Button", title: "OK" },
      { style: 0x50000000, ex_style: 0, x: 5, y: 25, cx: 190, cy: 10, id: 2, class_name: "Static", title: "Label" },
    ],
  };
  const dlgProc = 0x14000da10n;
  const result = user.instantiateDialog(template, dlgProc, 0xabcd);
  assert.notEqual(result.hwnd, 0, "the dialog frame window is created");
  assert.equal(user.getGuestWndProc(result.hwnd), dlgProc, "the frame carries the guest DlgProc for the message pump");
  assert.equal(result.control.length, 2, "both controls are instantiated as real windows");
  assert.equal(user.getDlgItem(result.hwnd, 1), result.control[0].handle, "GetDlgItem resolves control id 1");
  assert.equal(user.getDlgItem(result.hwnd, 2), result.control[1].handle, "GetDlgItem resolves control id 2");
  assert.equal(result.focus_control, result.control[0].handle, "the first WS_TABSTOP control takes initial focus");
  assert.equal(user.windowCount(), 3, "one frame plus two control windows exist");
});

test("mulDiv rounds to nearest and dialogBaseUnit derives the base from the font", () => {
  assert.equal(mulDiv(216, 6, 4), 324, "216 DLU * 6/4 = 324 px");
  assert.equal(mulDiv(118, 13, 8), 192, "118 DLU * 13/8 rounds 191.75 -> 192");
  assert.equal(mulDiv(0, 6, 4), 0, "zero maps to zero");
  assert.equal(mulDiv(10, 5, 0), 0, "a zero denominator is refused, not NaN");
  // No font: the standard MS Sans Serif 8pt default base (6, 13).
  assert.deepEqual(dialogBaseUnit(null), { x: defaultDialogBaseUnit.x, y: defaultDialogBaseUnit.y });
  assert.deepEqual(dialogBaseUnit({ point_size: 8, typeface: "MS Shell Dlg" }), { x: 6, y: 13 }, "8pt yields the reference base");
  // A larger point size scales the base proportionally (a 16pt font is ~2x).
  assert.deepEqual(dialogBaseUnit({ point_size: 16, typeface: "Tahoma" }), { x: 12, y: 26 }, "16pt scales the 8pt reference");
  // dialogRectToPixel applies the horizontal base over 4 DLU and vertical over 8.
  assert.deepEqual(
    dialogRectToPixel({ x: 6, y: 118, cx: 70, cy: 14 }, { x: 6, y: 13 }),
    { x: 9, y: 192, width: 105, height: 23 },
    "a control DLU rect converts under the base unit pair",
  );
});

test("instantiateDialog converts two side-by-side DLU buttons to non-overlapping pixel rects", () => {
  const user = createUserSubsystem();
  // Two buttons abutting in DLU (0..50 and 55..105 horizontally) with the same
  // top and height. Under the 8pt base (6,13) they must stay side by side and
  // non-overlapping in pixels; raw DLU widths (50 px) would be too narrow for the
  // 8px-per-glyph captions and the ink would collide.
  const template = {
    style: 0x80c800c0,
    ex_style: 0,
    x: 0, y: 0, cx: 120, cy: 40,
    class_name: null,
    title: "Pair",
    font: { point_size: 8, typeface: "MS Shell Dlg" },
    item: [
      { style: 0x50010001, ex_style: 0, x: 0, y: 10, cx: 50, cy: 14, id: 1, class_name: "Button", title: "Left One" },
      { style: 0x50010001, ex_style: 0, x: 55, y: 10, cx: 50, cy: 14, id: 2, class_name: "Button", title: "Right Two" },
    ],
  };
  const result = user.instantiateDialog(template, 0n, 0);
  assert.notEqual(result.hwnd, 0, "the frame is created");

  const unit = dialogBaseUnit(template.font);
  const snapshot = user.paintSnapshot();
  assert.ok(snapshot.length >= 3, "the frame and both buttons are in the paint log");

  // The frame stores pixel geometry: cx/cy converted, plus the caption band on
  // the height so the client (converted cy) fits below the caption.
  const frame = snapshot.find((entry) => (entry.parent >>> 0) === 0);
  const frameRect = dialogRectToPixel({ x: template.x, y: template.y, cx: template.cx, cy: template.cy }, unit);
  assert.equal(frame.x, frameRect.x, "frame x converts");
  assert.equal(frame.y, frameRect.y, "frame y converts");
  assert.equal(frame.width, frameRect.width, "frame width converts");
  assert.equal(frame.height, frameRect.height + 14, "frame height is the client height plus the caption band");

  // Each button window stores the converted local rect.
  const child = snapshot.filter((entry) => (entry.parent >>> 0) !== 0);
  assert.equal(child.length, 2, "both buttons are logged");
  for (let index = 0; index < template.item.length; index += 1) {
    const local = dialogRectToPixel(template.item[index], unit);
    assert.equal(child[index].x, local.x, `button ${index} x converts`);
    assert.equal(child[index].width, local.width, `button ${index} width converts`);
  }
  // Non-overlap in local pixel space: left button 0..75, right button 82..157.
  const leftRect = dialogRectToPixel(template.item[0], unit);
  const rightRect = dialogRectToPixel(template.item[1], unit);
  assert.ok(leftRect.x + leftRect.width <= rightRect.x, "the two buttons do not overlap after conversion");
});

test("registerClassGuest carries the guest WndProc to every window of the class", () => {
  const user = createUserSubsystem();
  const guestProc = 0x140000180n;
  const atom = user.registerClassGuest("AppClass", guestProc, 0);
  assert.equal(atom, FIRST_ATOM);
  const handle = user.createWindowEx({ class_name: "AppClass", style: 0 });
  assert.equal(user.getGuestWndProc(handle), guestProc, "the created window inherits the class guest WndProc");
});

// --- conformance: every served USER32 export carries a case -----------------

// The conformance implementation drives a fresh subsystem per case, applies
// the scenario, then the target call. Input is { scenario, argument }; the
// subsystem method is chosen by the USER32 symbol under test.
function applyUserOp(user, symbol, argument) {
  switch (symbol) {
    case "InitCommonControls":
      return 0;
    case "InitCommonControlsEx":
      return 1;
    case "RegisterClassW":
    case "RegisterClassExW":
    case "RegisterClassExA":
      return user.registerClass(argument[0], null, argument[1] ?? 0);
    case "GetClassInfoExW":
    case "GetClassInfoExA":
    case "GetClassInfoW":
    case "GetClassInfoA":
      if ((argument[1] >>> 0) === 0) {
        user.setLastError(87);
        return 0;
      }
      return user.getClassInfo(argument[0]) === null ? 0 : 1;
    case "UnregisterClassW":
    case "UnregisterClassA":
      return user.unregisterClass(argument[0]);
    case "CreateWindowExW":
      return user.createWindowEx({ class_name: argument[0], style: argument[1] ?? 0 });
    case "DestroyWindow":
      return user.destroyWindow(argument[0]);
    case "DefWindowProcW":
      return user.defWindowProc(argument[0], argument[1], argument[2] ?? 0, argument[3] ?? 0);
    case "ShowWindow":
      return user.showWindow(argument[0], argument[1]);
    case "UpdateWindow":
      return user.updateWindow(argument[0]);
    case "PostMessageW":
      return user.postMessage(argument[0], argument[1], argument[2] ?? 0, argument[3] ?? 0);
    case "SendMessageW":
      return user.sendMessage(argument[0], argument[1], argument[2] ?? 0, argument[3] ?? 0);
    case "PostQuitMessage":
      user.postQuitMessage(argument[0]);
      return 0;
    case "GetActiveWindow":
      return user.getActiveWindow();
    case "GetFocus":
      return user.getFocus();
    case "IsWindow":
      return user.isWindow(argument[0]) ? 1 : 0;
    case "GetMessageW": {
      const sink = {};
      return user.getMessage(sink);
    }
    case "PeekMessageW": {
      const sink = {};
      return user.peekMessage(sink, (argument[0] & 1) === 1);
    }
    case "TranslateMessage":
      return user.translateMessage(argument[0]);
    case "DispatchMessageW":
      return user.dispatchMessage(argument[0]);
    case "GetClientRect":
      return user.clientRect(argument[0]) === null ? 0 : 1;
    case "GetWindowRect":
      return user.windowRect(argument[0]) === null ? 0 : 1;
    case "ClientToScreen":
      if ((argument[1] >>> 0) === 0) {
        user.setLastError(87);
        return 0;
      }
      return user.clientToScreen(argument[0], 0, 0) === null ? 0 : 1;
    case "ScreenToClient":
      if ((argument[1] >>> 0) === 0) {
        user.setLastError(87);
        return 0;
      }
      return user.screenToClient(argument[0], 0, 0) === null ? 0 : 1;
    case "MoveWindow":
      return user.moveWindow(argument[0], argument[1], argument[2], argument[3], argument[4]);
    case "AdjustWindowRect":
      return 1;
    case "AdjustWindowRectEx":
      if ((argument[0] >>> 0) === 0) {
        user.setLastError(87);
        return 0;
      }
      return 1;
    case "GetSystemMetrics":
      return systemMetric[argument[0]] ?? 0;
    case "GetDoubleClickTime":
      return 500;
    case "MapVirtualKeyW":
    case "MapVirtualKeyA":
      return mapVirtualKey(argument[0], argument[1]);
    case "ToUnicode":
      if ((argument[3] >>> 0) === 0 || (argument[4] | 0) <= 0) {
        user.setLastError(87);
        return 0;
      }
      return toUnicode(argument[0], argument[1], null) === 0 ? 0 : 1;
    case "EnumDisplayMonitors":
      if ((argument[2] >>> 0) === 0) {
        user.setLastError(87);
        return 0;
      }
      return 1;
    case "GetMonitorInfoW":
    case "GetMonitorInfoA":
      if ((argument[0] >>> 0) !== 0x00020000 || (argument[1] >>> 0) === 0) {
        user.setLastError((argument[1] >>> 0) === 0 ? 87 : 6);
        return 0;
      }
      return 1;
    case "EnumDisplaySettingsW":
    case "EnumDisplaySettingsA":
      if ((argument[2] >>> 0) === 0) {
        user.setLastError(87);
        return 0;
      }
      if ((argument[1] >>> 0) !== 0 && (argument[1] >>> 0) !== 0xffffffff && (argument[1] >>> 0) !== 0xfffffffe) return 0;
      return 1;
    case "EnumDisplayDevicesW":
    case "EnumDisplayDevicesA":
      if ((argument[2] >>> 0) === 0) {
        user.setLastError(87);
        return 0;
      }
      if ((argument[1] >>> 0) !== 0) return 0;
      return 1;
    case "FindWindowA":
    case "GetCapture":
    case "GetClipboardOwner":
    case "IsClipboardFormatAvailable":
    case "GetClipboardData":
    case "MapWindowPoints":
    case "ChangeDisplaySettingsW":
      return 0;
    case "SetCapture":
      return 0;
    case "ReleaseCapture":
    case "SetCursorPos":
    case "InvalidateRect":
    case "ValidateRect":
    case "OpenClipboard":
    case "CloseClipboard":
    case "EndPaint":
      return 1;
    case "ShowCursor":
      return (argument[0] | 0) === 0 ? 0xffffffff : 1;
    case "GetWindowDC":
    case "GetDCEx":
    case "BeginPaint":
      return 0x00040000;
    case "GetUpdateRect":
      return 1;
    case "SetRect":
    case "SetRectEmpty":
    case "OffsetRect":
      return argument[0] ? 1 : 0;
    case "UnionRect":
      return 1;
    case "PtInRect":
      return 1;
    case "GetKeyboardLayout":
      return 0x04090409;
    case "WindowFromPoint":
      return user.getDesktopWindow();
    case "MessageBoxW":
      return user.messageBox(argument[0] ?? "", argument[1] ?? "", argument[2] ?? 0);
    case "DialogBoxParamW":
      return 0;
    case "SetDlgItemTextW":
      return user.setWindowText(user.getDlgItem(argument[0], argument[1]), argument[2] ?? "");
    case "SendDlgItemMessageW":
      return user.sendDlgItemMessage(argument[0], argument[1], argument[2] ?? 0, argument[3] ?? 0, argument[4] ?? 0);
    case "GetKeyState":
      return user.getKeyState(argument[0]);
    case "GetAsyncKeyState":
      return user.getAsyncKeyState(argument[0]);
    case "injectKey":
      return user.injectKey(argument[0], argument[1] !== 0);
    case "GetKeyboardState":
      if ((argument[0] >>> 0) === 0) {
        user.setLastError(87);
        return 0;
      }
      return 1;
    case "GetForegroundWindow":
      return user.getActiveWindow();
    case "GetQueueStatus": {
      const sink = {};
      return user.peekMessage(sink, false) === 1 ? ((argument[0] & 0xffff) << 16) >>> 0 : 0;
    }
    case "GetCursorPos":
      return 1; // the cursor rests at the origin; the point write is exercised in the HLE test
    case "MsgWaitForMultipleObjects": {
      const sink = {};
      return user.peekMessage(sink, false) === 1 ? (argument[0] >>> 0) : 0x102;
    }
    case "PeekMessageA": {
      const sink = {};
      return user.peekMessage(sink, (argument[4] & 1) === 1);
    }
    case "SendMessageA":
      return user.sendMessage(argument[0], argument[1], argument[2] ?? 0, argument[3] ?? 0);
    case "RegisterClassA":
      return user.registerClass(argument[0], null, argument[1] ?? 0);
    case "CreateWindowExA":
      return user.createWindowEx({ class_name: argument[0], style: argument[1] ?? 0, text: argument[2] ?? "" });
    case "GetMessageA": {
      const sink = {};
      return user.getMessage(sink);
    }
    case "DispatchMessageA":
      return user.dispatchMessage(argument[0]);
    case "PostMessageA":
      return user.postMessage(argument[0], argument[1], argument[2] ?? 0, argument[3] ?? 0);
    case "DefDlgProcA":
      return user.defWindowProc(argument[0], argument[1], argument[2] ?? 0, argument[3] ?? 0);
    case "GetWindowTextA":
    case "GetWindowTextW":
    case "GetWindowTextLengthA":
    case "GetWindowTextLengthW":
      return user.getWindowText(argument[0]).length;
    case "SetWindowTextW":
    case "SetWindowTextA":
      return user.setWindowText(argument[0], argument[1] ?? "");
    case "GetDlgItem":
      return user.getDlgItem(argument[0], argument[1]);
    case "GetDlgItemTextA":
      return user.getWindowText(user.getDlgItem(argument[0], argument[1])).length;
    case "SetDlgItemTextA":
      return user.setWindowText(user.getDlgItem(argument[0], argument[1]), argument[2] ?? "");
    case "GetDlgItemInt":
      return user.getDlgItemInt(argument[0], argument[1]);
    case "SetDlgItemInt":
      return user.setDlgItemInt(argument[0], argument[1], argument[2] ?? 0);
    case "SendDlgItemMessageA":
      return user.sendDlgItemMessage(argument[0], argument[1], argument[2] ?? 0, argument[3] ?? 0, argument[4] ?? 0);
    case "IsDlgButtonChecked":
      return user.isDlgButtonChecked(argument[0], argument[1]);
    case "CheckRadioButton":
      return user.checkRadioButton(argument[0], argument[1], argument[2], argument[3]);
    case "EnableWindow":
      return user.enableWindow(argument[0], argument[1]);
    case "GetWindowLongA":
    case "GetWindowLongW":
      return user.getWindowLong(argument[0], argument[1]);
    case "SetWindowLongA":
    case "SetWindowLongW":
      return user.setWindowLong(argument[0], argument[1], argument[2]);
    case "SetPropW":
    case "SetPropA":
      if (argument[1] === 0 || argument[1] === null || argument[1] === "") {
        user.setLastError(87);
        return 0;
      }
      return user.setProp(argument[0], argument[1], argument[2]);
    case "GetPropW":
    case "GetPropA":
      if (argument[1] === 0 || argument[1] === null || argument[1] === "") return 0;
      return user.getProp(argument[0], argument[1]);
    case "RemovePropW":
    case "RemovePropA":
      if (argument[1] === 0 || argument[1] === null || argument[1] === "") return 0;
      return user.removeProp(argument[0], argument[1]);
    case "SetWindowPos":
      return user.setWindowPos(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6]);
    case "SetActiveWindow":
      return user.setActiveWindow(argument[0]);
    case "SetForegroundWindow":
      return user.isWindow(argument[0]) ? 1 : 0;
    case "GetDesktopWindow":
      return user.getDesktopWindow();
    case "GetDC":
      return 0x00040000;
    case "ReleaseDC":
      return 1;
    case "LoadCursorA":
    case "LoadCursorW":
      return (0x00008000 | (argument[1] & 0xffff)) >>> 0;
    case "LoadIconA":
    case "LoadIconW":
      return (0x00008100 | (argument[1] & 0xffff)) >>> 0;
    case "CreateIconIndirect":
      if ((argument[0] >>> 0) === 0) {
        user.setLastError(87);
        return 0;
      }
      return 0x00008200;
    case "CreateIconFromResource":
    case "CreateIconFromResourceEx":
      if ((argument[0] >>> 0) === 0 || (argument[1] >>> 0) === 0 || (argument[3] >>> 0) !== 0x00030000) {
        user.setLastError(87);
        return 0;
      }
      return 0x00008200;
    case "DestroyIcon":
      return 1;
    case "RegisterWindowMessageA":
    case "RegisterWindowMessageW":
      if ((argument[0] >>> 0) === 0) {
        user.setLastError(87);
        return 0;
      }
      return 0x0000c000;
    case "SystemParametersInfoA":
    case "SystemParametersInfoW": {
      const action = argument[0] >>> 0;
      if (action === 3 || action === 0x20 || action === 0x30 || action === 0x68 || action === 0x70) {
        if ((argument[2] >>> 0) === 0) {
          user.setLastError(87);
          return 0;
        }
        return 1;
      }
      user.setLastError(87);
      return 0;
    }
    case "CopyImage": {
      const handle = argument[0] >>> 0;
      const type = argument[1] >>> 0;
      const flags = argument[4] >>> 0;
      if (handle === 0 || (type !== 0 && type !== 1 && type !== 2)) {
        user.setLastError(87);
        return 0;
      }
      if (handle < 0x00008000) {
        user.setLastError(6);
        return 0;
      }
      if ((flags & 4) !== 0) return handle;
      return 0x00008200;
    }
    case "CreateMenu":
      return user.createMenu();
    case "AppendMenuA":
      return user.appendMenu(argument[0], argument[1], argument[2], argument[3] ?? "");
    case "SetMenu":
      return user.setMenu(argument[0], argument[1]);
    case "CheckMenuItem":
      return user.checkMenuItem(argument[0], argument[1], argument[2]);
    case "CheckMenuRadioItem":
      return user.checkMenuRadioItem(argument[0], argument[1], argument[2], argument[3], argument[4]);
    case "EnableMenuItem":
      return user.enableMenuItem(argument[0], argument[1], argument[2]);
    case "SetTimer":
      return user.setTimer(argument[0], argument[1], argument[2]);
    case "KillTimer":
      return user.killTimer(argument[0], argument[1]);
    case "GetMessageTime":
      return 0;
    case "MapDialogRect":
      return user.mapDialogRect(4, 8, 8, 16) !== null ? 1 : 0;
    case "MessageBeep":
      return 1;
    case "MessageBoxA":
    case "MessageBoxIndirectA":
      return user.messageBox(argument[0] ?? "", argument[1] ?? "", argument[2] ?? 0);
    case "IsDialogMessageA":
      return user.isDialogMessage(argument[0], argument[1] ?? {});
    case "EndDialog":
      return user.endDialog(argument[0], argument[1]);
    case "CreateDialogParamA":
    case "DialogBoxParamA":
      return 0;
    default:
      return null;
  }
}

function userConformanceImplementation() {
  return (library, symbol, input) => {
    const user = createUserSubsystem();
    const argument = Array.isArray(input) ? input : input.argument ?? [];
    for (const step of Array.isArray(input) ? [] : input.scenario ?? []) {
      applyUserOp(user, step[0], step[1]);
    }
    const value = applyUserOp(user, symbol, argument);
    if (value === null) return { return_value: null, last_error: `The export ${library}!${symbol} is not served` };
    return { return_value: value >>> 0, last_error: user.getLastError() };
  };
}

function buildUserConformanceCase() {
  const caseList = [];
  let caseNumber = 0;
  function define(symbol, input, expected) {
    caseNumber += 1;
    caseList.push({ case_id: `USER-${String(caseNumber).padStart(3, "0")}`, library: "user32.dll", symbol, input, expected });
  }
  function defineLib(library, symbol, input, expected) {
    caseNumber += 1;
    caseList.push({ case_id: `USER-${String(caseNumber).padStart(3, "0")}`, library, symbol, input, expected });
  }
  const registerStep = ["RegisterClassW", ["AppClass", 0]];
  const createStep = ["CreateWindowExW", ["AppClass", 0]];
  const showStep = ["ShowWindow", [FIRST_HANDLE, showCommand.SW_SHOWNORMAL]];

  define("RegisterClassW", { argument: ["AppClass", 0] }, { return_value: FIRST_ATOM, last_error: 0 });
  define("RegisterClassExW", { argument: ["AppClass", 0] }, { return_value: FIRST_ATOM, last_error: 0 });
  define("RegisterClassExA", { argument: ["AppClass", 0] }, { return_value: FIRST_ATOM, last_error: 0 });
  define("GetClassInfoExW", { argument: ["AppClass", 0] }, { return_value: 0, last_error: 87 });
  define("GetClassInfoExW", { argument: ["Missing", 1] }, { return_value: 0, last_error: 0x583 });
  define("GetClassInfoExW", { scenario: [registerStep], argument: ["AppClass", 1] }, { return_value: 1, last_error: 0 });
  define("GetClassInfoExA", { scenario: [registerStep], argument: ["AppClass", 1] }, { return_value: 1, last_error: 0 });
  define("GetClassInfoW", { scenario: [registerStep], argument: ["AppClass", 1] }, { return_value: 1, last_error: 0 });
  define("GetClassInfoA", { scenario: [registerStep], argument: ["AppClass", 1] }, { return_value: 1, last_error: 0 });
  define("UnregisterClassW", { scenario: [registerStep], argument: ["AppClass"] }, { return_value: 1, last_error: 0 });
  define("UnregisterClassA", { scenario: [registerStep], argument: ["AppClass"] }, { return_value: 1, last_error: 0 });
  define("CreateWindowExW", { scenario: [registerStep], argument: ["AppClass", 0] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("DestroyWindow", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE] }, { return_value: 1, last_error: 0 });
  define("DefWindowProcW", { argument: [0, windowMessage.WM_NULL, 0, 0] }, { return_value: 0, last_error: 0 });
  define("ShowWindow", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, showCommand.SW_SHOWNORMAL] }, { return_value: 0, last_error: 0 });
  define("UpdateWindow", { scenario: [registerStep, createStep, showStep], argument: [FIRST_HANDLE] }, { return_value: 1, last_error: 0 });
  define("PostMessageW", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, windowMessage.WM_NULL, 0, 0] }, { return_value: 1, last_error: 0 });
  define("SendMessageW", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, windowMessage.WM_NULL, 0, 0] }, { return_value: 0, last_error: 0 });
  define("PostQuitMessage", { argument: [0] }, { return_value: 0, last_error: 0 });
  define("GetActiveWindow", { scenario: [registerStep, createStep, showStep], argument: [] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("GetFocus", { scenario: [registerStep, createStep, showStep], argument: [] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("IsWindow", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE] }, { return_value: 1, last_error: 0 });

  // message loop and geometry (BPTK-011)
  const postStep = ["PostMessageW", [FIRST_HANDLE, 0x0400, 1, 2]]; // WM_USER
  define("GetMessageW", { scenario: [registerStep, createStep, postStep], argument: [] }, { return_value: 1, last_error: 0 });
  define("GetMessageW", { scenario: [registerStep, createStep, ["PostQuitMessage", [0]]], argument: [] }, { return_value: 0, last_error: 0 });
  define("GetMessageW", { scenario: [registerStep, createStep], argument: [] }, { return_value: (-1) >>> 0, last_error: 0 });
  define("PeekMessageW", { scenario: [registerStep, createStep, postStep], argument: [1] }, { return_value: 1, last_error: 0 });
  define("PeekMessageW", { scenario: [registerStep, createStep], argument: [1] }, { return_value: 0, last_error: 0 });
  define("TranslateMessage", { argument: [{ handle: 0, message: windowMessage.WM_KEYDOWN, w_param: 0x41, l_param: 1 }] }, { return_value: 1, last_error: 0 });
  define("TranslateMessage", { argument: [{ handle: 0, message: windowMessage.WM_NULL, w_param: 0, l_param: 0 }] }, { return_value: 0, last_error: 0 });
  define("DispatchMessageW", { scenario: [registerStep, createStep], argument: [{ handle: FIRST_HANDLE, message: windowMessage.WM_NULL, w_param: 0, l_param: 0 }] }, { return_value: 0, last_error: 0 });
  define("GetClientRect", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE] }, { return_value: 1, last_error: 0 });
  define("GetWindowRect", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE] }, { return_value: 1, last_error: 0 });
  define("GetClientRect", { argument: [0xdeadbeef] }, { return_value: 0, last_error: 0 });
  define("ClientToScreen", { argument: [FIRST_HANDLE, 0] }, { return_value: 0, last_error: 87 });
  define("ClientToScreen", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, 1] }, { return_value: 1, last_error: 0 });
  define("ClientToScreen", { argument: [0xdeadbeef, 1] }, { return_value: 0, last_error: 0 });
  define("ScreenToClient", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, 1] }, { return_value: 1, last_error: 0 });
  define("MoveWindow", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, 10, 20, 100, 200, 1] }, { return_value: 1, last_error: 0 });
  define("AdjustWindowRect", { argument: [0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("AdjustWindowRectEx", { argument: [0, 0, 0, 0] }, { return_value: 0, last_error: 87 });
  define("AdjustWindowRectEx", { argument: [1, 0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("GetSystemMetrics", { argument: [0] }, { return_value: 1920, last_error: 0 });
  define("GetSystemMetrics", { argument: [1] }, { return_value: 1080, last_error: 0 });
  define("GetSystemMetrics", { argument: [99] }, { return_value: 0, last_error: 0 });
  define("GetDoubleClickTime", { argument: [] }, { return_value: 500, last_error: 0 });
  define("MapVirtualKeyW", { argument: [0x1e, 1] }, { return_value: 0x41, last_error: 0 });
  define("MapVirtualKeyW", { argument: [0x41, 2] }, { return_value: 0x41, last_error: 0 });
  define("MapVirtualKeyA", { argument: [0xff, 1] }, { return_value: 0, last_error: 0 });
  define("ToUnicode", { argument: [0x20, 0x39, 0, 0, 16, 0] }, { return_value: 0, last_error: 87 });
  define("ToUnicode", { argument: [0x20, 0x39, 1, 1, 16, 0] }, { return_value: 1, last_error: 0 });
  define("ToUnicode", { argument: [0xff, 0, 1, 1, 16, 0] }, { return_value: 0, last_error: 0 });
  define("EnumDisplayMonitors", { argument: [0, 0, 0, 0] }, { return_value: 0, last_error: 87 });
  define("EnumDisplayMonitors", { argument: [0, 0, 0x00401000, 0] }, { return_value: 1, last_error: 0 });
  define("GetMonitorInfoW", { argument: [0x00020000, 0] }, { return_value: 0, last_error: 87 });
  define("GetMonitorInfoW", { argument: [0xdeadbeef, 1] }, { return_value: 0, last_error: 6 });
  define("GetMonitorInfoA", { argument: [0xdeadbeef, 1] }, { return_value: 0, last_error: 6 });
  define("EnumDisplaySettingsW", { argument: [0, 0xffffffff, 0] }, { return_value: 0, last_error: 87 });
  define("EnumDisplaySettingsW", { argument: [0, 0xffffffff, 1] }, { return_value: 1, last_error: 0 });
  define("EnumDisplaySettingsA", { argument: [0, 1, 1] }, { return_value: 0, last_error: 0 });
  define("EnumDisplayDevicesW", { argument: [0, 0, 0, 0] }, { return_value: 0, last_error: 87 });
  define("EnumDisplayDevicesW", { argument: [0, 0, 1, 0] }, { return_value: 1, last_error: 0 });
  define("EnumDisplayDevicesA", { argument: [0, 1, 1, 0] }, { return_value: 0, last_error: 0 });

  // Plink import-surface widening (BPTK-146): the window, input, and message
  // queries the startup path probes. With no window and no host input device
  // the answer is the honest empty result.
  define("FindWindowA", { argument: [0, 0] }, { return_value: 0, last_error: 0 });
  define("GetCapture", { argument: [] }, { return_value: 0, last_error: 0 });
  define("GetKeyState", { argument: [0x14] }, { return_value: 0, last_error: 0 });
  define("GetAsyncKeyState", { argument: [0x11] }, { return_value: 0, last_error: 0 });
  define("GetKeyState", { scenario: [["injectKey", [0x41, 1]]], argument: [0x41] }, { return_value: 0x8000, last_error: 0 });
  define("GetAsyncKeyState", { scenario: [["injectKey", [0x11, 1]]], argument: [0x11] }, { return_value: 0x8001, last_error: 0 });
  define("GetKeyboardState", { argument: [0] }, { return_value: 0, last_error: 87 });
  define("GetKeyboardState", { argument: [1] }, { return_value: 1, last_error: 0 });
  define("GetClipboardOwner", { argument: [] }, { return_value: 0, last_error: 0 });
  define("GetForegroundWindow", { argument: [] }, { return_value: 0, last_error: 0 });
  define("GetQueueStatus", { argument: [0x1ff] }, { return_value: 0, last_error: 0 });
  define("GetCursorPos", { argument: [0] }, { return_value: 1, last_error: 0 });
  define("MsgWaitForMultipleObjects", { argument: [0, 0, 0, 0, 0x1ff] }, { return_value: 0x102, last_error: 0 });
  define("PeekMessageA", { scenario: [registerStep, createStep], argument: [0, 0, 0, 0, 1] }, { return_value: 0, last_error: 0 });
  define("SendMessageA", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, windowMessage.WM_NULL, 0, 0] }, { return_value: 0, last_error: 0 });
  const registerAnsiStep = ["RegisterClassA", ["AppClass", 0]];
  const createAnsiStep = ["CreateWindowExA", ["AppClass", 0]];
  define("RegisterClassA", { argument: ["AppClass", 0] }, { return_value: FIRST_ATOM, last_error: 0 });
  define("CreateWindowExA", { scenario: [registerAnsiStep], argument: ["AppClass", 0] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("GetMessageA", { scenario: [registerAnsiStep, createAnsiStep], argument: [] }, { return_value: (-1) >>> 0, last_error: 0 });
  define("DispatchMessageA", { scenario: [registerAnsiStep, createAnsiStep], argument: [{ handle: FIRST_HANDLE, message: windowMessage.WM_NULL, w_param: 0, l_param: 0 }] }, { return_value: 0, last_error: 0 });
  define("PostMessageA", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, windowMessage.WM_NULL, 0, 0] }, { return_value: 1, last_error: 0 });
  define("DefDlgProcA", { argument: [0, windowMessage.WM_NULL, 0, 0] }, { return_value: 0, last_error: 0 });
  define("GetWindowTextA", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE] }, { return_value: 0, last_error: 0 });
  define("GetWindowTextLengthA", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE] }, { return_value: 0, last_error: 0 });
  define("SetWindowTextW", { argument: [0, "x"] }, { return_value: 0, last_error: 0x578 });
  define("SetWindowTextW", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, "SuperTux"] }, { return_value: 1, last_error: 0 });
  define("GetWindowTextW", { scenario: [registerStep, createStep, ["SetWindowTextW", [FIRST_HANDLE, "SuperTux"]]], argument: [FIRST_HANDLE] }, { return_value: 8, last_error: 0 });
  define("GetWindowTextLengthW", { scenario: [registerStep, createStep, ["SetWindowTextW", [FIRST_HANDLE, "SuperTux"]]], argument: [FIRST_HANDLE] }, { return_value: 8, last_error: 0 });
  define("SetWindowTextA", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, "SuperTux"] }, { return_value: 1, last_error: 0 });
  define("GetDlgItem", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 1] }, { return_value: 0, last_error: 0 });
  define("GetDlgItemTextA", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 1] }, { return_value: 0, last_error: 0x578 });
  define("SetDlgItemTextA", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 1, ""] }, { return_value: 0, last_error: 0x578 });
  define("GetDlgItemInt", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 1] }, { return_value: 0, last_error: 0x578 });
  define("SetDlgItemInt", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 1, 0] }, { return_value: 0, last_error: 0x578 });
  define("SendDlgItemMessageA", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 1, 0, 0, 0] }, { return_value: 0, last_error: 0x578 });
  define("IsDlgButtonChecked", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 1] }, { return_value: 0, last_error: 0 });
  define("CheckRadioButton", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 1, 2, 1] }, { return_value: 1, last_error: 0 });
  define("EnableWindow", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 0] }, { return_value: 1, last_error: 0 });
  define("GetWindowLongA", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, -16] }, { return_value: 0, last_error: 0 });
  define("GetWindowLongW", { argument: [0, -6] }, { return_value: 0, last_error: 0x578 });
  define("GetWindowLongW", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, -6] }, { return_value: 0, last_error: 0 });
  define("SetWindowLongA", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, -21, 9] }, { return_value: 0, last_error: 0 });
  define("SetWindowLongW", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, -21, 9] }, { return_value: 0, last_error: 0 });
  define("SetPropW", { argument: [0, 0, 0] }, { return_value: 0, last_error: 87 });
  define("SetPropW", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, "SDL", 0x1234] }, { return_value: 1, last_error: 0 });
  define("GetPropW", { scenario: [registerStep, createStep, ["SetPropW", [FIRST_HANDLE, "SDL", 0x1234]]], argument: [FIRST_HANDLE, "SDL"] }, { return_value: 0x1234, last_error: 0 });
  define("GetPropW", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, "SDL"] }, { return_value: 0, last_error: 0 });
  define("RemovePropW", { scenario: [registerStep, createStep, ["SetPropW", [FIRST_HANDLE, "SDL", 0x1234]]], argument: [FIRST_HANDLE, "SDL"] }, { return_value: 0x1234, last_error: 0 });
  define("SetPropA", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, "SDL", 0x55] }, { return_value: 1, last_error: 0 });
  define("GetPropA", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, "SDL"] }, { return_value: 0, last_error: 0 });
  define("RemovePropA", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, "SDL"] }, { return_value: 0, last_error: 0 });
  define("SetWindowPos", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 0, 1, 2, 10, 20, 0] }, { return_value: 1, last_error: 0 });
  define("SetActiveWindow", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE] }, { return_value: 0, last_error: 0 });
  define("SetForegroundWindow", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE] }, { return_value: 1, last_error: 0 });
  define("GetDesktopWindow", { argument: [] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("GetDC", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE] }, { return_value: 0x00040000, last_error: 0 });
  define("ReleaseDC", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 0x00040000] }, { return_value: 1, last_error: 0 });
  define("LoadCursorA", { argument: [0, 32512] }, { return_value: 0x00008000 | 32512, last_error: 0 });
  define("LoadCursorW", { argument: [0, 32512] }, { return_value: 0x00008000 | 32512, last_error: 0 });
  define("LoadIconA", { argument: [0, 32512] }, { return_value: 0x00008100 | 32512, last_error: 0 });
  define("LoadIconW", { argument: [0, 32512] }, { return_value: 0x00008100 | 32512, last_error: 0 });
  define("CreateIconIndirect", { argument: [0] }, { return_value: 0, last_error: 87 });
  define("CreateIconIndirect", { argument: [1] }, { return_value: 0x00008200, last_error: 0 });
  define("CreateIconFromResource", { argument: [0, 40, 1, 0x00030000] }, { return_value: 0, last_error: 87 });
  define("CreateIconFromResource", { argument: [1, 0, 1, 0x00030000] }, { return_value: 0, last_error: 87 });
  define("CreateIconFromResource", { argument: [1, 40, 1, 0] }, { return_value: 0, last_error: 87 });
  define("CreateIconFromResource", { argument: [1, 40, 1, 0x00030000] }, { return_value: 0x00008200, last_error: 0 });
  define("CreateIconFromResourceEx", { argument: [0, 40, 1, 0x00030000, 0, 0, 0] }, { return_value: 0, last_error: 87 });
  define("CreateIconFromResourceEx", { argument: [1, 40, 1, 0x00030000, 32, 32, 0] }, { return_value: 0x00008200, last_error: 0 });
  define("DestroyIcon", { argument: [0x00008200] }, { return_value: 1, last_error: 0 });
  define("CopyImage", { argument: [0, 2, 0, 0, 0] }, { return_value: 0, last_error: 87 });
  define("CopyImage", { argument: [0x00008000 | 32512, 2, 0, 0, 4] }, { return_value: 0x00008000 | 32512, last_error: 0 });
  define("CopyImage", { argument: [0x00008000 | 32512, 2, 0, 0, 0] }, { return_value: 0x00008200, last_error: 0 });
  define("CopyImage", { argument: [0x00008000 | 32512, 2, 32, 32, 0] }, { return_value: 0x00008200, last_error: 0 });
  define("CopyImage", { argument: [0x1234, 2, 0, 0, 0] }, { return_value: 0, last_error: 6 });
  define("SystemParametersInfoW", { argument: [0x70, 0, 1, 0] }, { return_value: 1, last_error: 0 });
  define("SystemParametersInfoW", { argument: [3, 0, 1, 0] }, { return_value: 1, last_error: 0 });
  define("SystemParametersInfoW", { argument: [0x70, 0, 0, 0] }, { return_value: 0, last_error: 87 });
  define("SystemParametersInfoW", { argument: [0x9999, 0, 1, 0] }, { return_value: 0, last_error: 87 });
  define("SystemParametersInfoA", { argument: [0x70, 0, 1, 0] }, { return_value: 1, last_error: 0 });
  define("RegisterWindowMessageA", { argument: [0] }, { return_value: 0, last_error: 87 });
  define("RegisterWindowMessageA", { argument: [1] }, { return_value: 0x0000c000, last_error: 0 });
  define("RegisterWindowMessageW", { argument: [1] }, { return_value: 0x0000c000, last_error: 0 });
  define("CreateMenu", { argument: [] }, { return_value: 0x00030000, last_error: 0 });
  define("AppendMenuA", { scenario: [["CreateMenu", []]], argument: [0x00030000, 0, 1, ""] }, { return_value: 1, last_error: 0 });
  define("SetMenu", { scenario: [registerAnsiStep, createAnsiStep, ["CreateMenu", []]], argument: [FIRST_HANDLE, 0x00030000] }, { return_value: 1, last_error: 0 });
  define("CheckMenuItem", { scenario: [["CreateMenu", []], ["AppendMenuA", [0x00030000, 0, 1, ""]]], argument: [0x00030000, 1, 8] }, { return_value: 0, last_error: 0 });
  define("CheckMenuRadioItem", { scenario: [["CreateMenu", []], ["AppendMenuA", [0x00030000, 0, 1, ""]]], argument: [0x00030000, 1, 1, 1, 0] }, { return_value: 1, last_error: 0 });
  define("EnableMenuItem", { scenario: [["CreateMenu", []], ["AppendMenuA", [0x00030000, 0, 1, ""]]], argument: [0x00030000, 1, 1] }, { return_value: 0, last_error: 0 });
  define("SetTimer", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 1, 10] }, { return_value: 1, last_error: 0 });
  define("KillTimer", { scenario: [registerAnsiStep, createAnsiStep, ["SetTimer", [FIRST_HANDLE, 1, 10]]], argument: [FIRST_HANDLE, 1] }, { return_value: 1, last_error: 0 });
  define("GetMessageTime", { argument: [] }, { return_value: 0, last_error: 0 });
  define("MapDialogRect", { argument: [] }, { return_value: 1, last_error: 0 });
  define("MessageBeep", { argument: [0] }, { return_value: 1, last_error: 0 });
  define("MessageBoxA", { argument: ["ok", "", 0] }, { return_value: 1, last_error: 0 });
  define("MessageBoxIndirectA", { argument: ["ok", "", 0] }, { return_value: 1, last_error: 0 });
  define("IsDialogMessageA", { argument: [0, {}] }, { return_value: 0, last_error: 0 });
  define("EndDialog", { argument: [0, 1] }, { return_value: 0, last_error: 0x578 });
  define("CreateDialogParamA", { argument: [0, 1, 0, 0, 0] }, { return_value: 0, last_error: 0 });
  define("DialogBoxParamA", { argument: [0, 1, 0, 0, 0] }, { return_value: 0, last_error: 0 });
  define("DialogBoxParamW", { argument: [0, 1, 0, 0, 0] }, { return_value: 0, last_error: 0 });
  define("SetRect", { argument: [1, 0, 0, 10, 10] }, { return_value: 1, last_error: 0 });
  define("SetRectEmpty", { argument: [1] }, { return_value: 1, last_error: 0 });
  define("OffsetRect", { argument: [1, 1, 1] }, { return_value: 1, last_error: 0 });
  define("UnionRect", { argument: [1, 1, 1] }, { return_value: 1, last_error: 0 });
  define("PtInRect", { argument: [1, 1, 1] }, { return_value: 1, last_error: 0 });
  define("MapWindowPoints", { argument: [0, 0, 0, 0] }, { return_value: 0, last_error: 0 });
  define("SetCapture", { argument: [0] }, { return_value: 0, last_error: 0 });
  define("ReleaseCapture", { argument: [] }, { return_value: 1, last_error: 0 });
  define("ShowCursor", { argument: [1] }, { return_value: 1, last_error: 0 });
  define("ShowCursor", { argument: [0] }, { return_value: 0xffffffff, last_error: 0 });
  define("SetCursorPos", { argument: [10, 20] }, { return_value: 1, last_error: 0 });
  define("GetWindowDC", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE] }, { return_value: 0x00040000, last_error: 0 });
  define("GetDCEx", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 0, 0] }, { return_value: 0x00040000, last_error: 0 });
  define("InvalidateRect", { argument: [0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("ValidateRect", { argument: [0, 0] }, { return_value: 1, last_error: 0 });
  define("GetUpdateRect", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 0, 0] }, { return_value: 1, last_error: 0 });
  define("BeginPaint", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 0] }, { return_value: 0x00040000, last_error: 0 });
  define("EndPaint", { argument: [0, 0] }, { return_value: 1, last_error: 0 });
  define("OpenClipboard", { argument: [0] }, { return_value: 1, last_error: 0 });
  define("CloseClipboard", { argument: [] }, { return_value: 1, last_error: 0 });
  define("IsClipboardFormatAvailable", { argument: [1] }, { return_value: 0, last_error: 0 });
  define("GetClipboardData", { argument: [1] }, { return_value: 0, last_error: 0 });
  define("GetKeyboardLayout", { argument: [0] }, { return_value: 0x04090409, last_error: 0 });
  define("WindowFromPoint", { argument: [0, 0] }, { return_value: FIRST_HANDLE, last_error: 0 });
  define("ChangeDisplaySettingsW", { argument: [0, 0] }, { return_value: 0, last_error: 0 });
  define("MessageBoxW", { argument: ["ok", "", 0] }, { return_value: 1, last_error: 0 });
  define("SetDlgItemTextW", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 1, ""] }, { return_value: 0, last_error: 0x578 });
  define("SendDlgItemMessageW", { scenario: [registerAnsiStep, createAnsiStep], argument: [FIRST_HANDLE, 1, 0, 0, 0] }, { return_value: 0, last_error: 0x578 });

  defineLib("comctl32.dll", "InitCommonControls", { argument: [] }, { return_value: 0, last_error: 0 });
  defineLib("comctl32.dll", "InitCommonControlsEx", { argument: [0] }, { return_value: 1, last_error: 0 });

  return caseList;
}

test("conformance: every served USER32 export carries a case and matches the oracle", () => {
  const caseTable = buildUserConformanceCase();
  const report = runConformanceSuite(caseTable, userConformanceImplementation(), {
    served_export: userExportTable.map((entry) => `${entry.library}!${entry.symbol}`),
  });
  assert.equal(report.is_coverage_complete, true, `uncovered: ${report.uncovered_export.join(", ")}`);
  assert.equal(report.fail_count, 0, report.result.filter((entry) => !entry.pass).map((entry) => `${entry.case_id}: ${entry.mismatch.join("; ")}`).join("\n"));
  assert.equal(report.pass_count, caseTable.length);
});
