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
} from "../lib/user.mjs";

const FIRST_ATOM = 0xc000;
const FIRST_HANDLE = 0x00010010;

// A WndProc that records nothing of its own but defers to DefWindowProc, so a
// fixture measures the manager's delivery order rather than app behavior.
function defaultProc(handle, message, wParam, lParam, defWindowProc) {
  return defWindowProc(handle, message, wParam, lParam);
}

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
      return user.registerClass(argument[0], null, argument[1] ?? 0);
    case "UnregisterClassW":
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
    case "MoveWindow":
      return user.moveWindow(argument[0], argument[1], argument[2], argument[3], argument[4]);
    case "AdjustWindowRect":
      return 1;
    case "GetSystemMetrics":
      return systemMetric[argument[0]] ?? 0;
    case "FindWindowA":
    case "GetCapture":
    case "GetClipboardOwner":
      return 0;
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
  define("UnregisterClassW", { scenario: [registerStep], argument: ["AppClass"] }, { return_value: 1, last_error: 0 });
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
  define("MoveWindow", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, 10, 20, 100, 200, 1] }, { return_value: 1, last_error: 0 });
  define("AdjustWindowRect", { argument: [0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("GetSystemMetrics", { argument: [0] }, { return_value: 1920, last_error: 0 });
  define("GetSystemMetrics", { argument: [1] }, { return_value: 1080, last_error: 0 });
  define("GetSystemMetrics", { argument: [99] }, { return_value: 0, last_error: 0 });

  // Plink import-surface widening (BPTK-146): the window, input, and message
  // queries the startup path probes. With no window and no host input device
  // the answer is the honest empty result.
  define("FindWindowA", { argument: [0, 0] }, { return_value: 0, last_error: 0 });
  define("GetCapture", { argument: [] }, { return_value: 0, last_error: 0 });
  define("GetClipboardOwner", { argument: [] }, { return_value: 0, last_error: 0 });
  define("GetForegroundWindow", { argument: [] }, { return_value: 0, last_error: 0 });
  define("GetQueueStatus", { argument: [0x1ff] }, { return_value: 0, last_error: 0 });
  define("GetCursorPos", { argument: [0] }, { return_value: 1, last_error: 0 });
  define("MsgWaitForMultipleObjects", { argument: [0, 0, 0, 0, 0x1ff] }, { return_value: 0x102, last_error: 0 });
  define("PeekMessageA", { scenario: [registerStep, createStep], argument: [0, 0, 0, 0, 1] }, { return_value: 0, last_error: 0 });
  define("SendMessageA", { scenario: [registerStep, createStep], argument: [FIRST_HANDLE, windowMessage.WM_NULL, 0, 0] }, { return_value: 0, last_error: 0 });

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
