// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The USER32 windowing, message-loop, and input slice (BPTK-011). One generic
// window manager: a class registry, a window table, a per-thread message
// queue, the create/destroy lifecycle, DefWindowProc, the GetMessage /
// PeekMessage / TranslateMessage / DispatchMessage loop, and a deterministic
// input translator that turns a keyboard/mouse trace into the exact WM_*
// sequence. Nothing here branches on a title identity — a window is a window.
//
// The subsystem is host-side state. A WndProc is a callback the caller
// supplies per class; DefWindowProc is provided for the default path. When the
// CPU core and thread core land, the guest-code WndProc pointer is invoked
// through them and the per-thread queue keys on the real thread registry; the
// binding is one wiring row (see doc/user-gdi-log.md). Until then the queue
// keys on the single declared guest thread id so the fixture stays exact.

import { InputError } from "./input.mjs";
import { compositorMetric } from "./gdi.mjs";

function userFault(code, message) {
  return new InputError(code, message);
}

// The bounds the window manager refuses to exceed, so a runaway class or
// window count fails loudly instead of exhausting host memory.
export const userBound = Object.freeze({
  class_count: 512,
  window_count: 4096,
  message_count: 8192,
  string_byte: 256,
  property_count: 64,
  thread_id_default: 0x00001000,
});

// The window message the slice recognizes by name. Every value is the exact
// Win32 constant so a guest import and a fixture read the same number.
export const windowMessage = Object.freeze({
  WM_NULL: 0x0000,
  WM_CREATE: 0x0001,
  WM_DESTROY: 0x0002,
  WM_MOVE: 0x0003,
  WM_SIZE: 0x0005,
  WM_ACTIVATE: 0x0006,
  WM_SETFOCUS: 0x0007,
  WM_KILLFOCUS: 0x0008,
  WM_PAINT: 0x000f,
  WM_CLOSE: 0x0010,
  WM_QUIT: 0x0012,
  WM_INITDIALOG: 0x0110,
  WM_COMMAND: 0x0111,
  WM_ERASEBKGND: 0x0014,
  WM_SHOWWINDOW: 0x0018,
  WM_ACTIVATEAPP: 0x001c,
  WM_NCCREATE: 0x0081,
  WM_NCDESTROY: 0x0082,
  WM_KEYDOWN: 0x0100,
  WM_KEYUP: 0x0101,
  WM_CHAR: 0x0102,
  WM_SYSKEYDOWN: 0x0104,
  WM_SYSKEYUP: 0x0105,
  WM_TIMER: 0x0113,
  WM_MOUSEMOVE: 0x0200,
  WM_LBUTTONDOWN: 0x0201,
  WM_LBUTTONUP: 0x0202,
  WM_LBUTTONDBLCLK: 0x0203,
  WM_RBUTTONDOWN: 0x0204,
  WM_RBUTTONUP: 0x0205,
  WM_MBUTTONDOWN: 0x0207,
  WM_MBUTTONUP: 0x0208,
});

// ShowWindow command the lifecycle honors.
export const showCommand = Object.freeze({
  SW_HIDE: 0,
  SW_SHOWNORMAL: 1,
  SW_SHOW: 5,
});

// The activation state carried in WM_ACTIVATE wParam.
const activateState = Object.freeze({ WA_INACTIVE: 0, WA_ACTIVE: 1 });

// The pointer button and its down/up message pair, keyed by the button name
// the input trace uses. The generic translator reads this table, never a
// per-title special case.
const pointerButton = Object.freeze({
  left: { down: windowMessage.WM_LBUTTONDOWN, up: windowMessage.WM_LBUTTONUP },
  right: { down: windowMessage.WM_RBUTTONDOWN, up: windowMessage.WM_RBUTTONUP },
  middle: { down: windowMessage.WM_MBUTTONDOWN, up: windowMessage.WM_MBUTTONUP },
});

function makePoint(x, y) {
  return ((y & 0xffff) << 16 | (x & 0xffff)) >>> 0;
}

// A minimal, deterministic VK -> character map for the trace translator. Only
// the printable subset the fixture exercises is mapped; an unmapped key still
// posts WM_KEYDOWN/WM_KEYUP but yields no WM_CHAR, exactly as a dead key does.
// US 101 set-1 scan code, virtual-key, unshifted MapVirtualKey character.
// One virtual keyboard; no host layout is read. An unlisted code maps to 0.
const scanVirtualKey = Object.freeze([
  [0x01, 0x1b, 0x1b], [0x0e, 0x08, 0x08], [0x0f, 0x09, 0x09], [0x1c, 0x0d, 0x0d],
  [0x39, 0x20, 0x20],
  [0x02, 0x31, 0x31], [0x03, 0x32, 0x32], [0x04, 0x33, 0x33], [0x05, 0x34, 0x34], [0x06, 0x35, 0x35],
  [0x07, 0x36, 0x36], [0x08, 0x37, 0x37], [0x09, 0x38, 0x38], [0x0a, 0x39, 0x39], [0x0b, 0x30, 0x30],
  [0x10, 0x51, 0x51], [0x11, 0x57, 0x57], [0x12, 0x45, 0x45], [0x13, 0x52, 0x52], [0x14, 0x54, 0x54],
  [0x15, 0x59, 0x59], [0x16, 0x55, 0x55], [0x17, 0x49, 0x49], [0x18, 0x4f, 0x4f], [0x19, 0x50, 0x50],
  [0x1e, 0x41, 0x41], [0x1f, 0x53, 0x53], [0x20, 0x44, 0x44], [0x21, 0x46, 0x46], [0x22, 0x47, 0x47],
  [0x23, 0x48, 0x48], [0x24, 0x4a, 0x4a], [0x25, 0x4b, 0x4b], [0x26, 0x4c, 0x4c],
  [0x2c, 0x5a, 0x5a], [0x2d, 0x58, 0x58], [0x2e, 0x43, 0x43], [0x2f, 0x56, 0x56], [0x30, 0x42, 0x42],
  [0x31, 0x4e, 0x4e], [0x32, 0x4d, 0x4d],
  [0x1d, 0x11, 0], [0x2a, 0x10, 0], [0x36, 0x10, 0], [0x38, 0x12, 0],
  [0x3a, 0x14, 0], [0x3b, 0x70, 0], [0x3c, 0x71, 0], [0x3d, 0x72, 0], [0x3e, 0x73, 0],
  [0x3f, 0x74, 0], [0x40, 0x75, 0], [0x41, 0x76, 0], [0x42, 0x77, 0], [0x43, 0x78, 0], [0x44, 0x79, 0],
  [0x57, 0x7a, 0], [0x58, 0x7b, 0],
  [0x47, 0x24, 0], [0x48, 0x26, 0], [0x49, 0x21, 0], [0x4b, 0x25, 0], [0x4d, 0x27, 0],
  [0x4f, 0x23, 0], [0x50, 0x28, 0], [0x51, 0x22, 0], [0x52, 0x2d, 0], [0x53, 0x2e, 0],
]);
const scanToVirtualKey = Object.freeze(Object.fromEntries(scanVirtualKey.map((row) => [row[0], row[1]])));
const virtualKeyToScan = Object.freeze(Object.fromEntries(scanVirtualKey.map((row) => [row[1], row[0]])));
const mapVirtualKeyChar = Object.freeze(Object.fromEntries(scanVirtualKey.filter((row) => row[2] !== 0).map((row) => [row[1], row[2]])));

export function mapVirtualKey(code, mapType) {
  const value = code & 0xff;
  if (mapType === 0 || mapType === 4) return virtualKeyToScan[value] ?? 0;
  if (mapType === 1 || mapType === 3) return scanToVirtualKey[value] ?? 0;
  if (mapType === 2) return mapVirtualKeyChar[value] ?? 0;
  return 0;
}

// Browser KeyboardEvent.code → Win32 virtual-key. One generic US 101 map; an
// unknown code is 0 so the host can ignore it. No title branch.
const domCodeVirtualKey = Object.freeze({
  Escape: 0x1b, Enter: 0x0d, NumpadEnter: 0x0d, Space: 0x20, Tab: 0x09, Backspace: 0x08,
  ArrowLeft: 0x25, ArrowUp: 0x26, ArrowRight: 0x27, ArrowDown: 0x28,
  ControlLeft: 0xa2, ControlRight: 0xa3, ShiftLeft: 0xa0, ShiftRight: 0xa1,
  AltLeft: 0xa4, AltRight: 0xa5, CapsLock: 0x14,
  Delete: 0x2e, Insert: 0x2d, Home: 0x24, End: 0x23, PageUp: 0x21, PageDown: 0x22,
  Minus: 0xbd, Equal: 0xbb, BracketLeft: 0xdb, BracketRight: 0xdd, Backslash: 0xdc,
  Semicolon: 0xba, Quote: 0xde, Backquote: 0xc0, Comma: 0xbc, Period: 0xbe, Slash: 0xbf,
});

export function virtualKeyFromDomCode(code) {
  if (typeof code !== "string" || code.length === 0) return 0;
  if (code.startsWith("Key") && code.length === 4) {
    const letter = code.charCodeAt(3);
    if (letter >= 0x41 && letter <= 0x5a) return letter;
  }
  if (code.startsWith("Digit") && code.length === 6) {
    const digit = code.charCodeAt(5);
    if (digit >= 0x30 && digit <= 0x39) return digit;
  }
  if (code.startsWith("Numpad") && code.length === 7) {
    const digit = code.charCodeAt(6);
    if (digit >= 0x30 && digit <= 0x39) return 0x60 + (digit - 0x30);
  }
  if (code[0] === "F") {
    const index = Number.parseInt(code.slice(1), 10);
    if (index >= 1 && index <= 24) return 0x6f + index;
  }
  return domCodeVirtualKey[code] ?? 0;
}

export function pointerButtonFromDom(button) {
  if (button === 0) return "left";
  if (button === 1) return "middle";
  if (button === 2) return "right";
  return null;
}

const vkShift = 0x10;
const vkControl = 0x11;
const vkMenu = 0x12;
const vkCapital = 0x14;
const shiftedDigit = Object.freeze({
  0x30: 0x29, 0x31: 0x21, 0x32: 0x40, 0x33: 0x23, 0x34: 0x24,
  0x35: 0x25, 0x36: 0x5e, 0x37: 0x26, 0x38: 0x2a, 0x39: 0x28,
});
const oemGlyph = Object.freeze({
  0xba: [0x3b, 0x3a], 0xbb: [0x3d, 0x2b], 0xbc: [0x2c, 0x3c], 0xbd: [0x2d, 0x5f],
  0xbe: [0x2e, 0x3e], 0xbf: [0x2f, 0x3f], 0xc0: [0x60, 0x7e],
  0xdb: [0x5b, 0x7b], 0xdc: [0x5c, 0x7c], 0xdd: [0x5d, 0x7d], 0xde: [0x27, 0x22],
});

function keyStateByte(keyState, virtualKey) {
  if (keyState == null) return 0;
  return (keyState[virtualKey & 0xff] ?? 0) & 0xff;
}

// US 101 ToUnicode: one wchar from the virtual key and the 256-byte key table.
// Ctrl/Alt produce no character. Shift and Caps Lock apply; no dead key is stored.
export function toUnicode(virtualKey, _scanCode, keyState) {
  const vk = virtualKey & 0xff;
  if ((keyStateByte(keyState, vkControl) & 0x80) !== 0) return 0;
  if ((keyStateByte(keyState, vkMenu) & 0x80) !== 0) return 0;
  const is_shift = (keyStateByte(keyState, vkShift) & 0x80) !== 0;
  const is_caps = (keyStateByte(keyState, vkCapital) & 0x01) !== 0;
  if (vk >= 0x41 && vk <= 0x5a) return is_shift !== is_caps ? vk : vk + 0x20;
  if (vk >= 0x30 && vk <= 0x39) return is_shift ? shiftedDigit[vk] : vk;
  const oem = oemGlyph[vk];
  if (oem !== undefined) return is_shift ? oem[1] : oem[0];
  return virtualKeyChar[vk] ?? mapVirtualKeyChar[vk] ?? 0;
}

const virtualKeyChar = Object.freeze({
  0x0d: 0x0d, // VK_RETURN -> carriage return
  0x20: 0x20, // VK_SPACE
  0x30: 0x30, 0x31: 0x31, 0x32: 0x32, 0x33: 0x33, 0x34: 0x34,
  0x35: 0x35, 0x36: 0x36, 0x37: 0x37, 0x38: 0x38, 0x39: 0x39,
  0x41: 0x61, 0x42: 0x62, 0x43: 0x63, 0x44: 0x64, 0x45: 0x65,
  0x46: 0x66, 0x47: 0x67, 0x48: 0x68, 0x49: 0x69, 0x4a: 0x6a,
  0x4b: 0x6b, 0x4c: 0x6c, 0x4d: 0x6d, 0x4e: 0x6e, 0x4f: 0x6f,
  0x50: 0x70, 0x51: 0x71, 0x52: 0x72, 0x53: 0x73, 0x54: 0x74,
  0x55: 0x75, 0x56: 0x76, 0x57: 0x77, 0x58: 0x78, 0x59: 0x79, 0x5a: 0x7a,
});

// --- dialog units -> pixels ------------------------------------------------
// A RT_DIALOG template positions its frame and every control in dialog units
// (DLU), not pixels: 4 horizontal DLU span one average character width and 8
// vertical DLU span one character height, both measured from the dialog font.
// The window manager instantiates real windows, which are pixel-addressed, so
// the template geometry is converted here — exactly where CreateDialogIndirect
// maps a template to windows. The base unit pair (pixels per that DLU quantum)
// derives from the font: MS Sans Serif 8pt — the classic dialog font, and the
// default a template that names no font is drawn with — measures ~6px average
// character width and ~13px character height, so (baseX, baseY) = (6, 13). A
// template that names a font scales that 8pt reference by its point size, so the
// conversion tracks the font rather than any one program's pixel coordinates.
export const defaultDialogBaseUnit = Object.freeze({ x: 6, y: 13, reference_point_size: 8 });

// MulDiv(value, numerator, denominator): (value*numerator)/denominator rounded
// to nearest, the rounding the Win32 dialog manager applies mapping DLU to px.
export function mulDiv(value, numerator, denominator) {
  if (denominator === 0) return 0;
  return Math.round((value * numerator) / denominator);
}

// The base unit pair for a template's font. With no font (or an unusable point
// size) the standard MS Sans Serif 8pt default holds; a named font scales the
// 8pt reference by its point size, keeping at least 1px so a rect stays valid.
export function dialogBaseUnit(font) {
  const point = font !== null && font !== undefined && Number.isFinite(font.point_size) && font.point_size > 0 ? font.point_size : null;
  if (point === null) return { x: defaultDialogBaseUnit.x, y: defaultDialogBaseUnit.y };
  return {
    x: Math.max(1, mulDiv(defaultDialogBaseUnit.x, point, defaultDialogBaseUnit.reference_point_size)),
    y: Math.max(1, mulDiv(defaultDialogBaseUnit.y, point, defaultDialogBaseUnit.reference_point_size)),
  };
}

// Convert a DLU geometry {x, y, cx, cy} to a pixel geometry {x, y, width,
// height} under the base unit pair: x/cx use the horizontal base over 4 DLU,
// y/cy the vertical base over 8 DLU — the standard MapDialogRect formula.
export function dialogRectToPixel(geometry, unit) {
  return {
    x: mulDiv(geometry.x | 0, unit.x, 4),
    y: mulDiv(geometry.y | 0, unit.y, 8),
    width: mulDiv(geometry.cx | 0, unit.x, 4),
    height: mulDiv(geometry.cy | 0, unit.y, 8),
  };
}

// ---------------------------------------------------------------------------
// The window manager. One instance per guest process; owns the class
// registry, the window table, the per-thread queue, and the focus/active
// tracking that the lifecycle and input translation both read.
// ---------------------------------------------------------------------------

export function createUserSubsystem(option = {}) {
  const threadId = option.thread_id ?? userBound.thread_id_default;

  const classByName = new Map();
  const windowByHandle = new Map();
  // Win32 class names are case-insensitive. A dialog template may register
  // "Button" while CreateWindowExA asks for "BUTTON"; both name the same class.
  function classKey(name) {
    return typeof name === "string" ? name.toLowerCase() : "";
  }
  const predefinedClass = new Set([
    "button", "edit", "static", "listbox", "scrollbar", "combobox",
    "#32770", "#32769",
    "msctls_progress32", "msctls_trackbar32", "msctls_updown32", "msctls_statusbar32",
    "msctls_hotkey32", "toolbarwindow32", "rebarwindow32",
    "syslistview32", "systreeview32", "systabcontrol32", "sysanimate32",
    "sysmonthcal32", "sysdatetimepick32", "sysipaddress32", "comboboxex32",
  ]);
  const queueByThread = new Map();
  let nextAtom = 0xc000;
  let nextHandle = 0x00010010;
  let activeWindow = 0;
  let focusWindow = 0;
  let lastError = 0;
  const keyState = new Uint8Array(256);
  const asyncPressed = new Uint8Array(256);
  const modifierChild = Object.freeze({
    0xa0: 0x10, 0xa1: 0x10,
    0xa2: 0x11, 0xa3: 0x11,
    0xa4: 0x12, 0xa5: 0x12,
  });
  const modifierSibling = Object.freeze({
    0x10: [0xa0, 0xa1],
    0x11: [0xa2, 0xa3],
    0x12: [0xa4, 0xa5],
  });
  const mouseVirtualKey = Object.freeze({ left: 0x01, right: 0x02, middle: 0x04 });

  // The ordered paint log: a snapshot of a window's geometry, class, and caption
  // captured the moment it is shown (ShowWindow) or its paint is flushed
  // (UpdateWindow / a synthesized WM_PAINT). It is what the compositor draws, so
  // the painted pixels persist on the display surface exactly as a real screen
  // keeps them after the window is later destroyed — the frame the guest tears
  // down at teardown was already drawn, and its bytes remain. Deterministic:
  // same run -> same log -> same pixels.
  const paintLog = [];
  function capturePaint(window) {
    if (window === undefined || window.is_destroyed) return;
    paintLog.push({
      handle: window.handle,
      parent: window.parent >>> 0,
      class_name: window.class_name,
      text: window.text,
      style: window.style >>> 0,
      x: window.x | 0,
      y: window.y | 0,
      width: window.width | 0,
      height: window.height | 0,
    });
  }

  function setLastError(value) {
    lastError = value >>> 0;
  }

  function queueFor(thread) {
    let queue = queueByThread.get(thread);
    if (queue === undefined) {
      queue = { pending: [], quit_code: null, has_quit: false };
      queueByThread.set(thread, queue);
    }
    return queue;
  }

  // A window class binds a name to the WndProc the guest supplied. A JS
  // callback stands in for the guest procedure until the CPU core invokes the
  // real pointer; DefWindowProc is the fallback when no callback is given.
  function registerClass(name, wndProc, style = 0, guestWndProc = 0, extra = {}) {
    if (typeof name !== "string" || name.length === 0 || name.length > userBound.string_byte) {
      setLastError(0x57); // ERROR_INVALID_PARAMETER
      return 0;
    }
    const keyed = classKey(name);
    if (classByName.has(keyed)) {
      setLastError(0x582); // ERROR_CLASS_ALREADY_EXISTS
      return 0;
    }
    if (classByName.size >= userBound.class_count) {
      throw userFault("user_class_exhausted", `The class registry exceeds ${userBound.class_count} class`);
    }
    const atom = nextAtom;
    nextAtom += 1;
    // wndProc is a host JS callback (the i386 fixture path) or null; guestWndProc
    // is a guest-code procedure pointer (the x86-64 path) a window inherits and
    // lib/exec64.mjs re-enters. The two are independent: a class can carry the
    // guest pointer while its host WndProc stays DefWindowProc for frame messages.
    classByName.set(keyed, {
      atom,
      name,
      style: style >>> 0,
      wndProc: typeof wndProc === "function" ? wndProc : null,
      guest_wndproc: guestWndProc ?? 0,
      class_extra: (extra.class_extra ?? 0) | 0,
      window_extra: (extra.window_extra ?? 0) | 0,
      hinstance: (extra.hinstance ?? 0) >>> 0,
      icon: (extra.icon ?? 0) >>> 0,
      cursor: (extra.cursor ?? 0) >>> 0,
      background: (extra.background ?? 0) >>> 0,
      menu_name: (extra.menu_name ?? 0) >>> 0,
      icon_small: (extra.icon_small ?? 0) >>> 0,
    });
    setLastError(0);
    return atom;
  }

  // Register a class whose window procedure is guest code (a PE code pointer).
  // The x86-64 dispatch path (lib/exec64.mjs) uses this so a window created from
  // the class carries the guest WndProc the message loop re-enters.
  function registerClassGuest(name, guestWndProcPointer, style = 0) {
    return registerClass(name, null, style, guestWndProcPointer);
  }

  function unregisterClass(name) {
    const keyed = classKey(name);
    if (!classByName.has(keyed)) {
      setLastError(0x5c9); // ERROR_CLASS_DOES_NOT_EXIST
      return 0;
    }
    for (const window of windowByHandle.values()) {
      if (classKey(window.class_name) === keyed) {
        setLastError(0x582);
        return 0;
      }
    }
    classByName.delete(keyed);
    setLastError(0);
    return 1;
  }

  // The single dispatch point: hand a message to the window's WndProc, or to
  // DefWindowProc when the class supplied none. Recorded on the window's
  // delivery log so a fixture can assert the exact order.
  function invokeWndProc(window, message, wParam, lParam) {
    window.delivered.push({ handle: window.handle, message, w_param: wParam >>> 0, l_param: lParam >>> 0 });
    const proc = window.wndProc;
    const result = proc === null ? defWindowProc(window.handle, message, wParam, lParam) : proc(window.handle, message, wParam, lParam, defWindowProc);
    return (result ?? 0) >>> 0;
  }

  // CreateWindowEx: allocate the window, then send the creation pair. A
  // WM_NCCREATE that returns FALSE, or a WM_CREATE that returns -1, aborts
  // creation and yields NULL, exactly as Win32 does.
  function createWindowEx(spec = {}) {
    const className = spec.class_name;
    let klass = typeof className === "string" ? classByName.get(classKey(className)) : undefined;
    if (klass === undefined && typeof className === "string" && predefinedClass.has(classKey(className))) {
      ensureClass(className);
      klass = classByName.get(classKey(className));
    }
    if (klass === undefined) {
      setLastError(0x57f); // ERROR_CANNOT_FIND_WND_CLASS
      return 0;
    }
    if (windowByHandle.size >= userBound.window_count) {
      throw userFault("user_window_exhausted", `The window table exceeds ${userBound.window_count} window`);
    }
    const handle = nextHandle;
    nextHandle += 4;
    const window = {
      handle,
      class_name: className,
      wndProc: klass.wndProc,
      // The guest-code window procedure pointer (a PE code address). The i386
      // path leaves this 0 and drives the WndProc through the JS callback; the
      // x86-64 dialog path stores the guest DlgProc here and lib/exec64.mjs
      // re-enters it as real guest control flow (WM_INITDIALOG / message loop).
      guest_wndproc: spec.guest_wndproc ?? klass.guest_wndproc ?? 0,
      parent: spec.parent ?? 0,
      control_id: (spec.control_id ?? 0) >>> 0,
      style: (spec.style ?? 0) >>> 0,
      ex_style: (spec.ex_style ?? 0) >>> 0,
      x: spec.x ?? 0,
      y: spec.y ?? 0,
      width: spec.width ?? 0,
      height: spec.height ?? 0,
      // The window caption/control text the compositor paints (the RT_DIALOG
      // title for a frame, the control caption for a child). Stored generically;
      // the paint path reads it by class, never by identity.
      text: typeof spec.text === "string" ? spec.text : "",
      thread_id: threadId,
      is_visible: false,
      is_enabled: true,
      needs_paint: false,
      is_destroyed: false,
      user_data: 0,
      hinstance: (spec.hinstance ?? 0) >>> 0,
      dlg_result: 0,
      dlg_user: 0,
      dlg_ended: false,
      menu: 0,
      property: new Map(),
      is_drop_accepted: false,
      delivered: [],
    };
    windowByHandle.set(handle, window);

    const createParam = (spec.create_param ?? 0) >>> 0;
    if (invokeWndProc(window, windowMessage.WM_NCCREATE, 0, createParam) === 0) {
      windowByHandle.delete(handle);
      setLastError(0x57);
      return 0;
    }
    const createResult = invokeWndProc(window, windowMessage.WM_CREATE, 0, createParam) | 0;
    if (createResult === -1) {
      windowByHandle.delete(handle);
      setLastError(0x57);
      return 0;
    }
    setLastError(0);
    // A window created WS_VISIBLE shows itself as part of creation.
    if ((window.style & 0x10000000) !== 0) showWindow(handle, showCommand.SW_SHOWNORMAL);
    return handle;
  }

  // ShowWindow: the visibility transition and the activation cascade that
  // follows it. Returns the previous visibility, as Win32 does.
  function showWindow(handle, command) {
    const window = windowByHandle.get(handle);
    if (window === undefined || window.is_destroyed) return 0;
    const wasVisible = window.is_visible;
    if (command === showCommand.SW_HIDE) {
      if (!wasVisible) return 0;
      window.is_visible = false;
      invokeWndProc(window, windowMessage.WM_SHOWWINDOW, 0, 0);
      if (activeWindow === handle) {
        deactivate(window);
      }
      return 1;
    }
    window.is_visible = true;
    invokeWndProc(window, windowMessage.WM_SHOWWINDOW, 1, 0);
    activate(window);
    window.needs_paint = true;
    // The window became visible: capture it into the paint log so the compositor
    // draws it into the display surface (the show-time paint of milestone 3).
    capturePaint(window);
    return wasVisible ? 1 : 0;
  }

  function activate(window) {
    if (activeWindow === window.handle) return;
    activeWindow = window.handle;
    invokeWndProc(window, windowMessage.WM_ACTIVATEAPP, 1, 0);
    invokeWndProc(window, windowMessage.WM_ACTIVATE, activateState.WA_ACTIVE, 0);
    focusWindow = window.handle;
    invokeWndProc(window, windowMessage.WM_SETFOCUS, 0, 0);
  }

  function deactivate(window) {
    if (focusWindow === window.handle) {
      invokeWndProc(window, windowMessage.WM_KILLFOCUS, 0, 0);
      focusWindow = 0;
    }
    invokeWndProc(window, windowMessage.WM_ACTIVATE, activateState.WA_INACTIVE, 0);
    invokeWndProc(window, windowMessage.WM_ACTIVATEAPP, 0, 0);
    activeWindow = 0;
  }

  // UpdateWindow: flush a pending paint synchronously through WM_PAINT.
  function updateWindow(handle) {
    const window = windowByHandle.get(handle);
    if (window === undefined || window.is_destroyed) return 0;
    if (window.needs_paint) {
      window.needs_paint = false;
      invokeWndProc(window, windowMessage.WM_PAINT, 0, 0);
      // The paint was flushed: re-capture so a moved/resized window repaints at
      // its current geometry (the UpdateWindow / WM_PAINT paint of milestone 3).
      capturePaint(window);
    }
    return 1;
  }

  function invalidate(handle) {
    const window = windowByHandle.get(handle);
    if (window === undefined || window.is_destroyed) return 0;
    window.needs_paint = true;
    return 1;
  }

  function invalidateRect(handle) {
    if (handle === 0) {
      for (const window of windowByHandle.values()) {
        if (!window.is_destroyed) window.needs_paint = true;
      }
      setLastError(0);
      return 1;
    }
    const value = invalidate(handle);
    if (value === 0) setLastError(0x578);
    else setLastError(0);
    return value;
  }

  function validateRect(handle) {
    if (handle === 0) {
      for (const window of windowByHandle.values()) {
        if (!window.is_destroyed) window.needs_paint = false;
      }
      setLastError(0);
      return 1;
    }
    const window = windowByHandle.get(handle);
    if (window === undefined || window.is_destroyed) {
      setLastError(0x578);
      return 0;
    }
    window.needs_paint = false;
    setLastError(0);
    return 1;
  }

  function updateRect(handle) {
    const window = windowByHandle.get(handle);
    if (window === undefined || window.is_destroyed) {
      setLastError(0x578);
      return null;
    }
    setLastError(0);
    if (!window.needs_paint) return { left: 0, top: 0, right: 0, bottom: 0, is_empty: true };
    return { left: 0, top: 0, right: window.width, bottom: window.height, is_empty: false };
  }

  function monitorFromHit(isHit, flags) {
    if (isHit) return virtualMonitorHandle;
    return ((flags >>> 0) === monitorDefault.to_null) ? 0 : virtualMonitorHandle;
  }

  function desktopRect() {
    return { left: 0, top: 0, right: systemMetric[0], bottom: systemMetric[1] };
  }

  function rectsIntersect(left, right) {
    return left.right > right.left && left.bottom > right.top && left.left < right.right && left.top < right.bottom;
  }

  function monitorFromPoint(x, y, flags) {
    const desktop = desktopRect();
    const isHit = (x | 0) >= desktop.left && (x | 0) < desktop.right && (y | 0) >= desktop.top && (y | 0) < desktop.bottom;
    return monitorFromHit(isHit, flags);
  }

  function monitorFromRect(rect, flags) {
    return monitorFromHit(rectsIntersect(rect, desktopRect()), flags);
  }

  function monitorFromWindow(handle, flags) {
    if (handle === 0) return monitorFromHit(false, flags);
    const rect = windowByHandle.has(handle)
      ? { left: windowByHandle.get(handle).x, top: windowByHandle.get(handle).y, right: windowByHandle.get(handle).x + windowByHandle.get(handle).width, bottom: windowByHandle.get(handle).y + windowByHandle.get(handle).height }
      : null;
    return monitorFromHit(rect !== null && rectsIntersect(rect, desktopRect()), flags);
  }

  // DestroyWindow: the teardown pair. Focus and activation are released first
  // so a fixture observes WM_KILLFOCUS before WM_DESTROY.
  function destroyWindow(handle) {
    const window = windowByHandle.get(handle);
    if (window === undefined || window.is_destroyed) {
      setLastError(0x578); // ERROR_INVALID_WINDOW_HANDLE
      return 0;
    }
    if (window.is_visible) {
      window.is_visible = false;
      invokeWndProc(window, windowMessage.WM_SHOWWINDOW, 0, 0);
    }
    if (activeWindow === handle || focusWindow === handle) deactivate(window);
    invokeWndProc(window, windowMessage.WM_DESTROY, 0, 0);
    invokeWndProc(window, windowMessage.WM_NCDESTROY, 0, 0);
    window.is_destroyed = true;
    windowByHandle.delete(handle);
    setLastError(0);
    return 1;
  }

  // DefWindowProc: the default handling the slice implements. WM_CLOSE
  // destroys the window; everything else is absorbed with a zero result.
  function defWindowProc(handle, message, wParam, lParam) {
    switch (message) {
      case windowMessage.WM_NCCREATE:
        return 1;
      case windowMessage.WM_CLOSE:
        destroyWindow(handle);
        return 0;
      default:
        return 0;
    }
  }

  // PostMessage: enqueue onto the target window's thread queue. A null target
  // posts to the current thread queue (the PostThreadMessage shape).
  function postMessage(handle, message, wParam = 0, lParam = 0) {
    const window = handle === 0 ? null : windowByHandle.get(handle);
    if (handle !== 0 && window === undefined) {
      setLastError(0x578);
      return 0;
    }
    const thread = window === null || window === undefined ? threadId : window.thread_id;
    const queue = queueFor(thread);
    if (queue.pending.length >= userBound.message_count) {
      throw userFault("user_queue_exhausted", `The message queue exceeds ${userBound.message_count} message`);
    }
    queue.pending.push({ handle, message, w_param: wParam >>> 0, l_param: lParam >>> 0 });
    setLastError(0);
    return 1;
  }

  // SendMessage: synchronous dispatch, bypassing the queue, returning the
  // WndProc result.
  function sendMessage(handle, message, wParam = 0, lParam = 0) {
    const window = windowByHandle.get(handle);
    if (window === undefined) {
      setLastError(0x578);
      return 0;
    }
    return invokeWndProc(window, message, wParam, lParam);
  }

  function postQuitMessage(exitCode) {
    const queue = queueFor(threadId);
    queue.has_quit = true;
    queue.quit_code = exitCode >>> 0;
  }

  // The next queued message for the thread, or a synthesized WM_PAINT when a
  // visible window needs one, or WM_QUIT when PostQuitMessage has fired and
  // the queue has drained. Returns null only when nothing is pending.
  function nextMessage(thread) {
    const queue = queueFor(thread);
    if (queue.pending.length > 0) return queue.pending.shift();
    for (const window of windowByHandle.values()) {
      if (window.thread_id === thread && window.is_visible && window.needs_paint) {
        window.needs_paint = false;
        return { handle: window.handle, message: windowMessage.WM_PAINT, w_param: 0, l_param: 0 };
      }
    }
    if (queue.has_quit) {
      queue.has_quit = false;
      return { handle: 0, message: windowMessage.WM_QUIT, w_param: queue.quit_code ?? 0, l_param: 0 };
    }
    return null;
  }

  // GetMessage: block-shaped retrieval. Returns 0 on WM_QUIT, 1 on any other
  // message, and -1 on the exhausted-with-no-message case the caller treats as
  // idle. The retrieved message is written into the supplied sink.
  function getMessage(sink) {
    const message = nextMessage(threadId);
    if (message === null) {
      sink.message = null;
      return -1;
    }
    sink.message = message;
    return message.message === windowMessage.WM_QUIT ? 0 : 1;
  }

  // PeekMessage: non-blocking. With remove set, the message leaves the queue;
  // otherwise it stays. Returns 1 when a message is available, 0 otherwise.
  function peekMessage(sink, remove = true) {
    const queue = queueFor(threadId);
    if (remove) {
      const message = nextMessage(threadId);
      sink.message = message;
      return message === null ? 0 : 1;
    }
    if (queue.pending.length > 0) {
      sink.message = queue.pending[0];
      return 1;
    }
    for (const window of windowByHandle.values()) {
      if (window.thread_id === threadId && window.is_visible && window.needs_paint) {
        sink.message = { handle: window.handle, message: windowMessage.WM_PAINT, w_param: 0, l_param: 0 };
        return 1;
      }
    }
    sink.message = null;
    return 0;
  }

  // TranslateMessage: a WM_KEYDOWN for a mapped key posts the WM_CHAR that
  // follows it. Returns 1 when a character was generated, 0 otherwise.
  function translateMessage(message) {
    if (message === null) return 0;
    if (message.message === windowMessage.WM_KEYDOWN) {
      const character = virtualKeyChar[message.w_param];
      if (character !== undefined) {
        postMessage(message.handle, windowMessage.WM_CHAR, character, message.l_param);
        return 1;
      }
    }
    return 0;
  }

  // DispatchMessage: route the message to its window's WndProc and return the
  // result. A WM_QUIT or thread-target message dispatches to nothing.
  function dispatchMessage(message) {
    if (message === null || message.handle === 0) return 0;
    const window = windowByHandle.get(message.handle);
    if (window === undefined) return 0;
    return invokeWndProc(window, message.message, message.w_param, message.l_param);
  }

  // --- input translation ---------------------------------------------------
  // A host key or pointer always updates the 256-byte key table GetKeyboardState
  // / GetKeyState / GetAsyncKeyState read — that table is process-wide and does
  // not need a window. When a focus/active window exists, the same event also
  // posts WM_KEYDOWN / WM_KEYUP / the button pair / WM_MOUSEMOVE, with the
  // position packed into lParam. The target is always the current focus/active
  // window; the trace never names a window, so the translation stays generic.
  function setKeyDown(virtualKey, isDown) {
    const vk = virtualKey & 0xff;
    if (isDown) {
      if (vk === vkCapital) keyState[vk] = 0x80 | ((keyState[vk] ^ 0x01) & 0x01);
      else keyState[vk] = 0x80 | (keyState[vk] & 0x01);
      asyncPressed[vk] = 1;
    } else {
      keyState[vk] = keyState[vk] & 0x01;
    }
    const parent = modifierChild[vk];
    if (parent !== undefined) {
      const sibling = modifierSibling[parent];
      const is_parent_down = (keyState[sibling[0]] & 0x80) !== 0 || (keyState[sibling[1]] & 0x80) !== 0;
      if (is_parent_down) {
        keyState[parent] = 0x80 | (keyState[parent] & 0x01);
        if (isDown) asyncPressed[parent] = 1;
      } else {
        keyState[parent] = keyState[parent] & 0x01;
      }
    }
  }

  function getKeyState(virtualKey) {
    const vk = virtualKey & 0xff;
    const is_down = (keyState[vk] & 0x80) !== 0;
    const is_toggle = (keyState[vk] & 0x01) !== 0;
    return ((is_down ? 0x8000 : 0) | (is_toggle ? 1 : 0)) >>> 0;
  }

  function getAsyncKeyState(virtualKey) {
    const vk = virtualKey & 0xff;
    const is_down = (keyState[vk] & 0x80) !== 0;
    const was = asyncPressed[vk];
    asyncPressed[vk] = 0;
    return ((is_down ? 0x8000 : 0) | (was ? 1 : 0)) >>> 0;
  }

  function keyboardState() {
    return Uint8Array.from(keyState);
  }

  function keyLParam(virtualKey, isDown, wasDown) {
    const scan = mapVirtualKey(virtualKey, 0) & 0xff;
    let value = 1;
    value |= scan << 16;
    if (!isDown) value |= 0xc0000000;
    else if (wasDown) value |= 0x40000000;
    return value >>> 0;
  }

  function injectKey(virtualKey, isDown) {
    const vk = virtualKey & 0xff;
    const wasDown = (keyState[vk] & 0x80) !== 0;
    setKeyDown(vk, isDown === true);
    const target = focusWindow !== 0 ? focusWindow : activeWindow;
    if (target === 0) return 1;
    const message = isDown ? windowMessage.WM_KEYDOWN : windowMessage.WM_KEYUP;
    return postMessage(target, message, vk >>> 0, keyLParam(vk, isDown === true, wasDown));
  }

  function injectMouse(event) {
    const name = event.button;
    if (name !== undefined && name !== null) {
      const mouseKey = mouseVirtualKey[name];
      if (mouseKey === undefined) {
        setLastError(0x57);
        return 0;
      }
      setKeyDown(mouseKey, event.is_down === true);
    }
    const target = activeWindow !== 0 ? activeWindow : focusWindow;
    if (target === 0) return 1;
    const point = makePoint(event.x ?? 0, event.y ?? 0);
    if (event.button === undefined || event.button === null) {
      return postMessage(target, windowMessage.WM_MOUSEMOVE, 0, point);
    }
    const button = pointerButton[event.button];
    return postMessage(target, event.is_down ? button.down : button.up, 0, point);
  }

  // Replay a whole input trace, returning the exact ordered WM_* sequence the
  // queue received. The fixture asserts against this, and asserts it is
  // identical across two runs.
  function replayInput(traceEntry) {
    for (const entry of traceEntry) {
      if (entry.kind === "key") injectKey(entry.virtual_key, entry.is_down);
      else if (entry.kind === "mouse") injectMouse(entry);
      else throw userFault("user_input_kind", `Unknown input kind: ${entry.kind}`);
    }
    return queueFor(threadId).pending.map((message) => ({ ...message }));
  }

  // Register a class on demand with no host WndProc (the default frame proc, or
  // a guest control whose messages route through DefWindowProc host-side). Used
  // by the dialog instantiator for the frame and every predefined control class
  // the template names, so a CreateDialog never fails for an unregistered class.
  function ensureClass(name) {
    if (typeof name !== "string" || name.length === 0) return;
    if (classByName.has(classKey(name))) return;
    registerClass(name, null, 0);
  }

  // Instantiate a parsed RT_DIALOG template (lib/rsrc.mjs) as real window
  // objects: the frame window carrying the guest DlgProc pointer, then one child
  // window per control. The frame's WM_NCCREATE / WM_CREATE run host-side
  // (DefWindowProc); the guest DlgProc receives WM_INITDIALOG and the message
  // loop through the lib/exec64.mjs guest re-entry. Returns the frame handle, the
  // control list, and the initial-focus control (the first WS_TABSTOP control).
  function instantiateDialog(template, dlgProcPointer, initParam = 0) {
    const frameClass = typeof template.class_name === "string" && template.class_name.length > 0 ? template.class_name : "#32770";
    ensureClass(frameClass);
    // The template is in dialog units; convert the frame and every control to
    // pixels under the base unit pair the dialog font implies. The template
    // cx/cy is the CLIENT extent, so the frame window is that client height plus
    // the caption band the compositor draws inside the top of the frame — this
    // keeps every control (positioned client-relative, below the caption) within
    // the frame rather than spilling past its bottom edge.
    const unit = dialogBaseUnit(template.font);
    const frameRect = dialogRectToPixel({ x: template.x, y: template.y, cx: template.cx, cy: template.cy }, unit);
    const hwnd = createWindowEx({
      class_name: frameClass,
      style: template.style,
      ex_style: template.ex_style,
      x: frameRect.x,
      y: frameRect.y,
      width: frameRect.width,
      height: frameRect.height + compositorMetric.caption_height,
      text: typeof template.title === "string" ? template.title : "",
      create_param: initParam >>> 0,
      guest_wndproc: dlgProcPointer,
    });
    if (hwnd === 0) return { hwnd: 0, control: [], focus_control: 0 };
    // A dialog is instantiated to be shown; capture the frame into the paint log
    // (before its controls, so it paints behind them) unless creation already
    // showed it WS_VISIBLE. This is the dialog's show-time paint — the frame's
    // background and caption — without disturbing activation or message delivery.
    const frameWindow = windowByHandle.get(hwnd);
    if (frameWindow !== undefined && !frameWindow.is_visible) capturePaint(frameWindow);
    const control = [];
    let focusControl = 0;
    for (const item of template.item) {
      const controlClass = typeof item.class_name === "string" && item.class_name.length > 0 ? item.class_name : "Static";
      ensureClass(controlClass);
      const itemRect = dialogRectToPixel({ x: item.x, y: item.y, cx: item.cx, cy: item.cy }, unit);
      const childHandle = createWindowEx({
        class_name: controlClass,
        style: item.style,
        ex_style: item.ex_style,
        x: itemRect.x,
        y: itemRect.y,
        width: itemRect.width,
        height: itemRect.height,
        text: typeof item.title === "string" ? item.title : "",
        create_param: 0,
        parent: hwnd,
        control_id: item.id,
      });
      control.push({ handle: childHandle, id: item.id >>> 0, class_name: controlClass });
      // WS_TABSTOP (0x00010000): the first tabstop control receives initial focus.
      if (focusControl === 0 && childHandle !== 0 && (item.style & 0x00010000) !== 0) focusControl = childHandle;
    }
    return { hwnd, control, focus_control: focusControl };
  }

  // The guest window procedure a window carries (0 when host-driven). The x64
  // message pump reads this to decide whether to re-enter guest code.
  function getGuestWndProc(handle) {
    const window = windowByHandle.get(handle);
    return window === undefined ? 0 : window.guest_wndproc;
  }

  // SetActiveWindow / SetFocus: record the new active/focus window and return
  // the previous one, the value the Win32 caller reads back.
  function setActiveWindow(handle) {
    const previous = activeWindow;
    if (handle === 0 || windowByHandle.has(handle)) activeWindow = handle;
    return previous;
  }

  function setFocusWindow(handle) {
    const previous = focusWindow;
    if (handle === 0 || windowByHandle.has(handle)) focusWindow = handle;
    return previous;
  }

  // GetDlgItem: the child control window with control id `id` under `parent`.
  function getDlgItem(parent, id) {
    for (const window of windowByHandle.values()) {
      if (window.parent === parent && window.control_id === (id >>> 0)) return window.handle;
    }
    return 0;
  }

  function requireWindow(handle) {
    const window = windowByHandle.get(handle);
    if (window === undefined || window.is_destroyed) {
      setLastError(0x578);
      return null;
    }
    return window;
  }

  function classNameFromAtom(atom) {
    for (const [name, klass] of classByName) {
      if (klass.atom === (atom >>> 0)) return name;
    }
    return "";
  }

  function getClassInfo(name) {
    if (typeof name !== "string" || name.length === 0) {
      setLastError(87);
      return null;
    }
    const klass = classByName.get(classKey(name));
    if (klass === undefined) {
      setLastError(0x583); // ERROR_CLASS_DOES_NOT_EXIST
      return null;
    }
    setLastError(0);
    return klass;
  }

  function getWindowText(handle) {
    return requireWindow(handle)?.text ?? "";
  }

  function setWindowText(handle, text) {
    const window = requireWindow(handle);
    if (window === null) return 0;
    window.text = typeof text === "string" ? text : "";
    if (window.is_visible) capturePaint(window);
    setLastError(0);
    return 1;
  }

  function acceptDropFiles(handle, is_accept) {
    const window = requireWindow(handle);
    if (window === null) return 0;
    window.is_drop_accepted = is_accept === true;
    setLastError(0);
    return 0;
  }

  function enableWindow(handle, enabled) {
    const window = requireWindow(handle);
    if (window === null) return 0;
    const wasEnabled = window.is_enabled;
    window.is_enabled = enabled !== 0;
    return wasEnabled ? 1 : 0;
  }

  const GWL_WNDPROC = -4;
  const GWL_HINSTANCE = -6;
  const GWL_HWNDPARENT = -8;
  const GWL_ID = -12;
  const GWL_STYLE = -16;
  const GWL_EXSTYLE = -20;
  const GWL_USERDATA = -21;
  const DWL_MSGRESULT = 0;
  const DWL_DLGPROC = 4;
  const DWL_USER = 8;

  function getWindowLong(handle, index) {
    const window = requireWindow(handle);
    if (window === null) return 0;
    if (index === GWL_WNDPROC || index === DWL_DLGPROC) return window.guest_wndproc >>> 0;
    if (index === GWL_HINSTANCE) return window.hinstance >>> 0;
    if (index === GWL_HWNDPARENT) return window.parent >>> 0;
    if (index === GWL_ID) return window.control_id >>> 0;
    if (index === GWL_STYLE) return window.style >>> 0;
    if (index === GWL_EXSTYLE) return window.ex_style >>> 0;
    if (index === GWL_USERDATA) return window.user_data >>> 0;
    if (index === DWL_MSGRESULT) return window.dlg_result >>> 0;
    if (index === DWL_USER) return window.dlg_user >>> 0;
    return 0;
  }

  function setWindowLong(handle, index, value) {
    const window = requireWindow(handle);
    if (window === null) return 0;
    const previous = getWindowLong(handle, index);
    if (index === GWL_WNDPROC || index === DWL_DLGPROC) window.guest_wndproc = value >>> 0;
    else if (index === GWL_HINSTANCE) window.hinstance = value >>> 0;
    else if (index === GWL_STYLE) window.style = value >>> 0;
    else if (index === GWL_EXSTYLE) window.ex_style = value >>> 0;
    else if (index === GWL_USERDATA) window.user_data = value >>> 0;
    else if (index === GWL_ID) window.control_id = value >>> 0;
    else if (index === DWL_MSGRESULT) window.dlg_result = value >>> 0;
    else if (index === DWL_USER) window.dlg_user = value >>> 0;
    return previous;
  }

  function propertyKey(name) {
    if (typeof name === "number") return `atom:${name >>> 0}`;
    return `name:${name}`;
  }

  function setProp(handle, name, data) {
    const window = requireWindow(handle);
    if (window === null) return 0;
    const key = propertyKey(name);
    if (!window.property.has(key) && window.property.size >= userBound.property_count) {
      throw userFault("user_property_exhausted", `The window property table exceeds ${userBound.property_count} property`);
    }
    window.property.set(key, data >>> 0);
    setLastError(0);
    return 1;
  }

  function getProp(handle, name) {
    const window = requireWindow(handle);
    if (window === null) return 0;
    return window.property.get(propertyKey(name)) ?? 0;
  }

  function removeProp(handle, name) {
    const window = requireWindow(handle);
    if (window === null) return 0;
    const key = propertyKey(name);
    const previous = window.property.get(key) ?? 0;
    window.property.delete(key);
    return previous;
  }

  function setWindowPos(handle, _after, x, y, width, height, flag) {
    const window = requireWindow(handle);
    if (window === null) return 0;
    const swpNosize = (flag & 0x0001) !== 0;
    const swpNomove = (flag & 0x0002) !== 0;
    const nextX = swpNomove ? window.x : x | 0;
    const nextY = swpNomove ? window.y : y | 0;
    const nextWidth = swpNosize ? window.width : Math.max(width | 0, 0);
    const nextHeight = swpNosize ? window.height : Math.max(height | 0, 0);
    window.x = nextX;
    window.y = nextY;
    window.width = nextWidth;
    window.height = nextHeight;
    window.needs_paint = window.is_visible;
    return 1;
  }

  const menuByHandle = new Map();
  let nextMenuHandle = 0x00030000;
  function createMenu() {
    const handle = nextMenuHandle;
    nextMenuHandle += 4;
    menuByHandle.set(handle, { handle, item: [] });
    setLastError(0);
    return handle;
  }

  function appendMenu(menu, flags, idNew, text) {
    const record = menuByHandle.get(menu >>> 0);
    if (record === undefined) {
      setLastError(0x57b);
      return 0;
    }
    record.item.push({ flags: flags >>> 0, id: idNew >>> 0, text: typeof text === "string" ? text : "", checked: (flags & 0x0008) !== 0 });
    setLastError(0);
    return 1;
  }

  function findMenuItem(menu, id) {
    const record = menuByHandle.get(menu >>> 0);
    if (record === undefined) return null;
    return record.item.find((entry) => entry.id === (id >>> 0)) ?? null;
  }

  function checkMenuItem(menu, id, check) {
    const item = findMenuItem(menu, id);
    if (item === null) return 0xffffffff;
    const previous = item.checked ? 8 : 0;
    item.checked = (check & 0x0008) !== 0;
    return previous;
  }

  function checkMenuRadioItem(menu, first, last, check, _flag) {
    const record = menuByHandle.get(menu >>> 0);
    if (record === undefined) return 0;
    for (const item of record.item) {
      if (item.id >= (first >>> 0) && item.id <= (last >>> 0)) item.checked = item.id === (check >>> 0);
    }
    return 1;
  }

  function enableMenuItem(menu, id, enable) {
    const item = findMenuItem(menu, id);
    if (item === null) return 0xffffffff;
    const previous = (item.flags & 0x0001) !== 0 ? 1 : 0;
    if ((enable & 0x0001) !== 0) item.flags |= 0x0001;
    else item.flags &= ~0x0001;
    return previous;
  }

  function setMenu(handle, menu) {
    const window = requireWindow(handle);
    if (window === null) return 0;
    window.menu = menu >>> 0;
    return 1;
  }

  const timerById = new Map();
  let nextTimerId = 1;
  function setTimer(handle, idEvent, elapsedMs) {
    const timerId = idEvent === 0 ? nextTimerId++ : idEvent >>> 0;
    timerById.set(timerId, { hwnd: handle >>> 0, id: timerId, elapsed_ms: elapsedMs >>> 0, pending: true });
    setLastError(0);
    return timerId;
  }

  function killTimer(handle, idEvent) {
    return timerById.delete(idEvent >>> 0) ? 1 : 0;
  }

  function flushTimer() {
    const queue = queueFor(threadId);
    for (const timer of timerById.values()) {
      if (!timer.pending) continue;
      timer.pending = false;
      queue.pending.push({ handle: timer.hwnd, message: windowMessage.WM_TIMER, w_param: timer.id, l_param: 0 });
    }
  }

  const originalGetMessage = getMessage;
  const originalPeekMessage = peekMessage;
  function getMessageWithTimer(sink) {
    if (queueFor(threadId).pending.length === 0) flushTimer();
    return originalGetMessage(sink);
  }
  function peekMessageWithTimer(sink, remove) {
    if (queueFor(threadId).pending.length === 0) flushTimer();
    return originalPeekMessage(sink, remove);
  }

  let desktopHandle = 0;
  function getDesktopWindow() {
    if (desktopHandle !== 0 && windowByHandle.has(desktopHandle)) return desktopHandle;
    ensureClass("#32769");
    desktopHandle = createWindowEx({ class_name: "#32769", x: 0, y: 0, width: 1920, height: 1080, text: "Desktop" });
    return desktopHandle;
  }

  const messageBoxLog = [];
  function messageBox(text, caption, type) {
    const kind = (type >>> 0) & 0xf;
    messageBoxLog.push({ text: text ?? "", caption: caption ?? "", type: type >>> 0 });
    if (kind === 0) return 1; // MB_OK: IDOK is the one dismissal this world can deliver
    setLastError(0x57);
    return 0;
  }

  function mapDialogRect(left, top, right, bottom) {
    const unit = dialogBaseUnit(null);
    const origin = dialogRectToPixel({ x: left, y: top, cx: 0, cy: 0 }, unit);
    const extent = dialogRectToPixel({ x: right, y: bottom, cx: 0, cy: 0 }, unit);
    return { left: origin.x, top: origin.y, right: extent.x, bottom: extent.y };
  }

  function endDialog(handle, result) {
    const window = requireWindow(handle);
    if (window === null) return 0;
    window.dlg_ended = true;
    window.dlg_result = result | 0;
    return 1;
  }

  function checkDlgButton(parent, id, check) {
    const child = windowByHandle.get(getDlgItem(parent, id));
    if (child === undefined) return 0;
    child.dlg_user = check >>> 0;
    return 1;
  }

  function isDlgButtonChecked(parent, id) {
    const child = windowByHandle.get(getDlgItem(parent, id));
    return child === undefined ? 0 : child.dlg_user >>> 0;
  }

  function checkRadioButton(parent, first, last, check) {
    for (const window of windowByHandle.values()) {
      if (window.parent !== parent) continue;
      if (window.control_id >= (first >>> 0) && window.control_id <= (last >>> 0)) {
        window.dlg_user = window.control_id === (check >>> 0) ? 1 : 0;
      }
    }
    return 1;
  }

  function getDlgItemInt(parent, id) {
    const text = getWindowText(getDlgItem(parent, id));
    const value = Number.parseInt(text, 10);
    return Number.isFinite(value) ? value >>> 0 : 0;
  }

  function setDlgItemInt(parent, id, value) {
    return setWindowText(getDlgItem(parent, id), String(value >>> 0));
  }

  function sendDlgItemMessage(parent, id, message, wParam, lParam) {
    const child = getDlgItem(parent, id);
    if (child === 0) {
      setLastError(0x578);
      return 0;
    }
    return sendMessage(child, message, wParam, lParam);
  }

  function isDialogMessage(_handle, _message) {
    return 0;
  }

  let dpiContext = -1;
  function isValidDpiContext(value) {
    const v = value | 0;
    return v <= -1 && v >= -5;
  }
  function awarenessFromDpiContext(value) {
    const v = value | 0;
    if (v === -1 || v === -5) return 0;
    if (v === -2) return 1;
    if (v === -3 || v === -4) return 2;
    return -1;
  }

  return {
    thread_id: threadId,
    getLastError: () => lastError,
    setLastError,
    isValidDpiContext,
    awarenessFromDpiContext,
    getDpiContext: () => dpiContext,
    setProcessDpiAware() {
      dpiContext = -4;
      return 1;
    },
    setProcessDpiAwarenessContext(ctx) {
      if (!isValidDpiContext(ctx)) {
        setLastError(87);
        return 0;
      }
      dpiContext = ctx | 0;
      return 1;
    },
    setThreadDpiAwarenessContext(ctx) {
      if (!isValidDpiContext(ctx)) {
        setLastError(87);
        return 0;
      }
      const previous = dpiContext;
      dpiContext = ctx | 0;
      return previous;
    },
    getActiveWindow: () => activeWindow,
    getFocus: () => focusWindow,
    windowCount: () => windowByHandle.size,
    classCount: () => classByName.size,
    isWindow: (handle) => windowByHandle.has(handle),
    // The ordered snapshot the compositor reads to paint the screen. One entry
    // per live window in creation order (a Map preserves insertion order, so a
    // parent precedes its children and back-to-front paint is the natural pass),
    // carrying the geometry, class, caption, and visibility the paint path keys
    // on. It never branches on a title identity — a control is described by its
    // class, and the compositor paints it by class.
    windowList: () => {
      const list = [];
      for (const window of windowByHandle.values()) {
        list.push({
          handle: window.handle,
          class_name: window.class_name,
          text: window.text,
          parent: window.parent,
          control_id: window.control_id,
          style: window.style,
          x: window.x,
          y: window.y,
          width: window.width,
          height: window.height,
          is_visible: window.is_visible,
        });
      }
      return list;
    },
    // The persisted paint log the compositor draws (a copy so a caller cannot
    // mutate the manager's state). Ordered back-to-front by paint time, so a
    // frame precedes the controls shown after it, and a snapshot survives the
    // window's later destruction — the display surface keeps what was painted.
    paintSnapshot: () => paintLog.map((entry) => ({ ...entry })),
    // Window geometry (BPTK-011): the window rect is the declared frame; the
    // client rect is origin-anchored at the same extent (this HLE serves the
    // no-nonclient-frame case, so AdjustWindowRect leaves the rect unchanged).
    windowRect: (handle) => {
      const window = windowByHandle.get(handle);
      if (window === undefined) return null;
      return { left: window.x, top: window.y, right: window.x + window.width, bottom: window.y + window.height };
    },
    clientRect: (handle) => {
      const window = windowByHandle.get(handle);
      if (window === undefined) return null;
      return { left: 0, top: 0, right: window.width, bottom: window.height };
    },
    // No nonclient frame, so the client origin is the window origin.
    clientToScreen: (handle, x, y) => {
      const window = windowByHandle.get(handle);
      if (window === undefined) return null;
      return { x: (x | 0) + window.x, y: (y | 0) + window.y };
    },
    screenToClient: (handle, x, y) => {
      const window = windowByHandle.get(handle);
      if (window === undefined) return null;
      return { x: (x | 0) - window.x, y: (y | 0) - window.y };
    },
    moveWindow: (handle, x, y, width, height) => {
      const window = windowByHandle.get(handle);
      if (window === undefined) {
        setLastError(0x578);
        return 0;
      }
      window.x = x | 0;
      window.y = y | 0;
      window.width = Math.max(width | 0, 0);
      window.height = Math.max(height | 0, 0);
      window.needs_paint = window.is_visible;
      return 1;
    },
    deliveredFor: (handle) => (windowByHandle.get(handle)?.delivered ?? []).map((entry) => ({ ...entry })),
    registerClass,
    registerClassGuest,
    ensureClass,
    instantiateDialog,
    getGuestWndProc,
    getDlgItem,
    classNameFromAtom,
    getClassInfo,
    getWindowText,
    setWindowText,
    acceptDropFiles,
    isDropAccepted: (handle) => windowByHandle.get(handle)?.is_drop_accepted === true,
    enableWindow,
    getWindowLong,
    setWindowLong,
    setProp,
    getProp,
    removeProp,
    setWindowPos,
    createMenu,
    appendMenu,
    checkMenuItem,
    checkMenuRadioItem,
    enableMenuItem,
    setMenu,
    setTimer,
    killTimer,
    getDesktopWindow,
    messageBox,
    messageBoxLog: () => messageBoxLog.map((entry) => ({ ...entry })),
    mapDialogRect,
    endDialog,
    checkDlgButton,
    isDlgButtonChecked,
    checkRadioButton,
    getDlgItemInt,
    setDlgItemInt,
    sendDlgItemMessage,
    isDialogMessage,
    dialogEnded: (handle) => windowByHandle.get(handle)?.dlg_ended === true,
    dialogResult: (handle) => windowByHandle.get(handle)?.dlg_result ?? 0,
    setActiveWindow,
    setFocusWindow,
    monitorFromPoint,
    monitorFromRect,
    monitorFromWindow,
    invalidateRect,
    validateRect,
    updateRect,
    needsPaint: (handle) => windowByHandle.get(handle)?.needs_paint === true,
    unregisterClass,
    createWindowEx,
    destroyWindow,
    showWindow,
    updateWindow,
    invalidate,
    defWindowProc,
    postMessage,
    sendMessage,
    postQuitMessage,
    getMessage: getMessageWithTimer,
    peekMessage: peekMessageWithTimer,
    translateMessage,
    dispatchMessage,
    injectKey,
    injectMouse,
    replayInput,
    getKeyState,
    getAsyncKeyState,
    keyboardState,
  };
}

// ---------------------------------------------------------------------------
// The USER32 export table. One row per emulated export, delegating to the
// subsystem attached to the guest. This is the surface lib/hle.mjs registers;
// it stays a data table so the registration is one spread, never logic in the
// shared file.
// ---------------------------------------------------------------------------

export function buildUserExportTable() {
  const table = [];
  function define(symbol, argumentCount, emulate) {
    table.push(Object.freeze({ library: "user32.dll", symbol, argument_count: argumentCount, emulate }));
  }

  // A guest call arrives with dword argument low-to-high. RegisterClass reads
  // the WNDCLASS(EX)W struct from guest memory at the declared offset; the
  // WndProc field is a guest code pointer, stored as a number so the manager
  // falls back to DefWindowProc until the CPU core can invoke it.
  function classExtraFromStruct(guest, base, isEx) {
    if (isEx) {
      return {
        class_extra: guest.memory.readMemory(base + 12, 4) | 0,
        window_extra: guest.memory.readMemory(base + 16, 4) | 0,
        hinstance: guest.memory.readMemory(base + 20, 4),
        icon: guest.memory.readMemory(base + 24, 4),
        cursor: guest.memory.readMemory(base + 28, 4),
        background: guest.memory.readMemory(base + 32, 4),
        menu_name: guest.memory.readMemory(base + 36, 4),
        icon_small: guest.memory.readMemory(base + 44, 4),
      };
    }
    return {
      class_extra: guest.memory.readMemory(base + 8, 4) | 0,
      window_extra: guest.memory.readMemory(base + 12, 4) | 0,
      hinstance: guest.memory.readMemory(base + 16, 4),
      icon: guest.memory.readMemory(base + 20, 4),
      cursor: guest.memory.readMemory(base + 24, 4),
      background: guest.memory.readMemory(base + 28, 4),
      menu_name: guest.memory.readMemory(base + 32, 4),
      icon_small: 0,
    };
  }
  function writeWndClass(guest, dest, klass, classPointer, isEx) {
    const write = (offset, value) => guest.memory.writeMemory(dest + offset, 4, value >>> 0);
    if (isEx) {
      write(0, 48);
      write(4, klass.style);
      write(8, klass.guest_wndproc);
      write(12, klass.class_extra);
      write(16, klass.window_extra);
      write(20, klass.hinstance);
      write(24, klass.icon);
      write(28, klass.cursor);
      write(32, klass.background);
      write(36, klass.menu_name);
      write(40, classPointer);
      write(44, klass.icon_small);
      return;
    }
    write(0, klass.style);
    write(4, klass.guest_wndproc);
    write(8, klass.class_extra);
    write(12, klass.window_extra);
    write(16, klass.hinstance);
    write(20, klass.icon);
    write(24, klass.cursor);
    write(28, klass.background);
    write(32, klass.menu_name);
    write(36, classPointer);
  }
  function getClassInfoHle(guest, argument, isWide, isEx) {
    if ((argument[2] >>> 0) === 0) {
      guest.setLastError(87);
      return 0;
    }
    const name = classNameFromPointer(guest, argument[1], isWide);
    const klass = guest.user.getClassInfo(name);
    if (klass === null) {
      guest.setLastError(guest.user.getLastError());
      return 0;
    }
    writeWndClass(guest, argument[2], klass, argument[1], isEx);
    guest.setLastError(0);
    return 1;
  }
  define("RegisterClassW", 1, (guest, argument) => {
    const base = argument[0];
    const style = guest.memory.readMemory(base + 0, 4);
    const wndProc = guest.memory.readMemory(base + 4, 4);
    const name = guest.readWideString(guest.memory.readMemory(base + 36, 4));
    return guest.user.registerClass(name, null, style, wndProc, classExtraFromStruct(guest, base, false));
  });
  define("RegisterClassExW", 1, (guest, argument) => {
    const base = argument[0];
    const style = guest.memory.readMemory(base + 4, 4);
    const wndProc = guest.memory.readMemory(base + 8, 4);
    const name = guest.readWideString(guest.memory.readMemory(base + 40, 4));
    return guest.user.registerClass(name, null, style, wndProc, classExtraFromStruct(guest, base, true));
  });
  define("RegisterClassExA", 1, (guest, argument) => {
    const base = argument[0];
    const style = guest.memory.readMemory(base + 4, 4);
    const wndProc = guest.memory.readMemory(base + 8, 4);
    const name = guest.readAnsiString(guest.memory.readMemory(base + 40, 4));
    return guest.user.registerClass(name, null, style, wndProc, classExtraFromStruct(guest, base, true));
  });
  define("GetClassInfoExW", 3, (guest, argument) => getClassInfoHle(guest, argument, true, true));
  define("GetClassInfoExA", 3, (guest, argument) => getClassInfoHle(guest, argument, false, true));
  define("GetClassInfoW", 3, (guest, argument) => getClassInfoHle(guest, argument, true, false));
  define("GetClassInfoA", 3, (guest, argument) => getClassInfoHle(guest, argument, false, false));
  define("UnregisterClassW", 2, (guest, argument) => guest.user.unregisterClass(guest.readWideString(argument[0])));
  define("UnregisterClassA", 2, (guest, argument) => guest.user.unregisterClass(guest.readAnsiString(argument[0])));
  function classNameFromPointer(guest, value, isWide) {
    if (value === 0) return "";
    if ((value >>> 0) < 0x10000) return guest.user.classNameFromAtom(value);
    return isWide ? guest.readWideString(value) : guest.readAnsiString(value);
  }
  define("CreateWindowExW", 12, (guest, argument) => guest.user.createWindowEx({
    ex_style: argument[0],
    class_name: classNameFromPointer(guest, argument[1], true),
    text: argument[2] === 0 || (argument[2] >>> 0) < 0x10000 ? "" : guest.readWideString(argument[2]),
    style: argument[3],
    x: argument[4] | 0,
    y: argument[5] | 0,
    width: argument[6] | 0,
    height: argument[7] | 0,
    parent: argument[8],
    control_id: argument[8] !== 0 ? argument[9] : 0,
    hinstance: argument[10],
    create_param: argument[11],
  }));
  define("DestroyWindow", 1, (guest, argument) => guest.user.destroyWindow(argument[0]));
  define("DefWindowProcW", 4, (guest, argument) => guest.user.defWindowProc(argument[0], argument[1], argument[2], argument[3]));
  define("ShowWindow", 2, (guest, argument) => guest.user.showWindow(argument[0], argument[1]));
  define("UpdateWindow", 1, (guest, argument) => guest.user.updateWindow(argument[0]));
  define("PostMessageW", 4, (guest, argument) => guest.user.postMessage(argument[0], argument[1], argument[2], argument[3]));
  define("SendMessageW", 4, (guest, argument) => guest.user.sendMessage(argument[0], argument[1], argument[2], argument[3]));
  define("PostQuitMessage", 1, (guest, argument) => { guest.user.postQuitMessage(argument[0]); return 0; });
  define("GetActiveWindow", 0, (guest) => guest.user.getActiveWindow());
  define("GetFocus", 0, (guest) => guest.user.getFocus());
  define("IsWindow", 1, (guest, argument) => (guest.user.isWindow(argument[0]) ? 1 : 0));

  // --- message loop (BPTK-011): the queue exists in the subsystem; these rows
  // marshal the MSG struct to and from guest memory. MSG layout (x86, 28 byte):
  // hwnd +0, message +4, wParam +8, lParam +12, time +16, pt.x +20, pt.y +24.
  const writeMsg = (guest, address, message) => {
    if (address === 0 || message === null || message === undefined) return;
    guest.memory.writeMemory(address + 0, 4, message.handle >>> 0);
    guest.memory.writeMemory(address + 4, 4, message.message >>> 0);
    guest.memory.writeMemory(address + 8, 4, message.w_param >>> 0);
    guest.memory.writeMemory(address + 12, 4, message.l_param >>> 0);
    guest.memory.writeMemory(address + 16, 4, 0); // time: the one guest clock is not sampled per message yet
    guest.memory.writeMemory(address + 20, 4, 0); // pt.x
    guest.memory.writeMemory(address + 24, 4, 0); // pt.y
  };
  const readMsg = (guest, address) => ({
    handle: guest.memory.readMemory(address + 0, 4),
    message: guest.memory.readMemory(address + 4, 4),
    w_param: guest.memory.readMemory(address + 8, 4),
    l_param: guest.memory.readMemory(address + 12, 4),
  });
  define("GetMessageW", 4, (guest, argument) => {
    const sink = {};
    const code = guest.user.getMessage(sink);
    writeMsg(guest, argument[0], sink.message);
    return code; // 1 message, 0 WM_QUIT, -1 idle/no-message under the cooperative model
  });
  define("PeekMessageW", 5, (guest, argument) => {
    const sink = {};
    const available = guest.user.peekMessage(sink, (argument[4] & 1) === 1);
    if (available === 1) writeMsg(guest, argument[0], sink.message);
    return available;
  });
  define("TranslateMessage", 1, (guest, argument) => guest.user.translateMessage(readMsg(guest, argument[0])));
  define("DispatchMessageW", 1, (guest, argument) => guest.user.dispatchMessage(readMsg(guest, argument[0])));

  // --- window geometry and system metrics (BPTK-011) ----------------------------
  const readRect = (guest, address) => ({
    left: guest.memory.readMemory(address, 4) | 0,
    top: guest.memory.readMemory(address + 4, 4) | 0,
    right: guest.memory.readMemory(address + 8, 4) | 0,
    bottom: guest.memory.readMemory(address + 12, 4) | 0,
  });
  const writeRect = (guest, address, rect) => {
    if (address === 0 || rect === null) return 0;
    guest.memory.writeMemory(address + 0, 4, rect.left >>> 0);
    guest.memory.writeMemory(address + 4, 4, rect.top >>> 0);
    guest.memory.writeMemory(address + 8, 4, rect.right >>> 0);
    guest.memory.writeMemory(address + 12, 4, rect.bottom >>> 0);
    return 1;
  };
  define("GetClientRect", 2, (guest, argument) => writeRect(guest, argument[1], guest.user.clientRect(argument[0])));
  define("GetWindowRect", 2, (guest, argument) => writeRect(guest, argument[1], guest.user.windowRect(argument[0])));
  const writeMappedPoint = (guest, handle, address, is_to_screen) => {
    if ((address >>> 0) === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    const x = guest.memory.readMemory(address, 4) | 0;
    const y = guest.memory.readMemory(address + 4, 4) | 0;
    const mapped = is_to_screen
      ? guest.user.clientToScreen(handle, x, y)
      : guest.user.screenToClient(handle, x, y);
    if (mapped === null) return 0;
    guest.memory.writeMemory(address, 4, mapped.x >>> 0);
    guest.memory.writeMemory(address + 4, 4, mapped.y >>> 0);
    return 1;
  };
  define("ClientToScreen", 2, (guest, argument) => writeMappedPoint(guest, argument[0], argument[1], true));
  define("ScreenToClient", 2, (guest, argument) => writeMappedPoint(guest, argument[0], argument[1], false));
  define("MoveWindow", 6, (guest, argument) => guest.user.moveWindow(argument[0], argument[1], argument[2], argument[3], argument[4]));
  define("AdjustWindowRect", 3, () => 1); // no nonclient frame is served, so the rect is unchanged
  define("AdjustWindowRectEx", 4, (guest, argument) => {
    if ((argument[0] >>> 0) === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    return 1;
  });
  define("AdjustWindowRectExForDpi", 5, (guest, argument) => {
    if ((argument[0] >>> 0) === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    return 1;
  });
  define("SetProcessDPIAware", 0, (guest) => guest.user.setProcessDpiAware());
  define("SetProcessDpiAwarenessContext", 1, (guest, argument) => {
    const ok = guest.user.setProcessDpiAwarenessContext(argument[0]);
    if (ok === 0) guest.setLastError(guest.user.getLastError());
    return ok;
  });
  define("SetThreadDpiAwarenessContext", 1, (guest, argument) => {
    if (!guest.user.isValidDpiContext(argument[0])) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    return guest.user.setThreadDpiAwarenessContext(argument[0]);
  });
  define("GetThreadDpiAwarenessContext", 0, (guest) => guest.user.getDpiContext());
  define("GetAwarenessFromDpiAwarenessContext", 1, (guest, argument) => guest.user.awarenessFromDpiContext(argument[0]));
  define("AreDpiAwarenessContextsEqual", 2, (_guest, argument) => ((argument[0] | 0) === (argument[1] | 0) ? 1 : 0));
  define("IsValidDpiAwarenessContext", 1, (guest, argument) => (guest.user.isValidDpiContext(argument[0]) ? 1 : 0));
  define("EnableNonClientDpiScaling", 1, (guest, argument) => {
    if (!guest.user.isWindow(argument[0])) {
      guest.setLastError(0x578);
      guest.user.setLastError(0x578);
      return 0;
    }
    return 1;
  });
  define("GetDpiForWindow", 1, (guest, argument) => {
    if (!guest.user.isWindow(argument[0])) {
      guest.setLastError(0x578);
      guest.user.setLastError(0x578);
      return 0;
    }
    return 96;
  });
  define("GetSystemMetrics", 1, (guest, argument) => systemMetric[argument[0]] ?? 0);
  define("GetDoubleClickTime", 0, () => 500); // SPI_GETDOUBLECLICKTIME default, no host mouse
  define("MapVirtualKeyW", 2, (_guest, argument) => mapVirtualKey(argument[0], argument[1]));
  define("MapVirtualKeyA", 2, (_guest, argument) => mapVirtualKey(argument[0], argument[1]));
  define("ToUnicode", 6, (guest, argument) => {
    const dest = argument[3] >>> 0;
    const dest_count = argument[4] | 0;
    if (dest === 0 || dest_count <= 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    const key_state = new Uint8Array(256);
    const key_state_address = argument[2] >>> 0;
    if (key_state_address !== 0) {
      for (let index = 0; index < 256; index += 4) {
        const dword = guest.memory.readMemory(key_state_address + index, 4) >>> 0;
        key_state[index] = dword & 0xff;
        key_state[index + 1] = (dword >>> 8) & 0xff;
        key_state[index + 2] = (dword >>> 16) & 0xff;
        key_state[index + 3] = (dword >>> 24) & 0xff;
      }
    }
    const character = toUnicode(argument[0], argument[1], key_state);
    if (character === 0) return 0;
    guest.memory.writeMemory(dest, 2, character);
    return 1;
  });
  define("EnumDisplayMonitors", 4, (guest, argument) => {
    const hdc = argument[0] >>> 0;
    const clip = argument[1] >>> 0;
    const enumFunc = argument[2] >>> 0;
    const lParam = argument[3] >>> 0;
    if (enumFunc === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    const desktop = { left: 0, top: 0, right: systemMetric[0], bottom: systemMetric[1] };
    if (clip !== 0) {
      const left = guest.memory.readMemory(clip, 4) | 0;
      const top = guest.memory.readMemory(clip + 4, 4) | 0;
      const right = guest.memory.readMemory(clip + 8, 4) | 0;
      const bottom = guest.memory.readMemory(clip + 12, 4) | 0;
      if (right <= desktop.left || bottom <= desktop.top || left >= desktop.right || top >= desktop.bottom) {
        guest.setLastError(0);
        return 1;
      }
    }
    const rect = guest.allocate(16);
    writeRect(guest, rect, desktop);
    guest.pending_guest_call = {
      kind: "enum_callback",
      proc: enumFunc,
      argument: [virtualMonitorHandle, hdc, rect, lParam],
      result_kind: "enum_resource",
      remaining: [],
      module: virtualMonitorHandle,
      type_pointer: hdc,
      lparam: lParam,
      enum_func: enumFunc,
    };
    guest.setLastError(0);
    return 1;
  });

  // --- Plink import-surface widening (BPTK-146) ------------------------------
  // The window, input, and message-queue surface the Plink (win32) startup path
  // probes. With no window created and no host input device, the query returns
  // the honest empty answer; the ANSI message rows share the wide queue.
  define("FindWindowA", 2, (guest) => {
    // No window is enumerable by class or title name in the bounded probe.
    guest.user.setLastError(0);
    return 0;
  });
  define("GetCapture", 0, () => 0); // no window holds the mouse capture
  define("GetKeyState", 1, (guest, argument) => guest.user.getKeyState(argument[0]));
  define("GetAsyncKeyState", 1, (guest, argument) => guest.user.getAsyncKeyState(argument[0]));
  define("GetKeyboardState", 1, (guest, argument) => {
    const dest = argument[0] >>> 0;
    if (dest === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    const state = guest.user.keyboardState();
    for (let index = 0; index < 256; index += 4) {
      guest.memory.writeMemory(
        dest + index,
        4,
        (state[index] | (state[index + 1] << 8) | (state[index + 2] << 16) | (state[index + 3] << 24)) >>> 0,
      );
    }
    return 1;
  });
  define("GetClipboardOwner", 0, () => 0); // no window owns the clipboard
  define("GetForegroundWindow", 0, (guest) => guest.user.getActiveWindow());
  define("GetQueueStatus", 1, (guest, argument) => {
    // The high word is the currently-queued message type set; a pending message
    // reports its wake bit, an empty queue reports zero.
    const sink = {};
    if (guest.user.peekMessage(sink, false) !== 1) return 0;
    return ((argument[0] & 0xffff) << 16) >>> 0;
  });
  define("GetCursorPos", 1, (guest, argument) => {
    // No host pointer device is mapped, so the cursor rests at the origin.
    if (argument[0] === 0) {
      guest.user.setLastError(0x57);
      return 0;
    }
    guest.memory.writeMemory(argument[0], 4, 0);
    guest.memory.writeMemory(argument[0] + 4, 4, 0);
    return 1;
  });
  define("MsgWaitForMultipleObjects", 5, (guest, argument) => guest.messageWait(argument[0], argument[1], argument[2] !== 0, argument[3], argument[4]));
  define("PeekMessageA", 5, (guest, argument) => {
    const sink = {};
    const available = guest.user.peekMessage(sink, (argument[4] & 1) === 1);
    if (available === 1) writeMsg(guest, argument[0], sink.message);
    return available;
  });
  define("SendMessageA", 4, (guest, argument) => guest.user.sendMessage(argument[0], argument[1], argument[2], argument[3]));

  // ANSI twins and the dialog/menu/timer surface a Win32 GUI (PuTTYgen)
  // imports. String rows read ANSI; the window manager is encoding-blind.
  // CreateDialogParam / DialogBoxParam / DispatchMessage with a guest
  // procedure pointer ask the i386 probe to re-enter that pointer (the
  // _initterm twin) rather than swallowing WM_INITDIALOG host-side.
  function writeGuestText(guest, buffer, capacity, text, isWide) {
    if (buffer === 0) return 0;
    if (isWide) {
      const written = guest.writeWideString(buffer, text, capacity);
      return written.is_written ? written.length : capacity;
    }
    const written = guest.writeAnsiString(buffer, text, capacity);
    return written.is_written ? written.length : capacity;
  }
  function queueGuestProc(guest, handle, message, wParam, lParam, resultKind, hwndResult) {
    const proc = guest.user.getGuestWndProc(handle);
    if (proc === 0) return false;
    guest.pending_guest_call = {
      kind: "wnd_proc",
      proc,
      hwnd: handle >>> 0,
      message: message >>> 0,
      wparam: wParam >>> 0,
      lparam: lParam >>> 0,
      result_kind: resultKind,
      hwnd_result: (hwndResult ?? handle) >>> 0,
    };
    return true;
  }
  define("RegisterClassA", 1, (guest, argument) => {
    const base = argument[0];
    const style = guest.memory.readMemory(base + 0, 4);
    const wndProc = guest.memory.readMemory(base + 4, 4);
    const name = guest.readAnsiString(guest.memory.readMemory(base + 36, 4));
    return guest.user.registerClass(name, null, style, wndProc, classExtraFromStruct(guest, base, false));
  });
  define("CreateWindowExA", 12, (guest, argument) => guest.user.createWindowEx({
    ex_style: argument[0],
    class_name: classNameFromPointer(guest, argument[1], false),
    style: argument[3],
    x: argument[4] | 0,
    y: argument[5] | 0,
    width: argument[6] | 0,
    height: argument[7] | 0,
    parent: argument[8],
    control_id: argument[8] !== 0 ? argument[9] : 0,
    hinstance: argument[10],
    text: argument[2] === 0 || (argument[2] >>> 0) < 0x10000 ? "" : guest.readAnsiString(argument[2]),
    create_param: argument[11],
  }));
  define("GetMessageA", 4, (guest, argument) => {
    const sink = {};
    const code = guest.user.getMessage(sink);
    writeMsg(guest, argument[0], sink.message);
    return code;
  });
  define("DispatchMessageA", 1, (guest, argument) => {
    const message = readMsg(guest, argument[0]);
    if (queueGuestProc(guest, message.handle, message.message, message.w_param, message.l_param, "passthrough")) return 0;
    return guest.user.dispatchMessage(message);
  });
  define("PostMessageA", 4, (guest, argument) => guest.user.postMessage(argument[0], argument[1], argument[2], argument[3]));
  define("DefDlgProcA", 4, (guest, argument) => guest.user.defWindowProc(argument[0], argument[1], argument[2], argument[3]));
  define("GetWindowTextA", 3, (guest, argument) => writeGuestText(guest, argument[1], argument[2] >>> 0, guest.user.getWindowText(argument[0]), false));
  define("GetWindowTextW", 3, (guest, argument) => writeGuestText(guest, argument[1], argument[2] >>> 0, guest.user.getWindowText(argument[0]), true));
  define("GetWindowTextLengthA", 1, (guest, argument) => guest.user.getWindowText(argument[0]).length);
  define("GetWindowTextLengthW", 1, (guest, argument) => guest.user.getWindowText(argument[0]).length);
  function windowTitleFromPointer(guest, value, isWide) {
    if (value === 0 || (value >>> 0) < 0x10000) return "";
    return isWide ? guest.readWideString(value) : guest.readAnsiString(value);
  }
  define("SetWindowTextW", 2, (guest, argument) => guest.user.setWindowText(argument[0], windowTitleFromPointer(guest, argument[1], true)));
  define("SetWindowTextA", 2, (guest, argument) => guest.user.setWindowText(argument[0], windowTitleFromPointer(guest, argument[1], false)));
  define("GetDlgItem", 2, (guest, argument) => guest.user.getDlgItem(argument[0], argument[1]));
  define("GetDlgItemTextA", 4, (guest, argument) => writeGuestText(guest, argument[2], argument[3] >>> 0, guest.user.getWindowText(guest.user.getDlgItem(argument[0], argument[1])), false));
  define("SetDlgItemTextA", 3, (guest, argument) => guest.user.setWindowText(guest.user.getDlgItem(argument[0], argument[1]), argument[2] === 0 ? "" : guest.readAnsiString(argument[2])));
  define("GetDlgItemInt", 4, (guest, argument) => guest.user.getDlgItemInt(argument[0], argument[1]));
  define("SetDlgItemInt", 4, (guest, argument) => guest.user.setDlgItemInt(argument[0], argument[1], argument[2]));
  define("SendDlgItemMessageA", 5, (guest, argument) => guest.user.sendDlgItemMessage(argument[0], argument[1], argument[2], argument[3], argument[4]));
  define("IsDlgButtonChecked", 2, (guest, argument) => guest.user.isDlgButtonChecked(argument[0], argument[1]));
  define("CheckRadioButton", 4, (guest, argument) => guest.user.checkRadioButton(argument[0], argument[1], argument[2], argument[3]));
  define("EnableWindow", 2, (guest, argument) => guest.user.enableWindow(argument[0], argument[1]));
  define("GetWindowLongA", 2, (guest, argument) => guest.user.getWindowLong(argument[0], argument[1] | 0));
  define("GetWindowLongW", 2, (guest, argument) => guest.user.getWindowLong(argument[0], argument[1] | 0));
  define("SetWindowLongA", 3, (guest, argument) => guest.user.setWindowLong(argument[0], argument[1] | 0, argument[2]));
  define("SetWindowLongW", 3, (guest, argument) => guest.user.setWindowLong(argument[0], argument[1] | 0, argument[2]));
  function windowPropertyName(guest, value, isWide) {
    const pointer = value >>> 0;
    if (pointer === 0) return null;
    if (pointer < 0x10000) return pointer;
    const name = isWide ? guest.readWideString(pointer) : guest.readAnsiString(pointer);
    if (typeof name !== "string" || name.length === 0) return null;
    return name;
  }
  function setWindowProp(guest, argument, isWide) {
    const name = windowPropertyName(guest, argument[1], isWide);
    if (name === null) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    return guest.user.setProp(argument[0], name, argument[2]);
  }
  function getWindowProp(guest, argument, isWide) {
    const name = windowPropertyName(guest, argument[1], isWide);
    if (name === null) return 0;
    return guest.user.getProp(argument[0], name);
  }
  function removeWindowProp(guest, argument, isWide) {
    const name = windowPropertyName(guest, argument[1], isWide);
    if (name === null) return 0;
    return guest.user.removeProp(argument[0], name);
  }
  define("SetPropW", 3, (guest, argument) => setWindowProp(guest, argument, true));
  define("SetPropA", 3, (guest, argument) => setWindowProp(guest, argument, false));
  define("GetPropW", 2, (guest, argument) => getWindowProp(guest, argument, true));
  define("GetPropA", 2, (guest, argument) => getWindowProp(guest, argument, false));
  define("RemovePropW", 2, (guest, argument) => removeWindowProp(guest, argument, true));
  define("RemovePropA", 2, (guest, argument) => removeWindowProp(guest, argument, false));
  define("SetWindowPos", 7, (guest, argument) => guest.user.setWindowPos(argument[0], argument[1], argument[2], argument[3], argument[4], argument[5], argument[6]));
  define("SetActiveWindow", 1, (guest, argument) => guest.user.setActiveWindow(argument[0]));
  define("SetFocus", 1, (guest, argument) => guest.user.setFocusWindow(argument[0]));
  define("SetForegroundWindow", 1, (guest, argument) => {
    guest.user.setActiveWindow(argument[0]);
    return guest.user.isWindow(argument[0]) ? 1 : 0;
  });
  define("GetDesktopWindow", 0, (guest) => guest.user.getDesktopWindow());
  define("GetDC", 1, (guest, argument) => {
    const rect = guest.user.clientRect(argument[0]) ?? { right: 1, bottom: 1 };
    return guest.gdi.createDC(Math.max(rect.right, 1), Math.max(rect.bottom, 1));
  });
  define("ReleaseDC", 2, (guest, argument) => guest.gdi.deleteDC(argument[1]));
  define("LoadCursorA", 2, (_guest, argument) => (0x00008000 | (argument[1] & 0xffff)) >>> 0);
  define("LoadCursorW", 2, (_guest, argument) => (0x00008000 | (argument[1] & 0xffff)) >>> 0);
  define("LoadIconA", 2, (_guest, argument) => (0x00008100 | (argument[1] & 0xffff)) >>> 0);
  define("LoadIconW", 2, (_guest, argument) => (0x00008100 | (argument[1] & 0xffff)) >>> 0);
  function failIcon(guest, code) {
    guest.setLastError(code);
    guest.user.setLastError(code);
    return 0;
  }
  function allocateIcon(guest, record) {
    if (!guest.icon_by_handle) guest.icon_by_handle = new Map();
    if (guest.icon_by_handle.size >= 256) return failIcon(guest, 8);
    const handle = guest.icon_next ?? 0x00008200;
    guest.icon_next = handle + 4;
    guest.icon_by_handle.set(handle, record);
    return handle;
  }
  define("CreateIconIndirect", 1, (guest, argument) => {
    const base = argument[0] >>> 0;
    if (base === 0) return failIcon(guest, 87);
    const mask = guest.memory.readMemory(base + 12, 4) >>> 0;
    if (mask === 0) return failIcon(guest, 87);
    return allocateIcon(guest, {
      is_icon: guest.memory.readMemory(base, 4) !== 0,
      x: guest.memory.readMemory(base + 4, 4) >>> 0,
      y: guest.memory.readMemory(base + 8, 4) >>> 0,
      mask,
      color: guest.memory.readMemory(base + 16, 4) >>> 0,
    });
  });
  // CreateIconFromResource / Ex: RT_ICON (or RT_CURSOR) DIB bits, not a .ico
  // directory. A window icon does not need decoded pixels — SDL only needs a
  // live HICON to SendMessage(WM_SETICON). Version is the documented 0x30000.
  function createIconFromResource(guest, bit_address, size_byte, is_icon, version, width, height) {
    if (bit_address === 0 || size_byte === 0) return failIcon(guest, 87);
    if (version !== 0x00030000) return failIcon(guest, 87);
    let header_width = 0;
    let header_height = 0;
    if (size_byte >= 40) {
      const header_size = guest.memory.readMemory(bit_address, 4) >>> 0;
      if (header_size === 40 || header_size === 108 || header_size === 124) {
        header_width = Math.max(guest.memory.readMemory(bit_address + 4, 4) | 0, 0);
        const height_raw = guest.memory.readMemory(bit_address + 8, 4) | 0;
        header_height = Math.abs(height_raw) >> 1;
        if (header_height === 0) header_height = Math.abs(height_raw);
      }
    }
    return allocateIcon(guest, {
      is_icon: is_icon !== 0,
      x: 0,
      y: 0,
      mask: 0,
      color: 0,
      width: (width >>> 0) || (header_width >>> 0),
      height: (height >>> 0) || (header_height >>> 0),
      bit_address,
      size_byte,
    });
  }
  define("CreateIconFromResource", 4, (guest, argument) => createIconFromResource(
    guest,
    argument[0] >>> 0,
    argument[1] >>> 0,
    argument[2],
    argument[3] >>> 0,
    0,
    0,
  ));
  define("CreateIconFromResourceEx", 7, (guest, argument) => createIconFromResource(
    guest,
    argument[0] >>> 0,
    argument[1] >>> 0,
    argument[2],
    argument[3] >>> 0,
    argument[4] | 0,
    argument[5] | 0,
  ));
  function isStockImageHandle(guest, handle) {
    if (guest.icon_by_handle?.has(handle)) return false;
    // CreateIconIndirect allocates 0x8200 + 4n. LoadCursor/LoadIcon are 0x8000|id / 0x8100|id.
    if (handle >= 0x00008200 && handle < 0x00008600 && (handle & 3) === 0) return false;
    return handle >= 0x00008000 && handle <= 0x0000ffff;
  }
  define("DestroyIcon", 1, (guest, argument) => {
    const handle = argument[0] >>> 0;
    if (guest.icon_by_handle?.delete(handle)) return 1;
    if (isStockImageHandle(guest, handle)) return 1;
    guest.setLastError(6);
    guest.user.setLastError(6);
    return 0;
  });
  define("CopyImage", 5, (guest, argument) => {
    const handle = argument[0] >>> 0;
    const type = argument[1] >>> 0;
    const width = argument[2] | 0;
    const height = argument[3] | 0;
    const flags = argument[4] >>> 0;
    if (handle === 0 || (type !== 0 && type !== 1 && type !== 2)) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    const returnOriginal = (flags & 4) !== 0;
    const deleteOriginal = (flags & 8) !== 0;
    if (type === 0) {
      const bitmap = guest.gdi.lookupBitmap(handle);
      if (bitmap === null) {
        guest.setLastError(6);
        guest.user.setLastError(6);
        return 0;
      }
      if ((width !== 0 && width !== bitmap.width) || (height !== 0 && height !== bitmap.height)) {
        guest.setLastError(50);
        guest.user.setLastError(50);
        return 0;
      }
      if (returnOriginal) return handle;
      const copy = guest.gdi.copyBitmap(handle);
      if (deleteOriginal) guest.gdi.deleteObject(handle);
      return copy;
    }
    const icon = guest.icon_by_handle?.get(handle);
    if (icon === undefined && !isStockImageHandle(guest, handle)) {
      guest.setLastError(6);
      guest.user.setLastError(6);
      return 0;
    }
    if (returnOriginal && width === 0 && height === 0) return handle;
    const copy = allocateIcon(guest, {
      ...(icon === undefined
        ? { is_icon: type === 1, x: 0, y: 0, mask: 0, color: 0, stock: handle }
        : icon),
      width: width >>> 0,
      height: height >>> 0,
    });
    if (copy === 0) return 0;
    if (deleteOriginal && icon !== undefined) guest.icon_by_handle.delete(handle);
    return copy;
  });
  function systemParametersInfo(guest, action, pvParam) {
    const fail = (code) => {
      guest.setLastError(code);
      guest.user.setLastError(code);
      return 0;
    };
    if (pvParam === 0) return fail(87);
    if (action === 0x70) {
      guest.memory.writeMemory(pvParam, 4, 10);
      return 1;
    }
    if (action === 3) {
      guest.memory.writeMemory(pvParam, 4, 6);
      guest.memory.writeMemory(pvParam + 4, 4, 10);
      guest.memory.writeMemory(pvParam + 8, 4, 1);
      return 1;
    }
    if (action === 0x30) {
      guest.memory.writeMemory(pvParam, 4, 0);
      guest.memory.writeMemory(pvParam + 4, 4, 0);
      guest.memory.writeMemory(pvParam + 8, 4, systemMetric[0]);
      guest.memory.writeMemory(pvParam + 12, 4, systemMetric[1]);
      return 1;
    }
    if (action === 0x68) {
      guest.memory.writeMemory(pvParam, 4, 3);
      return 1;
    }
    if (action === 0x20) {
      guest.memory.writeMemory(pvParam, 4, 500);
      return 1;
    }
    return fail(87);
  }
  define("SystemParametersInfoA", 4, (guest, argument) => systemParametersInfo(guest, argument[0] >>> 0, argument[2] >>> 0));
  define("SystemParametersInfoW", 4, (guest, argument) => systemParametersInfo(guest, argument[0] >>> 0, argument[2] >>> 0));
  function registerWindowMessage(guest, name) {
    if (name.length === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    if (!guest.window_message_by_name) guest.window_message_by_name = new Map();
    const existing = guest.window_message_by_name.get(name);
    if (existing !== undefined) return existing;
    if (guest.window_message_by_name.size >= 256) {
      guest.setLastError(8);
      guest.user.setLastError(8);
      return 0;
    }
    const id = guest.window_message_next ?? 0x0000c000;
    guest.window_message_next = id + 1;
    guest.window_message_by_name.set(name, id);
    return id;
  }
  define("RegisterWindowMessageA", 1, (guest, argument) => registerWindowMessage(guest, argument[0] === 0 ? "" : guest.readAnsiString(argument[0])));
  define("RegisterWindowMessageW", 1, (guest, argument) => registerWindowMessage(guest, argument[0] === 0 ? "" : guest.readWideString(argument[0])));
  define("CreateMenu", 0, (guest) => guest.user.createMenu());
  define("AppendMenuA", 4, (guest, argument) => guest.user.appendMenu(argument[0], argument[1], argument[2], argument[3] === 0 || (argument[3] >>> 0) < 0x10000 ? "" : guest.readAnsiString(argument[3])));
  define("SetMenu", 2, (guest, argument) => guest.user.setMenu(argument[0], argument[1]));
  define("CheckMenuItem", 3, (guest, argument) => guest.user.checkMenuItem(argument[0], argument[1], argument[2]));
  define("CheckMenuRadioItem", 5, (guest, argument) => guest.user.checkMenuRadioItem(argument[0], argument[1], argument[2], argument[3], argument[4]));
  define("EnableMenuItem", 3, (guest, argument) => guest.user.enableMenuItem(argument[0], argument[1], argument[2]));
  define("SetTimer", 4, (guest, argument) => guest.user.setTimer(argument[0], argument[1], argument[2]));
  define("KillTimer", 2, (guest, argument) => guest.user.killTimer(argument[0], argument[1]));
  define("GetMessageTime", 0, (guest) => guest.clock.tickCount() >>> 0);
  define("MapDialogRect", 2, (guest, argument) => {
    const base = argument[1];
    if (base === 0) return 0;
    const mapped = guest.user.mapDialogRect(
      guest.memory.readMemory(base + 0, 4) | 0,
      guest.memory.readMemory(base + 4, 4) | 0,
      guest.memory.readMemory(base + 8, 4) | 0,
      guest.memory.readMemory(base + 12, 4) | 0,
    );
    guest.memory.writeMemory(base + 0, 4, mapped.left >>> 0);
    guest.memory.writeMemory(base + 4, 4, mapped.top >>> 0);
    guest.memory.writeMemory(base + 8, 4, mapped.right >>> 0);
    guest.memory.writeMemory(base + 12, 4, mapped.bottom >>> 0);
    return 1;
  });
  define("MessageBeep", 1, () => 1);
  define("MessageBoxA", 4, (guest, argument) => guest.user.messageBox(argument[1] === 0 ? "" : guest.readAnsiString(argument[1]), argument[2] === 0 ? "" : guest.readAnsiString(argument[2]), argument[3]));
  define("MessageBoxIndirectA", 1, (guest, argument) => {
    const base = argument[0];
    const text = guest.memory.readMemory(base + 8, 4);
    const caption = guest.memory.readMemory(base + 12, 4);
    const type = guest.memory.readMemory(base + 16, 4);
    return guest.user.messageBox(text === 0 ? "" : guest.readAnsiString(text), caption === 0 ? "" : guest.readAnsiString(caption), type);
  });
  define("IsDialogMessageA", 2, (guest, argument) => guest.user.isDialogMessage(argument[0], readMsg(guest, argument[1])));
  define("EndDialog", 2, (guest, argument) => guest.user.endDialog(argument[0], argument[1]));
  define("GetMonitorInfoW", 2, (guest, argument) => writeMonitorInfo(guest, argument[0], argument[1], true));
  define("GetMonitorInfoA", 2, (guest, argument) => writeMonitorInfo(guest, argument[0], argument[1], false));
  define("MonitorFromPoint", 2, (guest, argument) => {
    const point = argument[0] >>> 0;
    if (point === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    const x = guest.memory.readMemory(point, 4) | 0;
    const y = guest.memory.readMemory(point + 4, 4) | 0;
    guest.setLastError(0);
    guest.user.setLastError(0);
    return guest.user.monitorFromPoint(x, y, argument[1]);
  });
  define("MonitorFromRect", 2, (guest, argument) => {
    const rect = argument[0] >>> 0;
    if (rect === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    guest.setLastError(0);
    guest.user.setLastError(0);
    return guest.user.monitorFromRect(readRect(guest, rect), argument[1]);
  });
  define("MonitorFromWindow", 2, (guest, argument) => {
    guest.setLastError(0);
    guest.user.setLastError(0);
    return guest.user.monitorFromWindow(argument[0] >>> 0, argument[1]);
  });
  define("InvalidateRect", 3, (guest, argument) => guest.user.invalidateRect(argument[0] >>> 0));
  define("ValidateRect", 2, (guest, argument) => guest.user.validateRect(argument[0] >>> 0));
  define("GetUpdateRect", 3, (guest, argument) => {
    const rect = guest.user.updateRect(argument[0] >>> 0);
    if (rect === null) {
      guest.setLastError(0x578);
      return 0;
    }
    if ((argument[1] >>> 0) !== 0) writeRect(guest, argument[1], rect);
    return rect.is_empty ? 0 : 1;
  });
  // FillRect is a USER32 export (winuser.h). The paint lives on the GDI DC.
  define("FillRect", 3, (guest, argument) => {
    const base = argument[1] >>> 0;
    if (base === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    if (guest.gdi === undefined || typeof guest.gdi.fillRect !== "function") {
      guest.setLastError(6);
      guest.user.setLastError(6);
      return 0;
    }
    return guest.gdi.fillRect(argument[0], readRect(guest, base), argument[2]);
  });
  define("EnumDisplaySettingsW", 3, (guest, argument) => writeDisplaySettings(guest, argument[0], argument[1], argument[2], true));
  define("EnumDisplaySettingsA", 3, (guest, argument) => writeDisplaySettings(guest, argument[0], argument[1], argument[2], false));
  define("EnumDisplayDevicesW", 4, (guest, argument) => writeDisplayDevice(guest, argument[0], argument[1], argument[2], true));
  define("EnumDisplayDevicesA", 4, (guest, argument) => writeDisplayDevice(guest, argument[0], argument[1], argument[2], false));
  define("GetDisplayConfigBufferSizes", 3, (guest, argument) => {
    const numPath = argument[1] >>> 0;
    const numMode = argument[2] >>> 0;
    if (numPath === 0 || numMode === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 87;
    }
    guest.memory.writeMemory(numPath, 4, 1);
    guest.memory.writeMemory(numMode, 4, 2);
    guest.setLastError(0);
    guest.user.setLastError(0);
    return 0;
  });
  define("QueryDisplayConfig", 6, (guest, argument) => {
    const numPathPtr = argument[1] >>> 0;
    const pathArray = argument[2] >>> 0;
    const numModePtr = argument[3] >>> 0;
    const modeArray = argument[4] >>> 0;
    if (numPathPtr === 0 || numModePtr === 0 || pathArray === 0 || modeArray === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 87;
    }
    const pathCap = guest.memory.readMemory(numPathPtr, 4) >>> 0;
    const modeCap = guest.memory.readMemory(numModePtr, 4) >>> 0;
    if (pathCap < 1 || modeCap < 2) {
      guest.memory.writeMemory(numPathPtr, 4, 1);
      guest.memory.writeMemory(numModePtr, 4, 2);
      guest.setLastError(122);
      guest.user.setLastError(122);
      return 122;
    }
    guest.memory.writeBlock(pathArray, Buffer.alloc(72));
    guest.memory.writeBlock(modeArray, Buffer.alloc(128));
    guest.memory.writeMemory(pathArray + 16, 4, 1);
    guest.memory.writeMemory(pathArray + 68, 4, 1);
    guest.memory.writeMemory(modeArray, 4, 1);
    guest.memory.writeMemory(modeArray + 16, 4, systemMetric[0]);
    guest.memory.writeMemory(modeArray + 20, 4, systemMetric[1]);
    guest.memory.writeMemory(modeArray + 24, 4, 3);
    guest.memory.writeMemory(modeArray + 64, 4, 2);
    guest.memory.writeMemory(numPathPtr, 4, 1);
    guest.memory.writeMemory(numModePtr, 4, 2);
    const topology = argument[5] >>> 0;
    if (topology !== 0) guest.memory.writeMemory(topology, 4, 1);
    guest.setLastError(0);
    guest.user.setLastError(0);
    return 0;
  });
  define("DisplayConfigGetDeviceInfo", 1, (guest, argument) => {
    const header = argument[0] >>> 0;
    if (header === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 87;
    }
    const type = guest.memory.readMemory(header, 4) >>> 0;
    const size = guest.memory.readMemory(header + 4, 4) >>> 0;
    if (size < 20) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 87;
    }
    if ((type === 1 || type === 2) && size >= 84) writeGuestText(guest, header + 20, 32, "\\.\DISPLAY1", true);
    if (type === 4 && size >= 276) writeGuestText(guest, header + 20, 128, "BPTK Virtual Adapter", true);
    guest.setLastError(0);
    guest.user.setLastError(0);
    return 0;
  });
  function writeDisplayDevice(guest, device, index, info, isWide) {
    if (info === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    const name = device === 0 ? "" : (isWide ? guest.readWideString(device) : guest.readAnsiString(device));
    if (name !== "" && name.toLowerCase() !== "\\\\.\\display1") {
      guest.setLastError(0);
      guest.user.setLastError(0);
      return 0;
    }
    if ((index >>> 0) !== 0) {
      guest.setLastError(0);
      guest.user.setLastError(0);
      return 0;
    }
    const size = guest.memory.readMemory(info, 4) >>> 0;
    const charByte = isWide ? 2 : 1;
    const minSize = 4 + 32 * charByte + 128 * charByte + 4;
    if (size < minSize) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    writeGuestText(guest, info + 4, 32, "\\\\.\\DISPLAY1", isWide);
    writeGuestText(guest, info + 4 + 32 * charByte, 128, "Virtual Display", isWide);
    guest.memory.writeMemory(info + 4 + 32 * charByte + 128 * charByte, 4, 5);
    guest.setLastError(0);
    guest.user.setLastError(0);
    return 1;
  }
  function writeDisplaySettings(guest, device, mode, devmode, isWide) {
    if (devmode === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    const name = device === 0 ? "" : (isWide ? guest.readWideString(device) : guest.readAnsiString(device));
    if (name !== "" && name.toLowerCase() !== "\\\\.\\display1") {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    const modeIndex = mode >>> 0;
    if (modeIndex !== 0 && modeIndex !== 0xffffffff && modeIndex !== 0xfffffffe) {
      guest.setLastError(0);
      guest.user.setLastError(0);
      return 0;
    }
    const size = guest.memory.readMemory(devmode + 68, 2);
    if (size < 172) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    writeGuestText(guest, devmode, 32, "\\\\.\\DISPLAY1", isWide);
    guest.memory.writeMemory(devmode + 64, 2, 0x0401);
    guest.memory.writeMemory(devmode + 72, 4, 0x005c0000);
    guest.memory.writeMemory(devmode + 168, 4, 32);
    guest.memory.writeMemory(devmode + 172, 4, systemMetric[0]);
    guest.memory.writeMemory(devmode + 176, 4, systemMetric[1]);
    if (size >= 188) guest.memory.writeMemory(devmode + 184, 4, 60);
    guest.setLastError(0);
    guest.user.setLastError(0);
    return 1;
  }
  function writeMonitorInfo(guest, monitor, info, isWide) {
    if (info === 0) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    if ((monitor >>> 0) !== virtualMonitorHandle) {
      guest.setLastError(6);
      guest.user.setLastError(6);
      return 0;
    }
    const size = guest.memory.readMemory(info, 4) >>> 0;
    if (size < 40) {
      guest.setLastError(87);
      guest.user.setLastError(87);
      return 0;
    }
    writeRect(guest, info + 4, { left: 0, top: 0, right: systemMetric[0], bottom: systemMetric[1] });
    writeRect(guest, info + 20, { left: 0, top: 0, right: systemMetric[0], bottom: systemMetric[1] });
    guest.memory.writeMemory(info + 36, 4, 1);
    if (size >= (isWide ? 104 : 72)) writeGuestText(guest, info + 40, 32, "\\\\.\\DISPLAY1", isWide);
    guest.setLastError(0);
    guest.user.setLastError(0);
    return 1;
  }
  define("CreateDialogParamA", 5, (guest, argument) => guest.createDialogParam(argument[1], argument[3], argument[4], false));
  define("DialogBoxParamA", 5, (guest, argument) => guest.createDialogParam(argument[1], argument[3], argument[4], true));

  // comctl32.dll common-control initialization. A GUI program registers the
  // common control window classes at startup (PuTTY calls InitCommonControls
  // right after loading comctl32, before it opens its own window). The classes
  // are the stock comctl32 names; InitCommonControls remains void (return 0)
  // and InitCommonControlsEx reports success.
  const commonControlClass = [
    "msctls_progress32", "msctls_trackbar32", "msctls_updown32", "msctls_statusbar32",
    "msctls_hotkey32", "ToolbarWindow32", "ReBarWindow32",
    "SysListView32", "SysTreeView32", "SysTabControl32", "SysAnimate32",
    "SysMonthCal32", "SysDateTimePick32", "SysIPAddress32", "ComboBoxEx32",
  ];
  function registerCommonControls(guest) {
    for (const name of commonControlClass) guest.user.ensureClass(name);
  }
  function defineLib(library, symbol, argumentCount, emulate) {
    table.push(Object.freeze({ library, symbol, argument_count: argumentCount, emulate }));
  }
  defineLib("comctl32.dll", "InitCommonControls", 0, (guest) => {
    registerCommonControls(guest);
    return 0;
  });
  defineLib("comctl32.dll", "InitCommonControlsEx", 1, (guest) => {
    registerCommonControls(guest);
    return 1;
  });

  return table;
}

// The declared display and input metric profile: one deterministic virtual
// desktop so GetSystemMetrics returns a stable answer with no host display.
export const virtualMonitorHandle = 0x00020000;

export const monitorDefault = Object.freeze({
  to_null: 0,
  to_primary: 1,
  to_nearest: 2,
});

export const systemMetric = Object.freeze({
  0: 1920, // SM_CXSCREEN
  1: 1080, // SM_CYSCREEN
  2: 17, // SM_CXVSCROLL
  3: 17, // SM_CYHSCROLL
  4: 23, // SM_CYCAPTION
  5: 1, // SM_CXBORDER
  6: 1, // SM_CYBORDER
  11: 32, // SM_CXICON
  12: 32, // SM_CYICON
  16: 1920, // SM_CXFULLSCREEN
  17: 1057, // SM_CYFULLSCREEN
  23: 0, // SM_SWAPBUTTON
  28: 132, // SM_CXMIN
  29: 38, // SM_CYMIN
  43: 3, // SM_CMOUSEBUTTONS
});

export const userExportTable = Object.freeze(buildUserExportTable());
