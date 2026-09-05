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

// ---------------------------------------------------------------------------
// The window manager. One instance per guest process; owns the class
// registry, the window table, the per-thread queue, and the focus/active
// tracking that the lifecycle and input translation both read.
// ---------------------------------------------------------------------------

export function createUserSubsystem(option = {}) {
  const threadId = option.thread_id ?? userBound.thread_id_default;

  const classByName = new Map();
  const windowByHandle = new Map();
  const queueByThread = new Map();
  let nextAtom = 0xc000;
  let nextHandle = 0x00010010;
  let activeWindow = 0;
  let focusWindow = 0;
  let lastError = 0;

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
  function registerClass(name, wndProc, style = 0) {
    if (typeof name !== "string" || name.length === 0 || name.length > userBound.string_byte) {
      setLastError(0x57); // ERROR_INVALID_PARAMETER
      return 0;
    }
    if (classByName.has(name)) {
      setLastError(0x582); // ERROR_CLASS_ALREADY_EXISTS
      return 0;
    }
    if (classByName.size >= userBound.class_count) {
      throw userFault("user_class_exhausted", `The class registry exceeds ${userBound.class_count} class`);
    }
    const atom = nextAtom;
    nextAtom += 1;
    classByName.set(name, { atom, name, style: style >>> 0, wndProc: typeof wndProc === "function" ? wndProc : null });
    setLastError(0);
    return atom;
  }

  function unregisterClass(name) {
    if (!classByName.has(name)) {
      setLastError(0x5c9); // ERROR_CLASS_DOES_NOT_EXIST
      return 0;
    }
    for (const window of windowByHandle.values()) {
      if (window.class_name === name) {
        setLastError(0x582);
        return 0;
      }
    }
    classByName.delete(name);
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
    const klass = typeof className === "string" ? classByName.get(className) : undefined;
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
      style: (spec.style ?? 0) >>> 0,
      ex_style: (spec.ex_style ?? 0) >>> 0,
      x: spec.x ?? 0,
      y: spec.y ?? 0,
      width: spec.width ?? 0,
      height: spec.height ?? 0,
      thread_id: threadId,
      is_visible: false,
      needs_paint: false,
      is_destroyed: false,
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
    }
    return 1;
  }

  function invalidate(handle) {
    const window = windowByHandle.get(handle);
    if (window === undefined || window.is_destroyed) return 0;
    window.needs_paint = true;
    return 1;
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
  // A key event posts WM_KEYDOWN or WM_KEYUP to the focused window. A pointer
  // event posts the button pair or WM_MOUSEMOVE, with the position packed into
  // lParam. The target is always the current focus/active window; the trace
  // never names a window, so the translation stays generic.
  function injectKey(virtualKey, isDown) {
    const target = focusWindow !== 0 ? focusWindow : activeWindow;
    if (target === 0) return 0;
    const message = isDown ? windowMessage.WM_KEYDOWN : windowMessage.WM_KEYUP;
    const repeat = isDown ? 1 : 0xc0000001; // key-up carries the transition/prior-state bits
    return postMessage(target, message, virtualKey >>> 0, repeat >>> 0);
  }

  function injectMouse(event) {
    const target = activeWindow !== 0 ? activeWindow : focusWindow;
    if (target === 0) return 0;
    const point = makePoint(event.x ?? 0, event.y ?? 0);
    if (event.button === undefined || event.button === null) {
      return postMessage(target, windowMessage.WM_MOUSEMOVE, 0, point);
    }
    const button = pointerButton[event.button];
    if (button === undefined) {
      setLastError(0x57);
      return 0;
    }
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

  return {
    thread_id: threadId,
    getLastError: () => lastError,
    setLastError,
    getActiveWindow: () => activeWindow,
    getFocus: () => focusWindow,
    windowCount: () => windowByHandle.size,
    classCount: () => classByName.size,
    isWindow: (handle) => windowByHandle.has(handle),
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
    getMessage,
    peekMessage,
    translateMessage,
    dispatchMessage,
    injectKey,
    injectMouse,
    replayInput,
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
  define("RegisterClassW", 1, (guest, argument) => {
    const base = argument[0];
    const style = guest.memory.readMemory(base + 0, 4);
    const wndProc = guest.memory.readMemory(base + 4, 4);
    const name = guest.readWideString(guest.memory.readMemory(base + 36, 4));
    return guest.user.registerClass(name, wndProc, style);
  });
  define("RegisterClassExW", 1, (guest, argument) => {
    const base = argument[0];
    const style = guest.memory.readMemory(base + 4, 4);
    const wndProc = guest.memory.readMemory(base + 8, 4);
    const name = guest.readWideString(guest.memory.readMemory(base + 40, 4));
    return guest.user.registerClass(name, wndProc, style);
  });
  define("UnregisterClassW", 2, (guest, argument) => guest.user.unregisterClass(guest.readWideString(argument[0])));
  define("CreateWindowExW", 12, (guest, argument) => guest.user.createWindowEx({
    class_name: guest.readWideString(argument[1]),
    style: argument[3],
    x: argument[4] | 0,
    y: argument[5] | 0,
    width: argument[6] | 0,
    height: argument[7] | 0,
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
  define("MoveWindow", 6, (guest, argument) => guest.user.moveWindow(argument[0], argument[1], argument[2], argument[3], argument[4]));
  define("AdjustWindowRect", 3, () => 1); // no nonclient frame is served, so the rect is unchanged
  define("GetSystemMetrics", 1, (guest, argument) => systemMetric[argument[0]] ?? 0);

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

  // comctl32.dll common-control initialization. A GUI program registers the
  // common control window classes at startup (PuTTY calls InitCommonControls
  // right after loading comctl32, before it opens its own window). The bounded
  // probe renders nothing, so registering the classes is a real no-op that
  // returns control to the caller; InitCommonControlsEx reports success.
  function defineLib(library, symbol, argumentCount, emulate) {
    table.push(Object.freeze({ library, symbol, argument_count: argumentCount, emulate }));
  }
  defineLib("comctl32.dll", "InitCommonControls", 0, () => 0);
  defineLib("comctl32.dll", "InitCommonControlsEx", 1, () => 1);

  return table;
}

// The declared display and input metric profile: one deterministic virtual
// desktop so GetSystemMetrics returns a stable answer with no host display.
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
