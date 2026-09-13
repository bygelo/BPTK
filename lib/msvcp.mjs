// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Leftover msvcp140 sidecar IAT — generic Win32 HLE, no title branch.
// A mapped msvcp140.dll still imports the Vista threadpool, InitOnce
// execute-once, and the leftover C++ / UCRT surface that is not a package-
// local export. Those rows bind here so a sidecar IAT slot is a real thunk
// instead of a hint RVA. The bounded probe has one worker: Submit runs the
// work callback through pending_guest_call (the same re-enter the SEH
// handler uses). An x87-double CRT return stays unserved; faking ST(0)
// through EAX would be a wrong answer.

const errorInvalidParameter = 87;
const errorInvalidHandle = 6;
const cxxException = 0xe06d7363;
const exceptionContinueSearch = 1;

const ctypeUpper = 0x0001;
const ctypeLower = 0x0002;
const ctypeDigit = 0x0004;
const ctypeSpace = 0x0008;
const ctypePunct = 0x0010;
const ctypeControl = 0x0020;
const ctypeBlank = 0x0040;
const ctypeHex = 0x0080;

function unsigned(value) {
  return value >>> 0;
}

function abortProcess(guest) {
  const row = guest.lookupExport("msvcrt.dll", "abort");
  if (row != null) return row.emulate(guest, []);
  const exit = guest.lookupExport("kernel32.dll", "ExitProcess");
  if (exit != null) return exit.emulate(guest, [3]);
  return 3;
}

function failParameter(guest) {
  guest.setLastError(errorInvalidParameter);
  return 0;
}

function failHandle(guest) {
  guest.setLastError(errorInvalidHandle);
  return 0;
}

function ctypeFlags(code) {
  const ch = code & 0xff;
  if (ch > 127) return 0;
  let flag = 0;
  if (ch >= 0x41 && ch <= 0x5a) flag |= ctypeUpper;
  if (ch >= 0x61 && ch <= 0x7a) flag |= ctypeLower;
  if (ch >= 0x30 && ch <= 0x39) flag |= ctypeDigit;
  if (ch === 0x20 || (ch >= 0x09 && ch <= 0x0d)) flag |= ctypeSpace;
  if ((ch >= 0x21 && ch <= 0x2f) || (ch >= 0x3a && ch <= 0x40) || (ch >= 0x5b && ch <= 0x60) || (ch >= 0x7b && ch <= 0x7e)) flag |= ctypePunct;
  if (ch < 0x20 || ch === 0x7f) flag |= ctypeControl;
  if (ch === 0x20 || ch === 0x09) flag |= ctypeBlank;
  if ((ch >= 0x30 && ch <= 0x39) || (ch >= 0x41 && ch <= 0x46) || (ch >= 0x61 && ch <= 0x66)) flag |= ctypeHex;
  return flag;
}

function isWideClass(code, mask) {
  return (ctypeFlags(code) & mask) !== 0 ? 1 : 0;
}

function msvcpOf(guest) {
  if (guest.msvcp != null) return guest.msvcp;
  const table = new Map();
  const state = {
    next: 0x00030000,
    table,
    new_handler: 0,
    exception: 0,
    last_exception: 0,
    pctype: 0,
    locale_names: 0,
    days: 0,
    months: 0,
    tnames: 0,
    allocate() {
      const handle = state.next;
      state.next += 4;
      return handle;
    },
    put(kind, extra) {
      const handle = state.allocate();
      table.set(handle, { kind, ...extra });
      return handle;
    },
    get(handle, kind) {
      const record = table.get(unsigned(handle));
      return record !== undefined && record.kind === kind ? record : null;
    },
    close(handle) {
      return table.delete(unsigned(handle));
    },
  };
  guest.msvcp = state;
  return state;
}

function ensurePctype(guest) {
  const state = msvcpOf(guest);
  if (state.pctype !== 0) return state.pctype;
  const base = guest.allocate(257 * 2);
  guest.memory.writeBlock(base, Buffer.alloc(257 * 2));
  for (let code = 0; code < 256; code += 1) guest.memory.writeMemory(base + 2 + code * 2, 2, ctypeFlags(code));
  state.pctype = (base + 2) >>> 0;
  return state.pctype;
}

function writeCString(guest, text) {
  const address = guest.allocate(text.length + 1);
  guest.writeAnsiString(address, text, text.length + 1);
  return address;
}

function writeWideCString(guest, text) {
  const address = guest.allocate((text.length + 1) * 2);
  guest.writeWideString(address, text, text.length + 1);
  return address;
}

function ensureLocaleNames(guest) {
  const state = msvcpOf(guest);
  if (state.locale_names !== 0) return state.locale_names;
  const name = writeWideCString(guest, "C");
  const table = guest.allocate(6 * 4);
  for (let index = 0; index < 6; index += 1) guest.memory.writeMemory(table + index * 4, 4, name);
  state.locale_names = table;
  return table;
}

function ensureDays(guest) {
  const state = msvcpOf(guest);
  if (state.days !== 0) return state.days;
  state.days = writeCString(guest, ":Sun:Sunday:Mon:Monday:Tue:Tuesday:Wed:Wednesday:Thu:Thursday:Fri:Friday:Sat:Saturday");
  return state.days;
}

function ensureMonths(guest) {
  const state = msvcpOf(guest);
  if (state.months !== 0) return state.months;
  state.months = writeCString(guest, ":Jan:January:Feb:February:Mar:March:Apr:April:May:May:Jun:June:Jul:July:Aug:August:Sep:September:Oct:October:Nov:November:Dec:December");
  return state.months;
}

function ensureTnames(guest) {
  const state = msvcpOf(guest);
  if (state.tnames !== 0) return state.tnames;
  const days = ensureDays(guest);
  const months = ensureMonths(guest);
  const am = writeCString(guest, "AM");
  const pm = writeCString(guest, "PM");
  const block = guest.allocate(32);
  guest.memory.writeBlock(block, Buffer.alloc(32));
  guest.memory.writeMemory(block, 4, days);
  guest.memory.writeMemory(block + 4, 4, months);
  guest.memory.writeMemory(block + 8, 4, am);
  guest.memory.writeMemory(block + 12, 4, pm);
  state.tnames = block;
  return block;
}

function fireCallback(guest, proc, argument) {
  if (unsigned(proc) === 0) return;
  guest.pending_guest_call = {
    kind: "msvcp_callback",
    proc: unsigned(proc),
    argument: argument.map((value) => unsigned(value)),
  };
}

function createPoolObject(guest, kind, callback, context) {
  if (unsigned(callback) === 0) return failParameter(guest);
  return msvcpOf(guest).put(kind, {
    callback: unsigned(callback),
    context: unsigned(context),
    submitted: false,
    completed: false,
    wait_handle: 0,
    cancelled: false,
  });
}

function closePoolObject(guest, handle, kind) {
  if (unsigned(handle) === 0) return failHandle(guest);
  if (!msvcpOf(guest).close(handle)) return failHandle(guest);
  return 0;
}

function submitWork(guest, handle) {
  const record = msvcpOf(guest).get(handle, "work");
  if (record === null) return failHandle(guest);
  record.submitted = true;
  record.completed = true;
  fireCallback(guest, record.callback, [1, record.context, unsigned(handle)]);
  return 0;
}

function setPoolWait(guest, handle, objectHandle) {
  const record = msvcpOf(guest).get(handle, "wait");
  if (record === null) return failHandle(guest);
  record.wait_handle = unsigned(objectHandle);
  record.cancelled = unsigned(objectHandle) === 0;
  if (record.cancelled) return 0;
  fireCallback(guest, record.callback, [1, record.context, unsigned(handle)]);
  record.completed = true;
  return 0;
}

function setPoolTimer(guest, handle, duePointer) {
  const record = msvcpOf(guest).get(handle, "timer");
  if (record === null) return failHandle(guest);
  record.cancelled = unsigned(duePointer) === 0;
  if (record.cancelled) return 0;
  fireCallback(guest, record.callback, [1, record.context, unsigned(handle)]);
  record.completed = true;
  return 0;
}

function waitPoolObject(guest, handle, kind) {
  const record = msvcpOf(guest).get(handle, kind);
  if (record === null) return failHandle(guest);
  return 0;
}

function readAnsiOrEmpty(guest, address) {
  if (unsigned(address) === 0) return "";
  return guest.readAnsiString(address) ?? "";
}

function readWideOrEmpty(guest, address) {
  if (unsigned(address) === 0) return "";
  return guest.readWideString(address) ?? "";
}

function crtFail(guest) {
  if (typeof guest.crtErrno === "function") guest.crtErrno(22);
  return 0xffffffff;
}

function buildMsvcpExportTable() {
  const table = [];
  function define(library, symbol, argumentCount, emulate) {
    table.push(Object.freeze({ library, symbol, argument_count: argumentCount, emulate }));
  }
  function defineEach(libraryList, symbol, argumentCount, emulate) {
    for (const library of libraryList) define(library, symbol, argumentCount, emulate);
  }

  const msvcrt = "msvcrt.dll";
  const vcrt = "vcruntime140.dll";
  const crtRuntime = "api-ms-win-crt-runtime-l1-1-0.dll";
  const crtString = "api-ms-win-crt-string-l1-1-0.dll";
  const crtLocale = "api-ms-win-crt-locale-l1-1-0.dll";
  const crtStdio = "api-ms-win-crt-stdio-l1-1-0.dll";
  const crtFs = "api-ms-win-crt-filesystem-l1-1-0.dll";
  const crtTime = "api-ms-win-crt-time-l1-1-0.dll";
  const crtEnv = "api-ms-win-crt-environment-l1-1-0.dll";
  const crtMath = "api-ms-win-crt-math-l1-1-0.dll";
  const crtConvert = "api-ms-win-crt-convert-l1-1-0.dll";

  // --- kernel32 threadpool / leftover C++ runtime imports -------------------
  define("kernel32.dll", "CreateThreadpoolWork", 3, (guest, argument) => createPoolObject(guest, "work", argument[0], argument[1]));
  define("kernel32.dll", "SubmitThreadpoolWork", 1, (guest, argument) => submitWork(guest, argument[0]));
  define("kernel32.dll", "WaitForThreadpoolWorkCallbacks", 2, (guest, argument) => waitPoolObject(guest, argument[0], "work"));
  define("kernel32.dll", "CloseThreadpoolWork", 1, (guest, argument) => closePoolObject(guest, argument[0], "work"));
  define("kernel32.dll", "CreateThreadpoolWait", 3, (guest, argument) => createPoolObject(guest, "wait", argument[0], argument[1]));
  define("kernel32.dll", "SetThreadpoolWait", 3, (guest, argument) => setPoolWait(guest, argument[0], argument[1]));
  define("kernel32.dll", "CloseThreadpoolWait", 1, (guest, argument) => closePoolObject(guest, argument[0], "wait"));
  define("kernel32.dll", "CreateThreadpoolTimer", 3, (guest, argument) => createPoolObject(guest, "timer", argument[0], argument[1]));
  define("kernel32.dll", "SetThreadpoolTimer", 4, (guest, argument) => setPoolTimer(guest, argument[0], argument[1]));
  define("kernel32.dll", "WaitForThreadpoolTimerCallbacks", 2, (guest, argument) => waitPoolObject(guest, argument[0], "timer"));
  define("kernel32.dll", "CloseThreadpoolTimer", 1, (guest, argument) => closePoolObject(guest, argument[0], "timer"));
  define("kernel32.dll", "FreeLibraryWhenCallbackReturns", 2, () => 0);
  define("kernel32.dll", "GetCurrentProcessorNumber", 0, () => 0);
  define("kernel32.dll", "FlushProcessWriteBuffers", 0, () => 0);
  define("kernel32.dll", "CreateSemaphoreExW", 6, (guest, argument) => {
    if (unsigned(argument[4]) !== 0) return failParameter(guest);
    return guest.createSemaphore(argument[1] | 0, argument[2] | 0, argument[3], true);
  });
  define("kernel32.dll", "InitOnceExecuteOnce", 4, (guest, argument) => {
    const once = unsigned(argument[0]);
    const fn = unsigned(argument[1]);
    const parameter = unsigned(argument[2]);
    const context = unsigned(argument[3]);
    if (once === 0 || fn === 0) return failParameter(guest);
    const value = guest.memory.readMemory(once, 4) >>> 0;
    if ((value & 1) !== 0) {
      if (context !== 0) guest.memory.writeMemory(context, 4, value & ~3);
      return 1;
    }
    guest.memory.writeMemory(once, 4, 1);
    fireCallback(guest, fn, [once, parameter, context]);
    return 1;
  });
  define("kernel32.dll", "RtlCaptureStackBackTrace", 4, (guest, argument) => {
    const capture = unsigned(argument[1]);
    const dest = unsigned(argument[2]);
    if (capture === 0 || dest === 0) return 0;
    const count = Math.min(capture, 32);
    guest.memory.writeBlock(dest, Buffer.alloc(count * 4));
    if (unsigned(argument[3]) !== 0) guest.memory.writeMemory(unsigned(argument[3]), 4, 0);
    return 0;
  });

  // --- vcruntime140 C++ EH / exception ABI ----------------------------------
  define(vcrt, "_except_handler4_common", 6, () => exceptionContinueSearch);
  define(vcrt, "__CxxFrameHandler3", 4, () => exceptionContinueSearch);
  define(vcrt, "_CxxThrowException", 2, (guest, argument) => {
    msvcpOf(guest).last_exception = unsigned(argument[0]);
    return guest.raiseStructuredException(cxxException, 1, [unsigned(argument[0]), unsigned(argument[1])]);
  });
  define(vcrt, "__AdjustPointer", 2, (guest, argument) => {
    const pointer = unsigned(argument[0]);
    const pmd = unsigned(argument[1]);
    if (pointer === 0 || pmd === 0) return pointer;
    const mdisp = guest.memory.readMemory(pmd, 4) | 0;
    const pdisp = guest.memory.readMemory(pmd + 4, 4) | 0;
    const vdisp = guest.memory.readMemory(pmd + 8, 4) | 0;
    let adjusted = (pointer + mdisp) >>> 0;
    if (pdisp >= 0) {
      const vbtable = guest.memory.readMemory((adjusted + pdisp) >>> 0, 4) >>> 0;
      adjusted = (adjusted + vbtable + vdisp) >>> 0;
    }
    return adjusted;
  });
  define(vcrt, "__current_exception", 0, (guest) => msvcpOf(guest).last_exception);
  define(vcrt, "__current_exception_context", 0, () => 0);
  define(vcrt, "__uncaught_exception", 0, () => 0);
  define(vcrt, "__uncaught_exceptions", 0, () => 0);
  define(vcrt, "__std_terminate", 0, (guest) => abortProcess(guest));
  define(vcrt, "_purecall", 0, (guest) => abortProcess(guest));
  define(vcrt, "__std_exception_copy", 2, (guest, argument) => {
    const from = unsigned(argument[0]);
    const to = unsigned(argument[1]);
    if (from === 0 || to === 0) return 0;
    guest.memory.writeMemory(to, 4, guest.memory.readMemory(from, 4));
    guest.memory.writeMemory(to + 4, 4, guest.memory.readMemory(from + 4, 4));
    return 0;
  });
  define(vcrt, "__std_exception_destroy", 1, () => 0);
  define(vcrt, "__std_type_info_destroy_list", 1, () => 0);

  // --- leftover UCRT / C++ runtime ------------------------------------------
  defineEach([crtRuntime, msvcrt], "terminate", 0, (guest) => abortProcess(guest));
  defineEach([crtRuntime, msvcrt], "_initterm_e", 2, () => 0);
  defineEach([crtRuntime, msvcrt], "_execute_onexit_table", 1, () => 0);
  defineEach([crtRuntime, msvcrt], "_set_new_handler", 1, (guest, argument) => {
    const state = msvcpOf(guest);
    const previous = state.new_handler;
    state.new_handler = unsigned(argument[0]);
    return previous;
  });
  defineEach([crtRuntime, msvcrt], "_invoke_watson", 5, (guest) => abortProcess(guest));
  defineEach([crtRuntime, msvcrt], "_seh_filter_dll", 2, () => 0);

  defineEach([crtString, msvcrt], "strcspn", 2, (guest, argument) => {
    const text = readAnsiOrEmpty(guest, argument[0]);
    const reject = readAnsiOrEmpty(guest, argument[1]);
    for (let index = 0; index < text.length; index += 1) if (reject.includes(text[index])) return index;
    return text.length;
  });
  defineEach([crtString, msvcrt], "_wcsdup", 1, (guest, argument) => {
    const text = guest.readWideString(argument[0]);
    if (text === null) return 0;
    const address = guest.crtMalloc((text.length + 1) * 2);
    if (address === 0) return 0;
    guest.writeWideString(address, text, text.length + 1);
    return address;
  });
  defineEach([crtString, msvcrt], "wcsnlen", 2, (guest, argument) => {
    const bound = unsigned(argument[1]);
    if (unsigned(argument[0]) === 0) return 0;
    const text = guest.readWideString(argument[0]) ?? "";
    return Math.min(text.length, bound);
  });
  defineEach([crtString, msvcrt], "__strncnt", 2, (guest, argument) => {
    const bound = unsigned(argument[1]);
    if (unsigned(argument[0]) === 0) return 0;
    const text = guest.readAnsiString(argument[0]) ?? "";
    return Math.min(text.length, bound);
  });
  defineEach([crtString, msvcrt], "wcscpy_s", 3, (guest, argument) => {
    const dest = unsigned(argument[0]);
    const count = unsigned(argument[1]);
    const text = guest.readWideString(argument[2]);
    if (dest === 0 || count === 0 || text === null || text.length + 1 > count) return 22;
    guest.writeWideString(dest, text, count);
    return 0;
  });
  defineEach([crtString, msvcrt], "iswalnum", 1, (guest, argument) => isWideClass(argument[0], ctypeUpper | ctypeLower | ctypeDigit));
  defineEach([crtString, msvcrt], "iswxdigit", 1, (guest, argument) => isWideClass(argument[0], ctypeHex));
  defineEach([crtString, msvcrt], "iswdigit", 1, (guest, argument) => isWideClass(argument[0], ctypeDigit));
  defineEach([crtString, msvcrt], "iswspace", 1, (guest, argument) => isWideClass(argument[0], ctypeSpace));

  defineEach([crtLocale, msvcrt], "___lc_locale_name_func", 0, (guest) => ensureLocaleNames(guest));
  defineEach([crtLocale, msvcrt], "_lock_locales", 0, () => 0);
  defineEach([crtLocale, msvcrt], "_unlock_locales", 0, () => 0);
  defineEach([crtLocale, msvcrt], "___lc_codepage_func", 0, () => 1252);
  defineEach([crtLocale, msvcrt], "___lc_collate_cp_func", 0, () => 1252);
  defineEach([crtLocale, msvcrt], "__pctype_func", 0, (guest) => ensurePctype(guest));

  defineEach([crtStdio, msvcrt], "fputs", 2, (guest, argument) => {
    const text = readAnsiOrEmpty(guest, argument[0]);
    const written = guest.crtWriteStream(argument[1], Buffer.from(text, "latin1"));
    return written < 0 ? 0xffffffff : 0;
  });
  defineEach([crtStdio, msvcrt], "fgetc", 1, (guest, argument) => {
    const record = guest.crtFileRecord(argument[0]);
    if (record === null || record.object.position >= record.object.data.length) return 0xffffffff;
    const value = record.object.data[record.object.position];
    record.object.position += 1;
    return value;
  });
  defineEach([crtStdio, msvcrt], "fgetwc", 1, (guest, argument) => {
    const row = guest.lookupExport(msvcrt, "fgetc") ?? guest.lookupExport("api-ms-win-crt-stdio-l1-1-0.dll", "fgetc");
    const value = row.emulate(guest, [argument[0]]);
    return value === 0xffffffff ? 0xffffffff : value & 0xff;
  });
  defineEach([crtStdio, msvcrt], "fputwc", 2, (guest, argument) => {
    const written = guest.crtWriteStream(argument[1], Buffer.from([argument[0] & 0xff]));
    return written < 0 ? 0xffffffff : argument[0] & 0xffff;
  });
  defineEach([crtStdio, msvcrt], "ungetc", 2, (guest, argument) => {
    const record = guest.crtFileRecord(argument[1]);
    if (record === null || record.object.position <= 0) return 0xffffffff;
    record.object.position -= 1;
    return argument[0] & 0xff;
  });
  defineEach([crtStdio, msvcrt], "ungetwc", 2, (guest, argument) => {
    const row = guest.lookupExport(msvcrt, "ungetc");
    const value = row.emulate(guest, [argument[0] & 0xff, argument[1]]);
    return value === 0xffffffff ? 0xffffffff : argument[0] & 0xffff;
  });
  defineEach([crtStdio, msvcrt], "_fsopen", 3, (guest, argument) => {
    const open = guest.lookupExport(msvcrt, "fopen");
    return open.emulate(guest, [argument[0], argument[1]]);
  });
  defineEach([crtStdio, msvcrt], "_wfsopen", 3, (guest, argument) => {
    const open = guest.lookupExport(msvcrt, "_wfopen");
    return open.emulate(guest, [argument[0], argument[1]]);
  });
  defineEach([crtStdio, msvcrt], "_get_stream_buffer_pointers", 4, (guest, argument) => {
    for (let index = 1; index <= 3; index += 1) {
      if (unsigned(argument[index]) !== 0) guest.memory.writeMemory(unsigned(argument[index]), 4, 0);
    }
    return 0;
  });
  defineEach([crtStdio, msvcrt], "fgetpos", 2, (guest, argument) => {
    const dest = unsigned(argument[1]);
    if (dest === 0) return crtFail(guest);
    const position = guest.crtFtell(argument[0]);
    if (position < 0) return 0xffffffff;
    guest.memory.writeMemory(dest, 4, position >>> 0);
    guest.memory.writeMemory(dest + 4, 4, 0);
    return 0;
  });
  defineEach([crtStdio, msvcrt], "fsetpos", 2, (guest, argument) => {
    const src = unsigned(argument[1]);
    if (src === 0) return crtFail(guest);
    const position = guest.memory.readMemory(src, 4) | 0;
    return unsigned(guest.crtFseek(argument[0], position, 0));
  });
  defineEach([crtStdio, msvcrt], "_fseeki64", 4, (guest, argument) => unsigned(guest.crtFseek(argument[0], argument[1] | 0, unsigned(argument[3]))));

  defineEach([crtFs, msvcrt], "_wrmdir", 1, (guest, argument) => (guest.removeDirectory(guest.readWideString(argument[0])) ? 0 : 0xffffffff));
  defineEach([crtFs, msvcrt], "_wchdir", 1, (guest, argument) => (guest.setCurrentDirectory(guest.readWideString(argument[0])) ? 0 : 0xffffffff));
  defineEach([crtFs, msvcrt], "_wremove", 1, (guest, argument) => (guest.deleteFile(guest.readWideString(argument[0])) ? 0 : 0xffffffff));
  defineEach([crtFs, msvcrt], "_wrename", 2, (guest, argument) => (guest.moveFile(guest.readWideString(argument[0]), guest.readWideString(argument[1]), 0) ? 0 : 0xffffffff));
  defineEach([crtFs, msvcrt], "_lock_file", 1, () => 0);
  defineEach([crtFs, msvcrt], "_unlock_file", 1, () => 0);

  defineEach([crtTime, msvcrt], "_Getdays", 0, (guest) => ensureDays(guest));
  defineEach([crtTime, msvcrt], "_Getmonths", 0, (guest) => ensureMonths(guest));
  defineEach([crtTime, msvcrt], "_Gettnames", 0, (guest) => ensureTnames(guest));
  defineEach([crtTime, msvcrt], "_W_Getdays", 0, (guest) => {
    const state = msvcpOf(guest);
    if (state.wdays) return state.wdays;
    state.wdays = writeWideCString(guest, ":Sun:Sunday:Mon:Monday:Tue:Tuesday:Wed:Wednesday:Thu:Thursday:Fri:Friday:Sat:Saturday");
    return state.wdays;
  });
  defineEach([crtTime, msvcrt], "_W_Getmonths", 0, (guest) => {
    const state = msvcpOf(guest);
    if (state.wmonths) return state.wmonths;
    state.wmonths = writeWideCString(guest, ":Jan:January:Feb:February:Mar:March:Apr:April:May:May:Jun:June:Jul:July:Aug:August:Sep:September:Oct:October:Nov:November:Dec:December");
    return state.wmonths;
  });
  defineEach([crtTime, msvcrt], "_W_Gettnames", 0, (guest) => ensureTnames(guest));
  defineEach([crtTime, msvcrt], "_Strftime", 6, (guest, argument) => {
    const existing = guest.lookupExport(msvcrt, "strftime");
    return existing.emulate(guest, [argument[0], argument[1], argument[2], argument[3]]);
  });
  defineEach([crtTime, msvcrt], "_Wcsftime", 6, (guest, argument) => {
    const dest = unsigned(argument[0]);
    const max = unsigned(argument[1]);
    if (dest === 0 || max === 0) return 0;
    const ansi = guest.allocate(max);
    const written = guest.lookupExport(msvcrt, "strftime").emulate(guest, [ansi, max, argument[2], argument[3]]);
    const text = written > 0 ? guest.readAnsiString(ansi) ?? "" : "";
    guest.writeWideString(dest, text, max);
    return text.length;
  });

  defineEach([crtEnv, msvcrt], "_wgetcwd", 2, (guest, argument) => {
    const path = guest.currentDirectoryText();
    const needed = path.length + 1;
    const dest = unsigned(argument[0]) === 0 ? guest.crtMalloc(needed * 2) : unsigned(argument[0]);
    const count = unsigned(argument[0]) === 0 ? needed : unsigned(argument[1]);
    if (dest === 0 || count < needed) return 0;
    guest.writeWideString(dest, path.replace(/^c:/, "C:"), count);
    return dest;
  });

  defineEach([crtMath, msvcrt], "_dclass", 2, (guest, argument) => {
    const lo = unsigned(argument[0]);
    const hi = unsigned(argument[1]);
    const exp = (hi >>> 20) & 0x7ff;
    if (exp === 0) return (hi & 0xfffff) === 0 && lo === 0 ? 2 : 1;
    if (exp === 0x7ff) return (hi & 0xfffff) === 0 && lo === 0 ? 1 : 0;
    return 4;
  });
  defineEach([crtMath, msvcrt], "_ldclass", 3, (guest, argument) => {
    const row = guest.lookupExport(msvcrt, "_dclass");
    return row.emulate(guest, [argument[0], argument[1]]);
  });
  defineEach([crtConvert, msvcrt], "btowc", 1, (guest, argument) => {
    const code = argument[0] | 0;
    if (code === -1 || code === 0xffffffff) return 0xffffffff;
    return code & 0xff;
  });

  return table;
}

export const msvcpExportTable = Object.freeze(buildMsvcpExportTable());

export function listMsvcpHleExport() {
  return msvcpExportTable;
}

export function buildMsvcpConformanceCaseTable() {
  const caseList = [];
  let caseNumber = 0;
  const argument = (value) => ({ argument: value });
  function define(library, symbol, input, expected) {
    caseNumber += 1;
    caseList.push({
      case_id: `MSVCP-${String(caseNumber).padStart(3, "0")}`,
      library,
      symbol,
      input,
      expected,
    });
  }
  function defineEach(libraryList, symbol, input, expected) {
    for (const library of libraryList) define(library, symbol, input, expected);
  }

  const msvcrt = "msvcrt.dll";
  const vcrt = "vcruntime140.dll";
  const crtRuntime = "api-ms-win-crt-runtime-l1-1-0.dll";
  const crtString = "api-ms-win-crt-string-l1-1-0.dll";
  const crtLocale = "api-ms-win-crt-locale-l1-1-0.dll";
  const crtStdio = "api-ms-win-crt-stdio-l1-1-0.dll";
  const crtFs = "api-ms-win-crt-filesystem-l1-1-0.dll";
  const crtTime = "api-ms-win-crt-time-l1-1-0.dll";
  const crtEnv = "api-ms-win-crt-environment-l1-1-0.dll";
  const crtMath = "api-ms-win-crt-math-l1-1-0.dll";
  const crtConvert = "api-ms-win-crt-convert-l1-1-0.dll";
  const stringA = 0x00150080;
  const stringB = 0x001500c0;
  const stringDest = 0x00150100;
  const scratch = 0x00150040;

  define("kernel32.dll", "CreateThreadpoolWork", argument([0, 0, 0]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "CreateThreadpoolWork", argument([0x00401000, 0, 0]), { return_value: 0x00030000, last_error: 0 });
  define("kernel32.dll", "SubmitThreadpoolWork", argument([0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "SubmitThreadpoolWork", {
    scenario: [["kernel32.dll", "CreateThreadpoolWork", [0x00401000, 7, 0]]],
    argument: [0x00030000],
  }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "WaitForThreadpoolWorkCallbacks", {
    scenario: [["kernel32.dll", "CreateThreadpoolWork", [0x00401000, 0, 0]]],
    argument: [0x00030000, 0],
  }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "CloseThreadpoolWork", {
    scenario: [["kernel32.dll", "CreateThreadpoolWork", [0x00401000, 0, 0]]],
    argument: [0x00030000],
  }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "CreateThreadpoolWait", argument([0x00401000, 0, 0]), { return_value: 0x00030000, last_error: 0 });
  define("kernel32.dll", "SetThreadpoolWait", {
    scenario: [["kernel32.dll", "CreateThreadpoolWait", [0x00401000, 0, 0]]],
    argument: [0x00030000, 0, 0],
  }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "CloseThreadpoolWait", {
    scenario: [["kernel32.dll", "CreateThreadpoolWait", [0x00401000, 0, 0]]],
    argument: [0x00030000],
  }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "CreateThreadpoolTimer", argument([0x00401000, 0, 0]), { return_value: 0x00030000, last_error: 0 });
  define("kernel32.dll", "SetThreadpoolTimer", {
    scenario: [["kernel32.dll", "CreateThreadpoolTimer", [0x00401000, 0, 0]]],
    argument: [0x00030000, 0, 0, 0],
  }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "WaitForThreadpoolTimerCallbacks", {
    scenario: [["kernel32.dll", "CreateThreadpoolTimer", [0x00401000, 0, 0]]],
    argument: [0x00030000, 0],
  }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "CloseThreadpoolTimer", {
    scenario: [["kernel32.dll", "CreateThreadpoolTimer", [0x00401000, 0, 0]]],
    argument: [0x00030000],
  }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "FreeLibraryWhenCallbackReturns", argument([1, 0x00020002]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetCurrentProcessorNumber", argument([]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "FlushProcessWriteBuffers", argument([]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "CreateSemaphoreExW", argument([0, 1, 4, 0, 0, 0x1f0003]), { return_value: 0x00010000, last_error: 0 });
  define("kernel32.dll", "CreateSemaphoreExW", argument([0, 1, 4, 0, 1, 0]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "InitOnceExecuteOnce", argument([0, 0x00401000, 0, 0]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "InitOnceExecuteOnce", {
    prepare: (guest) => guest.memory.writeMemory(scratch, 4, 0),
    argument: [scratch, 0x00401000, 0, 0],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "RtlCaptureStackBackTrace", argument([0, 2, stringDest, scratch]), { return_value: 0, last_error: 0 });

  define(vcrt, "_except_handler4_common", argument([0, 0, 0, 0, 0, 0]), { return_value: 1, last_error: 0 });
  define(vcrt, "__CxxFrameHandler3", argument([0, 0, 0, 0]), { return_value: 1, last_error: 0 });
  define(vcrt, "_CxxThrowException", argument([0, 0]), { return_value: null, last_error: "The guest raised an unhandled exception" });
  define(vcrt, "__AdjustPointer", argument([0, 0]), { return_value: 0, last_error: 0 });
  define(vcrt, "__current_exception", argument([]), { return_value: 0, last_error: 0 });
  define(vcrt, "__current_exception_context", argument([]), { return_value: 0, last_error: 0 });
  define(vcrt, "__uncaught_exception", argument([]), { return_value: 0, last_error: 0 });
  define(vcrt, "__uncaught_exceptions", argument([]), { return_value: 0, last_error: 0 });
  define(vcrt, "__std_terminate", argument([]), { return_value: null, last_error: "The guest ended its own process" });
  define(vcrt, "_purecall", argument([]), { return_value: null, last_error: "The guest ended its own process" });
  define(vcrt, "__std_exception_copy", {
    prepare: (guest) => {
      guest.memory.writeMemory(stringA, 4, 0x11);
      guest.memory.writeMemory(stringA + 4, 4, 0);
    },
    argument: [stringA, stringDest],
  }, { return_value: 0, last_error: 0 });
  define(vcrt, "__std_exception_destroy", argument([stringDest]), { return_value: 0, last_error: 0 });
  define(vcrt, "__std_type_info_destroy_list", argument([0]), { return_value: 0, last_error: 0 });

  const abortExpected = { return_value: null, last_error: "The guest ended its own process" };
  defineEach([crtRuntime, msvcrt], "terminate", argument([]), abortExpected);
  defineEach([crtRuntime, msvcrt], "_initterm_e", argument([0, 0]), { return_value: 0, last_error: 0 });
  defineEach([crtRuntime, msvcrt], "_execute_onexit_table", argument([0]), { return_value: 0, last_error: 0 });
  defineEach([crtRuntime, msvcrt], "_set_new_handler", argument([0]), { return_value: 0, last_error: 0 });
  defineEach([crtRuntime, msvcrt], "_invoke_watson", argument([0, 0, 0, 0, 0]), abortExpected);
  defineEach([crtRuntime, msvcrt], "_seh_filter_dll", argument([0, 0]), { return_value: 0, last_error: 0 });

  const writeA = (at, text) => (guest) => guest.writeAnsiString(at, text, text.length + 1);
  const writeW = (at, text) => (guest) => guest.writeWideString(at, text, text.length + 1);
  defineEach([crtString, msvcrt], "strcspn", {
    prepare: (guest) => {
      writeA(stringA, "hello")(guest);
      writeA(stringB, "l")(guest);
    },
    argument: [stringA, stringB],
  }, { return_value: 2, last_error: 0 });
  defineEach([crtString, msvcrt], "wcsnlen", {
    prepare: writeW(stringA, "hi"),
    argument: [stringA, 8],
  }, { return_value: 2, last_error: 0 });
  defineEach([crtString, msvcrt], "__strncnt", {
    prepare: writeA(stringA, "abcd"),
    argument: [stringA, 2],
  }, { return_value: 2, last_error: 0 });
  defineEach([crtString, msvcrt], "wcscpy_s", {
    prepare: writeW(stringA, "ok"),
    argument: [stringDest, 8, stringA],
  }, { return_value: 0, last_error: 0 });
  defineEach([crtString, msvcrt], "iswalnum", argument([0x41]), { return_value: 1, last_error: 0 });
  defineEach([crtString, msvcrt], "iswxdigit", argument([0x67]), { return_value: 0, last_error: 0 });
  defineEach([crtString, msvcrt], "iswdigit", argument([0x35]), { return_value: 1, last_error: 0 });
  defineEach([crtString, msvcrt], "iswspace", argument([0x20]), { return_value: 1, last_error: 0 });
  defineEach([crtString, msvcrt], "_wcsdup", argument([0]), { return_value: 0, last_error: 0 });

  defineEach([crtLocale, msvcrt], "_lock_locales", argument([]), { return_value: 0, last_error: 0 });
  defineEach([crtLocale, msvcrt], "_unlock_locales", argument([]), { return_value: 0, last_error: 0 });
  defineEach([crtLocale, msvcrt], "___lc_codepage_func", argument([]), { return_value: 1252, last_error: 0 });
  defineEach([crtLocale, msvcrt], "___lc_collate_cp_func", argument([]), { return_value: 1252, last_error: 0 });
  defineEach([crtLocale, msvcrt], "___lc_locale_name_func", argument([]), { return_value: 1048672, last_error: 0 });
  defineEach([crtLocale, msvcrt], "__pctype_func", argument([]), { return_value: 1048658, last_error: 0 });

  const iobBase = 0x002fe000;
  const iobIn = iobBase;
  const iobOut = iobBase + 32;
  defineEach([crtStdio, msvcrt], "fputs", {
    prepare: writeA(stringA, "hi"),
    argument: [stringA, iobOut],
  }, { return_value: 0, last_error: 0 });
  defineEach([crtStdio, msvcrt], "fgetc", argument([iobIn]), { return_value: 0xffffffff, last_error: 0 });
  defineEach([crtStdio, msvcrt], "fgetwc", argument([iobIn]), { return_value: 0xffffffff, last_error: 0 });
  defineEach([crtStdio, msvcrt], "fputwc", argument([0x41, iobOut]), { return_value: 0x41, last_error: 0 });
  defineEach([crtStdio, msvcrt], "ungetc", argument([0x41, iobIn]), { return_value: 0xffffffff, last_error: 0 });
  defineEach([crtStdio, msvcrt], "ungetwc", argument([0x41, iobIn]), { return_value: 0xffffffff, last_error: 0 });
  defineEach([crtStdio, msvcrt], "_fsopen", {
    prepare: (guest) => {
      writeA(stringA, "c:\\none.txt")(guest);
      writeA(stringB, "rb")(guest);
    },
    argument: [stringA, stringB, 64],
  }, { return_value: 0, last_error: 2 });
  defineEach([crtStdio, msvcrt], "_wfsopen", {
    prepare: (guest) => {
      writeW(stringA, "c:\\none.txt")(guest);
      writeW(stringB, "rb")(guest);
    },
    argument: [stringA, stringB, 64],
  }, { return_value: 0, last_error: 2 });
  defineEach([crtStdio, msvcrt], "_get_stream_buffer_pointers", argument([0, scratch, stringDest, stringB]), { return_value: 0, last_error: 0 });
  defineEach([crtStdio, msvcrt], "fgetpos", argument([iobIn, scratch]), { return_value: 0xffffffff, last_error: 0 });
  defineEach([crtStdio, msvcrt], "fsetpos", {
    prepare: (guest) => {
      guest.memory.writeMemory(scratch, 4, 0);
      guest.memory.writeMemory(scratch + 4, 4, 0);
    },
    argument: [iobIn, scratch],
  }, { return_value: 0xffffffff, last_error: 0 });
  defineEach([crtStdio, msvcrt], "_fseeki64", argument([iobIn, 0, 0, 0]), { return_value: 0xffffffff, last_error: 0 });

  defineEach([crtFs, msvcrt], "_wrmdir", {
    prepare: writeW(stringA, "C:\\missingdir"),
    argument: [stringA],
  }, { return_value: 0xffffffff, last_error: 3 });
  defineEach([crtFs, msvcrt], "_wchdir", {
    prepare: writeW(stringA, "C:\\game"),
    argument: [stringA],
  }, { return_value: 0, last_error: 0 });
  defineEach([crtFs, msvcrt], "_wremove", {
    prepare: writeW(stringA, "C:\\missing"),
    argument: [stringA],
  }, { return_value: 0xffffffff, last_error: 2 });
  defineEach([crtFs, msvcrt], "_wrename", {
    prepare: (guest) => {
      writeW(stringA, "C:\\missing")(guest);
      writeW(stringB, "C:\\dest")(guest);
    },
    argument: [stringA, stringB],
  }, { return_value: 0xffffffff, last_error: 2 });
  defineEach([crtFs, msvcrt], "_lock_file", argument([0]), { return_value: 0, last_error: 0 });
  defineEach([crtFs, msvcrt], "_unlock_file", argument([0]), { return_value: 0, last_error: 0 });

  defineEach([crtTime, msvcrt], "_Getdays", argument([]), { return_value: 1048656, last_error: 0 });
  defineEach([crtTime, msvcrt], "_Getmonths", argument([]), { return_value: 1048656, last_error: 0 });
  defineEach([crtTime, msvcrt], "_Gettnames", argument([]), { return_value: 1048928, last_error: 0 });
  defineEach([crtTime, msvcrt], "_W_Getdays", argument([]), { return_value: 1048656, last_error: 0 });
  defineEach([crtTime, msvcrt], "_W_Getmonths", argument([]), { return_value: 1048656, last_error: 0 });
  defineEach([crtTime, msvcrt], "_W_Gettnames", argument([]), { return_value: 1048928, last_error: 0 });
  defineEach([crtTime, msvcrt], "_Strftime", {
    prepare: (guest) => {
      writeA(stringA, "%Y")(guest);
      const field = [0, 40, 18, 10, 8, 120, 4, 253, 0];
      for (let index = 0; index < field.length; index += 1) guest.memory.writeMemory(0x00170000 + index * 4, 4, field[index]);
    },
    argument: [stringDest, 64, stringA, 0x00170000, 0, 0],
  }, { return_value: 4, last_error: 0 });
  defineEach([crtTime, msvcrt], "_Wcsftime", {
    prepare: (guest) => {
      writeA(stringA, "%Y")(guest);
      const field = [0, 40, 18, 10, 8, 120, 4, 253, 0];
      for (let index = 0; index < field.length; index += 1) guest.memory.writeMemory(0x00170000 + index * 4, 4, field[index]);
    },
    argument: [stringDest, 64, stringA, 0x00170000, 0, 0],
  }, { return_value: 4, last_error: 0 });

  defineEach([crtEnv, msvcrt], "_wgetcwd", argument([0, 0]), { return_value: 1048672, last_error: 0 });
  defineEach([crtMath, msvcrt], "_dclass", argument([0, 0]), { return_value: 2, last_error: 0 });
  defineEach([crtMath, msvcrt], "_ldclass", argument([0, 0, 0]), { return_value: 2, last_error: 0 });
  defineEach([crtConvert, msvcrt], "btowc", argument([0x41]), { return_value: 0x41, last_error: 0 });

  return caseList;
}
