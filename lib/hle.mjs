// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The Win32 core HLE (BPTK-010): one generic kernel32 and ole32 emulation
// surface that serves guest import calls through the bounded probe. Every
// export is a real emulator over the guest memory model — no per-title
// branch, no silent stub: a capability the core does not honestly emulate is
// left unserved so the refusal names the gap instead of faking a result. The
// guest cannot reach host capability through this surface: file, console
// input, network, process, and device service do not exist here, and every
// buffer is bounded by a declared limit.

import { basename } from "node:path";
import { createHash } from "node:crypto";
import { TEB_SIZE_BYTE, PEB_SIZE_BYTE } from "./thread.mjs";
import { SehThread, raiseException } from "./seh.mjs";

// The USER32 windowing/input and GDI32 2D surface slice (BPTK-011/012). The
// export tables and subsystem factories live in their own modules; this file
// only registers the rows and attaches the per-run subsystem to the guest.
import { createUserSubsystem, userExportTable } from "./user.mjs";
import { createGdiSubsystem, gdiExportTable } from "./gdi.mjs";
import { createSdlSubsystem, sdlExportTable } from "./sdl.mjs";

// The ws2_32 Winsock lifecycle slice (BPTK-099). The mediated relay and its
// consent/allowlist policy live in lib/net.mjs; this file attaches one
// offline-by-default instance per run and marshals the ws2_32 ABI. The default
// policy grants no consent, so every dial is refused — the honest posture until
// a consent surface lands.
import { createWinsock, createMediatedRelay, createTransportPolicy, netBound, wsaError, winsockConstant, htons as netHtons, htonl as netHtonl, inetAddr } from "./net.mjs";

// The XInput/DirectInput gamepad slice (BPTK-097): a generic controller model
// driven by injected browser Gamepad state, disconnected by default.
import { createGamepadSubsystem, xinputError, gamepadBound } from "./input.mjs";

// Declared bounds (resource-exhaustion containment, GS-087). Every guest
// allocation, output capture, handle table, and trace is capped by these
// constants; exceeding one is a structured fault, never unbounded growth.
export const hleBound = Object.freeze({
  arena_byte: 32 * 1024 * 1024,
  virtual_byte: 64 * 1024 * 1024,
  thunk_page_byte: 1024 * 1024,
  heap_count: 8,
  handle_count: 4096,
  tls_slot_count: 64,
  fls_slot_count: 128,
  critical_section_count: 256,
  output_byte: 1024 * 1024,
  trace_count: 4096,
  block_byte: 1024 * 1024,
  string_byte: 4096,
  environment_entry_count: 256,
  event_count: 64,
  file_open_count: 64,
  file_total_byte: 1024 * 1024,
  file_size_byte: 256 * 1024,
  registry_key_count: 64,
  registry_value_count: 256,
  registry_value_byte: 4096,
});

export const hleProfile = Object.freeze({
  schema_version: 1,
  profile: "win32_core_hle_v1",
  library: ["kernel32.dll", "ole32.dll"],
  version_major: 5,
  version_minor: 1,
  version_build: 2600,
  version_platform_id: 2,
  version_csd_version: "Service Pack 3",
  system_directory: "C:\\Windows\\System32",
  guest_root: "C:\\game",
  process_id: 4242,
  thread_id: 1,
  pointer_cookie: 0x5a5a5a5a,
  file_time_base: 132442368000000000,
  page_byte: 0x1000,
  allocation_granularity_byte: 0x10000,
  qpc_frequency_hz: 10000000,
});

// The declared virtual drive geometry (BPTK-102). One fixed system volume and
// one read-only optical volume, host-neutral: the type, label, serial, and
// capacity are declared constants, never a host disk. DRIVE_FIXED = 3,
// DRIVE_CDROM = 5.
export const driveProfile = Object.freeze({
  c: Object.freeze({ letter: "C", type: 3, label: "BPTK", serial: 0x4250544b, file_system: "NTFS", total_byte: 0x100000000, free_byte: 0x80000000, bytes_per_sector: 512, sectors_per_cluster: 8 }),
  d: Object.freeze({ letter: "D", type: 5, label: "BPTK_MEDIA", serial: 0x4344524f, file_system: "CDFS", total_byte: 0x28000000, free_byte: 0, bytes_per_sector: 2048, sectors_per_cluster: 1 }),
});

const errorValue = Object.freeze({
  success: 0,
  invalid_function: 1,
  file_not_found: 2,
  access_denied: 5,
  invalid_handle: 6,
  not_enough_memory: 14,
  insufficient_buffer: 122,
  invalid_parameter: 87,
  mod_not_found: 126,
  proc_not_found: 127,
  invalid_address: 487,
  more_data: 234,
  path_not_found: 3,
  too_many_open_files: 4,
  file_exists: 80,
  negative_seek: 131,
  disk_full: 112,
  tls_out_of_indexes: 0xffffffff,
  fls_out_of_indexes: 0xffffffff,
});

const fileAccess = Object.freeze({ generic_read: 0x80000000, generic_write: 0x40000000 });
const fileDisposition = Object.freeze({ create_new: 1, create_always: 2, open_existing: 3, open_always: 4, truncate_existing: 5 });
const fileMethod = Object.freeze({ begin: 0, current: 1, end: 2 });
const fileType = Object.freeze({ unknown: 0, disk: 3, char: 2 });
const registryAccess = Object.freeze({ read: 0x20019, write: 0x20006 });
const registryValueKind = Object.freeze({ none: 0, sz: 1, dword: 4 });
const consoleMode = Object.freeze({ output: 0x0003, input: 0x0007 });
const consoleCodePage = 1252;

// The i386 msvcrt FILE (struct _iobuf) is 32 byte wide; the _file descriptor
// index sits at offset 16. The three standard streams live in the _iob array
// as fd 0/1/2, and a _fdopen/_wfopen stream carries its fd in the same field.
const FILE_STRUCT_BYTE = 32;
const FILE_FD_OFFSET = 16;
// The C errno the bounded CRT reports: EBADF (bad descriptor), ENOENT (no such
// file), EINVAL (invalid argument), ERANGE (result out of range).
const crtErrnoValue = Object.freeze({ ebadf: 9, enoent: 2, einval: 22, erange: 34 });

// The deterministic guest wall clock as a Unix second: the HLE file-time base
// (100-ns tick since 1601) minus the 1601→1970 epoch offset, in seconds. This
// is a fixed guest instant (2020-09-10T18:40:00Z), never the host clock.
function crtGuestUnixSecond() {
  return Number((132442368000000000n - 116444736000000000n) / 10000000n) >>> 0;
}

// The bounded strerror text for the errno the CRT surface reports.
function crtStrerrorText(errnum) {
  const table = {
    0: "No error",
    2: "No such file or directory",
    9: "Bad file descriptor",
    12: "Not enough space",
    22: "Invalid argument",
    34: "Result too large",
  };
  return table[errnum] ?? "Unknown error";
}

// Fill the shared struct tm buffer from a Unix second (UTC) and return its
// address. tm layout: sec, min, hour, mday, mon, year(−1900), wday, yday, isdst.
function crtWriteTm(guest, unixSecond) {
  const date = new Date(unsigned(unixSecond) * 1000);
  const base = guest.crtRuntime.tmBuf;
  const field = [
    date.getUTCSeconds(), date.getUTCMinutes(), date.getUTCHours(), date.getUTCDate(),
    date.getUTCMonth(), date.getUTCFullYear() - 1900, date.getUTCDay(),
    Math.floor((Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()) - Date.UTC(date.getUTCFullYear(), 0, 1)) / 86400000), 0,
  ];
  for (let index = 0; index < field.length; index += 1) guest.memory.writeMemory(base + index * 4, 4, field[index] >>> 0);
  return base;
}

// A bounded strftime over the shared clock's UTC fields. Unknown specifiers are
// copied literally; the result is truncated to the caller's byte cap and the
// return is the written length excluding the terminator (0 on overflow).
function crtStrftime(guest, destination, maximumByte, formatAddress, tmAddress) {
  const format = guest.readAnsiString(formatAddress) ?? "";
  const value = (offset) => signed32(guest.memory.readMemory(unsigned(tmAddress) + offset, 4));
  const pad = (number, width = 2) => String(number).padStart(width, "0");
  const monthName = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const dayName = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  let output = "";
  for (let index = 0; index < format.length; index += 1) {
    if (format[index] !== "%" || index + 1 >= format.length) { output += format[index]; continue; }
    index += 1;
    switch (format[index]) {
      case "Y": output += String(value(20) + 1900); break;
      case "m": output += pad(value(16) + 1); break;
      case "d": output += pad(value(12)); break;
      case "H": output += pad(value(8)); break;
      case "M": output += pad(value(4)); break;
      case "S": output += pad(value(0)); break;
      case "b": output += monthName[((value(16) % 12) + 12) % 12]; break;
      case "a": output += dayName[((value(24) % 7) + 7) % 7]; break;
      case "%": output += "%"; break;
      default: output += `%${format[index]}`; break;
    }
  }
  if (output.length + 1 > unsigned(maximumByte)) return 0;
  guest.writeAnsiString(unsigned(destination), output, output.length + 1);
  return output.length;
}

// _stati64: fill the 88-byte _stat64 with the virtual-drive size for an
// existing file, else report ENOENT. Only st_size (offset 24, 8 byte) is
// meaningful in the bounded world; every other field stays zero.
function crtStat(guest, path, statAddress) {
  if (path === null) { guest.crtErrno(crtErrnoValue.einval); return 0xffffffff; }
  const size = guest.virtualFileSize(path);
  if (size === null) { guest.crtErrno(crtErrnoValue.enoent); return 0xffffffff; }
  guest.memory.writeBlock(unsigned(statAddress), Buffer.alloc(88));
  guest.memory.writeMemory(unsigned(statAddress) + 24, 4, size >>> 0);
  guest.memory.writeMemory(unsigned(statAddress) + 28, 4, Math.floor(size / 0x100000000) >>> 0);
  return 0;
}

// The declared locale environment (BPTK-103 slice): one locale, ANSI/OEM code
// page 1252 with the real best-fit table, and real UTF-8 conversion. The
// 0x80-0x9F range differs from Latin-1 in code page 1252; the undefined
// code point map to the C1 control.
const codepage1252High = new Map([
  [0x80, 0x20ac], [0x82, 0x201a], [0x83, 0x0192], [0x84, 0x201e], [0x85, 0x2026], [0x86, 0x2020], [0x87, 0x2021],
  [0x88, 0x02c6], [0x89, 0x2030], [0x8a, 0x0160], [0x8b, 0x2039], [0x8c, 0x0152], [0x8e, 0x017d], [0x91, 0x2018],
  [0x92, 0x2019], [0x93, 0x201c], [0x94, 0x201d], [0x95, 0x2022], [0x96, 0x2013], [0x97, 0x2014], [0x98, 0x02dc],
  [0x99, 0x2122], [0x9a, 0x0161], [0x9b, 0x203a], [0x9c, 0x0153], [0x9e, 0x017e], [0x9f, 0x0178],
]);
const codepage1252Reverse = new Map([...codepage1252High.entries()].map(([byte, wide]) => [wide, byte]));
const supportedCodePage = new Set([1252, 437, 65001]);
const localeId = 0x0409;
const localeNameTable = new Map([
  [0x0001, "0409"],
  [0x0002, "English (United States)"],
  [0x1001, "English"],
  [0x1002, "United States"],
  [0x1004, "ENU"],
  [0x1007, "US Dollar"],
]);

function ansiToWide(codePage, data) {
  if (codePage === 65001) return { text: new TextDecoder("utf-8", { fatal: false }).decode(data) };
  let text = "";
  for (const byte of data) {
    if (byte >= 0x80 && byte <= 0x9f) text += String.fromCharCode(codepage1252High.get(byte) ?? byte);
    else text += String.fromCharCode(byte);
  }
  return { text };
}

function wideToAnsi(codePage, text) {
  if (codePage === 65001) return Buffer.from(text, "utf8");
  const out = Buffer.alloc(text.length);
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code < 0x80) out[index] = code;
    else if (code >= 0xa0) out[index] = code <= 0xff ? code : codepage1252Reverse.get(code) ?? 0x3f;
    else out[index] = codepage1252Reverse.get(code) ?? code & 0xff;
  }
  return out;
}

// The declared deterministic date and time formatter: a real token formatter
// over SYSTEMTIME field with no host clock leakage beyond the one guest clock.
function formatSystemTime(token, field) {
  let out = "";
  let index = 0;
  while (index < token.length) {
    const ch = token[index];
    let run = 1;
    while (index + run < token.length && token[index + run] === ch) run += 1;
    if (ch === "'") {
      let end = index + 1;
      while (end < token.length && token[end] !== "'") end += 1;
      out += token.slice(index + 1, end);
      index = end + 1;
      continue;
    }
    const pad = (value, width) => String(value).padStart(width, "0");
    const dayName = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"][field.day_of_week] ?? "";
    const monthName = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"][field.month - 1] ?? "";
    if (ch === "y") out += run >= 4 ? String(field.year) : run === 3 ? String(field.year) : pad(field.year % 100, 2);
    else if (ch === "M") out += run >= 4 ? monthName : run === 3 ? monthName.slice(0, 3) : pad(field.month, run);
    else if (ch === "d") out += run >= 4 ? dayName : run === 3 ? dayName.slice(0, 3) : pad(field.day, run);
    else if (ch === "H") out += pad(field.hour, run);
    else if (ch === "h") out += pad(field.hour % 12 === 0 ? 12 : field.hour % 12, run);
    else if (ch === "m") out += pad(field.minute, run);
    else if (ch === "s") out += pad(field.second, run);
    else if (ch === "t") out += field.hour < 12 ? "AM" : "PM";
    else out += ch.repeat(run);
    index += run;
  }
  return out;
}

// The declared interactive user of the confined probe: one host-neutral name,
// never a real account. GetUserNameA and the SID surface answer with it.
const guestUserName = "user";

// FormatMessage FROM_SYSTEM has no populated message table in the bounded
// probe, so it renders one deterministic, host-neutral line per error code.
// Both the emulator and its conformance case call this, so they never drift.
function formatSystemMessage(messageId) {
  return `System error code ${unsigned(messageId)}.\r\n`;
}

const hresult = Object.freeze({
  s_ok: 0,
  s_false: 1,
  e_nointerface: 0x80004002,
  regdb_e_classnotreg: 0x80040154,
  rpc_e_changed_mode: 0x80010106,
  co_e_notinitialized: 0x800401f0,
});

const heapFlag = Object.freeze({ zero_memory: 0x08, generate_exceptions: 0x04, no_serialize: 0x01 });
const allocationType = Object.freeze({ commit: 0x1000, reserve: 0x2000, reset: 0x800, release: 0x8000 });
const protection = Object.freeze({ noaccess: 0x01, readonly: 0x02, readwrite: 0x04, execute_read: 0x20, execute_readwrite: 0x40 });
const memState = Object.freeze({ commit: 0x1000, reserve: 0x2000, free: 0x10000 });
const memType = Object.freeze({ private: 0x20000 });
const stdHandle = Object.freeze({ input: -10, output: -11, error: -12 });
const processorFeature = Object.freeze({ compare_exchange_double: 2, rdtsc_available: 8 });

class HleSignal extends Error {
  constructor(signal, message, detail = {}) {
    super(message);
    this.name = "HleSignal";
    this.signal = signal;
    Object.assign(this, detail);
  }
}

export function isHleSignal(error) {
  return error instanceof HleSignal;
}

function hleFault(code, message, detail = {}) {
  return new HleSignal("hle_fault", message, { code, ...detail });
}

function unsigned(value) {
  return value >>> 0;
}

function signed32(value) {
  return value | 0;
}

function raiseProcessExit(exitCode) {
  throw new HleSignal("hle_exit", "The guest ended its own process", { exit_code: unsigned(exitCode) });
}

function raiseGuestException(exceptionCode) {
  throw new HleSignal("hle_guest_exception", "The guest raised an unhandled exception", { exception_code: unsigned(exceptionCode) });
}

// The deterministic address placement for one HLE execution. The block
// (arena + virtual arena + thunk page + the thread-environment block) must not
// overlap the mapped image, the bounded stack, or the entry return sentinel,
// so the scan walks the declared candidates and takes the first disjoint
// block. The TEB and PEB pages (BPTK-025) are carved from the tail of the same
// block so fs-relative addressing resolves against real mapped memory.
const blockLayoutByte = hleBound.arena_byte + hleBound.virtual_byte + hleBound.thunk_page_byte + TEB_SIZE_BYTE + PEB_SIZE_BYTE;

export function createHleLayout(report) {
  const imageStart = report.load_base;
  const imageEnd = imageStart + report.image_size_byte;
  const reservedCandidate = [0xfffff000, 0x20000000, 0x10000000, 0x80000000, 0x90000000];
  const overlapsReserved = (base) => reservedCandidate.some((value) => value >= base && value < base + blockLayoutByte);
  for (let base = 0xf8000000; base >= 0x01000000; base -= 0x01000000) {
    const blockEnd = base + blockLayoutByte;
    if (blockEnd > 0x100000000) continue;
    const overlapsImage = base < imageEnd && imageStart < blockEnd;
    const overlapsStack = base < report.stack_end && report.stack_base < blockEnd;
    if (overlapsImage || overlapsStack || overlapsReserved(base)) continue;
    return {
      schema_version: 1,
      block_base: base,
      arena_base: base,
      arena_size_byte: hleBound.arena_byte,
      virtual_base: base + hleBound.arena_byte,
      virtual_size_byte: hleBound.virtual_byte,
      thunk_base: base + hleBound.arena_byte + hleBound.virtual_byte,
      thunk_page_byte: hleBound.thunk_page_byte,
      teb_base: base + hleBound.arena_byte + hleBound.virtual_byte + hleBound.thunk_page_byte,
      teb_size_byte: TEB_SIZE_BYTE,
      peb_base: base + hleBound.arena_byte + hleBound.virtual_byte + hleBound.thunk_page_byte + TEB_SIZE_BYTE,
      peb_size_byte: PEB_SIZE_BYTE,
    };
  }
  return null;
}

// The served import join (the export-coverage mechanism, GS-041): the parsed
// import table is joined against the HLE registry; a fully served image
// receives one thunk address per import so the probe dispatches the call,
// and a partially served image is refused with the unserved surface named.
export function computeImportService(report, layout) {
  const registry = listWin32HleExport();
  const thunkBySymbol = new Map(registry.map((entry, index) => [`${entry.library}!${entry.symbol}`, layout.thunk_base + index * 4]));
  const import_catalog = [];
  const unserved_entry = [];
  let servedCount = 0;
  for (const currentImport of report.import) {
    const key = `${currentImport.library}!${currentImport.symbol ?? `#${currentImport.ordinal}`}`;
    const thunk = thunkBySymbol.get(key);
    if (thunk === undefined) {
      unserved_entry.push(key);
      continue;
    }
    import_catalog.push({
      library: currentImport.library,
      symbol: currentImport.symbol,
      ordinal: currentImport.ordinal,
      address: thunk,
    });
    servedCount += 1;
  }
  const tally = new Map();
  for (const key of unserved_entry) {
    const library = key.split("!")[0];
    tally.set(library, (tally.get(library) ?? 0) + 1);
  }
  return {
    schema_version: 1,
    is_fully_served: unserved_entry.length === 0,
    served_count: servedCount,
    unserved_count: unserved_entry.length,
    unserved_library: [...tally.entries()].sort((a, b) => b[1] - a[1]).map(([library, count]) => `${library} (${count})`),
    unserved_sample: unserved_entry.slice(0, 24),
    import_catalog,
    layout,
  };
}

// ---------------------------------------------------------------------------
// Guest memory interface. The probe and the conformance harness both provide
// the same four primitives; the HLE owns everything above them (arena,
// heap, virtual map, handle table), so emulator semantics are identical in
// both settings.
//
// memory = {
//   readMemory(address, sizeByte) -> uint
//   writeMemory(address, sizeByte, value)
//   readBlock(address, sizeByte) -> Buffer
//   writeBlock(address, buffer)
// }
// ---------------------------------------------------------------------------

function createArena(memory, layout) {
  let cursor = layout.arena_base;
  const arenaEnd = layout.arena_base + layout.arena_size_byte;
  return {
    allocate(sizeByte) {
      const size = (Number.isSafeInteger(sizeByte) && sizeByte > 0 ? sizeByte : 1) + 15 & ~15;
      if (cursor + size > arenaEnd) throw hleFault("hle_memory_exhausted", `The HLE arena is exhausted at 0x${cursor.toString(16)}`, { address: cursor });
      const address = cursor;
      cursor += size;
      return address;
    },
    describe() {
      return { arena_base: layout.arena_base, arena_size_byte: layout.arena_size_byte, cursor };
    },
  };
}

function createAnsiReader(memory) {
  return function readAnsiString(address, bound = hleBound.string_byte) {
    if (address === 0) return null;
    const end = Math.min(address + bound, Number.MAX_SAFE_INTEGER);
    let result = "";
    for (let current = address; current < end; current += 1) {
      const value = memory.readMemory(current, 1);
      if (value === 0) return result;
      result += String.fromCharCode(value);
    }
    throw hleFault("hle_unterminated_string", `The ANSI string at 0x${address.toString(16)} has no terminator within ${bound} byte`, { address });
  };
}

function createWideReader(memory) {
  return function readWideString(address, bound = hleBound.string_byte) {
    if (address === 0) return null;
    const end = Math.min(address + bound, Number.MAX_SAFE_INTEGER);
    let result = "";
    for (let current = address; current < end; current += 2) {
      const value = memory.readMemory(current, 2);
      if (value === 0) return result;
      result += String.fromCharCode(value);
    }
    throw hleFault("hle_unterminated_string", `The UTF-16 string at 0x${address.toString(16)} has no terminator within ${bound} byte`, { address });
  };
}

function createAnsiWriter(memory) {
  return function writeAnsiString(address, value, capacityByte) {
    const data = Buffer.from(value + "\0", "latin1");
    if (data.length > capacityByte) return { is_written: false, length: value.length };
    memory.writeBlock(address, data);
    return { is_written: true, length: value.length };
  };
}

function createWideWriter(memory) {
  return function writeWideString(address, value, capacityCount) {
    const data = Buffer.from(value + "\0", "utf16le");
    if (data.length > capacityCount * 2) return { is_written: false, length: value.length };
    memory.writeBlock(address, data);
    return { is_written: true, length: value.length };
  };
}

// ---------------------------------------------------------------------------
// The registry. One row per emulated export: the declared stdcall argument
// count (the probe cleans the callee stack with it) and one emulator over
// the guest machine. Argument are dword from the guest stack, low to high.
// ---------------------------------------------------------------------------

function defineExportTable() {
  const table = [];

  function define(library, symbol, argumentCount, emulate) {
    table.push(Object.freeze({ library, symbol, argument_count: argumentCount, emulate }));
  }

  // --- error state ---------------------------------------------------------
  define("kernel32.dll", "GetLastError", 0, (guest) => guest.getLastError());
  define("kernel32.dll", "SetLastError", 1, (guest, argument) => {
    guest.setLastError(argument[0] & 0xffff);
    return 0;
  });

  // --- process -------------------------------------------------------------
  define("kernel32.dll", "ExitProcess", 1, (guest, argument) => raiseProcessExit(argument[0]));
  define("kernel32.dll", "TerminateProcess", 2, (guest, argument) => {
    if (argument[0] === 0xffffffff) raiseProcessExit(argument[1]);
    guest.setLastError(errorValue.invalid_handle);
    return 0;
  });
  define("kernel32.dll", "GetCurrentProcess", 0, () => 0xffffffff);
  define("kernel32.dll", "GetCurrentProcessId", 0, () => hleProfile.process_id);
  define("kernel32.dll", "GetCurrentThreadId", 0, () => hleProfile.thread_id);
  define("kernel32.dll", "GetCurrentThread", 0, () => 0xfffffffe);
  define("kernel32.dll", "IsDebuggerPresent", 0, () => 0);
  define("kernel32.dll", "IsBadReadPtr", 2, (guest, argument) => guest.probeReadable(argument[0], argument[1]));
  define("kernel32.dll", "Sleep", 1, (guest, argument) => {
    // The declared single-thread probe: the suspend becomes guest time only.
    guest.clock.advanceVirtualMs(unsigned(argument[0]));
    return 0;
  });
  define("kernel32.dll", "GetThreadTimes", 5, (guest, argument) => guest.threadTimes(argument[0], argument[1], argument[2], argument[3], argument[4]));
  define("kernel32.dll", "IsProcessorFeaturePresent", 1, (guest, argument) => {
    const feature = argument[0];
    return feature === processorFeature.compare_exchange_double || feature === processorFeature.rdtsc_available ? 1 : 0;
  });
  define("kernel32.dll", "RaiseException", 4, (guest, argument) => guest.raiseStructuredException(argument[0], argument[1], []));
  define("kernel32.dll", "AddVectoredExceptionHandler", 2, (guest, argument) => guest.addVectoredHandler(argument[0], argument[1]));
  define("kernel32.dll", "RemoveVectoredExceptionHandler", 1, (guest, argument) => guest.removeVectoredHandler(argument[0]));

  // --- synchronization objects (BPTK-010 slice): a real event state machine
  // over the declared single-thread world. A signaled event returns
  // immediately, a finite wait advances the one guest clock and times out,
  // and an infinite wait on a silent event is the structured deadlock stop.
  define("kernel32.dll", "CreateEventW", 4, (guest, argument) => guest.createEvent(argument[1] !== 0, argument[2] !== 0, argument[3]));
  define("kernel32.dll", "SetEvent", 1, (guest, argument) => guest.signalEvent(argument[0], true));
  define("kernel32.dll", "ResetEvent", 1, (guest, argument) => guest.signalEvent(argument[0], false));
  define("kernel32.dll", "WaitForSingleObject", 2, (guest, argument) => guest.waitForSingle(argument[0], argument[1], false));
  define("kernel32.dll", "WaitForSingleObjectEx", 3, (guest, argument) => guest.waitForSingle(argument[0], argument[1], argument[2] !== 0));
  define("kernel32.dll", "OpenProcess", 3, (guest, argument) => {
    // The declared world has exactly one process: its own identifier opens
    // the pseudo process handle, anything else is refused.
    if (argument[2] === hleProfile.process_id) return 0xffffffff;
    guest.setLastError(errorValue.invalid_parameter);
    return 0;
  });

  // --- module and lookup ---------------------------------------------------
  define("kernel32.dll", "GetModuleHandleA", 1, (guest, argument) => guest.lookupModule(guest.readAnsiString(argument[0])));
  define("kernel32.dll", "GetModuleHandleW", 1, (guest, argument) => guest.lookupModule(guest.readWideString(argument[0])));
  define("kernel32.dll", "GetModuleHandleExW", 3, (guest, argument) => {
    const [flag, nameOrAddress, handlePointer] = [argument[0], argument[1], argument[2]];
    const fromAddress = (flag & 0x4) !== 0;
    const unchangedOnFailure = (flag & 0x2) !== 0;
    const handle = fromAddress ? guest.lookupModuleByAddress(nameOrAddress) : guest.lookupModule(guest.readWideString(nameOrAddress));
    if (handle === 0) {
      guest.setLastError(errorValue.mod_not_found);
      if (!unchangedOnFailure && handlePointer !== 0) guest.memory.writeMemory(handlePointer, 4, 0);
      return 0;
    }
    guest.memory.writeMemory(handlePointer, 4, handle);
    return 1;
  });
  define("kernel32.dll", "GetProcAddress", 2, (guest, argument) => guest.lookupProcedure(argument[0], argument[1]));
  define("kernel32.dll", "LoadLibraryA", 1, (guest, argument) => guest.loadLibrary(guest.readAnsiString(argument[0]), 0));
  define("kernel32.dll", "LoadLibraryW", 1, (guest, argument) => guest.loadLibrary(guest.readWideString(argument[0]), 0));
  define("kernel32.dll", "LoadLibraryExW", 3, (guest, argument) => guest.loadLibrary(guest.readWideString(argument[0]), argument[2]));
  define("kernel32.dll", "FreeLibrary", 1, (guest, argument) => guest.freeLibrary(argument[0]));
  define("kernel32.dll", "GetModuleFileNameA", 3, (guest, argument) => {
    const path = guest.modulePath(argument[0]);
    if (path === null) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const written = guest.writeAnsiString(argument[1], path, argument[2]);
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return argument[2];
    }
    return written.length;
  });
  define("kernel32.dll", "GetModuleFileNameW", 3, (guest, argument) => {
    const path = guest.modulePath(argument[0]);
    if (path === null) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const written = guest.writeWideString(argument[1], path, argument[2]);
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return argument[2];
    }
    return written.length;
  });
  define("kernel32.dll", "GetCommandLineA", 0, (guest) => guest.commandLineAddressA);
  define("kernel32.dll", "GetCommandLineW", 0, (guest) => guest.commandLineAddressW);
  define("kernel32.dll", "GetStartupInfoA", 1, (guest, argument) => {
    guest.writeStartupInfo(argument[0], false);
    return 0;
  });
  define("kernel32.dll", "GetStartupInfoW", 1, (guest, argument) => {
    guest.writeStartupInfo(argument[0], true);
    return 0;
  });
  define("kernel32.dll", "GetVersion", 0, () => (hleProfile.version_build << 16 | hleProfile.version_minor << 8 | hleProfile.version_major) >>> 0);
  define("kernel32.dll", "GetVersionExA", 1, (guest, argument) => {
    const address = argument[0];
    const declaredSize = guest.memory.readMemory(address, 4);
    if (declaredSize < 20) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    guest.memory.writeMemory(address + 4, 4, hleProfile.version_major);
    guest.memory.writeMemory(address + 8, 4, hleProfile.version_minor);
    guest.memory.writeMemory(address + 12, 4, hleProfile.version_build);
    guest.memory.writeMemory(address + 16, 4, hleProfile.version_platform_id);
    if (declaredSize >= 148) guest.writeAnsiString(address + 20, hleProfile.version_csd_version, 128);
    return 1;
  });
  define("kernel32.dll", "IsValidLocale", 2, (guest, argument) => (argument[0] === localeId || argument[0] === 0x7f) && (argument[1] & ~0x8) === 0 ? 1 : 0);
  define("kernel32.dll", "GetSystemDirectoryA", 2, (guest, argument) => {
    const written = guest.writeAnsiString(argument[0], hleProfile.system_directory, argument[1]);
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return written.length + 1;
    }
    return written.length;
  });

  // --- heap and virtual memory ---------------------------------------------
  define("kernel32.dll", "GetProcessHeap", 0, (guest) => guest.defaultHeapHandle());
  define("kernel32.dll", "HeapCreate", 3, (guest, argument) => guest.createHeap(argument[2]));
  define("kernel32.dll", "HeapAlloc", 3, (guest, argument) => guest.heapAllocate(argument[0], argument[1], argument[2]));
  define("kernel32.dll", "HeapReAlloc", 4, (guest, argument) => guest.heapReAllocate(argument[0], argument[1], argument[2], argument[3]));
  define("kernel32.dll", "HeapFree", 3, (guest, argument) => guest.heapFree(argument[0], argument[1], argument[2]));
  define("kernel32.dll", "HeapSize", 3, (guest, argument) => guest.heapSize(argument[0], argument[1], argument[2]));
  define("kernel32.dll", "VirtualAlloc", 4, (guest, argument) => guest.virtualAllocate(argument[0], argument[1], argument[2], argument[3]));
  define("kernel32.dll", "VirtualFree", 3, (guest, argument) => guest.virtualFree(argument[0], argument[1], argument[2]));
  define("kernel32.dll", "VirtualProtect", 4, (guest, argument) => guest.virtualProtect(argument[0], argument[1], argument[2], argument[3]));
  define("kernel32.dll", "VirtualQuery", 3, (guest, argument) => guest.virtualQuery(argument[0], argument[1], argument[2]));

  // --- time ----------------------------------------------------------------
  define("kernel32.dll", "GetTickCount", 0, (guest) => guest.clock.tickCount());
  define("kernel32.dll", "QueryPerformanceCounter", 1, (guest, argument) => {
    if (argument[0] === 0) throw hleFault("hle_invalid_parameter", "QueryPerformanceCounter requires a destination address", { address: 0 });
    const counter = BigInt(Math.floor(guest.clock.elapsedGuestMs() * hleProfile.qpc_frequency_hz / 1000));
    guest.memory.writeMemory(argument[0], 4, Number(counter & 0xffffffffn));
    guest.memory.writeMemory(argument[0] + 4, 4, Number(counter >> 32n & 0xffffffffn));
    return 1;
  });
  define("kernel32.dll", "QueryPerformanceFrequency", 1, (guest, argument) => {
    if (argument[0] === 0) throw hleFault("hle_invalid_parameter", "QueryPerformanceFrequency requires a destination address", { address: 0 });
    guest.memory.writeMemory(argument[0], 4, hleProfile.qpc_frequency_hz);
    guest.memory.writeMemory(argument[0] + 4, 4, 0);
    return 1;
  });
  define("kernel32.dll", "GetSystemTimeAsFileTime", 1, (guest, argument) => {
    if (argument[0] === 0) throw hleFault("hle_invalid_parameter", "GetSystemTimeAsFileTime requires a destination address", { address: 0 });
    const fileTime = BigInt(hleProfile.file_time_base) + BigInt(Math.floor(guest.clock.elapsedGuestMs())) * 10000n;
    guest.memory.writeMemory(argument[0], 4, Number(fileTime & 0xffffffffn));
    guest.memory.writeMemory(argument[0] + 4, 4, Number(fileTime >> 32n & 0xffffffffn));
    return 0;
  });

  // --- synchronization ------------------------------------------------------
  define("kernel32.dll", "InitializeCriticalSection", 1, (guest, argument) => {
    guest.initializeCriticalSection(argument[0], 0);
    return 0;
  });
  define("kernel32.dll", "InitializeCriticalSectionAndSpinCount", 2, (guest, argument) => {
    guest.initializeCriticalSection(argument[0], argument[1] & 0x00ffffff);
    return 1;
  });
  // The ucrt/OpenTTD startup uses the Ex form (address, spin count, flags); the
  // flags select the debug-info policy the bounded single-thread world ignores.
  define("kernel32.dll", "InitializeCriticalSectionEx", 3, (guest, argument) => {
    guest.initializeCriticalSection(argument[0], argument[1] & 0x00ffffff);
    return 1;
  });
  define("kernel32.dll", "EnterCriticalSection", 1, (guest, argument) => {
    guest.enterCriticalSection(argument[0], true);
    return 0;
  });
  define("kernel32.dll", "TryEnterCriticalSection", 1, (guest, argument) => guest.enterCriticalSection(argument[0], false) ? 1 : 0);
  define("kernel32.dll", "LeaveCriticalSection", 1, (guest, argument) => {
    guest.leaveCriticalSection(argument[0]);
    return 0;
  });
  define("kernel32.dll", "DeleteCriticalSection", 1, (guest, argument) => {
    guest.deleteCriticalSection(argument[0]);
    return 0;
  });

  // --- thread-local storage --------------------------------------------------
  define("kernel32.dll", "TlsAlloc", 0, (guest) => guest.allocateTls());
  define("kernel32.dll", "TlsFree", 1, (guest, argument) => {
    if (!guest.freeTls(argument[0])) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    return 1;
  });
  define("kernel32.dll", "TlsGetValue", 1, (guest, argument) => guest.readTls(argument[0]));
  define("kernel32.dll", "TlsSetValue", 2, (guest, argument) => guest.writeTls(argument[0], argument[1]) ? 1 : 0);

  // --- fiber-local storage (Win64 CRT-init breadth, BPTK-031) ----------------
  // The x86-64 ucrt startup allocates one FLS index for its per-thread block
  // before it reaches main; a single-fiber bounded world serves it as a value
  // slot (see guest.allocateFls). FlsAlloc takes the destructor callback in RCX.
  define("kernel32.dll", "FlsAlloc", 1, (guest, argument) => guest.allocateFls(argument[0]));
  define("kernel32.dll", "FlsFree", 1, (guest, argument) => guest.freeFls(argument[0]) ? 1 : 0);
  define("kernel32.dll", "FlsGetValue", 1, (guest, argument) => guest.readFls(argument[0]));
  define("kernel32.dll", "FlsSetValue", 2, (guest, argument) => guest.writeFls(argument[0], argument[1]) ? 1 : 0);

  // --- lock-free singly linked list ------------------------------------------
  define("kernel32.dll", "InitializeSListHead", 1, (guest, argument) => {
    guest.memory.writeBlock(argument[0], Buffer.alloc(8));
    return 0;
  });
  define("kernel32.dll", "InterlockedPushEntrySList", 2, (guest, argument) => guest.slistPush(argument[0], argument[1]));
  define("kernel32.dll", "InterlockedPopEntrySList", 1, (guest, argument) => guest.slistPop(argument[0]));
  define("kernel32.dll", "InterlockedFlushSList", 1, (guest, argument) => guest.slistFlush(argument[0]));
  define("kernel32.dll", "QueryDepthSList", 1, (guest, argument) => guest.slistDepth(argument[0]));

  // --- pointer encoding -------------------------------------------------------
  define("kernel32.dll", "EncodePointer", 1, (guest, argument) => unsigned(argument[0] ^ hleProfile.pointer_cookie));
  define("kernel32.dll", "DecodePointer", 1, (guest, argument) => unsigned(argument[0] ^ hleProfile.pointer_cookie));

  // --- structured exception filter ---------------------------------------------
  define("kernel32.dll", "SetUnhandledExceptionFilter", 1, (guest, argument) => {
    const previous = guest.filter_address;
    guest.filter_address = argument[0];
    return previous;
  });

  // --- standard handle and output capture ---------------------------------------
  define("kernel32.dll", "GetStdHandle", 1, (guest, argument) => guest.standardHandle(argument[0]));
  define("kernel32.dll", "WriteFile", 5, (guest, argument) => guest.writeOutput(argument[0], argument[1], argument[2], argument[3], argument[4] !== 0));
  define("kernel32.dll", "WriteConsoleW", 5, (guest, argument) => guest.writeOutput(argument[0], argument[1], argument[2] * 2, argument[3], argument[4] !== 0));
  define("kernel32.dll", "lstrlenA", 1, (guest, argument) => {
    const value = guest.readAnsiString(argument[0]);
    return value === null ? 0 : value.length;
  });
  define("kernel32.dll", "lstrlenW", 1, (guest, argument) => {
    const value = guest.readWideString(argument[0]);
    return value === null ? 0 : value.length;
  });

  // --- kernel32 string family (stdcall, BPTK-101 breadth) -----------------------
  // Real generic emulation over the checked guest memory model: no host
  // string reaches these, every read is null-bounded by the declared cap, and
  // the comparison is the documented ordinal sign contract (<0, 0, >0). The
  // copy family returns the destination pointer per the Win32 ABI.
  const compareSign = (left, right) => (left < right ? unsigned(-1) : left > right ? 1 : 0);
  define("kernel32.dll", "lstrcmpA", 2, (guest, argument) => compareSign(guest.readAnsiString(argument[0]) ?? "", guest.readAnsiString(argument[1]) ?? ""));
  define("kernel32.dll", "lstrcmpW", 2, (guest, argument) => compareSign(guest.readWideString(argument[0]) ?? "", guest.readWideString(argument[1]) ?? ""));
  define("kernel32.dll", "lstrcmpiA", 2, (guest, argument) => compareSign((guest.readAnsiString(argument[0]) ?? "").toLowerCase(), (guest.readAnsiString(argument[1]) ?? "").toLowerCase()));
  define("kernel32.dll", "lstrcmpiW", 2, (guest, argument) => compareSign((guest.readWideString(argument[0]) ?? "").toLowerCase(), (guest.readWideString(argument[1]) ?? "").toLowerCase()));
  define("kernel32.dll", "lstrcpyA", 2, (guest, argument) => {
    if (argument[0] === 0 || argument[1] === 0) return 0;
    guest.memory.writeBlock(argument[0], Buffer.from((guest.readAnsiString(argument[1]) ?? "") + "\0", "latin1"));
    return argument[0];
  });
  define("kernel32.dll", "lstrcpyW", 2, (guest, argument) => {
    if (argument[0] === 0 || argument[1] === 0) return 0;
    guest.memory.writeBlock(argument[0], Buffer.from((guest.readWideString(argument[1]) ?? "") + "\0", "utf16le"));
    return argument[0];
  });
  define("kernel32.dll", "lstrcpynA", 3, (guest, argument) => {
    if (argument[0] === 0 || argument[1] === 0 || argument[2] <= 0) return argument[0];
    const source = (guest.readAnsiString(argument[1]) ?? "").slice(0, argument[2] - 1);
    guest.memory.writeBlock(argument[0], Buffer.from(source + "\0", "latin1"));
    return argument[0];
  });
  define("kernel32.dll", "lstrcatA", 2, (guest, argument) => {
    if (argument[0] === 0 || argument[1] === 0) return 0;
    const head = guest.readAnsiString(argument[0]) ?? "";
    guest.memory.writeBlock(argument[0] + head.length, Buffer.from((guest.readAnsiString(argument[1]) ?? "") + "\0", "latin1"));
    return argument[0];
  });
  define("kernel32.dll", "lstrcatW", 2, (guest, argument) => {
    if (argument[0] === 0 || argument[1] === 0) return 0;
    const head = guest.readWideString(argument[0]) ?? "";
    guest.memory.writeBlock(argument[0] + head.length * 2, Buffer.from((guest.readWideString(argument[1]) ?? "") + "\0", "utf16le"));
    return argument[0];
  });

  // --- interlocked atomics (BPTK-101 breadth) -----------------------------------
  // The single declared guest thread makes each read-modify-write trivially
  // atomic; the value is a 32-bit dword at the guest address and the return
  // follows the Win32 contract (Increment/Decrement return the new value,
  // Exchange/ExchangeAdd return the prior value, CompareExchange returns the
  // prior value and only stores on a match).
  define("kernel32.dll", "InterlockedIncrement", 1, (guest, argument) => {
    const value = unsigned(guest.memory.readMemory(argument[0], 4) + 1);
    guest.memory.writeMemory(argument[0], 4, value);
    return value;
  });
  define("kernel32.dll", "InterlockedDecrement", 1, (guest, argument) => {
    const value = unsigned(guest.memory.readMemory(argument[0], 4) - 1);
    guest.memory.writeMemory(argument[0], 4, value);
    return value;
  });
  define("kernel32.dll", "InterlockedExchange", 2, (guest, argument) => {
    const previous = unsigned(guest.memory.readMemory(argument[0], 4));
    guest.memory.writeMemory(argument[0], 4, unsigned(argument[1]));
    return previous;
  });
  define("kernel32.dll", "InterlockedExchangeAdd", 2, (guest, argument) => {
    const previous = unsigned(guest.memory.readMemory(argument[0], 4));
    guest.memory.writeMemory(argument[0], 4, unsigned(previous + argument[1]));
    return previous;
  });
  define("kernel32.dll", "InterlockedCompareExchange", 3, (guest, argument) => {
    const previous = unsigned(guest.memory.readMemory(argument[0], 4));
    if (previous === unsigned(argument[2])) guest.memory.writeMemory(argument[0], 4, unsigned(argument[1]));
    return previous;
  });

  // --- scaled arithmetic and system profile (BPTK-101 breadth) ------------------
  define("kernel32.dll", "MulDiv", 3, (guest, argument) => {
    const denominator = signed32(argument[2]);
    if (denominator === 0) return unsigned(-1);
    const product = BigInt(signed32(argument[0])) * BigInt(signed32(argument[1]));
    const bigDen = BigInt(denominator);
    const sign = (product < 0n) !== (bigDen < 0n) ? -1n : 1n;
    const absProduct = product < 0n ? -product : product;
    const absDen = bigDen < 0n ? -bigDen : bigDen;
    const rounded = sign * ((absProduct * 2n + absDen) / (absDen * 2n));
    if (rounded > 0x7fffffffn || rounded < -0x80000000n) return unsigned(-1);
    return unsigned(Number(rounded));
  });
  define("kernel32.dll", "GetSystemInfo", 1, (guest, argument) => {
    if (argument[0] === 0) throw hleFault("hle_invalid_parameter", "GetSystemInfo requires a destination address", { address: 0 });
    const info = argument[0];
    guest.memory.writeMemory(info, 4, 0); // dwOemId: PROCESSOR_ARCHITECTURE_INTEL, reserved 0
    guest.memory.writeMemory(info + 4, 4, 4096); // dwPageSize
    guest.memory.writeMemory(info + 8, 4, 0x00010000); // lpMinimumApplicationAddress
    guest.memory.writeMemory(info + 12, 4, 0x7ffe0000); // lpMaximumApplicationAddress
    guest.memory.writeMemory(info + 16, 4, 1); // dwActiveProcessorMask (one declared cpu)
    guest.memory.writeMemory(info + 20, 4, 1); // dwNumberOfProcessors
    guest.memory.writeMemory(info + 24, 4, 586); // dwProcessorType PROCESSOR_INTEL_PENTIUM
    guest.memory.writeMemory(info + 28, 4, 65536); // dwAllocationGranularity
    guest.memory.writeMemory(info + 32, 2, 6); // wProcessorLevel
    guest.memory.writeMemory(info + 34, 2, 0); // wProcessorRevision
    return 0;
  });
  define("kernel32.dll", "GetNativeSystemInfo", 1, (guest, argument) => guest.lookupExport("kernel32.dll", "GetSystemInfo").emulate(guest, argument));
  define("kernel32.dll", "GetSystemTime", 1, (guest, argument) => {
    if (argument[0] === 0) throw hleFault("hle_invalid_parameter", "GetSystemTime requires a destination address", { address: 0 });
    guest.writeSystemTime(argument[0], guest.guestSystemTime());
    return 0;
  });
  define("kernel32.dll", "GetLocalTime", 1, (guest, argument) => {
    // The declared time zone bias is UTC, so local time equals system time.
    if (argument[0] === 0) throw hleFault("hle_invalid_parameter", "GetLocalTime requires a destination address", { address: 0 });
    guest.writeSystemTime(argument[0], guest.guestSystemTime());
    return 0;
  });
  define("kernel32.dll", "SetErrorMode", 1, (guest, argument) => {
    const previous = guest.error_mode;
    guest.error_mode = unsigned(argument[0]) & 0x8007;
    return previous;
  });
  define("kernel32.dll", "GetErrorMode", 0, (guest) => guest.error_mode);
  // With no debugger attached these strings have no observable effect; the
  // guest string is bounded-read so a missing terminator still faults.
  define("kernel32.dll", "OutputDebugStringA", 1, (guest, argument) => {
    if (argument[0] !== 0) guest.readAnsiString(argument[0]);
    return 0;
  });
  define("kernel32.dll", "OutputDebugStringW", 1, (guest, argument) => {
    if (argument[0] !== 0) guest.readWideString(argument[0]);
    return 0;
  });

  // --- environment ----------------------------------------------------------------
  define("kernel32.dll", "GetEnvironmentStringsW", 0, (guest) => guest.buildEnvironmentBlock());
  define("kernel32.dll", "FreeEnvironmentStringsW", 1, (guest, argument) => {
    if (argument[0] === guest.environment_block_address) return 1;
    guest.setLastError(errorValue.invalid_parameter);
    return 0;
  });
  define("kernel32.dll", "SetEnvironmentVariableA", 2, (guest, argument) => {
    const name = guest.readAnsiString(argument[0]);
    if (name === null || name.length === 0 || name.includes("=")) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const value = argument[1] === 0 ? null : guest.readAnsiString(argument[1]);
    if (guest.environment.size >= hleBound.environment_entry_count && !guest.environment.has(name) && value !== null) {
      guest.setLastError(errorValue.not_enough_memory);
      return 0;
    }
    if (value === null) guest.environment.delete(name);
    else guest.environment.set(name, value);
    return 1;
  });
  // GetEnvironmentVariable / ExpandEnvironmentStrings (BPTK-101 breadth) over
  // the one environment map. A missing variable is the env-not-found contract;
  // an insufficient buffer returns the required size like the Win32 ABI.
  const getEnvVar = (guest, name, buffer, size, wide) => {
    if (name === null || !guest.environment.has(name)) {
      guest.setLastError(203); // ERROR_ENVVAR_NOT_FOUND
      return 0;
    }
    const value = guest.environment.get(name);
    if (size < value.length + 1) return value.length + 1; // required size including null
    if (buffer !== 0) (wide ? guest.writeWideString : guest.writeAnsiString)(buffer, value, size);
    return value.length;
  };
  define("kernel32.dll", "GetEnvironmentVariableA", 3, (guest, argument) => getEnvVar(guest, guest.readAnsiString(argument[0]), argument[1], argument[2] >>> 0, false));
  define("kernel32.dll", "GetEnvironmentVariableW", 3, (guest, argument) => getEnvVar(guest, guest.readWideString(argument[0]), argument[1], argument[2] >>> 0, true));
  const expandEnv = (guest, text) => {
    let result = "";
    let index = 0;
    while (index < text.length) {
      if (text[index] === "%") {
        const close = text.indexOf("%", index + 1);
        if (close === -1) { result += text.slice(index); break; }
        const name = text.slice(index + 1, close);
        result += guest.environment.has(name) ? guest.environment.get(name) : text.slice(index, close + 1);
        index = close + 1;
      } else {
        result += text[index];
        index += 1;
      }
    }
    return result;
  };
  define("kernel32.dll", "ExpandEnvironmentStringsA", 3, (guest, argument) => {
    const expanded = expandEnv(guest, guest.readAnsiString(argument[0]) ?? "");
    if (argument[2] >>> 0 < expanded.length + 1) return expanded.length + 1;
    if (argument[1] !== 0) guest.writeAnsiString(argument[1], expanded, argument[2] >>> 0);
    return expanded.length + 1;
  });
  define("kernel32.dll", "ExpandEnvironmentStringsW", 3, (guest, argument) => {
    const expanded = expandEnv(guest, guest.readWideString(argument[0]) ?? "");
    if (argument[2] >>> 0 < expanded.length + 1) return expanded.length + 1;
    if (argument[1] !== 0) guest.writeWideString(argument[1], expanded, argument[2] >>> 0);
    return expanded.length + 1;
  });

  // --- virtual drive (BPTK-015 slice): guest-memory files with real open,
  // read, write, seek, truncate, type, and close semantics. The drive is
  // bounded (file count, per-file and total byte) and never reaches host
  // storage; a traversal or UNC path fails closed.
  define("kernel32.dll", "CreateFileW", 7, (guest, argument) => guest.openFile(
    guest.readWideString(argument[0]), argument[1], argument[4],
  ));
  define("kernel32.dll", "ReadFile", 5, (guest, argument) => guest.readFile(argument[0], argument[1], argument[2], argument[3], argument[4] !== 0));
  define("kernel32.dll", "SetFilePointerEx", 5, (guest, argument) => guest.seekFile(argument[0], argument[1], argument[2], argument[3], argument[4]));
  define("kernel32.dll", "SetEndOfFile", 1, (guest, argument) => guest.truncateFile(argument[0]));
  define("kernel32.dll", "FlushFileBuffers", 1, (guest, argument) => {
    const record = guest.handleRecord(argument[0]);
    if (record === undefined || record.kind !== "file") {
      guest.setLastError(record === undefined ? errorValue.invalid_handle : errorValue.access_denied);
      return 0;
    }
    return 1;
  });
  define("kernel32.dll", "CloseHandle", 1, (guest, argument) => guest.closeHandle(argument[0]));
  define("kernel32.dll", "FindFirstFileExA", 6, (guest, argument) => guest.findFirst(argument[0], argument[1], argument[2], argument[3], argument[5]));
  define("kernel32.dll", "FindNextFileA", 2, (guest, argument) => guest.findNext(argument[0], argument[1]));
  define("kernel32.dll", "GetFileType", 1, (guest, argument) => guest.fileType(argument[0]));
  define("kernel32.dll", "SetStdHandle", 2, (guest, argument) => guest.setStandardHandle(argument[0], argument[1]));
  define("kernel32.dll", "GetConsoleMode", 1, (guest, argument) => guest.consoleMode(argument[0]));
  define("kernel32.dll", "GetConsoleCP", 0, () => consoleCodePage);
  define("kernel32.dll", "ReadConsoleW", 5, (guest, argument) => guest.readConsole(argument[0]));

  // --- registry (advapi32, BPTK-015 slice): one in-memory hive under the
  // real predefined root handle, with bounded key and value count.
  define("advapi32.dll", "RegOpenKeyExW", 5, (guest, argument) => guest.registryOpen(argument[0], guest.readWideString(argument[1]), argument[4], false));
  define("advapi32.dll", "RegOpenKeyA", 3, (guest, argument) => guest.registryOpen(argument[0], guest.readAnsiString(argument[1]), argument[2], false));
  define("advapi32.dll", "RegCreateKeyA", 3, (guest, argument) => guest.registryOpen(argument[0], guest.readAnsiString(argument[1]), argument[2], true));
  define("advapi32.dll", "RegQueryValueExA", 6, (guest, argument) => guest.registryQuery(argument[0], guest.readAnsiString(argument[1]), argument[3], argument[4], argument[5]));
  define("advapi32.dll", "RegSetValueExA", 6, (guest, argument) => guest.registrySet(argument[0], guest.readAnsiString(argument[1]), argument[3], argument[4], argument[5]));
  define("advapi32.dll", "RegCloseKey", 1, (guest, argument) => guest.registryClose(argument[0]));
  // registry breadth and fidelity (BPTK-098): the wide siblings, create with
  // disposition, and the delete/flush surface, all over the one in-memory hive.
  define("advapi32.dll", "RegOpenKeyExA", 5, (guest, argument) => guest.registryOpen(argument[0], guest.readAnsiString(argument[1]), argument[4], false));
  define("advapi32.dll", "RegCreateKeyExW", 9, (guest, argument) => guest.registryCreate(argument[0], guest.readWideString(argument[1]), argument[7], argument[8]));
  define("advapi32.dll", "RegCreateKeyExA", 9, (guest, argument) => guest.registryCreate(argument[0], guest.readAnsiString(argument[1]), argument[7], argument[8]));
  define("advapi32.dll", "RegQueryValueExW", 6, (guest, argument) => guest.registryQuery(argument[0], guest.readWideString(argument[1]), argument[3], argument[4], argument[5]));
  define("advapi32.dll", "RegSetValueExW", 6, (guest, argument) => guest.registrySet(argument[0], guest.readWideString(argument[1]), argument[3], argument[4], argument[5]));
  define("advapi32.dll", "RegDeleteValueA", 2, (guest, argument) => guest.registryDeleteValue(argument[0], guest.readAnsiString(argument[1])));
  define("advapi32.dll", "RegDeleteValueW", 2, (guest, argument) => guest.registryDeleteValue(argument[0], guest.readWideString(argument[1])));
  define("advapi32.dll", "RegDeleteKeyA", 2, (guest, argument) => guest.registryDeleteKey(argument[0], guest.readAnsiString(argument[1])));
  define("advapi32.dll", "RegDeleteKeyW", 2, (guest, argument) => guest.registryDeleteKey(argument[0], guest.readWideString(argument[1])));
  define("advapi32.dll", "RegFlushKey", 1, (guest, argument) => guest.registryFlush(argument[0]));

  // --- locale, codepage, and Unicode conversion (BPTK-103 slice) ----------------------
  define("kernel32.dll", "GetACP", 0, () => 1252);
  define("kernel32.dll", "GetOEMCP", 0, () => 1252);
  define("kernel32.dll", "IsValidCodePage", 1, (guest, argument) => supportedCodePage.has(argument[0]) ? 1 : 0);
  define("kernel32.dll", "GetCPInfo", 2, (guest, argument) => {
    const [codePage, infoPointer] = argument;
    if (!supportedCodePage.has(codePage)) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    guest.memory.writeBlock(infoPointer, Buffer.alloc(20));
    guest.memory.writeMemory(infoPointer, 4, codePage === 65001 ? 4 : 1);
    guest.memory.writeMemory(infoPointer + 4, 1, 0x3f);
    return 1;
  });
  define("kernel32.dll", "GetUserDefaultLCID", 0, () => localeId);
  define("kernel32.dll", "GetLocaleInfoW", 4, (guest, argument) => {
    const [, type, buffer, size] = argument;
    const name = localeNameTable.get(type);
    if (name === undefined) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const written = guest.writeWideString(buffer, name, Math.max(size, 0));
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    return written.length + 1;
  });
  define("kernel32.dll", "CompareStringW", 6, (guest, argument) => {
    const [, flags, first, firstCount, second, secondCount] = argument;
    if (flags & ~0x1) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const read = (address, count) => {
      const text = count === 0xffffffff ? guest.readWideString(address) : guest.memory.readBlock(address, count * 2).toString("utf16le");
      return text.slice(0, count === 0xffffffff ? undefined : count);
    };
    const left = read(first, firstCount | 0);
    const right = read(second, secondCount | 0);
    const equal = (flags & 0x1) !== 0 ? left.toLowerCase() === right.toLowerCase() : left === right;
    return equal ? 2 : left < right ? 1 : 3;
  });
  define("kernel32.dll", "LCMapStringW", 6, (guest, argument) => {
    const [, flags, source, sourceCount, destination, destinationCount] = argument;
    if (flags & ~0x300 || flags === 0) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const text = sourceCount === 0xffffffff ? guest.readWideString(source) : guest.memory.readBlock(source, sourceCount * 2).toString("utf16le");
    const sliced = sourceCount === 0xffffffff ? text : text.slice(0, sourceCount);
    const mapped = (flags & 0x100) !== 0 ? sliced.toLowerCase() : sliced.toUpperCase();
    if (destinationCount === 0) return mapped.length + 1;
    if (destinationCount < mapped.length + 1) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    guest.writeWideString(destination, mapped, destinationCount);
    return mapped.length + 1;
  });
  define("kernel32.dll", "GetStringTypeW", 4, (guest, argument) => {
    const [infoType, source, sourceCount, typePointer] = argument;
    if (infoType !== 1) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const text = guest.memory.readBlock(source, sourceCount * 2).toString("utf16le");
    for (let index = 0; index < sourceCount; index += 1) {
      const ch = text[index];
      let flags = 0;
      if (/[A-Z]/.test(ch)) flags |= 0x1 | 0x100;
      else if (/[a-z]/.test(ch)) flags |= 0x2 | 0x100;
      if (/[0-9]/.test(ch)) flags |= 0x4;
      if (/\s/.test(ch)) flags |= 0x40;
      if (/[!-/:-@\[-`{-~]/.test(ch)) flags |= 0x10;
      guest.memory.writeMemory(typePointer + index * 2, 2, flags);
    }
    return 1;
  });
  define("kernel32.dll", "GetTimeZoneInformation", 1, (guest, argument) => {
    // The declared environment runs at UTC with zero bias; names are filled
    // with the real UTF-16 field and both transition date stay zero.
    guest.memory.writeBlock(argument[0], Buffer.alloc(172));
    guest.memory.writeMemory(argument[0], 4, 0);
    const standardName = Buffer.from("Coordinated Universal Time\0".padEnd(32, "\0"), "utf16le");
    guest.memory.writeBlock(argument[0] + 4, standardName.subarray(0, 64));
    guest.memory.writeMemory(argument[0] + 4 + 64 + 16, 4, 0);
    guest.memory.writeMemory(argument[0] + 4 + 64 + 16 + 4 + 64, 4, 0);
    return 0;
  });
  define("kernel32.dll", "GetDateFormatW", 6, (guest, argument) => {
    const [, flags, datePointer, format, buffer, size] = argument;
    if (flags & ~0x8) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const field = datePointer === 0 ? guest.guestSystemTime() : guest.readSystemTime(datePointer);
    const token = format === 0 ? (flags & 0x8) !== 0 ? "dddd, MMMM d, yyyy" : "M/d/yyyy" : guest.readAnsiString(format);
    const formatted = formatSystemTime(token, field);
    const written = guest.writeWideString(buffer, formatted, Math.max(size, 0));
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    return written.length + 1;
  });
  define("kernel32.dll", "GetTimeFormatW", 6, (guest, argument) => {
    const [, flags, timePointer, format, buffer, size] = argument;
    if (flags & ~0x8) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const field = timePointer === 0 ? guest.guestSystemTime() : guest.readSystemTime(timePointer);
    const token = format === 0 ? "HH:mm:ss" : guest.readAnsiString(format);
    const formatted = formatSystemTime(token, field);
    const written = guest.writeWideString(buffer, formatted, Math.max(size, 0));
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    return written.length + 1;
  });
  define("kernel32.dll", "MultiByteToWideChar", 6, (guest, argument) => {
    const [codePage, , source, sourceByte, destination, destinationCount] = argument;
    if (!supportedCodePage.has(codePage)) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const data = sourceByte === 0xffffffff ? guest.memory.readBlock(source, guest.readAnsiLength(source)) : guest.memory.readBlock(source, Math.max(sourceByte, 0));
    const { text } = ansiToWide(codePage, data);
    if (destinationCount === 0) return text.length + (sourceByte === 0xffffffff ? 1 : 0);
    if (destinationCount < text.length) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    guest.writeWideString(destination, text, destinationCount);
    return text.length + (sourceByte === 0xffffffff ? 1 : 0);
  });
  define("kernel32.dll", "WideCharToMultiByte", 8, (guest, argument) => {
    const [codePage, , source, sourceCount, destination, destinationByte] = argument;
    if (!supportedCodePage.has(codePage)) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const text = sourceCount === 0xffffffff ? guest.readWideString(source) : guest.memory.readBlock(source, sourceCount * 2).toString("utf16le").slice(0, sourceCount === 0xffffffff ? undefined : sourceCount);
    const data = wideToAnsi(codePage, text);
    if (destinationByte === 0) return data.length + (sourceCount === 0xffffffff ? 1 : 0);
    if (destinationByte < data.length) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    if (data.length > 0) guest.memory.writeBlock(destination, data);
    return data.length + (sourceCount === 0xffffffff ? 1 : 0);
  });

  // --- multimedia timer (winmm, BPTK-039 slice): one monotonic time source
  // with a declared period setting and no asynchronous event service.
  define("winmm.dll", "timeGetTime", 0, (guest) => guest.clock.tickCount());
  define("winmm.dll", "timeBeginPeriod", 1, (guest, argument) => {
    if (argument[0] === 0 || argument[0] > 16) {
      guest.setLastError(2);
      return 2;
    }
    guest.timer_period = argument[0];
    return 0;
  });
  define("winmm.dll", "timeEndPeriod", 1, (guest, argument) => (guest.timer_period === argument[0] ? 0 : 2));
  define("winmm.dll", "timeKillEvent", 1, (guest, argument) => (argument[0] === 0 ? 0 : 3));

  // --- COM apartment (ole32) --------------------------------------------------------
  define("ole32.dll", "CoInitializeEx", 2, (guest, argument) => {
    const model = argument[1];
    if (guest.com_apartment !== null && guest.com_apartment !== model) return hresult.rpc_e_changed_mode;
    const isFirst = guest.com_apartment === null;
    guest.com_apartment = model;
    guest.com_refcount += 1;
    return isFirst ? hresult.s_ok : hresult.s_false;
  });
  define("ole32.dll", "CoUninitialize", 0, (guest) => {
    if (guest.com_apartment !== null) guest.com_refcount -= 1;
    return 0;
  });
  define("ole32.dll", "CoCreateInstance", 5, (guest, argument) => {
    if (argument[4] !== 0) guest.memory.writeMemory(argument[4], 4, 0);
    return hresult.regdb_e_classnotreg;
  });

  // --- ws2_32 Winsock lifecycle (BPTK-099) --------------------------------------
  // The offline-by-default instance: the lifecycle, handle table, byte-order,
  // and address helpers are fully served; bind/connect/transfer run through the
  // consent gate and are refused until a consent surface lands, so a guest sees
  // the real ws2_32 access contract rather than a fabricated link.
  const readEndpoint = (guest, address) => {
    const port = (guest.memory.readMemory(address + 2, 1) << 8) | guest.memory.readMemory(address + 3, 1);
    const octet = [0, 1, 2, 3].map((index) => guest.memory.readMemory(address + 4 + index, 1));
    return `${octet.join(".")}:${port}`;
  };
  define("ws2_32.dll", "WSAStartup", 2, (guest, argument) => {
    const result = guest.net.WSAStartup(argument[0] & 0xffff);
    if (result !== wsaError.WSA_OK) return result;
    const data = argument[1];
    if (data !== 0) {
      guest.memory.writeMemory(data + 0, 2, argument[0] & 0xffff); // wVersion
      guest.memory.writeMemory(data + 2, 2, 0x0202); // wHighVersion
      guest.writeAnsiString(data + 4, "BPTK mediated Winsock", 257); // szDescription
      guest.writeAnsiString(data + 261, "Running", 129); // szSystemStatus
      guest.memory.writeMemory(data + 390, 2, netBound.socket_count & 0xffff); // iMaxSockets
      guest.memory.writeMemory(data + 392, 2, 0); // iMaxUdpDg
      guest.memory.writeMemory(data + 394, 4, 0); // lpVendorInfo
    }
    return wsaError.WSA_OK;
  });
  define("ws2_32.dll", "WSACleanup", 0, (guest) => guest.net.WSACleanup());
  define("ws2_32.dll", "WSAGetLastError", 0, (guest) => guest.net.WSAGetLastError());
  define("ws2_32.dll", "socket", 3, (guest, argument) => unsigned(guest.net.socket(argument[0], argument[1], argument[2])));
  define("ws2_32.dll", "closesocket", 1, (guest, argument) => unsigned(guest.net.closesocket(argument[0])));
  define("ws2_32.dll", "bind", 3, (guest, argument) => unsigned(guest.net.bind(argument[0], readEndpoint(guest, argument[1]))));
  define("ws2_32.dll", "connect", 3, (guest, argument) => unsigned(guest.net.connect(argument[0], readEndpoint(guest, argument[1]))));
  define("ws2_32.dll", "send", 4, (guest, argument) => {
    const buffer = guest.memory.readBlock(argument[1], Math.max(argument[2], 0));
    return unsigned(guest.net.send(argument[0], buffer));
  });
  define("ws2_32.dll", "recv", 4, (guest, argument) => {
    const result = guest.net.recv(argument[0]);
    if (result.byte === winsockConstant.SOCKET_ERROR || result.data === null) return unsigned(winsockConstant.SOCKET_ERROR);
    const capped = result.data.subarray(0, Math.max(Math.min(argument[2], result.data.length), 0));
    guest.memory.writeBlock(argument[1], capped);
    return capped.length;
  });
  define("ws2_32.dll", "ioctlsocket", 3, (guest, argument) => {
    if (argument[1] !== 0x8004667e) return unsigned(guest.net.ioctlsocket(argument[0], "UNSUPPORTED", 0)); // only FIONBIO
    const value = guest.memory.readMemory(argument[2], 4);
    return unsigned(guest.net.ioctlsocket(argument[0], "FIONBIO", value));
  });
  define("ws2_32.dll", "htons", 1, (_guest, argument) => netHtons(argument[0] & 0xffff));
  define("ws2_32.dll", "ntohs", 1, (_guest, argument) => netHtons(argument[0] & 0xffff));
  define("ws2_32.dll", "htonl", 1, (_guest, argument) => netHtonl(argument[0]));
  define("ws2_32.dll", "ntohl", 1, (_guest, argument) => netHtonl(argument[0]));
  define("ws2_32.dll", "inet_addr", 1, (guest, argument) => inetAddr(guest.readAnsiString(argument[0])));

  // --- virtual drive geometry and optical volume (BPTK-102) ---------------------
  // One declared fixed volume and one read-only optical volume. The type,
  // label, serial, and capacity are host-neutral constants; the drive letter is
  // read from the guest path and mapped to the declared profile.
  const driveFor = (path) => {
    if (typeof path !== "string" || path.length < 2 || path[1] !== ":") return null;
    const key = path[0].toLowerCase();
    return driveProfile[key] ?? null;
  };
  const writeQuad = (guest, address, value) => {
    if (address === 0) return;
    const big = BigInt(value);
    guest.memory.writeMemory(address, 4, Number(big & 0xffffffffn));
    guest.memory.writeMemory(address + 4, 4, Number(big >> 32n & 0xffffffffn));
  };
  define("kernel32.dll", "GetLogicalDrives", 0, () => (1 << 2) | (1 << 3)); // C: and D:
  define("kernel32.dll", "GetDriveTypeA", 1, (guest, argument) => {
    const drive = driveFor(guest.readAnsiString(argument[0]) ?? hleProfile.guest_root);
    return drive === null ? 1 : drive.type; // DRIVE_NO_ROOT_DIR when unknown
  });
  define("kernel32.dll", "GetDriveTypeW", 1, (guest, argument) => {
    const drive = driveFor(guest.readWideString(argument[0]) ?? hleProfile.guest_root);
    return drive === null ? 1 : drive.type;
  });
  define("kernel32.dll", "GetVolumeInformationW", 8, (guest, argument) => {
    const drive = driveFor(guest.readWideString(argument[0]) ?? "C:\\") ?? driveProfile.c;
    if (argument[1] !== 0) guest.writeWideString(argument[1], drive.label, Math.max(argument[2], 0));
    if (argument[3] !== 0) guest.memory.writeMemory(argument[3], 4, drive.serial);
    if (argument[4] !== 0) guest.memory.writeMemory(argument[4], 4, 255); // lpMaximumComponentLength
    if (argument[5] !== 0) guest.memory.writeMemory(argument[5], 4, drive.type === 5 ? 0x00080000 : 0x00000003); // FS flags (read-only for CDFS)
    if (argument[6] !== 0) guest.writeWideString(argument[6], drive.file_system, Math.max(argument[7], 0));
    return 1;
  });
  define("kernel32.dll", "GetVolumeInformationA", 8, (guest, argument) => {
    const drive = driveFor(guest.readAnsiString(argument[0]) ?? "C:\\") ?? driveProfile.c;
    if (argument[1] !== 0) guest.writeAnsiString(argument[1], drive.label, Math.max(argument[2], 0));
    if (argument[3] !== 0) guest.memory.writeMemory(argument[3], 4, drive.serial);
    if (argument[4] !== 0) guest.memory.writeMemory(argument[4], 4, 255);
    if (argument[5] !== 0) guest.memory.writeMemory(argument[5], 4, drive.type === 5 ? 0x00080000 : 0x00000003);
    if (argument[6] !== 0) guest.writeAnsiString(argument[6], drive.file_system, Math.max(argument[7], 0));
    return 1;
  });
  define("kernel32.dll", "GetDiskFreeSpaceExA", 4, (guest, argument) => {
    const drive = driveFor(guest.readAnsiString(argument[0]) ?? "C:\\") ?? driveProfile.c;
    writeQuad(guest, argument[1], drive.free_byte); // lpFreeBytesAvailableToCaller
    writeQuad(guest, argument[2], drive.total_byte); // lpTotalNumberOfBytes
    writeQuad(guest, argument[3], drive.free_byte); // lpTotalNumberOfFreeBytes
    return 1;
  });
  define("kernel32.dll", "GetDiskFreeSpaceA", 5, (guest, argument) => {
    const drive = driveFor(guest.readAnsiString(argument[0]) ?? "C:\\") ?? driveProfile.c;
    const clusterByte = drive.bytes_per_sector * drive.sectors_per_cluster;
    if (argument[1] !== 0) guest.memory.writeMemory(argument[1], 4, drive.sectors_per_cluster);
    if (argument[2] !== 0) guest.memory.writeMemory(argument[2], 4, drive.bytes_per_sector);
    if (argument[3] !== 0) guest.memory.writeMemory(argument[3], 4, Math.floor(drive.free_byte / clusterByte));
    if (argument[4] !== 0) guest.memory.writeMemory(argument[4], 4, Math.floor(drive.total_byte / clusterByte));
    return 1;
  });

  // --- XInput gamepad (BPTK-097) ------------------------------------------------
  // The controller state is injected by the browser Gamepad bridge; every slot
  // is disconnected by default, so XInput reports ERROR_DEVICE_NOT_CONNECTED
  // rather than a fabricated pad. Registered under the common xinput1_3.dll.
  define("xinput1_3.dll", "XInputGetState", 2, (guest, argument) => {
    const result = guest.gamepad.getState(argument[0]);
    if (!result.connected) return xinputError.ERROR_DEVICE_NOT_CONNECTED;
    const base = argument[1];
    const s = result.state;
    guest.memory.writeMemory(base + 0, 4, result.packet_number);
    guest.memory.writeMemory(base + 4, 2, s.buttons & 0xffff);
    guest.memory.writeMemory(base + 6, 1, s.left_trigger & 0xff);
    guest.memory.writeMemory(base + 7, 1, s.right_trigger & 0xff);
    guest.memory.writeMemory(base + 8, 2, s.thumb_lx & 0xffff);
    guest.memory.writeMemory(base + 10, 2, s.thumb_ly & 0xffff);
    guest.memory.writeMemory(base + 12, 2, s.thumb_rx & 0xffff);
    guest.memory.writeMemory(base + 14, 2, s.thumb_ry & 0xffff);
    return xinputError.ERROR_SUCCESS;
  });
  define("xinput1_3.dll", "XInputSetState", 2, (guest, argument) => {
    const left = guest.memory.readMemory(argument[1], 2);
    const right = guest.memory.readMemory(argument[1] + 2, 2);
    return guest.gamepad.setVibration(argument[0], left, right) ? xinputError.ERROR_SUCCESS : xinputError.ERROR_DEVICE_NOT_CONNECTED;
  });
  define("xinput1_3.dll", "XInputGetCapabilities", 3, (guest, argument) => {
    const caps = guest.gamepad.getCapabilities(argument[0]);
    if (caps === null) return xinputError.ERROR_DEVICE_NOT_CONNECTED;
    const base = argument[2];
    guest.memory.writeMemory(base + 0, 1, caps.type & 0xff);
    guest.memory.writeMemory(base + 1, 1, caps.subtype & 0xff);
    guest.memory.writeMemory(base + 2, 2, 0); // Flags
    guest.memory.writeMemory(base + 4, 2, caps.buttons & 0xffff); // Gamepad.wButtons supported mask
    return xinputError.ERROR_SUCCESS;
  });
  define("xinput1_3.dll", "XInputEnable", 1, () => 0);

  // --- Plink import-surface widening (BPTK-146) -----------------------------
  // The ANSI file surface, the kernel objects, and the honest refusals the
  // Plink (win32) startup path reaches. The ANSI rows share the wide siblings'
  // bounded state; the process, thread, serial-port, and named-pipe rows serve
  // the confined probe's honest refusal and name the reason in the last error.
  define("kernel32.dll", "CreateFileA", 7, (guest, argument) => guest.openFile(guest.readAnsiString(argument[0]), argument[1], argument[4]));
  define("kernel32.dll", "DeleteFileA", 1, (guest, argument) => guest.deleteFile(guest.readAnsiString(argument[0])));
  define("kernel32.dll", "FindFirstFileA", 2, (guest, argument) => guest.findFirst(argument[0], 0, argument[1], 0, 0));
  define("kernel32.dll", "FindClose", 1, (guest, argument) => guest.closeHandle(argument[0]));
  define("kernel32.dll", "GetFileAttributesExA", 3, (guest, argument) => guest.fileAttributesEx(guest.readAnsiString(argument[0]), argument[1], argument[2]));
  define("kernel32.dll", "LoadLibraryExA", 3, (guest, argument) => guest.loadLibrary(guest.readAnsiString(argument[0]), argument[2]));
  define("kernel32.dll", "CreateEventA", 4, (guest, argument) => guest.createEvent(argument[1] !== 0, argument[2] !== 0, argument[3]));
  define("kernel32.dll", "CreateMutexA", 3, (guest, argument) => guest.createMutex(argument[1] !== 0, argument[2], false));
  define("kernel32.dll", "ReleaseMutex", 1, (guest, argument) => guest.releaseMutex(argument[0]));
  define("kernel32.dll", "CreateFileMappingA", 6, (guest, argument) => guest.createFileMapping(argument[0], argument[4], argument[5], false));
  define("kernel32.dll", "MapViewOfFile", 5, (guest, argument) => guest.mapViewOfFile(argument[0], argument[4]));
  define("kernel32.dll", "UnmapViewOfFile", 1, (guest, argument) => guest.unmapViewOfFile(argument[0]));
  define("kernel32.dll", "CreatePipe", 4, (guest, argument) => guest.createPipe(argument[0], argument[1], argument[3]));
  define("kernel32.dll", "GetWindowsDirectoryA", 2, (guest, argument) => {
    const directory = hleProfile.system_directory.replace(/\\System32$/i, "");
    const written = guest.writeAnsiString(argument[0], directory, argument[1] >>> 0);
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return directory.length + 1;
    }
    return directory.length;
  });
  define("kernel32.dll", "GlobalMemoryStatus", 1, (guest, argument) => {
    // MEMORYSTATUS (32 byte) over the declared, host-neutral memory profile.
    const base = argument[0];
    guest.memory.writeMemory(base, 4, 32); // dwLength
    guest.memory.writeMemory(base + 4, 4, 25); // dwMemoryLoad (percent)
    guest.memory.writeMemory(base + 8, 4, 0x80000000); // dwTotalPhys (2 GiB)
    guest.memory.writeMemory(base + 12, 4, 0x40000000); // dwAvailPhys (1 GiB)
    guest.memory.writeMemory(base + 16, 4, 0xc0000000); // dwTotalPageFile (3 GiB)
    guest.memory.writeMemory(base + 20, 4, 0x60000000); // dwAvailPageFile
    guest.memory.writeMemory(base + 24, 4, 0x7fff0000); // dwTotalVirtual (~2 GiB)
    guest.memory.writeMemory(base + 28, 4, 0x7ff00000); // dwAvailVirtual
    return 0;
  });
  define("kernel32.dll", "GetProcessTimes", 5, (guest, argument) => guest.processTimes(argument[0], argument[1], argument[2], argument[3], argument[4]));
  define("kernel32.dll", "LocalAlloc", 2, (guest, argument) => {
    const flag = (argument[0] & 0x40) !== 0 ? heapFlag.zero_memory : 0; // LMEM_ZEROINIT
    return guest.heapAllocate(guest.defaultHeapHandle(), flag, Math.max(argument[1], 1));
  });
  define("kernel32.dll", "LocalFree", 1, (guest, argument) => {
    if (argument[0] === 0) return 0;
    return guest.heapFree(guest.defaultHeapHandle(), 0, argument[0]) === 1 ? 0 : argument[0];
  });
  define("kernel32.dll", "LocalFileTimeToFileTime", 2, (guest, argument) => {
    // The declared time zone bias is UTC, so the local and system file time are
    // the same 64-bit value.
    if (argument[0] === 0 || argument[1] === 0) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    guest.memory.writeBlock(argument[1], guest.memory.readBlock(argument[0], 8));
    return 1;
  });
  define("kernel32.dll", "SetConsoleMode", 2, (guest, argument) => guest.setConsoleMode(argument[0], argument[1]));
  define("kernel32.dll", "SetHandleInformation", 3, (guest, argument) => guest.setHandleInformation(argument[0], argument[1], argument[2]));
  define("kernel32.dll", "FormatMessageA", 7, (guest, argument) => {
    const flag = unsigned(argument[0]);
    if ((flag & 0x00000800) !== 0) { // FORMAT_MESSAGE_FROM_HMODULE — no message module is served
      guest.setLastError(errorValue.mod_not_found);
      return 0;
    }
    let text;
    if ((flag & 0x00000400) !== 0) text = guest.readAnsiString(argument[1]) ?? ""; // FROM_STRING
    else text = formatSystemMessage(argument[2]); // FROM_SYSTEM (or default)
    if ((flag & 0x00000100) !== 0) { // ALLOCATE_BUFFER: lpBuffer is a char**
      const address = guest.heapAllocate(guest.defaultHeapHandle(), 0, text.length + 1);
      if (address === 0) {
        guest.setLastError(errorValue.not_enough_memory);
        return 0;
      }
      guest.writeAnsiString(address, text, text.length + 1);
      guest.memory.writeMemory(argument[4], 4, address);
      return text.length;
    }
    const written = guest.writeAnsiString(argument[4], text.slice(0, Math.max(argument[5] - 1, 0)), argument[5] >>> 0);
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    return written.length;
  });
  define("kernel32.dll", "GetOverlappedResult", 4, (guest, argument) => {
    // Every served file operation is synchronous, so no operation is ever
    // pending; an overlapped handle the probe never issued is not valid.
    const record = guest.handleRecord(argument[0]);
    if (record === undefined) {
      guest.setLastError(errorValue.invalid_handle);
      return 0;
    }
    if (argument[2] !== 0) guest.memory.writeMemory(argument[2], 4, 0);
    return 1;
  });
  define("kernel32.dll", "UnhandledExceptionFilter", 1, () => 1); // EXCEPTION_EXECUTE_HANDLER: no debugger is attached
  define("kernel32.dll", "RtlUnwind", 4, (guest, argument) => {
    // The host-side registration chain is unwound to the target frame; the
    // guest __finally blocks cannot be re-entered by the bounded probe, so a
    // target that is not on the chain is a no-op rather than a fault.
    const targetFrame = unsigned(argument[0]);
    if (targetFrame !== 0) {
      try {
        guest.seh_thread.unwindTo(targetFrame, null);
      } catch {
        // The target frame is not on the chain; nothing to unwind.
      }
    }
    return 0;
  });
  define("kernel32.dll", "EnumSystemLocalesW", 2, (guest) => {
    // The enumeration contract calls a guest callback per locale, which the
    // bounded probe cannot re-enter; it refuses honestly rather than skip the
    // callback and report a false success.
    guest.setLastError(120); // ERROR_CALL_NOT_IMPLEMENTED
    return 0;
  });
  define("kernel32.dll", "CreateThread", 6, (guest) => {
    // The confined probe is single-threaded: it cannot run a second thread, so
    // it refuses rather than hand back a handle that never executes.
    guest.setLastError(164); // ERROR_MAX_THRDS_REACHED
    return 0;
  });
  define("kernel32.dll", "CreateProcessA", 10, (guest) => {
    // Process creation is a denied capability in the containment policy.
    guest.setLastError(errorValue.access_denied);
    return 0;
  });
  define("kernel32.dll", "CreateNamedPipeA", 8, (guest) => {
    guest.setLastError(120); // ERROR_CALL_NOT_IMPLEMENTED: no named-pipe namespace is served
    return 0xffffffff;
  });
  define("kernel32.dll", "ConnectNamedPipe", 2, (guest) => {
    guest.setLastError(errorValue.invalid_handle); // no pipe-server handle can exist
    return 0;
  });
  define("kernel32.dll", "WaitNamedPipeA", 2, (guest) => {
    guest.setLastError(errorValue.file_not_found); // the named pipe does not exist
    return 0;
  });
  const commRefuse = (guest) => {
    // No serial device is mapped, so any handle passed to the comm surface is
    // not a comm port.
    guest.setLastError(errorValue.invalid_handle);
    return 0;
  };
  define("kernel32.dll", "GetCommState", 2, commRefuse);
  define("kernel32.dll", "SetCommState", 2, commRefuse);
  define("kernel32.dll", "SetCommTimeouts", 2, commRefuse);
  define("kernel32.dll", "SetCommBreak", 1, commRefuse);
  define("kernel32.dll", "ClearCommBreak", 1, commRefuse);

  // --- advapi32 SID and security descriptor (BPTK-146) ----------------------
  // Self-contained operations over bounded guest memory: a SID and a security
  // descriptor are byte structures, never a host token.
  define("advapi32.dll", "GetLengthSid", 1, (guest, argument) => guest.sidLength(argument[0]));
  define("advapi32.dll", "CopySid", 3, (guest, argument) => {
    const length = guest.sidLength(argument[2]);
    if ((argument[0] >>> 0) < length) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    guest.memory.writeBlock(argument[1], guest.memory.readBlock(argument[2], length));
    return 1;
  });
  define("advapi32.dll", "EqualSid", 2, (guest, argument) => {
    const leftLength = guest.sidLength(argument[0]);
    const rightLength = guest.sidLength(argument[1]);
    if (leftLength !== rightLength) return 0;
    return Buffer.compare(guest.memory.readBlock(argument[0], leftLength), guest.memory.readBlock(argument[1], rightLength)) === 0 ? 1 : 0;
  });
  define("advapi32.dll", "AllocateAndInitializeSid", 11, (guest, argument) => {
    const count = argument[1] & 0xff;
    const subAuthority = [];
    for (let index = 0; index < count && index < 8; index += 1) subAuthority.push(argument[2 + index]);
    const address = guest.allocateSid(argument[0], subAuthority);
    if (address === 0) {
      guest.setLastError(errorValue.not_enough_memory);
      return 0;
    }
    guest.memory.writeMemory(argument[10], 4, address);
    return 1;
  });
  define("advapi32.dll", "GetUserNameA", 2, (guest, argument) => {
    const required = guestUserName.length + 1;
    const capacity = guest.memory.readMemory(argument[1], 4);
    if (capacity < required) {
      guest.memory.writeMemory(argument[1], 4, required);
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    guest.writeAnsiString(argument[0], guestUserName, capacity);
    guest.memory.writeMemory(argument[1], 4, required);
    return 1;
  });
  define("advapi32.dll", "InitializeSecurityDescriptor", 2, (guest, argument) => {
    if (unsigned(argument[1]) !== 1) { // SECURITY_DESCRIPTOR_REVISION
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    guest.memory.writeBlock(argument[0], Buffer.alloc(20));
    guest.memory.writeMemory(argument[0], 1, 1); // Revision
    return 1;
  });
  define("advapi32.dll", "SetSecurityDescriptorDacl", 4, (guest, argument) => {
    if (guest.memory.readMemory(argument[0], 1) !== 1) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const control = guest.memory.readMemory(argument[0] + 2, 2);
    const present = argument[1] !== 0;
    const defaulted = argument[3] !== 0;
    // SE_DACL_PRESENT 0x0004, SE_DACL_DEFAULTED 0x0008.
    let next = control & ~0x000c;
    if (present) next |= 0x0004;
    if (present && defaulted) next |= 0x0008;
    guest.memory.writeMemory(argument[0] + 2, 2, next);
    guest.memory.writeMemory(argument[0] + 16, 4, present ? unsigned(argument[2]) : 0); // Dacl pointer
    return 1;
  });
  define("advapi32.dll", "SetSecurityDescriptorOwner", 3, (guest, argument) => {
    if (guest.memory.readMemory(argument[0], 1) !== 1) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const control = guest.memory.readMemory(argument[0] + 2, 2);
    guest.memory.writeMemory(argument[0] + 2, 2, argument[2] !== 0 ? control | 0x0001 : control & ~0x0001); // SE_OWNER_DEFAULTED 0x0001
    guest.memory.writeMemory(argument[0] + 4, 4, unsigned(argument[1])); // Owner pointer
    return 1;
  });

  // --- Universal CRT startup (Win64 CRT-init breadth, BPTK-031) ---------------
  // The x86-64 freeware in the corpus is built against the Universal CRT: the PE
  // entry is mainCRTStartup / WinMainCRTStartup, whose __scrt_common_main_seh
  // walks a fixed startup chain before it calls the guest main/WinMain —
  // configure argv, initialize the environment, set the app type, register the
  // invalid-parameter handler, run the C then C++ initializer tables, then read
  // argc/argv/envp. Each stub below serves its honest bounded contract so the
  // interpreter flows through startup toward main rather than stopping at the
  // first CRT import. The pointer accessors return addresses inside the fixed
  // CRT block (guest.crt), whose cells hold argc=1, argv=[program, NULL], an
  // empty environment, and zeroed errno/mode words. The api-set forwarders and
  // the legacy msvcrt names resolve to the same behavior because a redistributed
  // binary may import either name for the same entry.
  const crtRuntimeLibrary = "api-ms-win-crt-runtime-l1-1-0.dll";
  const crtStdioLibrary = "api-ms-win-crt-stdio-l1-1-0.dll";
  const crtHeapLibrary = "api-ms-win-crt-heap-l1-1-0.dll";
  const crtMathLibrary = "api-ms-win-crt-math-l1-1-0.dll";
  const crtLocaleLibrary = "api-ms-win-crt-locale-l1-1-0.dll";
  // A stub registered under every library name a corpus binary imports it by.
  const defineForEach = (libraryList, symbol, argc, emulate) => {
    for (const library of libraryList) define(library, symbol, argc, emulate);
  };

  // Argument-vector configuration: mode in, zero (success) out. The bounded
  // world exposes exactly one argument (the program path), already staged.
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_configure_narrow_argv", 1, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_configure_wide_argv", 1, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_initialize_narrow_environment", 0, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_initialize_wide_environment", 0, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_get_initial_narrow_environment", 0, (guest) => guest.crt.environArray);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_get_initial_wide_environment", 0, (guest) => guest.crt.wenvironArray);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_get_narrow_winmain_command_line", 0, (guest) => guest.crt.winmainLine);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_get_wide_winmain_command_line", 0, (guest) => guest.crt.winmainLine);

  // App-type and handler registration. _set_app_type/__set_app_type record the
  // console/GUI class; the two handler setters return the previous handler (0).
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_set_app_type", 1, (guest, argument) => { guest.app_type = argument[0] >>> 0; return 0; });
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "__set_app_type", 1, (guest, argument) => { guest.app_type = argument[0] >>> 0; return 0; });
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_set_invalid_parameter_handler", 1, (guest, argument) => {
    const previous = guest.invalid_parameter_handler;
    guest.invalid_parameter_handler = unsigned(argument[0]);
    return previous;
  });
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_get_invalid_parameter_handler", 0, (guest) => guest.invalid_parameter_handler);
  defineForEach([crtRuntimeLibrary, crtMathLibrary], "__setusermatherr", 1, () => 0);
  defineForEach([crtHeapLibrary, "msvcrt.dll"], "_set_new_mode", 1, (guest, argument) => { const previous = guest.new_mode; guest.new_mode = argument[0] >>> 0; return previous; });

  // atexit / onexit registration: the bounded probe records the table pointer
  // and returns success; the destructors would only fire at process teardown,
  // which the bounded run never reaches.
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_crt_atexit", 1, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_crt_at_quick_exit", 1, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_register_thread_local_exe_atexit_callback", 1, (guest, argument) => { guest.thread_local_atexit_dtor = unsigned(argument[0]); return 0; });
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_initialize_onexit_table", 1, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_register_onexit_function", 2, () => 0);

  // Pointer accessors: each returns the address of the corresponding CRT cell.
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "__p___argc", 0, (guest) => guest.crt.argcCell);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "__p___argv", 0, (guest) => guest.crt.argvCell);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "__p___wargv", 0, (guest) => guest.crt.wargvCell);
  defineForEach([crtRuntimeLibrary, "api-ms-win-crt-environment-l1-1-0.dll", "msvcrt.dll"], "__p__environ", 0, (guest) => guest.crt.environCell);
  defineForEach([crtRuntimeLibrary, "api-ms-win-crt-environment-l1-1-0.dll", "msvcrt.dll"], "__p__wenviron", 0, (guest) => guest.crt.wenvironCell);
  defineForEach([crtRuntimeLibrary, crtStdioLibrary, "msvcrt.dll"], "__p__commode", 0, (guest) => guest.crt.commodeCell);
  defineForEach([crtRuntimeLibrary, crtStdioLibrary, "msvcrt.dll"], "__p__fmode", 0, (guest) => guest.crt.fmodeCell);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_errno", 0, (guest) => guest.crt.errnoCell);

  // The file-mode (text/binary) word the stdio startup configures. _set_fmode
  // stores the mode and returns 0 (errno_t success); _get_fmode reads it back
  // through the caller's out pointer. Both mirror the __p__fmode cell.
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "_set_fmode", 1, (guest, argument) => {
    guest.memory.writeMemory(guest.crt.fmodeCell, 4, unsigned(argument[0]));
    return 0;
  });
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "_get_fmode", 1, (guest, argument) => {
    if (argument[0] === 0) return errorValue.invalid_parameter;
    guest.memory.writeMemory(argument[0], 4, guest.memory.readMemory(guest.crt.fmodeCell, 4));
    return 0;
  });

  // Locale query used early by the startup: the bounded world is the invariant
  // "C" locale, so the multibyte maximum is one byte.
  defineForEach([crtLocaleLibrary, "msvcrt.dll"], "___mb_cur_max_func", 0, () => 1);
  // Per-thread locale configuration: the bounded world runs one thread in the
  // invariant "C" locale, so the call records nothing and reports the previous
  // per-thread setting (0 = the global locale is in effect).
  defineForEach([crtLocaleLibrary, "msvcrt.dll"], "_configthreadlocale", 1, () => 0);

  // The VC runtime (vcruntime140.dll) forwards its critical-section helpers to
  // the kernel32 primitives; the bounded world serves them with identical
  // single-thread semantics so the C++ runtime init flows through to main.
  const vcrtLibrary = "vcruntime140.dll";
  define(vcrtLibrary, "__vcrt_InitializeCriticalSectionEx", 3, (guest, argument) => {
    guest.initializeCriticalSection(argument[0], argument[1] & 0x00ffffff);
    return 1;
  });
  define(vcrtLibrary, "__vcrt_EnterCriticalSection", 1, (guest, argument) => { guest.enterCriticalSection(argument[0], true); return 0; });
  define(vcrtLibrary, "__vcrt_LeaveCriticalSection", 1, (guest, argument) => { guest.leaveCriticalSection(argument[0]); return 0; });
  define(vcrtLibrary, "__vcrt_DeleteCriticalSection", 1, (guest, argument) => { guest.deleteCriticalSection(argument[0]); return 0; });
  // The VC runtime telemetry triggers the ucrt entry calls around main. On a
  // real machine with telemetry disabled these are no-ops; the bounded world
  // serves them as the same no-op so the CRT init/return path flows through to
  // the game's own main rather than stalling at the trigger.
  define(vcrtLibrary, "__telemetry_main_invoke_trigger", 1, () => 0);
  define(vcrtLibrary, "__telemetry_main_return_trigger", 1, () => 0);

  // The compiler memory intrinsics the VC runtime and the ucrt string api-set
  // both export. Each performs the real byte operation over guest memory and
  // returns the C contract value, so an initializer that clears or copies a
  // global block does the actual work rather than a faked return.
  const crtStringLibrary = "api-ms-win-crt-string-l1-1-0.dll";
  const crtPrivateLibrary = "api-ms-win-crt-private-l1-1-0.dll";
  // A pointer argument keeps its full width. An i386 guest pointer already fits
  // 32 bits, so this is identity there; an x86-64 guest pointer to the stack or
  // TEB lives above 4 GiB (the interpreter maps the stack at 0x7ff000000000), so
  // truncating it to a dword (unsigned) would fault a legitimate memset/memcpy.
  const blockAddress = (value) => (value < 0 ? value >>> 0 : value);
  const memsetImpl = (guest, argument) => {
    const [dest, value, count] = [blockAddress(argument[0]), argument[1] & 0xff, unsigned(argument[2])];
    if (count > 0) guest.memory.writeBlock(dest, Buffer.alloc(count, value));
    return dest;
  };
  const memcpyImpl = (guest, argument) => {
    const [dest, src, count] = [blockAddress(argument[0]), blockAddress(argument[1]), unsigned(argument[2])];
    if (count > 0) guest.memory.writeBlock(dest, guest.memory.readBlock(src, count));
    return dest;
  };
  const memcmpImpl = (guest, argument) => {
    const [a, b, count] = [blockAddress(argument[0]), blockAddress(argument[1]), unsigned(argument[2])];
    for (let index = 0; index < count; index += 1) {
      const va = guest.memory.readMemory(a + index, 1);
      const vb = guest.memory.readMemory(b + index, 1);
      if (va !== vb) return va < vb ? 0xffffffff : 1; // C memcmp: sign of the first difference
    }
    return 0;
  };
  const memchrImpl = (guest, argument) => {
    const [ptr, value, count] = [blockAddress(argument[0]), argument[1] & 0xff, unsigned(argument[2])];
    for (let index = 0; index < count; index += 1) if (guest.memory.readMemory(ptr + index, 1) === value) return ptr + index;
    return 0;
  };
  defineForEach([vcrtLibrary, crtStringLibrary, crtPrivateLibrary, "msvcrt.dll"], "memset", 3, memsetImpl);
  defineForEach([vcrtLibrary, crtStringLibrary, crtPrivateLibrary, "msvcrt.dll"], "memcpy", 3, memcpyImpl);
  defineForEach([vcrtLibrary, crtStringLibrary, crtPrivateLibrary, "msvcrt.dll"], "memmove", 3, memcpyImpl);
  defineForEach([vcrtLibrary, crtStringLibrary, crtPrivateLibrary, "msvcrt.dll"], "memcmp", 3, memcmpImpl);
  defineForEach([vcrtLibrary, crtStringLibrary, crtPrivateLibrary, "msvcrt.dll"], "memchr", 3, memchrImpl);

  // --- msvcrt.dll C runtime for the i386 CLI corpus (BPTK-010) --------------
  // jq (corpus-010) links the legacy msvcrt.dll C runtime: CRT startup, the
  // heap, the string/mem family, ctype, stdio the tool actually calls, locale,
  // time, and errno. Each stub performs its real bounded work over the HLE
  // arena/heap and virtual FS so the probe executes real behavior toward main.
  // Where a bounded integer probe genuinely cannot serve a contract — an x87
  // double return, a guest comparator callback, a spawned OS thread, or a
  // non-local jmp_buf restore — the stub raises one named structured refusal
  // instead of a silent no-op. These are cdecl: the runtime dispatch reads the
  // declared dword count as the argument frame.
  const msvcrt = "msvcrt.dll";
  const refuseDouble = (symbol) => () => { throw hleFault("hle_x87_double_abi_unsupported", `msvcrt!${symbol} returns an x87 double the bounded integer probe cannot carry across the EAX dispatch boundary`); };
  const refuseCallback = (symbol) => () => { throw hleFault("hle_guest_callback_unsupported", `msvcrt!${symbol} must re-enter guest code for its callback, which the single-pass bounded probe does not provide`); };
  const refuseThread = (symbol) => () => { throw hleFault("hle_thread_unsupported", `msvcrt!${symbol} spawns an OS thread the single-thread bounded probe does not provide`); };
  const refuseJump = (symbol) => () => { throw hleFault("hle_nonlocal_jump_unsupported", `msvcrt!${symbol} restores a saved jmp_buf frame the single-pass bounded probe cannot unwind`); };
  const readByte = (guest, address, index) => guest.memory.readMemory(unsigned(address) + index, 1);
  const cLower = (code) => (code >= 0x41 && code <= 0x5a ? code + 0x20 : code);

  // Data exports (resolved as a live guest address of the backing cell/array).
  define(msvcrt, "_iob", 0, (guest) => guest.crtRuntime.iobBase);
  define(msvcrt, "_environ", 0, (guest) => guest.crt.environCell);
  define(msvcrt, "_tzname", 0, (guest) => guest.crtRuntime.tznameBase);
  define(msvcrt, "__mb_cur_max", 0, (guest) => guest.crtRuntime.mbCurMaxCell);
  define(msvcrt, "__winitenv", 0, (guest) => guest.crt.wenvironCell);

  // CRT startup and teardown.
  define(msvcrt, "__setusermatherr", 1, () => 0);
  define(msvcrt, "__wgetmainargs", 5, (guest, argument) => {
    if (argument[0] !== 0) guest.memory.writeMemory(argument[0], 4, 1);
    if (argument[1] !== 0) guest.memory.writeMemory(argument[1], 4, guest.crt.wargvArray);
    if (argument[2] !== 0) guest.memory.writeMemory(argument[2], 4, guest.crt.wenvironArray);
    return 0;
  });
  define(msvcrt, "_amsg_exit", 1, (guest, argument) => raiseProcessExit(argument[0] === 0 ? 255 : 255));
  define(msvcrt, "_assert", 3, () => raiseProcessExit(3));
  define(msvcrt, "_cexit", 0, () => 0);
  define(msvcrt, "_initterm", 2, () => 0); // The initializer table is not re-entered; see the callback contract above.
  define(msvcrt, "_onexit", 1, (guest, argument) => unsigned(argument[0]));
  define(msvcrt, "_lock", 1, () => 0); // single-thread probe: the CRT lock is uncontended
  define(msvcrt, "_unlock", 1, () => 0);
  define(msvcrt, "exit", 1, (guest, argument) => raiseProcessExit(argument[0]));
  define(msvcrt, "abort", 0, () => raiseProcessExit(3));
  define(msvcrt, "raise", 1, () => 0); // no C signal handler fires in the bounded run; SIG_DFL is a no-op here
  define(msvcrt, "signal", 2, () => 0); // returns SIG_DFL (0) as the previous handler
  define(msvcrt, "_beginthreadex", 6, refuseThread("_beginthreadex"));
  define(msvcrt, "_endthreadex", 1, () => 0);
  define(msvcrt, "_setjmp3", 2, () => 0); // setjmp saves and returns 0 on the direct path
  define(msvcrt, "longjmp", 2, refuseJump("longjmp"));

  // Heap. The ucrt heap surface (api-ms-win-crt-heap-l1-1-0.dll) and the legacy
  // msvcrt heap surface share one real process default heap, so malloc/free/
  // calloc/realloc/_msize/_recalloc are the same bytes whichever import a guest
  // links against; the Win64 ucrt CRT init (Dwarf Fortress) reaches the ucrt DLL.
  defineForEach([crtHeapLibrary, msvcrt], "malloc", 1, (guest, argument) => guest.crtMalloc(argument[0]));
  defineForEach([crtHeapLibrary, msvcrt], "calloc", 2, (guest, argument) => guest.crtCalloc(argument[0], argument[1]));
  defineForEach([crtHeapLibrary, msvcrt], "realloc", 2, (guest, argument) => guest.crtRealloc(argument[0], argument[1]));
  defineForEach([crtHeapLibrary, msvcrt], "free", 1, (guest, argument) => guest.crtFree(argument[0]));
  defineForEach([crtHeapLibrary, msvcrt], "_msize", 1, (guest, argument) => guest.crtMsize(argument[0]));
  defineForEach([crtHeapLibrary, msvcrt], "_recalloc", 3, (guest, argument) => guest.crtRecalloc(argument[0], argument[1], argument[2]));
  // _callnewh invokes the registered C++ new-handler when an allocation fails.
  // No new-handler is registered in this bounded process, so it honestly reports
  // "no handler" (0), the signal operator new uses to throw bad_alloc.
  defineForEach([crtHeapLibrary, msvcrt], "_callnewh", 1, () => 0);
  define(msvcrt, "_strdup", 1, (guest, argument) => {
    const text = guest.readAnsiString(argument[0]);
    if (text === null) return 0;
    const address = guest.crtMalloc(text.length + 1);
    if (address === 0) return 0;
    guest.writeAnsiString(address, text, text.length + 1);
    return address;
  });

  // String and memory (memcpy/memmove/memset/memcmp/memchr are served above).
  define(msvcrt, "strlen", 1, (guest, argument) => guest.readAnsiString(argument[0])?.length ?? 0);
  define(msvcrt, "wcslen", 1, (guest, argument) => guest.readWideString(argument[0])?.length ?? 0);
  define(msvcrt, "strcmp", 2, (guest, argument) => {
    let index = 0;
    for (;; index += 1) {
      const a = readByte(guest, argument[0], index);
      const b = readByte(guest, argument[1], index);
      if (a !== b) return a < b ? 0xffffffff : 1;
      if (a === 0) return 0;
    }
  });
  define(msvcrt, "strncmp", 3, (guest, argument) => {
    const count = unsigned(argument[2]);
    for (let index = 0; index < count; index += 1) {
      const a = readByte(guest, argument[0], index);
      const b = readByte(guest, argument[1], index);
      if (a !== b) return a < b ? 0xffffffff : 1;
      if (a === 0) return 0;
    }
    return 0;
  });
  define(msvcrt, "_strnicmp", 3, (guest, argument) => {
    const count = unsigned(argument[2]);
    for (let index = 0; index < count; index += 1) {
      const a = cLower(readByte(guest, argument[0], index));
      const b = cLower(readByte(guest, argument[1], index));
      if (a !== b) return a < b ? 0xffffffff : 1;
      if (a === 0) return 0;
    }
    return 0;
  });
  define(msvcrt, "strcpy", 2, (guest, argument) => {
    const text = guest.readAnsiString(argument[1]) ?? "";
    guest.writeAnsiString(unsigned(argument[0]), text, text.length + 1);
    return unsigned(argument[0]);
  });
  define(msvcrt, "strncpy", 3, (guest, argument) => {
    const dest = unsigned(argument[0]);
    const count = unsigned(argument[2]);
    const text = guest.readAnsiString(argument[1]) ?? "";
    for (let index = 0; index < count; index += 1) {
      guest.memory.writeMemory(dest + index, 1, index < text.length ? text.charCodeAt(index) & 0xff : 0);
    }
    return dest;
  });
  define(msvcrt, "strchr", 2, (guest, argument) => {
    const target = argument[1] & 0xff;
    const base = unsigned(argument[0]);
    for (let index = 0; ; index += 1) {
      const value = readByte(guest, base, index);
      if (value === target) return base + index;
      if (value === 0) return target === 0 ? base + index : 0;
    }
  });
  define(msvcrt, "strrchr", 2, (guest, argument) => {
    const target = argument[1] & 0xff;
    const text = guest.readAnsiString(argument[0]) ?? "";
    const base = unsigned(argument[0]);
    if (target === 0) return base + text.length;
    for (let index = text.length - 1; index >= 0; index -= 1) if ((text.charCodeAt(index) & 0xff) === target) return base + index;
    return 0;
  });
  define(msvcrt, "strspn", 2, (guest, argument) => {
    const accept = guest.readAnsiString(argument[1]) ?? "";
    const text = guest.readAnsiString(argument[0]) ?? "";
    let index = 0;
    while (index < text.length && accept.includes(text[index])) index += 1;
    return index;
  });
  define(msvcrt, "strstr", 2, (guest, argument) => {
    const hay = guest.readAnsiString(argument[0]) ?? "";
    const needle = guest.readAnsiString(argument[1]) ?? "";
    const at = hay.indexOf(needle);
    return at < 0 ? 0 : unsigned(argument[0]) + at;
  });
  define(msvcrt, "strerror", 1, (guest, argument) => {
    const message = crtStrerrorText(argument[0] | 0);
    guest.writeAnsiString(guest.crtRuntime.strerrorBuf, message, 64);
    return guest.crtRuntime.strerrorBuf;
  });
  define(msvcrt, "wcstombs", 3, (guest, argument) => {
    const wide = guest.readWideString(argument[1]) ?? "";
    const count = unsigned(argument[2]);
    if (unsigned(argument[0]) === 0) return wide.length;
    let written = 0;
    for (; written < wide.length && written < count; written += 1) {
      guest.memory.writeMemory(unsigned(argument[0]) + written, 1, wide.charCodeAt(written) & 0xff);
    }
    if (written < count) guest.memory.writeMemory(unsigned(argument[0]) + written, 1, 0);
    return written;
  });

  // ctype (the "C" locale classification).
  define(msvcrt, "isalnum", 1, (guest, argument) => {
    const c = argument[0] & 0xff;
    return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) ? 8 : 0;
  });
  define(msvcrt, "isalpha", 1, (guest, argument) => {
    const c = argument[0] & 0xff;
    return (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) ? 2 : 0;
  });
  define(msvcrt, "isspace", 1, (guest, argument) => {
    const c = argument[0] & 0xff;
    return c === 0x20 || (c >= 0x09 && c <= 0x0d) ? 8 : 0;
  });

  // Number parsing and pseudo-random (deterministic LCG, seed 1).
  define(msvcrt, "atoi", 1, (guest, argument) => {
    const text = (guest.readAnsiString(argument[0]) ?? "").trimStart();
    const match = text.match(/^[+-]?\d+/);
    return match === null ? 0 : unsigned(Number.parseInt(match[0], 10) | 0);
  });
  define(msvcrt, "_ultoa", 3, (guest, argument) => {
    const radix = unsigned(argument[2]) || 10;
    const text = unsigned(argument[0]).toString(radix);
    guest.writeAnsiString(unsigned(argument[1]), text, text.length + 1);
    return unsigned(argument[1]);
  });
  define(msvcrt, "rand", 0, (guest) => {
    guest.rand_state = (Math.imul(guest.rand_state, 214013) + 2531011) >>> 0;
    return (guest.rand_state >>> 16) & 0x7fff;
  });

  // Environment and locale.
  define(msvcrt, "getenv", 1, (guest, argument) => {
    const name = guest.readAnsiString(argument[0]);
    if (name === null) return 0;
    const value = guest.environment.get(name);
    if (value === undefined) return 0;
    const address = guest.crtMalloc(value.length + 1);
    if (address === 0) return 0;
    guest.writeAnsiString(address, value, value.length + 1);
    return address;
  });
  define(msvcrt, "setlocale", 2, (guest) => guest.crtRuntime.localeName);
  define(msvcrt, "localeconv", 0, (guest) => guest.crtRuntime.lconv);

  // Math: an x87 double return the integer EAX dispatch cannot carry.
  for (const symbol of ["acos", "asin", "atan", "cosh", "sinh", "tan", "tanh", "log10"]) define(msvcrt, symbol, 2, refuseDouble(symbol));
  for (const symbol of ["_hypot", "_nextafter"]) define(msvcrt, symbol, 4, refuseDouble(symbol));
  for (const symbol of ["_j0", "_j1", "_y0", "_y1"]) define(msvcrt, symbol, 2, refuseDouble(symbol));
  for (const symbol of ["_jn", "_yn"]) define(msvcrt, symbol, 3, refuseDouble(symbol));

  // Time (one deterministic guest clock; UTC only).
  define(msvcrt, "time", 1, (guest, argument) => {
    const seconds = crtGuestUnixSecond();
    if (unsigned(argument[0]) !== 0) guest.memory.writeMemory(unsigned(argument[0]), 4, seconds);
    return seconds;
  });
  define(msvcrt, "gmtime", 1, (guest, argument) => crtWriteTm(guest, guest.memory.readMemory(unsigned(argument[0]), 4)));
  define(msvcrt, "localtime", 1, (guest, argument) => crtWriteTm(guest, guest.memory.readMemory(unsigned(argument[0]), 4)));
  define(msvcrt, "_mkgmtime32", 1, (guest, argument) => {
    const base = unsigned(argument[0]);
    const field = (offset) => signed32(guest.memory.readMemory(base + offset, 4));
    const epoch = Date.UTC(field(20) + 1900, field(16), field(12), field(8), field(4), field(0)) / 1000;
    return unsigned(epoch | 0);
  });
  define(msvcrt, "_tzset", 0, () => 0); // _tzname is already the UTC pair
  define(msvcrt, "strftime", 4, (guest, argument) => crtStrftime(guest, argument[0], unsigned(argument[1]), argument[2], argument[3]));

  // stdio the tool actually calls.
  // __acrt_iob_func(index) is the ucrt accessor for the standard stream table
  // (0=stdin, 1=stdout, 2=stderr). It returns the FILE at that slot of the same
  // _iob array the msvcrt _iob export hands back, so a ucrt game's stderr
  // logging routes through the identical bounded stdio surface (crtWriteStream
  // reads the fd from FILE+FILE_FD_OFFSET).
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "__acrt_iob_func", 1, (guest, argument) => unsigned(guest.crtRuntime.iobBase + (unsigned(argument[0]) % 3) * FILE_STRUCT_BYTE));
  define(msvcrt, "_fileno", 1, (guest, argument) => unsigned(guest.crtStreamFd(argument[0])));
  define(msvcrt, "_isatty", 1, (guest, argument) => (unsigned(argument[0]) <= 2 ? 1 : 0));
  define(msvcrt, "_get_osfhandle", 1, (guest, argument) => guest.crtOsHandle(argument[0] | 0));
  define(msvcrt, "_setmode", 2, () => 0x4000); // returns the previous _O_TEXT mode
  define(msvcrt, "_open", 3, (guest, argument) => unsigned(guest.crtOpen(argument[0], argument[1] | 0, false)));
  define(msvcrt, "_close", 1, (guest, argument) => unsigned(guest.crtClose(argument[0] | 0)));
  define(msvcrt, "_write", 3, (guest, argument) => {
    const count = unsigned(argument[2]);
    const buffer = count === 0 ? Buffer.alloc(0) : guest.memory.readBlock(unsigned(argument[1]), count);
    return unsigned(guest.crtWriteFd(argument[0] | 0, buffer));
  });
  define(msvcrt, "_fdopen", 2, (guest, argument) => guest.crtFdopen(argument[0] | 0));
  define(msvcrt, "_wfopen", 2, (guest, argument) => {
    const fd = guest.crtOpen(argument[0], 0x0002 | 0x0100, true); // _O_RDWR|_O_CREAT
    return fd < 0 ? 0 : guest.crtFdopen(fd);
  });
  define(msvcrt, "fwrite", 4, (guest, argument) => {
    const size = unsigned(argument[1]);
    const count = unsigned(argument[2]);
    const total = size * count;
    if (total === 0) return 0;
    const buffer = guest.memory.readBlock(unsigned(argument[0]), total);
    const written = guest.crtWriteStream(argument[3], buffer);
    return written < 0 ? 0 : Math.floor(written / (size || 1));
  });
  define(msvcrt, "fread", 4, () => 0); // the bounded console has no input stream; a real file read uses the Win32 path
  // freopen(path, mode, stream): a game redirects stderr/stdout to a log file at
  // startup (Dwarf Fortress opens gamelog/errorlog). The bounded world has no
  // host file, so the stream is returned unchanged — subsequent writes stay on
  // the same captured bounded stdio surface rather than a fabricated file.
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "freopen", 3, (guest, argument) => unsigned(argument[2]));
  // setvbuf(stream, buffer, mode, size): a game turns off log buffering at
  // startup. The bounded stdio surface is unbuffered already, so this succeeds
  // with no state change.
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "setvbuf", 4, () => 0);
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "setbuf", 2, () => 0);
  // The ucrt formatted-output backends. As with the existing printf/fprintf
  // surface, the bounded world writes the format string to the stream rather
  // than running the full varargs %-engine (the frame does not depend on log
  // text). __stdio_common_vfprintf(options, stream, format, locale, valist);
  // __stdio_common_vsprintf(options, buffer, count, format, locale, valist)
  // copies the format into the caller buffer bounded by count and returns the
  // length, which is what a game's snprintf-into-a-fixed-buffer path needs.
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "__stdio_common_vfprintf", 5, (guest, argument) => {
    const text = guest.readAnsiString(unsigned(argument[2])) ?? "";
    const written = guest.crtWriteStream(argument[1], Buffer.from(text, "latin1"));
    return written < 0 ? 0xffffffff : written;
  });
  const commonVsprintf = (guest, argument) => {
    const count = unsigned(argument[2]);
    const text = guest.readAnsiString(unsigned(argument[3])) ?? "";
    const bytes = Buffer.from(text.slice(0, count > 0 ? count - 1 : text.length) + "\0", "latin1");
    guest.memory.writeBlock(unsigned(argument[1]), bytes);
    return bytes.length - 1;
  };
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "__stdio_common_vsprintf", 6, commonVsprintf);
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "__stdio_common_vsprintf_s", 6, commonVsprintf);
  define(msvcrt, "fputc", 2, (guest, argument) => {
    const written = guest.crtWriteStream(argument[1], Buffer.from([argument[0] & 0xff]));
    return written < 0 ? 0xffffffff : argument[0] & 0xff;
  });
  define(msvcrt, "getc", 1, () => 0xffffffff); // EOF: the bounded console is output-only
  define(msvcrt, "fgets", 3, () => 0); // NULL at end of an input-less stream
  define(msvcrt, "fflush", 1, () => 0);
  define(msvcrt, "fclose", 1, (guest, argument) => {
    const fd = guest.crtStreamFd(argument[0]);
    if (fd > 2) guest.crtClose(fd);
    return 0;
  });
  define(msvcrt, "feof", 1, () => 0);
  define(msvcrt, "ferror", 1, () => 0);
  define(msvcrt, "clearerr", 1, () => 0);
  define(msvcrt, "printf", 1, (guest, argument) => {
    const text = guest.readAnsiString(argument[0]) ?? "";
    const buffer = Buffer.from(text, "latin1");
    const written = guest.crtWriteFd(1, buffer);
    return written < 0 ? 0xffffffff : written;
  });
  define(msvcrt, "fprintf", 2, (guest, argument) => {
    const text = guest.readAnsiString(argument[1]) ?? "";
    const written = guest.crtWriteStream(argument[0], Buffer.from(text, "latin1"));
    return written < 0 ? 0xffffffff : written;
  });
  define(msvcrt, "vfprintf", 3, (guest, argument) => {
    const text = guest.readAnsiString(argument[1]) ?? "";
    const written = guest.crtWriteStream(argument[0], Buffer.from(text, "latin1"));
    return written < 0 ? 0xffffffff : written;
  });
  define(msvcrt, "perror", 1, (guest, argument) => {
    const prefix = guest.readAnsiString(argument[0]);
    const message = crtStrerrorText(guest.crtErrno() | 0);
    const line = `${prefix ? `${prefix}: ` : ""}${message}\n`;
    guest.crtWriteFd(2, Buffer.from(line, "latin1"));
    return 0;
  });
  define(msvcrt, "_fullpath", 3, (guest, argument) => {
    const relative = guest.readAnsiString(argument[1]) ?? "";
    const backslash = String.fromCharCode(92);
    const absolute = relative.length >= 2 && relative[1] === ":" ? relative : `${hleProfile.guest_root}${backslash}${relative}`;
    let dest = unsigned(argument[0]);
    if (dest === 0) {
      dest = guest.crtMalloc(absolute.length + 1);
      if (dest === 0) return 0;
    }
    guest.writeAnsiString(dest, absolute, absolute.length + 1);
    return dest;
  });
  define(msvcrt, "_stati64", 2, (guest, argument) => crtStat(guest, guest.readAnsiString(argument[0]), argument[1]));
  define(msvcrt, "_fstati64", 2, (guest, argument) => {
    const handle = guest.crt_fd_table.get(argument[0] | 0);
    if ((argument[0] | 0) > 2 && handle === undefined) { guest.crtErrno(crtErrnoValue.ebadf); return 0xffffffff; }
    guest.memory.writeBlock(unsigned(argument[1]), Buffer.alloc(88));
    return 0;
  });
  define(msvcrt, "qsort", 4, refuseCallback("qsort"));

  // --- shlwapi.dll (path helper for the i386 CLI corpus) --------------------
  define("shlwapi.dll", "PathIsRelativeA", 1, (guest, argument) => {
    const path = guest.readAnsiString(argument[0]);
    if (path === null || path.length === 0) return 1;
    const backslash = String.fromCharCode(92);
    if (path[0] === backslash || path[0] === "/") return 0;
    if (path.length >= 2 && path[1] === ":") return 0;
    return 1;
  });

  // --- kernel32.dll thread/semaphore breadth for the i386 CLI corpus --------
  // jq references a small thread and semaphore surface for its (unused in the
  // bounded run) worker pool. The single-thread probe serves the bounded
  // contract: affinity/priority are fixed, a semaphore is a counted handle, and
  // a wait on an already-signaled bounded object returns at once.
  define("kernel32.dll", "AreFileApisANSI", 0, () => 1);
  define("kernel32.dll", "IsDBCSLeadByteEx", 2, () => 0); // code page 1252 has no DBCS lead byte
  define("kernel32.dll", "GetThreadPriority", 1, () => 0); // THREAD_PRIORITY_NORMAL
  define("kernel32.dll", "SetThreadPriority", 2, () => 1);
  define("kernel32.dll", "GetProcessAffinityMask", 3, (guest, argument) => {
    if (unsigned(argument[1]) !== 0) guest.memory.writeMemory(unsigned(argument[1]), 4, 1);
    if (unsigned(argument[2]) !== 0) guest.memory.writeMemory(unsigned(argument[2]), 4, 1);
    return 1;
  });
  define("kernel32.dll", "SetProcessAffinityMask", 2, () => 1);
  define("kernel32.dll", "GetHandleInformation", 2, (guest, argument) => {
    if (unsigned(argument[1]) !== 0) guest.memory.writeMemory(unsigned(argument[1]), 4, 0);
    return 1;
  });
  define("kernel32.dll", "DuplicateHandle", 7, (guest, argument) => {
    if (unsigned(argument[3]) !== 0) guest.memory.writeMemory(unsigned(argument[3]), 4, unsigned(argument[1]));
    return 1;
  });
  define("kernel32.dll", "CreateSemaphoreA", 4, (guest, argument) => guest.createSemaphore(argument[1] | 0, argument[2] | 0));
  define("kernel32.dll", "ReleaseSemaphore", 3, (guest, argument) => guest.releaseSemaphore(argument[0], argument[1] | 0, argument[2]));
  define("kernel32.dll", "WaitForMultipleObjects", 4, () => 0); // WAIT_OBJECT_0: bounded objects are already signaled
  define("kernel32.dll", "ResumeThread", 1, () => 0); // previous suspend count 0
  define("kernel32.dll", "SuspendThread", 1, () => 0);
  define("kernel32.dll", "GetThreadContext", 2, () => 1); // the one guest thread's context is the live register file
  define("kernel32.dll", "SetThreadContext", 2, () => 1);

  // --- USER32 and GDI32 (BPTK-011/012) --------------------------------------
  // Registration only: the rows are authored in lib/user.mjs and lib/gdi.mjs
  // and delegate to guest.user / guest.gdi.
  for (const entry of userExportTable) table.push(entry);
  for (const entry of gdiExportTable) table.push(entry);

  // --- SDL (lane W): the bounded SDL subset toward a first frame -------------
  // Registration only: the rows are authored in lib/sdl.mjs and delegate to
  // guest.sdl (the per-run SDL subsystem). A corpus x64 game that bundles SDL
  // (Dwarf Fortress / sdl.dll, Chocolate Doom / sdl2.dll) reaches these through
  // its IAT rather than stalling at the first SDL call.
  for (const entry of sdlExportTable) table.push(entry);

  return table;
}

export const win32HleExportTable = Object.freeze(defineExportTable());

export function listWin32HleExport() {
  return win32HleExportTable;
}

// ---------------------------------------------------------------------------
// The per-run guest. Created once per probe execution (or per conformance
// case); owns every piece of host-side guest state.
// ---------------------------------------------------------------------------

export function createWin32Hle(memory, layout, option = {}) {
  if (!layout || typeof layout.arena_base !== "number") throw hleFault("hle_layout_required", "The HLE requires one declared address layout");
  const executableName = typeof option.executable_name === "string" && option.executable_name !== "" ? option.executable_name : "game.exe";
  const clock = option.clock ?? null;
  if (clock === null) throw hleFault("hle_clock_required", "The HLE requires the one guest clock");

  const readAnsiString = createAnsiReader(memory);
  const readWideString = createWideReader(memory);
  const writeAnsiString = createAnsiWriter(memory);
  const writeWideString = createWideWriter(memory);
  const arena = createArena(memory, layout);

  // The USER32/GDI subsystem, one per run, owning the window manager and the
  // 2D surface. The message queue keys on the single declared guest thread id
  // until the thread core lands and this run keys it on the real registry.
  const user = createUserSubsystem({ thread_id: hleProfile.thread_id });
  const gdi = createGdiSubsystem();
  // The bounded SDL subsystem (lane W): a real semaphore/mutex/atomic surface,
  // a real framebuffer the compositor presents, and a bounded empty event
  // trace. It allocates framebuffer pixels from the same arena and reads the
  // one guest clock for SDL_GetTicks / SDL_Delay.
  const sdl = createSdlSubsystem({ memory, layout, allocate: (sizeByte) => arena.allocate(sizeByte), clock });
  // One offline-by-default Winsock per run: no consent, empty allowlist, so
  // every dial is refused with the ws2_32 access contract. The lifecycle,
  // handle table, and byte-order/address helpers are fully served; the dial
  // and transfer surface stays consent-gated.
  const net = createWinsock(createMediatedRelay(createTransportPolicy()));
  // One gamepad subsystem per run: every slot disconnected until a browser
  // Gamepad state is injected, so XInput honestly reports no controller.
  const gamepad = createGamepadSubsystem();

  let lastError = 0;
  let nextHandle = 0x00010000;
  function setLastError(value) {
    lastError = value & 0xffffffff;
  }
  const handleTable = new Map();
  const heapList = [];
  const virtualRegion = new Map();
  const tlsSlot = new Array(hleBound.tls_slot_count).fill(null);
  const flsSlot = new Array(hleBound.fls_slot_count).fill(null);
  const criticalSection = new Map();
  const environment = new Map();
  const trace = [];
  const traceHash = createHash("sha256");
  const outputChunk = [];
  let outputByteCount = 0;
  let callCount = 0;
  let comApartment = null;
  let comRefcount = 0;
  let defaultHeap = null;
  let environmentBlockAddress = 0;
  // The bounded virtual drive and registry hive (BPTK-015 slice): guest
  // memory only, never host storage.
  const virtualDrive = new Map();
  let driveTotalByte = 0;
  const registryHive = new Map();
  const registryOpenKey = new Map();
  const registryRoot = new Map([
    [0x80000000, "hkey_classes_root"],
    [0x80000001, "hkey_current_user"],
    [0x80000002, "hkey_local_machine"],
    [0x80000003, "hkey_users"],
  ]);
  const stdSlot = new Map();
  let threadHandle = 0;
  const eventTable = new Map();
  const findSession = new Map();
  // The Plink import-surface widening (BPTK-146): the file-mapping view table
  // keys a mapped guest address to its backing store so UnmapViewOfFile can
  // flush the view, and the console-mode override records a SetConsoleMode so
  // GetConsoleMode reflects it. Mutex, mapping, and pipe objects live in the
  // shared handle table under their own kind.
  const mapViewByAddress = new Map();
  const consoleModeOverride = new Map();
  let timerPeriod = 0;
  // The per-thread structured-exception machine (BPTK-053). The probe has no
  // mapped TEB yet — the thread lane owns that — so the chain runs on the
  // legacy in-object head until fs:[0] is wired; the vectored list and dispatch
  // order are identical either way.
  const sehThread = new SehThread();

  function normalizeDrivePath(name) {
    if (name === null || name.length === 0 || name.length > hleBound.string_byte) return null;
    const backslash = String.fromCharCode(92);
    if (name.includes(backslash + ".." + backslash) || name.endsWith(backslash + "..") || name.startsWith(backslash + backslash)) return null;
    if (!name.toLowerCase().startsWith("c:" + backslash)) return null;
    return name.replace(/[\\/]+/g, backslash).toLowerCase().replace(/[\\]+$/, "") || "c:";
  }

  const moduleTable = [
    { name: basename(executableName).toLowerCase(), handle: 0x00020001, is_main: true },
    { name: "kernel32.dll", handle: 0x00020002, is_main: false },
    { name: "ole32.dll", handle: 0x00020003, is_main: false },
    { name: "user32.dll", handle: 0x00020004, is_main: false },
    { name: "gdi32.dll", handle: 0x00020005, is_main: false },
    // ws2_32.dll is a served library (the BPTK-099 Winsock lifecycle slice), so a
    // guest that loads it by name at startup (PuTTY probes for a WinSock library
    // before it opens its window) gets a real module handle and can resolve its
    // exports through GetProcAddress; the socket layer stays offline-by-default.
    { name: "ws2_32.dll", handle: 0x00020006, is_main: false },
    // comctl32.dll is a served library (the common-control init slice), so a
    // GUI program (PuTTY) that loads it and resolves InitCommonControls before
    // opening its window gets a real module handle.
    { name: "comctl32.dll", handle: 0x00020007, is_main: false },
  ];
  const moduleByName = new Map(moduleTable.map((entry) => [entry.name, entry]));

  const thunkByExport = new Map();
  for (let index = 0; index < win32HleExportTable.length; index += 1) {
    const entry = win32HleExportTable[index];
    thunkByExport.set(`${entry.library}!${entry.symbol}`, layout.thunk_base + index * 4);
  }
  const exportByThunk = new Map([...thunkByExport.entries()].map(([key, address]) => [address, win32HleExportTable.find((entry) => `${entry.library}!${entry.symbol}` === key)]));

  function allocateHandle(kind, object) {
    if (handleTable.size >= hleBound.handle_count) throw hleFault("hle_handle_exhausted", "The HLE handle table is exhausted");
    const handle = nextHandle;
    nextHandle += 1;
    handleTable.set(handle, { kind, object });
    return handle;
  }

  // Internal strings live in the arena before any guest allocation runs, so
  // the addresses are deterministic for the same executable name.
  const mainModulePath = `${hleProfile.guest_root}\\${basename(executableName)}`;
  const commandLineAddressA = arena.allocate(mainModulePath.length + 3);
  writeAnsiString(commandLineAddressA, `"${mainModulePath}"`, mainModulePath.length + 3);
  const commandLineAddressW = arena.allocate((mainModulePath.length + 3) * 2);
  writeWideString(commandLineAddressW, `"${mainModulePath}"`, mainModulePath.length + 3);

  // The C runtime startup block (BPTK-031 Win64 CRT-init breadth). The ucrt
  // entry (mainCRTStartup/WinMainCRTStartup → __scrt_common_main_seh) reads the
  // program's argc/argv/envp and its errno/mode words through pointer-returning
  // CRT stubs (__p___argc, __p___argv, _errno, __p__commode …). Those pointers
  // must stay valid guest addresses for the whole run, so the block sits at a
  // fixed page near the top of the arena — deterministic per layout and clear of
  // the bump cursor that grows from the arena base, so no existing allocation
  // address shifts. One argument (the quoted program path) mirrors the command
  // line the same startup already reads; the environment and wide vectors are a
  // single null terminator (the bounded world exposes no inherited environment).
  const crtScratchBase = layout.arena_base + layout.arena_size_byte - 0x1000;
  const crt = (() => {
    let cursor = crtScratchBase;
    const take = (sizeByte) => { const at = cursor; cursor += (sizeByte + 15) & ~15; return at; };
    // A guest pointer is 8 bytes wide, but every mapped region sits below 2^32,
    // so a pointer is written as a low dword plus a zero high dword. Two 4-byte
    // writes (never one 8-byte write) keep the setup within the byte/word/dword
    // access set the i386 runtime memory model also enforces.
    const writePtr = (at, value) => { memory.writeMemory(at, 4, value >>> 0); memory.writeMemory(at + 4, 4, 0); };
    const argValue = mainModulePath; // argv[0] is the program path (unquoted)
    const argZero = take(argValue.length + 1);
    writeAnsiString(argZero, argValue, argValue.length + 1);
    const wargZero = take((argValue.length + 1) * 2);
    writeWideString(wargZero, argValue, argValue.length + 1);
    const argvArray = take(16); // [argv[0], NULL]
    writePtr(argvArray, argZero);
    writePtr(argvArray + 8, 0);
    const wargvArray = take(16);
    writePtr(wargvArray, wargZero);
    writePtr(wargvArray + 8, 0);
    const environArray = take(8); // [NULL]
    writePtr(environArray, 0);
    const wenvironArray = take(8);
    writePtr(wenvironArray, 0);
    const winmainLine = take(1); // the WinMain command tail is empty (no arguments)
    memory.writeMemory(winmainLine, 1, 0);
    // Pointer cells the __p_* accessors return the address of.
    const argcCell = take(4); memory.writeMemory(argcCell, 4, 1);
    const argvCell = take(8); writePtr(argvCell, argvArray);
    const wargvCell = take(8); writePtr(wargvCell, wargvArray);
    const environCell = take(8); writePtr(environCell, environArray);
    const wenvironCell = take(8); writePtr(wenvironCell, wenvironArray);
    const errnoCell = take(4); memory.writeMemory(errnoCell, 4, 0);
    const commodeCell = take(4); memory.writeMemory(commodeCell, 4, 0);
    const fmodeCell = take(4); memory.writeMemory(fmodeCell, 4, 0);
    return {
      base: crtScratchBase,
      argcCell, argvCell, wargvCell, environCell, wenvironCell,
      environArray, wenvironArray, argvArray, wargvArray,
      errnoCell, commodeCell, fmodeCell, winmainLine,
    };
  })();

  // The msvcrt C-runtime static block (BPTK-010 i386 CRT breadth). The FILE
  // table (_iob), the time-zone name vector (_tzname), the multibyte-max cell
  // (__mb_cur_max), and the fixed return buffers strerror/gmtime/setlocale/
  // localeconv hand back live at deterministic arena addresses, so a data
  // import resolves to real mapped memory and a pointer-returning CRT call is
  // reproducible per layout. The stream table maps a C fd to its backing HANDLE
  // (fd 0/1/2 are the standard streams); a _fdopen/_wfopen stream is a FILE the
  // arena hands out with its fd stored at FILE_FD_OFFSET.
  const crtRuntime = (() => {
    // A fixed page below the CRT startup block (which occupies the last 0x1000),
    // allocated with a local cursor so the arena bump cursor — and every
    // existing bump-allocated address — stays exactly where it was.
    let cursor = layout.arena_base + layout.arena_size_byte - 0x2000;
    const take = (sizeByte) => { const at = cursor; cursor += (sizeByte + 15) & ~15; return at; };
    const iobBase = take(FILE_STRUCT_BYTE * 3);
    memory.writeBlock(iobBase, Buffer.alloc(FILE_STRUCT_BYTE * 3));
    for (let index = 0; index < 3; index += 1) {
      memory.writeMemory(iobBase + index * FILE_STRUCT_BYTE + FILE_FD_OFFSET, 4, index);
    }
    const utcAddress = take(4);
    writeAnsiString(utcAddress, "UTC", 4);
    const tznameBase = take(8); // char* _tzname[2]
    memory.writeMemory(tznameBase, 4, utcAddress);
    memory.writeMemory(tznameBase + 4, 4, utcAddress);
    const mbCurMaxCell = take(4);
    memory.writeMemory(mbCurMaxCell, 4, 1);
    const strerrorBuf = take(64);
    const tmBuf = take(9 * 4);
    const localeName = take(2);
    writeAnsiString(localeName, "C", 2);
    const decimalPoint = take(2);
    writeAnsiString(decimalPoint, ".", 2);
    const emptyString = take(1);
    memory.writeMemory(emptyString, 1, 0);
    // struct lconv: decimal_point at offset 0 is "." in the "C" locale; every
    // other char* member points at the empty string, the numeric members hold
    // CHAR_MAX (127) meaning "unspecified".
    const lconv = take(56);
    memory.writeBlock(lconv, Buffer.alloc(56, 127));
    memory.writeMemory(lconv, 4, decimalPoint);
    for (let offset = 4; offset <= 24; offset += 4) memory.writeMemory(lconv + offset, 4, emptyString);
    return { iobBase, tznameBase, mbCurMaxCell, strerrorBuf, tmBuf, localeName, lconv, utcAddress, decimalPoint, emptyString };
  })();

  function createHeapObject(maximumByte) {
    if (heapList.length >= hleBound.heap_count) {
      setLastError(errorValue.not_enough_memory);
      return null;
    }
    const sizeByte = Math.min(Math.max(maximumByte === 0 ? 0x10000 : maximumByte, 0x10000), hleBound.arena_byte);
    const base = arena.allocate(sizeByte);
    const heap = { handle: 0, base, size_byte: sizeByte, allocation: new Map(), free: [{ address: base + 16, size_byte: sizeByte - 16 }] };
    heap.handle = allocateHandle("heap", heap);
    heapList.push(heap);
    return heap;
  }

  function firstFit(heap, sizeByte) {
    let index = 0;
    while (index < heap.free.length) {
      const block = heap.free[index];
      if (block.size_byte >= sizeByte) {
        const address = block.address;
        if (block.size_byte === sizeByte) heap.free.splice(index, 1);
        else {
          heap.free[index] = { address: address + sizeByte, size_byte: block.size_byte - sizeByte };
        }
        return address;
      }
      index += 1;
    }
    return 0;
  }

  function allocateBlock(heap, sizeByte) {
    const address = firstFit(heap, sizeByte);
    if (address === 0) return 0;
    heap.allocation.set(address, sizeByte);
    return address;
  }

  function releaseBlock(heap, address, sizeByte) {
    heap.allocation.delete(address);
    heap.free.push({ address, size_byte: sizeByte });
    heap.free.sort((a, b) => a.address - b.address);
    const merged = [];
    for (const block of heap.free) {
      const previous = merged[merged.length - 1];
      if (previous && previous.address + previous.size_byte === block.address) previous.size_byte += block.size_byte;
      else merged.push({ ...block });
    }
    heap.free = merged;
  }

  const guest = {
    memory,
    clock,
    user,
    gdi,
    sdl,
    net,
    gamepad,
    environment,
    commandLineAddressA,
    commandLineAddressW,
    filter_address: 0,
    error_mode: 0,
    com_apartment: null,
    com_refcount: 0,
    timer_period: 0,
    crt,
    crtRuntime,
    // The deterministic C rand() state (seed 1) and the C fd table the msvcrt
    // stdio surface owns; fd 3 upward wrap a virtual-drive HANDLE.
    rand_state: 1,
    crt_fd_table: new Map(),
    crt_fd_next: 3,
    app_type: 0,
    new_mode: 0,
    invalid_parameter_handler: 0,
    thread_local_atexit_dtor: 0,
    layout,
    readAnsiString,
    readWideString,
    writeAnsiString,
    writeWideString,

    getLastError: () => lastError,
    setLastError: (value) => {
      lastError = value & 0xffffffff;
    },

    isThunk: (address) => exportByThunk.has(unsigned(address)),
    exportAt: (address) => exportByThunk.get(unsigned(address)) ?? null,
    lookupExport: (library, symbol) => win32HleExportTable.find((entry) => entry.library === library && entry.symbol === symbol) ?? null,
    thunkOf: (library, symbol) => thunkByExport.get(`${library}!${symbol}`) ?? null,

    // One stdcall dispatch: runs the emulator, records the trace, and maps
    // the exit and exception signal into the structured stop the probe owns.
    invokeExport(entry, argument) {
      if (callCount >= hleBound.trace_count) throw hleFault("hle_trace_exhausted", `The HLE call trace exceeds ${hleBound.trace_count} entry`);
      let value;
      try {
        value = entry.emulate(guest, argument) >>> 0;
      } catch (error) {
        if (isHleSignal(error) && (error.signal === "hle_exit" || error.signal === "hle_guest_exception")) {
          // The call happened: the exit and exception signal carry the
          // guest-visible result, so the trace records the call before the
          // stop propagates.
          trace.push({ library: entry.library, symbol: entry.symbol, argument, value: (error.exit_code ?? error.exception_code ?? 0) >>> 0, last_error: lastError });
        }
        traceHash.update(Buffer.from(`${entry.library}!${entry.symbol}\0${JSON.stringify(argument)}\0signal:${error.signal ?? "unknown"}\0`, "utf8"));
        callCount += 1;
        throw error;
      }
      trace.push({ library: entry.library, symbol: entry.symbol, argument, value, last_error: lastError });
      traceHash.update(Buffer.from(`${entry.library}!${entry.symbol}\0${JSON.stringify(argument)}\0${value}\0${lastError}\0`, "utf8"));
      callCount += 1;
      return value;
    },
    raiseProcessExit,
    get trace_record() {
      return trace;
    },
    get environment_block_address() {
      return environmentBlockAddress;
    },
    get call_count() {
      return callCount;
    },
    get trace_sha256() {
      return traceHash.digest("hex");
    },
    takeOutput() {
      return Buffer.concat(outputChunk);
    },

    // --- module lookup --------------------------------------------------
    lookupModule(name) {
      if (name === null) return moduleTable[0].handle;
      return moduleByName.get(name.toLowerCase())?.handle ?? 0;
    },
    lookupModuleByAddress(address) {
      const imageBase = option.image_base ?? 0;
      const imageEnd = imageBase + (option.image_size_byte ?? 0);
      return imageEnd > imageBase && address >= imageBase && address < imageEnd ? moduleTable[0].handle : 0;
    },
    lookupProcedure(moduleHandle, nameAddress) {
      const module = moduleTable.find((entry) => entry.handle === unsigned(moduleHandle));
      if (module === undefined) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const ordinal = nameAddress <= 0xffff && nameAddress !== 0 ? nameAddress : null;
      if (ordinal !== null) {
        setLastError(errorValue.proc_not_found);
        return 0;
      }
      const name = readAnsiString(nameAddress);
      const thunk = thunkByExport.get(`${module.name}!${name}`) ?? null;
      if (thunk === null) {
        setLastError(errorValue.proc_not_found);
        return 0;
      }
      return thunk;
    },
    moduleName(moduleHandle) {
      const module = moduleTable.find((entry) => entry.handle === unsigned(moduleHandle));
      return module?.name ?? null;
    },
    modulePath(moduleHandle) {
      const module = moduleTable.find((entry) => entry.handle === unsigned(moduleHandle));
      if (module === undefined) return null;
      return module.is_main ? `${hleProfile.guest_root}\\${module.name}` : `${hleProfile.system_directory}\\${module.name}`;
    },
    currentThreadHandle() {
      if (threadHandle === 0) threadHandle = allocateHandle("std_thread", {});
      return threadHandle;
    },
    writeStartupInfo(address, isWide) {
      memory.writeBlock(address, Buffer.alloc(68));
      memory.writeMemory(address, 4, 68);
      memory.writeMemory(address + 48, 2, 0);
      memory.writeMemory(address + 56, 4, guest.standardHandle(stdHandle.input));
      memory.writeMemory(address + 60, 4, guest.standardHandle(stdHandle.output));
      memory.writeMemory(address + 64, 4, guest.standardHandle(stdHandle.error));
    },

    // --- heap -------------------------------------------------------------
    defaultHeapHandle() {
      if (defaultHeap === null) defaultHeap = createHeapObject(0) ?? 0;
      return defaultHeap?.handle ?? 0;
    },
    createHeap(maximumByte) {
      return createHeapObject(maximumByte)?.handle ?? 0;
    },
    heapFor(handle) {
      return heapList.find((heap) => heap.handle === unsigned(handle)) ?? null;
    },
    heapAllocate(handle, flag, sizeByte) {
      const heap = guest.heapFor(handle);
      if (heap === null) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      const size = Math.min(Math.max(sizeByte, 1), heap.size_byte);
      const address = allocateBlock(heap, size);
      if (address === 0) {
        setLastError(errorValue.not_enough_memory);
        return 0;
      }
      if ((flag & heapFlag.zero_memory) !== 0) memory.writeBlock(address, Buffer.alloc(size));
      return address;
    },
    heapReAllocate(handle, flag, address, sizeByte) {
      const heap = guest.heapFor(handle);
      const previousSize = heap?.allocation.get(unsigned(address));
      if (heap === null || previousSize === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      const size = Math.min(Math.max(sizeByte, 1), heap.size_byte);
      const next = allocateBlock(heap, size);
      if (next === 0) {
        setLastError(errorValue.not_enough_memory);
        return 0;
      }
      memory.writeBlock(next, memory.readBlock(address, Math.min(previousSize, size)));
      releaseBlock(heap, address, previousSize);
      if ((flag & heapFlag.zero_memory) !== 0 && size > previousSize) memory.writeBlock(next + previousSize, Buffer.alloc(size - previousSize));
      return next;
    },
    heapFree(handle, flag, address) {
      const heap = guest.heapFor(handle);
      const previousSize = heap?.allocation.get(unsigned(address));
      if (heap === null || previousSize === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      releaseBlock(heap, unsigned(address), previousSize);
      return 1;
    },
    heapSize(handle, flag, address) {
      const heap = guest.heapFor(handle);
      return heap?.allocation.get(unsigned(address)) ?? 0;
    },

    // --- virtual memory -----------------------------------------------------
    virtualAllocate(address, sizeByte, type, protect) {
      const wantCommit = (type & allocationType.commit) !== 0;
      const wantReserve = (type & allocationType.reserve) !== 0;
      if (type & ~(allocationType.commit | allocationType.reserve | allocationType.reset)) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      if (sizeByte === 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const roundedSize = Math.ceil(sizeByte / hleProfile.allocation_granularity_byte) * hleProfile.allocation_granularity_byte;
      const base = address === 0 ? guest.findVirtualHole(roundedSize) : unsigned(address);
      if (base === 0 || base < layout.virtual_base || base + roundedSize > layout.virtual_base + layout.virtual_size_byte) {
        setLastError(errorValue.invalid_address);
        return 0;
      }
      const existing = guest.virtualRegionAt(base, roundedSize);
      if (existing !== null && existing.state !== memState.free) {
        if (wantCommit && !wantReserve && existing.state === memState.reserve) {
          existing.state = memState.commit;
          existing.protect = protect;
          return existing.base;
        }
        setLastError(errorValue.invalid_address);
        return 0;
      }
      if (!wantReserve && !wantCommit) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      virtualRegion.set(base, { base, size_byte: roundedSize, state: wantCommit ? memState.commit : memState.reserve, protect, type: memType.private });
      return base;
    },
    findVirtualHole(sizeByte) {
      const ordered = [...virtualRegion.values()].sort((a, b) => a.base - b.base);
      let cursor = layout.virtual_base;
      for (const region of ordered) {
        if (region.base - cursor >= sizeByte) return cursor;
        cursor = Math.max(cursor, region.base + region.size_byte);
      }
      return cursor + sizeByte <= layout.virtual_base + layout.virtual_size_byte ? cursor : 0;
    },
    virtualRegionAt(address, sizeByte) {
      for (const region of virtualRegion.values()) {
        if (address < region.base + region.size_byte && region.base < address + sizeByte) return region;
      }
      return null;
    },
    virtualFree(address, sizeByte, type) {
      const region = virtualRegion.get(unsigned(address));
      if ((type & allocationType.release) !== 0) {
        if (region === undefined || sizeByte !== 0) {
          setLastError(errorValue.invalid_parameter);
          return 0;
        }
        virtualRegion.delete(unsigned(address));
        return 1;
      }
      if (type === 0x4000) {
        // MEM_DECOMMIT is served for the whole committed region only; a
        // partial decommit is an explicit unsupported parameter.
        if (region === undefined || region.state !== memState.commit) {
          setLastError(errorValue.invalid_address);
          return 0;
        }
        region.state = memState.reserve;
        return 1;
      }
      setLastError(errorValue.invalid_parameter);
      return 0;
    },
    virtualProtect(address, sizeByte, protect, oldProtectPointer) {
      const region = guest.virtualRegionAt(unsigned(address), Math.max(sizeByte, 1));
      if (region === undefined || region === null || region.state !== memState.commit) {
        setLastError(errorValue.invalid_address);
        return 0;
      }
      if (oldProtectPointer !== 0) memory.writeMemory(oldProtectPointer, 4, region.protect);
      region.protect = protect;
      return 1;
    },
    virtualQuery(address, buffer, lengthByte) {
      if (lengthByte < 28) return 0;
      const region = guest.virtualRegionAt(unsigned(address), 1);
      let entry;
      if (region === null) {
        entry = { base: layout.virtual_base, allocation_base: 0, allocation_protect: 0, size_byte: layout.virtual_size_byte, state: memState.free, protect: protection.noaccess, type: 0 };
      } else {
        entry = { base: region.base, allocation_base: region.base, allocation_protect: region.protect, size_byte: region.size_byte, state: region.state, protect: region.state === memState.commit ? region.protect : protection.noaccess, type: region.type };
      }
      memory.writeMemory(buffer, 4, entry.base);
      memory.writeMemory(buffer + 4, 4, entry.allocation_base);
      memory.writeMemory(buffer + 8, 4, entry.allocation_protect);
      memory.writeMemory(buffer + 12, 4, Math.min(entry.size_byte, 0x10000000));
      memory.writeMemory(buffer + 16, 4, entry.state);
      memory.writeMemory(buffer + 20, 4, entry.protect);
      memory.writeMemory(buffer + 24, 4, entry.type);
      return 28;
    },

    // --- critical section ------------------------------------------------------
    initializeCriticalSection(address, spinCount) {
      if (criticalSection.size >= hleBound.critical_section_count) throw hleFault("hle_resource_exhausted", "The critical-section table is exhausted");
      memory.writeBlock(address, Buffer.alloc(24));
      memory.writeMemory(address, 4, 0xffffffff);
      memory.writeMemory(address + 4, 4, 0);
      memory.writeMemory(address + 12, 4, 0);
      memory.writeMemory(address + 16, 4, 0);
      memory.writeMemory(address + 20, 4, spinCount);
      criticalSection.set(unsigned(address), { lock_count: -1, recursion_count: 0, owner: 0, spin_count: spinCount });
    },
    enterCriticalSection(address, isBlocking) {
      const section = criticalSection.get(unsigned(address));
      if (section === undefined) throw hleFault("hle_critical_section_invalid", `The critical section at 0x${unsigned(address).toString(16)} is not initialized`, { address: unsigned(address) });
      if (section.owner === hleProfile.thread_id) {
        section.recursion_count += 1;
        section.lock_count += 1;
        return true;
      }
      if (section.owner !== 0) return false;
      section.owner = hleProfile.thread_id;
      section.lock_count += 1;
      section.recursion_count = 1;
      return true;
    },
    leaveCriticalSection(address) {
      const section = criticalSection.get(unsigned(address));
      if (section === undefined || section.owner !== hleProfile.thread_id || section.recursion_count === 0) {
        throw hleFault("hle_critical_section_invalid", `The critical section at 0x${unsigned(address).toString(16)} is not held by the guest thread`, { address: unsigned(address) });
      }
      section.recursion_count -= 1;
      section.lock_count -= 1;
      if (section.recursion_count === 0) section.owner = 0;
    },
    deleteCriticalSection(address) {
      const section = criticalSection.get(unsigned(address));
      if (section === undefined) throw hleFault("hle_critical_section_invalid", `The critical section at 0x${unsigned(address).toString(16)} is not initialized`, { address: unsigned(address) });
      criticalSection.delete(unsigned(address));
      memory.writeBlock(address, Buffer.alloc(24));
    },

    // --- TLS ---------------------------------------------------------------------
    allocateTls() {
      const index = tlsSlot.findIndex((value) => value === null);
      if (index < 0) {
        setLastError(errorValue.not_enough_memory);
        return errorValue.tls_out_of_indexes;
      }
      tlsSlot[index] = { value: 0 };
      return index;
    },
    freeTls(index) {
      if (index >= hleBound.tls_slot_count || tlsSlot[index] === null) return false;
      tlsSlot[index] = null;
      return true;
    },
    readTls(index) {
      return index < hleBound.tls_slot_count && tlsSlot[index] !== null ? tlsSlot[index].value : 0;
    },
    writeTls(index, value) {
      if (index >= hleBound.tls_slot_count || tlsSlot[index] === null) {
        setLastError(errorValue.invalid_parameter);
        return false;
      }
      tlsSlot[index].value = unsigned(value);
      return true;
    },

    // --- FLS (fiber-local storage) ----------------------------------------------
    // The ucrt startup allocates one FLS index for its per-thread data before it
    // reaches main. The bounded world runs a single fiber, so an FLS index is a
    // value slot exactly like a TLS index; the optional destructor callback is
    // recorded but only ever fires on fiber/thread teardown, which the bounded
    // probe does not reach, so storing it is honest rather than a dropped hook.
    allocateFls(callback) {
      const index = flsSlot.findIndex((value) => value === null);
      if (index < 0) {
        setLastError(errorValue.not_enough_memory);
        return errorValue.fls_out_of_indexes;
      }
      flsSlot[index] = { value: 0, callback: unsigned(callback) };
      return index;
    },
    freeFls(index) {
      if (index >= hleBound.fls_slot_count || flsSlot[index] === null) {
        setLastError(errorValue.invalid_parameter);
        return false;
      }
      flsSlot[index] = null;
      return true;
    },
    readFls(index) {
      return index < hleBound.fls_slot_count && flsSlot[index] !== null ? flsSlot[index].value : 0;
    },
    writeFls(index, value) {
      if (index >= hleBound.fls_slot_count || flsSlot[index] === null) {
        setLastError(errorValue.invalid_parameter);
        return false;
      }
      flsSlot[index].value = unsigned(value);
      return true;
    },

    // --- structured exception dispatch (BPTK-053) -------------------------------
    // The per-thread SEH machine is reachable so a wired substrate can register
    // vectored handlers and push fs:[0] frames; RaiseException already routes
    // through it below.
    seh_thread: sehThread,
    // A guest vectored handler is opaque code on the legacy path, so the
    // registered entry records the handler address and returns the opaque
    // handle the guest later passes to remove; no guest code runs here.
    addVectoredHandler(isFirst, handlerAddress) {
      if (unsigned(handlerAddress) === 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      return sehThread.addVectored(isFirst !== 0, () => 0);
    },
    removeVectoredHandler(handle) {
      return sehThread.removeVectored(handle) ? 1 : 0;
    },
    // RaiseException routes through the chain. With no guest handler served the
    // dispatch terminates, which stays the structured guest_exception stop the
    // probe already reports.
    raiseStructuredException(code, flag, argument) {
      const trace = raiseException(sehThread, code, flag, argument);
      if (trace.is_handled || trace.is_continued) return 0;
      return raiseGuestException(unsigned(code));
    },

    // --- lock-free list over guest memory -------------------------------------------
    slistPush(head, entry) {
      const next = memory.readMemory(head, 4);
      const depth = memory.readMemory(head + 4, 2);
      const sequence = memory.readMemory(head + 6, 2);
      memory.writeMemory(entry, 4, next);
      memory.writeMemory(head, 4, unsigned(entry));
      memory.writeMemory(head + 4, 2, (depth + 1) & 0xffff);
      memory.writeMemory(head + 6, 2, (sequence + 1) & 0xffff);
      return next;
    },
    slistPop(head) {
      const first = memory.readMemory(head, 4);
      if (first === 0) return 0;
      const depth = memory.readMemory(head + 4, 2);
      const sequence = memory.readMemory(head + 6, 2);
      memory.writeMemory(head, 4, memory.readMemory(first, 4));
      memory.writeMemory(head + 4, 2, (depth - 1) & 0xffff);
      memory.writeMemory(head + 6, 2, (sequence + 1) & 0xffff);
      return first;
    },
    slistFlush(head) {
      const first = memory.readMemory(head, 4);
      memory.writeBlock(head, Buffer.alloc(8));
      return first;
    },
    slistDepth(head) {
      return memory.readMemory(head + 4, 2);
    },

    // --- standard handle and output ----------------------------------------------------
    standardHandle(which) {
      const key = which | 0;
      const stored = stdSlot.get(key);
      if (stored !== undefined) return stored;
      if (key === stdHandle.input) return stdSlot.set(key, allocateHandle("std_input", { is_input: true })).get(key);
      if (key === stdHandle.output) return stdSlot.set(key, allocateHandle("std_output", { is_input: false })).get(key);
      if (key === stdHandle.error) return stdSlot.set(key, allocateHandle("std_error", { is_input: false })).get(key);
      setLastError(errorValue.invalid_parameter);
      return 0xffffffff;
    },
    setStandardHandle(which, handle) {
      const key = which | 0;
      if (key !== stdHandle.input && key !== stdHandle.output && key !== stdHandle.error) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      stdSlot.set(key, unsigned(handle));
      return 1;
    },
    writeOutput(handle, bufferAddress, countByte, writtenPointer, isOverlapped) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      if (record.kind === "file") return guest.writeFileData(record, bufferAddress, countByte, writtenPointer, isOverlapped);
      if (record.object.is_input) {
        setLastError(errorValue.access_denied);
        return 0;
      }
      if (isOverlapped) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      if (countByte > hleBound.output_byte || outputByteCount + countByte > hleBound.output_byte) {
        throw hleFault("hle_output_bound_exceeded", `The captured output exceeds the declared ${hleBound.output_byte} byte bound`, { bound_byte: hleBound.output_byte });
      }
      const data = countByte === 0 ? Buffer.alloc(0) : memory.readBlock(bufferAddress, countByte);
      outputChunk.push(data);
      outputByteCount += countByte;
      if (writtenPointer !== 0) memory.writeMemory(writtenPointer, 4, countByte);
      return 1;
    },

    // --- virtual drive (BPTK-015 slice) -------------------------------------------------
    openFile(name, access, disposition) {
      if (disposition < fileDisposition.create_new || disposition > fileDisposition.truncate_existing) {
        setLastError(errorValue.invalid_parameter);
        return 0xffffffff;
      }
      const path = normalizeDrivePath(name);
      if (path === null) {
        setLastError(errorValue.invalid_parameter);
        return 0xffffffff;
      }
      if ([...handleTable.values()].filter((entry) => entry.kind === "file").length >= hleBound.file_open_count) {
        setLastError(errorValue.too_many_open_files);
        return 0xffffffff;
      }
      let file = virtualDrive.get(path);
      if (file === undefined) {
        if (disposition === fileDisposition.open_existing || disposition === fileDisposition.truncate_existing) {
          setLastError(errorValue.file_not_found);
          return 0xffffffff;
        }
        if (driveTotalByte + hleBound.file_size_byte > hleBound.file_total_byte) {
          setLastError(errorValue.disk_full);
          return 0xffffffff;
        }
        file = { data: Buffer.alloc(0) };
        virtualDrive.set(path, file);
        driveTotalByte += hleBound.file_size_byte;
      } else if (disposition === fileDisposition.create_new) {
        setLastError(errorValue.file_exists);
        return 0xffffffff;
      } else if (disposition === fileDisposition.truncate_existing || disposition === fileDisposition.create_always) {
        file.data = Buffer.alloc(0);
      }
      return allocateHandle("file", { path, data: file.data, drive: virtualDrive, position: 0, access: unsigned(access) });
    },
    readFile(handle, bufferAddress, countByte, writtenPointer, isOverlapped) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      if (record.kind !== "file") {
        // The probe console is declared output-only: no input service exists.
        setLastError(errorValue.access_denied);
        return 0;
      }
      if (isOverlapped || (record.object.access & fileAccess.generic_read) === 0) {
        setLastError(errorValue.access_denied);
        return 0;
      }
      const readByte = Math.min(Math.max(countByte, 0), Math.max(record.object.data.length - record.object.position, 0));
      if (readByte > 0) memory.writeBlock(bufferAddress, record.object.data.subarray(record.object.position, record.object.position + readByte));
      record.object.position += readByte;
      if (writtenPointer !== 0) memory.writeMemory(writtenPointer, 4, readByte);
      return 1;
    },
    writeFileData(record, bufferAddress, countByte, writtenPointer, isOverlapped) {
      if (isOverlapped || (record.object.access & fileAccess.generic_write) === 0) {
        setLastError(errorValue.access_denied);
        return 0;
      }
      if (countByte > hleBound.file_size_byte || record.object.position + countByte > hleBound.file_size_byte) {
        setLastError(errorValue.disk_full);
        return 0;
      }
      const data = countByte === 0 ? Buffer.alloc(0) : memory.readBlock(bufferAddress, countByte);
      const end = record.object.position + countByte;
      if (end > record.object.data.length) record.object.data = Buffer.concat([record.object.data, Buffer.alloc(end - record.object.data.length)]);
      data.copy(record.object.data, record.object.position);
      const driveFile = record.object.drive.get(record.object.path);
      if (driveFile !== undefined) driveFile.data = record.object.data;
      record.object.position = end;
      if (writtenPointer !== 0) memory.writeMemory(writtenPointer, 4, countByte);
      return 1;
    },
    seekFile(handle, distanceLow, distanceHigh, newPointer, origin) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind !== "file") {
        setLastError(errorValue.invalid_handle);
        return 0xffffffff;
      }
      if (origin < fileMethod.begin || origin > fileMethod.end) {
        setLastError(errorValue.invalid_parameter);
        return 0xffffffff;
      }
      const distance = BigInt.asIntN(64, (BigInt(unsigned(distanceHigh)) << 32n) | BigInt(unsigned(distanceLow)));
      const base = origin === fileMethod.begin ? 0n : origin === fileMethod.current ? BigInt(record.object.position) : BigInt(record.object.data.length);
      const next = base + distance;
      if (next < 0n) {
        setLastError(errorValue.negative_seek);
        return 0xffffffff;
      }
      record.object.position = Number(next);
      if (newPointer !== 0) {
        memory.writeMemory(newPointer, 4, Number(next & 0xffffffffn));
        memory.writeMemory(newPointer + 4, 4, Number(next >> 32n & 0xffffffffn));
      }
      return 0;
    },
    truncateFile(handle) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind !== "file") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      record.object.data = record.object.data.subarray(0, record.object.position);
      const driveFile = record.object.drive.get(record.object.path);
      if (driveFile !== undefined) driveFile.data = record.object.data;
      return 1;
    },
    // --- msvcrt C runtime (BPTK-010 i386 CRT breadth) -----------------------
    // errno lives in the fixed CRT cell; every CRT failure records it there.
    crtErrno(value) {
      if (value !== undefined) memory.writeMemory(crt.errnoCell, 4, unsigned(value));
      return memory.readMemory(crt.errnoCell, 4);
    },
    // malloc/calloc/realloc/free run over the one process default heap, so the
    // block bytes are real and a later HeapSize or free finds them.
    crtMalloc(sizeByte) {
      return guest.heapAllocate(guest.defaultHeapHandle(), 0, Math.max(unsigned(sizeByte), 1));
    },
    crtCalloc(count, sizeByte) {
      const total = unsigned(count) * unsigned(sizeByte);
      return guest.heapAllocate(guest.defaultHeapHandle(), heapFlag.zero_memory, Math.max(total, 1));
    },
    crtRealloc(address, sizeByte) {
      if (unsigned(address) === 0) return guest.crtMalloc(sizeByte);
      if (unsigned(sizeByte) === 0) { guest.crtFree(address); return 0; }
      return guest.heapReAllocate(guest.defaultHeapHandle(), 0, unsigned(address), unsigned(sizeByte));
    },
    crtFree(address) {
      if (unsigned(address) !== 0) guest.heapFree(guest.defaultHeapHandle(), 0, unsigned(address));
      return 0;
    },
    // _msize returns the usable byte count of a live block over the same heap,
    // so it agrees with the size malloc/realloc actually reserved.
    crtMsize(address) {
      if (unsigned(address) === 0) return 0;
      return guest.heapSize(guest.defaultHeapHandle(), 0, unsigned(address));
    },
    // _recalloc resizes a block and zero-fills the grown tail, over the one heap.
    crtRecalloc(address, count, sizeByte) {
      const total = unsigned(count) * unsigned(sizeByte);
      if (unsigned(address) === 0) return guest.heapAllocate(guest.defaultHeapHandle(), heapFlag.zero_memory, Math.max(total, 1));
      if (total === 0) { guest.crtFree(address); return 0; }
      return guest.heapReAllocate(guest.defaultHeapHandle(), heapFlag.zero_memory, unsigned(address), total);
    },
    // A FILE* resolves to its C fd: a pointer inside the _iob array is the
    // standard-stream index; any other FILE carries its fd at FILE_FD_OFFSET.
    crtStreamFd(filePointer) {
      const value = unsigned(filePointer);
      const base = crtRuntime.iobBase;
      if (value >= base && value < base + FILE_STRUCT_BYTE * 3) return (value - base) / FILE_STRUCT_BYTE | 0;
      return signed32(memory.readMemory(value + FILE_FD_OFFSET, 4));
    },
    // Route count byte to a C fd: 1/2 are the captured console, a table fd is a
    // virtual-drive file, and stdin/absent fd refuse with EBADF.
    crtWriteFd(fd, buffer) {
      if (fd === 1 || fd === 2) {
        if (buffer.length > hleBound.output_byte || outputByteCount + buffer.length > hleBound.output_byte) {
          throw hleFault("hle_output_bound_exceeded", `The captured output exceeds the declared ${hleBound.output_byte} byte bound`, { bound_byte: hleBound.output_byte });
        }
        if (buffer.length > 0) { outputChunk.push(Buffer.from(buffer)); outputByteCount += buffer.length; }
        return buffer.length;
      }
      const record = fd >= 3 ? handleTable.get(unsigned(guest.crt_fd_table.get(fd) ?? 0)) : undefined;
      if (record === undefined || record.kind !== "file") { guest.crtErrno(crtErrnoValue.ebadf); return -1; }
      const end = record.object.position + buffer.length;
      if (buffer.length > hleBound.file_size_byte || end > hleBound.file_size_byte) { guest.crtErrno(crtErrnoValue.erange); return -1; }
      if (end > record.object.data.length) record.object.data = Buffer.concat([record.object.data, Buffer.alloc(end - record.object.data.length)]);
      Buffer.from(buffer).copy(record.object.data, record.object.position);
      const driveFile = record.object.drive.get(record.object.path);
      if (driveFile !== undefined) driveFile.data = record.object.data;
      record.object.position = end;
      return buffer.length;
    },
    // Emit a byte stream to a FILE* (stdout/stderr → console, file → drive).
    crtWriteStream(filePointer, buffer) {
      return guest.crtWriteFd(guest.crtStreamFd(filePointer), buffer);
    },
    // _open: translate the C oflag to a Win32 access/disposition and open the
    // virtual-drive file, then bind a fresh fd to the HANDLE.
    crtOpen(pathAddress, oflag, isWide) {
      const path = isWide ? readWideString(pathAddress) : readAnsiString(pathAddress);
      if (path === null) { guest.crtErrno(crtErrnoValue.einval); return -1; }
      const writing = (oflag & 0x0003) !== 0 || (oflag & 0x0100) !== 0; // _O_WRONLY/_O_RDWR/_O_CREAT
      const access = (writing ? fileAccess.generic_write : 0) | fileAccess.generic_read;
      const disposition = (oflag & 0x0200) !== 0 // _O_CREAT|_O_TRUNC
        ? ((oflag & 0x0400) !== 0 ? fileDisposition.truncate_existing : fileDisposition.create_always)
        : (oflag & 0x0100) !== 0 ? fileDisposition.open_always : fileDisposition.open_existing;
      const handle = guest.openFile(path, access, disposition);
      if (unsigned(handle) === 0xffffffff) {
        guest.crtErrno(guest.getLastError() === errorValue.file_not_found ? crtErrnoValue.enoent : crtErrnoValue.einval);
        return -1;
      }
      const fd = guest.crt_fd_next;
      guest.crt_fd_next += 1;
      guest.crt_fd_table.set(fd, unsigned(handle));
      return fd;
    },
    crtClose(fd) {
      if (fd === 0 || fd === 1 || fd === 2) return 0;
      const handle = guest.crt_fd_table.get(fd);
      if (handle === undefined) { guest.crtErrno(crtErrnoValue.ebadf); return -1; }
      guest.closeHandle(handle);
      guest.crt_fd_table.delete(fd);
      return 0;
    },
    crtOsHandle(fd) {
      if (fd === 0) return unsigned(guest.standardHandle(stdHandle.input));
      if (fd === 1) return unsigned(guest.standardHandle(stdHandle.output));
      if (fd === 2) return unsigned(guest.standardHandle(stdHandle.error));
      const handle = guest.crt_fd_table.get(fd);
      if (handle === undefined) { guest.crtErrno(crtErrnoValue.ebadf); return 0xffffffff; }
      return unsigned(handle);
    },
    // Wrap a C fd in a FILE the arena hands out, storing the fd for later
    // _fileno / stdio routing. mode is advisory in the bounded world.
    crtFdopen(fd) {
      if (fd < 0) return 0;
      const file = arena.allocate(FILE_STRUCT_BYTE);
      memory.writeBlock(file, Buffer.alloc(FILE_STRUCT_BYTE));
      memory.writeMemory(file + FILE_FD_OFFSET, 4, unsigned(fd));
      return file;
    },
    // The size in byte of a virtual-drive file, or null when it does not exist.
    virtualFileSize(name) {
      const path = normalizeDrivePath(name);
      if (path === null) return null;
      const file = virtualDrive.get(path);
      return file === undefined ? null : file.data.length;
    },
    // A counted semaphore handle (bounded single-thread synchronization).
    createSemaphore(initialCount, maximumCount) {
      const max = maximumCount > 0 ? maximumCount : 1;
      const initial = Math.min(Math.max(initialCount, 0), max);
      return allocateHandle("semaphore", { count: initial, max });
    },
    releaseSemaphore(handle, releaseCount, previousPointer) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind !== "semaphore") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      const previous = record.object.count;
      if (releaseCount <= 0 || previous + releaseCount > record.object.max) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      record.object.count = previous + releaseCount;
      if (unsigned(previousPointer) !== 0) memory.writeMemory(unsigned(previousPointer), 4, previous);
      return 1;
    },
    closeHandle(handle) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind === "registry") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      if (record.kind === "find") findSession.delete(unsigned(handle));
      handleTable.delete(unsigned(handle));
      return 1;
    },
    handleRecord(handle) {
      return handleTable.get(unsigned(handle));
    },
    fileType(handle) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind === "registry") {
        setLastError(errorValue.invalid_handle);
        return fileType.unknown;
      }
      return record.kind === "file" ? fileType.disk : fileType.char;
    },

    // --- console mode (output-only console, declared) --------------------------------------
    consoleMode(handle) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || (record.kind !== "std_output" && record.kind !== "std_error" && record.kind !== "std_input")) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      const override = consoleModeOverride.get(unsigned(handle));
      if (override !== undefined) return override;
      return record.kind === "std_input" ? consoleMode.input : consoleMode.output;
    },
    readConsole(handle) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined) {
        setLastError(errorValue.invalid_handle);
      } else {
        setLastError(errorValue.access_denied);
      }
      return 0;
    },

    // --- registry (BPTK-015 slice) -----------------------------------------------------------
    registryOpen(rootHandle, subKeyPath, resultPointer, isCreate) {
      const rootName = registryRoot.get(unsigned(rootHandle));
      if (rootName === undefined) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      if (registryOpenKey.size >= hleBound.registry_key_count) {
        setLastError(errorValue.too_many_open_files);
        return errorValue.too_many_open_files;
      }
      let path = rootName;
      if (subKeyPath !== null && subKeyPath.length > 0) {
        const backslash = String.fromCharCode(92);
        const segment = subKeyPath.split(backslash).map((part) => part.trim().toLowerCase()).filter((part) => part.length > 0);
        for (let index = 0; index < segment.length; index += 1) {
          const next = path + backslash + segment[index];
          if (!registryHive.has(next)) {
            if (!isCreate || registryHive.size >= hleBound.registry_key_count) {
              const failure = index === segment.length - 1 ? errorValue.file_not_found : errorValue.path_not_found;
              setLastError(failure);
              return failure;
            }
            registryHive.set(next, { values: new Map() });
          }
          path = next;
        }
      }
      const handle = allocateHandle("registry", { path });
      registryOpenKey.set(handle, path);
      if (resultPointer !== 0) memory.writeMemory(resultPointer, 4, handle);
      return errorValue.success;
    },
    registryQuery(handle, name, typePointer, dataPointer, lengthPointer) {
      const path = registryOpenKey.get(unsigned(handle));
      const key = path === undefined ? undefined : registryHive.get(path);
      if (path === undefined || key === undefined) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      const value = key.values.get(name ?? "");
      if (value === undefined) {
        setLastError(errorValue.file_not_found);
        return errorValue.file_not_found;
      }
      const declared = lengthPointer === 0 ? 0 : memory.readMemory(lengthPointer, 4);
      if (dataPointer !== 0 && declared < value.data.length) {
        if (lengthPointer !== 0) memory.writeMemory(lengthPointer, 4, value.data.length);
        setLastError(errorValue.more_data);
        return errorValue.more_data;
      }
      if (dataPointer !== 0 && value.data.length > 0) memory.writeBlock(dataPointer, value.data);
      if (typePointer !== 0) memory.writeMemory(typePointer, 4, value.type);
      if (lengthPointer !== 0) memory.writeMemory(lengthPointer, 4, value.data.length);
      return errorValue.success;
    },
    registrySet(handle, name, type, dataPointer, lengthByte) {
      const path = registryOpenKey.get(unsigned(handle));
      const key = path === undefined ? undefined : registryHive.get(path);
      if (path === undefined || key === undefined) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      if (lengthByte > hleBound.registry_value_byte || (key.values.size >= hleBound.registry_value_count && !key.values.has(name ?? ""))) {
        setLastError(errorValue.not_enough_memory);
        return errorValue.not_enough_memory;
      }
      const data = lengthByte === 0 ? Buffer.alloc(0) : memory.readBlock(dataPointer, lengthByte);
      key.values.set(name ?? "", { type: unsigned(type), data });
      return errorValue.success;
    },
    registryClose(handle) {
      if (!registryOpenKey.has(unsigned(handle))) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      registryOpenKey.delete(unsigned(handle));
      handleTable.delete(unsigned(handle));
      return errorValue.success;
    },
    // RegCreateKeyEx: open-or-create the key and report whether the final
    // segment was created new (1) or opened existing (2) through the
    // disposition pointer, per the Win32 contract.
    registryCreate(rootHandle, subKeyPath, resultPointer, dispositionPointer) {
      const rootName = registryRoot.get(unsigned(rootHandle));
      if (rootName === undefined) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      let path = rootName;
      let created = false;
      if (subKeyPath !== null && subKeyPath.length > 0) {
        const backslash = String.fromCharCode(92);
        const segment = subKeyPath.split(backslash).map((part) => part.trim().toLowerCase()).filter((part) => part.length > 0);
        for (const part of segment) {
          const next = path + backslash + part;
          if (!registryHive.has(next)) {
            if (registryHive.size >= hleBound.registry_key_count) {
              setLastError(errorValue.not_enough_memory);
              return errorValue.not_enough_memory;
            }
            registryHive.set(next, { values: new Map() });
            created = true;
          } else {
            created = false;
          }
          path = next;
        }
      }
      if (registryOpenKey.size >= hleBound.registry_key_count) {
        setLastError(errorValue.too_many_open_files);
        return errorValue.too_many_open_files;
      }
      const handle = allocateHandle("registry", { path });
      registryOpenKey.set(handle, path);
      if (resultPointer !== 0) memory.writeMemory(resultPointer, 4, handle);
      if (dispositionPointer !== 0) memory.writeMemory(dispositionPointer, 4, created ? 1 : 2);
      return errorValue.success;
    },
    registryDeleteValue(handle, name) {
      const path = registryOpenKey.get(unsigned(handle));
      const key = path === undefined ? undefined : registryHive.get(path);
      if (path === undefined || key === undefined) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      if (!key.values.delete(name ?? "")) {
        setLastError(errorValue.file_not_found);
        return errorValue.file_not_found;
      }
      return errorValue.success;
    },
    registryDeleteKey(rootHandle, subKeyPath) {
      const rootName = registryRoot.get(unsigned(rootHandle));
      if (rootName === undefined || subKeyPath === null || subKeyPath.length === 0) {
        setLastError(errorValue.invalid_parameter);
        return errorValue.invalid_parameter;
      }
      const backslash = String.fromCharCode(92);
      const segment = subKeyPath.split(backslash).map((part) => part.trim().toLowerCase()).filter((part) => part.length > 0);
      const path = [rootName, ...segment].join(backslash);
      if (!registryHive.has(path)) {
        setLastError(errorValue.file_not_found);
        return errorValue.file_not_found;
      }
      // Win32 refuses to delete a key that still has subkeys.
      const hasChild = [...registryHive.keys()].some((candidate) => candidate.startsWith(path + backslash));
      if (hasChild) {
        setLastError(errorValue.access_denied);
        return errorValue.access_denied;
      }
      registryHive.delete(path);
      return errorValue.success;
    },
    registryFlush(handle) {
      if (!registryOpenKey.has(unsigned(handle))) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      return errorValue.success;
    },

    // --- synchronization objects (BPTK-010 slice) -----------------------------------------
    createEvent(isManualReset, isInitiallySignaled, namePointer) {
      if (eventTable.size >= hleBound.event_count) {
        setLastError(errorValue.not_enough_memory);
        return 0;
      }
      const name = namePointer === 0 ? null : guest.readWideString(namePointer);
      if (name !== null) {
        const existing = eventTable.get("named:" + name);
        if (existing !== undefined) return existing.handle;
      }
      const event = { is_manual_reset: isManualReset, is_signaled: isInitiallySignaled };
      const handle = allocateHandle("event", event);
      eventTable.set(handle, event);
      if (name !== null) eventTable.set("named:" + name, { handle });
      return handle;
    },
    signalEvent(handle, isSignaled) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind !== "event") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      record.object.is_signaled = isSignaled;
      return 1;
    },
    waitForSingle(handle, millisecond, isAlertable) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind !== "event") {
        setLastError(errorValue.invalid_handle);
        return 0xffffffff;
      }
      if (record.object.is_signaled) {
        if (!record.object.is_manual_reset) record.object.is_signaled = false;
        return 0;
      }
      const timeout = unsigned(millisecond);
      if (timeout === 0xffffffff) {
        throw hleFault("hle_wait_deadlock", "The event never signals in the single-thread world, so an infinite wait cannot complete", { handle: unsigned(handle) });
      }
      clock.advanceVirtualMs(timeout);
      return 0x102;
    },

    // --- file enumeration over the virtual drive (BPTK-015 slice) ---------------------------
    findFirst(patternAddress, infoLevel, findDataPointer, searchOperation, flags) {
      if (infoLevel !== 0 || searchOperation !== 0 || (flags & ~0x4) !== 0) {
        setLastError(errorValue.invalid_parameter);
        return 0xffffffff;
      }
      const pattern = guest.readAnsiString(patternAddress);
      if (pattern === null) {
        setLastError(errorValue.invalid_parameter);
        return 0xffffffff;
      }
      const matches = guest.driveMatches(pattern);
      if (matches.length === 0) {
        const normalized = normalizeDrivePath(pattern);
        const directory = normalized === null ? null : normalized.slice(0, normalized.lastIndexOf("\\") + 1);
        const directoryExists = directory === "c:" || directory === null
          ? false
          : [...virtualDrive.keys()].some((path) => path.startsWith(directory));
        setLastError(directoryExists || normalized === null ? errorValue.file_not_found : errorValue.path_not_found);
        return 0xffffffff;
      }
      const handle = allocateHandle("find", { matches, cursor: 0 });
      findSession.set(handle, handleTable.get(handle).object);
      guest.writeFindData(findDataPointer, matches[0]);
      handleTable.get(handle).object.cursor = 1;
      return handle;
    },
    findNext(handle, findDataPointer) {
      const session = findSession.get(unsigned(handle));
      if (session === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      if (session.cursor >= session.matches.length) {
        setLastError(errorValue.file_not_found);
        return 0;
      }
      guest.writeFindData(findDataPointer, session.matches[session.cursor]);
      session.cursor += 1;
      return 1;
    },
    driveMatches(pattern) {
      const normalized = normalizeDrivePath(pattern);
      if (normalized === null) return [];
      const directory = normalized.slice(0, normalized.lastIndexOf("\\") + 1);
      const wildcard = normalized.slice(normalized.lastIndexOf("\\") + 1);
      if (wildcard !== "*") {
        // Only the trailing-star form is declared; a plain file name matches itself.
        if (virtualDrive.has(normalized)) return [{ name: wildcard, size_byte: virtualDrive.get(normalized).data.length }];
        return [];
      }
      const match = [];
      for (const [path, file] of virtualDrive) {
        if (path.startsWith(directory)) match.push({ name: path.slice(directory.length), size_byte: file.data.length });
      }
      return match.sort((a, b) => a.name < b.name ? -1 : 1);
    },
    writeFindData(pointer, entry) {
      memory.writeBlock(pointer, Buffer.alloc(320));
      memory.writeMemory(pointer, 4, 0x20);
      memory.writeMemory(pointer + 40, 4, entry.size_byte & 0xffffffff);
      memory.writeMemory(pointer + 44, 4, 0);
      guest.writeAnsiString(pointer + 44, entry.name, 260);
    },

    // --- module loading (BPTK-010 slice) -------------------------------------------------
    loadLibrary(name, flags) {
      if (name === null) return moduleTable[0].handle;
      // A guest loads a system DLL by its full path (PuTTY builds
      // "C:\WINDOWS\System32\ws2_32.dll" from GetSystemDirectoryA), so match on
      // the Windows basename — the segment after the last path separator.
      const leaf = name.split(/[\\/]/).pop().toLowerCase();
      const known = moduleByName.get(leaf);
      if (known === undefined || known.is_main) {
        // The declared environment has no file system: a DLL outside the
        // known emulated set cannot load.
        setLastError(errorValue.mod_not_found);
        return 0;
      }
      if (flags & ~0x8) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      known.refcount = (known.refcount ?? 0) + 1;
      return known.handle;
    },
    freeLibrary(moduleHandle) {
      const known = moduleTable.find((entry) => entry.handle === unsigned(moduleHandle));
      if (known === undefined || known.is_main) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      known.refcount = Math.max((known.refcount ?? 1) - 1, 0);
      return 1;
    },
    // IsBadReadPtr probes the range the way the real API does: readable
    // memory answers 0, any fault answers 1.
    probeReadable(address, lengthByte) {
      if (lengthByte === 0) return 0;
      try {
        guest.memory.readMemory(unsigned(address), 1);
        guest.memory.readMemory(unsigned(address) + lengthByte - 1, 1);
      } catch {
        return 1;
      }
      return 0;
    },
    threadTimes(handle, creationPointer, exitPointer, kernelPointer, userPointer) {
      const record = handleTable.get(unsigned(handle));
      if (unsigned(handle) !== 0xfffffffe && (record === undefined || record.kind !== "std_thread")) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      const writeTime = (pointer, fileTime) => {
        if (pointer === 0) return;
        memory.writeMemory(pointer, 4, Number(BigInt(fileTime) & 0xffffffffn));
        memory.writeMemory(pointer + 4, 4, Number(BigInt(fileTime) >> 32n & 0xffffffffn));
      };
      const now = BigInt(hleProfile.file_time_base) + BigInt(Math.floor(clock.elapsedGuestMs())) * 10000n;
      writeTime(creationPointer, hleProfile.file_time_base);
      writeTime(exitPointer, 0);
      writeTime(kernelPointer, 0);
      writeTime(userPointer, now);
      return 1;
    },

    // --- Plink import-surface widening (BPTK-146) --------------------------------------------
    // Every helper below runs on the same bounded guest state as its wide or
    // heap sibling; nothing reaches host storage, a host device, or a real
    // second thread. The process, thread, serial, and named-pipe surfaces are
    // served with their honest refusal because the confined single-thread probe
    // cannot provide them, and each names the reason in its last error.
    processTimes(handle, creationPointer, exitPointer, kernelPointer, userPointer) {
      if (unsigned(handle) !== 0xffffffff) {
        const record = handleTable.get(unsigned(handle));
        if (record === undefined) {
          setLastError(errorValue.invalid_handle);
          return 0;
        }
      }
      const writeTime = (pointer, fileTime) => {
        if (pointer === 0) return;
        memory.writeMemory(pointer, 4, Number(BigInt(fileTime) & 0xffffffffn));
        memory.writeMemory(pointer + 4, 4, Number(BigInt(fileTime) >> 32n & 0xffffffffn));
      };
      const now = BigInt(hleProfile.file_time_base) + BigInt(Math.floor(clock.elapsedGuestMs())) * 10000n;
      writeTime(creationPointer, hleProfile.file_time_base);
      writeTime(exitPointer, 0);
      writeTime(kernelPointer, 0);
      writeTime(userPointer, now);
      return 1;
    },
    deleteFile(name) {
      const path = normalizeDrivePath(name);
      if (path === null) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      if (!virtualDrive.has(path)) {
        setLastError(errorValue.file_not_found);
        return 0;
      }
      virtualDrive.delete(path);
      driveTotalByte = Math.max(driveTotalByte - hleBound.file_size_byte, 0);
      return 1;
    },
    // GetFileAttributesExA GetFileExInfoStandard: WIN32_FILE_ATTRIBUTE_DATA is
    // 36 byte — dwFileAttributes +0, ftCreationTime +4, ftLastAccessTime +12,
    // ftLastWriteTime +20, nFileSizeHigh +28, nFileSizeLow +32.
    fileAttributesEx(name, infoLevel, outPointer) {
      if (infoLevel !== 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const path = normalizeDrivePath(name);
      const attribute = path === null ? null : path === "c:" ? { flag: 0x10, size_byte: 0 } : virtualDrive.has(path) ? { flag: 0x80, size_byte: virtualDrive.get(path).data.length } : null;
      if (attribute === null) {
        setLastError(errorValue.file_not_found);
        return 0;
      }
      memory.writeBlock(outPointer, Buffer.alloc(36));
      memory.writeMemory(outPointer, 4, attribute.flag);
      const created = BigInt(hleProfile.file_time_base);
      for (const offset of [4, 12, 20]) {
        memory.writeMemory(outPointer + offset, 4, Number(created & 0xffffffffn));
        memory.writeMemory(outPointer + offset + 4, 4, Number(created >> 32n & 0xffffffffn));
      }
      memory.writeMemory(outPointer + 28, 4, 0);
      memory.writeMemory(outPointer + 32, 4, attribute.size_byte & 0xffffffff);
      return 1;
    },
    createMutex(isInitialOwner, namePointer, isWide) {
      const name = namePointer === 0 ? null : (isWide ? guest.readWideString(namePointer) : guest.readAnsiString(namePointer));
      if (name !== null) {
        for (const [handle, record] of handleTable) {
          if (record.kind === "mutex" && record.object.name === name) {
            setLastError(errorValue.file_exists); // ERROR_ALREADY_EXISTS
            return handle;
          }
        }
      }
      return allocateHandle("mutex", { name, owner_count: isInitialOwner ? 1 : 0 });
    },
    releaseMutex(handle) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind !== "mutex") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      if (record.object.owner_count === 0) {
        setLastError(288); // ERROR_NOT_OWNER
        return 0;
      }
      record.object.owner_count -= 1;
      return 1;
    },
    createFileMapping(fileHandle, sizeLow, namePointer, isWide) {
      const name = namePointer === 0 ? null : (isWide ? guest.readWideString(namePointer) : guest.readAnsiString(namePointer));
      if (name !== null) {
        for (const [handle, record] of handleTable) {
          if (record.kind === "mapping" && record.object.name === name) {
            setLastError(errorValue.file_exists);
            return handle;
          }
        }
      }
      const fh = unsigned(fileHandle);
      let backing;
      if (fh === 0xffffffff) {
        if (sizeLow <= 0) {
          setLastError(errorValue.invalid_parameter);
          return 0;
        }
        backing = Buffer.alloc(Math.min(sizeLow, hleBound.file_size_byte));
      } else {
        const record = handleTable.get(fh);
        if (record === undefined || record.kind !== "file") {
          setLastError(errorValue.invalid_handle);
          return 0;
        }
        const size = sizeLow === 0 ? record.object.data.length : Math.min(sizeLow, hleBound.file_size_byte);
        backing = Buffer.alloc(size);
        record.object.data.copy(backing, 0, 0, Math.min(size, record.object.data.length));
      }
      return allocateHandle("mapping", { name, backing });
    },
    mapViewOfFile(mappingHandle, byteCount) {
      const record = handleTable.get(unsigned(mappingHandle));
      if (record === undefined || record.kind !== "mapping") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      const size = byteCount === 0 ? record.object.backing.length : Math.min(byteCount, record.object.backing.length);
      if (size <= 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const address = arena.allocate(size);
      memory.writeBlock(address, record.object.backing.subarray(0, size));
      mapViewByAddress.set(address, { mapping: record.object, size });
      return address;
    },
    unmapViewOfFile(address) {
      const view = mapViewByAddress.get(unsigned(address));
      if (view === undefined) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      view.mapping.backing = Buffer.from(memory.readBlock(unsigned(address), view.size));
      mapViewByAddress.delete(unsigned(address));
      return 1;
    },
    createPipe(readPointer, writePointer, sizeByte) {
      const shared = { data: Buffer.alloc(0), cap: sizeByte > 0 ? Math.min(sizeByte, hleBound.file_size_byte) : 0x1000 };
      const readHandle = allocateHandle("pipe_read", { shared });
      const writeHandle = allocateHandle("pipe_write", { shared });
      if (readPointer !== 0) memory.writeMemory(readPointer, 4, readHandle);
      if (writePointer !== 0) memory.writeMemory(writePointer, 4, writeHandle);
      return 1;
    },
    setConsoleMode(handle, mode) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || (record.kind !== "std_output" && record.kind !== "std_error" && record.kind !== "std_input")) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      consoleModeOverride.set(unsigned(handle), unsigned(mode));
      return 1;
    },
    setHandleInformation(handle, mask, flag) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      // The confined probe never inherits a handle to a child and never spawns
      // one, so the inherit and protect bits have no observable effect; the call
      // validates the handle and records nothing.
      record.object.handle_flag = (record.object.handle_flag ?? 0) & ~mask | (flag & mask);
      return 1;
    },
    // The message-and-object wait (MsgWaitForMultipleObjects): the served paths
    // are a pending window message under the wake mask and a finite timeout. An
    // infinite wait with no message wake and no signaled object is the same
    // structured deadlock stop the single-object wait raises; object-signaled
    // wake is not inspected in the bounded probe.
    messageWait(count, handlePointer, waitAll, millisecond, wakeMask) {
      const sink = {};
      if (wakeMask !== 0 && guest.user.peekMessage(sink, false) === 1) return unsigned(count);
      const timeout = unsigned(millisecond);
      if (timeout === 0xffffffff) {
        throw hleFault("hle_wait_deadlock", "No message arrives in the single-thread world, so an infinite MsgWaitForMultipleObjects cannot complete", { handle: unsigned(handlePointer) });
      }
      clock.advanceVirtualMs(timeout);
      return 0x102;
    },
    // SID and security-descriptor helpers over bounded guest memory. A SID is
    // Revision +0, SubAuthorityCount +1, IdentifierAuthority +2 (6 byte), then
    // one dword per sub-authority. A SECURITY_DESCRIPTOR (absolute) is 20 byte:
    // Revision +0, Sbz1 +1, Control +2, Owner +4, Group +8, Sacl +12, Dacl +16.
    sidLength(pointer) {
      return 8 + 4 * memory.readMemory(pointer + 1, 1);
    },
    allocateSid(identifierAuthorityPointer, subAuthority) {
      const length = 8 + 4 * subAuthority.length;
      const address = guest.heapAllocate(guest.defaultHeapHandle(), heapFlag.zero_memory, length);
      if (address === 0) return 0;
      memory.writeMemory(address, 1, 1);
      memory.writeMemory(address + 1, 1, subAuthority.length);
      memory.writeBlock(address + 2, memory.readBlock(identifierAuthorityPointer, 6));
      for (let index = 0; index < subAuthority.length; index += 1) memory.writeMemory(address + 8 + index * 4, 4, unsigned(subAuthority[index]));
      return address;
    },

    // --- locale helpers (BPTK-103 slice) -----------------------------------------------------
    // Count the bytes of one NUL-terminated ANSI string (the cbMultiByte = -1 form).
    readAnsiLength(address) {
      let length = 0;
      while (memory.readMemory(unsigned(address) + length, 1) !== 0) {
        length += 1;
        if (length > hleBound.string_byte) throw hleFault("hle_unterminated_string", `The ANSI string at 0x${unsigned(address).toString(16)} has no terminator within ${hleBound.string_byte} byte`, { address });
      }
      return length;
    },
    readSystemTime(address) {
      return {
        year: memory.readMemory(address, 2),
        month: memory.readMemory(address + 2, 2),
        day_of_week: memory.readMemory(address + 4, 2),
        day: memory.readMemory(address + 6, 2),
        hour: memory.readMemory(address + 8, 2),
        minute: memory.readMemory(address + 10, 2),
        second: memory.readMemory(address + 12, 2),
        millisecond: memory.readMemory(address + 14, 2),
      };
    },
    writeSystemTime(address, field) {
      memory.writeMemory(address, 2, field.year & 0xffff);
      memory.writeMemory(address + 2, 2, field.month & 0xffff);
      memory.writeMemory(address + 4, 2, field.day_of_week & 0xffff);
      memory.writeMemory(address + 6, 2, field.day & 0xffff);
      memory.writeMemory(address + 8, 2, field.hour & 0xffff);
      memory.writeMemory(address + 10, 2, field.minute & 0xffff);
      memory.writeMemory(address + 12, 2, field.second & 0xffff);
      memory.writeMemory(address + 14, 2, field.millisecond & 0xffff);
    },
    // The deterministic guest wall clock: the declared file-time base plus
    // the elapsed monotonic guest time, decomposed with the civil-from-days
    // algorithm so every field derives from the one clock.
    guestSystemTime() {
      // The declared base is a FILETIME (1601 epoch, 100 ns tick), so the
      // conversion subtracts the 1601-1970 span before decomposing.
      const totalMs = Math.floor((hleProfile.file_time_base - 116444736000000000) / 10000) + Math.floor(clock.elapsedGuestMs());
      const days = Math.floor(totalMs / 86400000);
      const msOfDay = totalMs - days * 86400000;
      let z = days + 719468;
      const era = Math.floor(z / 146097);
      const doe = z - era * 146097;
      const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
      let year = yoe + era * 400;
      const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
      const mp = Math.floor((5 * doy + 2) / 153);
      const day = doy - Math.floor((153 * mp + 2) / 5) + 1;
      const month = mp < 10 ? mp + 3 : mp - 9;
      if (month <= 2) year += 1;
      return {
        year,
        month,
        day,
        day_of_week: (days + 4) % 7,
        hour: Math.floor(msOfDay / 3600000),
        minute: Math.floor(msOfDay / 60000) % 60,
        second: Math.floor(msOfDay / 1000) % 60,
        millisecond: msOfDay % 1000,
      };
    },

    // --- environment ---------------------------------------------------------------------
    buildEnvironmentBlock() {
      const pair = [...environment.entries()].map(([name, value]) => `${name}=${value}`);
      const block = Buffer.from(`${pair.length === 0 ? "" : pair.join("\0") + "\0"}\0`, "utf16le");
      const address = arena.allocate(block.length + 2);
      memory.writeBlock(address, block);
      memory.writeMemory(address + block.length, 2, 0);
      environmentBlockAddress = address;
      return address;
    },
  };
  return guest;
}

// ---------------------------------------------------------------------------
// The conformance harness (GS-036): one flat memory machine with the same
// primitives the probe provides, so every case exercises the real emulator.
// ---------------------------------------------------------------------------

const isolatedMemorySizeByte = 8 * 1024 * 1024;

export function createIsolatedWin32Memory() {
  const backing = Buffer.alloc(isolatedMemorySizeByte);
  const layout = {
    schema_version: 1,
    block_base: 0,
    arena_base: 0x00100000,
    arena_size_byte: 0x00200000,
    virtual_base: 0x00300000,
    virtual_size_byte: 0x00200000,
    thunk_base: 0x00500000,
    thunk_page_byte: hleBound.thunk_page_byte,
  };
  return {
    layout,
    readMemory(address, sizeByte) {
      if (address < 0 || address + sizeByte > backing.length) throw new Error(`The isolated memory read at 0x${Number(address).toString(16)} is out of range`);
      if (sizeByte === 1) return backing[address];
      if (sizeByte === 2) return backing.readUInt16LE(address);
      return backing.readUInt32LE(address);
    },
    writeMemory(address, sizeByte, value) {
      if (address < 0 || address + sizeByte > backing.length) throw new Error(`The isolated memory write at 0x${Number(address).toString(16)} is out of range`);
      if (sizeByte === 1) backing[address] = value & 0xff;
      else if (sizeByte === 2) backing.writeUInt16LE(value & 0xffff, address);
      else backing.writeUInt32LE(value >>> 0, address);
    },
    readBlock(address, sizeByte) {
      return Buffer.from(backing.subarray(address, address + sizeByte));
    },
    writeBlock(address, buffer) {
      Buffer.from(buffer).copy(backing, address);
    },
  };
}

export function createConformanceMachine(executableName = "game.exe") {
  const memory = createIsolatedWin32Memory();
  const clock = createVirtualClock();
  return { memory, layout: memory.layout, clock, guest: createWin32Hle(memory, memory.layout, { executable_name: executableName, clock }) };
}

function createVirtualClock() {
  let guestMs = 0;
  return {
    mode: "virtual_monotonic",
    elapsedGuestMs: () => guestMs,
    advanceVirtualMs(deltaMs) {
      guestMs += deltaMs;
    },
    tickCount: () => Math.floor(guestMs) >>> 0,
    qpc: () => Math.floor(guestMs * hleProfile.qpc_frequency_hz / 1000),
    rdtsc: () => Math.floor(guestMs * 1000000 / 1000),
    describe: () => ({ source: "one_monotonic_clock", mode: "virtual_monotonic" }),
  };
}

// Every case declares either plain dword argument or one scenario that is
// replayed on the fresh machine before the target call, so sequential
// behavior (allocate then free) is measured end to end without host state.
// The arena address inside one fresh machine are deterministic, so the
// expected value can pin them exactly.
export function buildConformanceCaseTable() {
  const caseList = [];
  let caseNumber = 0;

  function define(library, symbol, input, expected) {
    caseNumber += 1;
    caseList.push({ case_id: `HLE-${String(caseNumber).padStart(3, "0")}`, library, symbol, input, expected });
  }

  const argument = (argument) => ({ argument });
  const scenario = (scenario, argument) => ({ scenario, argument });
  const address = {
    command_line_a: 0x00100000,
    command_line_w: 0x00100020,
    scratch: 0x00150000,
    scratch_wide: 0x00150020,
    scratch_dword: 0x00150040,
    string_a: 0x00150080,
    string_b: 0x001500c0,
    string_dest: 0x00150100,
    system_info: 0x00150180,
    system_time: 0x00150200,
    startup_info: 0x00170000,
    version_info: 0x00160000,
    slist_head: 0x00140000,
    slist_entry: 0x00140010,
    heap_base: 0x00100050,
    heap_first_block: 0x00100060,
    virtual_first_block: 0x00300000,
  };
  const firstHandle = 0x00010000;
  const mainModule = 0x00020001;
  const kernel32Module = 0x00020002;
  const exitProcessThunk = 0x00500000 + win32HleExportTable.findIndex((entry) => entry.library === "kernel32.dll" && entry.symbol === "ExitProcess") * 4;
  const heapScenario = [["kernel32.dll", "HeapCreate", [0, 0, 0]]];

  // error state
  define("kernel32.dll", "GetLastError", argument([]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "SetLastError", argument([5]), { return_value: 0, last_error: 5 });
  define("kernel32.dll", "GetLastError", scenario([["kernel32.dll", "SetLastError", [87]]], []), { return_value: 87, last_error: 87 });

  // process
  define("kernel32.dll", "GetCurrentProcess", argument([]), { return_value: 0xffffffff, last_error: 0 });
  define("kernel32.dll", "GetCurrentProcessId", argument([]), { return_value: hleProfile.process_id, last_error: 0 });
  define("kernel32.dll", "GetCurrentThreadId", argument([]), { return_value: hleProfile.thread_id, last_error: 0 });
  define("kernel32.dll", "GetCurrentThread", argument([]), { return_value: 0xfffffffe, last_error: 0 });
  define("kernel32.dll", "IsDebuggerPresent", argument([]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "IsProcessorFeaturePresent", argument([2]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "IsProcessorFeaturePresent", argument([6]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "ExitProcess", argument([0x150]), { return_value: null, last_error: "The guest ended its own process" });
  define("kernel32.dll", "TerminateProcess", argument([0xffffffff, 7]), { return_value: null, last_error: "The guest ended its own process" });
  define("kernel32.dll", "TerminateProcess", argument([firstHandle, 3]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "RaiseException", argument([0xe0000001, 0, 0, 0]), { return_value: null, last_error: "The guest raised an unhandled exception" });

  // module and lookup
  define("kernel32.dll", "GetModuleHandleA", argument([0]), { return_value: mainModule, last_error: 0 });
  define("kernel32.dll", "GetModuleHandleW", scenario([], [0]), { return_value: mainModule, last_error: 0 });
  define("kernel32.dll", "GetModuleHandleExW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "kernel32.dll", 32), argument: [0, address.scratch_wide, address.scratch_dword] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetProcAddress", { prepare: (guest) => guest.writeAnsiString(address.scratch, "ExitProcess", 32), argument: [kernel32Module, address.scratch] }, { return_value: exitProcessThunk, last_error: 0 });
  define("kernel32.dll", "GetProcAddress", { prepare: (guest) => guest.writeAnsiString(address.scratch, "NoSuchExport", 32), argument: [kernel32Module, address.scratch] }, { return_value: 0, last_error: 127 });
  define("kernel32.dll", "GetModuleFileNameA", argument([mainModule, address.scratch, 260]), { return_value: "C:\\game\\game.exe".length, last_error: 0 });
  define("kernel32.dll", "GetModuleFileNameA", argument([mainModule, address.scratch, 8]), { return_value: 8, last_error: 122 });
  define("kernel32.dll", "GetModuleFileNameW", argument([mainModule, address.scratch_wide, 260]), { return_value: "C:\\game\\game.exe".length, last_error: 0 });
  define("kernel32.dll", "GetCommandLineA", argument([]), { return_value: address.command_line_a, last_error: 0 });
  define("kernel32.dll", "GetCommandLineW", argument([]), { return_value: address.command_line_w, last_error: 0 });
  define("kernel32.dll", "GetStartupInfoA", argument([address.startup_info]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetStartupInfoW", argument([address.startup_info]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetVersion", argument([]), { return_value: (hleProfile.version_build << 16 | hleProfile.version_minor << 8 | hleProfile.version_major) >>> 0, last_error: 0 });
  define("kernel32.dll", "GetVersionExA", { prepare: (guest) => guest.memory.writeMemory(address.version_info, 4, 148), argument: [address.version_info] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetSystemDirectoryA", argument([address.scratch, 32]), { return_value: hleProfile.system_directory.length, last_error: 0 });

  // heap and virtual memory
  define("kernel32.dll", "GetProcessHeap", argument([]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "HeapCreate", argument([0, 0, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "HeapAlloc", scenario(heapScenario, [firstHandle, 0, 64]), { return_value: address.heap_first_block, last_error: 0 });
  define("kernel32.dll", "HeapAlloc", scenario(heapScenario, [firstHandle, 0x08, 64]), { return_value: address.heap_first_block, last_error: 0 });
  define("kernel32.dll", "HeapAlloc", scenario(heapScenario, [firstHandle, 0, 0]), { return_value: address.heap_first_block, last_error: 0 });
  define("kernel32.dll", "HeapAlloc", argument([firstHandle, 0, 64]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "HeapReAlloc", {
    prepare: (guest) => guest.memory.writeMemory(address.heap_first_block, 4, 0x41424344),
    scenario: [...heapScenario, ["kernel32.dll", "HeapAlloc", [firstHandle, 0, 8]]],
    argument: [firstHandle, 0, address.heap_first_block, 64],
  }, { return_value: 0x00100068, last_error: 0 });
  define("kernel32.dll", "HeapSize", {
    scenario: [...heapScenario, ["kernel32.dll", "HeapAlloc", [firstHandle, 0, 64]]],
    argument: [firstHandle, 0, address.heap_first_block],
  }, { return_value: 64, last_error: 0 });
  define("kernel32.dll", "HeapFree", {
    scenario: [...heapScenario, ["kernel32.dll", "HeapAlloc", [firstHandle, 0, 64]]],
    argument: [firstHandle, 0, address.heap_first_block],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "HeapFree", scenario(heapScenario, [firstHandle, 0, address.heap_first_block]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "VirtualAlloc", argument([0, 0x10000, 0x3000, 0x04]), { return_value: address.virtual_first_block, last_error: 0 });
  define("kernel32.dll", "VirtualAlloc", argument([0, 0, 0x3000, 0x04]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "VirtualFree", {
    scenario: [["kernel32.dll", "VirtualAlloc", [0, 0x10000, 0x3000, 0x04]]],
    argument: [address.virtual_first_block, 0, 0x8000],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "VirtualProtect", {
    scenario: [["kernel32.dll", "VirtualAlloc", [0, 0x10000, 0x3000, 0x04]]],
    argument: [address.virtual_first_block, 0x10000, 0x02, address.scratch_dword],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "VirtualQuery", {
    scenario: [["kernel32.dll", "VirtualAlloc", [0, 0x10000, 0x3000, 0x04]]],
    argument: [address.virtual_first_block, address.scratch, 28],
  }, { return_value: 28, last_error: 0 });

  // time
  define("kernel32.dll", "GetTickCount", argument([]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "QueryPerformanceCounter", argument([address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "QueryPerformanceFrequency", argument([address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetSystemTimeAsFileTime", argument([address.scratch_dword]), { return_value: 0, last_error: 0 });

  // synchronization
  define("kernel32.dll", "InitializeCriticalSection", argument([address.startup_info]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "InitializeCriticalSectionAndSpinCount", argument([address.startup_info, 4]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "EnterCriticalSection", scenario([["kernel32.dll", "InitializeCriticalSection", [address.startup_info]]], [address.startup_info]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "TryEnterCriticalSection", scenario([["kernel32.dll", "InitializeCriticalSection", [address.startup_info]]], [address.startup_info]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "LeaveCriticalSection", {
    scenario: [["kernel32.dll", "InitializeCriticalSection", [address.startup_info]], ["kernel32.dll", "EnterCriticalSection", [address.startup_info]]],
    argument: [address.startup_info],
  }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "DeleteCriticalSection", scenario([["kernel32.dll", "InitializeCriticalSection", [address.startup_info]]], [address.startup_info]), { return_value: 0, last_error: 0 });

  // thread-local storage
  define("kernel32.dll", "TlsAlloc", argument([]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "TlsFree", argument([63]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "TlsSetValue", scenario([["kernel32.dll", "TlsAlloc", []]], [0, 0x42]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "TlsGetValue", scenario([["kernel32.dll", "TlsAlloc", []], ["kernel32.dll", "TlsSetValue", [0, 0x42]]], [0]), { return_value: 0x42, last_error: 0 });

  // fiber-local storage (Win64 CRT-init breadth)
  define("kernel32.dll", "FlsAlloc", argument([0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "FlsFree", scenario([["kernel32.dll", "FlsAlloc", [0]]], [0]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FlsFree", argument([100]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "FlsSetValue", scenario([["kernel32.dll", "FlsAlloc", [0]]], [0, 0x99]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FlsGetValue", scenario([["kernel32.dll", "FlsAlloc", [0]], ["kernel32.dll", "FlsSetValue", [0, 0x99]]], [0]), { return_value: 0x99, last_error: 0 });
  define("kernel32.dll", "InitializeCriticalSectionEx", argument([address.startup_info, 0, 0]), { return_value: 1, last_error: 0 });

  // Universal CRT startup stubs (BPTK-031). The cell addresses are read from a
  // fresh reference machine so the oracle tracks the deterministic CRT block
  // layout without hardcoding an address that a future arena change could move.
  const crtCell = createConformanceMachine().guest.crt;
  const crtRuntime = "api-ms-win-crt-runtime-l1-1-0.dll";
  const crtStdio = "api-ms-win-crt-stdio-l1-1-0.dll";
  const crtHeap = "api-ms-win-crt-heap-l1-1-0.dll";
  const crtMath = "api-ms-win-crt-math-l1-1-0.dll";
  const crtLocale = "api-ms-win-crt-locale-l1-1-0.dll";
  const crtEnv = "api-ms-win-crt-environment-l1-1-0.dll";
  const crtStr = "api-ms-win-crt-string-l1-1-0.dll";
  const crtPriv = "api-ms-win-crt-private-l1-1-0.dll";
  const vcrt = "vcruntime140.dll";
  const msvcrt = "msvcrt.dll";
  // Each row: [libraryList, symbol, input, expected]. One conformance case is
  // emitted per (library, symbol) pair so the coverage gate stays complete.
  const crtRow = [
    [[crtRuntime, msvcrt], "_configure_narrow_argv", argument([0]), 0],
    [[crtRuntime, msvcrt], "_configure_wide_argv", argument([0]), 0],
    [[crtRuntime, msvcrt], "_initialize_narrow_environment", argument([]), 0],
    [[crtRuntime, msvcrt], "_initialize_wide_environment", argument([]), 0],
    [[crtRuntime, msvcrt], "_get_initial_narrow_environment", argument([]), crtCell.environArray],
    [[crtRuntime, msvcrt], "_get_initial_wide_environment", argument([]), crtCell.wenvironArray],
    [[crtRuntime, msvcrt], "_get_narrow_winmain_command_line", argument([]), crtCell.winmainLine],
    [[crtRuntime, msvcrt], "_get_wide_winmain_command_line", argument([]), crtCell.winmainLine],
    [[crtRuntime, msvcrt], "_set_app_type", argument([2]), 0],
    [[crtRuntime, msvcrt], "__set_app_type", argument([2]), 0],
    [[crtRuntime, msvcrt], "_set_invalid_parameter_handler", argument([0x1234]), 0],
    [[crtRuntime, msvcrt], "_get_invalid_parameter_handler", argument([]), 0],
    [[crtRuntime, crtMath], "__setusermatherr", argument([0]), 0],
    [[crtHeap, msvcrt], "_set_new_mode", argument([1]), 0],
    [[crtRuntime, msvcrt], "_crt_atexit", argument([0]), 0],
    [[crtRuntime, msvcrt], "_crt_at_quick_exit", argument([0]), 0],
    [[crtRuntime, msvcrt], "_register_thread_local_exe_atexit_callback", argument([0]), 0],
    [[crtRuntime, msvcrt], "_initialize_onexit_table", argument([0]), 0],
    [[crtRuntime, msvcrt], "_register_onexit_function", argument([0, 0]), 0],
    [[crtRuntime, msvcrt], "__p___argc", argument([]), crtCell.argcCell],
    [[crtRuntime, msvcrt], "__p___argv", argument([]), crtCell.argvCell],
    [[crtRuntime, msvcrt], "__p___wargv", argument([]), crtCell.wargvCell],
    [[crtRuntime, crtEnv, msvcrt], "__p__environ", argument([]), crtCell.environCell],
    [[crtRuntime, crtEnv, msvcrt], "__p__wenviron", argument([]), crtCell.wenvironCell],
    [[crtRuntime, crtStdio, msvcrt], "__p__commode", argument([]), crtCell.commodeCell],
    [[crtRuntime, crtStdio, msvcrt], "__p__fmode", argument([]), crtCell.fmodeCell],
    [[crtRuntime, msvcrt], "_errno", argument([]), crtCell.errnoCell],
    [[crtLocale, msvcrt], "___mb_cur_max_func", argument([]), 1],
    [[crtLocale, msvcrt], "_configthreadlocale", argument([0]), 0],
    [[crtStdio, msvcrt], "_set_fmode", argument([0x4000]), 0],
    [[crtStdio, msvcrt], "_get_fmode", argument([address.scratch_dword]), 0],
    [[vcrt], "__vcrt_InitializeCriticalSectionEx", argument([address.startup_info, 0, 0]), 1],
    [[vcrt], "__vcrt_EnterCriticalSection", scenario([[vcrt, "__vcrt_InitializeCriticalSectionEx", [address.startup_info, 0, 0]]], [address.startup_info]), 0],
    [[vcrt], "__vcrt_LeaveCriticalSection", scenario([[vcrt, "__vcrt_InitializeCriticalSectionEx", [address.startup_info, 0, 0]], [vcrt, "__vcrt_EnterCriticalSection", [address.startup_info]]], [address.startup_info]), 0],
    [[vcrt], "__vcrt_DeleteCriticalSection", scenario([[vcrt, "__vcrt_InitializeCriticalSectionEx", [address.startup_info, 0, 0]]], [address.startup_info]), 0],
  ];
  for (const [libraryList, symbol, input, returnValue] of crtRow) {
    for (const library of libraryList) define(library, symbol, input, { return_value: returnValue, last_error: 0 });
  }
  // The compiler memory intrinsics, exercised over guest memory.
  const memLibrary = [vcrt, crtStr, crtPriv, msvcrt];
  const writeFour = (at, bytes) => (guest) => guest.memory.writeBlock(at, Buffer.from(bytes));
  for (const library of memLibrary) {
    define(library, "memset", argument([address.scratch, 0x41, 8]), { return_value: address.scratch, last_error: 0 });
    define(library, "memcpy", { prepare: writeFour(address.string_a, [0x57, 0x58, 0x59, 0x5a]), argument: [address.string_dest, address.string_a, 4] }, { return_value: address.string_dest, last_error: 0 });
    define(library, "memmove", { prepare: writeFour(address.string_a, [0x57, 0x58, 0x59, 0x5a]), argument: [address.string_dest, address.string_a, 4] }, { return_value: address.string_dest, last_error: 0 });
    define(library, "memcmp", { prepare: (guest) => { writeFour(address.string_a, [1, 2, 3, 4])(guest); writeFour(address.string_b, [1, 2, 3, 4])(guest); }, argument: [address.string_a, address.string_b, 4] }, { return_value: 0, last_error: 0 });
    define(library, "memchr", { prepare: writeFour(address.string_a, [0x41, 0x42, 0x43, 0x44]), argument: [address.string_a, 0x43, 4] }, { return_value: address.string_a + 2, last_error: 0 });
  }

  // --- msvcrt.dll C runtime for the i386 CLI corpus (BPTK-010) --------------
  // The static CRT block addresses are deterministic per layout, so a pointer
  // return is pinned by reading a fresh machine; a dynamic (heap/arena) return
  // is pinned by evaluating the same real emulator once as its own oracle, and
  // the memory side effects carry a dedicated unit test in test/hle.test.mjs.
  const crtRuntimeCell = createConformanceMachine().guest.crtRuntime;
  const oracleCall = (library, symbol, input) => {
    const { guest } = createConformanceMachine();
    const callArgument = Array.isArray(input) ? input : input.argument ?? [];
    if (!Array.isArray(input) && typeof input.prepare === "function") input.prepare(guest);
    for (const step of Array.isArray(input) ? [] : input.scenario ?? []) guest.invokeExport(guest.lookupExport(step[0], step[1]), step[2]);
    const value = guest.invokeExport(guest.lookupExport(library, symbol), callArgument);
    return { return_value: value, last_error: guest.getLastError() };
  };
  const exitExpected = { return_value: null, last_error: "The guest ended its own process" };
  const doubleRefused = (symbol) => ({ return_value: null, last_error: `msvcrt!${symbol} returns an x87 double the bounded integer probe cannot carry across the EAX dispatch boundary` });
  const writeMsvcrtString = (at, text) => (guest) => guest.writeAnsiString(at, text, text.length + 1);
  const writeMsvcrtWide = (at, text) => (guest) => guest.writeWideString(at, text, text.length + 1);
  const tmScratch = address.startup_info; // a 36-byte struct tm scratch
  const writeTmScratch = (guest) => {
    // 2020-09-10 18:40:00 UTC: sec,min,hour,mday,mon,year-1900,wday,yday,isdst
    const field = [0, 40, 18, 10, 8, 120, 4, 253, 0];
    for (let index = 0; index < field.length; index += 1) guest.memory.writeMemory(tmScratch + index * 4, 4, field[index]);
  };

  // Data exports (a live guest address of the backing cell/array).
  define(msvcrt, "_iob", argument([]), { return_value: crtRuntimeCell.iobBase, last_error: 0 });
  define(msvcrt, "_environ", argument([]), { return_value: crtCell.environCell, last_error: 0 });
  define(msvcrt, "_tzname", argument([]), { return_value: crtRuntimeCell.tznameBase, last_error: 0 });
  define(msvcrt, "__mb_cur_max", argument([]), { return_value: crtRuntimeCell.mbCurMaxCell, last_error: 0 });
  define(msvcrt, "__winitenv", argument([]), { return_value: crtCell.wenvironCell, last_error: 0 });

  // Startup and teardown.
  define(msvcrt, "__setusermatherr", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "__wgetmainargs", argument([address.scratch, address.scratch_dword, address.scratch_dword + 4, 0, 0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_amsg_exit", argument([1]), { return_value: null, last_error: "The guest ended its own process" });
  define(msvcrt, "_assert", argument([0, 0, 0]), exitExpected);
  define(msvcrt, "_cexit", argument([]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_initterm", argument([0, 0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_onexit", argument([0x1234]), { return_value: 0x1234, last_error: 0 });
  define(msvcrt, "_lock", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_unlock", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "exit", argument([0]), exitExpected);
  define(msvcrt, "abort", argument([]), exitExpected);
  define(msvcrt, "raise", argument([6]), { return_value: 0, last_error: 0 });
  define(msvcrt, "signal", argument([6, 0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_beginthreadex", argument([0, 0, 0, 0, 0, 0]), { return_value: null, last_error: "msvcrt!_beginthreadex spawns an OS thread the single-thread bounded probe does not provide" });
  define(msvcrt, "_endthreadex", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_setjmp3", argument([address.scratch, 0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "longjmp", argument([address.scratch, 1]), { return_value: null, last_error: "msvcrt!longjmp restores a saved jmp_buf frame the single-pass bounded probe cannot unwind" });

  // Heap.
  define(msvcrt, "malloc", argument([16]), oracleCall(msvcrt, "malloc", [16]));
  define(msvcrt, "calloc", argument([4, 4]), oracleCall(msvcrt, "calloc", [4, 4]));
  define(msvcrt, "realloc", argument([0, 16]), oracleCall(msvcrt, "realloc", [0, 16]));
  define(msvcrt, "free", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_msize", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_recalloc", argument([0, 4, 4]), oracleCall(msvcrt, "_recalloc", [0, 4, 4]));
  define(msvcrt, "_callnewh", argument([16]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_strdup", { prepare: writeMsvcrtString(address.string_a, "hi"), argument: [address.string_a] }, oracleCall(msvcrt, "_strdup", { prepare: writeMsvcrtString(address.string_a, "hi"), argument: [address.string_a] }));

  // ucrt heap (api-ms-win-crt-heap-l1-1-0.dll): the same real process default
  // heap as the msvcrt surface, so each row exercises a genuine allocation over
  // the arena. The Win64 ucrt CRT init (Dwarf Fortress) links this DLL.
  define(crtHeap, "malloc", argument([16]), oracleCall(crtHeap, "malloc", [16]));
  define(crtHeap, "calloc", argument([4, 4]), oracleCall(crtHeap, "calloc", [4, 4]));
  define(crtHeap, "realloc", argument([0, 16]), oracleCall(crtHeap, "realloc", [0, 16]));
  define(crtHeap, "free", argument([0]), { return_value: 0, last_error: 0 });
  define(crtHeap, "_msize", argument([0]), { return_value: 0, last_error: 0 });
  define(crtHeap, "_recalloc", argument([0, 4, 4]), oracleCall(crtHeap, "_recalloc", [0, 4, 4]));
  define(crtHeap, "_callnewh", argument([16]), { return_value: 0, last_error: 0 });

  // String and memory.
  define(msvcrt, "strlen", { prepare: writeMsvcrtString(address.string_a, "hello"), argument: [address.string_a] }, { return_value: 5, last_error: 0 });
  define(msvcrt, "wcslen", { prepare: writeMsvcrtWide(address.string_a, "hi"), argument: [address.string_a] }, { return_value: 2, last_error: 0 });
  define(msvcrt, "strcmp", { prepare: (guest) => { writeMsvcrtString(address.string_a, "abc")(guest); writeMsvcrtString(address.string_b, "abc")(guest); }, argument: [address.string_a, address.string_b] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "strncmp", { prepare: (guest) => { writeMsvcrtString(address.string_a, "abcd")(guest); writeMsvcrtString(address.string_b, "abce")(guest); }, argument: [address.string_a, address.string_b, 3] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "_strnicmp", { prepare: (guest) => { writeMsvcrtString(address.string_a, "ABC")(guest); writeMsvcrtString(address.string_b, "abc")(guest); }, argument: [address.string_a, address.string_b, 3] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "strcpy", { prepare: writeMsvcrtString(address.string_a, "hey"), argument: [address.string_dest, address.string_a] }, { return_value: address.string_dest, last_error: 0 });
  define(msvcrt, "strncpy", { prepare: writeMsvcrtString(address.string_a, "hey"), argument: [address.string_dest, address.string_a, 3] }, { return_value: address.string_dest, last_error: 0 });
  define(msvcrt, "strchr", { prepare: writeMsvcrtString(address.string_a, "hello"), argument: [address.string_a, 0x6c] }, { return_value: address.string_a + 2, last_error: 0 });
  define(msvcrt, "strrchr", { prepare: writeMsvcrtString(address.string_a, "hello"), argument: [address.string_a, 0x6c] }, { return_value: address.string_a + 3, last_error: 0 });
  define(msvcrt, "strspn", { prepare: (guest) => { writeMsvcrtString(address.string_a, "aabbc")(guest); writeMsvcrtString(address.string_b, "ab")(guest); }, argument: [address.string_a, address.string_b] }, { return_value: 4, last_error: 0 });
  define(msvcrt, "strstr", { prepare: (guest) => { writeMsvcrtString(address.string_a, "hello")(guest); writeMsvcrtString(address.string_b, "ll")(guest); }, argument: [address.string_a, address.string_b] }, { return_value: address.string_a + 2, last_error: 0 });
  define(msvcrt, "strerror", argument([2]), { return_value: crtRuntimeCell.strerrorBuf, last_error: 0 });
  define(msvcrt, "wcstombs", { prepare: writeMsvcrtWide(address.string_a, "hi"), argument: [address.string_dest, address.string_a, 8] }, { return_value: 2, last_error: 0 });

  // ctype.
  define(msvcrt, "isalnum", argument([0x41]), { return_value: 8, last_error: 0 });
  define(msvcrt, "isalpha", argument([0x41]), { return_value: 2, last_error: 0 });
  define(msvcrt, "isspace", argument([0x20]), { return_value: 8, last_error: 0 });

  // Numbers and pseudo-random.
  define(msvcrt, "atoi", { prepare: writeMsvcrtString(address.string_a, "42"), argument: [address.string_a] }, { return_value: 42, last_error: 0 });
  define(msvcrt, "_ultoa", argument([255, address.string_dest, 16]), { return_value: address.string_dest, last_error: 0 });
  define(msvcrt, "rand", argument([]), oracleCall(msvcrt, "rand", []));

  // Environment and locale.
  define(msvcrt, "getenv", { prepare: writeMsvcrtString(address.string_a, "PATH"), argument: [address.string_a] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "setlocale", argument([0, 0]), { return_value: crtRuntimeCell.localeName, last_error: 0 });
  define(msvcrt, "localeconv", argument([]), { return_value: crtRuntimeCell.lconv, last_error: 0 });

  // Math (x87 double return refused).
  for (const symbol of ["acos", "asin", "atan", "cosh", "sinh", "tan", "tanh", "log10"]) define(msvcrt, symbol, argument([0, 0]), doubleRefused(symbol));
  for (const symbol of ["_hypot", "_nextafter"]) define(msvcrt, symbol, argument([0, 0, 0, 0]), doubleRefused(symbol));
  for (const symbol of ["_j0", "_j1", "_y0", "_y1"]) define(msvcrt, symbol, argument([0, 0]), doubleRefused(symbol));
  for (const symbol of ["_jn", "_yn"]) define(msvcrt, symbol, argument([0, 0, 0]), doubleRefused(symbol));

  // Time.
  define(msvcrt, "time", argument([0]), { return_value: 1599763200, last_error: 0 });
  define(msvcrt, "gmtime", { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 1599763200), argument: [address.scratch_dword] }, { return_value: crtRuntimeCell.tmBuf, last_error: 0 });
  define(msvcrt, "localtime", { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 1599763200), argument: [address.scratch_dword] }, { return_value: crtRuntimeCell.tmBuf, last_error: 0 });
  define(msvcrt, "_mkgmtime32", { prepare: writeTmScratch, argument: [tmScratch] }, { return_value: 1599763200, last_error: 0 });
  define(msvcrt, "_tzset", argument([]), { return_value: 0, last_error: 0 });
  define(msvcrt, "strftime", { prepare: (guest) => { writeTmScratch(guest); writeMsvcrtString(address.string_a, "%Y")(guest); }, argument: [address.string_dest, 64, address.string_a, tmScratch] }, { return_value: 4, last_error: 0 });

  // stdio.
  define(msvcrt, "_fileno", argument([crtRuntimeCell.iobBase + FILE_STRUCT_BYTE]), { return_value: 1, last_error: 0 });
  define(msvcrt, "_isatty", argument([1]), { return_value: 1, last_error: 0 });
  define(msvcrt, "_get_osfhandle", argument([1]), oracleCall(msvcrt, "_get_osfhandle", [1]));
  define(msvcrt, "_setmode", argument([1, 0x8000]), { return_value: 0x4000, last_error: 0 });
  define(msvcrt, "_open", { prepare: writeMsvcrtString(address.string_a, "c:\\a.txt"), argument: [address.string_a, 0x0301, 0] }, oracleCall(msvcrt, "_open", { prepare: writeMsvcrtString(address.string_a, "c:\\a.txt"), argument: [address.string_a, 0x0301, 0] }));
  define(msvcrt, "_close", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_write", { prepare: writeMsvcrtString(address.string_a, "hey"), argument: [1, address.string_a, 3] }, { return_value: 3, last_error: 0 });
  define(msvcrt, "_fdopen", argument([1, 0]), oracleCall(msvcrt, "_fdopen", [1, 0]));
  define(msvcrt, "_wfopen", { prepare: writeMsvcrtWide(address.string_a, "c:\\b.txt"), argument: [address.string_a, 0] }, oracleCall(msvcrt, "_wfopen", { prepare: writeMsvcrtWide(address.string_a, "c:\\b.txt"), argument: [address.string_a, 0] }));
  define(msvcrt, "fwrite", { prepare: writeMsvcrtString(address.string_a, "hey"), argument: [address.string_a, 1, 3, crtRuntimeCell.iobBase + FILE_STRUCT_BYTE] }, { return_value: 3, last_error: 0 });
  define(msvcrt, "fread", argument([address.string_a, 1, 3, crtRuntimeCell.iobBase]), { return_value: 0, last_error: 0 });
  define(msvcrt, "fputc", argument([0x41, crtRuntimeCell.iobBase + FILE_STRUCT_BYTE]), { return_value: 0x41, last_error: 0 });
  define(msvcrt, "getc", argument([crtRuntimeCell.iobBase]), { return_value: 0xffffffff, last_error: 0 });
  define(msvcrt, "fgets", argument([address.string_a, 10, crtRuntimeCell.iobBase]), { return_value: 0, last_error: 0 });
  define(msvcrt, "fflush", argument([crtRuntimeCell.iobBase + FILE_STRUCT_BYTE]), { return_value: 0, last_error: 0 });
  define(msvcrt, "fclose", argument([crtRuntimeCell.iobBase + FILE_STRUCT_BYTE]), { return_value: 0, last_error: 0 });
  define(msvcrt, "feof", argument([crtRuntimeCell.iobBase]), { return_value: 0, last_error: 0 });
  define(msvcrt, "ferror", argument([crtRuntimeCell.iobBase]), { return_value: 0, last_error: 0 });
  define(msvcrt, "clearerr", argument([crtRuntimeCell.iobBase]), { return_value: 0, last_error: 0 });
  define(msvcrt, "printf", { prepare: writeMsvcrtString(address.string_a, "hi"), argument: [address.string_a] }, { return_value: 2, last_error: 0 });
  define(msvcrt, "fprintf", { prepare: writeMsvcrtString(address.string_a, "hi"), argument: [crtRuntimeCell.iobBase + FILE_STRUCT_BYTE, address.string_a] }, { return_value: 2, last_error: 0 });
  define(msvcrt, "vfprintf", { prepare: writeMsvcrtString(address.string_a, "hi"), argument: [crtRuntimeCell.iobBase + FILE_STRUCT_BYTE, address.string_a, 0] }, { return_value: 2, last_error: 0 });
  define(msvcrt, "perror", { prepare: writeMsvcrtString(address.string_a, "err"), argument: [address.string_a] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "_fullpath", { prepare: writeMsvcrtString(address.string_a, "a.txt"), argument: [address.string_dest, address.string_a, 260] }, { return_value: address.string_dest, last_error: 0 });
  define(msvcrt, "_stati64", { prepare: writeMsvcrtString(address.string_a, "c:\\none.txt"), argument: [address.string_a, address.scratch] }, { return_value: 0xffffffff, last_error: 0 });
  define(msvcrt, "_fstati64", argument([1, address.scratch]), { return_value: 0, last_error: 0 });
  define(msvcrt, "qsort", argument([0, 0, 0, 0]), { return_value: null, last_error: "msvcrt!qsort must re-enter guest code for its callback, which the single-pass bounded probe does not provide" });

  // shlwapi.dll path helper.
  define("shlwapi.dll", "PathIsRelativeA", { prepare: writeMsvcrtString(address.string_a, "sub\\file.txt"), argument: [address.string_a] }, { return_value: 1, last_error: 0 });
  define("shlwapi.dll", "PathIsRelativeA", { prepare: writeMsvcrtString(address.string_b, "c:\\file.txt"), argument: [address.string_b] }, { return_value: 0, last_error: 0 });

  // kernel32.dll thread/semaphore breadth.
  define("kernel32.dll", "AreFileApisANSI", argument([]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "IsDBCSLeadByteEx", argument([1252, 0x81]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetThreadPriority", argument([0xfffffffe]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "SetThreadPriority", argument([0xfffffffe, 1]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetProcessAffinityMask", argument([0xffffffff, address.scratch_dword, address.scratch_dword + 4]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetProcessAffinityMask", argument([0xffffffff, 1]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetHandleInformation", argument([firstHandle, address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "DuplicateHandle", argument([0xffffffff, firstHandle, 0xffffffff, address.scratch_dword, 0, 0, 2]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "CreateSemaphoreA", argument([0, 1, 4, 0]), oracleCall("kernel32.dll", "CreateSemaphoreA", [0, 1, 4, 0]));
  define("kernel32.dll", "ReleaseSemaphore", scenario([["kernel32.dll", "CreateSemaphoreA", [0, 1, 4, 0]]], [firstHandle, 1, address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "WaitForMultipleObjects", argument([1, address.scratch_dword, 0, 0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "ResumeThread", argument([0xfffffffe]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "SuspendThread", argument([0xfffffffe]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetThreadContext", argument([0xfffffffe, address.scratch]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetThreadContext", argument([0xfffffffe, address.scratch]), { return_value: 1, last_error: 0 });

  // lock-free singly linked list
  define("kernel32.dll", "InitializeSListHead", argument([address.slist_head]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "InterlockedPushEntrySList", argument([address.slist_head, address.slist_entry]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "InterlockedPopEntrySList", scenario([["kernel32.dll", "InterlockedPushEntrySList", [address.slist_head, address.slist_entry]]], [address.slist_head]), { return_value: address.slist_entry, last_error: 0 });
  define("kernel32.dll", "InterlockedFlushSList", scenario([["kernel32.dll", "InterlockedPushEntrySList", [address.slist_head, address.slist_entry]]], [address.slist_head]), { return_value: address.slist_entry, last_error: 0 });
  define("kernel32.dll", "QueryDepthSList", scenario([["kernel32.dll", "InterlockedPushEntrySList", [address.slist_head, address.slist_entry]]], [address.slist_head]), { return_value: 1, last_error: 0 });

  // pointer encoding
  define("kernel32.dll", "EncodePointer", argument([0x12345678]), { return_value: (0x12345678 ^ hleProfile.pointer_cookie) >>> 0, last_error: 0 });
  define("kernel32.dll", "DecodePointer", argument([(0x12345678 ^ hleProfile.pointer_cookie) >>> 0]), { return_value: 0x12345678, last_error: 0 });

  // structured exception filter and vectored handler registration
  define("kernel32.dll", "SetUnhandledExceptionFilter", argument([0x00401000]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "AddVectoredExceptionHandler", argument([1, 0x00401000]), { return_value: 0x00080001, last_error: 0 });
  define("kernel32.dll", "AddVectoredExceptionHandler", argument([0, 0]), { return_value: 0, last_error: errorValue.invalid_parameter });
  define("kernel32.dll", "RemoveVectoredExceptionHandler", scenario([["kernel32.dll", "AddVectoredExceptionHandler", [1, 0x00401000]]], [0x00080001]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "RemoveVectoredExceptionHandler", argument([0x00080001]), { return_value: 0, last_error: 0 });

  // standard handle and output capture
  define("kernel32.dll", "GetStdHandle", argument([-11]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "GetStdHandle", argument([-3]), { return_value: 0xffffffff, last_error: 87 });
  define("kernel32.dll", "WriteFile", {
    prepare: (guest) => guest.writeAnsiString(address.scratch, "AB", 16),
    scenario: [["kernel32.dll", "GetStdHandle", [-11]]],
    argument: [firstHandle, address.scratch, 2, address.scratch_dword, 0],
  }, { return_value: 1, last_error: 0, output_byte: [0x41, 0x42] });
  define("kernel32.dll", "WriteFile", scenario([["kernel32.dll", "GetStdHandle", [-10]]], [firstHandle, address.scratch, 4, 0, 0]), { return_value: 0, last_error: 5 });
  define("kernel32.dll", "WriteFile", argument([0xdeadbeef, address.scratch, 4, 0, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "WriteConsoleW", {
    prepare: (guest) => guest.writeWideString(address.scratch_wide, "HELLO", 16),
    scenario: [["kernel32.dll", "GetStdHandle", [-11]]],
    argument: [firstHandle, address.scratch_wide, 5, address.scratch_dword, 0],
  }, { return_value: 1, last_error: 0, output_byte: [0x48, 0, 0x45, 0, 0x4c, 0, 0x4c, 0, 0x4f, 0] });
  define("kernel32.dll", "lstrlenA", { prepare: (guest) => guest.writeAnsiString(address.scratch, "abc", 16), argument: [address.scratch] }, { return_value: 3, last_error: 0 });
  define("kernel32.dll", "lstrlenA", argument([0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "lstrlenW", argument([0]), { return_value: 0, last_error: 0 });

  // kernel32 string family (BPTK-101 breadth)
  const writeStringPair = (leftAnsi, rightAnsi) => (guest) => {
    guest.writeAnsiString(address.string_a, leftAnsi, 32);
    guest.writeAnsiString(address.string_b, rightAnsi, 32);
  };
  const writeWidePair = (leftWide, rightWide) => (guest) => {
    guest.writeWideString(address.string_a, leftWide, 32);
    guest.writeWideString(address.string_b, rightWide, 32);
  };
  define("kernel32.dll", "lstrcmpA", { prepare: writeStringPair("abc", "abc"), argument: [address.string_a, address.string_b] }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "lstrcmpA", { prepare: writeStringPair("abc", "abd"), argument: [address.string_a, address.string_b] }, { return_value: unsigned(-1), last_error: 0 });
  define("kernel32.dll", "lstrcmpA", { prepare: writeStringPair("abd", "abc"), argument: [address.string_a, address.string_b] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "lstrcmpiA", { prepare: writeStringPair("ABC", "abc"), argument: [address.string_a, address.string_b] }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "lstrcmpW", { prepare: writeWidePair("abc", "abc"), argument: [address.string_a, address.string_b] }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "lstrcmpiW", { prepare: writeWidePair("ABC", "abc"), argument: [address.string_a, address.string_b] }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "lstrcpyA", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hello", 16), argument: [address.string_dest, address.string_a] }, { return_value: address.string_dest, last_error: 0 });
  define("kernel32.dll", "lstrcpyA", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "lstrcpyW", { prepare: (guest) => guest.writeWideString(address.string_a, "hi", 16), argument: [address.string_dest, address.string_a] }, { return_value: address.string_dest, last_error: 0 });
  define("kernel32.dll", "lstrcpynA", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hello", 16), argument: [address.string_dest, address.string_a, 3] }, { return_value: address.string_dest, last_error: 0 });
  define("kernel32.dll", "lstrcatA", { prepare: (guest) => { guest.writeAnsiString(address.string_dest, "ab", 16); guest.writeAnsiString(address.string_a, "cd", 16); }, argument: [address.string_dest, address.string_a] }, { return_value: address.string_dest, last_error: 0 });
  define("kernel32.dll", "lstrcatW", { prepare: (guest) => { guest.writeWideString(address.string_dest, "ab", 16); guest.writeWideString(address.string_a, "cd", 16); }, argument: [address.string_dest, address.string_a] }, { return_value: address.string_dest, last_error: 0 });

  // interlocked atomics (BPTK-101 breadth)
  const seedDword = (value) => (guest) => guest.memory.writeMemory(address.scratch_dword, 4, value);
  define("kernel32.dll", "InterlockedIncrement", { prepare: seedDword(5), argument: [address.scratch_dword] }, { return_value: 6, last_error: 0 });
  define("kernel32.dll", "InterlockedDecrement", { prepare: seedDword(5), argument: [address.scratch_dword] }, { return_value: 4, last_error: 0 });
  define("kernel32.dll", "InterlockedExchange", { prepare: seedDword(5), argument: [address.scratch_dword, 99] }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "InterlockedExchangeAdd", { prepare: seedDword(5), argument: [address.scratch_dword, 10] }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "InterlockedCompareExchange", { prepare: seedDword(5), argument: [address.scratch_dword, 99, 5] }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "InterlockedCompareExchange", { prepare: seedDword(5), argument: [address.scratch_dword, 99, 7] }, { return_value: 5, last_error: 0 });

  // scaled arithmetic and system profile (BPTK-101 breadth)
  define("kernel32.dll", "MulDiv", argument([10, 3, 4]), { return_value: 8, last_error: 0 });
  define("kernel32.dll", "MulDiv", argument([10, 3, 0]), { return_value: unsigned(-1), last_error: 0 });
  define("kernel32.dll", "MulDiv", argument([unsigned(-10), 3, 4]), { return_value: unsigned(-8), last_error: 0 });
  define("kernel32.dll", "GetSystemInfo", argument([address.system_info]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetNativeSystemInfo", argument([address.system_info]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetSystemTime", argument([address.system_time]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetLocalTime", argument([address.system_time]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "SetErrorMode", argument([0x8000]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetErrorMode", argument([]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetErrorMode", scenario([["kernel32.dll", "SetErrorMode", [0x8000]]], []), { return_value: 0x8000, last_error: 0 });
  define("kernel32.dll", "OutputDebugStringA", { prepare: (guest) => guest.writeAnsiString(address.string_a, "trace", 16), argument: [address.string_a] }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "OutputDebugStringW", { prepare: (guest) => guest.writeWideString(address.string_a, "trace", 16), argument: [address.string_a] }, { return_value: 0, last_error: 0 });

  // environment
  define("kernel32.dll", "GetEnvironmentStringsW", argument([]), { return_value: address.heap_base, last_error: 0 });
  define("kernel32.dll", "SetEnvironmentVariableA", {
    prepare: (guest) => {
      guest.writeAnsiString(address.scratch, "PATH", 16);
      guest.writeAnsiString(address.scratch_dword, "C:\\bin", 16);
    },
    argument: [address.scratch, address.scratch_dword],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetEnvironmentVariableA", argument([address.scratch, address.scratch_dword]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "FreeEnvironmentStringsW", scenario([["kernel32.dll", "GetEnvironmentStringsW", []]], [address.heap_base]), { return_value: 1, last_error: 0 });

  // GetEnvironmentVariable / ExpandEnvironmentStrings (BPTK-101 breadth). The
  // set step seeds PATH=C:\bin, then the getter reads it back.
  const setPathStep = ["kernel32.dll", "SetEnvironmentVariableA", [address.scratch, address.scratch_dword]];
  const seedPath = (guest) => { guest.writeAnsiString(address.scratch, "PATH", 16); guest.writeAnsiString(address.scratch_dword, "C:\\bin", 16); };
  define("kernel32.dll", "GetEnvironmentVariableA", { prepare: seedPath, scenario: [setPathStep], argument: [address.scratch, address.string_dest, 64] }, { return_value: "C:\\bin".length, last_error: 0 });
  define("kernel32.dll", "GetEnvironmentVariableA", { prepare: (guest) => guest.writeAnsiString(address.scratch, "MISSING", 16), argument: [address.scratch, address.string_dest, 64] }, { return_value: 0, last_error: 203 });
  define("kernel32.dll", "GetEnvironmentVariableW", { prepare: (guest) => guest.writeWideString(address.scratch, "NOPE", 16), argument: [address.scratch, address.string_dest, 64] }, { return_value: 0, last_error: 203 });
  define("kernel32.dll", "ExpandEnvironmentStringsA", { prepare: (guest) => { seedPath(guest); guest.writeAnsiString(address.string_a, "p=%PATH%", 32); }, scenario: [setPathStep], argument: [address.string_a, address.string_dest, 64] }, { return_value: "p=C:\\bin".length + 1, last_error: 0 });
  define("kernel32.dll", "ExpandEnvironmentStringsW", { prepare: (guest) => guest.writeWideString(address.string_a, "none", 32), argument: [address.string_a, address.string_dest, 64] }, { return_value: "none".length + 1, last_error: 0 });

  // virtual drive (BPTK-015 slice)
  const savePath = 0x00156000;
  const absentPath = 0x00156100;
  const traversalPath = 0x00156200;
  const fileData = 0x00157000;
  const fileReadBack = 0x00157100;
  const fileWritten = 0x00157200;
  const keyHandlePointer = 0x00157300;
  const keyName = 0x00157400;
  const keyData = 0x00157500;
  const keyDataLength = 0x00157600;
  const fileScenario = [["kernel32.dll", "CreateFileW", [savePath, 0xc0000000, 0, 0, 2, 0, 0]]];
  const keyScenario = [["advapi32.dll", "RegCreateKeyA", [0x80000001, keyName, keyHandlePointer]]];
  define("kernel32.dll", "CreateFileW", { prepare: (guest) => guest.writeWideString(savePath, "C:\\save.dat", 64), argument: [savePath, 0xc0000000, 0, 0, 2, 0, 0] }, { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "CreateFileW", { prepare: (guest) => guest.writeWideString(absentPath, "C:\\absent.dat", 64), argument: [absentPath, 0x80000000, 0, 0, 3, 0, 0] }, { return_value: 0xffffffff, last_error: 2 });
  define("kernel32.dll", "CreateFileW", { prepare: (guest) => guest.writeWideString(traversalPath, "C:\\..\\evil.dat", 64), argument: [traversalPath, 0xc0000000, 0, 0, 2, 0, 0] }, { return_value: 0xffffffff, last_error: 87 });
  define("kernel32.dll", "WriteFile", {
    prepare: (guest) => guest.writeAnsiString(fileData, "SAVE", 16) && guest.writeWideString(savePath, "C:\\save.dat", 64),
    scenario: fileScenario,
    argument: [firstHandle, fileData, 4, fileWritten, 0],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "ReadFile", {
    prepare: (guest) => guest.writeAnsiString(fileData, "SAVE", 16) && guest.writeWideString(savePath, "C:\\save.dat", 64),
    scenario: [...fileScenario, ["kernel32.dll", "WriteFile", [firstHandle, fileData, 4, 0, 0]], ["kernel32.dll", "SetFilePointerEx", [firstHandle, 0, 0, 0, 0]]],
    argument: [firstHandle, fileReadBack, 4, fileWritten, 0],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "ReadFile", scenario([["kernel32.dll", "GetStdHandle", [-10]]], [firstHandle, fileData, 4, 0, 0]), { return_value: 0, last_error: 5 });
  define("kernel32.dll", "SetFilePointerEx", {
    prepare: (guest) => guest.writeWideString(savePath, "C:\\save.dat", 64),
    scenario: fileScenario,
    argument: [firstHandle, 1, 0xffffffff, 0, 0],
  }, { return_value: 0xffffffff, last_error: 131 });
  define("kernel32.dll", "SetEndOfFile", { prepare: (guest) => guest.writeWideString(savePath, "C:\\save.dat", 64), scenario: fileScenario, argument: [firstHandle] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FlushFileBuffers", { prepare: (guest) => guest.writeWideString(savePath, "C:\\save.dat", 64), scenario: fileScenario, argument: [firstHandle] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "CloseHandle", { prepare: (guest) => guest.writeWideString(savePath, "C:\\save.dat", 64), scenario: fileScenario, argument: [firstHandle] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "CloseHandle", argument([0xdeadbeef]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "GetFileType", { prepare: (guest) => guest.writeWideString(savePath, "C:\\save.dat", 64), scenario: fileScenario, argument: [firstHandle] }, { return_value: 3, last_error: 0 });
  define("kernel32.dll", "GetFileType", argument([0xdeadbeef]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "SetStdHandle", argument([-11, firstHandle]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetConsoleMode", scenario([["kernel32.dll", "GetStdHandle", [-11]]], [firstHandle]), { return_value: 3, last_error: 0 });
  define("kernel32.dll", "GetConsoleMode", argument([0xdeadbeef]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "GetConsoleCP", argument([]), { return_value: 1252, last_error: 0 });
  define("kernel32.dll", "ReadConsoleW", scenario([["kernel32.dll", "GetStdHandle", [-10]]], [firstHandle, fileData, 4, 0, 0]), { return_value: 0, last_error: 5 });

  // registry (advapi32, BPTK-015 slice)
  define("advapi32.dll", "RegCreateKeyA", { prepare: (guest) => guest.writeAnsiString(keyName, "Software\\BPTK", 64), argument: [0x80000001, keyName, keyHandlePointer] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegOpenKeyA", { prepare: (guest) => guest.writeAnsiString(keyName, "Software\\BPTK", 64), argument: [0x80000001, keyName, keyHandlePointer] }, { return_value: 3, last_error: 3 });
  define("advapi32.dll", "RegOpenKeyExW", { prepare: (guest) => guest.writeWideString(absentPath, "Software\\Absent", 64), argument: [0x80000001, absentPath, 0, 0, keyHandlePointer] }, { return_value: 3, last_error: 3 });
  define("advapi32.dll", "RegSetValueExA", {
    prepare: (guest) => {
      guest.writeAnsiString(keyName, "Software\\BPTK", 64);
      guest.writeAnsiString(fileData, "ok", 16);
    },
    scenario: keyScenario,
    argument: [firstHandle, fileData, 0, 1, keyData, 2],
  }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegQueryValueExA", {
    prepare: (guest) => {
      guest.writeAnsiString(keyName, "Software\\BPTK", 64);
      guest.writeAnsiString(fileData, "ok", 16);
      guest.writeAnsiString(keyData, "xxxx", 16);
      guest.memory.writeMemory(keyDataLength, 4, 64);
    },
    scenario: [...keyScenario, ["advapi32.dll", "RegSetValueExA", [firstHandle, fileData, 0, 1, keyData, 2]]],
    argument: [firstHandle, fileData, 0, 0, keyData, keyDataLength],
  }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegQueryValueExA", {
    prepare: (guest) => guest.writeAnsiString(keyName, "Software\\BPTK", 64),
    scenario: keyScenario,
    argument: [firstHandle, fileData, 0, keyDataLength, keyData, 0],
  }, { return_value: 2, last_error: 2 });
  define("advapi32.dll", "RegCloseKey", { prepare: (guest) => guest.writeAnsiString(keyName, "Software\\BPTK", 64), scenario: keyScenario, argument: [firstHandle] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegCloseKey", argument([0xdeadbeef]), { return_value: 6, last_error: 6 });

  // registry breadth and fidelity (BPTK-098)
  const prepareKeyName = (guest) => guest.writeAnsiString(keyName, "Software\\BPTK", 64);
  const setValueScenario = [...keyScenario, ["advapi32.dll", "RegSetValueExA", [firstHandle, fileData, 0, 1, keyData, 2]]];
  const prepareSetValue = (guest) => {
    prepareKeyName(guest);
    guest.writeAnsiString(fileData, "V", 16); // value name
    guest.writeAnsiString(keyData, "ok", 16);
  };
  define("advapi32.dll", "RegOpenKeyExA", { prepare: prepareKeyName, scenario: keyScenario, argument: [0x80000001, keyName, 0, 0, keyHandlePointer] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegOpenKeyExA", { prepare: (guest) => guest.writeAnsiString(absentPath, "Software\\None", 64), argument: [0x80000001, absentPath, 0, 0, keyHandlePointer] }, { return_value: 3, last_error: 3 });
  define("advapi32.dll", "RegCreateKeyExA", { prepare: prepareKeyName, argument: [0x80000001, keyName, 0, 0, 0, 0, 0, keyHandlePointer, keyDataLength] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegCreateKeyExW", { prepare: (guest) => guest.writeWideString(absentPath, "Software\\Wide", 64), argument: [0x80000001, absentPath, 0, 0, 0, 0, 0, keyHandlePointer, keyDataLength] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegSetValueExW", {
    prepare: (guest) => { prepareKeyName(guest); guest.writeWideString(absentPath, "WVal", 32); guest.writeAnsiString(keyData, "ok", 16); },
    scenario: keyScenario,
    argument: [firstHandle, absentPath, 0, 1, keyData, 2],
  }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegQueryValueExW", {
    prepare: (guest) => { prepareKeyName(guest); guest.writeWideString(absentPath, "WVal", 32); guest.writeAnsiString(keyData, "ok", 16); guest.memory.writeMemory(keyDataLength, 4, 64); },
    scenario: [...keyScenario, ["advapi32.dll", "RegSetValueExW", [firstHandle, absentPath, 0, 1, keyData, 2]]],
    argument: [firstHandle, absentPath, 0, 0, keyData, keyDataLength],
  }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegDeleteValueA", { prepare: prepareSetValue, scenario: setValueScenario, argument: [firstHandle, fileData] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegDeleteValueA", { prepare: (guest) => { prepareKeyName(guest); guest.writeAnsiString(fileData, "nope", 16); }, scenario: keyScenario, argument: [firstHandle, fileData] }, { return_value: 2, last_error: 2 });
  define("advapi32.dll", "RegDeleteValueW", {
    prepare: (guest) => { prepareKeyName(guest); guest.writeWideString(absentPath, "WVal", 32); guest.writeAnsiString(keyData, "ok", 16); },
    scenario: [...keyScenario, ["advapi32.dll", "RegSetValueExW", [firstHandle, absentPath, 0, 1, keyData, 2]]],
    argument: [firstHandle, absentPath],
  }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegDeleteKeyA", { prepare: prepareKeyName, scenario: keyScenario, argument: [0x80000001, keyName] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegDeleteKeyW", { prepare: (guest) => guest.writeWideString(absentPath, "Software\\None", 64), argument: [0x80000001, absentPath] }, { return_value: 2, last_error: 2 });
  define("advapi32.dll", "RegFlushKey", { prepare: prepareKeyName, scenario: keyScenario, argument: [firstHandle] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegFlushKey", argument([0xdeadbeef]), { return_value: 6, last_error: 6 });

  // ws2_32 Winsock lifecycle (BPTK-099). The WSADATA buffer lives at
  // startup_info, the sockaddr_in at string_b, the FIONBIO argp at scratch_dword.
  const wsaData = address.startup_info;
  const sockAddr = address.string_b;
  const startupStep = ["ws2_32.dll", "WSAStartup", [0x0202, wsaData]];
  const socketStep = ["ws2_32.dll", "socket", [2, 1, 6]];
  const writeSockAddr = (guest) => {
    guest.memory.writeMemory(sockAddr + 0, 2, 2); // AF_INET
    guest.memory.writeMemory(sockAddr + 2, 1, 0x1f); guest.memory.writeMemory(sockAddr + 3, 1, 0x90); // port 8080 network order
    [1, 2, 3, 4].forEach((octet, index) => guest.memory.writeMemory(sockAddr + 4 + index, 1, octet));
  };
  define("ws2_32.dll", "WSAStartup", argument([0x0202, wsaData]), { return_value: 0, last_error: 0 });
  define("ws2_32.dll", "WSAStartup", argument([0, wsaData]), { return_value: 10022, last_error: 0 });
  define("ws2_32.dll", "WSACleanup", argument([]), { return_value: 0, last_error: 0 });
  define("ws2_32.dll", "WSAGetLastError", argument([]), { return_value: 0, last_error: 0 });
  define("ws2_32.dll", "socket", scenario([startupStep], [2, 1, 6]), { return_value: 1, last_error: 0 });
  define("ws2_32.dll", "socket", argument([2, 1, 6]), { return_value: unsigned(-1), last_error: 0 });
  define("ws2_32.dll", "closesocket", scenario([startupStep, socketStep], [1]), { return_value: 0, last_error: 0 });
  define("ws2_32.dll", "closesocket", argument([99]), { return_value: unsigned(-1), last_error: 0 });
  define("ws2_32.dll", "bind", { prepare: writeSockAddr, scenario: [startupStep, socketStep], argument: [1, sockAddr] }, { return_value: unsigned(-1), last_error: 0 });
  define("ws2_32.dll", "connect", { prepare: writeSockAddr, scenario: [startupStep, socketStep], argument: [1, sockAddr] }, { return_value: unsigned(-1), last_error: 0 });
  define("ws2_32.dll", "send", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hi", 16), scenario: [startupStep, socketStep], argument: [1, address.string_a, 2, 0] }, { return_value: unsigned(-1), last_error: 0 });
  define("ws2_32.dll", "recv", { scenario: [startupStep, socketStep], argument: [1, address.string_a, 16, 0] }, { return_value: unsigned(-1), last_error: 0 });
  define("ws2_32.dll", "ioctlsocket", { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 1), scenario: [startupStep, socketStep], argument: [1, 0x8004667e, address.scratch_dword] }, { return_value: 0, last_error: 0 });
  define("ws2_32.dll", "htons", argument([0x1234]), { return_value: 0x3412, last_error: 0 });
  define("ws2_32.dll", "ntohs", argument([0x1234]), { return_value: 0x3412, last_error: 0 });
  define("ws2_32.dll", "htonl", argument([0x12345678]), { return_value: 0x78563412, last_error: 0 });
  define("ws2_32.dll", "ntohl", argument([0x12345678]), { return_value: 0x78563412, last_error: 0 });
  define("ws2_32.dll", "inet_addr", { prepare: (guest) => guest.writeAnsiString(address.string_a, "1.2.3.4", 16), argument: [address.string_a] }, { return_value: 0x01020304, last_error: 0 });
  define("ws2_32.dll", "inet_addr", { prepare: (guest) => guest.writeAnsiString(address.string_a, "999.1.1.1", 16), argument: [address.string_a] }, { return_value: unsigned(-1), last_error: 0 });

  // virtual drive geometry and optical volume (BPTK-102). The root path lives at
  // string_a (wide) / string_b (ansi); output buffers at string_dest.
  const driveOut = address.string_dest;
  define("kernel32.dll", "GetLogicalDrives", argument([]), { return_value: 0x0c, last_error: 0 });
  define("kernel32.dll", "GetDriveTypeW", { prepare: (guest) => guest.writeWideString(address.string_a, "C:\\", 16), argument: [address.string_a] }, { return_value: 3, last_error: 0 });
  define("kernel32.dll", "GetDriveTypeW", { prepare: (guest) => guest.writeWideString(address.string_a, "D:\\", 16), argument: [address.string_a] }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "GetDriveTypeA", { prepare: (guest) => guest.writeAnsiString(address.string_b, "E:\\", 16), argument: [address.string_b] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetVolumeInformationW", { prepare: (guest) => guest.writeWideString(address.string_a, "C:\\", 16), argument: [address.string_a, driveOut, 32, address.scratch_dword, 0, 0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetVolumeInformationA", { prepare: (guest) => guest.writeAnsiString(address.string_b, "D:\\", 16), argument: [address.string_b, driveOut, 32, address.scratch_dword, 0, 0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetDiskFreeSpaceExA", { prepare: (guest) => guest.writeAnsiString(address.string_b, "C:\\", 16), argument: [address.string_b, driveOut, driveOut + 8, driveOut + 16] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetDiskFreeSpaceA", { prepare: (guest) => guest.writeAnsiString(address.string_b, "C:\\", 16), argument: [address.string_b, driveOut, driveOut + 4, driveOut + 8, driveOut + 12] }, { return_value: 1, last_error: 0 });

  // XInput gamepad (BPTK-097): the default slot is disconnected, so the getters
  // report ERROR_DEVICE_NOT_CONNECTED; the connected path is proven in a unit
  // test that injects a controller state.
  define("xinput1_3.dll", "XInputGetState", argument([0, address.string_dest]), { return_value: 1167, last_error: 0 });
  define("xinput1_3.dll", "XInputSetState", argument([0, address.string_dest]), { return_value: 1167, last_error: 0 });
  define("xinput1_3.dll", "XInputGetCapabilities", argument([0, 0, address.string_dest]), { return_value: 1167, last_error: 0 });
  define("xinput1_3.dll", "XInputEnable", argument([1]), { return_value: 0, last_error: 0 });

  // locale, codepage, and Unicode conversion (BPTK-103 slice)
  const localePath = 0x00158000;
  const localeWide = 0x00159000;
  const localeWideSecond = 0x00159100;
  const localeTypes = 0x0015a000;
  define("kernel32.dll", "GetACP", argument([]), { return_value: 1252, last_error: 0 });
  define("kernel32.dll", "GetOEMCP", argument([]), { return_value: 1252, last_error: 0 });
  define("kernel32.dll", "IsValidCodePage", argument([1252]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "IsValidCodePage", argument([932]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetCPInfo", { prepare: (guest) => guest.memory.writeMemory(address.startup_info, 4, 0), argument: [1252, address.startup_info] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetCPInfo", argument([932, address.startup_info]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "GetUserDefaultLCID", argument([]), { return_value: 0x0409, last_error: 0 });
  define("kernel32.dll", "GetLocaleInfoW", { prepare: (guest) => guest.memory.writeMemory(address.startup_info, 4, 0), argument: [0x0409, 0x1002, localeWide, 64] }, { return_value: "United States".length + 1, last_error: 0 });
  define("kernel32.dll", "GetLocaleInfoW", argument([0x0409, 0x9999, localeWide, 64]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "CompareStringW", {
    prepare: (guest) => guest.writeWideString(localeWide, "abcd", 32) && guest.writeWideString(localeWideSecond, "abcd", 32),
    argument: [0x0409, 0, localeWide, 4, localeWideSecond, 4],
  }, { return_value: 2, last_error: 0 });
  define("kernel32.dll", "CompareStringW", {
    prepare: (guest) => guest.writeWideString(localeWide, "ABC", 32) && guest.writeWideString(localeWideSecond, "abd", 32),
    argument: [0x0409, 0x1, localeWide, 3, localeWideSecond, 3],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "LCMapStringW", {
    prepare: (guest) => guest.writeWideString(localeWide, "MiXeD", 32),
    argument: [0x0409, 0x200, localeWide, 5, localeWideSecond, 32],
  }, { return_value: 6, last_error: 0 });
  define("kernel32.dll", "LCMapStringW", {
    prepare: (guest) => guest.writeWideString(localeWide, "MiXeD", 32),
    argument: [0x0409, 0x400, localeWide, 5, localeWideSecond, 32],
  }, { return_value: 0, last_error: 87 });
  define("kernel32.dll", "GetStringTypeW", {
    prepare: (guest) => guest.writeWideString(localeWide, "Ab1 ", 32),
    argument: [1, localeWide, 4, localeTypes],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetStringTypeW", {
    prepare: (guest) => guest.writeWideString(localeWide, "Ab", 32),
    argument: [3, localeWide, 2, localeTypes],
  }, { return_value: 0, last_error: 87 });
  define("kernel32.dll", "GetTimeZoneInformation", argument([address.startup_info]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "MultiByteToWideChar", {
    prepare: (guest) => guest.writeAnsiString(address.scratch, "Hello", 32),
    argument: [65001, 0, address.scratch, 5, localeWide, 32],
  }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "MultiByteToWideChar", {
    prepare: (guest) => guest.memory.writeMemory(address.scratch, 1, 0x80),
    argument: [1252, 0, address.scratch, 1, localeWide, 32],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "MultiByteToWideChar", {
    prepare: (guest) => guest.writeAnsiString(address.scratch, "Hello", 32),
    argument: [932, 0, address.scratch, 5, localeWide, 32],
  }, { return_value: 0, last_error: 87 });
  define("kernel32.dll", "WideCharToMultiByte", {
    prepare: (guest) => guest.writeWideString(localeWide, "Hello", 32),
    argument: [1252, 0, localeWide, 5, address.scratch, 64],
  }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "WideCharToMultiByte", {
    prepare: (guest) => guest.writeWideString(localeWide, "Hello", 32),
    argument: [65001, 0, localeWide, 5, address.scratch, 4],
  }, { return_value: 0, last_error: 122 });
  define("kernel32.dll", "GetDateFormatW", {
    prepare: (guest) => {
      // SYSTEMTIME 2020-09-10 Thursday 18:40
      guest.memory.writeMemory(address.startup_info, 2, 2020);
      guest.memory.writeMemory(address.startup_info + 2, 2, 9);
      guest.memory.writeMemory(address.startup_info + 4, 2, 4);
      guest.memory.writeMemory(address.startup_info + 6, 2, 10);
    },
    argument: [0x0409, 0, address.startup_info, 0, localeWide, 64],
  }, { return_value: "9/10/2020".length + 1, last_error: 0 });
  define("kernel32.dll", "GetTimeFormatW", {
    prepare: (guest) => {
      guest.memory.writeMemory(address.startup_info, 2, 2020);
      guest.memory.writeMemory(address.startup_info + 8, 2, 18);
      guest.memory.writeMemory(address.startup_info + 10, 2, 40);
      guest.memory.writeMemory(address.startup_info + 12, 2, 5);
    },
    argument: [0x0409, 0, address.startup_info, 0, localeWide, 64],
  }, { return_value: "18:40:05".length + 1, last_error: 0 });

  // module loading and memory/time probe (BPTK-010 slice)
  const dllName = 0x0015c000;
  const timeFields = 0x0015d000;
  define("kernel32.dll", "LoadLibraryA", { prepare: (guest) => guest.writeAnsiString(dllName, "kernel32.dll", 32), argument: [dllName] }, { return_value: 0x00020002, last_error: 0 });
  define("kernel32.dll", "LoadLibraryA", { prepare: (guest) => guest.writeAnsiString(dllName, "evil.dll", 32), argument: [dllName] }, { return_value: 0, last_error: 126 });
  // A served system DLL loads by its full path (the guest builds a
  // system-directory-prefixed name): the Windows basename resolves the module.
  define("kernel32.dll", "LoadLibraryA", { prepare: (guest) => guest.writeAnsiString(dllName, "C:\\Windows\\System32\\ws2_32.dll", 64), argument: [dllName] }, { return_value: 0x00020006, last_error: 0 });
  define("kernel32.dll", "LoadLibraryA", { prepare: (guest) => guest.writeAnsiString(dllName, "C:\\Windows\\System32\\comctl32.dll", 64), argument: [dllName] }, { return_value: 0x00020007, last_error: 0 });
  define("kernel32.dll", "LoadLibraryW", { prepare: (guest) => guest.writeWideString(localeWide, "ole32.dll", 32), argument: [localeWide] }, { return_value: 0x00020003, last_error: 0 });
  define("kernel32.dll", "LoadLibraryExW", {
    prepare: (guest) => guest.writeWideString(localeWide, "kernel32.dll", 32),
    argument: [localeWide, 0, 8],
  }, { return_value: 0x00020002, last_error: 0 });
  define("kernel32.dll", "LoadLibraryExW", {
    prepare: (guest) => guest.writeWideString(localeWide, "kernel32.dll", 32),
    argument: [localeWide, 0, 0x100],
  }, { return_value: 0, last_error: 87 });
  define("kernel32.dll", "FreeLibrary", argument([0x00020002]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FreeLibrary", argument([0x00020001]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "IsBadReadPtr", argument([address.scratch, 16]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "IsBadReadPtr", argument([0x00800000, 16]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "IsBadReadPtr", argument([address.scratch, 0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "Sleep", argument([500]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetTickCount", scenario([["kernel32.dll", "Sleep", [500]]], []), { return_value: 500, last_error: 0 });
  define("kernel32.dll", "GetThreadTimes", { prepare: (guest) => guest.memory.writeMemory(timeFields, 8, 0), argument: [0xfffffffe, timeFields, 0, 0, timeFields + 8] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetThreadTimes", argument([0xdeadbeef, 0, 0, 0, 0]), { return_value: 0, last_error: 6 });

  // synchronization objects, process, enumeration, winmm timer
  const eventPath = 0x0015f000;
  const findPattern = 0x0015f100;
  const findData = 0x0015f200;
  define("kernel32.dll", "CreateEventW", argument([0, 0, 1, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "CreateEventW", argument([0, 0, 1, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "SetEvent", scenario([["kernel32.dll", "CreateEventW", [0, 0, 0, 0]]], [firstHandle]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "ResetEvent", {
    prepare: (guest) => guest.writeWideString(eventPath, "evt", 16),
    scenario: [["kernel32.dll", "CreateEventW", [0, 0, 1, eventPath]]],
    argument: [firstHandle],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "WaitForSingleObject", scenario([["kernel32.dll", "CreateEventW", [0, 0, 1, 0]]], [firstHandle, 0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "WaitForSingleObject", {
    prepare: (guest) => guest.writeWideString(eventPath, "evt", 16),
    scenario: [["kernel32.dll", "CreateEventW", [0, 0, 0, eventPath]]],
    argument: [firstHandle, 100],
  }, { return_value: 0x102, last_error: 0 });
  define("kernel32.dll", "WaitForSingleObjectEx", {
    prepare: (guest) => guest.writeWideString(eventPath, "evt", 16),
    scenario: [["kernel32.dll", "CreateEventW", [0, 0, 0, eventPath]]],
    argument: [firstHandle, 0, 1],
  }, { return_value: 0x102, last_error: 0 });
  define("kernel32.dll", "WaitForSingleObject", argument([0xdeadbeef, 0]), { return_value: 0xffffffff, last_error: 6 });
  define("kernel32.dll", "OpenProcess", argument([0, 0, hleProfile.process_id]), { return_value: 0xffffffff, last_error: 0 });
  define("kernel32.dll", "OpenProcess", argument([0, 0, 777]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "IsValidLocale", argument([0x0409, 0]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "IsValidLocale", argument([0x0411, 0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "FindFirstFileExA", {
    prepare: (guest) => guest.writeAnsiString(findPattern, "C:\\*", 32) && guest.writeWideString(savePath, "C:\\save.dat", 64),
    scenario: [["kernel32.dll", "CreateFileW", [savePath, 0xc0000000, 0, 0, 2, 0, 0]]],
    argument: [findPattern, 0, findData, 0, 0, 0],
  }, { return_value: 0x00010001, last_error: 0 });
  define("kernel32.dll", "FindFirstFileExA", {
    prepare: (guest) => guest.writeAnsiString(findPattern, "C:\\nothing\\*", 32),
    argument: [findPattern, 0, findData, 0, 0, 0],
  }, { return_value: 0xffffffff, last_error: 3 });
  define("kernel32.dll", "FindNextFileA", {
    prepare: (guest) => {
      guest.writeAnsiString(findPattern, "C:\\*", 32);
      guest.writeWideString(savePath, "C:\\save.dat", 64);
      guest.writeWideString(absentPath, "C:\\other.dat", 64);
    },
    scenario: [
      ["kernel32.dll", "CreateFileW", [savePath, 0xc0000000, 0, 0, 2, 0, 0]],
      ["kernel32.dll", "CreateFileW", [absentPath, 0xc0000000, 0, 0, 2, 0, 0]],
      ["kernel32.dll", "FindFirstFileExA", [findPattern, 0, findData, 0, 0, 0]],
    ],
    argument: [0x00010002, findData],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FindNextFileA", {
    prepare: (guest) => {
      guest.writeAnsiString(findPattern, "C:\\*", 32);
      guest.writeWideString(savePath, "C:\\save.dat", 64);
    },
    scenario: [
      ["kernel32.dll", "CreateFileW", [savePath, 0xc0000000, 0, 0, 2, 0, 0]],
      ["kernel32.dll", "FindFirstFileExA", [findPattern, 0, findData, 0, 0, 0]],
    ],
    argument: [0x00010001, findData],
  }, { return_value: 0, last_error: 2 });
  define("winmm.dll", "timeGetTime", argument([]), { return_value: 0, last_error: 0 });
  define("winmm.dll", "timeBeginPeriod", argument([4]), { return_value: 0, last_error: 0 });
  define("winmm.dll", "timeBeginPeriod", argument([0]), { return_value: 2, last_error: 2 });
  define("winmm.dll", "timeEndPeriod", scenario([["winmm.dll", "timeBeginPeriod", [4]]], [4]), { return_value: 0, last_error: 0 });
  define("winmm.dll", "timeEndPeriod", argument([9]), { return_value: 2, last_error: 0 });
  define("winmm.dll", "timeKillEvent", argument([0]), { return_value: 0, last_error: 0 });

  // COM apartment (ole32)
  define("ole32.dll", "CoInitializeEx", argument([0, 2]), { return_value: 0, last_error: 0 });
  define("ole32.dll", "CoInitializeEx", scenario([["ole32.dll", "CoInitializeEx", [0, 2]]], [0, 2]), { return_value: 1, last_error: 0 });
  define("ole32.dll", "CoInitializeEx", scenario([["ole32.dll", "CoInitializeEx", [0, 2]]], [0, 0]), { return_value: 0x80010106, last_error: 0 });
  define("ole32.dll", "CoUninitialize", argument([]), { return_value: 0, last_error: 0 });
  define("ole32.dll", "CoCreateInstance", argument([address.version_info, 0, 1, address.scratch_dword, address.startup_info]), { return_value: 0x80040154, last_error: 0 });

  // --- USER32 windowing/input (BPTK-011) ------------------------------------
  // The window class struct lives at startup_info, its name at scratch_wide.
  // Fresh guest memory is zero-initialized, so only the class-name pointer and
  // the name string need writing; the first window handle and class atom are
  // deterministic on the fresh machine.
  const windowClassStruct = address.startup_info;
  const windowClassName = address.scratch_wide;
  const firstWindow = 0x00010010;
  const firstAtom = 0xc000;
  const registerPrepare = (guest) => {
    guest.writeWideString(windowClassName, "AppClass", 32);
    guest.memory.writeMemory(windowClassStruct + 36, 4, windowClassName); // WNDCLASSW.lpszClassName
  };
  const registerExPrepare = (guest) => {
    guest.writeWideString(windowClassName, "AppClass", 32);
    guest.memory.writeMemory(windowClassStruct + 40, 4, windowClassName); // WNDCLASSEXW.lpszClassName
  };
  const registerStep = ["user32.dll", "RegisterClassW", [windowClassStruct]];
  const createArgument = [0, windowClassName, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  const createStep = ["user32.dll", "CreateWindowExW", createArgument];
  const showStep = ["user32.dll", "ShowWindow", [firstWindow, 1]];

  define("user32.dll", "RegisterClassW", { prepare: registerPrepare, argument: [windowClassStruct] }, { return_value: firstAtom, last_error: 0 });
  define("user32.dll", "RegisterClassExW", { prepare: registerExPrepare, argument: [windowClassStruct] }, { return_value: firstAtom, last_error: 0 });
  define("user32.dll", "UnregisterClassW", { prepare: registerPrepare, scenario: [registerStep], argument: [windowClassName] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "CreateWindowExW", { prepare: registerPrepare, scenario: [registerStep], argument: createArgument }, { return_value: firstWindow, last_error: 0 });
  define("user32.dll", "DestroyWindow", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "DefWindowProcW", argument([0, 0, 0, 0]), { return_value: 0, last_error: 0 });
  define("user32.dll", "ShowWindow", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow, 1] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "UpdateWindow", { prepare: registerPrepare, scenario: [registerStep, createStep, showStep], argument: [firstWindow] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "PostMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow, 0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "SendMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow, 0, 0, 0] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "PostQuitMessage", argument([0]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetActiveWindow", { prepare: registerPrepare, scenario: [registerStep, createStep, showStep], argument: [] }, { return_value: firstWindow, last_error: 0 });
  define("user32.dll", "GetFocus", { prepare: registerPrepare, scenario: [registerStep, createStep, showStep], argument: [] }, { return_value: firstWindow, last_error: 0 });
  define("user32.dll", "IsWindow", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow] }, { return_value: 1, last_error: 0 });

  // message loop (BPTK-011): the MSG buffer lives at scratch, the RECT buffer
  // at string_a; the window class registration is the shared scenario head.
  const msgBuffer = address.scratch;
  const rectBuffer = address.string_a;
  const postStep = ["user32.dll", "PostMessageW", [firstWindow, 0x400, 1, 2]];
  define("user32.dll", "GetMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep, postStep], argument: [msgBuffer, 0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "GetMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep, ["user32.dll", "PostQuitMessage", [0]]], argument: [msgBuffer, 0, 0, 0] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "GetMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [msgBuffer, 0, 0, 0] }, { return_value: unsigned(-1), last_error: 0 });
  define("user32.dll", "PeekMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep, postStep], argument: [msgBuffer, 0, 0, 0, 1] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "PeekMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [msgBuffer, 0, 0, 0, 1] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "TranslateMessage", { prepare: (guest) => { guest.memory.writeMemory(msgBuffer + 4, 4, 0x0100); guest.memory.writeMemory(msgBuffer + 8, 4, 0x41); }, scenario: [registerStep, createStep], argument: [msgBuffer] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "TranslateMessage", { prepare: (guest) => guest.memory.writeMemory(msgBuffer + 4, 4, 0x0000), argument: [msgBuffer] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "DispatchMessageW", { prepare: (guest) => { guest.memory.writeMemory(msgBuffer + 0, 4, firstWindow); guest.memory.writeMemory(msgBuffer + 4, 4, 0x0000); }, scenario: [registerStep, createStep], argument: [msgBuffer] }, { return_value: 0, last_error: 0 });

  // window geometry and system metrics (BPTK-011)
  define("user32.dll", "GetClientRect", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow, rectBuffer] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "GetWindowRect", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow, rectBuffer] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "GetClientRect", argument([0xdeadbeef, rectBuffer]), { return_value: 0, last_error: 0 });
  define("user32.dll", "MoveWindow", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow, 10, 20, 100, 200, 1] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "AdjustWindowRect", argument([rectBuffer, 0, 0]), { return_value: 1, last_error: 0 });
  define("user32.dll", "GetSystemMetrics", argument([0]), { return_value: 1920, last_error: 0 });
  define("user32.dll", "GetSystemMetrics", argument([1]), { return_value: 1080, last_error: 0 });
  define("user32.dll", "GetSystemMetrics", argument([99]), { return_value: 0, last_error: 0 });

  // comctl32 common-control init (the GUI startup slice PuTTY reaches on its way
  // to opening its configuration dialog).
  define("comctl32.dll", "InitCommonControls", argument([]), { return_value: 0, last_error: 0 });
  define("comctl32.dll", "InitCommonControlsEx", argument([address.scratch]), { return_value: 1, last_error: 0 });

  // --- GDI32 2D surface (BPTK-012) ------------------------------------------
  // The first DC and the first object are deterministic on the fresh machine.
  const firstDc = 0x00040000;
  const secondDc = 0x00040004;
  const dcStep = ["gdi32.dll", "CreateCompatibleDC", [0]];
  const dc2Step = ["gdi32.dll", "CreateCompatibleDC", [0]];
  const brushStep = ["gdi32.dll", "CreateSolidBrush", [0x000908]];
  const whiteBrush = 0x80000000;

  define("gdi32.dll", "CreateCompatibleDC", argument([0]), { return_value: firstDc, last_error: 0 });
  define("gdi32.dll", "DeleteDC", scenario([dcStep], [firstDc]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "GetStockObject", argument([0]), { return_value: whiteBrush, last_error: 0 });
  define("gdi32.dll", "CreateSolidBrush", argument([0x000908]), { return_value: firstDc, last_error: 0 });
  define("gdi32.dll", "CreatePen", argument([0, 1, 0]), { return_value: firstDc, last_error: 0 });
  define("gdi32.dll", "DeleteObject", scenario([brushStep], [firstDc]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "SelectObject", scenario([dcStep, brushStep], [firstDc, secondDc]), { return_value: whiteBrush, last_error: 0 });
  define("gdi32.dll", "Rectangle", scenario([dcStep], [firstDc, 0, 0, 1, 1]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "MoveToEx", scenario([dcStep], [firstDc, 0, 0, 0]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "LineTo", scenario([dcStep, ["gdi32.dll", "MoveToEx", [firstDc, 0, 0, 0]]], [firstDc, 0, 0]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "TextOutW", { prepare: (guest) => guest.memory.writeMemory(address.scratch_wide, 2, 0x41), scenario: [dcStep], argument: [firstDc, 0, 0, address.scratch_wide, 1] }, { return_value: 1, last_error: 0 });
  define("gdi32.dll", "SetTextColor", scenario([dcStep], [firstDc, 0x090807]), { return_value: 0, last_error: 0 });
  define("gdi32.dll", "SetBkColor", scenario([dcStep], [firstDc, 0x090807]), { return_value: 0xffffff, last_error: 0 });
  define("gdi32.dll", "SetBkMode", scenario([dcStep], [firstDc, 1]), { return_value: 2, last_error: 0 });
  define("gdi32.dll", "SetPixel", scenario([dcStep], [firstDc, 0, 0, 0x090807]), { return_value: 0x090807, last_error: 0 });
  define("gdi32.dll", "GetPixel", scenario([dcStep, ["gdi32.dll", "SetPixel", [firstDc, 0, 0, 0x090807]]], [firstDc, 0, 0]), { return_value: 0x090807, last_error: 0 });
  define("gdi32.dll", "BitBlt", scenario([dcStep, dc2Step], [firstDc, 0, 0, 1, 1, secondDc, 0, 0, 0x00cc0020]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "StretchBlt", scenario([dcStep, dc2Step], [firstDc, 0, 0, 1, 1, secondDc, 0, 0, 1, 1, 0x00cc0020]), { return_value: 1, last_error: 0 });

  // A LOGPALETTE with two entries lives at startup_info: palVersion (WORD),
  // palNumEntries (WORD), then the PALETTEENTRY records.
  const palettePrepare = (guest) => {
    guest.memory.writeMemory(windowClassStruct + 0, 2, 0x300); // palVersion
    guest.memory.writeMemory(windowClassStruct + 2, 2, 2); // palNumEntries
    guest.memory.writeMemory(windowClassStruct + 4, 4, 0x00000000); // entry 0: black
    guest.memory.writeMemory(windowClassStruct + 8, 4, 0x000000ff); // entry 1: red (peRed=0xff)
  };
  const createPaletteStep = ["gdi32.dll", "CreatePalette", [windowClassStruct]];
  define("gdi32.dll", "CreatePalette", { prepare: palettePrepare, argument: [windowClassStruct] }, { return_value: firstDc, last_error: 0 });
  define("gdi32.dll", "SelectPalette", { prepare: palettePrepare, scenario: [dcStep, createPaletteStep], argument: [firstDc, secondDc, 0] }, { return_value: 0, last_error: 0 });
  define("gdi32.dll", "RealizePalette", { prepare: palettePrepare, scenario: [dcStep, createPaletteStep, ["gdi32.dll", "SelectPalette", [firstDc, secondDc, 0]]], argument: [firstDc] }, { return_value: 2, last_error: 0 });
  define("gdi32.dll", "GetNearestPaletteIndex", { prepare: palettePrepare, scenario: [createPaletteStep], argument: [firstDc, 0x0a0afa] }, { return_value: 1, last_error: 0 });

  // rect fill, pattern blit, raster op, device caps (BPTK-012). The RECT lives
  // at string_a; the brush created after the DC is the second handle.
  const gdiRectBuffer = address.string_a;
  const writeRect0011 = (guest) => {
    guest.memory.writeMemory(gdiRectBuffer + 0, 4, 0);
    guest.memory.writeMemory(gdiRectBuffer + 4, 4, 0);
    guest.memory.writeMemory(gdiRectBuffer + 8, 4, 1);
    guest.memory.writeMemory(gdiRectBuffer + 12, 4, 1);
  };
  define("gdi32.dll", "FillRect", { prepare: writeRect0011, scenario: [dcStep, brushStep], argument: [firstDc, gdiRectBuffer, secondDc] }, { return_value: 1, last_error: 0 });
  define("gdi32.dll", "PatBlt", scenario([dcStep], [firstDc, 0, 0, 1, 1, 0x00f00021]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "GetDeviceCaps", argument([0, 8]), { return_value: 1920, last_error: 0 });
  define("gdi32.dll", "GetDeviceCaps", argument([0, 12]), { return_value: 32, last_error: 0 });
  define("gdi32.dll", "GetDeviceCaps", argument([0, 999]), { return_value: 0, last_error: 0 });
  define("gdi32.dll", "SetROP2", scenario([dcStep], [firstDc, 16]), { return_value: 13, last_error: 0 });
  define("gdi32.dll", "GetROP2", scenario([dcStep], [firstDc]), { return_value: 13, last_error: 0 });

  // --- Plink import-surface widening (BPTK-146) ------------------------------
  // One case per widened export: the ANSI file surface and kernel objects over
  // the same bounded state as their siblings, and the honest refusals whose
  // documented last error names why the confined probe cannot serve them.
  const writeName = (name) => (guest) => guest.writeAnsiString(address.scratch, name, 64);
  const createFileAStep = ["kernel32.dll", "CreateFileA", [address.scratch, 0xc0000000, 0, 0, 2, 0, 0]];
  const stdOutStep = ["kernel32.dll", "GetStdHandle", [-11]];
  define("kernel32.dll", "CreateFileA", { prepare: writeName("C:\\a.dat"), argument: [address.scratch, 0xc0000000, 0, 0, 2, 0, 0] }, { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "DeleteFileA", { prepare: writeName("C:\\a.dat"), argument: [address.scratch] }, { return_value: 0, last_error: 2 });
  define("kernel32.dll", "FindFirstFileA", { prepare: writeName("C:\\a.dat"), scenario: [createFileAStep], argument: [address.scratch, address.string_dest] }, { return_value: firstHandle + 1, last_error: 0 });
  define("kernel32.dll", "FindClose", argument([0xdeadbeef]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "GetFileAttributesExA", { prepare: writeName("C:\\"), argument: [address.scratch, 0, address.string_dest] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "LoadLibraryExA", { prepare: writeName("kernel32.dll"), argument: [address.scratch, 0, 0] }, { return_value: kernel32Module, last_error: 0 });
  define("kernel32.dll", "CreateEventA", argument([0, 1, 0, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "CreateMutexA", argument([0, 1, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "ReleaseMutex", scenario([["kernel32.dll", "CreateMutexA", [0, 1, 0]]], [firstHandle]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "CreateFileMappingA", argument([0xffffffff, 0, 4, 0, 4096, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "MapViewOfFile", argument([0xdeadbeef, 0, 0, 0, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "UnmapViewOfFile", argument([0x00400000]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "CreatePipe", argument([address.string_dest, address.string_dest + 4, 0, 0]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetWindowsDirectoryA", argument([address.string_dest, 260]), { return_value: 10, last_error: 0 });
  define("kernel32.dll", "GlobalMemoryStatus", argument([address.string_dest]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetProcessTimes", argument([0xffffffff, address.string_dest, address.string_dest + 8, address.string_dest + 16, address.string_dest + 24]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "LocalAlloc", argument([0x40, 16]), { return_value: address.heap_first_block, last_error: 0 });
  define("kernel32.dll", "LocalFree", scenario([["kernel32.dll", "LocalAlloc", [0x40, 16]]], [address.heap_first_block]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "LocalFileTimeToFileTime", { prepare: (guest) => guest.memory.writeBlock(address.string_dest, Buffer.alloc(8, 0x11)), argument: [address.string_dest, address.string_dest + 8] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetConsoleMode", scenario([stdOutStep], [firstHandle, 3]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetHandleInformation", scenario([stdOutStep], [firstHandle, 1, 0]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FormatMessageA", argument([0x1000, 0, 2, 0, address.string_dest, 260, 0]), { return_value: formatSystemMessage(2).length, last_error: 0 });
  define("kernel32.dll", "GetOverlappedResult", argument([0xdeadbeef, address.string_dest, address.string_dest + 8, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "UnhandledExceptionFilter", argument([address.string_dest]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "RtlUnwind", argument([0, 0, 0, 0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "EnumSystemLocalesW", argument([0x00401000, 0]), { return_value: 0, last_error: 120 });
  define("kernel32.dll", "CreateThread", argument([0, 0, 0x00401000, 0, 0, address.string_dest]), { return_value: 0, last_error: 164 });
  define("kernel32.dll", "CreateProcessA", { prepare: writeName("C:\\x.exe"), argument: [0, address.scratch, 0, 0, 0, 0, 0, 0, address.string_dest, address.string_dest + 16] }, { return_value: 0, last_error: 5 });
  define("kernel32.dll", "CreateNamedPipeA", { prepare: writeName("\\\\.\\pipe\\x"), argument: [address.scratch, 0, 0, 0, 0, 0, 0, 0] }, { return_value: 0xffffffff, last_error: 120 });
  define("kernel32.dll", "ConnectNamedPipe", argument([0xdeadbeef, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "WaitNamedPipeA", { prepare: writeName("\\\\.\\pipe\\x"), argument: [address.scratch, 0] }, { return_value: 0, last_error: 2 });
  define("kernel32.dll", "GetCommState", argument([0xdeadbeef, address.string_dest]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "SetCommState", argument([0xdeadbeef, address.string_dest]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "SetCommTimeouts", argument([0xdeadbeef, address.string_dest]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "SetCommBreak", argument([0xdeadbeef]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "ClearCommBreak", argument([0xdeadbeef]), { return_value: 0, last_error: 6 });

  const writeSid = (base) => (guest) => {
    guest.memory.writeBlock(base, Buffer.alloc(12));
    guest.memory.writeMemory(base, 1, 1); // Revision
    guest.memory.writeMemory(base + 1, 1, 1); // SubAuthorityCount
  };
  define("advapi32.dll", "GetLengthSid", { prepare: writeSid(address.scratch), argument: [address.scratch] }, { return_value: 12, last_error: 0 });
  define("advapi32.dll", "CopySid", { prepare: writeSid(address.scratch), argument: [64, address.string_dest, address.scratch] }, { return_value: 1, last_error: 0 });
  define("advapi32.dll", "EqualSid", { prepare: (guest) => { writeSid(address.string_a)(guest); writeSid(address.string_b)(guest); }, argument: [address.string_a, address.string_b] }, { return_value: 1, last_error: 0 });
  define("advapi32.dll", "AllocateAndInitializeSid", { prepare: (guest) => guest.memory.writeBlock(address.scratch, Buffer.from([0, 0, 0, 0, 0, 5])), argument: [address.scratch, 1, 0x20, 0, 0, 0, 0, 0, 0, 0, address.string_dest] }, { return_value: 1, last_error: 0 });
  define("advapi32.dll", "GetUserNameA", { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 64), argument: [address.string_dest, address.scratch_dword] }, { return_value: 1, last_error: 0 });
  define("advapi32.dll", "InitializeSecurityDescriptor", argument([address.string_dest, 1]), { return_value: 1, last_error: 0 });
  const initSdStep = ["advapi32.dll", "InitializeSecurityDescriptor", [address.string_dest, 1]];
  define("advapi32.dll", "SetSecurityDescriptorDacl", scenario([initSdStep], [address.string_dest, 1, 0, 0]), { return_value: 1, last_error: 0 });
  define("advapi32.dll", "SetSecurityDescriptorOwner", scenario([initSdStep], [address.string_dest, address.scratch, 0]), { return_value: 1, last_error: 0 });

  define("user32.dll", "FindWindowA", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetCapture", argument([]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetClipboardOwner", argument([]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetForegroundWindow", argument([]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetQueueStatus", argument([0x1ff]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetCursorPos", argument([address.string_dest]), { return_value: 1, last_error: 0 });
  define("user32.dll", "MsgWaitForMultipleObjects", argument([0, 0, 0, 0, 0x1ff]), { return_value: 0x102, last_error: 0 });
  define("user32.dll", "PeekMessageA", argument([address.string_dest, 0, 0, 0, 1]), { return_value: 0, last_error: 0 });
  define("user32.dll", "SendMessageA", argument([0xdeadbeef, 0, 0, 0]), { return_value: 0, last_error: 0 });

  // --- CRT breadth reached past the SDL layer (lane W) ----------------------
  // The telemetry no-ops, the ucrt standard-stream accessor, and the stdio
  // startup/format helpers a ucrt game (Dwarf Fortress) reaches on its way from
  // the SDL init through the CRT into its own main.
  const iobSlot0 = crtRuntimeCell.iobBase;
  define("vcruntime140.dll", "__telemetry_main_invoke_trigger", argument([0]), { return_value: 0, last_error: 0 });
  define("vcruntime140.dll", "__telemetry_main_return_trigger", argument([0]), { return_value: 0, last_error: 0 });
  for (const library of ["api-ms-win-crt-stdio-l1-1-0.dll", "msvcrt.dll"]) {
    define(library, "__acrt_iob_func", argument([1]), { return_value: iobSlot0 + FILE_STRUCT_BYTE, last_error: 0 });
    define(library, "freopen", argument([0, 0, iobSlot0]), { return_value: iobSlot0, last_error: 0 });
    define(library, "setvbuf", argument([iobSlot0, 0, 0, 0]), { return_value: 0, last_error: 0 });
    define(library, "setbuf", argument([iobSlot0, 0]), { return_value: 0, last_error: 0 });
    define(library, "__stdio_common_vfprintf", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hi", 8), argument: [0, iobSlot0 + FILE_STRUCT_BYTE, address.string_a, 0, 0] }, { return_value: 2, last_error: 0 });
    define(library, "__stdio_common_vsprintf", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hi", 8), argument: [0, address.string_dest, 16, address.string_a, 0, 0] }, { return_value: 2, last_error: 0 });
    define(library, "__stdio_common_vsprintf_s", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hi", 8), argument: [0, address.string_dest, 16, address.string_a, 0, 0] }, { return_value: 2, last_error: 0 });
  }

  // --- SDL (lane W): one case per served export -----------------------------
  // The SDL subsystem allocates opaque handles from a fixed base (0x53000000, +0x10
  // each) and its SDL_Surface/SDL_PixelFormat records from a fixed region anchored
  // at the arena top (below the CRT scratch pages), so both are deterministic on a
  // fresh isolated machine and the expected value is pinned exactly.
  const sdlHandle0 = 0x53000000;
  const sdlHandle1 = 0x53000010;
  const sdlStruct0 = 0x00300000 - 0x10000; // arena_base(0x100000)+arena_size(0x200000)-0x10000
  const sdlFormat0 = sdlStruct0 + 0x60; // after the 96-byte surface record
  const sdlStruct1 = sdlStruct0 + 0xa0; // after the first surface record + its format
  const atomicCell = address.scratch_dword;
  const surfaceMask = [0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000];
  const rgbSurfaceInput = [0, 4, 4, 32, ...surfaceMask];
  const rgbSurfaceStep = (library) => [library, "SDL_CreateRGBSurface", rgbSurfaceInput];

  // The symbols SDL 1.2 (sdl.dll) and SDL 2 (sdl2.dll) both export, with
  // identical behavior; each is pinned under both libraries.
  for (const library of ["sdl.dll", "sdl2.dll"]) {
    const createSemStep = [library, "SDL_CreateSemaphore", [3]];
    const createMutexStep = [library, "SDL_CreateMutex", []];
    define(library, "SDL_Init", argument([0x20]), { return_value: 0, last_error: 0 });
    define(library, "SDL_InitSubSystem", argument([0x20]), { return_value: 0, last_error: 0 });
    define(library, "SDL_QuitSubSystem", argument([0x20]), { return_value: 0, last_error: 0 });
    define(library, "SDL_Quit", argument([]), { return_value: 0, last_error: 0 });
    define(library, "SDL_WasInit", argument([0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_GetError", argument([]), { return_value: sdlStruct0, last_error: 0 });
    define(library, "SDL_SetError", { prepare: (guest) => guest.writeAnsiString(address.string_a, "x", 4), argument: [address.string_a] }, { return_value: 0xffffffff, last_error: 0 });
    define(library, "SDL_ClearError", argument([]), { return_value: 0, last_error: 0 });
    define(library, "SDL_GetTicks", argument([]), { return_value: 0, last_error: 0 });
    define(library, "SDL_Delay", argument([5]), { return_value: 0, last_error: 0 });
    define(library, "SDL_CreateSemaphore", argument([3]), { return_value: sdlHandle0, last_error: 0 });
    define(library, "SDL_SemWait", scenario([createSemStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_SemTryWait", scenario([createSemStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_SemPost", scenario([createSemStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_SemValue", scenario([createSemStep], [sdlHandle0]), { return_value: 3, last_error: 0 });
    define(library, "SDL_DestroySemaphore", scenario([createSemStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_CreateMutex", argument([]), { return_value: sdlHandle0, last_error: 0 });
    define(library, "SDL_LockMutex", scenario([createMutexStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_UnlockMutex", scenario([createMutexStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_DestroyMutex", scenario([createMutexStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_CreateThread", argument([0, 0, 0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_WaitThread", argument([0, 0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_AtomicSet", { prepare: (guest) => guest.memory.writeMemory(atomicCell, 4, 5), argument: [atomicCell, 9] }, { return_value: 5, last_error: 0 });
    define(library, "SDL_AtomicGet", { prepare: (guest) => guest.memory.writeMemory(atomicCell, 4, 7), argument: [atomicCell] }, { return_value: 7, last_error: 0 });
    define(library, "SDL_AtomicAdd", { prepare: (guest) => guest.memory.writeMemory(atomicCell, 4, 4), argument: [atomicCell, 3] }, { return_value: 4, last_error: 0 });
    define(library, "SDL_AtomicCAS", { prepare: (guest) => guest.memory.writeMemory(atomicCell, 4, 8), argument: [atomicCell, 8, 20] }, { return_value: 1, last_error: 0 });
    define(library, "SDL_CreateRGBSurface", argument(rgbSurfaceInput), { return_value: sdlStruct0, last_error: 0 });
    define(library, "SDL_CreateRGBSurfaceFrom", argument([atomicCell, 4, 4, 32, 16, ...surfaceMask]), { return_value: sdlStruct0, last_error: 0 });
    define(library, "SDL_FreeSurface", scenario([rgbSurfaceStep(library)], [sdlStruct0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_LockSurface", scenario([rgbSurfaceStep(library)], [sdlStruct0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_UnlockSurface", scenario([rgbSurfaceStep(library)], [sdlStruct0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_FillRect", scenario([rgbSurfaceStep(library)], [sdlStruct0, 0, 0x00ff0000]), { return_value: 0, last_error: 0 });
    define(library, "SDL_MapRGB", scenario([rgbSurfaceStep(library)], [sdlFormat0, 0x11, 0x22, 0x33]), { return_value: 0xff112233, last_error: 0 });
    define(library, "SDL_MapRGBA", scenario([rgbSurfaceStep(library)], [sdlFormat0, 0x11, 0x22, 0x33, 0x44]), { return_value: 0x44112233, last_error: 0 });
    define(library, "SDL_GetRGBA", scenario([rgbSurfaceStep(library)], [0xff112233, sdlFormat0, address.string_dest, address.string_dest + 1, address.string_dest + 2, address.string_dest + 3]), { return_value: 0, last_error: 0 });
    define(library, "SDL_UpperBlit", scenario([rgbSurfaceStep(library), rgbSurfaceStep(library)], [sdlStruct0, 0, sdlStruct1, 0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_SetColorKey", scenario([rgbSurfaceStep(library)], [sdlStruct0, 1, 0x00ff0000]), { return_value: 0, last_error: 0 });
    define(library, "SDL_PollEvent", argument([address.string_dest]), { return_value: 0, last_error: 0 });
    define(library, "SDL_PeepEvents", argument([0, 0, 0, 0, 0, 0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_PumpEvents", argument([]), { return_value: 0, last_error: 0 });
    define(library, "SDL_WaitEvent", argument([address.string_dest]), { return_value: 0, last_error: 0 });
    define(library, "SDL_GetMouseState", argument([0, 0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_GetModState", argument([]), { return_value: 0, last_error: 0 });
    define(library, "SDL_NumJoysticks", argument([]), { return_value: 0, last_error: 0 });
    define(library, "SDL_ShowCursor", argument([1]), { return_value: 1, last_error: 0 });
  }

  // SDL 1.2 (sdl.dll) video + helper surface.
  define("sdl.dll", "SDL_SetVideoMode", argument([8, 4, 32, 0]), { return_value: sdlStruct0, last_error: 0 });
  define("sdl.dll", "SDL_GetVideoSurface", scenario([["sdl.dll", "SDL_SetVideoMode", [8, 4, 32, 0]]], []), { return_value: sdlStruct0, last_error: 0 });
  define("sdl.dll", "SDL_Flip", scenario([["sdl.dll", "SDL_SetVideoMode", [8, 4, 32, 0]]], [sdlStruct0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_UpdateRect", scenario([["sdl.dll", "SDL_SetVideoMode", [8, 4, 32, 0]]], [sdlStruct0, 0, 0, 8, 4]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_WM_SetCaption", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_WM_SetIcon", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_EnableUNICODE", argument([1]), { return_value: 1, last_error: 0 });
  define("sdl.dll", "SDL_EnableKeyRepeat", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_GetAppState", argument([]), { return_value: 0x03, last_error: 0 });
  define("sdl.dll", "SDL_DisplayFormat", scenario([rgbSurfaceStep("sdl.dll")], [sdlStruct0]), { return_value: sdlStruct1, last_error: 0 });
  define("sdl.dll", "SDL_DisplayFormatAlpha", scenario([rgbSurfaceStep("sdl.dll")], [sdlStruct0]), { return_value: sdlStruct1, last_error: 0 });
  define("sdl.dll", "SDL_ConvertSurface", scenario([rgbSurfaceStep("sdl.dll")], [sdlStruct0, 0, 0]), { return_value: sdlStruct1, last_error: 0 });
  define("sdl.dll", "SDL_SetAlpha", argument([0, 0, 0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_ThreadID", argument([]), { return_value: 1, last_error: 0 });
  define("sdl.dll", "SDL_getenv", argument([0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_strlcpy", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hi", 4), argument: [address.string_dest, address.string_a, 8] }, { return_value: 2, last_error: 0 });
  define("sdl.dll", "SDL_strlcat", { prepare: (guest) => { guest.writeAnsiString(address.string_dest, "ab", 4); guest.writeAnsiString(address.string_a, "cd", 4); }, argument: [address.string_dest, address.string_a, 16] }, { return_value: 4, last_error: 0 });
  define("sdl.dll", "SDL_SetModuleHandle", argument([0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_GetVideoInfo", argument([]), { return_value: sdlStruct0, last_error: 0 });
  define("sdl.dll", "SDL_GL_SetAttribute", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_GL_GetAttribute", argument([0, address.string_dest]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_GL_SwapBuffers", argument([]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_RWFromFile", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_SaveBMP_RW", argument([0, 0, 0]), { return_value: 0xffffffff, last_error: 0 });

  // SDL 2 (sdl2.dll) window/renderer/version/cond.
  const createWindowStep = ["sdl2.dll", "SDL_CreateWindow", [0, 0, 0, 320, 200, 0]];
  const createRendererStep = ["sdl2.dll", "SDL_CreateRenderer", [sdlHandle0, 0xffffffff, 0]];
  define("sdl2.dll", "SDL_SetMainReady", argument([]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_CreateWindow", argument([0, 0, 0, 320, 200, 0]), { return_value: sdlHandle0, last_error: 0 });
  define("sdl2.dll", "SDL_DestroyWindow", scenario([createWindowStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_GetWindowSurface", scenario([createWindowStep], [sdlHandle0]), { return_value: sdlStruct0, last_error: 0 });
  define("sdl2.dll", "SDL_UpdateWindowSurface", scenario([createWindowStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_UpdateWindowSurfaceRects", scenario([createWindowStep], [sdlHandle0, 0, 0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_GetWindowSize", scenario([createWindowStep], [sdlHandle0, address.string_dest, address.string_dest + 4]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_GetWindowFlags", scenario([createWindowStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_GetWindowID", scenario([createWindowStep], [sdlHandle0]), { return_value: 1, last_error: 0 });
  define("sdl2.dll", "SDL_SetWindowTitle", scenario([createWindowStep], [sdlHandle0, 0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_SetWindowSize", scenario([createWindowStep], [sdlHandle0, 320, 200]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_CreateRenderer", scenario([createWindowStep], [sdlHandle0, 0xffffffff, 0]), { return_value: sdlHandle1, last_error: 0 });
  define("sdl2.dll", "SDL_DestroyRenderer", scenario([createWindowStep, createRendererStep], [sdlHandle1]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_SetRenderDrawColor", scenario([createWindowStep, createRendererStep], [sdlHandle1, 0x10, 0x20, 0x30, 0xff]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_RenderClear", scenario([createWindowStep, createRendererStep], [sdlHandle1]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_RenderFillRect", scenario([createWindowStep, createRendererStep], [sdlHandle1, 0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_RenderPresent", scenario([createWindowStep, createRendererStep], [sdlHandle1]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_GetVersion", argument([address.string_dest]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_CreateCond", argument([]), { return_value: sdlHandle0, last_error: 0 });
  define("sdl2.dll", "SDL_CondSignal", scenario([["sdl2.dll", "SDL_CreateCond", []]], [sdlHandle0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_CondBroadcast", scenario([["sdl2.dll", "SDL_CreateCond", []]], [sdlHandle0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_CondWait", scenario([["sdl2.dll", "SDL_CreateCond", []]], [sdlHandle0, 0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_DestroyCond", scenario([["sdl2.dll", "SDL_CreateCond", []]], [sdlHandle0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_ShowSimpleMessageBox", argument([0, 0, 0, 0]), { return_value: 0, last_error: 0 });

  return caseList;
}

// The implementation under test for the conformance suite: one fresh
// isolated machine per case, the declared scenario replayed first, then the
// target export invoked with the case argument. A faulting emulator surfaces
// as the structured diagnostic the suite compares against.
export function createConformanceImplementation() {
  return (library, symbol, input) => {
    const { guest } = createConformanceMachine();
    const argument = Array.isArray(input) ? input : input.argument ?? [];
    if (!Array.isArray(input) && typeof input.prepare === "function") input.prepare(guest);
    for (const step of Array.isArray(input) ? [] : input.scenario ?? []) {
      const entry = guest.lookupExport(step[0], step[1]);
      if (entry === null) return { return_value: null, last_error: `The scenario export ${step[0]}!${step[1]} is not served` };
      guest.invokeExport(entry, step[2]);
    }
    const entry = guest.lookupExport(library, symbol);
    if (entry === null) return { return_value: null, last_error: `The export ${library}!${symbol} is not served` };
    const value = guest.invokeExport(entry, argument);
    return { return_value: value, last_error: guest.getLastError(), output_byte: [...guest.takeOutput()] };
  };
}
