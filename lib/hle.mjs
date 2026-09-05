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
import { SehThread, raiseException } from "./seh.mjs";

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
});

const fileAccess = Object.freeze({ generic_read: 0x80000000, generic_write: 0x40000000 });
const fileDisposition = Object.freeze({ create_new: 1, create_always: 2, open_existing: 3, open_always: 4, truncate_existing: 5 });
const fileMethod = Object.freeze({ begin: 0, current: 1, end: 2 });
const fileType = Object.freeze({ unknown: 0, disk: 3, char: 2 });
const registryAccess = Object.freeze({ read: 0x20019, write: 0x20006 });
const registryValueKind = Object.freeze({ none: 0, sz: 1, dword: 4 });
const consoleMode = Object.freeze({ output: 0x0003, input: 0x0007 });
const consoleCodePage = 1252;

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

function raiseProcessExit(exitCode) {
  throw new HleSignal("hle_exit", "The guest ended its own process", { exit_code: unsigned(exitCode) });
}

function raiseGuestException(exceptionCode) {
  throw new HleSignal("hle_guest_exception", "The guest raised an unhandled exception", { exception_code: unsigned(exceptionCode) });
}

// The deterministic address placement for one HLE execution. The block
// (arena + virtual arena + thunk page) must not overlap the mapped image,
// the bounded stack, or the entry return sentinel, so the scan walks the
// declared candidates and takes the first disjoint block.
const blockLayoutByte = hleBound.arena_byte + hleBound.virtual_byte + hleBound.thunk_page_byte;

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

  let lastError = 0;
  let nextHandle = 0x00010000;
  function setLastError(value) {
    lastError = value & 0xffffffff;
  }
  const handleTable = new Map();
  const heapList = [];
  const virtualRegion = new Map();
  const tlsSlot = new Array(hleBound.tls_slot_count).fill(null);
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
    environment,
    commandLineAddressA,
    commandLineAddressW,
    filter_address: 0,
    com_apartment: null,
    com_refcount: 0,
    timer_period: 0,
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

    // --- structured exception dispatch (BPTK-053) -------------------------------
    // The per-thread SEH machine is reachable so a wired substrate can register
    // vectored handlers and push fs:[0] frames; RaiseException already routes
    // through it below.
    seh_thread: sehThread,
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
      const known = moduleByName.get(name.toLowerCase());
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

  // lock-free singly linked list
  define("kernel32.dll", "InitializeSListHead", argument([address.slist_head]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "InterlockedPushEntrySList", argument([address.slist_head, address.slist_entry]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "InterlockedPopEntrySList", scenario([["kernel32.dll", "InterlockedPushEntrySList", [address.slist_head, address.slist_entry]]], [address.slist_head]), { return_value: address.slist_entry, last_error: 0 });
  define("kernel32.dll", "InterlockedFlushSList", scenario([["kernel32.dll", "InterlockedPushEntrySList", [address.slist_head, address.slist_entry]]], [address.slist_head]), { return_value: address.slist_entry, last_error: 0 });
  define("kernel32.dll", "QueryDepthSList", scenario([["kernel32.dll", "InterlockedPushEntrySList", [address.slist_head, address.slist_entry]]], [address.slist_head]), { return_value: 1, last_error: 0 });

  // pointer encoding
  define("kernel32.dll", "EncodePointer", argument([0x12345678]), { return_value: (0x12345678 ^ hleProfile.pointer_cookie) >>> 0, last_error: 0 });
  define("kernel32.dll", "DecodePointer", argument([(0x12345678 ^ hleProfile.pointer_cookie) >>> 0]), { return_value: 0x12345678, last_error: 0 });

  // structured exception filter
  define("kernel32.dll", "SetUnhandledExceptionFilter", argument([0x00401000]), { return_value: 0, last_error: 0 });

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
