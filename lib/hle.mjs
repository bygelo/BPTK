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
  file_time_base: 132000000000000000,
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
  tls_out_of_indexes: 0xffffffff,
});

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
  define("kernel32.dll", "IsProcessorFeaturePresent", 1, (guest, argument) => {
    const feature = argument[0];
    return feature === processorFeature.compare_exchange_double || feature === processorFeature.rdtsc_available ? 1 : 0;
  });
  define("kernel32.dll", "RaiseException", 4, (guest, argument) => raiseGuestException(argument[0]));

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
  define("kernel32.dll", "GetModuleFileNameA", 3, (guest, argument) => {
    const module = guest.moduleName(argument[0]);
    if (module === null) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const path = `${hleProfile.guest_root}\\${module}`;
    const written = guest.writeAnsiString(argument[1], path, argument[2]);
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return argument[2];
    }
    return written.length;
  });
  define("kernel32.dll", "GetModuleFileNameW", 3, (guest, argument) => {
    const module = guest.moduleName(argument[0]);
    if (module === null) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const path = `${hleProfile.guest_root}\\${module}`;
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
      if (key === stdHandle.input) return allocateHandle("std_input", { is_input: true });
      if (key === stdHandle.output) return allocateHandle("std_output", { is_input: false });
      if (key === stdHandle.error) return allocateHandle("std_error", { is_input: false });
      setLastError(errorValue.invalid_parameter);
      return 0xffffffff;
    },
    writeOutput(handle, bufferAddress, countByte, writtenPointer, isOverlapped) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
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
      if (sizeByte === 1) return backing[address];
      if (sizeByte === 2) return backing.readUInt16LE(address);
      return backing.readUInt32LE(address);
    },
    writeMemory(address, sizeByte, value) {
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
