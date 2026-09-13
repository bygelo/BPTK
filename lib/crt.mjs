// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Generic Win32 leftovers that a shipped ucrtbase sidecar still imports
// through api-ms-win-core-* (heap walk/validate/compact/query, SetLocalTime,
// console input, TzSpecificLocalTimeToSystemTime, Beep). Rows are kernel32
// so the existing api-set forward in resolveHleExport binds them. No title
// branch. Registration is appended to the already-imported SDL export table
// because lib/hle.mjs is owned by another lane.

const errorValue = Object.freeze({
  invalid_handle: 6,
  insufficient_buffer: 122,
  invalid_parameter: 87,
  no_more_items: 259,
});

const heapInfoClass = Object.freeze({
  compatibility: 0,
});

const processHeapEntry = Object.freeze({
  region: 0x0001,
  busy: 0x0004,
});

function unsigned(value) {
  return (value ?? 0) >>> 0;
}

function requireHeap(guest, handle) {
  const heap = guest.heapFor(guest.resolveHeapHandle(handle));
  if (heap === null) {
    guest.setLastError(errorValue.invalid_handle);
    return null;
  }
  return heap;
}

function requireConsole(guest, handle) {
  const mode = guest.consoleMode(handle);
  if (mode === 0) return false;
  guest.setLastError(0);
  return true;
}

function writeHeapEntry(memory, dest, entry) {
  memory.writeMemory(dest, 4, unsigned(entry.lpData));
  memory.writeMemory(dest + 4, 4, unsigned(entry.cbData));
  memory.writeMemory(dest + 8, 1, unsigned(entry.cbOverhead) & 0xff);
  memory.writeMemory(dest + 9, 1, unsigned(entry.iRegionIndex) & 0xff);
  memory.writeMemory(dest + 10, 2, unsigned(entry.wFlags) & 0xffff);
  const extra = Buffer.alloc(16);
  if (Buffer.isBuffer(entry.extra)) entry.extra.copy(extra);
  memory.writeBlock(dest + 12, extra);
}

function busyBlocks(heap) {
  return [...heap.allocation.entries()].sort((left, right) => left[0] - right[0]);
}

function heapWalk(guest, handle, entryPointer) {
  const heap = requireHeap(guest, handle);
  if (heap === null) return 0;
  if (unsigned(entryPointer) === 0) {
    guest.setLastError(errorValue.invalid_parameter);
    return 0;
  }
  const lastData = guest.memory.readMemory(entryPointer, 4) >>> 0;
  const busy = busyBlocks(heap);
  if (lastData === 0) {
    const extra = Buffer.alloc(16);
    extra.writeUInt32LE(heap.size_byte >>> 0, 0);
    extra.writeUInt32LE(0, 4);
    extra.writeUInt32LE((heap.base + 16) >>> 0, 8);
    extra.writeUInt32LE((heap.base + heap.size_byte) >>> 0, 12);
    writeHeapEntry(guest.memory, entryPointer, {
      lpData: heap.base,
      cbData: heap.size_byte,
      cbOverhead: 0,
      iRegionIndex: 0,
      wFlags: processHeapEntry.region,
      extra,
    });
    guest.setLastError(0);
    return 1;
  }
  if (lastData === (heap.base >>> 0)) {
    if (busy.length === 0) {
      guest.setLastError(errorValue.no_more_items);
      return 0;
    }
    const [address, size] = busy[0];
    writeHeapEntry(guest.memory, entryPointer, {
      lpData: address,
      cbData: size,
      cbOverhead: 8,
      iRegionIndex: 0,
      wFlags: processHeapEntry.busy,
    });
    guest.setLastError(0);
    return 1;
  }
  const index = busy.findIndex(([address]) => address === lastData);
  if (index >= 0 && index + 1 < busy.length) {
    const [address, size] = busy[index + 1];
    writeHeapEntry(guest.memory, entryPointer, {
      lpData: address,
      cbData: size,
      cbOverhead: 8,
      iRegionIndex: 0,
      wFlags: processHeapEntry.busy,
    });
    guest.setLastError(0);
    return 1;
  }
  guest.setLastError(errorValue.no_more_items);
  return 0;
}

function heapValidate(guest, handle, _flag, mem) {
  const heap = requireHeap(guest, handle);
  if (heap === null) return 0;
  const address = unsigned(mem);
  if (address === 0) {
    guest.setLastError(0);
    return 1;
  }
  if (!heap.allocation.has(address)) {
    guest.setLastError(errorValue.invalid_parameter);
    return 0;
  }
  guest.setLastError(0);
  return 1;
}

function heapCompact(guest, handle) {
  const heap = requireHeap(guest, handle);
  if (heap === null) return 0;
  let largest = 0;
  for (const block of heap.free ?? []) {
    if (block.size_byte > largest) largest = block.size_byte;
  }
  guest.setLastError(0);
  return largest >>> 0;
}

function heapQueryInformation(guest, handle, infoClass, dest, length, returnLength) {
  const heap = requireHeap(guest, handle);
  if (heap === null) return 0;
  if (unsigned(infoClass) !== heapInfoClass.compatibility) {
    guest.setLastError(errorValue.invalid_parameter);
    return 0;
  }
  const needed = 4;
  if (unsigned(returnLength) !== 0) guest.memory.writeMemory(unsigned(returnLength), 4, needed);
  if (unsigned(length) === 0 && unsigned(dest) === 0) {
    guest.setLastError(0);
    return 1;
  }
  if (unsigned(dest) === 0 || unsigned(length) < needed) {
    guest.setLastError(errorValue.insufficient_buffer);
    return 0;
  }
  // HEAP_STANDARD: the bounded bump heap is not LFH.
  guest.memory.writeMemory(unsigned(dest), 4, 0);
  guest.setLastError(0);
  return 1;
}

function setLocalTime(guest, systemTimePointer) {
  if (unsigned(systemTimePointer) === 0) {
    guest.setLastError(errorValue.invalid_parameter);
    return 0;
  }
  const field = guest.readSystemTime(systemTimePointer);
  const daysInMonth = [0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (
    field.year < 1601 || field.year > 30827
    || field.month < 1 || field.month > 12
    || field.day < 1 || field.day > daysInMonth[field.month]
    || field.hour > 23 || field.minute > 59 || field.second > 59
    || field.millisecond > 999
  ) {
    guest.setLastError(errorValue.invalid_parameter);
    return 0;
  }
  guest.local_system_time = field;
  guest.setLastError(0);
  return 1;
}

function writeEventCount(guest, dest, count) {
  if (unsigned(dest) === 0) {
    guest.setLastError(errorValue.invalid_parameter);
    return 0;
  }
  guest.memory.writeMemory(unsigned(dest), 4, count >>> 0);
  guest.setLastError(0);
  return 1;
}

function peekConsoleInput(guest, handle, buffer, length, countPointer) {
  if (!requireConsole(guest, handle)) return 0;
  if (unsigned(countPointer) === 0 || (unsigned(length) !== 0 && unsigned(buffer) === 0)) {
    guest.setLastError(errorValue.invalid_parameter);
    return 0;
  }
  // Declared output-only console: no pending INPUT_RECORD.
  return writeEventCount(guest, countPointer, 0);
}

function getNumberOfConsoleInputEvents(guest, handle, countPointer) {
  if (!requireConsole(guest, handle)) return 0;
  return writeEventCount(guest, countPointer, 0);
}

function buildCrtExportTable() {
  const table = [];
  function define(symbol, argumentCount, emulate) {
    table.push(Object.freeze({ library: "kernel32.dll", symbol, argument_count: argumentCount, emulate }));
  }

  define("HeapQueryInformation", 5, (guest, argument) => (
    heapQueryInformation(guest, argument[0], argument[1], argument[2], argument[3], argument[4])
  ));
  define("HeapCompact", 2, (guest, argument) => heapCompact(guest, argument[0]));
  define("HeapWalk", 2, (guest, argument) => heapWalk(guest, argument[0], argument[1]));
  define("HeapValidate", 3, (guest, argument) => heapValidate(guest, argument[0], argument[1], argument[2]));
  define("SetLocalTime", 1, (guest, argument) => setLocalTime(guest, argument[0]));
  define("PeekConsoleInputA", 4, (guest, argument) => (
    peekConsoleInput(guest, argument[0], argument[1], argument[2], argument[3])
  ));
  define("GetNumberOfConsoleInputEvents", 2, (guest, argument) => (
    getNumberOfConsoleInputEvents(guest, argument[0], argument[1])
  ));
  define("ReadConsoleInputW", 4, (guest, argument) => guest.readConsole(argument[0]));
  define("TzSpecificLocalTimeToSystemTime", 3, (guest, argument) => guest.copySystemTime(argument[1], argument[2]));
  define("Beep", 2, (guest) => {
    guest.setLastError(0);
    return 1;
  });

  return table;
}

export const crtExportTable = Object.freeze(buildCrtExportTable());

export function listCrtHleExport() {
  return crtExportTable;
}

// Conformance rows for the coverage gate. Addresses match the HLE case table
// so a merged suite can replay HeapCreate / GetStdHandle scenarios.
export function buildCrtConformanceCaseTable() {
  const caseList = [];
  let caseNumber = 0;
  function define(library, symbol, input, expected) {
    caseNumber += 1;
    caseList.push({
      case_id: `CRT-${String(caseNumber).padStart(3, "0")}`,
      library,
      symbol,
      input,
      expected,
    });
  }
  const argument = (value) => ({ argument: value });
  const scenario = (steps, value) => ({ scenario: steps, argument: value });
  const address = {
    scratch: 0x00150000,
    scratch_dword: 0x00150040,
    string_dest: 0x00150100,
    system_time: 0x00150200,
    startup_info: 0x00170000,
  };
  const firstHandle = 0x00010000;
  const heapScenario = [["kernel32.dll", "HeapCreate", [0, 0, 0]]];
  const stdinScenario = [["kernel32.dll", "GetStdHandle", [-10]]];
  const writeLocalTime = (guest) => {
    guest.memory.writeMemory(address.system_time, 2, 2020);
    guest.memory.writeMemory(address.system_time + 2, 2, 9);
    guest.memory.writeMemory(address.system_time + 4, 2, 0);
    guest.memory.writeMemory(address.system_time + 6, 2, 13);
    guest.memory.writeMemory(address.system_time + 8, 2, 12);
    guest.memory.writeMemory(address.system_time + 10, 2, 0);
    guest.memory.writeMemory(address.system_time + 12, 2, 0);
    guest.memory.writeMemory(address.system_time + 14, 2, 0);
  };

  define("kernel32.dll", "HeapQueryInformation", scenario(heapScenario, [firstHandle, 0, address.scratch_dword, 4, address.scratch]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "HeapQueryInformation", argument([0xdeadbeef, 0, address.scratch_dword, 4, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "HeapCompact", scenario(heapScenario, [firstHandle, 0]), { return_value: 25165808, last_error: 0 });
  define("kernel32.dll", "HeapCompact", argument([0xdeadbeef, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "HeapWalk", {
    prepare: (guest) => guest.memory.writeBlock(address.string_dest, Buffer.alloc(28)),
    scenario: heapScenario,
    argument: [firstHandle, address.string_dest],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "HeapWalk", scenario(heapScenario, [firstHandle, 0]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "HeapValidate", scenario(heapScenario, [firstHandle, 0, 0]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "HeapValidate", argument([0xdeadbeef, 0, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "SetLocalTime", { prepare: writeLocalTime, argument: [address.system_time] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetLocalTime", argument([0]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "PeekConsoleInputA", scenario(stdinScenario, [firstHandle, address.string_dest, 1, address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "PeekConsoleInputA", argument([0xdeadbeef, address.string_dest, 1, address.scratch_dword]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "GetNumberOfConsoleInputEvents", scenario(stdinScenario, [firstHandle, address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetNumberOfConsoleInputEvents", argument([0xdeadbeef, address.scratch_dword]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "ReadConsoleInputW", scenario(stdinScenario, [firstHandle, address.string_dest, 1, address.scratch_dword]), { return_value: 0, last_error: 5 });
  define("kernel32.dll", "TzSpecificLocalTimeToSystemTime", argument([0, address.startup_info, address.string_dest]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "TzSpecificLocalTimeToSystemTime", argument([0, 0, address.string_dest]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "Beep", argument([750, 250]), { return_value: 1, last_error: 0 });

  return caseList;
}
