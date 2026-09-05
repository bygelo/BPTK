// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The x86-64 (PE32+) loader for runtime v2 (BPTK-031 / doc/runtime-v2-scope.md).
// v1 refuses machine 0x8664 at the machine gate, so six of the eleven corpus
// payloads never load. This maps a PE32+ image — sections, imports, TLS,
// relocations — into the 64-bit address space and reports a `loaded` state.
// It executes nothing: v2 execution (lifter, WASM codegen) is a later milestone,
// and the runtime blocker says so. A mapped image is not a compatibility claim.
//
// The small file-reading and validation helpers mirror lib/pe.mjs by intent;
// they are duplicated rather than shared so the v2 loader stays isolated from
// the PE32 path (and its packaged content pin) while the two cores coexist.

import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { resolve } from "node:path";
import { InputError } from "./input.mjs";

const maxImageSizeByte = 512 * 1024 * 1024; // the 64-bit map admits a larger image than the 128 MiB PE32 cap
const maxExecutableSizeByte = 128 * 1024 * 1024;
const maxReserveSizeByte = 4 * 1024 * 1024 * 1024;
const maxImportDescriptorCount = 1024;
const maxImportThunkCount = 16384;
const maxImportStringSizeByte = 4096;
const maxTlsCallbackCount = 256;
const ordinalFlag64 = 0x8000000000000000n; // IMAGE_ORDINAL_FLAG64: bit 63 of a PE32+ thunk
const executableSectionFlag = 0x20000000;
const pe32PlusMagic = 0x20b;
const machineAmd64 = 0x8664;

function assertRange(buffer, offset, sizeByte, label) {
  if (!Number.isInteger(offset) || !Number.isInteger(sizeByte) || offset < 0 || sizeByte < 0 || offset > buffer.length - sizeByte) {
    throw new InputError("invalid_pe_range", `${label} is outside the executable`);
  }
}

function readName(buffer, offset, sizeByte) {
  assertRange(buffer, offset, sizeByte, "name");
  const end = buffer.indexOf(0, offset);
  const boundedEnd = end >= offset && end < offset + sizeByte ? end : offset + sizeByte;
  return buffer.toString("ascii", offset, boundedEnd);
}

function readAsciiZero(buffer, offset, label) {
  assertRange(buffer, offset, 1, label);
  const limit = Math.min(buffer.length, offset + maxImportStringSizeByte);
  const end = buffer.indexOf(0, offset);
  if (end < offset || end >= limit) {
    throw new InputError("unterminated_pe_string", `${label} has no terminator within ${maxImportStringSizeByte} byte`);
  }
  return buffer.toString("ascii", offset, end);
}

function normalizeOpenError(error, inputPath) {
  if (error?.code === "ENOENT") return new InputError("not_found", `Input does not exist: ${inputPath}`);
  if (error?.code === "ELOOP") return new InputError("symlink_input", `Symbolic-link input is not followed: ${inputPath}`);
  return new InputError("input_failure", `Unable to open executable: ${inputPath}`);
}

// Reads one local executable into memory under the size bound, never following a
// symlink. Mirrors lib/pe.mjs readExecutable so the v2 loader has no cross-import.
function readExecutable(input) {
  if (typeof input !== "string" || input.trim() === "") throw new InputError("missing_input", "A local input path is required");
  const inputPath = resolve(input);
  let flag = constants.O_RDONLY | constants.O_NONBLOCK;
  if (Number.isInteger(constants.O_NOFOLLOW)) flag |= constants.O_NOFOLLOW;
  else {
    let linkStat;
    try {
      linkStat = lstatSync(inputPath);
    } catch (error) {
      throw normalizeOpenError(error, inputPath);
    }
    if (linkStat.isSymbolicLink()) throw new InputError("symlink_input", `Symbolic-link input is not followed: ${inputPath}`);
  }
  let descriptor;
  try {
    descriptor = openSync(inputPath, flag);
  } catch (error) {
    throw normalizeOpenError(error, inputPath);
  }
  try {
    let inputStat;
    try {
      inputStat = fstatSync(descriptor);
    } catch {
      throw new InputError("input_failure", `Unable to stat executable: ${inputPath}`);
    }
    if (!inputStat.isFile()) throw new InputError("pe_file_required", "PE32+ loading requires one executable file");
    if (inputStat.size > maxExecutableSizeByte) {
      throw new InputError("pe_file_size_limit", `Executable size ${inputStat.size} exceeds ${maxExecutableSizeByte} byte`);
    }
    const file = Buffer.alloc(inputStat.size);
    let readByte = 0;
    while (readByte < inputStat.size) {
      let currentReadByte;
      try {
        currentReadByte = readSync(descriptor, file, readByte, inputStat.size - readByte, readByte);
      } catch {
        throw new InputError("pe_read_failure", `Unable to read executable: ${inputPath}`);
      }
      if (currentReadByte <= 0) throw new InputError("pe_read_failure", `Executable ended before its validated size: ${inputPath}`);
      readByte += currentReadByte;
    }
    return { input_path: inputPath, file };
  } finally {
    try {
      closeSync(descriptor);
    } catch {
      // The validated read result remains deterministic even if close reports an OS error.
    }
  }
}

// Parses the PE32+ import directory. A thunk is 8 byte; the ordinal flag is bit
// 63; a by-name thunk points at a 2-byte hint followed by the ASCII symbol.
function parseImport(image, importDirectory) {
  const report = { import: [], resolution_blocker: [], descriptor_count: 0 };
  if (importDirectory.rva === 0 || importDirectory.size_byte === 0) return report;
  assertRange(image, importDirectory.rva, Math.min(importDirectory.size_byte, 20), "import directory");
  let descriptorOffset = importDirectory.rva;
  for (let guard = 0; guard <= maxImportDescriptorCount; guard += 1) {
    if (guard === maxImportDescriptorCount) throw new InputError("import_descriptor_limit", `Import directory exceeds ${maxImportDescriptorCount} descriptor`);
    assertRange(image, descriptorOffset, 20, "import descriptor");
    const lookupRva = image.readUInt32LE(descriptorOffset);
    const libraryRva = image.readUInt32LE(descriptorOffset + 12);
    const iatRva = image.readUInt32LE(descriptorOffset + 16);
    if (lookupRva === 0 && libraryRva === 0 && iatRva === 0) break;
    report.descriptor_count += 1;
    const library = readAsciiZero(image, libraryRva, "import library").toLowerCase();
    const thunkTableRva = lookupRva !== 0 ? lookupRva : iatRva;
    for (let index = 0; index <= maxImportThunkCount; index += 1) {
      if (index === maxImportThunkCount) throw new InputError("import_thunk_limit", `Import table ${library} exceeds ${maxImportThunkCount} thunk`);
      const thunkRva = thunkTableRva + index * 8;
      assertRange(image, thunkRva, 8, "import thunk");
      const thunk = image.readBigUInt64LE(thunkRva);
      if (thunk === 0n) break;
      let symbol = null;
      let ordinal = null;
      if ((thunk & ordinalFlag64) !== 0n) {
        ordinal = Number(thunk & 0xffffn);
      } else {
        const hintNameRva = Number(thunk & 0x7fffffffn);
        symbol = readAsciiZero(image, hintNameRva + 2, "import symbol");
      }
      const iatSlotRva = iatRva + index * 8;
      report.import.push({ library, symbol, ordinal, iat_slot_rva: iatSlotRva, resolution_state: "unresolved" });
    }
    descriptorOffset += 20;
  }
  // v2 serves no import yet; every import is an unresolved-by-HLE blocker.
  const distinct = new Set(report.import.map((entry) => `${entry.library}\0${entry.symbol ?? `#${entry.ordinal}`}`));
  if (distinct.size > 0) report.resolution_blocker.push(`${distinct.size} distinct import require a Win64 HLE that v2 does not yet serve`);
  return report;
}

// Parses the PE32+ TLS directory. Its start/end/index/callback addresses are
// 64-bit virtual addresses (not RVAs); the callback list is a null-terminated
// array of 64-bit pointers.
function parseTls(image, tlsDirectory, loadBase, imageSizeByte) {
  const report = { tls_callback: [], tls_index_address: null };
  if (tlsDirectory.rva === 0 || tlsDirectory.size_byte === 0) return report;
  assertRange(image, tlsDirectory.rva, 40, "TLS directory");
  const callbackAddress = image.readBigUInt64LE(tlsDirectory.rva + 24);
  report.tls_index_address = image.readBigUInt64LE(tlsDirectory.rva + 16);
  if (callbackAddress === 0n) return report;
  const imageEnd = loadBase + BigInt(imageSizeByte);
  if (callbackAddress < loadBase || callbackAddress >= imageEnd) {
    throw new InputError("invalid_tls_callback", "TLS callback array lies outside the mapped image");
  }
  let callbackRva = Number(callbackAddress - loadBase);
  for (let index = 0; index <= maxTlsCallbackCount; index += 1) {
    if (index === maxTlsCallbackCount) throw new InputError("tls_callback_limit", `TLS callback array exceeds ${maxTlsCallbackCount} entry`);
    assertRange(image, callbackRva, 8, "TLS callback");
    const pointer = image.readBigUInt64LE(callbackRva);
    if (pointer === 0n) break;
    if (pointer < loadBase || pointer >= imageEnd) throw new InputError("invalid_tls_callback", "TLS callback points outside the mapped image");
    report.tls_callback.push(pointer);
    callbackRva += 8;
  }
  return report;
}

// Reads only the DOS+PE header prefix to report the machine code without
// reading the whole file. Returns null when the prefix is not a recognizable
// PE, so a caller can cheaply decide the x86-64 path before committing to the
// full load (and never reads a giant non-PE file on the way). Bounded read.
export function peekPeMachine(input) {
  if (typeof input !== "string" || input.trim() === "") return null;
  const inputPath = resolve(input);
  let flag = constants.O_RDONLY | constants.O_NONBLOCK;
  if (Number.isInteger(constants.O_NOFOLLOW)) flag |= constants.O_NOFOLLOW;
  else {
    try {
      if (lstatSync(inputPath).isSymbolicLink()) return null;
    } catch {
      return null;
    }
  }
  let descriptor;
  try {
    descriptor = openSync(inputPath, flag);
  } catch {
    return null;
  }
  try {
    const prefix = Buffer.alloc(0x1000);
    let readByte = 0;
    while (readByte < prefix.length) {
      let current;
      try {
        current = readSync(descriptor, prefix, readByte, prefix.length - readByte, readByte);
      } catch {
        return null;
      }
      if (current <= 0) break;
      readByte += current;
    }
    if (readByte < 0x40 || prefix.readUInt16LE(0) !== 0x5a4d) return null; // "MZ"
    const peOffset = prefix.readUInt32LE(0x3c);
    if (peOffset + 6 > readByte) return null;
    if (prefix.toString("ascii", peOffset, peOffset + 4) !== "PE\0\0") return null;
    return prefix.readUInt16LE(peOffset + 4);
  } finally {
    try {
      closeSync(descriptor);
    } catch {
      // The peek result is deterministic even if close reports an OS error.
    }
  }
}

// Maps a PE32+ (x86-64) image and reports its loaded state. `requestedBase`
// overrides the preferred ImageBase (relocations apply the delta). Nothing runs.
export function mapPe64State(input, requestedBase = null) {
  const inputValue = readExecutable(input);
  const file = inputValue.file;
  assertRange(file, 0, 64, "DOS header");
  if (file.toString("ascii", 0, 2) !== "MZ") throw new InputError("invalid_dos_signature", "Executable does not start with MZ");
  const peOffset = file.readUInt32LE(0x3c);
  assertRange(file, peOffset, 24, "PE header");
  if (file.toString("ascii", peOffset, peOffset + 4) !== "PE\0\0") throw new InputError("invalid_pe_signature", "PE signature is missing");
  const machineCode = file.readUInt16LE(peOffset + 4);
  if (machineCode !== machineAmd64) throw new InputError("unsupported_machine", `PE machine 0x${machineCode.toString(16)} is not x86-64`);
  const sectionCount = file.readUInt16LE(peOffset + 6);
  if (sectionCount < 1 || sectionCount > 96) throw new InputError("invalid_section_count", `PE section count ${sectionCount} is outside 1..96`);
  const optionalSizeByte = file.readUInt16LE(peOffset + 20);
  const optionalOffset = peOffset + 24;
  assertRange(file, optionalOffset, optionalSizeByte, "optional header");
  // PE32+ optional-header layout differs from PE32: magic 0x20b, an 8-byte
  // ImageBase at +24 (PE32 has BaseOfData at +24 then a 4-byte ImageBase at
  // +28), and 8-byte stack/heap sizes that shift the directory count to +108.
  if (optionalSizeByte < 112 || file.readUInt16LE(optionalOffset) !== pe32PlusMagic) {
    throw new InputError("unsupported_optional_header", "Only PE32+ optional headers are supported");
  }
  const entryRva = file.readUInt32LE(optionalOffset + 16);
  const imageBase = file.readBigUInt64LE(optionalOffset + 24);
  const imageSizeByte = file.readUInt32LE(optionalOffset + 56);
  const headerSizeByte = file.readUInt32LE(optionalOffset + 60);
  const stackReserveByte = file.readBigUInt64LE(optionalOffset + 72);
  const stackCommitByte = file.readBigUInt64LE(optionalOffset + 80);
  const heapReserveByte = file.readBigUInt64LE(optionalOffset + 88);
  const heapCommitByte = file.readBigUInt64LE(optionalOffset + 96);
  if (imageSizeByte < headerSizeByte || imageSizeByte > maxImageSizeByte) throw new InputError("image_size_limit", `PE image size ${imageSizeByte} is invalid or exceeds ${maxImageSizeByte}`);
  if (headerSizeByte === 0) throw new InputError("invalid_header_size", "PE header size must be non-zero");
  assertRange(file, 0, headerSizeByte, "PE headers");
  if (stackCommitByte > stackReserveByte || heapCommitByte > heapReserveByte) {
    throw new InputError("invalid_memory_reserve", "PE stack and heap commit must not exceed reserve");
  }
  if (stackReserveByte > BigInt(maxReserveSizeByte) || heapReserveByte > BigInt(maxReserveSizeByte)) {
    throw new InputError("memory_reserve_limit", `PE stack and heap reserve must not exceed ${maxReserveSizeByte} byte`);
  }
  const sectionOffset = optionalOffset + optionalSizeByte;
  assertRange(file, sectionOffset, sectionCount * 40, "section table");
  if (sectionOffset + sectionCount * 40 > headerSizeByte) {
    throw new InputError("invalid_header_size", "PE header size does not cover the section table");
  }
  const section = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const offset = sectionOffset + index * 40;
    const name = readName(file, offset, 8);
    const virtualSizeByte = file.readUInt32LE(offset + 8);
    const virtualAddress = file.readUInt32LE(offset + 12);
    const rawSizeByte = file.readUInt32LE(offset + 16);
    const rawOffset = file.readUInt32LE(offset + 20);
    const mappedSizeByte = Math.max(virtualSizeByte, rawSizeByte);
    if (rawSizeByte > 0) assertRange(file, rawOffset, rawSizeByte, `section ${name} raw data`);
    if (virtualAddress + mappedSizeByte > imageSizeByte) throw new InputError("section_image_escape", `Section ${name} escapes the mapped image`);
    if (mappedSizeByte > 0) {
      const overlap = section.find((entry) => virtualAddress < entry.virtual_address + entry.mapped_size_byte && entry.virtual_address < virtualAddress + mappedSizeByte);
      if (overlap) throw new InputError("section_overlap", `Section ${name} overlaps section ${overlap.name}`);
    }
    section.push({
      name,
      virtual_address: virtualAddress,
      virtual_size_byte: virtualSizeByte,
      mapped_size_byte: mappedSizeByte,
      raw_offset: rawOffset,
      raw_size_byte: rawSizeByte,
      characteristic: file.readUInt32LE(offset + 36),
    });
  }
  const entrySection = section.find((entry) => entryRva >= entry.virtual_address && entryRva < entry.virtual_address + entry.mapped_size_byte);
  if (!entrySection || (entrySection.characteristic & executableSectionFlag) === 0) {
    throw new InputError("entry_not_executable", "PE entry point is not inside an executable section");
  }
  const image = Buffer.alloc(imageSizeByte);
  file.copy(image, 0, 0, Math.min(headerSizeByte, image.length));
  for (const currentSection of section) {
    if (currentSection.raw_size_byte > 0) file.copy(image, currentSection.virtual_address, currentSection.raw_offset, currentSection.raw_offset + currentSection.raw_size_byte);
  }
  const directoryCount = Math.min(file.readUInt32LE(optionalOffset + 108), 16);
  const directoryOffset = optionalOffset + 112;
  const directory = [];
  for (let index = 0; index < directoryCount && directoryOffset + index * 8 + 8 <= optionalOffset + optionalSizeByte; index += 1) {
    directory.push({ index, rva: file.readUInt32LE(directoryOffset + index * 8), size_byte: file.readUInt32LE(directoryOffset + index * 8 + 4) });
  }
  const importDirectory = directory[1] ?? { rva: 0, size_byte: 0 };
  const relocationDirectory = directory[5] ?? { rva: 0, size_byte: 0 };
  const tlsDirectory = directory[9] ?? { rva: 0, size_byte: 0 };
  const loadBase = requestedBase === null ? imageBase : BigInt(requestedBase);
  if (loadBase < 0n || loadBase > 0xffffffffffffffffn || (loadBase & 0xffffn) !== 0n) {
    throw new InputError("invalid_load_base", "Requested load base must be a 64-bit unsigned integer aligned to 64 KiB");
  }
  if (loadBase + BigInt(imageSizeByte) > 0x10000000000000000n) throw new InputError("image_address_overflow", "Mapped PE32+ image exceeds the 64-bit address space");
  const delta = loadBase - imageBase;
  let relocationCount = 0;
  if ((relocationDirectory.rva === 0) !== (relocationDirectory.size_byte === 0)) {
    throw new InputError("invalid_relocation_directory", "Relocation directory requires both RVA and size");
  }
  if (delta !== 0n) {
    if (relocationDirectory.rva === 0 || relocationDirectory.size_byte === 0) throw new InputError("relocation_required", "Requested load base differs and the image has no relocation directory");
    assertRange(image, relocationDirectory.rva, relocationDirectory.size_byte, "relocation directory");
    let offset = relocationDirectory.rva;
    const end = relocationDirectory.rva + relocationDirectory.size_byte;
    while (offset + 8 <= end) {
      const pageRva = image.readUInt32LE(offset);
      const blockSizeByte = image.readUInt32LE(offset + 4);
      if (blockSizeByte < 8 || offset + blockSizeByte > end) throw new InputError("invalid_relocation_block", "Relocation block is malformed");
      for (let entryOffset = offset + 8; entryOffset + 2 <= offset + blockSizeByte; entryOffset += 2) {
        const entry = image.readUInt16LE(entryOffset);
        const type = entry >>> 12;
        const targetRva = pageRva + (entry & 0x0fff);
        if (type === 0) continue; // IMAGE_REL_BASED_ABSOLUTE: padding
        if (type !== 10 || targetRva + 8 > image.length) throw new InputError("unsupported_relocation", `Relocation type ${type} is unsupported or out of range`);
        image.writeBigUInt64LE(BigInt.asUintN(64, image.readBigUInt64LE(targetRva) + delta), targetRva);
        relocationCount += 1;
      }
      offset += blockSizeByte;
    }
    if (offset !== end) throw new InputError("invalid_relocation_block", "Relocation directory has trailing partial data");
  }
  const importReport = parseImport(image, importDirectory);
  const tlsReport = parseTls(image, tlsDirectory, loadBase, imageSizeByte);
  const runtimeBlocker = [];
  if (tlsReport.tls_callback.length > 0) runtimeBlocker.push("TLS callback execution is not implemented");
  // v2 execution (lifter → WASM codegen) is a later milestone: the mapped entry
  // is never executed here. A loaded image is not a compatibility claim.
  runtimeBlocker.push("The mapped entry point is not executed because the x86-64 v2 runtime is not implemented");
  return {
    machine: "x86_64",
    format: "pe32_plus",
    input_path: inputValue.input_path,
    image_base: imageBase,
    load_base: loadBase,
    entry_rva: entryRva,
    entry_address: loadBase + BigInt(entryRva),
    image,
    image_size_byte: imageSizeByte,
    header_size_byte: headerSizeByte,
    stack_reserve_byte: stackReserveByte,
    heap_reserve_byte: heapReserveByte,
    section,
    directory,
    import: importReport.import,
    import_descriptor_count: importReport.descriptor_count,
    tls_callback: tlsReport.tls_callback,
    relocation_count: relocationCount,
    resolution_blocker: importReport.resolution_blocker,
    runtime_blocker: runtimeBlocker,
    is_executed: false,
    state: "loaded",
  };
}
