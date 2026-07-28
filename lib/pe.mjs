// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { inspectPath, InputError } from "./input.mjs";

const maxImageSizeByte = 128 * 1024 * 1024;
const maxReserveSizeByte = 1024 * 1024 * 1024;
const maxImportDescriptorCount = 1024;
const maxImportThunkCount = 16384;
const maxImportStringSizeByte = 4096;
const maxTlsCallbackCount = 256;
const ordinalFlag = 0x80000000;
const executableSectionFlag = 0x20000000;

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

function normalizeLibrary(value) {
  if (typeof value !== "string" || value.trim() === "" || !/^[\x20-\x7e]+$/.test(value)) {
    throw new InputError("invalid_import_catalog", "Import catalog library must be non-empty printable ASCII");
  }
  return value.trim().toLowerCase();
}

function normalizeSymbol(value, code = "invalid_import_catalog") {
  if (typeof value !== "string" || value.length === 0 || value.length > maxImportStringSizeByte || !/^[\x20-\x7e]+$/.test(value)) {
    throw new InputError(code, "Import symbol must be bounded printable ASCII");
  }
  return value;
}

function importKey(library, symbol, ordinal) {
  return `${library}\0${symbol === null ? `#${ordinal}` : symbol}`;
}

function createImportCatalog(value, loadBase, imageSizeByte) {
  if (value === null || value === undefined) return new Map();
  if (!Array.isArray(value) || value.length > maxImportThunkCount) {
    throw new InputError("invalid_import_catalog", `Package import must be an array with at most ${maxImportThunkCount} entry`);
  }
  const catalog = new Map();
  const address = new Set();
  const imageEnd = loadBase + imageSizeByte;
  for (const currentImport of value) {
    if (typeof currentImport !== "object" || currentImport === null || Array.isArray(currentImport)) {
      throw new InputError("invalid_import_catalog", "Every package import entry must be an object");
    }
    const library = normalizeLibrary(currentImport.library);
    const hasSymbol = typeof currentImport.symbol === "string";
    const hasOrdinal = Number.isInteger(currentImport.ordinal);
    if (hasSymbol === hasOrdinal) {
      throw new InputError("invalid_import_catalog", "Every package import entry requires exactly one symbol or ordinal");
    }
    const symbol = hasSymbol ? normalizeSymbol(currentImport.symbol) : null;
    const ordinal = hasOrdinal ? currentImport.ordinal : null;
    if (ordinal !== null && (ordinal < 0 || ordinal > 0xffff)) {
      throw new InputError("invalid_import_catalog", "Package import ordinal must be a 16-bit unsigned integer");
    }
    const thunkAddress = currentImport.address;
    if (!Number.isSafeInteger(thunkAddress) || thunkAddress <= 0 || thunkAddress > 0xffffffff) {
      throw new InputError("invalid_import_catalog", "Package import address must be a non-zero 32-bit unsigned integer");
    }
    if (thunkAddress >= loadBase && thunkAddress < imageEnd) {
      throw new InputError("import_address_overlap", "Package import address overlaps the mapped PE32 image");
    }
    const key = importKey(library, symbol, ordinal);
    if (catalog.has(key)) {
      throw new InputError("duplicate_import_binding", `Package import repeats ${library}!${symbol ?? `#${ordinal}`}`);
    }
    if (address.has(thunkAddress)) {
      throw new InputError("duplicate_import_address", `Package import address 0x${thunkAddress.toString(16)} is reused`);
    }
    address.add(thunkAddress);
    catalog.set(key, { library, symbol, ordinal, address: thunkAddress });
  }
  return catalog;
}

function parseImport(image, importDirectory, catalog) {
  const importValue = [];
  const resolutionBlocker = [];
  if (importDirectory.rva === 0 && importDirectory.size_byte === 0) {
    return { import: importValue, resolution_blocker: resolutionBlocker };
  }
  if (importDirectory.rva === 0 || importDirectory.size_byte < 20) {
    throw new InputError("invalid_import_directory", "Import directory requires a non-zero RVA and room for a descriptor");
  }
  assertRange(image, importDirectory.rva, importDirectory.size_byte, "import directory");
  const directoryEnd = importDirectory.rva + importDirectory.size_byte;
  let descriptorOffset = importDirectory.rva;
  let descriptorCount = 0;
  let hasTerminator = false;
  while (descriptorOffset + 20 <= directoryEnd) {
    if (descriptorCount >= maxImportDescriptorCount) {
      throw new InputError("import_descriptor_limit", `Import descriptor count exceeds ${maxImportDescriptorCount}`);
    }
    const lookupRvaValue = image.readUInt32LE(descriptorOffset);
    const timestamp = image.readUInt32LE(descriptorOffset + 4);
    const forwarderChain = image.readUInt32LE(descriptorOffset + 8);
    const libraryRva = image.readUInt32LE(descriptorOffset + 12);
    const iatRvaValue = image.readUInt32LE(descriptorOffset + 16);
    if (lookupRvaValue === 0 && timestamp === 0 && forwarderChain === 0 && libraryRva === 0 && iatRvaValue === 0) {
      hasTerminator = true;
      break;
    }
    if (libraryRva === 0 || iatRvaValue === 0) {
      throw new InputError("invalid_import_descriptor", "Import descriptor requires library and IAT RVA");
    }
    const library = normalizeLibrary(readAsciiZero(image, libraryRva, "import library"));
    const lookupRva = lookupRvaValue === 0 ? iatRvaValue : lookupRvaValue;
    let thunkCount = 0;
    let hasThunkTerminator = false;
    while (thunkCount < maxImportThunkCount) {
      const lookupEntryRva = lookupRva + thunkCount * 4;
      const iatEntryRva = iatRvaValue + thunkCount * 4;
      assertRange(image, lookupEntryRva, 4, `${library} import lookup entry`);
      assertRange(image, iatEntryRva, 4, `${library} import address entry`);
      const lookupValue = image.readUInt32LE(lookupEntryRva);
      if (lookupValue === 0) {
        hasThunkTerminator = true;
        break;
      }
      const isOrdinal = (lookupValue & ordinalFlag) !== 0;
      let symbol = null;
      let ordinal = null;
      let hint = null;
      if (isOrdinal) {
        ordinal = lookupValue & 0xffff;
      } else {
        assertRange(image, lookupValue, 3, `${library} import name`);
        hint = image.readUInt16LE(lookupValue);
        symbol = normalizeSymbol(
          readAsciiZero(image, lookupValue + 2, `${library} import symbol`),
          "invalid_import_symbol",
        );
      }
      const key = importKey(library, symbol, ordinal);
      const binding = catalog.get(key) ?? null;
      const originalValue = image.readUInt32LE(iatEntryRva);
      if (binding) {
        image.writeUInt32LE(binding.address, iatEntryRva);
      } else {
        resolutionBlocker.push(`Unresolved import ${library}!${symbol ?? `#${ordinal}`}`);
      }
      importValue.push({
        library,
        symbol,
        ordinal,
        hint,
        lookup_rva: lookupEntryRva,
        iat_rva: iatEntryRva,
        original_value: originalValue,
        resolution_state: binding ? "resolved" : "unresolved",
        address: binding?.address ?? null,
      });
      thunkCount += 1;
    }
    if (!hasThunkTerminator) {
      throw new InputError("import_thunk_limit", `${library} import table has no terminator within ${maxImportThunkCount} entry`);
    }
    descriptorCount += 1;
    descriptorOffset += 20;
  }
  if (!hasTerminator) {
    throw new InputError("unterminated_import_directory", "Import directory has no null descriptor within its declared size");
  }
  return { import: importValue, resolution_blocker: resolutionBlocker };
}

function addressToRva(address, loadBase, image, label, allowEnd = false) {
  const imageEnd = loadBase + image.length;
  if (!Number.isSafeInteger(address) || address < loadBase || address > imageEnd || (!allowEnd && address === imageEnd)) {
    throw new InputError("invalid_tls_address", `${label} is outside the mapped image`);
  }
  return address - loadBase;
}

function parseTls(image, tlsDirectory, loadBase, section) {
  if (tlsDirectory.rva === 0 && tlsDirectory.size_byte === 0) {
    return { tls: null, tls_callback: [] };
  }
  if (tlsDirectory.rva === 0 || tlsDirectory.size_byte < 24) {
    throw new InputError("invalid_tls_directory", "PE32 TLS directory requires 24 byte");
  }
  assertRange(image, tlsDirectory.rva, 24, "TLS directory");
  const startAddress = image.readUInt32LE(tlsDirectory.rva);
  const endAddress = image.readUInt32LE(tlsDirectory.rva + 4);
  const indexAddress = image.readUInt32LE(tlsDirectory.rva + 8);
  const callbackAddress = image.readUInt32LE(tlsDirectory.rva + 12);
  const zeroFillSizeByte = image.readUInt32LE(tlsDirectory.rva + 16);
  const characteristic = image.readUInt32LE(tlsDirectory.rva + 20);
  if ((startAddress === 0) !== (endAddress === 0)) {
    throw new InputError("invalid_tls_range", "TLS raw-data address must both be zero or both be present");
  }
  let rawRva = null;
  let rawSizeByte = 0;
  if (startAddress !== 0) {
    rawRva = addressToRva(startAddress, loadBase, image, "TLS raw-data start");
    const endRva = addressToRva(endAddress, loadBase, image, "TLS raw-data end", true);
    if (endRva < rawRva) throw new InputError("invalid_tls_range", "TLS raw-data end precedes start");
    rawSizeByte = endRva - rawRva;
    assertRange(image, rawRva, rawSizeByte, "TLS raw data");
  }
  if (zeroFillSizeByte > maxImageSizeByte || rawSizeByte > maxImageSizeByte - zeroFillSizeByte) {
    throw new InputError("tls_data_limit", `TLS raw data and zero fill must not exceed ${maxImageSizeByte} byte`);
  }
  const indexRva = indexAddress === 0 ? null : addressToRva(indexAddress, loadBase, image, "TLS index");
  if (indexRva !== null) assertRange(image, indexRva, 4, "TLS index");
  const tlsCallback = [];
  let callbackTableRva = null;
  if (callbackAddress !== 0) {
    callbackTableRva = addressToRva(callbackAddress, loadBase, image, "TLS callback table");
    let hasTerminator = false;
    for (let index = 0; index < maxTlsCallbackCount; index += 1) {
      const entryRva = callbackTableRva + index * 4;
      assertRange(image, entryRva, 4, "TLS callback table entry");
      const currentAddress = image.readUInt32LE(entryRva);
      if (currentAddress === 0) {
        hasTerminator = true;
        break;
      }
      const currentRva = addressToRva(currentAddress, loadBase, image, "TLS callback");
      const currentSection = section.find((entry) => currentRva >= entry.virtual_address && currentRva < entry.virtual_address + entry.mapped_size_byte);
      if (!currentSection || (currentSection.characteristic & executableSectionFlag) === 0) {
        throw new InputError("tls_callback_not_executable", `TLS callback 0x${currentAddress.toString(16)} is not in an executable section`);
      }
      tlsCallback.push({ address: currentAddress, rva: currentRva, section: currentSection.name });
    }
    if (!hasTerminator) {
      throw new InputError("tls_callback_limit", `TLS callback table has no terminator within ${maxTlsCallbackCount} entry`);
    }
  }
  return {
    tls: {
      directory_rva: tlsDirectory.rva,
      raw_rva: rawRva,
      raw_size_byte: rawSizeByte,
      index_rva: indexRva,
      callback_table_rva: callbackTableRva,
      zero_fill_size_byte: zeroFillSizeByte,
      characteristic,
    },
    tls_callback: tlsCallback,
  };
}

export function mapPe32(input, requestedBase = null, importCatalog = null) {
  const inputValue = inspectPath(input);
  if (inputValue.type !== "file") throw new InputError("pe_file_required", "PE32 loading requires one executable file");
  const file = readFileSync(inputValue.input_path);
  assertRange(file, 0, 64, "DOS header");
  if (file.toString("ascii", 0, 2) !== "MZ") throw new InputError("invalid_dos_signature", "Executable does not start with MZ");
  const peOffset = file.readUInt32LE(0x3c);
  assertRange(file, peOffset, 24, "PE header");
  if (file.toString("ascii", peOffset, peOffset + 4) !== "PE\0\0") throw new InputError("invalid_pe_signature", "PE signature is missing");
  const machineCode = file.readUInt16LE(peOffset + 4);
  if (machineCode !== 0x14c) throw new InputError("unsupported_machine", `PE machine 0x${machineCode.toString(16)} is not i386`);
  const sectionCount = file.readUInt16LE(peOffset + 6);
  if (sectionCount < 1 || sectionCount > 96) throw new InputError("invalid_section_count", `PE section count ${sectionCount} is outside 1..96`);
  const optionalSizeByte = file.readUInt16LE(peOffset + 20);
  const optionalOffset = peOffset + 24;
  assertRange(file, optionalOffset, optionalSizeByte, "optional header");
  if (optionalSizeByte < 96 || file.readUInt16LE(optionalOffset) !== 0x10b) throw new InputError("unsupported_optional_header", "Only PE32 optional headers are supported");
  const entryRva = file.readUInt32LE(optionalOffset + 16);
  const imageBase = file.readUInt32LE(optionalOffset + 28);
  const imageSizeByte = file.readUInt32LE(optionalOffset + 56);
  const headerSizeByte = file.readUInt32LE(optionalOffset + 60);
  const stackReserveByte = file.readUInt32LE(optionalOffset + 72);
  const stackCommitByte = file.readUInt32LE(optionalOffset + 76);
  const heapReserveByte = file.readUInt32LE(optionalOffset + 80);
  const heapCommitByte = file.readUInt32LE(optionalOffset + 84);
  if (imageSizeByte < headerSizeByte || imageSizeByte > maxImageSizeByte) throw new InputError("image_size_limit", `PE image size ${imageSizeByte} is invalid or exceeds ${maxImageSizeByte}`);
  if (headerSizeByte === 0) throw new InputError("invalid_header_size", "PE header size must be non-zero");
  assertRange(file, 0, headerSizeByte, "PE headers");
  if (stackCommitByte > stackReserveByte || heapCommitByte > heapReserveByte) {
    throw new InputError("invalid_memory_reserve", "PE stack and heap commit must not exceed reserve");
  }
  if (stackReserveByte > maxReserveSizeByte || heapReserveByte > maxReserveSizeByte) {
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
  const directoryCount = optionalSizeByte >= 96 ? Math.min(file.readUInt32LE(optionalOffset + 92), 16) : 0;
  const directoryOffset = optionalOffset + 96;
  const directory = [];
  for (let index = 0; index < directoryCount && directoryOffset + index * 8 + 8 <= optionalOffset + optionalSizeByte; index += 1) {
    directory.push({ index, rva: file.readUInt32LE(directoryOffset + index * 8), size_byte: file.readUInt32LE(directoryOffset + index * 8 + 4) });
  }
  const importDirectory = directory[1] ?? { rva: 0, size_byte: 0 };
  const relocationDirectory = directory[5] ?? { rva: 0, size_byte: 0 };
  const tlsDirectory = directory[9] ?? { rva: 0, size_byte: 0 };
  const loadBase = requestedBase === null ? imageBase : Number(requestedBase);
  if (!Number.isSafeInteger(loadBase) || loadBase < 0 || loadBase > 0xffffffff) throw new InputError("invalid_load_base", "Requested load base must be a 32-bit unsigned integer");
  if (loadBase + imageSizeByte > 0x100000000) throw new InputError("image_address_overflow", "Mapped PE32 image exceeds the 32-bit address space");
  const delta = loadBase - imageBase;
  let relocationCount = 0;
  if ((relocationDirectory.rva === 0) !== (relocationDirectory.size_byte === 0)) {
    throw new InputError("invalid_relocation_directory", "Relocation directory requires both RVA and size");
  }
  if (delta !== 0) {
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
        if (type === 0) continue;
        if (type !== 3 || targetRva + 4 > image.length) throw new InputError("unsupported_relocation", `Relocation type ${type} is unsupported or out of range`);
        image.writeUInt32LE((image.readUInt32LE(targetRva) + delta) >>> 0, targetRva);
        relocationCount += 1;
      }
      offset += blockSizeByte;
    }
    if (offset !== end) throw new InputError("invalid_relocation_block", "Relocation directory has trailing partial data");
  }
  const catalog = createImportCatalog(importCatalog, loadBase, imageSizeByte);
  const importReport = parseImport(image, importDirectory, catalog);
  const tlsReport = parseTls(image, tlsDirectory, loadBase, section);
  const resolutionBlocker = [...importReport.resolution_blocker];
  const runtimeBlocker = [];
  if (tlsReport.tls_callback.length > 0) runtimeBlocker.push("TLS callback execution is not implemented");
  runtimeBlocker.push("The mapped entry point is not executed because the i386 and Win32 runtime is not implemented");
  const resolvedImportCount = importReport.import.filter((entry) => entry.resolution_state === "resolved").length;
  const unresolvedImportCount = importReport.import.length - resolvedImportCount;
  const blocker = [...resolutionBlocker, ...runtimeBlocker];
  return {
    schema_version: 1,
    input_path: inputValue.input_path,
    machine: "i386",
    image_base: imageBase,
    load_base: loadBase,
    image_size_byte: imageSizeByte,
    entry_rva: entryRva,
    entry_address: loadBase + entryRva,
    entry_section: entrySection.name,
    stack_reserve_byte: stackReserveByte,
    stack_commit_byte: stackCommitByte,
    heap_reserve_byte: heapReserveByte,
    heap_commit_byte: heapCommitByte,
    section,
    relocation_count: relocationCount,
    directory,
    import: importReport.import,
    import_count: importReport.import.length,
    resolved_import_count: resolvedImportCount,
    unresolved_import_count: unresolvedImportCount,
    import_directory: importDirectory,
    tls_directory: tlsDirectory,
    tls: tlsReport.tls,
    tls_callback: tlsReport.tls_callback,
    tls_callback_count: tlsReport.tls_callback.length,
    image_sha256: createHash("sha256").update(image).digest("hex"),
    state: resolutionBlocker.length === 0 ? "resolved_static_image" : "mapped_with_unresolved_import",
    resolution_blocker: resolutionBlocker,
    runtime_blocker: runtimeBlocker,
    blocker,
    is_executed: false,
  };
}
