// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { inspectPath, InputError } from "./input.mjs";

const maxImageSizeByte = 128 * 1024 * 1024;

function assertRange(buffer, offset, sizeByte, label) {
  if (!Number.isInteger(offset) || !Number.isInteger(sizeByte) || offset < 0 || sizeByte < 0 || offset + sizeByte > buffer.length) {
    throw new InputError("invalid_pe_range", `${label} is outside the executable`);
  }
}

function readName(buffer, offset, sizeByte) {
  assertRange(buffer, offset, sizeByte, "name");
  const end = buffer.indexOf(0, offset);
  const boundedEnd = end >= offset && end < offset + sizeByte ? end : offset + sizeByte;
  return buffer.toString("ascii", offset, boundedEnd);
}

export function mapPe32(input, requestedBase = null) {
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
  const sectionOffset = optionalOffset + optionalSizeByte;
  assertRange(file, sectionOffset, sectionCount * 40, "section table");
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
    section.push({ name, virtual_address: virtualAddress, virtual_size_byte: virtualSizeByte, raw_offset: rawOffset, raw_size_byte: rawSizeByte, characteristic: file.readUInt32LE(offset + 36) });
  }
  const image = Buffer.alloc(imageSizeByte);
  file.copy(image, 0, 0, Math.min(headerSizeByte, file.length, image.length));
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
  const delta = loadBase - imageBase;
  let relocationCount = 0;
  if (delta !== 0) {
    if (relocationDirectory.rva === 0 || relocationDirectory.size_byte === 0) throw new InputError("relocation_required", "Requested load base differs and the image has no relocation directory");
    let offset = relocationDirectory.rva;
    const end = Math.min(image.length, relocationDirectory.rva + relocationDirectory.size_byte);
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
  }
  const blocker = [];
  if (importDirectory.rva !== 0) blocker.push("Import directory is present; Win32 symbol resolution is not implemented");
  if (tlsDirectory.rva !== 0) blocker.push("TLS directory is present; callback execution is not implemented");
  blocker.push("The mapped entry point is not executed because the i386 and Win32 runtime is not implemented");
  return {
    schema_version: 1,
    input_path: inputValue.input_path,
    machine: "i386",
    image_base: imageBase,
    load_base: loadBase,
    image_size_byte: imageSizeByte,
    entry_rva: entryRva,
    entry_address: loadBase + entryRva,
    stack_reserve_byte: stackReserveByte,
    stack_commit_byte: stackCommitByte,
    heap_reserve_byte: heapReserveByte,
    heap_commit_byte: heapCommitByte,
    section,
    relocation_count: relocationCount,
    import_directory: importDirectory,
    tls_directory: tlsDirectory,
    image_sha256: createHash("sha256").update(image).digest("hex"),
    state: blocker.length === 1 ? "mapped" : "mapped_with_unresolved_runtime",
    blocker,
    is_executed: false,
  };
}
