// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Static installer extraction for BPTK-038. The extractor reads a supported
// installer container, enumerates the payload, and optionally writes the
// payload files under a caller-declared directory. Installer code is never
// executed: the module performs no process launch, no dynamic evaluation, and
// no interpretation of payload byte beyond checksum verification. Every read,
// decompression, and write is bounded by the declared extraction bound from
// lib/bound.mjs. Format support is pinned to the documented Inno Setup 6
// unicode setup-data family and to MSCF cabinet with stored or MSZIP folder.

import { closeSync, fstatSync, mkdirSync, openSync, readSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { inflateRawSync, inflateSync } from "node:zlib";
import { dirname, relative, resolve, sep } from "node:path";
import {
  assertChunkInputBound,
  assertChunkRatioBound,
  assertDepthBound,
  assertEntryBound,
  assertOutputBound,
  chunkOutputCap,
  createExtractionBound,
  describeExtractionBound,
} from "./bound.mjs";
import { InputError } from "./input.mjs";

const crcTable = (() => {
  const table = new Int32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    table[index] = value;
  }
  return table;
})();

function crc32(buffer, start = 0, end = buffer.length) {
  let value = 0xffffffff;
  for (let index = start; index < end; index += 1) value = crcTable[(value ^ buffer[index]) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

function extractorError(code, message) {
  return new InputError(code, message);
}

// Bounded reader over one opened file descriptor. Every read is explicit and
// capped so a hostile size field cannot grow the resident buffer unbounded.
class BoundedFile {
  constructor(path) {
    this.path = resolve(path);
    this.descriptor = openSync(this.path, "r");
    this.sizeByte = fstatSync(this.descriptor).size;
  }

  close() {
    try {
      closeSync(this.descriptor);
    } catch {
      // The bounded reads are complete and the descriptor state is already best effort.
    }
  }

  slice(offset, lengthByte) {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > this.sizeByte) {
      throw extractorError("extractor_read_failure", `Read offset ${offset} is outside the installer`);
    }
    const length = Math.min(Number(lengthByte), this.sizeByte - offset);
    if (length < 0) throw extractorError("extractor_read_failure", "Read extends past the installer end");
    const buffer = Buffer.alloc(length);
    let readByte = 0;
    while (readByte < length) {
      const current = readSync(this.descriptor, buffer, readByte, length - readByte, offset + readByte);
      if (current <= 0) throw extractorError("extractor_read_failure", "Installer ended before its declared structure");
      readByte += current;
    }
    return buffer;
  }
}

// Pull reader over the Inno block stream: one CRC-protected header per zlib
// or stored frame, and a CRC32 word ahead of every 4096 decompressed byte
// inside the frame. The CRC sub-block word are stripped and verified here so
// the consumer sees the plain header byte stream.
class BlockReader {
  constructor(file, offset, bound) {
    this.file = file;
    this.position = offset;
    this.bound = bound;
    this.chunk = null;
    this.chunkPosition = 0;
  }

  fillChunk() {
    const expectedCrc = this.file.slice(this.position, 4).readUInt32LE(0);
    const header = this.file.slice(this.position + 4, 5);
    if (crc32(header) !== expectedCrc) {
      throw extractorError("installer_block_checksum", "Inno block header CRC32 mismatch");
    }
    const storedSize = header.readUInt32LE(0);
    const isCompressed = header.readUInt8(4) !== 0;
    this.position += 9;
    const payload = this.file.slice(this.position, storedSize);
    this.position += storedSize;
    assertChunkInputBound(this.bound, storedSize);
    let framed;
    if (isCompressed) {
      try {
        framed = inflateSync(payload, { maxOutputLength: this.bound.chunk_input_byte });
      } catch {
        throw extractorError("bound_output_exceeded", "Inno block decompression exceeds the declared read bound");
      }
    } else {
      framed = payload;
    }
    const part = [];
    let cursor = 0;
    while (cursor < framed.length) {
      const subCrc = framed.readUInt32LE(cursor);
      const subLength = Math.min(4096, framed.length - cursor - 4);
      const subData = framed.subarray(cursor + 4, cursor + 4 + subLength);
      if (crc32(subData) !== subCrc) {
        throw extractorError("installer_block_checksum", "Inno block sub-block CRC32 mismatch");
      }
      part.push(subData);
      cursor += 4 + subLength;
    }
    this.chunk = Buffer.concat(part);
    this.chunkPosition = 0;
  }

  nextByte() {
    if (this.chunk === null || this.chunkPosition >= this.chunk.length) this.fillChunk();
    const value = this.chunk[this.chunkPosition];
    this.chunkPosition += 1;
    return value;
  }

  readBytes(lengthByte) {
    const buffer = Buffer.alloc(lengthByte);
    for (let index = 0; index < lengthByte; index += 1) buffer[index] = this.nextByte();
    return buffer;
  }

  readU8() {
    return this.nextByte();
  }

  readU16() {
    return this.readBytes(2).readUInt16LE(0);
  }

  readU32() {
    return this.readBytes(4).readUInt32LE(0);
  }

  readI32() {
    return this.readBytes(4).readInt32LE(0);
  }

  readU64() {
    return Number(this.readBytes(8).readBigUInt64LE(0));
  }

  readBool() {
    return this.readU8() !== 0;
  }

  readBinaryString() {
    const lengthByte = Number(this.readU32());
    if (lengthByte > this.bound.chunk_input_byte) {
      throw extractorError("bound_input_exceeded", "Inno string exceeds the declared read bound");
    }
    return this.readBytes(lengthByte);
  }

  // Unicode installers store an encoded string as a byte length plus UTF-16LE
  // text; non-unicode field reuse the same prefix with single byte text.
  readEncodedString() {
    return this.readBinaryString().toString("utf16le");
  }
}

// Reads the packed Inno flag bit field: one byte per eight declared flag and a
// padding byte when exactly three byte are stored.
function readFlags(reader, flagCount) {
  const flag = new Array(flagCount).fill(false);
  let byte = null;
  for (let index = 0; index < flagCount; index += 1) {
    if (index % 8 === 0) byte = reader.readU8();
    flag[index] = (byte & (1 << index % 8)) !== 0;
  }
  if (Math.ceil(flagCount / 8) === 3) reader.readU8();
  return flag;
}

function readWindowsVersionRange(reader) {
  reader.readBytes(20);
}

// The supported setup-data census: the Inno Setup 6 unicode family. Every
// other setup-data version is refused with its identity recorded.
const innoFamily = Object.freeze([
  { id: "Inno Setup Setup Data (6.0.0) (u)", minor: 0 },
  { id: "Inno Setup Setup Data (6.1.0) (u)", minor: 1 },
  { id: "Inno Setup Setup Data (6.3.0)", minor: 3 },
]);

// Loader magic with their revision-field layout: 5.1.5 and newer store a
// revision word between the magic and the offset body; older magic do not.
const innoLoaderMagic = Object.freeze({
  "rDlPtS06\x87eVx": { is_revisioned: false },
  "rDlPtS07\x87eVx": { is_revisioned: false },
  "rDlPtS\xcd\xe6\xd7{\x0b*": { is_revisioned: true },
  "nS5W7d\x83\xaa\x1b\x0fj": { is_revisioned: true },
});

function locateInnoResource(file) {
  if (file.sizeByte < 0x100 || file.slice(0, 2).readUInt16LE(0) !== 0x5a4d) return null;
  const headerOffset = file.slice(0x3c, 4).readUInt32LE(0);
  if (headerOffset + 248 > file.sizeByte || file.slice(headerOffset, 4).toString("ascii") !== "PE\0\0") return null;
  const sectionCount = file.slice(headerOffset + 6, 2).readUInt16LE(0);
  const optionalSize = file.slice(headerOffset + 20, 2).readUInt16LE(0);
  const sectionTable = headerOffset + 24 + optionalSize;
  if (sectionTable + sectionCount * 40 > file.sizeByte) return null;
  const section = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const entry = sectionTable + index * 40;
    section.push({
      name: file.slice(entry, 8).toString("ascii").replace(/\0.*$/, ""),
      virtual_address: file.slice(entry + 12, 4).readUInt32LE(0),
      virtual_size: file.slice(entry + 8, 4).readUInt32LE(0),
      raw_address: file.slice(entry + 20, 4).readUInt32LE(0),
    });
  }
  const resourceSection = section.find((entry) => entry.name === ".rsrc");
  if (!resourceSection) return null;
  const directoryBase = resourceSection.raw_address;
  const readDirectory = (offset) => {
    const namedCount = file.slice(directoryBase + offset + 12, 2).readUInt16LE(0);
    const idCount = file.slice(directoryBase + offset + 14, 2).readUInt16LE(0);
    const entry = [];
    for (let index = 0; index < namedCount + idCount; index += 1) {
      const record = file.slice(directoryBase + offset + 16 + index * 8, 8);
      entry.push({ name: record.readUInt32LE(0), value: record.readUInt32LE(4) });
    }
    return entry;
  };
  const walk = (offset, depthCount) => {
    if (depthCount > 3) return null;
    for (const current of readDirectory(offset)) {
      const isDirectory = (current.value & 0x80000000) !== 0;
      if (depthCount === 0 && (isDirectory || current.name !== 11111)) continue;
      if (isDirectory) {
        const found = walk(current.value & 0x7fffffff, depthCount + 1);
        if (found !== null) return found;
        continue;
      }
      const dataRecord = file.slice(directoryBase + (current.value & 0x7fffffff), 16);
      const dataRva = dataRecord.readUInt32LE(0);
      for (const sectionEntry of section) {
        if (dataRva >= sectionEntry.virtual_address && dataRva < sectionEntry.virtual_address + Math.max(sectionEntry.virtual_size, 1)) {
          return sectionEntry.raw_address + dataRva - sectionEntry.virtual_address;
        }
      }
    }
    return null;
  };
  return walk(0, 0);
}

function locateOffsetTable(file, evidence) {
  // Primary loader form: a fixed pointer at file offset 0x30 protected by an
  // inverted-offset checksum, used before Inno Setup 5.1.5.
  if (file.sizeByte >= 0x3c) {
    const probe = file.slice(0x30, 8);
    if (probe.length === 8 && probe.readUInt32LE(0) === 0x6f6e6e49) {
      const offset = probe.readUInt32LE(4);
      const inverse = file.slice(0x38, 4).readUInt32LE(0);
      if (offset !== (~inverse >>> 0)) {
        throw extractorError("installer_offset_checksum", "Inno loader offset checksum does not match");
      }
      evidence.push("loader offset table found at the fixed 0x30 pointer");
      return offset;
    }
  }
  // 5.1.5+ loader form: the offset table lives in a PE resource named 11111.
  const resourceOffset = locateInnoResource(file);
  if (resourceOffset !== null) {
    evidence.push("loader offset table found in the 11111 resource entry");
    return resourceOffset;
  }
  return null;
}

function readOffsetTable(file, tableOffset, evidence) {
  const magic = file.slice(tableOffset, 12);
  const loader = innoLoaderMagic[magic.toString("latin1")];
  if (!loader) {
    throw extractorError("installer_version_unsupported", "The Inno loader magic is outside the supported census");
  }
  evidence.push("loader magic identifies an Inno Setup 4.0.10 or newer loader");
  // Loader offset table layout: [magic 12][revision 4 if revisioned]
  // [unused 4][exe_offset 4][exe_uncompressed_size 4][exe_checksum 4]
  // [header_offset 4][data_offset 4][crc32 4] with the CRC covering all
  // preceding byte. Supported magic are 4.1.6 or newer so the compressed-size
  // field is never present.
  let bodyOffset = tableOffset + 12;
  if (loader.is_revisioned) {
    if (file.sizeByte < bodyOffset + 4) throw extractorError("extractor_read_failure", "Inno offset table is truncated");
    const revision = file.slice(bodyOffset, 4).readUInt32LE(0);
    if (revision !== 1) {
      throw extractorError("installer_revision_unsupported", `Unexpected Inno loader revision ${revision}`);
    }
    bodyOffset += 4;
  }
  const body = file.slice(bodyOffset, bodyOffset + 28);
  if (body.length < 28) throw extractorError("extractor_read_failure", "Inno offset table is truncated");
  const actualCrc = crc32(Buffer.concat([magic, body.subarray(0, 24)]));
  if (actualCrc !== body.readUInt32LE(24)) {
    throw extractorError("installer_offset_checksum", "Inno loader offset table CRC32 mismatch");
  }
  return {
    header_offset: body.readUInt32LE(16),
    data_offset: body.readUInt32LE(20),
  };
}

function assertSetupVersion(versionId, evidence) {
  const family = innoFamily.find((entry) => {
    const declared = Buffer.from(entry.id, "latin1");
    return versionId.length >= declared.length && versionId.subarray(0, declared.length).equals(declared);
  });
  if (!family) {
    const listed = versionId.toString("latin1").replace(/\0.*$/, "");
    throw extractorError("installer_version_unsupported", `Setup data version "${listed}" is outside the supported Inno Setup 6 census`);
  }
  evidence.push(`setup data version ${family.id}`);
  return family;
}

function parseInnoHeader(reader, family) {
  const hasArchitectureField = family.minor >= 3;
  const header = {};
  const text = () => reader.readEncodedString();
  const blob = () => reader.readBinaryString();
  header.app_name = text();
  header.app_versioned_name = text();
  header.app_id = blob().toString("latin1");
  header.app_copyright = text();
  header.app_publisher = text();
  header.app_publisher_url = text();
  header.app_support_phone = text();
  header.app_support_url = text();
  header.app_updates_url = text();
  header.app_version = text();
  header.default_dir_name = text();
  header.default_group_name = text();
  header.base_filename = text();
  header.uninstall_files_dir = text();
  header.uninstall_name = text();
  header.uninstall_icon = text();
  header.app_mutex = text();
  header.default_user_name = text();
  header.default_user_organisation = text();
  header.default_serial = text();
  header.app_readme_file = text();
  header.app_contact = text();
  header.app_comments = text();
  header.app_modify_path = text();
  header.create_uninstall_registry_key = text();
  header.uninstallable = text();
  header.close_applications_filter = text();
  header.setup_mutex = text();
  header.changes_environment = text();
  header.changes_associations = text();
  if (hasArchitectureField) {
    header.architectures_allowed_expr = text();
    header.architectures_installed_in_64bit_mode_expr = text();
  }
  header.license_text = blob();
  header.info_before = blob();
  header.info_after = blob();
  header.compiled_code = blob();

  header.language_count = reader.readU32();
  header.message_count = reader.readU32();
  header.permission_count = reader.readU32();
  header.type_count = reader.readU32();
  header.component_count = reader.readU32();
  header.task_count = reader.readU32();
  header.directory_count = reader.readU32();
  header.file_count = reader.readU32();
  header.data_entry_count = reader.readU32();
  header.icon_count = reader.readU32();
  header.ini_entry_count = reader.readU32();
  header.registry_entry_count = reader.readU32();
  header.delete_entry_count = reader.readU32();
  header.uninstall_delete_entry_count = reader.readU32();
  header.run_entry_count = reader.readU32();
  header.uninstall_run_entry_count = reader.readU32();

  readWindowsVersionRange(reader);
  reader.readU32(); // back_color
  reader.readU32(); // back_color2
  reader.readU8(); // wizard_style
  reader.readU32(); // wizard_resize_percent_x
  reader.readU32(); // wizard_resize_percent_y
  reader.readU8(); // image_alpha_format
  reader.readBytes(20); // password sha1
  reader.readBytes(8); // password salt
  reader.readU64(); // extra_disk_space_required
  header.slices_per_disk = reader.readU32();
  reader.readU8(); // uninstall_log_mode
  reader.readU8(); // dir_exists_warning
  reader.readU8(); // privileges_required
  reader.readU8(); // privileges_required_override_allowed
  reader.readU8(); // show_language_dialog
  reader.readU8(); // language_detection
  header.compression = reader.readU8();
  if (!hasArchitectureField) {
    reader.readU8(); // architectures_allowed
    reader.readU8(); // architectures_installed_in_64bit_mode
  }
  reader.readU8(); // disable_dir_page
  reader.readU8(); // disable_program_group_page
  reader.readU64(); // uninstall_display_size
  // 6.0 and 6.1 declare 48 setup flag and 6.3 declares 49.
  readFlags(reader, hasArchitectureField ? 49 : 48);
  return header;
}

function skipConditionData(reader) {
  reader.readEncodedString(); // components
  reader.readEncodedString(); // tasks
  reader.readEncodedString(); // languages
  reader.readEncodedString(); // check
  reader.readEncodedString(); // after_install
  reader.readEncodedString(); // before_install
}

function skipSections(reader, header, family) {
  for (let index = 0; index < header.language_count; index += 1) {
    for (let field = 0; field < 10; field += 1) reader.readBinaryString();
    reader.readU32(); // language_id
    reader.readU32(); // dialog_font_size
    reader.readU32(); // title_font_size
    reader.readU32(); // welcome_font_size
    reader.readU32(); // copyright_font_size
    reader.readU8(); // right_to_left
  }
  for (let index = 0; index < header.message_count; index += 1) {
    reader.readEncodedString();
    reader.readBinaryString();
    reader.readI32();
  }
  for (let index = 0; index < header.permission_count; index += 1) {
    reader.readBinaryString();
  }
  for (let index = 0; index < header.type_count; index += 1) {
    reader.readEncodedString();
    reader.readEncodedString();
    reader.readEncodedString();
    reader.readEncodedString();
    readWindowsVersionRange(reader);
    readFlags(reader, 1);
    reader.readU8(); // setup type
    reader.readU64(); // size
  }
  for (let index = 0; index < header.component_count; index += 1) {
    for (let field = 0; field < 5; field += 1) reader.readEncodedString();
    reader.readU64(); // extra_disk_space_required
    reader.readI32(); // level
    reader.readBool(); // used
    readWindowsVersionRange(reader);
    readFlags(reader, 5);
    reader.readU64(); // size
  }
  for (let index = 0; index < header.task_count; index += 1) {
    for (let field = 0; field < 6; field += 1) reader.readEncodedString();
    reader.readI32(); // level
    reader.readBool(); // used
    readWindowsVersionRange(reader);
    readFlags(reader, 5);
  }
  for (let index = 0; index < header.directory_count; index += 1) {
    reader.readEncodedString();
    skipConditionData(reader);
    reader.readU32(); // attributes
    readWindowsVersionRange(reader);
    reader.readI32(); // permission
    readFlags(reader, 5);
  }
  const file = [];
  for (let index = 0; index < header.file_count; index += 1) {
    const source = reader.readEncodedString();
    const destination = reader.readEncodedString();
    reader.readEncodedString(); // install_font_name
    reader.readEncodedString(); // strong_assembly_name
    skipConditionData(reader);
    readWindowsVersionRange(reader);
    const location = reader.readU32();
    reader.readU32(); // attributes
    reader.readU64(); // external_size
    reader.readI32(); // permission
    readFlags(reader, 32);
    reader.readU8(); // file type
    file.push({ source, destination, location });
  }
  for (let index = 0; index < header.icon_count; index += 1) {
    for (let field = 0; field < 6; field += 1) reader.readEncodedString();
    skipConditionData(reader);
    reader.readEncodedString(); // app_user_model_id
    if (family.minor >= 1) reader.readBytes(16); // toast activator clsid
    readWindowsVersionRange(reader);
    reader.readU32(); // icon_index
    reader.readI32(); // show_command
    reader.readU8(); // close_on_exit
    reader.readU16(); // hotkey
    readFlags(reader, family.minor >= 3 ? 6 : family.minor >= 1 ? 7 : 6);
  }
  for (let index = 0; index < header.ini_entry_count; index += 1) {
    for (let field = 0; field < 4; field += 1) reader.readEncodedString();
    skipConditionData(reader);
    readWindowsVersionRange(reader);
    readFlags(reader, 5);
  }
  for (let index = 0; index < header.registry_entry_count; index += 1) {
    reader.readEncodedString();
    reader.readEncodedString();
    reader.readBinaryString();
    skipConditionData(reader);
    readWindowsVersionRange(reader);
    reader.readU32(); // hive
    reader.readI32(); // permission
    reader.readU8(); // value type
    readFlags(reader, 12);
  }
  for (let index = 0; index < header.delete_entry_count + header.uninstall_delete_entry_count; index += 1) {
    reader.readEncodedString();
    skipConditionData(reader);
    readWindowsVersionRange(reader);
    reader.readU8(); // delete type
  }
  for (let index = 0; index < header.run_entry_count + header.uninstall_run_entry_count; index += 1) {
    for (let field = 0; field < 7; field += 1) reader.readEncodedString();
    skipConditionData(reader);
    readWindowsVersionRange(reader);
    reader.readI32(); // show_command
    reader.readU8(); // wait condition
    readFlags(reader, family.minor >= 3 ? 12 : family.minor >= 1 ? 11 : 10);
  }
  return file;
}

function readWizardAndDecompressor(reader, header) {
  for (let pass = 0; pass < 2; pass += 1) {
    const count = reader.readU32();
    for (let index = 0; index < count; index += 1) reader.readBinaryString();
  }
  // zlib-compressed installers carry an external decompressor dll blob.
  if (header.compression === 1) reader.readBinaryString();
}

function readDataEntries(reader, header, family, bound) {
  const entry = [];
  for (let index = 0; index < header.data_entry_count; index += 1) {
    reader.readU32(); // first_slice
    reader.readU32(); // last_slice
    const chunkOffset = reader.readU32();
    const fileOffset = reader.readU64();
    const fileSize = reader.readU64();
    const chunkSize = reader.readU64();
    const checksum = reader.readBytes(20).toString("hex"); // sha1
    reader.readU64(); // filetime
    reader.readU32(); // file_version_ms
    reader.readU32(); // file_version_ls
    const flag = readFlags(reader, 9);
    if (family.minor >= 3) reader.readU8(); // sign mode
    if (flag[6]) {
      throw extractorError("installer_chunk_encrypted", "Encrypted payload chunk are outside the supported extraction census");
    }
    entry.push({
      chunk_offset: chunkOffset,
      file_offset: fileOffset,
      file_size: fileSize,
      chunk_size: chunkSize,
      checksum,
      is_chunk_compressed: flag[7],
      has_instruction_filter: flag[4],
    });
  }
  return entry;
}

// Undoes the Inno Setup 5.3.9+ call and jump address transform on a decoded
// executable slice. The transform is length preserving and deterministic.
function applyInstructionFilter(input, isFlipHighByte) {
  const output = Buffer.alloc(input.length);
  const buffer = Buffer.from([0, 0, 0, 0]);
  let flushCount = 0;
  let offset = 0;
  let source = 0;
  let destination = 0;
  const flush = (count) => {
    if (count <= 0) return;
    flushCount = count;
    let index = 0;
    do {
      if (destination === input.length) {
        buffer.copy(buffer, 0, index);
        return;
      }
      output[destination] = buffer[index];
      destination += 1;
      index += 1;
    } while ((flushCount -= 1) > 0);
  };
  flush(flushCount);
  while (destination < input.length) {
    if (flushCount === 0) {
      if (source >= input.length) break;
      const byte = input[source];
      source += 1;
      offset += 1;
      output[destination] = byte;
      destination += 1;
      if (byte !== 0xe8 && byte !== 0xe9) continue;
      if (0x10000 - ((offset - 1) % 0x10000) < 5) continue;
      flushCount = -4;
    }
    const take = Math.min(-flushCount, input.length - source);
    input.copy(buffer, 4 + flushCount, source, source + take);
    source += take;
    offset += take;
    flushCount += take;
    if (flushCount < 0) {
      flush(4 + flushCount);
      continue;
    }
    if (buffer[3] === 0x00 || buffer[3] === 0xff) {
      const address = offset & 0xffffff;
      let relative = (buffer[0] | (buffer[1] << 8) | (buffer[2] << 16)) >>> 0;
      relative = (relative - address) >>> 0;
      buffer[0] = relative & 0xff;
      buffer[1] = (relative >>> 8) & 0xff;
      buffer[2] = (relative >>> 16) & 0xff;
      if (isFlipHighByte && (relative & 0x800000) !== 0) buffer[3] = ~buffer[3] & 0xff;
    }
    flush(4);
  }
  return output;
}

const chunkMagic = Buffer.from([0x7a, 0x6c, 0x62, 0x1a]); // zlb + eof marker

function decompressChunk(file, dataOffset, entry, bound) {
  assertChunkInputBound(bound, entry.chunk_size);
  const magic = file.slice(dataOffset + entry.chunk_offset, 4);
  if (!magic.equals(chunkMagic)) {
    throw extractorError("installer_chunk_magic", "Payload chunk does not carry the Inno chunk magic");
  }
  const payload = file.slice(dataOffset + entry.chunk_offset + 4, entry.chunk_size);
  if (entry.is_chunk_compressed) {
    const cap = chunkOutputCap(bound, entry.chunk_size);
    let output;
    try {
      output = inflateSync(payload, { maxOutputLength: cap });
    } catch {
      throw extractorError("bound_ratio_exceeded", `Payload chunk amplification exceeds the declared bound ${bound.ratio_max}`);
    }
    assertChunkRatioBound(bound, entry.chunk_size, output.length);
    return output;
  }
  return payload;
}

function sanitizePayloadPath(part, destination, bound) {
  if (part.some((entry) => entry === "..")) {
    throw extractorError("payload_path_escape", `Payload destination escapes its directory: ${destination}`);
  }
  if (part.length === 0) {
    throw extractorError("payload_path_escape", `Payload destination resolves to no file: ${destination}`);
  }
  assertDepthBound(bound, part.length);
  return part.join("/");
}

// Inno Setup destinations are expressed against install constants; only the
// {app} root is in the bounded extraction census and every other constant is
// refused so a payload can never name a host path outside the output.
function resolveInnoPayloadPath(destination, bound) {
  const match = /^\{app\}(.*)$/i.exec(destination);
  if (!match) {
    throw extractorError("installer_const_unsupported", `Payload destination does not resolve inside {app}: ${destination}`);
  }
  if (/\{[^}]*\}/.test(match[1])) {
    throw extractorError("installer_const_unsupported", `Payload destination uses an unsupported installer constant: ${destination}`);
  }
  const part = match[1].replace(/\\/g, "/").split("/").filter((entry) => entry.length > 0 && entry !== ".");
  return sanitizePayloadPath(part, destination, bound);
}

// Cabinet payload name are already plain relative path.
function resolveCabinetPayloadPath(name, bound) {
  if (/\{[^}]*\}/.test(name)) {
    throw extractorError("installer_const_unsupported", `Payload destination uses an unsupported installer constant: ${name}`);
  }
  const part = name.replace(/\\/g, "/").split("/").filter((entry) => entry.length > 0 && entry !== ".");
  if (/^[a-zA-Z]:/.test(name) || name.startsWith("/")) {
    throw extractorError("payload_path_escape", `Payload destination is absolute: ${name}`);
  }
  return sanitizePayloadPath(part, name, bound);
}

function parseInno(file, bound, evidence) {
  const tableOffset = locateOffsetTable(file, evidence);
  if (tableOffset === null) {
    throw extractorError("installer_offset_missing", "No Inno offset table was found at the fixed pointer or the 11111 resource");
  }
  const table = readOffsetTable(file, tableOffset, evidence);
  const versionId = file.slice(table.header_offset, 64);
  const family = assertSetupVersion(versionId, evidence);
  const reader = new BlockReader(file, table.header_offset + 64, bound);
  const header = parseInnoHeader(reader, family);
  if (header.compression > 1) {
    throw extractorError("installer_compression_unsupported", "Only stored and zlib Inno chunk compression are in the supported census");
  }
  const fileEntry = skipSections(reader, header, family);
  readWizardAndDecompressor(reader, header);
  const dataEntry = readDataEntries(reader, header, family, bound);
  assertEntryBound(bound, header.file_count);

  const chunkCache = new Map();
  const payloadFile = [];
  let outputByte = 0;
  for (const entry of fileEntry) {
    const location = dataEntry[entry.location];
    if (!location) {
      throw extractorError("installer_location_missing", `Payload file references missing data entry ${entry.location}`);
    }
    const cacheKey = `${location.chunk_offset}:${location.chunk_size}:${location.is_chunk_compressed}`;
    if (!chunkCache.has(cacheKey)) {
      chunkCache.set(cacheKey, decompressChunk(file, table.data_offset, location, bound));
    }
    const chunkData = chunkCache.get(cacheKey);
    if (location.file_offset + location.file_size > chunkData.length) {
      throw extractorError("installer_file_out_of_chunk", "Payload file extends past its decoded chunk");
    }
    let content = Buffer.from(chunkData.subarray(location.file_offset, location.file_offset + location.file_size));
    if (location.has_instruction_filter) {
      content = applyInstructionFilter(content, family.minor >= 3);
    }
    const actualChecksum = createHash("sha1").update(content).digest("hex");
    if (actualChecksum !== location.checksum) {
      throw extractorError("installer_checksum_mismatch", `Payload file failed its sha1 reference: ${entry.destination}`);
    }
    outputByte += content.length;
    assertOutputBound(bound, outputByte);
    payloadFile.push({
      path: resolveInnoPayloadPath(entry.destination, bound),
      size_byte: content.length,
      checksum_state: "verified",
      content,
    });
  }
  return {
    family: "inno_setup_6",
    version_id: family.id,
    file: payloadFile,
    output_byte: outputByte,
    evidence,
    header_summary: { app_name: header.app_name, compression: header.compression === 1 ? "zlib" : "stored" },
  };
}

function parseCabinet(file, bound, evidence) {
  const header = file.slice(0, 36);
  const cabinetSize = header.readUInt32LE(8);
  if (cabinetSize > file.sizeByte) {
    throw extractorError("installer_cabinet_truncated", "The MSCF cabinet declares more byte than the file holds");
  }
  const fileOffset = header.readUInt32LE(16);
  const folderCount = header.readUInt16LE(26);
  const fileCount = header.readUInt16LE(28);
  const flags = header.readUInt16LE(30);
  if ((flags & 0b1110) !== 0) {
    throw extractorError("installer_cabinet_flag_unsupported", "Multi-cabinet or reserved-area cabinet flag are outside the supported census");
  }
  assertEntryBound(bound, fileCount);
  evidence.push("MSCF cabinet with stored or MSZIP folder");
  let position = 36;
  const folder = [];
  for (let index = 0; index < folderCount; index += 1) {
    const record = file.slice(position, 12);
    folder.push({
      data_offset: record.readUInt32LE(0),
      data_block_count: record.readUInt16LE(4),
      compression: record.readUInt16LE(6),
    });
    position += 12;
  }
  const folderData = new Map();
  const decodeFolder = (folderIndex) => {
    if (folderData.has(folderIndex)) return folderData.get(folderIndex);
    const current = folder[folderIndex];
    if (!current) throw extractorError("installer_cabinet_folder", "Payload file references a missing cabinet folder");
    if (current.compression > 1) {
      throw extractorError("installer_compression_unsupported", "Only stored and MSZIP cabinet folder are in the supported census");
    }
    let data = Buffer.alloc(0);
    let blockPosition = current.data_offset;
    for (let blockIndex = 0; blockIndex < current.data_block_count; blockIndex += 1) {
      if (blockPosition + 8 > file.sizeByte) throw extractorError("installer_block_checksum", "Cabinet data block is truncated");
      const block = file.slice(blockPosition, 8);
      const compressedByte = block.readUInt16LE(4);
      const uncompressedByte = block.readUInt16LE(6);
      blockPosition += 8;
      const blockData = file.slice(blockPosition, compressedByte);
      blockPosition += compressedByte;
      let decoded;
      if (current.compression === 1) {
        if (blockData.length < 2 || blockData[0] !== 0x43 || blockData[1] !== 0x4b) {
          throw extractorError("installer_chunk_magic", "MSZIP block does not carry the CK signature");
        }
        decoded = inflateRawSync(blockData.subarray(2), { maxOutputLength: uncompressedByte + 1 });
      } else {
        decoded = blockData;
      }
      if (decoded.length !== uncompressedByte) {
        throw extractorError("installer_block_checksum", "Cabinet block did not decode to its declared size");
      }
      assertChunkRatioBound(bound, compressedByte, uncompressedByte);
      data = Buffer.concat([data, decoded]);
      assertOutputBound(bound, data.length);
    }
    folderData.set(folderIndex, data);
    return data;
  };
  position = fileOffset;
  const payloadFile = [];
  let outputByte = 0;
  for (let index = 0; index < fileCount; index += 1) {
    const sizeByte = file.slice(position, 4).readUInt32LE(0);
    const folderStart = file.slice(position + 4, 4).readUInt32LE(0);
    const folderIndex = file.slice(position + 8, 2).readUInt16LE(0);
    const attributes = file.slice(position + 14, 2).readUInt16LE(0);
    let nameEnd = position + 16;
    while (nameEnd < file.sizeByte && file.slice(nameEnd, 1)[0] !== 0) nameEnd += 1;
    const nameBuffer = file.slice(position + 16, nameEnd - position - 16);
    const name = (attributes & 0x80) !== 0 ? nameBuffer.toString("utf8") : nameBuffer.toString("latin1");
    position = nameEnd + 1;
    const folderBuffer = decodeFolder(folderIndex);
    if (folderStart + sizeByte > folderBuffer.length) {
      throw extractorError("installer_file_out_of_chunk", "Payload file extends past its decoded cabinet folder");
    }
    outputByte += sizeByte;
    assertOutputBound(bound, outputByte);
    payloadFile.push({
      path: resolveCabinetPayloadPath(name, bound),
      size_byte: sizeByte,
      checksum_state: "undeclared",
      content: Buffer.from(folderBuffer.subarray(folderStart, folderStart + sizeByte)),
    });
  }
  return { family: "mscf_cabinet", version_id: null, file: payloadFile, output_byte: outputByte, evidence, header_summary: { folder_count: folderCount } };
}

function assertNoExecutableStub(file) {
  if (file.sizeByte < 64 || file.slice(0, 2).readUInt16LE(0) !== 0x5a4d) return;
  const headerOffset = file.slice(0x3c, 4).readUInt32LE(0);
  if (headerOffset + 2 > file.sizeByte) return;
  const signature = file.slice(headerOffset, 2).toString("ascii");
  if (signature === "NE" || signature === "LE" || signature === "LX") {
    throw extractorError("installer_stub_16bit", "The installer is a 16-bit setup stub and is refused without execution");
  }
}

// Detects the installer kind for a path or an already opened bounded file.
export function detectInstaller(input) {
  const owned = typeof input === "string" ? new BoundedFile(input) : null;
  const file = owned ?? input;
  try {
    if (file.sizeByte >= 4 && file.slice(0, 4).toString("ascii") === "MSCF") return "cabinet";
    if (file.sizeByte >= 0x3c && file.slice(0, 2).readUInt16LE(0) === 0x5a4d) {
      if (file.slice(0x30, 4).readUInt32LE(0) === 0x6f6e6e49) return "inno";
      if (locateInnoResource(file) !== null) return "inno";
    }
    return null;
  } finally {
    if (owned !== null) owned.close();
  }
}

export function extractInstaller(input, option = {}) {
  const bound = createExtractionBound(option.bound);
  const outputDir = option.extract ? resolve(option.extract) : null;
  const file = new BoundedFile(input);
  try {
    assertNoExecutableStub(file);
    const installer = detectInstaller(file);
    if (installer === null) {
      throw extractorError("installer_format_unknown", "The input does not carry a supported installer signature");
    }
    const parsed = installer === "inno" ? parseInno(file, bound, []) : parseCabinet(file, bound, []);
    const writtenFile = [];
    if (outputDir !== null) {
      for (const entry of parsed.file) {
        const target = resolve(outputDir, entry.path);
        if (relative(outputDir, target).startsWith(`..${sep}`) || resolve(outputDir, entry.path) === outputDir) {
          throw extractorError("payload_path_escape", `Payload target escapes the declared output directory: ${entry.path}`);
        }
        mkdirSync(dirname(target), { recursive: true });
        writeFileSync(target, entry.content);
        writtenFile.push(entry.path);
      }
    }
    return {
      schema_version: 1,
      command: option.extract ? "import --extract" : "import",
      input_path: file.path,
      installer,
      installer_family: parsed.family,
      version_id: parsed.version_id,
      header_summary: parsed.header_summary,
      entry_count: parsed.file.length,
      output_byte: parsed.output_byte,
      entry: parsed.file.map((entry) => ({ path: entry.path, size_byte: entry.size_byte, checksum_state: entry.checksum_state })),
      file: writtenFile,
      output_dir: outputDir,
      is_extracted: outputDir !== null,
      refusal: [],
      evidence: parsed.evidence,
      bound: describeExtractionBound(bound),
      is_executed: false,
      privacy: { is_local_only: true, is_uploaded: false },
    };
  } finally {
    file.close();
  }
}

export function formatExtraction(report) {
  return [
    `Input: ${report.input_path}`,
    `Installer: ${report.installer} (${report.installer_family})`,
    ...(report.version_id ? [`Version: ${report.version_id}`] : []),
    `Payload entry: ${report.entry_count} (${report.output_byte} byte)`,
    ...report.entry.map((entry) => `Payload: ${entry.path} — ${entry.size_byte} byte (${entry.checksum_state})`),
    `Extracted: ${report.is_extracted ? `yes → ${report.output_dir}` : "no (plan only)"}`,
    ...report.evidence.map((entry) => `Evidence: ${entry}`),
    ...report.refusal.map((entry) => `Refused: ${entry}`),
    "Executed: no; installer code is never run",
  ].join("\n");
}
