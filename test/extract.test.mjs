// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { deflateRawSync, deflateSync } from "node:zlib";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { extractInstaller } from "../lib/extract.mjs";

const binPath = fileURLToPath(new URL("../bin/bptk.mjs", import.meta.url));

function run(argument) {
  return spawnSync(process.execPath, [binPath, ...argument], { encoding: "utf8" });
}

const crcTable = (() => {
  const table = new Int32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    table[index] = value;
  }
  return table;
})();

function crc32(buffer) {
  let value = 0xffffffff;
  for (let index = 0; index < buffer.length; index += 1) value = crcTable[(value ^ buffer[index]) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

function text(value) {
  const body = Buffer.from(value, "utf16le");
  const out = Buffer.alloc(4 + body.length);
  out.writeUInt32LE(body.length, 0);
  body.copy(out, 4);
  return out;
}

function blob(value) {
  const body = Buffer.from(value, "latin1");
  const out = Buffer.alloc(4 + body.length);
  out.writeUInt32LE(body.length, 0);
  body.copy(out, 4);
  return out;
}

function uint8(value) {
  return Buffer.from([value & 0xff]);
}

function uint16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16LE(value, 0);
  return out;
}

function uint32(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value >>> 0, 0);
  return out;
}

function uint64(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt(value), 0);
  return out;
}

function winver() {
  return Buffer.alloc(20);
}

// Rebuilds the Inno block framing: a CRC32 word ahead of the stored size and
// compression flag, then the zlib frame of the CRC-sub-blocked content.
function innoBlock(bytes) {
  const part = [];
  for (let offset = 0; offset < bytes.length; offset += 4096) {
    const sub = bytes.subarray(offset, Math.min(offset + 4096, bytes.length));
    const framed = Buffer.alloc(4 + sub.length);
    framed.writeUInt32LE(crc32(sub), 0);
    sub.copy(framed, 4);
    part.push(framed);
  }
  const compressed = deflateSync(Buffer.concat(part));
  const blockHeader = Buffer.alloc(5);
  blockHeader.writeUInt32LE(compressed.length, 0);
  blockHeader.writeUInt8(1, 4);
  const out = Buffer.alloc(4 + 5 + compressed.length);
  out.writeUInt32LE(crc32(blockHeader), 0);
  blockHeader.copy(out, 4);
  compressed.copy(out, 9);
  return out;
}

// Builds a faithful Inno Setup 6.3.0 unicode setup-data archive: a minimal
// PE32 loader stub, the real loader offset table, the real header chain, and
// the real chunk layout for the declared payload.
function createInnoFixture(context, option = {}) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-extract-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));

  const payload = option.payload ?? [
    { destination: "{app}\\bin\\game.dat", content: Buffer.from("classic 2D game payload\n") },
    { destination: "{app}\\data\\readme.txt", content: Buffer.from("readme\n") },
  ];
  const isCompressed = option.is_stored !== true;
  const chunkBody = isCompressed
    ? deflateSync(Buffer.concat(payload.map((entry) => entry.content)))
    : Buffer.concat(payload.map((entry) => entry.content));
  const chunkData = Buffer.concat([Buffer.from([0x7a, 0x6c, 0x62, 0x1a]), chunkBody]);

  const setupStrings = Buffer.concat([
    text("BPTK Extract Fixture"), // app_name
    text("BPTK Extract Fixture 1"), // app_versioned_name
    blob("bptk-fixture"), // app_id
    text(""), // app_copyright
    text(""), // app_publisher
    text(""), // app_publisher_url
    text(""), // app_support_phone
    text(""), // app_support_url
    text(""), // app_updates_url
    text(""), // app_version
    text("{app}"), // default_dir_name
    text(""), // default_group_name
    text("fixture"), // base_filename
    text(""), // uninstall_files_dir
    text(""), // uninstall_name
    text(""), // uninstall_icon
    text(""), // app_mutex
    text(""), // default_user_name
    text(""), // default_user_organisation
    text(""), // default_serial
    text(""), // app_readme_file
    text(""), // app_contact
    text(""), // app_comments
    text(""), // app_modify_path
    text(""), // create_uninstall_registry_key
    text(""), // uninstallable
    text(""), // close_applications_filter
    text(""), // setup_mutex
    text(""), // changes_environment
    text(""), // changes_associations
    text(""), // architectures_allowed_expr
    text(""), // architectures_installed_in_64bit_mode_expr
    blob(""), // license_text
    blob(""), // info_before
    blob(""), // info_after
    blob(""), // compiled_code
  ]);

  const count = Buffer.concat([
    uint32(0), // language_count
    uint32(0), // message_count
    uint32(0), // permission_count
    uint32(0), // type_count
    uint32(0), // component_count
    uint32(0), // task_count
    uint32(0), // directory_count
    uint32(payload.length), // file_count
    uint32(payload.length), // data_entry_count
    uint32(0), // icon_count
    uint32(0), // ini_entry_count
    uint32(0), // registry_entry_count
    uint32(0), // delete_entry_count
    uint32(0), // uninstall_delete_entry_count
    uint32(0), // run_entry_count
    uint32(0), // uninstall_run_entry_count
  ]);

  const setupTail = Buffer.concat([
    winver(),
    uint32(0), uint32(0), // back_color, back_color2
    uint8(0), uint32(0), uint32(0), uint8(0), // wizard_style, resize x/y, alpha format
    Buffer.alloc(20), Buffer.alloc(8), // password sha1, password salt
    uint64(0), uint32(1), // extra_disk_space_required, slices_per_disk
    uint8(0), uint8(0), uint8(0), uint8(0), uint8(0), uint8(0), // log mode, dir warning, privileges, override, language dialog, detection
    uint8(isCompressed ? 1 : 0), // compression: stored or zlib
    uint8(0), uint8(0), // disable_dir_page, disable_program_group_page
    uint64(0), // uninstall_display_size
    Buffer.alloc(7), // 49 setup flag, all clear
  ]);

  const fileEntry = [];
  for (let index = 0; index < payload.length; index += 1) {
    fileEntry.push(Buffer.concat([
      text(`payload.${index}.bin`), // source
      text(payload[index].destination),
      text(""), // install_font_name
      text(""), // strong_assembly_name
      text(""), text(""), text(""), text(""), text(""), text(""), // condition data
      winver(),
      uint32(index), // location
      uint32(0), // attributes
      uint64(0), // external_size
      uint32(0xffffffff), // permission
      Buffer.alloc(4), // 32 file flag, all clear
      uint8(0), // user file type
    ]));
  }

  const dataEntry = [];
  let fileOffset = 0;
  for (const item of payload) {
    const digest = createHash("sha1").update(item.content).digest();
    if (option.break_checksum === true) digest[0] ^= 0xff;
    dataEntry.push(Buffer.concat([
      uint32(0), uint32(0), // first_slice, last_slice
      uint32(0), // chunk_offset: the payload shares the single chunk
      uint64(fileOffset), uint64(item.content.length), uint64(chunkBody.length),
      digest,
      uint64(0), uint32(0), uint32(0), // filetime, file version ms/ls
      uint8((option.is_encrypted === true ? 0x40 : 0) | (isCompressed ? 0x80 : 0) | (option.has_instruction_filter === true ? 0x10 : 0)),
      uint8(0), // nine location flag occupy two byte
      uint8(0), // sign mode (6.3 and later)
    ]));
    fileOffset += item.content.length;
  }

  const versionId = Buffer.alloc(64);
  Buffer.from(option.version_id ?? "Inno Setup Setup Data (6.3.0)", "latin1").copy(versionId);
  // The external decompressor blob exists only for zlib-compressed installer.
  const tail = isCompressed ? [uint32(0), uint32(0), blob("")] : [uint32(0), uint32(0)];
  const headerBody = Buffer.concat([
    versionId,
    innoBlock(Buffer.concat([setupStrings, count, setupTail, ...fileEntry, ...tail])),
    innoBlock(Buffer.concat(dataEntry)),
  ]);

  const stub = Buffer.alloc(0x400);
  stub.write("MZ", 0, "ascii");
  stub.writeUInt32LE(0x80, 0x3c);
  stub.write("PE\0\0", 0x80, "ascii");
  stub.writeUInt16LE(0x14c, 0x84); // i386
  stub.write("Inno", 0x30, "ascii");

  const table = Buffer.alloc(44);
  Buffer.from("rDlPtS\xcd\xe6\xd7{\x0b*", "latin1").copy(table, 0);
  table.writeUInt32LE(1, 12); // revision
  table.writeUInt32LE(0, 16); // unused
  table.writeUInt32LE(0, 20); // exe_offset
  table.writeUInt32LE(0, 24); // exe_uncompressed_size
  table.writeUInt32LE(0, 28); // exe_checksum
  const headerOffsetValue = 0x400 + table.length;
  const dataOffsetValue = headerOffsetValue + headerBody.length;
  table.writeUInt32LE(headerOffsetValue, 32);
  table.writeUInt32LE(dataOffsetValue, 36);
  table.writeUInt32LE(crc32(Buffer.concat([table.subarray(0, 12), table.subarray(16, 40)])), 40);

  stub.writeUInt32LE(0x400, 0x34); // offset table pointer
  stub.writeUInt32LE(~0x400 >>> 0, 0x38); // inverted pointer checksum

  const installerPath = join(rootPath, "setup.exe");
  writeFileSync(installerPath, Buffer.concat([stub, table, headerBody, chunkData]));
  return { installerPath, payload, rootPath };
}

// Builds a real MSCF cabinet with one stored folder, one MSZIP folder, and a
// payload spread across both.
function createCabinetFixture(context) {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-cabinet-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const payload = [
    { name: "GAMEDATA\\GAME.EXE", content: Buffer.from("cabinet payload one\n"), folder: 0 },
    { name: "GAMEDATA\\README.TXT", content: Buffer.from("cabinet payload two\n"), folder: 0 },
    { name: "SOUND\\MUSIC.WAV", content: Buffer.from("cabinet payload three with more byte\n"), folder: 1 },
  ];
  const folder = [
    { compression: 0, content: Buffer.concat([payload[0].content, payload[1].content]) },
    { compression: 1, content: payload[2].content },
  ];
  const dataBlock = [];
  for (const current of folder) {
    const block = current.compression === 1
      ? Buffer.concat([Buffer.from([0x43, 0x4b]), deflateRawSync(current.content)])
      : current.content;
    const record = Buffer.alloc(8);
    record.writeUInt16LE(block.length, 4);
    record.writeUInt16LE(current.content.length, 6);
    dataBlock.push({ record, block });
  }
  const fileRecord = [];
  for (let index = 0; index < payload.length; index += 1) {
    const item = payload[index];
    const folderStart = item.folder === 0
      ? payload.slice(0, index).filter((entry) => entry.folder === 0).reduce((sum, entry) => sum + entry.content.length, 0)
      : 0;
    fileRecord.push(Buffer.concat([
      uint32(item.content.length), uint32(folderStart), uint16(item.folder), uint16(0), uint16(0), uint16(0),
      Buffer.concat([Buffer.from(item.name, "latin1"), Buffer.from([0])]),
    ]));
  }
  const fileRecordOffset = 36 + folder.length * 12;
  const dataOffsetValue = fileRecordOffset + fileRecord.reduce((sum, record) => sum + record.length, 0);
  const cabinetSize = dataOffsetValue + dataBlock.reduce((sum, block) => sum + 8 + block.block.length, 0);
  const header = Buffer.alloc(36);
  header.write("MSCF", 0, "ascii");
  header.writeUInt32LE(cabinetSize, 8);
  header.writeUInt32LE(fileRecordOffset, 16);
  header.writeUInt8(3, 24); // version minor
  header.writeUInt8(1, 25); // version major
  header.writeUInt16LE(folder.length, 26);
  header.writeUInt16LE(payload.length, 28);
  const folderRecord = [];
  let blockCursor = dataOffsetValue;
  for (let index = 0; index < folder.length; index += 1) {
    const record = Buffer.alloc(12);
    record.writeUInt32LE(blockCursor, 0);
    record.writeUInt16LE(1, 4);
    record.writeUInt16LE(folder[index].compression, 6);
    folderRecord.push(record);
    blockCursor += 8 + dataBlock[index].block.length;
  }
  const cabinetPath = join(rootPath, "game.cab");
  writeFileSync(cabinetPath, Buffer.concat([header, ...folderRecord, ...fileRecord, ...dataBlock.map((block) => Buffer.concat([block.record, block.block]))]));
  return { cabinetPath, payload };
}

test("inno setup 6 fixture extracts its declared payload through the CLI", (context) => {
  const { installerPath, payload, rootPath } = createInnoFixture(context);
  const outputDir = join(rootPath, "out");
  const extractRun = run(["import", installerPath, "--extract", outputDir, "--json"]);
  assert.equal(extractRun.status, 0, extractRun.stderr);
  const report = JSON.parse(extractRun.stdout);
  assert.equal(report.extraction.installer_family, "inno_setup_6");
  assert.equal(report.extraction.version_id, "Inno Setup Setup Data (6.3.0)");
  assert.equal(report.extraction.is_extracted, true);
  assert.equal(report.extraction.is_executed, false);
  assert.equal(report.state, "extracted_no_runtime");
  for (const item of payload) {
    const relativePath = item.destination.replace("{app}\\", "").replace(/\\/g, "/");
    const written = readFileSync(join(outputDir, relativePath));
    assert.ok(written.equals(item.content), `payload mismatch for ${relativePath}`);
  }
});

test("inno setup 6 plan-only import writes nothing", (context) => {
  const { installerPath } = createInnoFixture(context);
  const importRun = run(["import", installerPath, "--json"]);
  assert.equal(importRun.status, 0, importRun.stderr);
  const report = JSON.parse(importRun.stdout);
  assert.equal(report.extraction.is_extracted, false);
  assert.equal(report.extraction.file.length, 0);
  assert.equal(report.extraction.entry_count, 2);
  assert.equal(report.state, "extractable_no_runtime");
});

test("stored-chunk inno fixture extracts without decompression", (context) => {
  const { installerPath, payload } = createInnoFixture(context, { is_stored: true });
  const report = extractInstaller(installerPath);
  assert.equal(report.entry_count, payload.length);
  assert.equal(report.is_executed, false);
});

test("a 16-bit setup stub is refused without execution", (context) => {
  const rootPath = mkdtempSync(join(tmpdir(), "bptk-stub-"));
  context.after(() => rmSync(rootPath, { recursive: true, force: true }));
  const stub = Buffer.alloc(0x400);
  stub.write("MZ", 0, "ascii");
  stub.writeUInt32LE(0x80, 0x3c);
  stub.write("NE", 0x80, "ascii");
  const stubPath = join(rootPath, "setup.exe");
  writeFileSync(stubPath, stub);
  assert.throws(() => extractInstaller(stubPath), (error) => error.input_code === "installer_stub_16bit");
});

test("a decompression bomb is refused at the declared amplification bound", (context) => {
  const bomb = Buffer.alloc(8 * 1024 * 1024);
  const { installerPath } = createInnoFixture(context, { payload: [{ destination: "{app}\\bomb.bin", content: bomb }] });
  assert.throws(() => extractInstaller(installerPath), (error) => error.input_code === "bound_ratio_exceeded");
  const outputDir = join(installerPath, "..", "bomb-out");
  const refusal = run(["import", installerPath, "--extract", outputDir, "--json"]);
  assert.equal(refusal.status, 1);
  assert.equal(JSON.parse(refusal.stderr).error_code, "bound_ratio_exceeded");
});

test("an encrypted payload chunk is refused", (context) => {
  const { installerPath } = createInnoFixture(context, { is_encrypted: true });
  assert.throws(() => extractInstaller(installerPath), (error) => error.input_code === "installer_chunk_encrypted");
});

test("a checksum mismatch is refused", (context) => {
  const { installerPath } = createInnoFixture(context, { break_checksum: true });
  assert.throws(() => extractInstaller(installerPath), (error) => error.input_code === "installer_checksum_mismatch");
});

test("a payload destination outside {app} escapes and is refused", (context) => {
  const { installerPath } = createInnoFixture(context, {
    payload: [{ destination: "{app}\\..\\evil.bin", content: Buffer.from("escape\n") }],
  });
  assert.throws(() => extractInstaller(installerPath), (error) => error.input_code === "payload_path_escape");
});

test("an unsupported setup data version is refused with its identity", (context) => {
  const { installerPath } = createInnoFixture(context, { version_id: "Inno Setup Setup Data (5.6.0) (u)" });
  assert.throws(() => extractInstaller(installerPath), (error) => error.input_code === "installer_version_unsupported");
});

test("an MSCF cabinet with stored and MSZIP folder extracts its payload", (context) => {
  const { cabinetPath, payload } = createCabinetFixture(context);
  const report = extractInstaller(cabinetPath);
  assert.equal(report.installer_family, "mscf_cabinet");
  assert.equal(report.entry_count, payload.length);
  for (let index = 0; index < payload.length; index += 1) {
    assert.equal(report.entry[index].size_byte, payload[index].content.length);
  }
});

export { createInnoFixture, createCabinetFixture };
