// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseExportDirectory } from "../lib/pe.mjs";

test("parseExportDirectory reads named exports and a forwarder string", () => {
  const image = Buffer.alloc(0x200);
  const dirRva = 0x40;
  const functionsRva = 0x80;
  const namesRva = 0x90;
  const ordinalsRva = 0x98;
  const nameRva0 = 0xc0;
  const nameRva1 = 0xd0;
  const forwarderRva = 0xe0;
  image.writeUInt32LE(1, dirRva + 16); // Base
  image.writeUInt32LE(2, dirRva + 20); // NumberOfFunctions
  image.writeUInt32LE(2, dirRva + 24); // NumberOfNames
  image.writeUInt32LE(functionsRva, dirRva + 28);
  image.writeUInt32LE(namesRva, dirRva + 32);
  image.writeUInt32LE(ordinalsRva, dirRva + 36);
  image.writeUInt32LE(0x1000, functionsRva);
  image.writeUInt32LE(forwarderRva, functionsRva + 4);
  image.writeUInt32LE(nameRva0, namesRva);
  image.writeUInt32LE(nameRva1, namesRva + 4);
  image.writeUInt16LE(0, ordinalsRva);
  image.writeUInt16LE(1, ordinalsRva + 2);
  image.write("crc32\0", nameRva0);
  image.write("inflate\0", nameRva1);
  image.write("NTDLL.RtlUnwind\0", forwarderRva);
  const record = parseExportDirectory(image, { rva: dirRva, size_byte: 0x180 });
  assert.deepEqual(record, [
    { symbol: "crc32", ordinal: 1, rva: 0x1000, is_forwarder: false, forwarder: null },
    { symbol: "inflate", ordinal: 2, rva: forwarderRva, is_forwarder: true, forwarder: "NTDLL.RtlUnwind" },
  ]);
});

test("parseExportDirectory treats a missing directory as empty", () => {
  assert.deepEqual(parseExportDirectory(Buffer.alloc(64), { rva: 0, size_byte: 0 }), []);
});
