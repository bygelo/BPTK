// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The PE .rsrc resource-directory reader and RT_DIALOG template parser suite
// (runtime v2 / BPTK-031). Every template is hand-assembled from the documented
// Win32 DLGTEMPLATE / DLGTEMPLATEEX layout and its expected decode is frozen
// here by hand, never from running the parser: they prove the parser is the
// exact inverse of the on-disk resource format for the classic and extended
// header, the sz_Or_Ord name fields, the DS_SETFONT font block, the DWORD
// control alignment, and the three-level type->name->language directory walk.

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDialogTemplate, findDialogResource, loadDialogTemplate, controlClassAtom } from "../lib/rsrc.mjs";

function u16(value) {
  return [value & 0xff, (value >> 8) & 0xff];
}
function u32(value) {
  return [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24) & 0xff];
}
function wide(text) {
  const byte = [];
  for (const character of text) byte.push(...u16(character.charCodeAt(0)));
  byte.push(0, 0); // the null terminator
  return byte;
}
function pad4(byte) {
  while ((byte.length & 3) !== 0) byte.push(0);
  return byte;
}

// A classic DLGTEMPLATE with DS_SETFONT set, a title, a font block, and two
// controls: a WS_TABSTOP button (ordinal class) and a static (ordinal class).
function classicTemplate() {
  const style = 0x80c800c0; // WS_POPUP|WS_CAPTION|... with DS_SETFONT (0x40)
  const byte = [
    ...u32(style),
    ...u32(0), // dwExtendedStyle
    ...u16(2), // cdit: two controls
    ...u16(10), ...u16(20), ...u16(200), ...u16(100), // x, y, cx, cy
    ...u16(0), // menu: none
    ...u16(0), // windowClass: none (default dialog class)
    ...wide("Test Dialog"), // title
    ...u16(8), // font point size (DS_SETFONT)
    ...wide("MS Shell Dlg"), // typeface
  ];
  pad4(byte);
  // control 0: a WS_TABSTOP button
  byte.push(
    ...u32(0x50010001), // style with WS_TABSTOP (0x00010000)
    ...u32(0),
    ...u16(5), ...u16(5), ...u16(40), ...u16(14), // x, y, cx, cy
    ...u16(1), // id
    ...u16(0xffff), ...u16(0x0080), // class ordinal: Button
    ...wide("OK"), // title
    ...u16(0), // creation data byte count
  );
  pad4(byte);
  // control 1: a static label
  byte.push(
    ...u32(0x50000000),
    ...u32(0),
    ...u16(5), ...u16(25), ...u16(190), ...u16(10),
    ...u16(2), // id
    ...u16(0xffff), ...u16(0x0082), // class ordinal: Static
    ...wide("Label"),
    ...u16(0),
  );
  pad4(byte);
  return Buffer.from(byte);
}

test("parseDialogTemplate decodes a classic DLGTEMPLATE header, font, and controls", () => {
  const template = parseDialogTemplate(classicTemplate(), 0);
  assert.equal(template.is_ex, false);
  assert.equal(template.style >>> 0, 0x80c800c0);
  assert.equal(template.control_count, 2);
  assert.deepEqual([template.x, template.y, template.cx, template.cy], [10, 20, 200, 100]);
  assert.equal(template.title, "Test Dialog");
  assert.equal(template.class_name, null); // default dialog class
  assert.equal(template.font.point_size, 8);
  assert.equal(template.font.typeface, "MS Shell Dlg");
  assert.equal(template.item.length, 2);
  assert.equal(template.item[0].class_name, controlClassAtom[0x0080]); // Button
  assert.equal(template.item[0].id, 1);
  assert.equal(template.item[0].title, "OK");
  assert.equal((template.item[0].style & 0x00010000) !== 0, true, "the button keeps its WS_TABSTOP bit");
  assert.equal(template.item[1].class_name, controlClassAtom[0x0082]); // Static
  assert.equal(template.item[1].id, 2);
  assert.equal(template.item[1].title, "Label");
});

test("parseDialogTemplate decodes an extended DLGTEMPLATEEX header and its one control", () => {
  const byte = [
    ...u16(1), // dlgVer
    ...u16(0xffff), // signature: marks the extended template
    ...u32(0), // helpID
    ...u32(0), // exStyle
    ...u32(0x80c800c0), // style with DS_SETFONT
    ...u16(1), // cDlgItems
    ...u16(0), ...u16(0), ...u16(160), ...u16(80), // x, y, cx, cy
    ...u16(0), // menu
    ...u16(0), // windowClass
    ...wide("Ex Dialog"), // title
    ...u16(9), // font point size
    ...u16(400), // weight
    0, 1, // italic (BYTE), charset (BYTE)
    ...wide("Segoe UI"), // typeface
  ];
  pad4(byte);
  byte.push(
    ...u32(0), // helpID
    ...u32(0), // exStyle
    ...u32(0x50010000), // style
    ...u16(4), ...u16(4), ...u16(50), ...u16(14), // x, y, cx, cy
    ...u32(100), // id (DWORD in the extended item)
    ...u16(0xffff), ...u16(0x0080), // Button
    ...wide("Go"),
    ...u16(0),
  );
  pad4(byte);
  const template = parseDialogTemplate(Buffer.from(byte), 0);
  assert.equal(template.is_ex, true);
  assert.equal(template.title, "Ex Dialog");
  assert.equal(template.font.typeface, "Segoe UI");
  assert.equal(template.control_count, 1);
  assert.equal(template.item[0].id, 100);
  assert.equal(template.item[0].class_name, controlClassAtom[0x0080]);
  assert.equal(template.item[0].title, "Go");
});

// Build a minimal three-level resource directory (type -> name -> language)
// whose single RT_DIALOG leaf points at a template placed later in the image.
// The resource directory sits at a nonzero base (RVA 0 means "no resource
// directory"), exactly as a mapped PE places it. Directory child offsets are
// relative to that base; the leaf data entry stores an absolute image RVA.
const resourceBase = 0x1000;

function buildResourceImage(templateBytes, dialogId) {
  const dirHeader = (namedCount, idCount) => [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ...u16(namedCount), ...u16(idCount)];
  const dataRva = resourceBase + 0x60; // the template, placed below, is an absolute image RVA
  const bytes = [];
  while (bytes.length < resourceBase) bytes.push(0);
  // root directory at base+0x00: one id entry for RT_DIALOG (type 5) -> type dir at +0x18
  bytes.push(...dirHeader(0, 1), ...u32(5), ...u32(0x80000000 | 0x18));
  // type directory at base+0x18: one id entry for dialogId -> name dir at +0x30
  bytes.push(...dirHeader(0, 1), ...u32(dialogId), ...u32(0x80000000 | 0x30));
  // name directory at base+0x30: one id entry for language 0 -> data entry at +0x48
  bytes.push(...dirHeader(0, 1), ...u32(0), ...u32(0x48));
  // data entry at base+0x48: rva, size, codepage, reserved
  bytes.push(...u32(dataRva), ...u32(templateBytes.length), ...u32(0), ...u32(0));
  while (bytes.length < dataRva) bytes.push(0);
  bytes.push(...templateBytes);
  return Buffer.from(bytes);
}

test("findDialogResource walks the type->name->language tree to the RT_DIALOG leaf", () => {
  const image = buildResourceImage(classicTemplate(), 200);
  const located = findDialogResource(image, resourceBase, 200);
  assert.notEqual(located, null);
  assert.equal(located.rva, resourceBase + 0x60);
  assert.equal(findDialogResource(image, resourceBase, 999), null, "a dialog id with no resource returns null");
});

test("loadDialogTemplate locates and parses one dialog by id", () => {
  const image = buildResourceImage(classicTemplate(), 200);
  const template = loadDialogTemplate(image, resourceBase, 200);
  assert.equal(template.title, "Test Dialog");
  assert.equal(template.control_count, 2);
  assert.equal(loadDialogTemplate(image, resourceBase, 999), null);
});
