// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The PE `.rsrc` resource-directory reader and RT_DIALOG template parser
// (BPTK-031 / doc/runtime-v2-scope.md). The x86-64 window/dialog-creation path
// (lib/exec64.mjs) instantiates a guest dialog from the REAL template bytes in
// the mapped image's resource directory rather than a per-title fixture: this
// file walks the three-level resource tree (type -> name -> language) to locate
// an RT_DIALOG entry by id, then decodes the DLGTEMPLATE / DLGTEMPLATEEX header
// and its control (DLGITEMTEMPLATE) array into a structured, arch-neutral
// object the user subsystem turns into window objects.
//
// It reads only; it maps nothing and calls nothing. Every offset is bounds
// checked against the mapped image buffer, so a malformed resource fails with a
// named fault instead of reading past the image. The parser is the exact
// inverse of the documented Win32 resource layout — no title identity is read.

import { InputError } from "./input.mjs";

// The resource type ids this reader recognizes by name. RT_DIALOG (5) is the
// only one the x64 dialog path needs; the rest are named for the log.
export const resourceType = Object.freeze({
  RT_CURSOR: 1,
  RT_BITMAP: 2,
  RT_ICON: 3,
  RT_MENU: 4,
  RT_DIALOG: 5,
  RT_STRING: 6,
  RT_GROUP_CURSOR: 12,
  RT_GROUP_ICON: 14,
  RT_VERSION: 16,
  RT_MANIFEST: 24,
});

// The predefined control-class atoms a DLGITEMTEMPLATE stores as an ordinal
// (0xFFFF followed by the atom). Mapped to the Win32 class name so the window
// manager registers and creates the control by the same name a guest
// RegisterClass would use.
export const controlClassAtom = Object.freeze({
  0x0080: "Button",
  0x0081: "Edit",
  0x0082: "Static",
  0x0083: "ListBox",
  0x0084: "ScrollBar",
  0x0085: "ComboBox",
});

const DS_SETFONT = 0x40;
const DS_SHELLFONT = 0x40 | 0x2000; // DS_SETFONT | DS_FIXEDSYS-adjacent shell-font flag
const maxDialogControlCount = 4096;
const maxResourceEntryCount = 4096;
const maxStringWordCount = 4096;

function assertRange(image, offset, sizeByte, label) {
  if (!Number.isInteger(offset) || offset < 0 || sizeByte < 0 || offset > image.length - sizeByte) {
    throw new InputError("invalid_resource_range", `${label} is outside the mapped image`);
  }
}

// Reads a null-terminated UTF-16LE string starting at `offset`, returning the
// decoded text and the offset just past the terminator. A cursor helper for the
// variable-length DLGTEMPLATE fields.
function readWideZero(image, offset) {
  let scan = offset;
  const unit = [];
  for (let guard = 0; guard <= maxStringWordCount; guard += 1) {
    if (guard === maxStringWordCount) throw new InputError("resource_string_limit", `A resource string exceeds ${maxStringWordCount} word`);
    assertRange(image, scan, 2, "resource string");
    const code = image.readUInt16LE(scan);
    scan += 2;
    if (code === 0) break;
    unit.push(code);
  }
  return { text: String.fromCharCode(...unit), next: scan };
}

// Decodes a "sz_Or_Ord": a resource name field that is either absent (a single
// 0x0000 word), an ordinal (0xFFFF then a 16-bit atom/id), or an inline
// null-terminated wide string. Returns the value shape plus the next cursor.
function readNameOrOrdinal(image, offset) {
  assertRange(image, offset, 2, "resource name field");
  const lead = image.readUInt16LE(offset);
  if (lead === 0x0000) return { kind: "none", value: null, next: offset + 2 };
  if (lead === 0xffff) {
    assertRange(image, offset + 2, 2, "resource ordinal");
    return { kind: "ordinal", value: image.readUInt16LE(offset + 2), next: offset + 4 };
  }
  const { text, next } = readWideZero(image, offset);
  return { kind: "string", value: text, next };
}

function align4(value) {
  return (value + 3) & ~3;
}

// Walks one resource directory level, returning its entries as
// { name, is_directory, offset } where `offset` is relative to the resource
// base. `named` entries key on a string (unused by the dialog path); `id`
// entries key on an integer.
function readDirectoryEntry(image, resourceBase, directoryOffset) {
  const off = resourceBase + directoryOffset;
  assertRange(image, off, 16, "resource directory header");
  const namedCount = image.readUInt16LE(off + 12);
  const idCount = image.readUInt16LE(off + 14);
  const total = namedCount + idCount;
  if (total > maxResourceEntryCount) throw new InputError("resource_entry_limit", `A resource directory exceeds ${maxResourceEntryCount} entry`);
  const entry = [];
  let cursor = off + 16;
  for (let index = 0; index < total; index += 1) {
    assertRange(image, cursor, 8, "resource directory entry");
    const name = image.readUInt32LE(cursor);
    const child = image.readUInt32LE(cursor + 4);
    entry.push({
      is_named: index < namedCount,
      name: (name & 0x80000000) !== 0 ? (name & 0x7fffffff) : name, // a named entry keeps its string offset; an id entry its integer
      is_directory: (child & 0x80000000) !== 0,
      offset: child & 0x7fffffff,
    });
    cursor += 8;
  }
  return entry;
}

function readResourceKey(image, resourceBase, entry) {
  if (!entry.is_named) return { kind: "id", value: entry.name >>> 0 };
  const off = resourceBase + (entry.name >>> 0);
  assertRange(image, off, 2, "resource name length");
  const length = image.readUInt16LE(off);
  assertRange(image, off + 2, length * 2, "resource name");
  const unit = [];
  for (let index = 0; index < length; index += 1) unit.push(image.readUInt16LE(off + 2 + index * 2));
  return { kind: "string", value: String.fromCharCode(...unit) };
}

function keysMatch(entryKey, want) {
  if (want === null || want === undefined) return false;
  if (entryKey.kind === "id") return want.kind === "id" && (entryKey.value >>> 0) === (want.value >>> 0);
  if (want.kind !== "string" || typeof want.value !== "string") return false;
  return entryKey.value.toLowerCase() === want.value.toLowerCase();
}

// Locates the raw bytes of the first resource whose type and name match,
// following the type -> name -> language tree and its leaf data entry
// (RVA + size). `typeKey` / `nameKey` are `{ kind: "id", value }` or
// `{ kind: "string", value }`. Returns { rva, size_byte } or null.
export function findResource(image, resourceBase, typeKey, nameKey) {
  if (!Buffer.isBuffer(image) && !(image instanceof Uint8Array)) throw new TypeError("findResource requires the mapped image buffer");
  if (!Number.isInteger(resourceBase) || resourceBase <= 0) return null;
  const typeEntry = readDirectoryEntry(image, resourceBase, 0);
  const typeMatch = typeEntry.find((entry) => entry.is_directory && keysMatch(readResourceKey(image, resourceBase, entry), typeKey));
  if (typeMatch === undefined) return null;
  const nameEntry = readDirectoryEntry(image, resourceBase, typeMatch.offset);
  const named = nameEntry.find((entry) => entry.is_directory && keysMatch(readResourceKey(image, resourceBase, entry), nameKey));
  if (named === undefined) return null;
  const langEntry = readDirectoryEntry(image, resourceBase, named.offset);
  const leaf = langEntry.find((entry) => !entry.is_directory) ?? langEntry[0];
  if (leaf === undefined || leaf.is_directory) return null;
  const dataDescriptor = resourceBase + leaf.offset;
  assertRange(image, dataDescriptor, 16, "resource data descriptor");
  const rva = image.readUInt32LE(dataDescriptor);
  const sizeByte = image.readUInt32LE(dataDescriptor + 4);
  return { rva, size_byte: sizeByte };
}

// Locates the raw bytes of the first RT_DIALOG resource whose name/id matches
// `dialogId`. `resourceBase` is the resource directory RVA in the mapped image
// (mapped.directory[2].rva).
export function findDialogResource(image, resourceBase, dialogId) {
  return findResource(image, resourceBase, { kind: "id", value: resourceType.RT_DIALOG }, { kind: "id", value: dialogId >>> 0 });
}

// Decodes one DLGITEMTEMPLATE (classic) or DLGITEMTEMPLATEEX, starting at the
// DWORD-aligned `offset` inside the mapped image. Returns the control shape and
// the next (unaligned) cursor; the caller re-aligns before the next item.
function readItem(image, offset, isEx) {
  let cursor = offset;
  let style;
  let exStyle;
  let x;
  let y;
  let cx;
  let cy;
  let id;
  if (isEx) {
    assertRange(image, cursor, 24, "dialog item header (ex)");
    exStyle = image.readUInt32LE(cursor + 4);
    style = image.readUInt32LE(cursor + 8);
    x = image.readInt16LE(cursor + 12);
    y = image.readInt16LE(cursor + 14);
    cx = image.readInt16LE(cursor + 16);
    cy = image.readInt16LE(cursor + 18);
    id = image.readUInt32LE(cursor + 20);
    cursor += 24;
  } else {
    assertRange(image, cursor, 18, "dialog item header");
    style = image.readUInt32LE(cursor);
    exStyle = image.readUInt32LE(cursor + 4);
    x = image.readInt16LE(cursor + 8);
    y = image.readInt16LE(cursor + 10);
    cx = image.readInt16LE(cursor + 12);
    cy = image.readInt16LE(cursor + 14);
    id = image.readUInt16LE(cursor + 16);
    cursor += 18;
  }
  const classField = readNameOrOrdinal(image, cursor);
  cursor = classField.next;
  const titleField = readNameOrOrdinal(image, cursor);
  cursor = titleField.next;
  assertRange(image, cursor, 2, "dialog item creation data");
  const extraByte = image.readUInt16LE(cursor);
  cursor += 2;
  // The creation-data block: extraByte === 0 means none; otherwise the count is
  // in bytes and the block follows inline. The bounded probe skips it.
  if (extraByte !== 0) {
    assertRange(image, cursor, extraByte, "dialog item creation block");
    cursor += extraByte;
  }
  const className = classField.kind === "ordinal"
    ? (controlClassAtom[classField.value] ?? `#${classField.value}`)
    : classField.kind === "string" ? classField.value : "";
  return {
    item: {
      style: style >>> 0,
      ex_style: exStyle >>> 0,
      x, y, cx, cy,
      id: id >>> 0,
      class_name: className,
      class_ordinal: classField.kind === "ordinal" ? classField.value : null,
      title: titleField.kind === "string" ? titleField.value : null,
      title_ordinal: titleField.kind === "ordinal" ? titleField.value : null,
    },
    next: cursor,
  };
}

// Parses a DLGTEMPLATE / DLGTEMPLATEEX at image RVA `rva` into a structured,
// arch-neutral template: the frame style/geometry, the optional class and
// title, the font request, and the control array. Every control carries its
// class, id, style, and geometry so the window manager instantiates it exactly.
export function parseDialogTemplate(image, rva) {
  if (!Buffer.isBuffer(image) && !(image instanceof Uint8Array)) throw new TypeError("parseDialogTemplate requires the mapped image buffer");
  assertRange(image, rva, 4, "dialog template header");
  // DLGTEMPLATEEX leads with WORD dlgVer (1) then WORD signature (0xffff); a
  // classic DLGTEMPLATE leads with its DWORD style, whose low word is never
  // 0xffff at the signature position, so the second word disambiguates them.
  const dlgVer = image.readUInt16LE(rva);
  const signature = image.readUInt16LE(rva + 2);
  const isEx = signature === 0xffff && dlgVer === 0x0001;
  let cursor = rva;
  let style;
  let exStyle;
  let count;
  let geometry;
  if (isEx) {
    assertRange(image, rva, 26, "dialog template header (ex)");
    exStyle = image.readUInt32LE(rva + 8);
    style = image.readUInt32LE(rva + 12);
    count = image.readUInt16LE(rva + 16);
    geometry = { x: image.readInt16LE(rva + 18), y: image.readInt16LE(rva + 20), cx: image.readInt16LE(rva + 22), cy: image.readInt16LE(rva + 24) };
    cursor = rva + 26;
  } else {
    assertRange(image, rva, 18, "dialog template header");
    style = image.readUInt32LE(rva);
    exStyle = image.readUInt32LE(rva + 4);
    count = image.readUInt16LE(rva + 8);
    geometry = { x: image.readInt16LE(rva + 10), y: image.readInt16LE(rva + 12), cx: image.readInt16LE(rva + 14), cy: image.readInt16LE(rva + 16) };
    cursor = rva + 18;
  }
  if (count > maxDialogControlCount) throw new InputError("dialog_control_limit", `A dialog template exceeds ${maxDialogControlCount} control`);
  const menu = readNameOrOrdinal(image, cursor);
  cursor = menu.next;
  const windowClass = readNameOrOrdinal(image, cursor);
  cursor = windowClass.next;
  const titleField = readNameOrOrdinal(image, cursor);
  cursor = titleField.next;
  let font = null;
  const wantFont = isEx ? (style & DS_SHELLFONT) !== 0 || (style & DS_SETFONT) !== 0 : (style & DS_SETFONT) !== 0;
  if (wantFont) {
    assertRange(image, cursor, 2, "dialog font pointsize");
    const pointSize = image.readUInt16LE(cursor);
    cursor += 2;
    if (isEx) {
      assertRange(image, cursor, 4, "dialog font weight/style");
      cursor += 4; // weight (WORD) + italic (BYTE) + charset (BYTE)
    }
    const typeface = readWideZero(image, cursor);
    cursor = typeface.next;
    font = { point_size: pointSize, typeface: typeface.text };
  }
  const item = [];
  for (let index = 0; index < count; index += 1) {
    cursor = align4(cursor);
    const parsed = readItem(image, cursor, isEx);
    item.push(parsed.item);
    cursor = parsed.next;
  }
  return {
    is_ex: isEx,
    style: style >>> 0,
    ex_style: exStyle >>> 0,
    control_count: count,
    x: geometry.x,
    y: geometry.y,
    cx: geometry.cx,
    cy: geometry.cy,
    class_name: windowClass.kind === "string" ? windowClass.value : windowClass.kind === "ordinal" ? `#${windowClass.value}` : null,
    title: titleField.kind === "string" ? titleField.value : null,
    font,
    item,
  };
}

// The one entry the dialog path calls: locate RT_DIALOG `dialogId` and parse it,
// or return null when the image carries no such dialog resource. `resourceBase`
// is the resource directory RVA (mapped.directory[2].rva).
export function loadDialogTemplate(image, resourceBase, dialogId) {
  const located = findDialogResource(image, resourceBase, dialogId);
  if (located === null || located.rva === 0) return null;
  return parseDialogTemplate(image, located.rva);
}
