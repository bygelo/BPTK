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
import { TEB_SIZE_BYTE, PEB_SIZE_BYTE } from "./thread.mjs";
import { SehThread, raiseException } from "./seh.mjs";

// The USER32 windowing/input and GDI32 2D surface slice (BPTK-011/012). The
// export tables and subsystem factories live in their own modules; this file
// only registers the rows and attaches the per-run subsystem to the guest.
import { createUserSubsystem, userExportTable, windowMessage } from "./user.mjs";
import { createGdiSubsystem, gdiExportTable } from "./gdi.mjs";
import { findResource, listResourceNames, loadDialogTemplate, parseDialogTemplate, resourceType } from "./rsrc.mjs";
import { createSdlSubsystem, sdlExportTable, sdlPixelFormat } from "./sdl.mjs";
import { createGlSubsystem, glExportTable } from "./gl.mjs";

// The ws2_32 Winsock lifecycle slice (BPTK-099). The mediated relay and its
// consent/allowlist policy live in lib/net.mjs; this file attaches one
// offline-by-default instance per run and marshals the ws2_32 ABI. The default
// policy grants no consent, so every dial is refused — the honest posture until
// a consent surface lands.
import { createWinsock, createMediatedRelay, createTransportPolicy, netBound, wsaError, winsockConstant, htons as netHtons, htonl as netHtonl, inetAddr } from "./net.mjs";

// The XInput/DirectInput gamepad slice (BPTK-097): a generic controller model
// driven by injected browser Gamepad state, disconnected by default.
import { createGamepadSubsystem, xinputError, gamepadBound } from "./input.mjs";

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
  fls_slot_count: 128,
  critical_section_count: 256,
  output_byte: 1024 * 1024,
  trace_count: 1048576,
  block_byte: 1024 * 1024,
  string_byte: 4096,
  environment_entry_count: 256,
  event_count: 64,
  file_open_count: 64,
  file_total_byte: 1024 * 1024,
  file_size_byte: 256 * 1024,
  registry_key_count: 64,
  registry_value_count: 256,
  registry_value_byte: 4096,
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
  service_pack_major: 3,
  service_pack_minor: 0,
  product_type: 1,
  suite_mask: 0,
  system_directory: "C:\\Windows\\System32",
  guest_root: "C:\\game",
  process_id: 4242,
  thread_id: 1,
  pointer_cookie: 0x5a5a5a5a,
  file_time_base: 132442368000000000,
  page_byte: 0x1000,
  allocation_granularity_byte: 0x10000,
  qpc_frequency_hz: 10000000,
});

// The declared virtual drive geometry (BPTK-102). One fixed system volume and
// one read-only optical volume, host-neutral: the type, label, serial, and
// capacity are declared constants, never a host disk. DRIVE_FIXED = 3,
// DRIVE_CDROM = 5.
export const driveProfile = Object.freeze({
  c: Object.freeze({ letter: "C", type: 3, label: "BPTK", serial: 0x4250544b, file_system: "NTFS", total_byte: 0x100000000, free_byte: 0x80000000, bytes_per_sector: 512, sectors_per_cluster: 8 }),
  d: Object.freeze({ letter: "D", type: 5, label: "BPTK_MEDIA", serial: 0x4344524f, file_system: "CDFS", total_byte: 0x28000000, free_byte: 0, bytes_per_sector: 2048, sectors_per_cluster: 1 }),
});

const errorValue = Object.freeze({
  success: 0,
  invalid_function: 1,
  not_supported: 50,
  file_not_found: 2,
  access_denied: 5,
  invalid_handle: 6,
  not_enough_memory: 14,
  insufficient_buffer: 122,
  invalid_parameter: 87,
  mod_not_found: 126,
  proc_not_found: 127,
  invalid_address: 487,
  old_win_version: 1150,
  more_data: 234,
  path_not_found: 3,
  too_many_open_files: 4,
  file_exists: 80,
  negative_seek: 131,
  disk_full: 112,
  tls_out_of_indexes: 0xffffffff,
  fls_out_of_indexes: 0xffffffff,
});

const fileAccess = Object.freeze({ generic_read: 0x80000000, generic_write: 0x40000000, file_read_attributes: 0x80 });
const fileFlag = Object.freeze({ backup_semantics: 0x02000000 });
const fileDisposition = Object.freeze({ create_new: 1, create_always: 2, open_existing: 3, open_always: 4, truncate_existing: 5 });
const fileMethod = Object.freeze({ begin: 0, current: 1, end: 2 });
const fileType = Object.freeze({ unknown: 0, disk: 3, char: 2 });
const registryAccess = Object.freeze({ read: 0x20019, write: 0x20006 });
const registryValueKind = Object.freeze({ none: 0, sz: 1, dword: 4 });
const consoleMode = Object.freeze({ output: 0x0003, input: 0x0007 });
const consoleCodePage = 1252;

// The i386 msvcrt FILE (struct _iobuf) is 32 byte wide; the _file descriptor
// index sits at offset 16. The three standard streams live in the _iob array
// as fd 0/1/2, and a _fdopen/_wfopen stream carries its fd in the same field.
const FILE_STRUCT_BYTE = 32;
const FILE_FD_OFFSET = 16;
// The C errno the bounded CRT reports: EBADF (bad descriptor), ENOENT (no such
// file), EINVAL (invalid argument), ERANGE (result out of range).
const crtErrnoValue = Object.freeze({ ebadf: 9, enoent: 2, einval: 22, erange: 34 });

// The MSVCRT/UCRT ctype classification bits (ctype.h). A binary's isX call
// returns the masked bit — nonzero iff the class holds — so these must match the
// real header values a guest may compare against.
const CTYPE_UPPER = 0x01;
const CTYPE_LOWER = 0x02;
const CTYPE_DIGIT = 0x04;
const CTYPE_SPACE = 0x08;
const CTYPE_PUNCT = 0x10;
const CTYPE_CONTROL = 0x20;
const CTYPE_BLANK = 0x40;
const CTYPE_HEX = 0x80;
const CTYPE_ALPHA = 0x0100;

// The classification mask of one byte in the "C" locale, the single locale the
// bounded CRT emulates. This is the real ctype table ucrt builds for "C":
// 0x00-0x08,0x0e-0x1f,0x7f are control; 0x09-0x0d and 0x20 are space (0x20 also
// blank, 0x09 also blank); 0-9 digit; A-Z upper+alpha; a-z lower+alpha;
// A-F/a-f/0-9 hex; every other printable byte is punctuation.
function crtCtypeMask(byte) {
  const c = byte & 0xff;
  let mask = 0;
  if (c <= 0x08 || (c >= 0x0e && c <= 0x1f) || c === 0x7f) mask |= CTYPE_CONTROL;
  if (c >= 0x09 && c <= 0x0d) mask |= CTYPE_SPACE | CTYPE_CONTROL;
  if (c === 0x09) mask |= CTYPE_BLANK;
  if (c === 0x20) mask |= CTYPE_SPACE | CTYPE_BLANK;
  if (c >= 0x30 && c <= 0x39) mask |= CTYPE_DIGIT | CTYPE_HEX;
  if (c >= 0x41 && c <= 0x5a) mask |= CTYPE_UPPER | CTYPE_ALPHA;
  if (c >= 0x61 && c <= 0x7a) mask |= CTYPE_LOWER | CTYPE_ALPHA;
  if ((c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66)) mask |= CTYPE_HEX;
  const isControl = (mask & CTYPE_CONTROL) !== 0;
  const isSpaceOrDigitOrAlpha = (mask & (CTYPE_SPACE | CTYPE_DIGIT | CTYPE_ALPHA)) !== 0;
  if (c >= 0x21 && c <= 0x7e && !isControl && !isSpaceOrDigitOrAlpha) mask |= CTYPE_PUNCT;
  return mask;
}

// The library sets the ctype / conversion / utility CRT breadth registers under.
// The Universal CRT api-sets (Dwarf Fortress links these) and the legacy
// msvcrt.dll export the same names; both the runtime export table and the
// conformance census iterate these one list so the served set and the census
// coverage cannot drift apart.
const CRT_STRING_API = "api-ms-win-crt-string-l1-1-0.dll";
const CRT_CONVERT_API = "api-ms-win-crt-convert-l1-1-0.dll";
const CRT_UTILITY_API = "api-ms-win-crt-utility-l1-1-0.dll";
const CRT_MSVCRT = "msvcrt.dll";
const CTYPE_LIBRARY = [CRT_STRING_API, CRT_MSVCRT];
const CASECONV_LIBRARY = [CRT_STRING_API, CRT_CONVERT_API, CRT_MSVCRT];
const NUMBER_LIBRARY = [CRT_CONVERT_API, CRT_MSVCRT];
const RANDOM_LIBRARY = [CRT_UTILITY_API, CRT_MSVCRT];
// symbol -> the single ctype mask bit (or bit union) the classifier tests.
const CTYPE_CLASSIFIER_BIT = {
  isupper: CTYPE_UPPER, islower: CTYPE_LOWER, isdigit: CTYPE_DIGIT, isspace: CTYPE_SPACE,
  ispunct: CTYPE_PUNCT, iscntrl: CTYPE_CONTROL, isxdigit: CTYPE_HEX,
  isalpha: CTYPE_ALPHA | CTYPE_UPPER | CTYPE_LOWER,
  isalnum: CTYPE_ALPHA | CTYPE_UPPER | CTYPE_LOWER | CTYPE_DIGIT,
};
// The range classifiers whose "C"-locale answer is a printable-range test.
const CTYPE_RANGE = {
  isprint: (c) => (c >= 0x20 && c <= 0x7e ? 1 : 0),
  isgraph: (c) => (c > 0x20 && c <= 0x7e ? 1 : 0),
  isblank: (c) => (c === 0x20 || c === 0x09 ? 1 : 0),
};
const crtToUpper = (c) => (c >= 0x61 && c <= 0x7a ? c - 0x20 : c);
const crtToLower = (c) => (c >= 0x41 && c <= 0x5a ? c + 0x20 : c);

// The deterministic guest wall clock as a Unix second: the HLE file-time base
// (100-ns tick since 1601) minus the 1601→1970 epoch offset, in seconds. This
// is a fixed guest instant (2020-09-10T18:40:00Z), never the host clock.
function crtGuestUnixSecond() {
  return Number((132442368000000000n - 116444736000000000n) / 10000000n) >>> 0;
}

// The bounded strerror text for the errno the CRT surface reports.
function crtStrerrorText(errnum) {
  const table = {
    0: "No error",
    2: "No such file or directory",
    9: "Bad file descriptor",
    12: "Not enough space",
    22: "Invalid argument",
    34: "Result too large",
  };
  return table[errnum] ?? "Unknown error";
}

// Fill the shared struct tm buffer from a Unix second (UTC) and return its
// address. tm layout: sec, min, hour, mday, mon, year(−1900), wday, yday, isdst.
function crtWriteTm(guest, unixSecond) {
  const date = new Date(unsigned(unixSecond) * 1000);
  const base = guest.crtRuntime.tmBuf;
  const field = [
    date.getUTCSeconds(), date.getUTCMinutes(), date.getUTCHours(), date.getUTCDate(),
    date.getUTCMonth(), date.getUTCFullYear() - 1900, date.getUTCDay(),
    Math.floor((Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()) - Date.UTC(date.getUTCFullYear(), 0, 1)) / 86400000), 0,
  ];
  for (let index = 0; index < field.length; index += 1) guest.memory.writeMemory(base + index * 4, 4, field[index] >>> 0);
  return base;
}

// A bounded strftime over the shared clock's UTC fields. Unknown specifiers are
// copied literally; the result is truncated to the caller's byte cap and the
// return is the written length excluding the terminator (0 on overflow).
function crtStrftime(guest, destination, maximumByte, formatAddress, tmAddress) {
  const format = guest.readAnsiString(formatAddress) ?? "";
  const value = (offset) => signed32(guest.memory.readMemory(unsigned(tmAddress) + offset, 4));
  const pad = (number, width = 2) => String(number).padStart(width, "0");
  const monthName = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const dayName = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  let output = "";
  for (let index = 0; index < format.length; index += 1) {
    if (format[index] !== "%" || index + 1 >= format.length) { output += format[index]; continue; }
    index += 1;
    switch (format[index]) {
      case "Y": output += String(value(20) + 1900); break;
      case "m": output += pad(value(16) + 1); break;
      case "d": output += pad(value(12)); break;
      case "H": output += pad(value(8)); break;
      case "M": output += pad(value(4)); break;
      case "S": output += pad(value(0)); break;
      case "b": output += monthName[((value(16) % 12) + 12) % 12]; break;
      case "a": output += dayName[((value(24) % 7) + 7) % 7]; break;
      case "%": output += "%"; break;
      default: output += `%${format[index]}`; break;
    }
  }
  if (output.length + 1 > unsigned(maximumByte)) return 0;
  guest.writeAnsiString(unsigned(destination), output, output.length + 1);
  return output.length;
}

// _stati64: fill the 88-byte _stat64 with the virtual-drive size for an
// existing file, else report ENOENT. Only st_size (offset 24, 8 byte) is
// meaningful in the bounded world; every other field stays zero.
// Translate a C stdio fopen mode string ("rb", "w", "a+", …) to the _O_* oflag
// _open takes. The read modes must NOT create: a game probes for its IWAD by
// fopen(path, "rb") and relies on a NULL return for an absent file (an always
// -create open would fabricate an empty file and make the probe pass wrongly).
function crtFopenOflag(modeText) {
  const mode = (modeText ?? "").toLowerCase();
  const plus = mode.includes("+");
  if (mode.startsWith("w")) return (plus ? 0x0002 : 0x0001) | 0x0100 | 0x0200; // _O_RDWR/_O_WRONLY | _O_CREAT | _O_TRUNC
  if (mode.startsWith("a")) return (plus ? 0x0002 : 0x0001) | 0x0100 | 0x0008; // | _O_CREAT | _O_APPEND
  return plus ? 0x0002 : 0x0000; // _O_RDWR / _O_RDONLY, never creating
}

function crtStat(guest, path, statAddress) {
  if (path === null) { guest.crtErrno(crtErrnoValue.einval); return 0xffffffff; }
  const size = guest.virtualFileSize(path);
  if (size === null) { guest.crtErrno(crtErrnoValue.enoent); return 0xffffffff; }
  guest.memory.writeBlock(unsigned(statAddress), Buffer.alloc(88));
  guest.memory.writeMemory(unsigned(statAddress) + 24, 4, size >>> 0);
  guest.memory.writeMemory(unsigned(statAddress) + 28, 4, Math.floor(size / 0x100000000) >>> 0);
  return 0;
}

// A bounded C printf format engine over an x86-64 va_list. The ucrt formatted
// backends (__stdio_common_vsprintf/_vfprintf and their _s variants) receive an
// explicit va_list pointer — on x64 a pointer into the caller's argument-spill
// area — so the variadic argument are real guest bytes, read eight per slot in
// order. This is load-bearing control flow, not cosmetic log text: Chocolate
// Doom builds its configuration-variable names with sprintf("...%i", index)
// and then string-compares the result against its known table, so an
// unexpanded "%i" makes every name unknown and aborts the startup with
// I_Error. Supports the flag set (- + space 0 #), a numeric or `*` width and
// precision, the length modifier (h hh l ll z j t L), and the
// d/i/u/o/x/X/c/s/p/e/E/f/F/g/G/% conversion a game's snprintf path uses. The
// width is bounded so a hostile `*` width cannot blow the output.
function formatPrintf(guest, formatText, vaListAddress) {
  const widthBound = 4096;
  let va = vaListAddress < 0 ? vaListAddress >>> 0 : vaListAddress;
  const slot = () => { const block = guest.memory.readBlock(va, 8); va += 8; return block; };
  const nextU64 = () => slot().readBigUInt64LE(0);
  const nextDouble = () => slot().readDoubleLE(0);
  let out = "";
  let i = 0;
  while (i < formatText.length) {
    const ch = formatText[i];
    if (ch !== "%") { out += ch; i += 1; continue; }
    i += 1;
    if (formatText[i] === "%") { out += "%"; i += 1; continue; }
    let leftAlign = false; let plus = false; let space = false; let zero = false; let alt = false;
    for (; i < formatText.length; i += 1) {
      const flag = formatText[i];
      if (flag === "-") leftAlign = true;
      else if (flag === "+") plus = true;
      else if (flag === " ") space = true;
      else if (flag === "0") zero = true;
      else if (flag === "#") alt = true;
      else break;
    }
    let width = 0;
    if (formatText[i] === "*") { width = Number(BigInt.asIntN(32, nextU64())); i += 1; if (width < 0) { leftAlign = true; width = -width; } }
    else for (; i < formatText.length && formatText[i] >= "0" && formatText[i] <= "9"; i += 1) width = width * 10 + (formatText.charCodeAt(i) - 48);
    if (width > widthBound) width = widthBound;
    let precision = -1;
    if (formatText[i] === ".") {
      i += 1; precision = 0;
      if (formatText[i] === "*") { precision = Number(BigInt.asIntN(32, nextU64())); i += 1; if (precision < 0) precision = -1; }
      else for (; i < formatText.length && formatText[i] >= "0" && formatText[i] <= "9"; i += 1) precision = precision * 10 + (formatText.charCodeAt(i) - 48);
      if (precision > widthBound) precision = widthBound;
    }
    let length = "";
    for (; i < formatText.length && "hljztL".includes(formatText[i]); i += 1) length += formatText[i];
    const conv = formatText[i]; i += 1;
    if (conv === undefined) { out += "%"; break; }
    const wide64 = length === "l" || length === "ll" || length === "z" || length === "j" || length === "t";
    let sign = "";
    let prefix = "";
    let body = "";
    let numeric = false;
    if (conv === "d" || conv === "i") {
      numeric = true;
      const raw = wide64 ? BigInt.asIntN(64, nextU64()) : BigInt.asIntN(32, nextU64() & 0xffffffffn);
      const magnitude = raw < 0n ? -raw : raw;
      sign = raw < 0n ? "-" : plus ? "+" : space ? " " : "";
      body = magnitude.toString(10);
      if (precision >= 0) { zero = false; body = body.padStart(precision, "0"); if (precision === 0 && raw === 0n) body = ""; }
    } else if (conv === "u" || conv === "o" || conv === "x" || conv === "X") {
      numeric = true;
      const raw = wide64 ? nextU64() : (nextU64() & 0xffffffffn);
      const base = conv === "u" ? 10 : conv === "o" ? 8 : 16;
      body = raw.toString(base);
      if (conv === "X") body = body.toUpperCase();
      if (precision >= 0) { zero = false; body = body.padStart(precision, "0"); if (precision === 0 && raw === 0n) body = ""; }
      if (alt && raw !== 0n) prefix = conv === "o" ? "0" : conv === "x" ? "0x" : conv === "X" ? "0X" : "";
    } else if (conv === "p") {
      const raw = nextU64();
      prefix = "0x";
      body = raw.toString(16);
    } else if (conv === "c") {
      body = String.fromCharCode(Number(nextU64() & 0xffn));
    } else if (conv === "s") {
      const pointer = Number(nextU64());
      let text = pointer === 0 ? "(null)" : (guest.readAnsiString(pointer) ?? "");
      if (precision >= 0) text = text.slice(0, precision);
      body = text;
    } else if (conv === "e" || conv === "E" || conv === "f" || conv === "F" || conv === "g" || conv === "G") {
      numeric = true;
      const value = nextDouble();
      const prec = precision >= 0 ? precision : 6;
      const magnitude = Math.abs(value);
      sign = value < 0 || Object.is(value, -0) ? "-" : plus ? "+" : space ? " " : "";
      if (conv === "f" || conv === "F") body = magnitude.toFixed(prec);
      else if (conv === "e" || conv === "E") body = magnitude.toExponential(prec);
      else body = magnitude.toPrecision(Math.max(prec, 1));
      if (conv === "E" || conv === "G") body = body.toUpperCase();
    } else {
      // An unrecognized conversion is emitted verbatim (percent then the letter).
      out += "%" + (conv ?? "");
      continue;
    }
    let piece = sign + prefix + body;
    if (piece.length < width) {
      if (leftAlign) piece = piece + " ".repeat(width - piece.length);
      else if (zero && numeric) piece = sign + prefix + "0".repeat(width - piece.length) + body;
      else piece = " ".repeat(width - piece.length) + piece;
    }
    out += piece;
  }
  return out;
}

// A bounded C scanf format engine over a byte source and an x86-64 va_list. The
// ucrt formatted-input backends read from either a string (sscanf) or a real
// file (fscanf); `readByte` returns the next input byte or -1 at end, and the
// va_list pointer supplies the assignment targets eight bytes per slot. This is
// load-bearing WAD-load control flow: Chocolate Doom parses its DEHACKED lump
// with sscanf. Supports whitespace/literal matching, assignment suppression
// (%*), a field width, the length modifier, and the d/i/u/o/x/c/s/[…] and
// float conversion. Returns the number of assigned fields, or EOF (-1) when the
// input ends before the first conversion assigns.
function scanfInput(guest, formatText, readByte, vaListAddress) {
  let va = vaListAddress < 0 ? vaListAddress >>> 0 : vaListAddress;
  const nextPtr = () => { const block = guest.memory.readBlock(va, 8); va += 8; return Number(block.readBigUInt64LE(0)); };
  const isSpace = (c) => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d || c === 0x0b || c === 0x0c;
  let pending = -2;
  const peek = () => { if (pending === -2) pending = readByte(); return pending; };
  const take = () => { const c = peek(); pending = -2; return c; };
  const storeInt = (ptr, length, value) => {
    const masked = BigInt(value) & 0xffffffffffffffffn;
    if (length === "hh") guest.memory.writeMemory(ptr, 1, Number(masked & 0xffn));
    else if (length === "h") guest.memory.writeMemory(ptr, 2, Number(masked & 0xffffn));
    else if (length === "l" || length === "ll" || length === "j" || length === "z" || length === "t") { guest.memory.writeMemory(ptr, 4, Number(masked & 0xffffffffn)); guest.memory.writeMemory(ptr + 4, 4, Number((masked >> 32n) & 0xffffffffn)); }
    else guest.memory.writeMemory(ptr, 4, Number(masked & 0xffffffffn));
  };
  let assigned = 0;
  let sawInput = false;
  let i = 0;
  while (i < formatText.length) {
    const ch = formatText[i];
    if (isSpace(ch.charCodeAt(0))) { while (isSpace(peek())) take(); i += 1; continue; }
    if (ch !== "%") { if (peek() === ch.charCodeAt(0)) { take(); i += 1; continue; } break; }
    i += 1;
    if (formatText[i] === "%") { while (isSpace(peek())) take(); if (peek() === 0x25) { take(); i += 1; continue; } break; }
    let suppress = false;
    if (formatText[i] === "*") { suppress = true; i += 1; }
    let width = 0; let hasWidth = false;
    for (; formatText[i] >= "0" && formatText[i] <= "9"; i += 1) { hasWidth = true; width = width * 10 + (formatText.charCodeAt(i) - 48); }
    let length = "";
    for (; i < formatText.length && "hljztL".includes(formatText[i]); i += 1) length += formatText[i];
    const conv = formatText[i]; i += 1;
    if (conv === undefined) break;
    if (conv === "c") {
      const wanted = hasWidth ? width : 1;
      const ptr = suppress ? 0 : nextPtr();
      let wrote = 0;
      for (; wrote < wanted; wrote += 1) { const c = take(); if (c < 0) break; sawInput = true; if (ptr) guest.memory.writeMemory(ptr + wrote, 1, c & 0xff); }
      if (wrote < wanted) break;
      if (!suppress) assigned += 1;
      continue;
    }
    if (conv === "s") {
      while (isSpace(peek())) take();
      const ptr = suppress ? 0 : nextPtr();
      let wrote = 0;
      for (; !hasWidth || wrote < width; wrote += 1) { const c = peek(); if (c < 0 || isSpace(c)) break; take(); sawInput = true; if (ptr) guest.memory.writeMemory(ptr + wrote, 1, c & 0xff); }
      if (ptr) guest.memory.writeMemory(ptr + wrote, 1, 0);
      if (wrote === 0) break;
      if (!suppress) assigned += 1;
      continue;
    }
    if (conv === "[") {
      let negate = false;
      if (formatText[i] === "^") { negate = true; i += 1; }
      const set = new Set();
      if (formatText[i] === "]") { set.add(0x5d); i += 1; }
      for (; i < formatText.length && formatText[i] !== "]"; i += 1) set.add(formatText.charCodeAt(i));
      i += 1; // consume ']'
      const ptr = suppress ? 0 : nextPtr();
      let wrote = 0;
      for (; !hasWidth || wrote < width; wrote += 1) { const c = peek(); if (c < 0 || (set.has(c) === negate)) break; take(); sawInput = true; if (ptr) guest.memory.writeMemory(ptr + wrote, 1, c & 0xff); }
      if (ptr) guest.memory.writeMemory(ptr + wrote, 1, 0);
      if (wrote === 0) break;
      if (!suppress) assigned += 1;
      continue;
    }
    if ("diuoxX".includes(conv)) {
      while (isSpace(peek())) take();
      let text = "";
      let sign = "";
      const cap = hasWidth ? width : Number.MAX_SAFE_INTEGER;
      if (peek() === 0x2b || peek() === 0x2d) { sign = String.fromCharCode(take()); sawInput = true; }
      let base = conv === "x" || conv === "X" ? 16 : conv === "o" ? 8 : conv === "u" || conv === "d" ? 10 : 0; // %i auto-detects
      if ((base === 0 || base === 16) && peek() === 0x30) { // leading 0 / 0x
        text += String.fromCharCode(take()); sawInput = true;
        if ((peek() === 0x78 || peek() === 0x58) && (base === 16 || base === 0)) { take(); base = 16; text = ""; }
        else if (base === 0) base = 8;
      }
      if (base === 0) base = 10;
      const isDigit = (c) => { if (c >= 0x30 && c <= 0x39) return (c - 0x30) < base; if (base === 16) return (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66); return false; };
      for (; text.length < cap && isDigit(peek()); ) { text += String.fromCharCode(take()); sawInput = true; }
      if (text === "") break;
      let parsed = 0n;
      for (const dch of text) parsed = parsed * BigInt(base) + BigInt(parseInt(dch, 16));
      if (sign === "-") parsed = -parsed;
      if (!suppress) { storeInt(nextPtr(), length, parsed); assigned += 1; }
      continue;
    }
    if ("eEfFgGaA".includes(conv)) {
      while (isSpace(peek())) take();
      let text = "";
      const cap = hasWidth ? width : Number.MAX_SAFE_INTEGER;
      const takeIf = (pred) => { if (text.length < cap && pred(peek())) { text += String.fromCharCode(take()); sawInput = true; return true; } return false; };
      takeIf((c) => c === 0x2b || c === 0x2d);
      while (takeIf((c) => c >= 0x30 && c <= 0x39));
      if (takeIf((c) => c === 0x2e)) while (takeIf((c) => c >= 0x30 && c <= 0x39));
      if (takeIf((c) => c === 0x65 || c === 0x45)) { takeIf((c) => c === 0x2b || c === 0x2d); while (takeIf((c) => c >= 0x30 && c <= 0x39)); }
      const value = Number.parseFloat(text);
      if (text === "" || Number.isNaN(value)) break;
      if (!suppress) {
        const ptr = nextPtr();
        const buffer = Buffer.alloc(8);
        if (length === "l" || length === "L") { buffer.writeDoubleLE(value, 0); guest.memory.writeBlock(ptr, buffer); }
        else { const single = Buffer.alloc(4); single.writeFloatLE(value, 0); guest.memory.writeBlock(ptr, single); }
        assigned += 1;
      }
      continue;
    }
    if (conv === "n") { if (!suppress) nextPtr(); continue; }
    break; // an unrecognized conversion stops the scan
  }
  if (assigned === 0 && !sawInput && peek() < 0) return 0xffffffff; // EOF before any assignment
  return assigned;
}

// The declared locale environment (BPTK-103 slice): one locale, ANSI/OEM code
// page 1252 with the real best-fit table, and real UTF-8 conversion. The
// 0x80-0x9F range differs from Latin-1 in code page 1252; the undefined
// code point map to the C1 control.
const codepage1252High = new Map([
  [0x80, 0x20ac], [0x82, 0x201a], [0x83, 0x0192], [0x84, 0x201e], [0x85, 0x2026], [0x86, 0x2020], [0x87, 0x2021],
  [0x88, 0x02c6], [0x89, 0x2030], [0x8a, 0x0160], [0x8b, 0x2039], [0x8c, 0x0152], [0x8e, 0x017d], [0x91, 0x2018],
  [0x92, 0x2019], [0x93, 0x201c], [0x94, 0x201d], [0x95, 0x2022], [0x96, 0x2013], [0x97, 0x2014], [0x98, 0x02dc],
  [0x99, 0x2122], [0x9a, 0x0161], [0x9b, 0x203a], [0x9c, 0x0153], [0x9e, 0x017e], [0x9f, 0x0178],
]);
const codepage1252Reverse = new Map([...codepage1252High.entries()].map(([byte, wide]) => [wide, byte]));
const supportedCodePage = new Set([1252, 437, 65001]);
// CP_ACP / CP_OEMCP / CP_THREAD_ACP are aliases for the declared pages, not
// distinct encodings. Conversion and GetCPInfo accept them; IsValidCodePage
// does not (Windows returns FALSE for 0).
function resolveCodePage(codePage) {
  const id = unsigned(codePage);
  if (id === 0 || id === 3) return 1252;
  if (id === 1) return 1252;
  return id;
}
const localeId = 0x0409;
const localeNameTable = new Map([
  [0x0001, "0409"],
  [0x0002, "English (United States)"],
  [0x1001, "English"],
  [0x1002, "United States"],
  [0x1004, "ENU"],
  [0x1007, "US Dollar"],
]);

function ansiToWide(codePage, data) {
  if (codePage === 65001) return { text: new TextDecoder("utf-8", { fatal: false }).decode(data) };
  let text = "";
  for (const byte of data) {
    if (byte >= 0x80 && byte <= 0x9f) text += String.fromCharCode(codepage1252High.get(byte) ?? byte);
    else text += String.fromCharCode(byte);
  }
  return { text };
}

function wideToAnsi(codePage, text) {
  if (codePage === 65001) return Buffer.from(text, "utf8");
  const out = Buffer.alloc(text.length);
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code < 0x80) out[index] = code;
    else if (code >= 0xa0) out[index] = code <= 0xff ? code : codepage1252Reverse.get(code) ?? 0x3f;
    else out[index] = codepage1252Reverse.get(code) ?? code & 0xff;
  }
  return out;
}

// The CommandLineToArgvW tokenizer: the exact Windows argv parsing rule a
// program applies to its command line. Whitespace separates arguments; a double
// quote toggles a quoted span; a run of backslashes is literal unless it
// precedes a quote, where 2n backslashes become n and consume the quote-toggle
// while 2n+1 emit n backslashes plus a literal quote; a doubled quote inside a
// quoted span is a literal quote. Real bytes in, real argv out.
function parseCommandLineW(text) {
  const argv = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    while (i < n && (text[i] === " " || text[i] === "\t")) i += 1;
    if (i >= n) break;
    let arg = "";
    let inQuote = false;
    while (i < n) {
      const c = text[i];
      if (c === "\\") {
        let slash = 0;
        while (i < n && text[i] === "\\") { slash += 1; i += 1; }
        if (i < n && text[i] === '"') {
          arg += "\\".repeat(slash >> 1);
          if (slash & 1) { arg += '"'; i += 1; } else { inQuote = !inQuote; i += 1; }
        } else {
          arg += "\\".repeat(slash);
        }
      } else if (c === '"') {
        if (inQuote && i + 1 < n && text[i + 1] === '"') { arg += '"'; i += 2; } else { inQuote = !inQuote; i += 1; }
      } else if ((c === " " || c === "\t") && !inQuote) {
        break;
      } else {
        arg += c;
        i += 1;
      }
    }
    argv.push(arg);
  }
  return argv;
}

// The declared deterministic date and time formatter: a real token formatter
// over SYSTEMTIME field with no host clock leakage beyond the one guest clock.
function formatSystemTime(token, field) {
  let out = "";
  let index = 0;
  while (index < token.length) {
    const ch = token[index];
    let run = 1;
    while (index + run < token.length && token[index + run] === ch) run += 1;
    if (ch === "'") {
      let end = index + 1;
      while (end < token.length && token[end] !== "'") end += 1;
      out += token.slice(index + 1, end);
      index = end + 1;
      continue;
    }
    const pad = (value, width) => String(value).padStart(width, "0");
    const dayName = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"][field.day_of_week] ?? "";
    const monthName = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"][field.month - 1] ?? "";
    if (ch === "y") out += run >= 4 ? String(field.year) : run === 3 ? String(field.year) : pad(field.year % 100, 2);
    else if (ch === "M") out += run >= 4 ? monthName : run === 3 ? monthName.slice(0, 3) : pad(field.month, run);
    else if (ch === "d") out += run >= 4 ? dayName : run === 3 ? dayName.slice(0, 3) : pad(field.day, run);
    else if (ch === "H") out += pad(field.hour, run);
    else if (ch === "h") out += pad(field.hour % 12 === 0 ? 12 : field.hour % 12, run);
    else if (ch === "m") out += pad(field.minute, run);
    else if (ch === "s") out += pad(field.second, run);
    else if (ch === "t") out += field.hour < 12 ? "AM" : "PM";
    else out += ch.repeat(run);
    index += run;
  }
  return out;
}

// The declared interactive user of the confined probe: one host-neutral name,
// never a real account. GetUserNameA and the SID surface answer with it.
const guestUserName = "user";

// FormatMessage FROM_SYSTEM has no populated message table in the bounded
// probe, so it renders one deterministic, host-neutral line per error code.
// Both the emulator and its conformance case call this, so they never drift.
function formatSystemMessage(messageId) {
  return `System error code ${unsigned(messageId)}.\r\n`;
}

const hresult = Object.freeze({
  s_ok: 0,
  s_false: 1,
  e_nointerface: 0x80004002,
  e_invalidarg: 0x80070057,
  e_insufficient_buffer: 0x8007007a,
  regdb_e_classnotreg: 0x80040154,
  rpc_e_changed_mode: 0x80010106,
  co_e_notinitialized: 0x800401f0,
});

const heapFlag = Object.freeze({ zero_memory: 0x08, generate_exceptions: 0x04, no_serialize: 0x01 });
const allocationType = Object.freeze({ commit: 0x1000, reserve: 0x2000, reset: 0x800, release: 0x8000 });
const protection = Object.freeze({ noaccess: 0x01, readonly: 0x02, readwrite: 0x04, execute_read: 0x20, execute_readwrite: 0x40 });
const memState = Object.freeze({ commit: 0x1000, reserve: 0x2000, free: 0x10000 });
const memType = Object.freeze({ private: 0x20000, mapped: 0x40000 });
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

const versionTypeBit = Object.freeze({
  minor: 0x00000001,
  major: 0x00000002,
  build: 0x00000004,
  platform: 0x00000008,
  service_pack_minor: 0x00000010,
  service_pack_major: 0x00000020,
  suite: 0x00000040,
  product: 0x00000080,
});

function verSetConditionMask(conditionMask, typeMask, condition) {
  let mask = BigInt.asUintN(64, BigInt(conditionMask));
  let type = unsigned(typeMask);
  const cond = condition & 7;
  for (let index = 0; type !== 0 && index < 22; index += 1) {
    if ((type & 1) !== 0) mask = BigInt.asUintN(64, mask | (BigInt(cond) << BigInt(index * 3)));
    type >>>= 1;
  }
  return mask;
}

function verConditionAt(mask, bitIndex) {
  return Number((BigInt.asUintN(64, BigInt(mask)) >> BigInt(bitIndex * 3)) & 7n);
}

function compareVersionField(actual, requested, condition) {
  if (condition === 1) return actual === requested;
  if (condition === 2) return actual > requested;
  if (condition === 3) return actual >= requested;
  if (condition === 4) return actual < requested;
  if (condition === 5) return actual <= requested;
  return false;
}

function localeNameToLcid(name) {
  if (name === null || name === "") return 0x007f;
  const key = name.toLowerCase();
  if (key === "en-us" || key === "en") return 0x0409;
  if (key === "en-gb") return 0x0809;
  return 0;
}

function lcidToLocaleName(lcid) {
  const id = unsigned(lcid) & 0xffff;
  if (id === 0x0409 || id === 0x0400 || id === 0x0800) return "en-US";
  if (id === 0x0809) return "en-GB";
  if (id === 0x007f) return "";
  return null;
}

function writeLocaleName(guest, destination, destinationCount, name) {
  const needed = name.length + 1;
  if (destinationCount === 0) return needed;
  if (destination === 0 || destinationCount < needed) {
    guest.setLastError(errorValue.insufficient_buffer);
    return 0;
  }
  guest.writeWideString(destination, name, destinationCount);
  return needed;
}

function lcMapString(guest, flags, source, sourceCount, destination, destinationCount) {
  const count = unsigned(sourceCount);
  const destCount = unsigned(destinationCount);
  const isNulTerm = count === 0xffffffff;
  if (source === 0 || (!isNulTerm && (sourceCount | 0) < 0)) {
    guest.setLastError(errorValue.invalid_parameter);
    return 0;
  }
  const text = isNulTerm
    ? guest.readWideString(source)
    : count === 0 ? ""
    : guest.memory.readBlock(source, count * 2).toString("utf16le").slice(0, count);
  const mapped = (flags & 0x100) !== 0 ? text.toLowerCase() : text.toUpperCase();
  const needed = mapped.length + (isNulTerm ? 1 : 0);
  // cchDest is a Win32 int: a 64-bit stack slot can carry stale high bits.
  // Masked 0 is the documented size-query form (lpDestStr may be NULL).
  if (destCount === 0 || destination === 0) return destCount === 0 ? needed : (guest.setLastError(errorValue.invalid_parameter), 0);
  if (destCount < needed) {
    guest.setLastError(errorValue.insufficient_buffer);
    return 0;
  }
  if (isNulTerm) guest.writeWideString(destination, mapped, destCount);
  else guest.memory.writeBlock(destination, Buffer.from(mapped, "utf16le"));
  return needed;
}

function signed32(value) {
  return value | 0;
}

function raiseProcessExit(exitCode) {
  throw new HleSignal("hle_exit", "The guest ended its own process", { exit_code: unsigned(exitCode) });
}

function raiseGuestException(exceptionCode) {
  throw new HleSignal("hle_guest_exception", "The guest raised an unhandled exception", { exception_code: unsigned(exceptionCode) });
}

// The deterministic address placement for one HLE execution. The block
// (arena + virtual arena + thunk page + the thread-environment block) must not
// overlap the mapped image, the bounded stack, or the entry return sentinel,
// so the scan walks the declared candidates and takes the first disjoint
// block. The TEB and PEB pages (BPTK-025) are carved from the tail of the same
// block so fs-relative addressing resolves against real mapped memory.
const blockLayoutByte = hleBound.arena_byte + hleBound.virtual_byte + hleBound.thunk_page_byte + TEB_SIZE_BYTE + PEB_SIZE_BYTE;

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
      teb_base: base + hleBound.arena_byte + hleBound.virtual_byte + hleBound.thunk_page_byte,
      teb_size_byte: TEB_SIZE_BYTE,
      peb_base: base + hleBound.arena_byte + hleBound.virtual_byte + hleBound.thunk_page_byte + TEB_SIZE_BYTE,
      peb_size_byte: PEB_SIZE_BYTE,
    };
  }
  return null;
}

// The served import join (the export-coverage mechanism, GS-041): the parsed
// import table is joined against the HLE registry; a fully served image
// receives one thunk address per import so the probe dispatches the call,
// and a partially served image is refused with the unserved surface named.
// Resolves one guest import against the HLE registry. An exact library!symbol
// hit wins; otherwise the Windows api-set and ntdll name-forwards apply so a
// binary that imports WaitOnAddress from api-ms-win-core-synch (or strtok
// from api-ms-win-crt-string) is served by the same real kernel32/msvcrt
// row, never a second invented implementation.
export function resolveHleExport(library, symbol, ordinal = null) {
  if (typeof library !== "string") return null;
  const lib = library.toLowerCase();
  if (typeof symbol === "string") {
    const exact = win32HleExportTable.find((entry) => entry.library === lib && entry.symbol === symbol);
    if (exact) return exact;
    if (/^api-ms-win-crt-[a-z0-9-]+\.dll$/.test(lib)) {
      return win32HleExportTable.find((entry) => entry.library === "msvcrt.dll" && entry.symbol === symbol)
        ?? win32HleExportTable.find((entry) => entry.library === "vcruntime140.dll" && entry.symbol === symbol)
        ?? null;
    }
    if (/^api-ms-win-core-[a-z0-9-]+\.dll$/.test(lib)) {
      return win32HleExportTable.find((entry) => entry.library === "kernel32.dll" && entry.symbol === symbol)
        ?? win32HleExportTable.find((entry) => entry.library === "ntdll.dll" && entry.symbol === symbol)
        ?? null;
    }
    if (lib === "ntdll.dll") {
      return win32HleExportTable.find((entry) => entry.library === "kernel32.dll" && entry.symbol === symbol) ?? null;
    }
    if (lib === "sspicli.dll") {
      return win32HleExportTable.find((entry) => entry.library === "secur32.dll" && entry.symbol === symbol) ?? null;
    }
  }
  if (Number.isInteger(ordinal) && ordinal > 0) {
    return win32HleExportTable.find((entry) => entry.library === lib && entry.ordinal === ordinal) ?? null;
  }
  return null;
}

export function computeImportService(report, layout) {
  const registry = listWin32HleExport();
  const thunkBySymbol = new Map(registry.map((entry, index) => [`${entry.library}!${entry.symbol}`, layout.thunk_base + index * 4]));
  const import_catalog = [];
  const unserved_entry = [];
  let servedCount = 0;
  for (const currentImport of report.import) {
    const key = `${currentImport.library}!${currentImport.symbol ?? `#${currentImport.ordinal}`}`;
    const resolved = resolveHleExport(currentImport.library, currentImport.symbol, currentImport.ordinal);
    const thunk = resolved ? thunkBySymbol.get(`${resolved.library}!${resolved.symbol}`) : undefined;
    if (thunk === undefined) {
      unserved_entry.push(key);
      continue;
    }
    import_catalog.push({
      library: currentImport.library,
      symbol: currentImport.symbol,
      ordinal: currentImport.ordinal,
      address: hleImportBindAddress(layout, resolved, thunk),
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

// CRT data exports live at deterministic arena addresses, not on the thunk
// page. A guest that imports `_iob` (jq's stdout is `&_iob[1]`) must receive
// the FILE table itself; binding a CALL thunk made fputc treat the thunk as
// FILE* and write fd 0 (EBADF / EOF).
export function hleCrtDataLayout(layout) {
  let cursor = (layout.arena_base + layout.arena_size_byte - 0x2000) >>> 0;
  const take = (sizeByte) => {
    const at = cursor;
    cursor += (sizeByte + 15) & ~15;
    return at >>> 0;
  };
  const iob_base = take(FILE_STRUCT_BYTE * 3);
  const utc_address = take(4);
  const tzname_base = take(8);
  const mb_cur_max_cell = take(4);
  const environ_cell = take(8);
  const wenviron_cell = take(8);
  const sspi_table = take(128);
  return Object.freeze({ iob_base, utc_address, tzname_base, mb_cur_max_cell, environ_cell, wenviron_cell, sspi_table, cursor });
}

export function hleDataExportAddress(layout, symbol) {
  const placed = hleCrtDataLayout(layout);
  if (symbol === "_iob") return placed.iob_base;
  if (symbol === "_tzname") return placed.tzname_base;
  if (symbol === "__mb_cur_max") return placed.mb_cur_max_cell;
  if (symbol === "_environ") return placed.environ_cell;
  if (symbol === "__winitenv") return placed.wenviron_cell;
  return null;
}

export function hleImportBindAddress(layout, resolved, thunk) {
  if (resolved?.kind === "data") {
    const address = hleDataExportAddress(layout, resolved.symbol);
    if (address !== null) return address;
  }
  return thunk;
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

function specialFolderPath(csidl) {
  const windows = hleProfile.system_directory.replace(/\\System32$/i, "");
  const profile = "C:\\Users\\Guest";
  switch ((csidl >>> 0) & 0xff) {
    case 0x00: return `${profile}\\Desktop`;
    case 0x05: return `${profile}\\Documents`;
    case 0x1a: return `${profile}\\AppData\\Roaming`;
    case 0x1c: return `${profile}\\AppData\\Local`;
    case 0x23: return `${windows}\\ProgramData`;
    case 0x24: return windows;
    case 0x25: return hleProfile.system_directory;
    case 0x26: return `${windows}\\Program Files`;
    case 0x28: return profile;
    default: return null;
  }
}

function writeSpecialFolderPath(guest, csidl, buffer, isWide) {
  const path = specialFolderPath(csidl);
  if (path === null || buffer === 0) {
    guest.setLastError(errorValue.invalid_parameter);
    return hresult.e_invalidarg;
  }
  const written = isWide ? guest.writeWideString(buffer, path, 260) : guest.writeAnsiString(buffer, path, 260);
  if (!written.is_written) {
    guest.setLastError(errorValue.insufficient_buffer);
    return hresult.e_insufficient_buffer;
  }
  return hresult.s_ok;
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

// i386 CRT and SDL are cdecl (caller cleans). Win32 system libraries stay
// stdcall (callee cleans). The probe uses this at the thunk so a cdecl
// `_crt_atexit(fn)` cannot pop the caller's frame out from under `_initterm`.
export function hleCallingConvention(library) {
  const name = String(library ?? "").toLowerCase();
  if (name === "msvcrt.dll" || name === "ucrtbase.dll") return "cdecl";
  if (name.startsWith("vcruntime") || name.startsWith("api-ms-win-crt-")) return "cdecl";
  if (name === "sdl.dll" || name.startsWith("sdl2")) return "cdecl";
  return "stdcall";
}

// ---------------------------------------------------------------------------
// The registry. One row per emulated export: the declared argument count and
// one emulator over the guest machine. Argument are dword from the guest
// stack, low to high. Stack cleanup follows hleCallingConvention(library).
// ---------------------------------------------------------------------------

function defineExportTable() {
  const table = [];

  function define(library, symbol, argumentCount, emulate, extra) {
    table.push(Object.freeze({ library, symbol, argument_count: argumentCount, calling_convention: hleCallingConvention(library), emulate, ...(extra ?? {}) }));
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
  define("advapi32.dll", "OpenProcessToken", 3, (guest, argument) => {
    const process = argument[0] >>> 0;
    const out = argument[2] >>> 0;
    if (process !== 0xffffffff || out === 0) {
      guest.setLastError(errorValue.invalid_handle);
      return 0;
    }
    guest.memory.writeMemory(out, 4, guest.openProcessToken(argument[1]));
    return 1;
  });
  define("kernel32.dll", "GetCurrentThreadId", 0, (guest) => guest.current_tid ?? hleProfile.thread_id);
  define("kernel32.dll", "GetCurrentThread", 0, () => 0xfffffffe);
  define("kernel32.dll", "IsDebuggerPresent", 0, () => 0);
  define("kernel32.dll", "IsThreadAFiber", 0, () => 0);
  define("kernel32.dll", "IsBadReadPtr", 2, (guest, argument) => guest.probeReadable(argument[0], argument[1]));
  define("kernel32.dll", "Sleep", 1, (guest, argument) => {
    if (typeof guest.park_sleep === "function") return guest.park_sleep(unsigned(argument[0]));
    guest.clock.advanceVirtualMs(unsigned(argument[0]));
    return 0;
  });
  define("kernel32.dll", "GetThreadTimes", 5, (guest, argument) => guest.threadTimes(argument[0], argument[1], argument[2], argument[3], argument[4]));
  define("kernel32.dll", "IsProcessorFeaturePresent", 1, (guest, argument) => {
    const feature = argument[0];
    return feature === processorFeature.compare_exchange_double || feature === processorFeature.rdtsc_available ? 1 : 0;
  });
  define("kernel32.dll", "RaiseException", 4, (guest, argument) => {
    const count = Math.min(unsigned(argument[2]), 15);
    const pointer = unsigned(argument[3]);
    const information = [];
    for (let index = 0; index < count; index += 1) information.push(pointer === 0 ? 0 : guest.memory.readMemory(pointer + index * 4, 4));
    return guest.raiseStructuredException(argument[0], argument[1], information);
  });
  define("kernel32.dll", "AddVectoredExceptionHandler", 2, (guest, argument) => guest.addVectoredHandler(argument[0], argument[1]));
  define("kernel32.dll", "RemoveVectoredExceptionHandler", 1, (guest, argument) => guest.removeVectoredHandler(argument[0]));

  // --- synchronization objects (BPTK-010 slice): a real event state machine
  // over the declared single-thread world. A signaled event returns
  // immediately, a finite wait advances the one guest clock and times out,
  // and an infinite wait on a silent event is the structured deadlock stop.
  define("kernel32.dll", "CreateEventW", 4, (guest, argument) => guest.createEvent(argument[1] !== 0, argument[2] !== 0, argument[3]));
  define("kernel32.dll", "SetEvent", 1, (guest, argument) => guest.signalEvent(argument[0], true));
  define("kernel32.dll", "ResetEvent", 1, (guest, argument) => guest.signalEvent(argument[0], false));
  define("kernel32.dll", "WaitForSingleObject", 2, (guest, argument) => guest.waitForSingle(argument[0], argument[1], false));
  define("kernel32.dll", "WaitForSingleObjectEx", 3, (guest, argument) => guest.waitForSingle(argument[0], argument[1], argument[2] !== 0));

  // --- the kernel32 synchronization breadth slice (extends BPTK-010/101) -----
  // Every surface the single-thread containment world serves faithfully: the
  // multi-object wait over the real object table, the waitable-timer trio
  // over the one virtual clock, the named-object open family, the futex-style
  // address wait, and the thread-exit rows the one live thread can carry.
  // An infinite wait still names the world instead of spinning; a timer due
  // time is the one wake the world can deliver deterministically.
  define("kernel32.dll", "WaitForMultipleObjects", 4, (guest, argument) => guest.waitForMultiple(argument[0], argument[1], argument[2] !== 0, argument[3]));
  define("kernel32.dll", "WaitForMultipleObjectsEx", 5, (guest, argument) => guest.waitForMultiple(argument[0], argument[1], argument[2] !== 0, argument[3])); // bAlertable: no APC completes here
  define("kernel32.dll", "SleepEx", 2, (guest, argument) => {
    guest.clock.advanceVirtualMs(unsigned(argument[0]));
    return 0; // no APC completes in the bounded world, so WAIT_IO_COMPLETION never fires
  });
  define("kernel32.dll", "SwitchToThread", 0, () => 0); // no other ready thread exists to switch to
  define("kernel32.dll", "SignalObjectAndWait", 4, (guest, argument) => guest.signalObjectAndWait(argument[0], argument[1], argument[2], argument[3] !== 0));
  define("kernel32.dll", "CreateMutexW", 3, (guest, argument) => guest.createMutex(argument[1] !== 0, argument[2], true));
  define("kernel32.dll", "CreateSemaphoreW", 4, (guest, argument) => guest.createSemaphore(argument[1] | 0, argument[2] | 0, argument[3], true));
  define("kernel32.dll", "CreateWaitableTimerA", 3, (guest, argument) => guest.createWaitableTimer(argument[1] !== 0, argument[2], false));
  define("kernel32.dll", "CreateWaitableTimerW", 3, (guest, argument) => guest.createWaitableTimer(argument[1] !== 0, argument[2], true));
  define("kernel32.dll", "SetWaitableTimer", 6, (guest, argument) => guest.setWaitableTimer(argument[0], argument[1], argument[2], argument[3], argument[5] !== 0));
  define("kernel32.dll", "CancelWaitableTimer", 1, (guest, argument) => guest.cancelWaitableTimer(argument[0]));
  define("kernel32.dll", "OpenWaitableTimerA", 3, (guest, argument) => guest.openNamedObject("timer", argument[2], false));
  define("kernel32.dll", "OpenWaitableTimerW", 3, (guest, argument) => guest.openNamedObject("timer", argument[2], true));
  define("kernel32.dll", "OpenEventA", 3, (guest, argument) => guest.openNamedObject("event", argument[2], false));
  define("kernel32.dll", "OpenEventW", 3, (guest, argument) => guest.openNamedObject("event", argument[2], true));
  define("kernel32.dll", "OpenMutexA", 3, (guest, argument) => guest.openNamedObject("mutex", argument[2], false));
  define("kernel32.dll", "OpenMutexW", 3, (guest, argument) => guest.openNamedObject("mutex", argument[2], true));
  define("kernel32.dll", "OpenSemaphoreA", 3, (guest, argument) => guest.openNamedObject("semaphore", argument[2], false));
  define("kernel32.dll", "OpenSemaphoreW", 3, (guest, argument) => guest.openNamedObject("semaphore", argument[2], true));
  define("kernel32.dll", "WaitOnAddress", 4, (guest, argument) => guest.waitOnAddress(argument[0], argument[1], argument[2], argument[3]));
  define("kernel32.dll", "WakeByAddressAll", 1, (guest, argument) => {
    if (typeof guest.after_wake_address === "function") guest.after_wake_address(unsigned(argument[0]), 0xffffffff);
    return 1;
  });
  define("kernel32.dll", "WakeByAddressSingle", 1, (guest, argument) => {
    if (typeof guest.after_wake_address === "function") guest.after_wake_address(unsigned(argument[0]), 1);
    return 1;
  });
  define("kernel32.dll", "ExitThread", 1, (guest, argument) => {
    if (guest.current_tid !== hleProfile.thread_id && typeof guest.park_wait === "function") {
      guest.pending_thread_switch = { kind: "exit", code: unsigned(argument[0]) };
      return 0;
    }
    raiseProcessExit(argument[0]);
  });
  define("kernel32.dll", "GetExitCodeThread", 2, (guest, argument) => {
    const handle = unsigned(argument[0]);
    if (handle === 0xfffffffe) {
      guest.memory.writeMemory(unsigned(argument[1]), 4, 259);
      return 1;
    }
    const record = guest.threadRecord(handle);
    if (record === null) {
      guest.setLastError(errorValue.invalid_handle);
      return 0;
    }
    guest.memory.writeMemory(unsigned(argument[1]), 4, record.object.exit_code >>> 0);
    return 1;
  });
  define("kernel32.dll", "FreeLibraryAndExitThread", 2, (guest, argument) => {
    guest.freeLibrary(argument[0]);
    if (guest.current_tid !== hleProfile.thread_id && typeof guest.park_wait === "function") {
      guest.pending_thread_switch = { kind: "exit", code: unsigned(argument[1]) };
      return 0;
    }
    raiseProcessExit(argument[1]);
  });
  define("kernel32.dll", "OpenProcess", 3, (guest, argument) => {
    // The declared world has exactly one process: its own identifier opens
    // the pseudo process handle, anything else is refused.
    if (argument[2] === hleProfile.process_id) return 0xffffffff;
    guest.setLastError(errorValue.invalid_parameter);
    return 0;
  });

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
  define("kernel32.dll", "LoadLibraryA", 1, (guest, argument) => guest.loadLibrary(guest.readAnsiString(argument[0]), 0));
  define("kernel32.dll", "LoadLibraryW", 1, (guest, argument) => guest.loadLibrary(guest.readWideString(argument[0]), 0));
  define("kernel32.dll", "LoadLibraryExW", 3, (guest, argument) => guest.loadLibrary(guest.readWideString(argument[0]), argument[2]));
  define("kernel32.dll", "FreeLibrary", 1, (guest, argument) => guest.freeLibrary(argument[0]));
  define("kernel32.dll", "GetModuleFileNameA", 3, (guest, argument) => {
    const path = guest.modulePath(argument[0]);
    if (path === null) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const written = guest.writeAnsiString(argument[1], path, argument[2]);
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return argument[2];
    }
    return written.length;
  });
  define("kernel32.dll", "GetModuleFileNameW", 3, (guest, argument) => {
    const path = guest.modulePath(argument[0]);
    if (path === null) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
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
  define("kernel32.dll", "VerSetConditionMask", 4, (guest, argument) => {
    const mask = verSetConditionMask((BigInt(unsigned(argument[1])) << 32n) | BigInt(unsigned(argument[0])), argument[2], argument[3]);
    guest.return_edx = Number(mask >> 32n) >>> 0;
    return Number(mask & 0xffffffffn) >>> 0;
  });
  define("kernel32.dll", "VerifyVersionInfoW", 4, (guest, argument) => guest.verifyVersionInfo(argument[0], argument[1], (BigInt(unsigned(argument[3])) << 32n) | BigInt(unsigned(argument[2]))));
  define("kernel32.dll", "IsValidLocale", 2, (guest, argument) => (argument[0] === localeId || argument[0] === 0x7f) && (argument[1] & ~0x8) === 0 ? 1 : 0);
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
  define("kernel32.dll", "GetTickCount64", 0, (guest) => {
    const tick = Number(guest.clock.tickCount64?.() ?? guest.clock.tickCount());
    guest.return_edx = Math.floor(tick / 0x100000000) >>> 0;
    return tick >>> 0;
  });
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
  // The ucrt/OpenTTD startup uses the Ex form (address, spin count, flags); the
  // flags select the debug-info policy the bounded single-thread world ignores.
  define("kernel32.dll", "InitializeCriticalSectionEx", 3, (guest, argument) => {
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

  // --- fiber-local storage (Win64 CRT-init breadth, BPTK-031) ----------------
  // The x86-64 ucrt startup allocates one FLS index for its per-thread block
  // before it reaches main; a single-fiber bounded world serves it as a value
  // slot (see guest.allocateFls). FlsAlloc takes the destructor callback in RCX.
  define("kernel32.dll", "FlsAlloc", 1, (guest, argument) => guest.allocateFls(argument[0]));
  define("kernel32.dll", "FlsFree", 1, (guest, argument) => guest.freeFls(argument[0]) ? 1 : 0);
  define("kernel32.dll", "FlsGetValue", 1, (guest, argument) => guest.readFls(argument[0]));
  define("kernel32.dll", "FlsSetValue", 2, (guest, argument) => guest.writeFls(argument[0], argument[1]) ? 1 : 0);
  define("kernel32.dll", "FlsGetValue2", 1, (guest, argument) => guest.readFls(argument[0]));

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
  define("kernel32.dll", "WriteConsoleW", 5, (guest, argument) => {
    // lpNumberOfCharsWritten is a character count. writeOutput records bytes
    // and would store 2× the Win32 value, which rust treats as a short write
    // and panics on after a successful --version print.
    const charCount = argument[2] >>> 0;
    const ok = guest.writeOutput(argument[0], argument[1], charCount * 2, 0, argument[4] !== 0);
    if (ok && argument[3] !== 0) guest.memory.writeMemory(argument[3], 4, charCount);
    return ok;
  });
  define("kernel32.dll", "lstrlenA", 1, (guest, argument) => {
    const value = guest.readAnsiString(argument[0]);
    return value === null ? 0 : value.length;
  });
  define("kernel32.dll", "lstrlenW", 1, (guest, argument) => {
    const value = guest.readWideString(argument[0]);
    return value === null ? 0 : value.length;
  });

  // --- kernel32 string family (stdcall, BPTK-101 breadth) -----------------------
  // Real generic emulation over the checked guest memory model: no host
  // string reaches these, every read is null-bounded by the declared cap, and
  // the comparison is the documented ordinal sign contract (<0, 0, >0). The
  // copy family returns the destination pointer per the Win32 ABI.
  const compareSign = (left, right) => (left < right ? unsigned(-1) : left > right ? 1 : 0);
  define("kernel32.dll", "lstrcmpA", 2, (guest, argument) => compareSign(guest.readAnsiString(argument[0]) ?? "", guest.readAnsiString(argument[1]) ?? ""));
  define("kernel32.dll", "lstrcmpW", 2, (guest, argument) => compareSign(guest.readWideString(argument[0]) ?? "", guest.readWideString(argument[1]) ?? ""));
  define("kernel32.dll", "lstrcmpiA", 2, (guest, argument) => compareSign((guest.readAnsiString(argument[0]) ?? "").toLowerCase(), (guest.readAnsiString(argument[1]) ?? "").toLowerCase()));
  define("kernel32.dll", "lstrcmpiW", 2, (guest, argument) => compareSign((guest.readWideString(argument[0]) ?? "").toLowerCase(), (guest.readWideString(argument[1]) ?? "").toLowerCase()));
  define("kernel32.dll", "lstrcpyA", 2, (guest, argument) => {
    if (argument[0] === 0 || argument[1] === 0) return 0;
    guest.memory.writeBlock(argument[0], Buffer.from((guest.readAnsiString(argument[1]) ?? "") + "\0", "latin1"));
    return argument[0];
  });
  define("kernel32.dll", "lstrcpyW", 2, (guest, argument) => {
    if (argument[0] === 0 || argument[1] === 0) return 0;
    guest.memory.writeBlock(argument[0], Buffer.from((guest.readWideString(argument[1]) ?? "") + "\0", "utf16le"));
    return argument[0];
  });
  define("kernel32.dll", "lstrcpynA", 3, (guest, argument) => {
    if (argument[0] === 0 || argument[1] === 0 || argument[2] <= 0) return argument[0];
    const source = (guest.readAnsiString(argument[1]) ?? "").slice(0, argument[2] - 1);
    guest.memory.writeBlock(argument[0], Buffer.from(source + "\0", "latin1"));
    return argument[0];
  });
  define("kernel32.dll", "lstrcatA", 2, (guest, argument) => {
    if (argument[0] === 0 || argument[1] === 0) return 0;
    const head = guest.readAnsiString(argument[0]) ?? "";
    guest.memory.writeBlock(argument[0] + head.length, Buffer.from((guest.readAnsiString(argument[1]) ?? "") + "\0", "latin1"));
    return argument[0];
  });
  define("kernel32.dll", "lstrcatW", 2, (guest, argument) => {
    if (argument[0] === 0 || argument[1] === 0) return 0;
    const head = guest.readWideString(argument[0]) ?? "";
    guest.memory.writeBlock(argument[0] + head.length * 2, Buffer.from((guest.readWideString(argument[1]) ?? "") + "\0", "utf16le"));
    return argument[0];
  });

  // --- interlocked atomics (BPTK-101 breadth) -----------------------------------
  // The single declared guest thread makes each read-modify-write trivially
  // atomic; the value is a 32-bit dword at the guest address and the return
  // follows the Win32 contract (Increment/Decrement return the new value,
  // Exchange/ExchangeAdd return the prior value, CompareExchange returns the
  // prior value and only stores on a match).
  define("kernel32.dll", "InterlockedIncrement", 1, (guest, argument) => {
    const value = unsigned(guest.memory.readMemory(argument[0], 4) + 1);
    guest.memory.writeMemory(argument[0], 4, value);
    return value;
  });
  define("kernel32.dll", "InterlockedDecrement", 1, (guest, argument) => {
    const value = unsigned(guest.memory.readMemory(argument[0], 4) - 1);
    guest.memory.writeMemory(argument[0], 4, value);
    return value;
  });
  define("kernel32.dll", "InterlockedExchange", 2, (guest, argument) => {
    const previous = unsigned(guest.memory.readMemory(argument[0], 4));
    guest.memory.writeMemory(argument[0], 4, unsigned(argument[1]));
    return previous;
  });
  define("kernel32.dll", "InterlockedExchangeAdd", 2, (guest, argument) => {
    const previous = unsigned(guest.memory.readMemory(argument[0], 4));
    guest.memory.writeMemory(argument[0], 4, unsigned(previous + argument[1]));
    return previous;
  });
  define("kernel32.dll", "InterlockedCompareExchange", 3, (guest, argument) => {
    const previous = unsigned(guest.memory.readMemory(argument[0], 4));
    if (previous === unsigned(argument[2])) guest.memory.writeMemory(argument[0], 4, unsigned(argument[1]));
    return previous;
  });
  define("kernel32.dll", "InterlockedAnd", 2, (guest, argument) => {
    const previous = unsigned(guest.memory.readMemory(argument[0], 4));
    guest.memory.writeMemory(argument[0], 4, unsigned(previous & unsigned(argument[1])));
    return previous;
  });
  define("kernel32.dll", "InterlockedOr", 2, (guest, argument) => {
    const previous = unsigned(guest.memory.readMemory(argument[0], 4));
    guest.memory.writeMemory(argument[0], 4, unsigned(previous | unsigned(argument[1])));
    return previous;
  });
  define("kernel32.dll", "InterlockedXor", 2, (guest, argument) => {
    const previous = unsigned(guest.memory.readMemory(argument[0], 4));
    guest.memory.writeMemory(argument[0], 4, unsigned(previous ^ unsigned(argument[1])));
    return previous;
  });
  define("kernel32.dll", "InterlockedCompareExchangePointer", 3, (guest, argument) => {
    // A pointer is dword-wide in this 32-bit world, so the pointer family is
    // the dword family with pointer-sized operands.
    const previous = unsigned(guest.memory.readMemory(argument[0], 4));
    if (previous === unsigned(argument[2])) guest.memory.writeMemory(argument[0], 4, unsigned(argument[1]));
    return previous;
  });
  define("kernel32.dll", "InterlockedExchangePointer", 2, (guest, argument) => {
    const previous = unsigned(guest.memory.readMemory(argument[0], 4));
    guest.memory.writeMemory(argument[0], 4, unsigned(argument[1]));
    return previous;
  });
  define("kernel32.dll", "InterlockedCompareExchange64", 3, () => {
    // The prior quadword cannot cross the EAX dispatch boundary (EDX:EAX), so
    // the bounded surface refuses instead of handing back half a result.
    throw hleFault("hle_quadword_return_unsupported", "kernel32.dll!InterlockedCompareExchange64 returns a 64-bit prior value the bounded integer probe cannot carry across the EAX dispatch boundary");
  });

  // --- scaled arithmetic and system profile (BPTK-101 breadth) ------------------
  define("kernel32.dll", "MulDiv", 3, (guest, argument) => {
    const denominator = signed32(argument[2]);
    if (denominator === 0) return unsigned(-1);
    const product = BigInt(signed32(argument[0])) * BigInt(signed32(argument[1]));
    const bigDen = BigInt(denominator);
    const sign = (product < 0n) !== (bigDen < 0n) ? -1n : 1n;
    const absProduct = product < 0n ? -product : product;
    const absDen = bigDen < 0n ? -bigDen : bigDen;
    const rounded = sign * ((absProduct * 2n + absDen) / (absDen * 2n));
    if (rounded > 0x7fffffffn || rounded < -0x80000000n) return unsigned(-1);
    return unsigned(Number(rounded));
  });
  define("kernel32.dll", "GetSystemInfo", 1, (guest, argument) => {
    if (argument[0] === 0) throw hleFault("hle_invalid_parameter", "GetSystemInfo requires a destination address", { address: 0 });
    const info = argument[0];
    guest.memory.writeMemory(info, 4, 0); // dwOemId: PROCESSOR_ARCHITECTURE_INTEL, reserved 0
    guest.memory.writeMemory(info + 4, 4, 4096); // dwPageSize
    guest.memory.writeMemory(info + 8, 4, 0x00010000); // lpMinimumApplicationAddress
    guest.memory.writeMemory(info + 12, 4, 0x7ffe0000); // lpMaximumApplicationAddress
    guest.memory.writeMemory(info + 16, 4, 1); // dwActiveProcessorMask (one declared cpu)
    guest.memory.writeMemory(info + 20, 4, 1); // dwNumberOfProcessors
    guest.memory.writeMemory(info + 24, 4, 586); // dwProcessorType PROCESSOR_INTEL_PENTIUM
    guest.memory.writeMemory(info + 28, 4, 65536); // dwAllocationGranularity
    guest.memory.writeMemory(info + 32, 2, 6); // wProcessorLevel
    guest.memory.writeMemory(info + 34, 2, 0); // wProcessorRevision
    return 0;
  });
  define("kernel32.dll", "GetNativeSystemInfo", 1, (guest, argument) => guest.lookupExport("kernel32.dll", "GetSystemInfo").emulate(guest, argument));
  define("kernel32.dll", "GetSystemTime", 1, (guest, argument) => {
    if (argument[0] === 0) throw hleFault("hle_invalid_parameter", "GetSystemTime requires a destination address", { address: 0 });
    guest.writeSystemTime(argument[0], guest.guestSystemTime());
    return 0;
  });
  define("kernel32.dll", "GetLocalTime", 1, (guest, argument) => {
    // The declared time zone bias is UTC, so local time equals system time.
    if (argument[0] === 0) throw hleFault("hle_invalid_parameter", "GetLocalTime requires a destination address", { address: 0 });
    guest.writeSystemTime(argument[0], guest.guestSystemTime());
    return 0;
  });
  define("kernel32.dll", "SetErrorMode", 1, (guest, argument) => {
    const previous = guest.error_mode;
    guest.error_mode = unsigned(argument[0]) & 0x8007;
    return previous;
  });
  define("kernel32.dll", "GetErrorMode", 0, (guest) => guest.error_mode);
  // With no debugger attached these strings have no observable effect; the
  // guest string is bounded-read so a missing terminator still faults.
  define("kernel32.dll", "OutputDebugStringA", 1, (guest, argument) => {
    if (argument[0] !== 0) guest.readAnsiString(argument[0]);
    return 0;
  });
  define("kernel32.dll", "OutputDebugStringW", 1, (guest, argument) => {
    if (argument[0] !== 0) guest.readWideString(argument[0]);
    return 0;
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
  // GetEnvironmentVariable / ExpandEnvironmentStrings (BPTK-101 breadth) over
  // the one environment map. A missing variable is the env-not-found contract;
  // an insufficient buffer returns the required size like the Win32 ABI.
  const getEnvVar = (guest, name, buffer, size, wide) => {
    if (name === null || !guest.environment.has(name)) {
      guest.setLastError(203); // ERROR_ENVVAR_NOT_FOUND
      return 0;
    }
    const value = guest.environment.get(name);
    if (size < value.length + 1) return value.length + 1; // required size including null
    if (buffer !== 0) (wide ? guest.writeWideString : guest.writeAnsiString)(buffer, value, size);
    return value.length;
  };
  define("kernel32.dll", "GetEnvironmentVariableA", 3, (guest, argument) => getEnvVar(guest, guest.readAnsiString(argument[0]), argument[1], argument[2] >>> 0, false));
  define("kernel32.dll", "GetEnvironmentVariableW", 3, (guest, argument) => getEnvVar(guest, guest.readWideString(argument[0]), argument[1], argument[2] >>> 0, true));
  const expandEnv = (guest, text) => {
    let result = "";
    let index = 0;
    while (index < text.length) {
      if (text[index] === "%") {
        const close = text.indexOf("%", index + 1);
        if (close === -1) { result += text.slice(index); break; }
        const name = text.slice(index + 1, close);
        result += guest.environment.has(name) ? guest.environment.get(name) : text.slice(index, close + 1);
        index = close + 1;
      } else {
        result += text[index];
        index += 1;
      }
    }
    return result;
  };
  define("kernel32.dll", "ExpandEnvironmentStringsA", 3, (guest, argument) => {
    const expanded = expandEnv(guest, guest.readAnsiString(argument[0]) ?? "");
    if (argument[2] >>> 0 < expanded.length + 1) return expanded.length + 1;
    if (argument[1] !== 0) guest.writeAnsiString(argument[1], expanded, argument[2] >>> 0);
    return expanded.length + 1;
  });
  define("kernel32.dll", "ExpandEnvironmentStringsW", 3, (guest, argument) => {
    const expanded = expandEnv(guest, guest.readWideString(argument[0]) ?? "");
    if (argument[2] >>> 0 < expanded.length + 1) return expanded.length + 1;
    if (argument[1] !== 0) guest.writeWideString(argument[1], expanded, argument[2] >>> 0);
    return expanded.length + 1;
  });

  // --- virtual drive (BPTK-015 slice): guest-memory files with real open,
  // read, write, seek, truncate, type, and close semantics. The drive is
  // bounded (file count, per-file and total byte) and never reaches host
  // storage; a traversal or UNC path fails closed.
  define("kernel32.dll", "CreateFileW", 7, (guest, argument) => guest.openFile(
    guest.readWideString(argument[0]), argument[1], argument[4], argument[5],
  ));
  define("kernel32.dll", "CreateFile2", 5, (guest, argument) => {
    const extra = unsigned(argument[4]);
    const flags = extra === 0 ? 0 : guest.memory.readMemory(extra + 8, 4);
    return guest.openFile(guest.readWideString(argument[0]), argument[1], argument[3], flags);
  });
  define("kernel32.dll", "ReadFile", 5, (guest, argument) => guest.readFile(argument[0], argument[1], argument[2], argument[3], argument[4] !== 0));
  define("kernel32.dll", "SetFilePointerEx", 5, (guest, argument) => guest.seekFile(argument[0], argument[1], argument[2], argument[3], argument[4]));
  define("kernel32.dll", "SetEndOfFile", 1, (guest, argument) => guest.truncateFile(argument[0]));
  define("kernel32.dll", "FlushFileBuffers", 1, (guest, argument) => {
    const record = guest.handleRecord(argument[0]);
    if (record === undefined || record.kind !== "file") {
      guest.setLastError(record === undefined ? errorValue.invalid_handle : errorValue.access_denied);
      return 0;
    }
    return 1;
  });
  define("kernel32.dll", "CloseHandle", 1, (guest, argument) => guest.closeHandle(argument[0]));
  define("kernel32.dll", "FindFirstFileExA", 6, (guest, argument) => guest.findFirst(argument[0], argument[1], argument[2], argument[3], argument[5]));
  define("kernel32.dll", "FindFirstFileW", 2, (guest, argument) => guest.findFirst(argument[0], 0, argument[1], 0, 0, true));
  define("kernel32.dll", "FindFirstFileExW", 6, (guest, argument) => guest.findFirst(argument[0], argument[1], argument[2], argument[3], argument[5], true));
  define("kernel32.dll", "FindNextFileW", 2, (guest, argument) => guest.findNext(argument[0], argument[1]));
  define("kernel32.dll", "FindNextFileA", 2, (guest, argument) => guest.findNext(argument[0], argument[1]));
  define("kernel32.dll", "GetFileType", 1, (guest, argument) => guest.fileType(argument[0]));
  define("kernel32.dll", "SetStdHandle", 2, (guest, argument) => guest.setStandardHandle(argument[0], argument[1]));
  define("kernel32.dll", "GetConsoleMode", 2, (guest, argument) => {
    // Win32 writes the mode through the second pointer and returns BOOL.
    // A one-argument stdcall pop left the pointer on the stack so a later
    // RET fetched it as code (NX stack).
    const mode = guest.consoleMode(argument[0]);
    if (mode === 0) return 0;
    if (argument[1] === 0) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    guest.memory.writeMemory(argument[1], 4, mode);
    return 1;
  });
  define("kernel32.dll", "GetConsoleCP", 0, () => consoleCodePage);
  define("kernel32.dll", "SetConsoleCtrlHandler", 2, (guest, argument) => guest.setConsoleCtrlHandler(argument[0], argument[1] !== 0));
  define("kernel32.dll", "ReadConsoleW", 5, (guest, argument) => guest.readConsole(argument[0]));

  // --- registry (advapi32, BPTK-015 slice): one in-memory hive under the
  // real predefined root handle, with bounded key and value count.
  define("advapi32.dll", "RegOpenKeyExW", 5, (guest, argument) => guest.registryOpen(argument[0], guest.readWideString(argument[1]), argument[4], false));
  define("advapi32.dll", "RegOpenKeyA", 3, (guest, argument) => guest.registryOpen(argument[0], guest.readAnsiString(argument[1]), argument[2], false));
  define("advapi32.dll", "RegCreateKeyA", 3, (guest, argument) => guest.registryOpen(argument[0], guest.readAnsiString(argument[1]), argument[2], true));
  define("advapi32.dll", "RegQueryValueExA", 6, (guest, argument) => guest.registryQuery(argument[0], guest.readAnsiString(argument[1]), argument[3], argument[4], argument[5]));
  define("advapi32.dll", "RegSetValueExA", 6, (guest, argument) => guest.registrySet(argument[0], guest.readAnsiString(argument[1]), argument[3], argument[4], argument[5]));
  define("advapi32.dll", "RegCloseKey", 1, (guest, argument) => guest.registryClose(argument[0]));
  // registry breadth and fidelity (BPTK-098): the wide siblings, create with
  // disposition, and the delete/flush surface, all over the one in-memory hive.
  define("advapi32.dll", "RegOpenKeyExA", 5, (guest, argument) => guest.registryOpen(argument[0], guest.readAnsiString(argument[1]), argument[4], false));
  define("advapi32.dll", "RegCreateKeyExW", 9, (guest, argument) => guest.registryCreate(argument[0], guest.readWideString(argument[1]), argument[7], argument[8]));
  define("advapi32.dll", "RegCreateKeyExA", 9, (guest, argument) => guest.registryCreate(argument[0], guest.readAnsiString(argument[1]), argument[7], argument[8]));
  define("advapi32.dll", "RegQueryValueExW", 6, (guest, argument) => guest.registryQuery(argument[0], guest.readWideString(argument[1]), argument[3], argument[4], argument[5]));
  define("advapi32.dll", "RegSetValueExW", 6, (guest, argument) => guest.registrySet(argument[0], guest.readWideString(argument[1]), argument[3], argument[4], argument[5]));
  define("advapi32.dll", "RegDeleteValueA", 2, (guest, argument) => guest.registryDeleteValue(argument[0], guest.readAnsiString(argument[1])));
  define("advapi32.dll", "RegDeleteValueW", 2, (guest, argument) => guest.registryDeleteValue(argument[0], guest.readWideString(argument[1])));
  define("advapi32.dll", "RegDeleteKeyA", 2, (guest, argument) => guest.registryDeleteKey(argument[0], guest.readAnsiString(argument[1])));
  define("advapi32.dll", "RegDeleteKeyW", 2, (guest, argument) => guest.registryDeleteKey(argument[0], guest.readWideString(argument[1])));
  define("advapi32.dll", "RegFlushKey", 1, (guest, argument) => guest.registryFlush(argument[0]));

  // --- locale, codepage, and Unicode conversion (BPTK-103 slice) ----------------------
  define("kernel32.dll", "GetACP", 0, () => 1252);
  define("kernel32.dll", "GetOEMCP", 0, () => 1252);
  define("kernel32.dll", "IsValidCodePage", 1, (guest, argument) => supportedCodePage.has(argument[0]) ? 1 : 0);
  define("kernel32.dll", "GetCPInfo", 2, (guest, argument) => {
    const [codePage, infoPointer] = argument;
    const resolved = resolveCodePage(codePage);
    if (!supportedCodePage.has(resolved)) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    guest.memory.writeBlock(infoPointer, Buffer.alloc(20));
    guest.memory.writeMemory(infoPointer, 4, resolved === 65001 ? 4 : 1);
    guest.memory.writeMemory(infoPointer + 4, 1, 0x3f);
    return 1;
  });
  define("kernel32.dll", "GetUserDefaultLCID", 0, () => localeId);
  define("kernel32.dll", "GetLocaleInfoW", 4, (guest, argument) => {
    const [, type, buffer, size] = argument;
    const name = localeNameTable.get(type);
    if (name === undefined) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const written = guest.writeWideString(buffer, name, Math.max(size, 0));
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    return written.length + 1;
  });
  define("kernel32.dll", "CompareStringW", 6, (guest, argument) => {
    const [, flags, first, firstCount, second, secondCount] = argument;
    if (flags & ~0x1) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const read = (address, count) => {
      const text = count === 0xffffffff ? guest.readWideString(address) : guest.memory.readBlock(address, count * 2).toString("utf16le");
      return text.slice(0, count === 0xffffffff ? undefined : count);
    };
    const left = read(first, firstCount | 0);
    const right = read(second, secondCount | 0);
    const equal = (flags & 0x1) !== 0 ? left.toLowerCase() === right.toLowerCase() : left === right;
    return equal ? 2 : left < right ? 1 : 3;
  });
  define("kernel32.dll", "LCMapStringW", 6, (guest, argument) => {
    const [, flags, source, sourceCount, destination, destinationCount] = argument;
    if (flags & ~0x300 || flags === 0) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    return lcMapString(guest, flags, source, sourceCount, destination, destinationCount);
  });
  define("kernel32.dll", "LCMapStringEx", 9, (guest, argument) => {
    const flags = argument[1];
    if ((flags & 0x300) === 0 || (flags & 0x300) === 0x300) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    return lcMapString(guest, flags, argument[2], argument[3], argument[4], argument[5]);
  });
  define("kernel32.dll", "LocaleNameToLCID", 2, (guest, argument) => {
    if (argument[0] === 0) return 0x0409;
    const lcid = localeNameToLcid(guest.readWideString(argument[0]));
    if (lcid === 0) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    return lcid;
  });
  define("kernel32.dll", "IsValidLocaleName", 1, (guest, argument) => {
    if (argument[0] === 0) return 0;
    return localeNameToLcid(guest.readWideString(argument[0])) !== 0 ? 1 : 0;
  });
  define("kernel32.dll", "GetUserDefaultLocaleName", 2, (guest, argument) => writeLocaleName(guest, argument[0], argument[1], "en-US"));
  define("kernel32.dll", "LCIDToLocaleName", 4, (guest, argument) => {
    const name = lcidToLocaleName(argument[0]);
    if (name === null) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    return writeLocaleName(guest, argument[1], argument[2], name);
  });
  define("kernel32.dll", "CompareStringEx", 9, (guest, argument) => {
    const compare = guest.lookupExport("kernel32.dll", "CompareStringW");
    return compare.emulate(guest, [localeId, argument[1] & 0x1, argument[2], argument[3], argument[4], argument[5]]);
  });
  define("kernel32.dll", "GetDateFormatEx", 7, (guest, argument) => {
    const row = guest.lookupExport("kernel32.dll", "GetDateFormatW");
    return row.emulate(guest, [localeId, argument[1], argument[2], argument[3], argument[4], argument[5]]);
  });
  define("kernel32.dll", "GetTimeFormatEx", 7, (guest, argument) => {
    const row = guest.lookupExport("kernel32.dll", "GetTimeFormatW");
    return row.emulate(guest, [localeId, argument[1], argument[2], argument[3], argument[4], argument[5]]);
  });
  define("kernel32.dll", "AppPolicyGetProcessTerminationMethod", 2, (guest, argument) => {
    if (argument[1] !== 0) guest.memory.writeMemory(argument[1], 4, 1);
    return 0;
  });
  define("kernel32.dll", "AppPolicyGetShowDeveloperDiagnostic", 2, (guest, argument) => {
    if (argument[1] !== 0) guest.memory.writeMemory(argument[1], 4, 0);
    return 0;
  });
  define("kernel32.dll", "AppPolicyGetThreadInitializationType", 2, (guest, argument) => {
    if (argument[1] !== 0) guest.memory.writeMemory(argument[1], 4, 0);
    return 0;
  });
  define("kernel32.dll", "AppPolicyGetWindowingModel", 2, (guest, argument) => {
    if (argument[1] !== 0) guest.memory.writeMemory(argument[1], 4, 1);
    return 0;
  });
  define("kernel32.dll", "GetStringTypeW", 4, (guest, argument) => {
    const [infoType, source, sourceCount, typePointer] = argument;
    if (infoType !== 1) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const text = guest.memory.readBlock(source, sourceCount * 2).toString("utf16le");
    for (let index = 0; index < sourceCount; index += 1) {
      const ch = text[index];
      let flags = 0;
      if (/[A-Z]/.test(ch)) flags |= 0x1 | 0x100;
      else if (/[a-z]/.test(ch)) flags |= 0x2 | 0x100;
      if (/[0-9]/.test(ch)) flags |= 0x4;
      if (/\s/.test(ch)) flags |= 0x40;
      if (/[!-/:-@\[-`{-~]/.test(ch)) flags |= 0x10;
      guest.memory.writeMemory(typePointer + index * 2, 2, flags);
    }
    return 1;
  });
  define("kernel32.dll", "GetTimeZoneInformation", 1, (guest, argument) => {
    // The declared environment runs at UTC with zero bias; names are filled
    // with the real UTF-16 field and both transition date stay zero.
    guest.memory.writeBlock(argument[0], Buffer.alloc(172));
    guest.memory.writeMemory(argument[0], 4, 0);
    const standardName = Buffer.from("Coordinated Universal Time\0".padEnd(32, "\0"), "utf16le");
    guest.memory.writeBlock(argument[0] + 4, standardName.subarray(0, 64));
    guest.memory.writeMemory(argument[0] + 4 + 64 + 16, 4, 0);
    guest.memory.writeMemory(argument[0] + 4 + 64 + 16 + 4 + 64, 4, 0);
    return 0;
  });
  define("kernel32.dll", "GetDateFormatW", 6, (guest, argument) => {
    const [, flags, datePointer, format, buffer, size] = argument;
    if (flags & ~0x8) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const field = datePointer === 0 ? guest.guestSystemTime() : guest.readSystemTime(datePointer);
    const token = format === 0 ? (flags & 0x8) !== 0 ? "dddd, MMMM d, yyyy" : "M/d/yyyy" : guest.readAnsiString(format);
    const formatted = formatSystemTime(token, field);
    const written = guest.writeWideString(buffer, formatted, Math.max(size, 0));
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    return written.length + 1;
  });
  define("kernel32.dll", "GetTimeFormatW", 6, (guest, argument) => {
    const [, flags, timePointer, format, buffer, size] = argument;
    if (flags & ~0x8) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const field = timePointer === 0 ? guest.guestSystemTime() : guest.readSystemTime(timePointer);
    const token = format === 0 ? "HH:mm:ss" : guest.readAnsiString(format);
    const formatted = formatSystemTime(token, field);
    const written = guest.writeWideString(buffer, formatted, Math.max(size, 0));
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    return written.length + 1;
  });
  define("kernel32.dll", "MultiByteToWideChar", 6, (guest, argument) => {
    const codePage = resolveCodePage(argument[0]);
    // The count parameters are Win32 `int`: a 64-bit stack slot for the 6th
    // argument (cchWideChar) can carry stale high bits, so mask to 32 bits — an
    // unmasked 0x1_00000000 would defeat the destinationCount === 0 query test
    // and drive a write to a NULL destination. The pointers keep full width: on
    // x64 the string can live on the stack above 4 GiB.
    const source = blockAddress(argument[2]);
    const sourceByte = unsigned(argument[3]);
    const destination = blockAddress(argument[4]);
    const destinationCount = unsigned(argument[5]);
    if (!supportedCodePage.has(codePage)) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const data = sourceByte === 0xffffffff ? guest.memory.readBlock(source, guest.readAnsiLength(source)) : guest.memory.readBlock(source, Math.max(sourceByte, 0));
    const { text } = ansiToWide(codePage, data);
    // A counted source (cbMultiByte != -1) does not null-terminate; cchWideChar
    // equal to the character count is enough. writeWideString always appends a
    // NUL and would refuse the exact-fit buffer MSVC canonical uses.
    const counted = sourceByte !== 0xffffffff;
    const needed = text.length + (counted ? 0 : 1);
    if (destinationCount === 0 || destination === 0) return needed;
    if (destinationCount < needed) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    // Counted Win32 does not require a terminator, so dest == character count
    // is enough (msvcp140 canonical). When the caller gives extra room, write
    // a NUL in that spare slot so a later wcslen sees a C string — the old
    // writeWideString behavior CRT locale init depends on.
    const withNul = !counted || destinationCount > text.length;
    guest.memory.writeBlock(destination, Buffer.from(withNul ? `${text}\0` : text, "utf16le"));
    return needed;
  });
  define("kernel32.dll", "WideCharToMultiByte", 8, (guest, argument) => {
    const codePage = resolveCodePage(argument[0]);
    const source = blockAddress(argument[2]);
    const sourceCount = unsigned(argument[3]);
    const destination = blockAddress(argument[4]);
    const destinationByte = unsigned(argument[5]);
    if (!supportedCodePage.has(codePage)) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const text = sourceCount === 0xffffffff ? guest.readWideString(source) : guest.memory.readBlock(source, sourceCount * 2).toString("utf16le").slice(0, sourceCount === 0xffffffff ? undefined : sourceCount);
    const data = wideToAnsi(codePage, text);
    if (destinationByte === 0 || destination === 0) return data.length + (sourceCount === 0xffffffff ? 1 : 0);
    if (destinationByte < data.length) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    if (data.length > 0) guest.memory.writeBlock(destination, data);
    return data.length + (sourceCount === 0xffffffff ? 1 : 0);
  });

  // --- multimedia timer (winmm, BPTK-039 slice): one monotonic time source
  // with a declared period setting and no asynchronous event service.
  define("winmm.dll", "timeGetTime", 0, (guest) => guest.clock.tickCount());
  define("winmm.dll", "timeBeginPeriod", 1, (guest, argument) => {
    if (argument[0] === 0 || argument[0] > 16) {
      guest.setLastError(2);
      return 2;
    }
    guest.timer_period = argument[0];
    return 0;
  });
  define("winmm.dll", "timeEndPeriod", 1, (guest, argument) => (guest.timer_period === argument[0] ? 0 : 2));
  define("winmm.dll", "timeKillEvent", 1, (guest, argument) => (argument[0] === 0 ? 0 : 3));

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

  // --- ws2_32 Winsock lifecycle (BPTK-099) --------------------------------------
  // The offline-by-default instance: the lifecycle, handle table, byte-order,
  // and address helpers are fully served; bind/connect/transfer run through the
  // consent gate and are refused until a consent surface lands, so a guest sees
  // the real ws2_32 access contract rather than a fabricated link.
  const readEndpoint = (guest, address) => {
    const port = (guest.memory.readMemory(address + 2, 1) << 8) | guest.memory.readMemory(address + 3, 1);
    const octet = [0, 1, 2, 3].map((index) => guest.memory.readMemory(address + 4 + index, 1));
    return `${octet.join(".")}:${port}`;
  };
  define("ws2_32.dll", "WSAStartup", 2, (guest, argument) => {
    const result = guest.net.WSAStartup(argument[0] & 0xffff);
    if (result !== wsaError.WSA_OK) return result;
    const data = argument[1];
    if (data !== 0) {
      guest.memory.writeMemory(data + 0, 2, argument[0] & 0xffff); // wVersion
      guest.memory.writeMemory(data + 2, 2, 0x0202); // wHighVersion
      guest.writeAnsiString(data + 4, "BPTK mediated Winsock", 257); // szDescription
      guest.writeAnsiString(data + 261, "Running", 129); // szSystemStatus
      guest.memory.writeMemory(data + 390, 2, netBound.socket_count & 0xffff); // iMaxSockets
      guest.memory.writeMemory(data + 392, 2, 0); // iMaxUdpDg
      guest.memory.writeMemory(data + 394, 4, 0); // lpVendorInfo
    }
    return wsaError.WSA_OK;
  }, { ordinal: 115 });
  define("ws2_32.dll", "WSACleanup", 0, (guest) => guest.net.WSACleanup(), { ordinal: 116 });
  define("ws2_32.dll", "WSAGetLastError", 0, (guest) => guest.net.WSAGetLastError(), { ordinal: 111 });
  define("ws2_32.dll", "socket", 3, (guest, argument) => unsigned(guest.net.socket(argument[0], argument[1], argument[2])), { ordinal: 23 });
  define("ws2_32.dll", "closesocket", 1, (guest, argument) => unsigned(guest.net.closesocket(argument[0])), { ordinal: 3 });
  define("ws2_32.dll", "bind", 3, (guest, argument) => unsigned(guest.net.bind(argument[0], readEndpoint(guest, argument[1]))), { ordinal: 2 });
  define("ws2_32.dll", "connect", 3, (guest, argument) => unsigned(guest.net.connect(argument[0], readEndpoint(guest, argument[1]))), { ordinal: 4 });
  define("ws2_32.dll", "send", 4, (guest, argument) => {
    const buffer = guest.memory.readBlock(argument[1], Math.max(argument[2], 0));
    return unsigned(guest.net.send(argument[0], buffer));
  }, { ordinal: 19 });
  define("ws2_32.dll", "recv", 4, (guest, argument) => {
    const result = guest.net.recv(argument[0]);
    if (result.byte === winsockConstant.SOCKET_ERROR || result.data === null) return unsigned(winsockConstant.SOCKET_ERROR);
    const capped = result.data.subarray(0, Math.max(Math.min(argument[2], result.data.length), 0));
    guest.memory.writeBlock(argument[1], capped);
    return capped.length;
  }, { ordinal: 16 });
  define("ws2_32.dll", "ioctlsocket", 3, (guest, argument) => {
    if (argument[1] !== 0x8004667e) return unsigned(guest.net.ioctlsocket(argument[0], "UNSUPPORTED", 0)); // only FIONBIO
    const value = guest.memory.readMemory(argument[2], 4);
    return unsigned(guest.net.ioctlsocket(argument[0], "FIONBIO", value));
  }, { ordinal: 10 });
  define("ws2_32.dll", "htons", 1, (_guest, argument) => netHtons(argument[0] & 0xffff), { ordinal: 9 });
  define("ws2_32.dll", "ntohs", 1, (_guest, argument) => netHtons(argument[0] & 0xffff), { ordinal: 15 });
  define("ws2_32.dll", "htonl", 1, (_guest, argument) => netHtonl(argument[0]), { ordinal: 8 });
  define("ws2_32.dll", "ntohl", 1, (_guest, argument) => netHtonl(argument[0]), { ordinal: 14 });
  define("ws2_32.dll", "inet_addr", 1, (guest, argument) => inetAddr(guest.readAnsiString(argument[0])), { ordinal: 11 });
  // WSA event objects are kernel events (manual-reset, initially unset).
  // EventSelect records the socket→event mask; the offline guest never
  // signals FD_* bits, so EnumNetworkEvents writes an empty report.
  define("ws2_32.dll", "WSACreateEvent", 0, (guest) => guest.createEvent(true, false, 0));
  define("ws2_32.dll", "WSACloseEvent", 1, (guest, argument) => guest.closeHandle(argument[0]));
  define("ws2_32.dll", "WSASetEvent", 1, (guest, argument) => guest.signalEvent(argument[0], true));
  define("ws2_32.dll", "WSAResetEvent", 1, (guest, argument) => guest.signalEvent(argument[0], false));
  define("ws2_32.dll", "WSAWaitForMultipleEvents", 5, (guest, argument) => guest.waitForMultiple(argument[0], argument[1], argument[2] !== 0, argument[3]));
  define("ws2_32.dll", "WSAEventSelect", 3, (guest, argument) => {
    const socket = unsigned(argument[0]);
    const event = unsigned(argument[1]);
    const mask = argument[2] | 0;
    if (!guest.net.hasSocket(socket)) {
      guest.net.WSASetLastError(wsaError.WSAENOTSOCK);
      guest.setLastError(wsaError.WSAENOTSOCK);
      return unsigned(winsockConstant.SOCKET_ERROR);
    }
    if (event !== 0 && guest.waitableRecord(event) === null) {
      guest.net.WSASetLastError(wsaError.WSAEINVAL);
      guest.setLastError(wsaError.WSAEINVAL);
      return unsigned(winsockConstant.SOCKET_ERROR);
    }
    if (event === 0 || mask === 0) guest.wsa_event_select.delete(socket);
    else guest.wsa_event_select.set(socket, { event, mask });
    guest.net.WSASetLastError(wsaError.WSA_OK);
    return 0;
  });
  define("ws2_32.dll", "WSAEnumNetworkEvents", 3, (guest, argument) => {
    const socket = unsigned(argument[0]);
    const event = unsigned(argument[1]);
    const out = unsigned(argument[2]);
    if (!guest.net.hasSocket(socket)) {
      guest.net.WSASetLastError(wsaError.WSAENOTSOCK);
      guest.setLastError(wsaError.WSAENOTSOCK);
      return unsigned(winsockConstant.SOCKET_ERROR);
    }
    if (out !== 0) guest.memory.writeBlock(out, Buffer.alloc(44));
    if (event !== 0) guest.signalEvent(event, false);
    guest.net.WSASetLastError(wsaError.WSA_OK);
    return 0;
  });

  // --- virtual drive geometry and optical volume (BPTK-102) ---------------------
  // One declared fixed volume and one read-only optical volume. The type,
  // label, serial, and capacity are host-neutral constants; the drive letter is
  // read from the guest path and mapped to the declared profile.
  const driveFor = (path) => {
    if (typeof path !== "string" || path.length < 2 || path[1] !== ":") return null;
    const key = path[0].toLowerCase();
    return driveProfile[key] ?? null;
  };
  const writeQuad = (guest, address, value) => {
    if (address === 0) return;
    const big = BigInt(value);
    guest.memory.writeMemory(address, 4, Number(big & 0xffffffffn));
    guest.memory.writeMemory(address + 4, 4, Number(big >> 32n & 0xffffffffn));
  };
  define("kernel32.dll", "GetLogicalDrives", 0, () => (1 << 2) | (1 << 3)); // C: and D:
  define("kernel32.dll", "GetDriveTypeA", 1, (guest, argument) => {
    const drive = driveFor(guest.readAnsiString(argument[0]) ?? hleProfile.guest_root);
    return drive === null ? 1 : drive.type; // DRIVE_NO_ROOT_DIR when unknown
  });
  define("kernel32.dll", "GetDriveTypeW", 1, (guest, argument) => {
    const drive = driveFor(guest.readWideString(argument[0]) ?? hleProfile.guest_root);
    return drive === null ? 1 : drive.type;
  });
  define("kernel32.dll", "GetVolumeInformationW", 8, (guest, argument) => {
    const drive = driveFor(guest.readWideString(argument[0]) ?? "C:\\") ?? driveProfile.c;
    if (argument[1] !== 0) guest.writeWideString(argument[1], drive.label, Math.max(argument[2], 0));
    if (argument[3] !== 0) guest.memory.writeMemory(argument[3], 4, drive.serial);
    if (argument[4] !== 0) guest.memory.writeMemory(argument[4], 4, 255); // lpMaximumComponentLength
    if (argument[5] !== 0) guest.memory.writeMemory(argument[5], 4, drive.type === 5 ? 0x00080000 : 0x00000003); // FS flags (read-only for CDFS)
    if (argument[6] !== 0) guest.writeWideString(argument[6], drive.file_system, Math.max(argument[7], 0));
    return 1;
  });
  define("kernel32.dll", "GetVolumeInformationA", 8, (guest, argument) => {
    const drive = driveFor(guest.readAnsiString(argument[0]) ?? "C:\\") ?? driveProfile.c;
    if (argument[1] !== 0) guest.writeAnsiString(argument[1], drive.label, Math.max(argument[2], 0));
    if (argument[3] !== 0) guest.memory.writeMemory(argument[3], 4, drive.serial);
    if (argument[4] !== 0) guest.memory.writeMemory(argument[4], 4, 255);
    if (argument[5] !== 0) guest.memory.writeMemory(argument[5], 4, drive.type === 5 ? 0x00080000 : 0x00000003);
    if (argument[6] !== 0) guest.writeAnsiString(argument[6], drive.file_system, Math.max(argument[7], 0));
    return 1;
  });
  define("kernel32.dll", "GetDiskFreeSpaceExA", 4, (guest, argument) => {
    const drive = driveFor(guest.readAnsiString(argument[0]) ?? "C:\\") ?? driveProfile.c;
    writeQuad(guest, argument[1], drive.free_byte); // lpFreeBytesAvailableToCaller
    writeQuad(guest, argument[2], drive.total_byte); // lpTotalNumberOfBytes
    writeQuad(guest, argument[3], drive.free_byte); // lpTotalNumberOfFreeBytes
    return 1;
  });
  define("kernel32.dll", "GetDiskFreeSpaceExW", 4, (guest, argument) => {
    const drive = driveFor(guest.readWideString(argument[0]) ?? "C:\\") ?? driveProfile.c;
    writeQuad(guest, argument[1], drive.free_byte);
    writeQuad(guest, argument[2], drive.total_byte);
    writeQuad(guest, argument[3], drive.free_byte);
    return 1;
  });
  define("kernel32.dll", "GetDiskFreeSpaceA", 5, (guest, argument) => {
    const drive = driveFor(guest.readAnsiString(argument[0]) ?? "C:\\") ?? driveProfile.c;
    const clusterByte = drive.bytes_per_sector * drive.sectors_per_cluster;
    if (argument[1] !== 0) guest.memory.writeMemory(argument[1], 4, drive.sectors_per_cluster);
    if (argument[2] !== 0) guest.memory.writeMemory(argument[2], 4, drive.bytes_per_sector);
    if (argument[3] !== 0) guest.memory.writeMemory(argument[3], 4, Math.floor(drive.free_byte / clusterByte));
    if (argument[4] !== 0) guest.memory.writeMemory(argument[4], 4, Math.floor(drive.total_byte / clusterByte));
    return 1;
  });

  // --- XInput gamepad (BPTK-097) ------------------------------------------------
  // The controller state is injected by the browser Gamepad bridge; every slot
  // is disconnected by default, so XInput reports ERROR_DEVICE_NOT_CONNECTED
  // rather than a fabricated pad. Registered under the common xinput1_3.dll.
  define("xinput1_3.dll", "XInputGetState", 2, (guest, argument) => {
    const result = guest.gamepad.getState(argument[0]);
    if (!result.connected) return xinputError.ERROR_DEVICE_NOT_CONNECTED;
    const base = argument[1];
    const s = result.state;
    guest.memory.writeMemory(base + 0, 4, result.packet_number);
    guest.memory.writeMemory(base + 4, 2, s.buttons & 0xffff);
    guest.memory.writeMemory(base + 6, 1, s.left_trigger & 0xff);
    guest.memory.writeMemory(base + 7, 1, s.right_trigger & 0xff);
    guest.memory.writeMemory(base + 8, 2, s.thumb_lx & 0xffff);
    guest.memory.writeMemory(base + 10, 2, s.thumb_ly & 0xffff);
    guest.memory.writeMemory(base + 12, 2, s.thumb_rx & 0xffff);
    guest.memory.writeMemory(base + 14, 2, s.thumb_ry & 0xffff);
    return xinputError.ERROR_SUCCESS;
  });
  define("xinput1_3.dll", "XInputSetState", 2, (guest, argument) => {
    const left = guest.memory.readMemory(argument[1], 2);
    const right = guest.memory.readMemory(argument[1] + 2, 2);
    return guest.gamepad.setVibration(argument[0], left, right) ? xinputError.ERROR_SUCCESS : xinputError.ERROR_DEVICE_NOT_CONNECTED;
  });
  define("xinput1_3.dll", "XInputGetCapabilities", 3, (guest, argument) => {
    const caps = guest.gamepad.getCapabilities(argument[0]);
    if (caps === null) return xinputError.ERROR_DEVICE_NOT_CONNECTED;
    const base = argument[2];
    guest.memory.writeMemory(base + 0, 1, caps.type & 0xff);
    guest.memory.writeMemory(base + 1, 1, caps.subtype & 0xff);
    guest.memory.writeMemory(base + 2, 2, 0); // Flags
    guest.memory.writeMemory(base + 4, 2, caps.buttons & 0xffff); // Gamepad.wButtons supported mask
    return xinputError.ERROR_SUCCESS;
  });
  define("xinput1_3.dll", "XInputEnable", 1, () => 0);

  // --- Plink import-surface widening (BPTK-146) -----------------------------
  // The ANSI file surface, the kernel objects, and the honest refusals the
  // Plink (win32) startup path reaches. The ANSI rows share the wide siblings'
  // bounded state; the process, thread, serial-port, and named-pipe rows serve
  // the confined probe's honest refusal and name the reason in the last error.
  define("kernel32.dll", "CreateFileA", 7, (guest, argument) => guest.openFile(guest.readAnsiString(argument[0]), argument[1], argument[4], argument[5]));
  define("kernel32.dll", "DeleteFileA", 1, (guest, argument) => guest.deleteFile(guest.readAnsiString(argument[0])));
  define("kernel32.dll", "DeleteFileW", 1, (guest, argument) => guest.deleteFile(guest.readWideString(argument[0])));
  define("kernel32.dll", "RemoveDirectoryW", 1, (guest, argument) => guest.removeDirectory(guest.readWideString(argument[0])));
  define("kernel32.dll", "RemoveDirectoryA", 1, (guest, argument) => guest.removeDirectory(guest.readAnsiString(argument[0])));
  define("kernel32.dll", "FileTimeToSystemTime", 2, (guest, argument) => guest.fileTimeToSystemTime(argument[0], argument[1]));
  define("kernel32.dll", "SystemTimeToFileTime", 2, (guest, argument) => guest.systemTimeToFileTime(argument[0], argument[1]));
  define("kernel32.dll", "SystemTimeToTzSpecificLocalTime", 3, (guest, argument) => guest.copySystemTime(argument[1], argument[2]));
  define("kernel32.dll", "FindFirstFileA", 2, (guest, argument) => guest.findFirst(argument[0], 0, argument[1], 0, 0));
  define("kernel32.dll", "FindClose", 1, (guest, argument) => guest.closeHandle(argument[0]));
  define("kernel32.dll", "GetFileAttributesExA", 3, (guest, argument) => guest.fileAttributesEx(guest.readAnsiString(argument[0]), argument[1], argument[2]));
  define("kernel32.dll", "GetFileAttributesExW", 3, (guest, argument) => guest.fileAttributesEx(guest.readWideString(argument[0]), argument[1], argument[2]));
  define("kernel32.dll", "LoadLibraryExA", 3, (guest, argument) => guest.loadLibrary(guest.readAnsiString(argument[0]), argument[2]));
  define("kernel32.dll", "CreateEventA", 4, (guest, argument) => guest.createEvent(argument[1] !== 0, argument[2] !== 0, argument[3], false));
  define("kernel32.dll", "CreateMutexA", 3, (guest, argument) => guest.createMutex(argument[1] !== 0, argument[2], false));
  define("kernel32.dll", "ReleaseMutex", 1, (guest, argument) => guest.releaseMutex(argument[0]));
  define("kernel32.dll", "CreateFileMappingA", 6, (guest, argument) => guest.createFileMapping(argument[0], argument[4], argument[5], false));
  define("kernel32.dll", "MapViewOfFile", 5, (guest, argument) => guest.mapViewOfFile(argument[0], argument[4]));
  define("kernel32.dll", "UnmapViewOfFile", 1, (guest, argument) => guest.unmapViewOfFile(argument[0]));
  define("kernel32.dll", "CreatePipe", 4, (guest, argument) => guest.createPipe(argument[0], argument[1], argument[3]));
  define("kernel32.dll", "GetWindowsDirectoryA", 2, (guest, argument) => {
    const directory = hleProfile.system_directory.replace(/\\System32$/i, "");
    const written = guest.writeAnsiString(argument[0], directory, argument[1] >>> 0);
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return directory.length + 1;
    }
    return directory.length;
  });
  define("kernel32.dll", "GlobalMemoryStatus", 1, (guest, argument) => {
    // MEMORYSTATUS (32 byte) over the declared, host-neutral memory profile.
    const base = argument[0];
    guest.memory.writeMemory(base, 4, 32); // dwLength
    guest.memory.writeMemory(base + 4, 4, 25); // dwMemoryLoad (percent)
    guest.memory.writeMemory(base + 8, 4, 0x80000000); // dwTotalPhys (2 GiB)
    guest.memory.writeMemory(base + 12, 4, 0x40000000); // dwAvailPhys (1 GiB)
    guest.memory.writeMemory(base + 16, 4, 0xc0000000); // dwTotalPageFile (3 GiB)
    guest.memory.writeMemory(base + 20, 4, 0x60000000); // dwAvailPageFile
    guest.memory.writeMemory(base + 24, 4, 0x7fff0000); // dwTotalVirtual (~2 GiB)
    guest.memory.writeMemory(base + 28, 4, 0x7ff00000); // dwAvailVirtual
    return 0;
  });
  define("kernel32.dll", "GetProcessTimes", 5, (guest, argument) => guest.processTimes(argument[0], argument[1], argument[2], argument[3], argument[4]));
  define("kernel32.dll", "LocalAlloc", 2, (guest, argument) => {
    const flag = (argument[0] & 0x40) !== 0 ? heapFlag.zero_memory : 0; // LMEM_ZEROINIT
    return guest.heapAllocate(guest.defaultHeapHandle(), flag, Math.max(argument[1], 1));
  });
  define("kernel32.dll", "LocalFree", 1, (guest, argument) => {
    if (argument[0] === 0) return 0;
    return guest.heapFree(guest.defaultHeapHandle(), 0, argument[0]) === 1 ? 0 : argument[0];
  });
  define("kernel32.dll", "LocalFileTimeToFileTime", 2, (guest, argument) => {
    // The declared time zone bias is UTC, so the local and system file time are
    // the same 64-bit value.
    if (argument[0] === 0 || argument[1] === 0) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    guest.memory.writeBlock(argument[1], guest.memory.readBlock(argument[0], 8));
    return 1;
  });
  define("kernel32.dll", "SetConsoleMode", 2, (guest, argument) => guest.setConsoleMode(argument[0], argument[1]));
  define("kernel32.dll", "SetHandleInformation", 3, (guest, argument) => guest.setHandleInformation(argument[0], argument[1], argument[2]));
  define("kernel32.dll", "FormatMessageA", 7, (guest, argument) => {
    const flag = unsigned(argument[0]);
    if ((flag & 0x00000800) !== 0) { // FORMAT_MESSAGE_FROM_HMODULE — no message module is served
      guest.setLastError(errorValue.mod_not_found);
      return 0;
    }
    let text;
    if ((flag & 0x00000400) !== 0) text = guest.readAnsiString(argument[1]) ?? ""; // FROM_STRING
    else text = formatSystemMessage(argument[2]); // FROM_SYSTEM (or default)
    if ((flag & 0x00000100) !== 0) { // ALLOCATE_BUFFER: lpBuffer is a char**
      const address = guest.heapAllocate(guest.defaultHeapHandle(), 0, text.length + 1);
      if (address === 0) {
        guest.setLastError(errorValue.not_enough_memory);
        return 0;
      }
      guest.writeAnsiString(address, text, text.length + 1);
      guest.memory.writeMemory(argument[4], 4, address);
      return text.length;
    }
    const written = guest.writeAnsiString(argument[4], text.slice(0, Math.max(argument[5] - 1, 0)), argument[5] >>> 0);
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    return written.length;
  });
  define("kernel32.dll", "GetOverlappedResult", 4, (guest, argument) => {
    // Every served file operation is synchronous, so no operation is ever
    // pending; an overlapped handle the probe never issued is not valid.
    const record = guest.handleRecord(argument[0]);
    if (record === undefined) {
      guest.setLastError(errorValue.invalid_handle);
      return 0;
    }
    if (argument[2] !== 0) guest.memory.writeMemory(argument[2], 4, 0);
    return 1;
  });
  define("kernel32.dll", "UnhandledExceptionFilter", 1, () => 1); // EXCEPTION_EXECUTE_HANDLER: no debugger is attached
  define("kernel32.dll", "RtlUnwind", 4, (guest, argument) => {
    const targetFrame = unsigned(argument[0]);
    const targetIp = unsigned(argument[1]);
    if (targetFrame !== 0) {
      try {
        guest.seh_thread.unwindTo(targetFrame, null);
      } catch {
        // The host-side chain is empty; the live FS:[0] walk below is the one
        // the guest actually pushed.
      }
    }
    const teb = guest.layout.teb_base;
    if (teb !== undefined) {
      let head = unsigned(guest.memory.readMemory(teb, 4));
      for (let guard = 0; head !== 0 && head !== 0xffffffff && head !== targetFrame && guard < 4096; guard += 1) {
        head = unsigned(guest.memory.readMemory(head, 4));
      }
      guest.memory.writeMemory(teb, 4, targetFrame === 0 ? 0xffffffff : targetFrame);
    }
    // Windows RtlUnwind does not return when TargetIp is set: it restores EAX
    // and continues at that address. C++ catch uses this to leave the throw.
    if (targetIp !== 0) {
      guest.seh_transfer = { eip: targetIp, eax: unsigned(argument[3]) };
    }
    return unsigned(argument[3]);
  });

  // --- secur32 SSPI (offline, no packages) -----------------------------------
  // InitSecurityInterfaceW returns a real SecurityFunctionTableW. The guest
  // has no security package (no schannel, no NTLM), so acquire/query/encrypt
  // refuse with SEC_E_SECPKG_NOT_FOUND. Same posture as ws2_32: the DLL exists,
  // the capability does not.
  const sspiStatus = Object.freeze({
    ok: 0,
    invalid_handle: 0x80090301,
    secpkg_not_found: 0x80090305,
  });
  const sspiRefuse = () => sspiStatus.secpkg_not_found;
  const sspiFree = (guest, argument) => unsigned(argument[0]) === 0 ? sspiStatus.ok : sspiStatus.invalid_handle;
  define("secur32.dll", "InitSecurityInterfaceW", 0, (guest) => hleCrtDataLayout(guest.layout).sspi_table);
  define("secur32.dll", "EnumerateSecurityPackagesW", 2, (guest, argument) => {
    if (unsigned(argument[0]) !== 0) guest.memory.writeMemory(argument[0], 4, 0);
    if (unsigned(argument[1]) !== 0) guest.memory.writeMemory(argument[1], 4, 0);
    return sspiStatus.ok;
  });
  define("secur32.dll", "QueryCredentialsAttributesW", 3, sspiRefuse);
  define("secur32.dll", "AcquireCredentialsHandleW", 9, sspiRefuse);
  define("secur32.dll", "FreeCredentialsHandle", 1, sspiFree);
  define("secur32.dll", "InitializeSecurityContextW", 12, sspiRefuse);
  define("secur32.dll", "AcceptSecurityContext", 9, sspiRefuse);
  define("secur32.dll", "CompleteAuthToken", 2, sspiRefuse);
  define("secur32.dll", "DeleteSecurityContext", 1, sspiFree);
  define("secur32.dll", "ApplyControlToken", 2, sspiRefuse);
  define("secur32.dll", "QueryContextAttributesW", 3, sspiRefuse);
  define("secur32.dll", "ImpersonateSecurityContext", 1, sspiRefuse);
  define("secur32.dll", "RevertSecurityContext", 1, sspiRefuse);
  define("secur32.dll", "MakeSignature", 4, sspiRefuse);
  define("secur32.dll", "VerifySignature", 4, sspiRefuse);
  define("secur32.dll", "FreeContextBuffer", 1, sspiFree);
  define("secur32.dll", "QuerySecurityPackageInfoW", 2, (guest, argument) => {
    if (unsigned(argument[1]) !== 0) guest.memory.writeMemory(argument[1], 4, 0);
    return sspiStatus.secpkg_not_found;
  });
  define("secur32.dll", "ExportSecurityContext", 4, sspiRefuse);
  define("secur32.dll", "ImportSecurityContextW", 4, sspiRefuse);
  define("secur32.dll", "AddCredentialsW", 8, sspiRefuse);
  define("secur32.dll", "QuerySecurityContextToken", 2, sspiRefuse);
  define("secur32.dll", "EncryptMessage", 4, sspiRefuse);
  define("secur32.dll", "DecryptMessage", 4, sspiRefuse);
  define("secur32.dll", "SetContextAttributesW", 4, sspiRefuse);
  define("kernel32.dll", "EnumSystemLocalesW", 2, (guest) => {
    // The enumeration contract calls a guest callback per locale, which the
    // bounded probe cannot re-enter; it refuses honestly rather than skip the
    // callback and report a false success.
    guest.setLastError(120); // ERROR_CALL_NOT_IMPLEMENTED
    return 0;
  });
  define("kernel32.dll", "EnumSystemLocalesEx", 4, (guest) => {
    guest.setLastError(120);
    return 0;
  });
  define("kernel32.dll", "GetSystemTimePreciseAsFileTime", 1, (guest, argument) => guest.lookupExport("kernel32.dll", "GetSystemTimeAsFileTime").emulate(guest, argument));
  define("kernel32.dll", "GetTempPath2W", 2, (guest, argument) => guest.lookupExport("kernel32.dll", "GetTempPathW").emulate(guest, argument));
  define("kernel32.dll", "CreateThread", 6, (guest, argument) => guest.createGuestThread(argument[2], argument[3], argument[4], argument[5]));
  define("kernel32.dll", "CreateProcessA", 10, (guest) => {
    // Process creation is a denied capability in the containment policy.
    guest.setLastError(errorValue.access_denied);
    return 0;
  });
  define("kernel32.dll", "CreateNamedPipeA", 8, (guest) => {
    guest.setLastError(120); // ERROR_CALL_NOT_IMPLEMENTED: no named-pipe namespace is served
    return 0xffffffff;
  });
  define("kernel32.dll", "ConnectNamedPipe", 2, (guest) => {
    guest.setLastError(errorValue.invalid_handle); // no pipe-server handle can exist
    return 0;
  });
  define("kernel32.dll", "WaitNamedPipeA", 2, (guest) => {
    guest.setLastError(errorValue.file_not_found); // the named pipe does not exist
    return 0;
  });

  // --- ripgrep / SuperTux import-surface widening ---------------------------
  // Wide siblings of already-served ANSI rows, the console and path surface a
  // Rust/MSVC console program reaches at CRT startup, the single-thread SRW
  // and condition-variable rows C++ games take before any second thread
  // exists, and the ntdll / userenv / bcryptprimitives names those programs
  // import instead of the kernel32 spelling. Every row is a real emulator or
  // the same honest refusal its ANSI sibling already serves.
  define("kernel32.dll", "CreateFileMappingW", 6, (guest, argument) => guest.createFileMapping(argument[0], argument[4], argument[5], true));
  define("kernel32.dll", "GetSystemDirectoryW", 2, (guest, argument) => guest.writePath(argument[0], argument[1] >>> 0, hleProfile.system_directory, true));
  define("kernel32.dll", "GetWindowsDirectoryW", 2, (guest, argument) => {
    const directory = hleProfile.system_directory.replace(/\\System32$/i, "");
    return guest.writePath(argument[0], argument[1] >>> 0, directory, true);
  });
  define("kernel32.dll", "SetEnvironmentVariableW", 2, (guest, argument) => {
    const name = guest.readWideString(argument[0]);
    if (name === null || name.length === 0 || name.includes("=")) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const value = argument[1] === 0 ? null : guest.readWideString(argument[1]);
    if (guest.environment.size >= hleBound.environment_entry_count && !guest.environment.has(name) && value !== null) {
      guest.setLastError(errorValue.not_enough_memory);
      return 0;
    }
    if (value === null) guest.environment.delete(name);
    else guest.environment.set(name, value);
    return 1;
  });
  define("kernel32.dll", "CreateProcessW", 10, (guest) => {
    guest.setLastError(errorValue.access_denied);
    return 0;
  });
  define("kernel32.dll", "CreateNamedPipeW", 8, (guest) => {
    guest.setLastError(120);
    return 0xffffffff;
  });
  define("kernel32.dll", "GetFileAttributesW", 1, (guest, argument) => guest.fileAttributes(guest.readWideString(argument[0])));
  define("kernel32.dll", "GetFileAttributesA", 1, (guest, argument) => guest.fileAttributes(guest.readAnsiString(argument[0])));
  define("kernel32.dll", "GetTempPathW", 2, (guest, argument) => guest.writeTempPath(argument[1], argument[0] >>> 0));
  define("kernel32.dll", "GetTempPathA", 2, (guest, argument) => guest.writePath(argument[1], argument[0] >>> 0, "C:\\Temp\\", false));
  define("kernel32.dll", "GetFileSizeEx", 2, (guest, argument) => guest.fileSizeEx(argument[0], argument[1]));
  define("kernel32.dll", "FindResourceA", 3, (guest, argument) => guest.findResourceA(argument[0], argument[1], argument[2]));
  define("kernel32.dll", "EnumResourceNamesW", 4, (guest, argument) => guest.enumResourceNamesW(argument[0], argument[1], argument[2], argument[3]));
  define("kernel32.dll", "LoadResource", 2, (guest, argument) => guest.loadResource(argument[0], argument[1]));
  define("kernel32.dll", "LockResource", 1, (guest, argument) => guest.lockResource(argument[0]));
  define("kernel32.dll", "SizeofResource", 2, (guest, argument) => guest.sizeofResource(argument[0], argument[1]));
  define("kernel32.dll", "CreateDirectoryW", 2, (guest, argument) => guest.createDirectory(guest.readWideString(argument[0])));
  define("kernel32.dll", "CreateDirectoryExW", 3, (guest, argument) => guest.createDirectory(guest.readWideString(argument[1])));
  define("kernel32.dll", "CopyFileW", 3, (guest, argument) => guest.copyFile(guest.readWideString(argument[0]), guest.readWideString(argument[1])));
  define("kernel32.dll", "MoveFileExW", 3, (guest, argument) => guest.moveFile(guest.readWideString(argument[0]), guest.readWideString(argument[1]), argument[2]));
  define("kernel32.dll", "SetFileAttributesW", 2, (guest, argument) => guest.setFileAttributes(guest.readWideString(argument[0]), argument[1]));
  define("kernel32.dll", "SetFileTime", 4, (guest, argument) => guest.setFileTime(argument[0]));
  define("kernel32.dll", "GetThreadLocale", 0, () => localeId);
  define("kernel32.dll", "GetLocaleInfoEx", 4, (guest, argument) => {
    const name = guest.lookupExport("kernel32.dll", "GetLocaleInfoW");
    return name.emulate(guest, [localeId, argument[1], argument[2], argument[3]]);
  });
  define("kernel32.dll", "DeviceIoControl", 8, (guest) => {
    guest.setLastError(errorValue.not_supported);
    return 0;
  });
  define("kernel32.dll", "CreateSymbolicLinkW", 3, (guest) => {
    guest.setLastError(errorValue.access_denied);
    return 0;
  });
  define("kernel32.dll", "CreateHardLinkW", 3, (guest) => {
    guest.setLastError(errorValue.access_denied);
    return 0;
  });
  define("kernel32.dll", "PeekNamedPipe", 5, (guest) => {
    guest.setLastError(errorValue.invalid_handle);
    return 0;
  });
  define("kernel32.dll", "WaitNamedPipeW", 2, (guest) => {
    guest.setLastError(errorValue.file_not_found);
    return 0;
  });
  define("kernel32.dll", "DisableThreadLibraryCalls", 1, () => 1);
  define("shell32.dll", "ShellExecuteA", 6, (guest) => {
    guest.setLastError(errorValue.access_denied);
    return 0;
  });
  define("shell32.dll", "ShellExecuteW", 6, (guest) => {
    guest.setLastError(errorValue.access_denied);
    return 0;
  });
  // SHGetFolderPath: a declared virtual profile, never a host folder. Known
  // CSIDL ids write a MAX_PATH guest path; an unknown id is E_INVALIDARG.
  // CSIDL_FLAG_CREATE / DONT_VERIFY are ignored — the path is virtual.
  define("shell32.dll", "SHGetFolderPathW", 5, (guest, argument) => writeSpecialFolderPath(guest, argument[1], argument[4], true));
  define("shell32.dll", "SHGetFolderPathA", 5, (guest, argument) => writeSpecialFolderPath(guest, argument[1], argument[4], false));
  define("dbghelp.dll", "StackWalk64", 9, () => 0);
  define("dbghelp.dll", "SymSetOptions", 1, (guest, argument) => argument[0] >>> 0);
  define("dbghelp.dll", "SymFunctionTableAccess64", 2, () => 0);
  define("dbghelp.dll", "SymGetModuleBase64", 2, () => 0);
  define("dbghelp.dll", "SymGetLineFromAddr64", 4, () => 0);
  define("dbghelp.dll", "SymInitializeW", 3, () => 0);
  define("dbghelp.dll", "SymFromAddr", 4, () => 0);
  define("kernel32.dll", "GetCurrentDirectoryW", 2, (guest, argument) => guest.writePath(argument[1], argument[0] >>> 0, guest.currentDirectoryText(), true));
  define("kernel32.dll", "GetCurrentDirectoryA", 2, (guest, argument) => guest.writePath(argument[1], argument[0] >>> 0, guest.currentDirectoryText(), false));
  define("kernel32.dll", "SetCurrentDirectoryW", 1, (guest, argument) => guest.setCurrentDirectory(guest.readWideString(argument[0])));
  define("kernel32.dll", "SetCurrentDirectoryA", 1, (guest, argument) => guest.setCurrentDirectory(guest.readAnsiString(argument[0])));
  define("kernel32.dll", "GetFullPathNameW", 4, (guest, argument) => guest.fullPathName(guest.readWideString(argument[0]), argument[2], argument[1] >>> 0, argument[3], true));
  define("kernel32.dll", "GetFullPathNameA", 4, (guest, argument) => guest.fullPathName(guest.readAnsiString(argument[0]), argument[2], argument[1] >>> 0, argument[3], false));
  define("kernel32.dll", "FormatMessageW", 7, (guest, argument) => {
    const flag = unsigned(argument[0]);
    if ((flag & 0x00000800) !== 0) {
      guest.setLastError(errorValue.mod_not_found);
      return 0;
    }
    let text;
    if ((flag & 0x00000400) !== 0) text = guest.readWideString(argument[1]) ?? "";
    else text = formatSystemMessage(argument[2]);
    if ((flag & 0x00000100) !== 0) {
      const address = guest.heapAllocate(guest.defaultHeapHandle(), 0, (text.length + 1) * 2);
      if (address === 0) {
        guest.setLastError(errorValue.not_enough_memory);
        return 0;
      }
      guest.writeWideString(address, text, text.length + 1);
      guest.memory.writeMemory(argument[4], 4, address);
      return text.length;
    }
    const written = guest.writeWideString(argument[4], text.slice(0, Math.max(argument[5] - 1, 0)), argument[5] >>> 0);
    if (!written.is_written) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    return written.length;
  });
  define("kernel32.dll", "GetConsoleOutputCP", 0, () => consoleCodePage);
  define("kernel32.dll", "GetConsoleScreenBufferInfo", 2, (guest, argument) => {
    const record = guest.handleRecord(argument[0]);
    if (record === undefined) {
      guest.setLastError(errorValue.invalid_handle);
      return 0;
    }
    guest.memory.writeBlock(argument[1], Buffer.alloc(22));
    guest.memory.writeMemory(argument[1], 2, 80);
    guest.memory.writeMemory(argument[1] + 2, 2, 25);
    guest.memory.writeMemory(argument[1] + 8, 2, guest.console_attribute);
    guest.memory.writeMemory(argument[1] + 14, 2, 79);
    guest.memory.writeMemory(argument[1] + 16, 2, 24);
    guest.memory.writeMemory(argument[1] + 18, 2, 80);
    guest.memory.writeMemory(argument[1] + 20, 2, 25);
    return 1;
  });
  define("kernel32.dll", "SetConsoleTextAttribute", 2, (guest, argument) => {
    const record = guest.handleRecord(argument[0]);
    if (record === undefined) {
      guest.setLastError(errorValue.invalid_handle);
      return 0;
    }
    guest.console_attribute = argument[1] & 0xffff;
    return 1;
  });
  define("kernel32.dll", "GetComputerNameExW", 3, (guest, argument) => {
    const name = "BPTK";
    if (argument[2] === 0) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const needed = name.length + 1;
    const capacity = guest.memory.readMemory(argument[2], 4);
    guest.memory.writeMemory(argument[2], 4, needed);
    if (capacity < needed) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    guest.writeWideString(argument[1], name, capacity);
    return 1;
  });
  define("kernel32.dll", "CompareStringOrdinal", 5, (guest, argument) => {
    const read = (address, count) => {
      const text = count === 0xffffffff ? guest.readWideString(address) : guest.memory.readBlock(address, count * 2).toString("utf16le");
      return count === 0xffffffff ? text : text.slice(0, count);
    };
    const left = read(argument[0], argument[1] | 0);
    const right = read(argument[2], argument[3] | 0);
    const ignoreCase = argument[4] !== 0;
    const a = ignoreCase ? left.toLowerCase() : left;
    const b = ignoreCase ? right.toLowerCase() : right;
    return a === b ? 2 : a < b ? 1 : 3;
  });
  define("kernel32.dll", "SetThreadStackGuarantee", 1, () => 1);
  define("kernel32.dll", "CreateWaitableTimerExW", 4, (guest, argument) => guest.createWaitableTimer((argument[2] & 1) !== 0, argument[1], true));
  define("kernel32.dll", "InitializeProcThreadAttributeList", 4, (guest, argument) => {
    if (argument[3] === 0) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    guest.memory.writeMemory(argument[3], 4, 64);
    if (argument[0] === 0) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    return 1;
  });
  define("kernel32.dll", "UpdateProcThreadAttribute", 7, () => 1);
  define("kernel32.dll", "DeleteProcThreadAttributeList", 1, () => 0);
  define("kernel32.dll", "GetFileInformationByHandle", 2, (guest, argument) => guest.fileInformationByHandle(argument[0], argument[1]));
  define("kernel32.dll", "GetFileInformationByHandleEx", 4, (guest, argument) => {
    const record = guest.handleRecord(argument[0]);
    if (record === undefined || record.kind !== "file") {
      guest.setLastError(errorValue.invalid_handle);
      return 0;
    }
    const klass = argument[1] >>> 0;
    const out = argument[2];
    const sizeByte = argument[3] >>> 0;
    const created = BigInt(hleProfile.file_time_base);
    const attribute = record.object.is_directory === true ? 0x10 : 0x80;
    if (klass === 0) {
      if (sizeByte < 40) {
        guest.setLastError(errorValue.insufficient_buffer);
        return 0;
      }
      guest.memory.writeBlock(out, Buffer.alloc(sizeByte));
      for (const offset of [0, 8, 16, 24]) {
        guest.memory.writeMemory(out + offset, 4, Number(created & 0xffffffffn));
        guest.memory.writeMemory(out + offset + 4, 4, Number(created >> 32n & 0xffffffffn));
      }
      guest.memory.writeMemory(out + 32, 4, attribute);
      return 1;
    }
    if (klass !== 1) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const size = record.object.data.length;
    guest.memory.writeBlock(out, Buffer.alloc(Math.max(sizeByte, 24)));
    guest.memory.writeMemory(out + 8, 4, size & 0xffffffff);
    guest.memory.writeMemory(out + 16, 4, 1);
    return 1;
  });
  define("kernel32.dll", "GetFinalPathNameByHandleW", 4, (guest, argument) => {
    const record = guest.handleRecord(argument[0]);
    if (record === undefined || record.kind !== "file") {
      guest.setLastError(errorValue.invalid_handle);
      return 0;
    }
    return guest.writePath(argument[1], argument[2] >>> 0, record.object.path ?? hleProfile.guest_root, true);
  });
  define("kernel32.dll", "SetFileInformationByHandle", 4, (guest, argument) => {
    const record = guest.handleRecord(argument[0]);
    if (record === undefined || record.kind !== "file") {
      guest.setLastError(errorValue.invalid_handle);
      return 0;
    }
    return 1;
  });
  define("kernel32.dll", "WriteFileEx", 5, (guest, argument) => guest.writeOutput(argument[0], argument[1], argument[2], 0, false));
  define("kernel32.dll", "ReadFileEx", 5, (guest, argument) => guest.readFile(argument[0], argument[1], argument[2], 0, false));
  define("kernel32.dll", "GetExitCodeProcess", 2, (guest, argument) => {
    if (unsigned(argument[0]) !== 0xffffffff) {
      guest.setLastError(errorValue.invalid_handle);
      return 0;
    }
    guest.memory.writeMemory(argument[1], 4, 259);
    return 1;
  });
  define("kernel32.dll", "RtlCaptureContext", 1, (guest, argument) => {
    guest.memory.writeBlock(argument[0], Buffer.alloc(716));
    guest.memory.writeMemory(argument[0], 4, 0x10007);
    return 0;
  });
  define("kernel32.dll", "InitializeSRWLock", 1, (guest, argument) => {
    guest.memory.writeMemory(argument[0], 4, 0);
    return 0;
  });
  define("kernel32.dll", "AcquireSRWLockExclusive", 1, () => 0);
  define("kernel32.dll", "AcquireSRWLockShared", 1, () => 0);
  define("kernel32.dll", "ReleaseSRWLockExclusive", 1, () => 0);
  define("kernel32.dll", "ReleaseSRWLockShared", 1, () => 0);
  define("kernel32.dll", "TryAcquireSRWLockExclusive", 1, () => 1);
  define("kernel32.dll", "TryAcquireSRWLockShared", 1, () => 1);
  define("kernel32.dll", "InitializeConditionVariable", 1, (guest, argument) => {
    guest.memory.writeMemory(argument[0], 4, 0);
    return 0;
  });
  define("kernel32.dll", "WakeConditionVariable", 1, () => 0);
  define("kernel32.dll", "WakeAllConditionVariable", 1, () => 0);
  define("kernel32.dll", "SleepConditionVariableSRW", 4, (guest, argument) => {
    const timeout = unsigned(argument[2]);
    if (timeout === 0xffffffff) throw hleFault("hle_wait_deadlock", "No other thread signals the condition in the single-thread world, so an infinite condition wait cannot complete", { address: unsigned(argument[0]) });
    guest.clock.advanceVirtualMs(timeout);
    guest.setLastError(258);
    return 0;
  });
  define("kernel32.dll", "SleepConditionVariableCS", 3, (guest, argument) => {
    const timeout = unsigned(argument[2]);
    if (timeout === 0xffffffff) throw hleFault("hle_wait_deadlock", "No other thread signals the condition in the single-thread world, so an infinite condition wait cannot complete", { address: unsigned(argument[0]) });
    guest.clock.advanceVirtualMs(timeout);
    guest.setLastError(258);
    return 0;
  });
  define("bcryptprimitives.dll", "ProcessPrng", 2, (guest, argument) => {
    const size = argument[1] >>> 0;
    const block = Buffer.alloc(size);
    let state = (hleProfile.pointer_cookie ^ guest.clock.tickCount()) >>> 0;
    for (let index = 0; index < size; index += 1) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      block[index] = state >>> 24;
    }
    if (size > 0) guest.memory.writeBlock(argument[0], block);
    return 1;
  });
  define("userenv.dll", "GetUserProfileDirectoryW", 3, (guest, argument) => {
    const profile = "C:\\Users\\guest";
    if (argument[2] === 0) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const needed = profile.length + 1;
    const capacity = guest.memory.readMemory(argument[2], 4);
    guest.memory.writeMemory(argument[2], 4, needed);
    if (capacity < needed) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    guest.writeWideString(argument[1], profile, capacity);
    return 1;
  });
  define("ntdll.dll", "RtlNtStatusToDosError", 1, (guest, argument) => {
    const status = unsigned(argument[0]);
    if (status === 0) return 0;
    const table = new Map([
      [0xc0000001, 31],
      [0xc0000005, 998],
      [0xc0000008, 6],
      [0xc0000022, 5],
      [0xc0000034, 2],
      [0xc000003a, 3],
      [0xc000009a, 8],
    ]);
    return table.get(status) ?? (status & 0xffff);
  });
  define("ntdll.dll", "NtReadFile", 9, (guest, argument) => {
    const [fileHandle, eventHandle, , , iosb, buffer, length, offsetPointer] = argument;
    if (eventHandle !== 0) return 0xc000000d;
    if (offsetPointer !== 0) {
      const low = guest.memory.readMemory(offsetPointer, 4);
      const high = guest.memory.readMemory(offsetPointer + 4, 4);
      if (guest.seekFile(fileHandle, low, high, 0, 0) === 0xffffffff) return 0xc0000008;
    }
    const ok = guest.readFile(fileHandle, buffer, length, 0, false);
    if (iosb !== 0) {
      guest.memory.writeMemory(iosb, 4, ok ? 0 : 0xc0000008);
      guest.memory.writeMemory(iosb + 4, 4, ok ? Math.min(length >>> 0, 0xffffffff) : 0);
    }
    return ok ? 0 : 0xc0000008;
  });
  define("ntdll.dll", "NtWriteFile", 9, (guest, argument) => {
    const [fileHandle, eventHandle, , , iosb, buffer, length, offsetPointer] = argument;
    if (eventHandle !== 0) return 0xc000000d;
    if (offsetPointer !== 0) {
      const low = guest.memory.readMemory(offsetPointer, 4);
      const high = guest.memory.readMemory(offsetPointer + 4, 4);
      if (guest.seekFile(fileHandle, low, high, 0, 0) === 0xffffffff) return 0xc0000008;
    }
    const ok = guest.writeOutput(fileHandle, buffer, length, 0, false);
    if (iosb !== 0) {
      guest.memory.writeMemory(iosb, 4, ok ? 0 : 0xc0000008);
      guest.memory.writeMemory(iosb + 4, 4, ok ? Math.min(length >>> 0, 0xffffffff) : 0);
    }
    return ok ? 0 : 0xc0000008;
  });
  const commRefuse = (guest) => {
    // No serial device is mapped, so any handle passed to the comm surface is
    // not a comm port.
    guest.setLastError(errorValue.invalid_handle);
    return 0;
  };
  define("kernel32.dll", "GetCommState", 2, commRefuse);
  define("kernel32.dll", "SetCommState", 2, commRefuse);
  define("kernel32.dll", "SetCommTimeouts", 2, commRefuse);
  define("kernel32.dll", "SetCommBreak", 1, commRefuse);
  define("kernel32.dll", "ClearCommBreak", 1, commRefuse);

  // --- advapi32 SID and security descriptor (BPTK-146) ----------------------
  // Self-contained operations over bounded guest memory: a SID and a security
  // descriptor are byte structures, never a host token.
  define("advapi32.dll", "GetLengthSid", 1, (guest, argument) => guest.sidLength(argument[0]));
  define("advapi32.dll", "CopySid", 3, (guest, argument) => {
    const length = guest.sidLength(argument[2]);
    if ((argument[0] >>> 0) < length) {
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    guest.memory.writeBlock(argument[1], guest.memory.readBlock(argument[2], length));
    return 1;
  });
  define("advapi32.dll", "EqualSid", 2, (guest, argument) => {
    const leftLength = guest.sidLength(argument[0]);
    const rightLength = guest.sidLength(argument[1]);
    if (leftLength !== rightLength) return 0;
    return Buffer.compare(guest.memory.readBlock(argument[0], leftLength), guest.memory.readBlock(argument[1], rightLength)) === 0 ? 1 : 0;
  });
  define("advapi32.dll", "AllocateAndInitializeSid", 11, (guest, argument) => {
    const count = argument[1] & 0xff;
    const subAuthority = [];
    for (let index = 0; index < count && index < 8; index += 1) subAuthority.push(argument[2 + index]);
    const address = guest.allocateSid(argument[0], subAuthority);
    if (address === 0) {
      guest.setLastError(errorValue.not_enough_memory);
      return 0;
    }
    guest.memory.writeMemory(argument[10], 4, address);
    return 1;
  });
  define("advapi32.dll", "GetUserNameA", 2, (guest, argument) => {
    const required = guestUserName.length + 1;
    const capacity = guest.memory.readMemory(argument[1], 4);
    if (capacity < required) {
      guest.memory.writeMemory(argument[1], 4, required);
      guest.setLastError(errorValue.insufficient_buffer);
      return 0;
    }
    guest.writeAnsiString(argument[0], guestUserName, capacity);
    guest.memory.writeMemory(argument[1], 4, required);
    return 1;
  });
  define("advapi32.dll", "InitializeSecurityDescriptor", 2, (guest, argument) => {
    if (unsigned(argument[1]) !== 1) { // SECURITY_DESCRIPTOR_REVISION
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    guest.memory.writeBlock(argument[0], Buffer.alloc(20));
    guest.memory.writeMemory(argument[0], 1, 1); // Revision
    return 1;
  });
  define("advapi32.dll", "SetSecurityDescriptorDacl", 4, (guest, argument) => {
    if (guest.memory.readMemory(argument[0], 1) !== 1) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const control = guest.memory.readMemory(argument[0] + 2, 2);
    const present = argument[1] !== 0;
    const defaulted = argument[3] !== 0;
    // SE_DACL_PRESENT 0x0004, SE_DACL_DEFAULTED 0x0008.
    let next = control & ~0x000c;
    if (present) next |= 0x0004;
    if (present && defaulted) next |= 0x0008;
    guest.memory.writeMemory(argument[0] + 2, 2, next);
    guest.memory.writeMemory(argument[0] + 16, 4, present ? unsigned(argument[2]) : 0); // Dacl pointer
    return 1;
  });
  define("advapi32.dll", "SetSecurityDescriptorOwner", 3, (guest, argument) => {
    if (guest.memory.readMemory(argument[0], 1) !== 1) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const control = guest.memory.readMemory(argument[0] + 2, 2);
    guest.memory.writeMemory(argument[0] + 2, 2, argument[2] !== 0 ? control | 0x0001 : control & ~0x0001); // SE_OWNER_DEFAULTED 0x0001
    guest.memory.writeMemory(argument[0] + 4, 4, unsigned(argument[1])); // Owner pointer
    return 1;
  });

  // --- Universal CRT startup (Win64 CRT-init breadth, BPTK-031) ---------------
  // The x86-64 freeware in the corpus is built against the Universal CRT: the PE
  // entry is mainCRTStartup / WinMainCRTStartup, whose __scrt_common_main_seh
  // walks a fixed startup chain before it calls the guest main/WinMain —
  // configure argv, initialize the environment, set the app type, register the
  // invalid-parameter handler, run the C then C++ initializer tables, then read
  // argc/argv/envp. Each stub below serves its honest bounded contract so the
  // interpreter flows through startup toward main rather than stopping at the
  // first CRT import. The pointer accessors return addresses inside the fixed
  // CRT block (guest.crt), whose cells hold argc=1, argv=[program, NULL], an
  // empty environment, and zeroed errno/mode words. The api-set forwarders and
  // the legacy msvcrt names resolve to the same behavior because a redistributed
  // binary may import either name for the same entry.
  const crtRuntimeLibrary = "api-ms-win-crt-runtime-l1-1-0.dll";
  const crtStdioLibrary = "api-ms-win-crt-stdio-l1-1-0.dll";
  const crtHeapLibrary = "api-ms-win-crt-heap-l1-1-0.dll";
  const crtMathLibrary = "api-ms-win-crt-math-l1-1-0.dll";
  const crtLocaleLibrary = "api-ms-win-crt-locale-l1-1-0.dll";
  // A stub registered under every library name a corpus binary imports it by.
  const defineForEach = (libraryList, symbol, argc, emulate) => {
    for (const library of libraryList) define(library, symbol, argc, emulate);
  };

  // Argument-vector configuration: mode in, zero (success) out. The bounded
  // world exposes exactly one argument (the program path), already staged.
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_configure_narrow_argv", 1, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_configure_wide_argv", 1, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_initialize_narrow_environment", 0, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_initialize_wide_environment", 0, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_get_initial_narrow_environment", 0, (guest) => guest.crt.environArray);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_get_initial_wide_environment", 0, (guest) => guest.crt.wenvironArray);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_get_narrow_winmain_command_line", 0, (guest) => guest.crt.winmainLine);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_get_wide_winmain_command_line", 0, (guest) => guest.crt.winmainLine);

  // App-type and handler registration. _set_app_type/__set_app_type record the
  // console/GUI class; the two handler setters return the previous handler (0).
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_set_app_type", 1, (guest, argument) => { guest.app_type = argument[0] >>> 0; return 0; });
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "__set_app_type", 1, (guest, argument) => { guest.app_type = argument[0] >>> 0; return 0; });
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_set_invalid_parameter_handler", 1, (guest, argument) => {
    const previous = guest.invalid_parameter_handler;
    guest.invalid_parameter_handler = unsigned(argument[0]);
    return previous;
  });
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_get_invalid_parameter_handler", 0, (guest) => guest.invalid_parameter_handler);
  defineForEach([crtRuntimeLibrary, crtMathLibrary], "__setusermatherr", 1, () => 0);
  defineForEach([crtHeapLibrary, "msvcrt.dll"], "_set_new_mode", 1, (guest, argument) => { const previous = guest.new_mode; guest.new_mode = argument[0] >>> 0; return previous; });

  // atexit / onexit registration: the bounded probe records the table pointer
  // and returns success; the destructors would only fire at process teardown,
  // which the bounded run never reaches.
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_crt_atexit", 1, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_crt_at_quick_exit", 1, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_register_thread_local_exe_atexit_callback", 1, (guest, argument) => { guest.thread_local_atexit_dtor = unsigned(argument[0]); return 0; });
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_initialize_onexit_table", 1, () => 0);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_register_onexit_function", 2, () => 0);

  // Pointer accessors: each returns the address of the corresponding CRT cell.
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "__p___argc", 0, (guest) => guest.crt.argcCell);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "__p___argv", 0, (guest) => guest.crt.argvCell);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "__p___wargv", 0, (guest) => guest.crt.wargvCell);
  defineForEach([crtRuntimeLibrary, "api-ms-win-crt-environment-l1-1-0.dll", "msvcrt.dll"], "__p__environ", 0, (guest) => guest.crt.environCell);
  defineForEach([crtRuntimeLibrary, "api-ms-win-crt-environment-l1-1-0.dll", "msvcrt.dll"], "__p__wenviron", 0, (guest) => guest.crt.wenvironCell);
  defineForEach([crtRuntimeLibrary, crtStdioLibrary, "msvcrt.dll"], "__p__commode", 0, (guest) => guest.crt.commodeCell);
  defineForEach([crtRuntimeLibrary, crtStdioLibrary, "msvcrt.dll"], "__p__fmode", 0, (guest) => guest.crt.fmodeCell);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "_errno", 0, (guest) => guest.crt.errnoCell);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "__p__acmdln", 0, (guest) => guest.crt.acmdlnCell);
  defineForEach([crtRuntimeLibrary, "msvcrt.dll"], "__p__wcmdln", 0, (guest) => guest.crt.wcmdlnCell);

  // The file-mode (text/binary) word the stdio startup configures. _set_fmode
  // stores the mode and returns 0 (errno_t success); _get_fmode reads it back
  // through the caller's out pointer. Both mirror the __p__fmode cell.
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "_set_fmode", 1, (guest, argument) => {
    guest.memory.writeMemory(guest.crt.fmodeCell, 4, unsigned(argument[0]));
    return 0;
  });
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "_get_fmode", 1, (guest, argument) => {
    if (argument[0] === 0) return errorValue.invalid_parameter;
    guest.memory.writeMemory(argument[0], 4, guest.memory.readMemory(guest.crt.fmodeCell, 4));
    return 0;
  });

  // Locale query used early by the startup: the bounded world is the invariant
  // "C" locale, so the multibyte maximum is one byte.
  defineForEach([crtLocaleLibrary, "msvcrt.dll"], "___mb_cur_max_func", 0, () => 1);
  // Per-thread locale configuration: the bounded world runs one thread in the
  // invariant "C" locale, so the call records nothing and reports the previous
  // per-thread setting (0 = the global locale is in effect).
  defineForEach([crtLocaleLibrary, "msvcrt.dll"], "_configthreadlocale", 1, () => 0);

  // The VC runtime (vcruntime140.dll) forwards its critical-section helpers to
  // the kernel32 primitives; the bounded world serves them with identical
  // single-thread semantics so the C++ runtime init flows through to main.
  const vcrtLibrary = "vcruntime140.dll";
  define(vcrtLibrary, "__vcrt_InitializeCriticalSectionEx", 3, (guest, argument) => {
    guest.initializeCriticalSection(argument[0], argument[1] & 0x00ffffff);
    return 1;
  });
  define(vcrtLibrary, "__vcrt_EnterCriticalSection", 1, (guest, argument) => { guest.enterCriticalSection(argument[0], true); return 0; });
  define(vcrtLibrary, "__vcrt_LeaveCriticalSection", 1, (guest, argument) => { guest.leaveCriticalSection(argument[0]); return 0; });
  define(vcrtLibrary, "__vcrt_DeleteCriticalSection", 1, (guest, argument) => { guest.deleteCriticalSection(argument[0]); return 0; });
  // The VC runtime telemetry triggers the ucrt entry calls around main. On a
  // real machine with telemetry disabled these are no-ops; the bounded world
  // serves them as the same no-op so the CRT init/return path flows through to
  // the game's own main rather than stalling at the trigger.
  define(vcrtLibrary, "__telemetry_main_invoke_trigger", 1, () => 0);
  define(vcrtLibrary, "__telemetry_main_return_trigger", 1, () => 0);

  // The compiler memory intrinsics the VC runtime and the ucrt string api-set
  // both export. Each performs the real byte operation over guest memory and
  // returns the C contract value, so an initializer that clears or copies a
  // global block does the actual work rather than a faked return.
  const crtStringLibrary = "api-ms-win-crt-string-l1-1-0.dll";
  const crtPrivateLibrary = "api-ms-win-crt-private-l1-1-0.dll";
  // A pointer argument keeps its full width. An i386 guest pointer already fits
  // 32 bits, so this is identity there; an x86-64 guest pointer to the stack or
  // TEB lives above 4 GiB (the interpreter maps the stack at 0x7ff000000000), so
  // truncating it to a dword (unsigned) would fault a legitimate memset/memcpy.
  const blockAddress = (value) => (value < 0 ? value >>> 0 : value);
  const memsetImpl = (guest, argument) => {
    const [dest, value, count] = [blockAddress(argument[0]), argument[1] & 0xff, unsigned(argument[2])];
    if (count > 0) guest.memory.writeBlock(dest, Buffer.alloc(count, value));
    return dest;
  };
  const memcpyImpl = (guest, argument) => {
    const [dest, src, count] = [blockAddress(argument[0]), blockAddress(argument[1]), unsigned(argument[2])];
    if (count > 0) guest.memory.writeBlock(dest, guest.memory.readBlock(src, count));
    return dest;
  };
  const memcmpImpl = (guest, argument) => {
    const [a, b, count] = [blockAddress(argument[0]), blockAddress(argument[1]), unsigned(argument[2])];
    for (let index = 0; index < count; index += 1) {
      const va = guest.memory.readMemory(a + index, 1);
      const vb = guest.memory.readMemory(b + index, 1);
      if (va !== vb) return va < vb ? 0xffffffff : 1; // C memcmp: sign of the first difference
    }
    return 0;
  };
  const memchrImpl = (guest, argument) => {
    const [ptr, value, count] = [blockAddress(argument[0]), argument[1] & 0xff, unsigned(argument[2])];
    for (let index = 0; index < count; index += 1) if (guest.memory.readMemory(ptr + index, 1) === value) return ptr + index;
    return 0;
  };
  defineForEach([vcrtLibrary, crtStringLibrary, crtPrivateLibrary, "msvcrt.dll"], "memset", 3, memsetImpl);
  defineForEach([vcrtLibrary, crtStringLibrary, crtPrivateLibrary, "msvcrt.dll"], "memcpy", 3, memcpyImpl);
  defineForEach([vcrtLibrary, crtStringLibrary, crtPrivateLibrary, "msvcrt.dll"], "memmove", 3, memcpyImpl);
  defineForEach([vcrtLibrary, crtStringLibrary, crtPrivateLibrary, "msvcrt.dll"], "memcmp", 3, memcmpImpl);
  defineForEach([vcrtLibrary, crtStringLibrary, crtPrivateLibrary, "msvcrt.dll"], "memchr", 3, memchrImpl);

  // --- msvcrt.dll C runtime for the i386 CLI corpus (BPTK-010) --------------
  // jq (corpus-010) links the legacy msvcrt.dll C runtime: CRT startup, the
  // heap, the string/mem family, ctype, stdio the tool actually calls, locale,
  // time, and errno. Each stub performs its real bounded work over the HLE
  // arena/heap and virtual FS so the probe executes real behavior toward main.
  // Where a bounded integer probe genuinely cannot serve a contract — an x87
  // double return, a guest comparator callback, a spawned OS thread, or a
  // non-local jmp_buf restore — the stub raises one named structured refusal
  // instead of a silent no-op. These are cdecl: the runtime dispatch reads the
  // declared dword count as the argument frame.
  const msvcrt = "msvcrt.dll";
  const refuseDouble = (symbol) => () => { throw hleFault("hle_x87_double_abi_unsupported", `msvcrt!${symbol} returns an x87 double the bounded integer probe cannot carry across the EAX dispatch boundary`); };
  const refuseCallback = (symbol) => () => { throw hleFault("hle_guest_callback_unsupported", `msvcrt!${symbol} must re-enter guest code for its callback, which the single-pass bounded probe does not provide`); };
  const refuseThread = (symbol) => () => { throw hleFault("hle_thread_unsupported", `msvcrt!${symbol} spawns an OS thread the single-thread bounded probe does not provide`); };
  const refuseJump = (symbol) => () => { throw hleFault("hle_nonlocal_jump_unsupported", `msvcrt!${symbol} restores a saved jmp_buf frame the single-pass bounded probe cannot unwind`); };
  // A byte read at a string pointer keeps the pointer's full width: on x64 the
  // compared string commonly lives on the stack (0x7ff0_00000000 range) or in
  // the image above 4 GiB, so truncating it to a dword (unsigned) would fault a
  // legitimate strcmp/strncmp over a stack buffer. blockAddress is identity for
  // an i386 32-bit pointer and preserves the x64 pointer whole.
  const readByte = (guest, address, index) => guest.memory.readMemory(blockAddress(address) + index, 1);
  const cLower = (code) => (code >= 0x41 && code <= 0x5a ? code + 0x20 : code);

  // Data exports. The IAT must receive the live cell/array address (kind
  // "data"), not a CALL thunk. Calling the row still returns the same
  // address so GetProcAddress-then-call and the conformance table stay honest.
  define(msvcrt, "_iob", 0, (guest) => guest.crtRuntime.iobBase, { kind: "data" });
  define(msvcrt, "_environ", 0, (guest) => guest.crt.environCell, { kind: "data" });
  define(msvcrt, "_tzname", 0, (guest) => guest.crtRuntime.tznameBase, { kind: "data" });
  define(msvcrt, "__mb_cur_max", 0, (guest) => guest.crtRuntime.mbCurMaxCell, { kind: "data" });
  define(msvcrt, "__winitenv", 0, (guest) => guest.crt.wenvironCell, { kind: "data" });

  // CRT startup and teardown.
  define(msvcrt, "__setusermatherr", 1, () => 0);
  define(msvcrt, "__wgetmainargs", 5, (guest, argument) => {
    if (argument[0] !== 0) guest.memory.writeMemory(argument[0], 4, guest.crt.argc);
    if (argument[1] !== 0) guest.memory.writeMemory(argument[1], 4, guest.crt.wargvArray);
    if (argument[2] !== 0) guest.memory.writeMemory(argument[2], 4, guest.crt.wenvironArray);
    return 0;
  });
  define(msvcrt, "__getmainargs", 5, (guest, argument) => {
    if (argument[0] !== 0) guest.memory.writeMemory(argument[0], 4, guest.crt.argc);
    if (argument[1] !== 0) guest.memory.writeMemory(argument[1], 4, guest.crt.argvArray);
    if (argument[2] !== 0) guest.memory.writeMemory(argument[2], 4, guest.crt.environArray);
    return 0;
  });
  define(msvcrt, "_amsg_exit", 1, (guest, argument) => raiseProcessExit(argument[0] === 0 ? 255 : 255));
  define(msvcrt, "_assert", 3, () => raiseProcessExit(3));
  define(msvcrt, "_cexit", 0, () => 0);
  define(msvcrt, "_initterm", 2, () => 0); // The i386 probe walks the table as guest control flow (runtime.mjs).
  define(msvcrt, "_onexit", 1, (guest, argument) => unsigned(argument[0]));
  define(msvcrt, "_lock", 1, () => 0); // single-thread probe: the CRT lock is uncontended
  define(msvcrt, "_unlock", 1, () => 0);
  define(msvcrt, "exit", 1, (guest, argument) => raiseProcessExit(argument[0]));
  define(msvcrt, "abort", 0, () => raiseProcessExit(3));
  define(msvcrt, "raise", 1, () => 0); // no C signal handler fires in the bounded run; SIG_DFL is a no-op here
  define(msvcrt, "signal", 2, () => 0); // returns SIG_DFL (0) as the previous handler
  define(msvcrt, "_beginthreadex", 6, refuseThread("_beginthreadex"));
  define(msvcrt, "_endthreadex", 1, () => 0);
  define(msvcrt, "_setjmp3", 2, () => 0); // setjmp saves and returns 0 on the direct path
  define(msvcrt, "longjmp", 2, refuseJump("longjmp"));

  // Heap. The ucrt heap surface (api-ms-win-crt-heap-l1-1-0.dll) and the legacy
  // msvcrt heap surface share one real process default heap, so malloc/free/
  // calloc/realloc/_msize/_recalloc are the same bytes whichever import a guest
  // links against; the Win64 ucrt CRT init (Dwarf Fortress) reaches the ucrt DLL.
  defineForEach([crtHeapLibrary, msvcrt], "malloc", 1, (guest, argument) => guest.crtMalloc(argument[0]));
  defineForEach([crtHeapLibrary, msvcrt], "calloc", 2, (guest, argument) => guest.crtCalloc(argument[0], argument[1]));
  defineForEach([crtHeapLibrary, msvcrt], "realloc", 2, (guest, argument) => guest.crtRealloc(argument[0], argument[1]));
  defineForEach([crtHeapLibrary, msvcrt], "free", 1, (guest, argument) => guest.crtFree(argument[0]));
  defineForEach([crtHeapLibrary, msvcrt], "_msize", 1, (guest, argument) => guest.crtMsize(argument[0]));
  defineForEach([crtHeapLibrary, msvcrt], "_recalloc", 3, (guest, argument) => guest.crtRecalloc(argument[0], argument[1], argument[2]));
  // _callnewh invokes the registered C++ new-handler when an allocation fails.
  // No new-handler is registered in this bounded process, so it honestly reports
  // "no handler" (0), the signal operator new uses to throw bad_alloc.
  defineForEach([crtHeapLibrary, msvcrt], "_callnewh", 1, () => 0);
  define(msvcrt, "_strdup", 1, (guest, argument) => {
    const text = guest.readAnsiString(argument[0]);
    if (text === null) return 0;
    const address = guest.crtMalloc(text.length + 1);
    if (address === 0) return 0;
    guest.writeAnsiString(address, text, text.length + 1);
    return address;
  });

  // String and memory (memcpy/memmove/memset/memcmp/memchr are served above).
  define(msvcrt, "strlen", 1, (guest, argument) => guest.readAnsiString(argument[0])?.length ?? 0);
  define(msvcrt, "wcslen", 1, (guest, argument) => guest.readWideString(argument[0])?.length ?? 0);
  define(msvcrt, "strcmp", 2, (guest, argument) => {
    let index = 0;
    for (;; index += 1) {
      const a = readByte(guest, argument[0], index);
      const b = readByte(guest, argument[1], index);
      if (a !== b) return a < b ? 0xffffffff : 1;
      if (a === 0) return 0;
    }
  });
  define(msvcrt, "strncmp", 3, (guest, argument) => {
    const count = unsigned(argument[2]);
    for (let index = 0; index < count; index += 1) {
      const a = readByte(guest, argument[0], index);
      const b = readByte(guest, argument[1], index);
      if (a !== b) return a < b ? 0xffffffff : 1;
      if (a === 0) return 0;
    }
    return 0;
  });
  define(msvcrt, "_stricmp", 2, (guest, argument) => {
    for (let index = 0; ; index += 1) {
      const a = cLower(readByte(guest, argument[0], index));
      const b = cLower(readByte(guest, argument[1], index));
      if (a !== b) return a < b ? 0xffffffff : 1;
      if (a === 0) return 0;
    }
  });
  define(msvcrt, "_strnicmp", 3, (guest, argument) => {
    const count = unsigned(argument[2]);
    for (let index = 0; index < count; index += 1) {
      const a = cLower(readByte(guest, argument[0], index));
      const b = cLower(readByte(guest, argument[1], index));
      if (a !== b) return a < b ? 0xffffffff : 1;
      if (a === 0) return 0;
    }
    return 0;
  });
  define(msvcrt, "strcpy", 2, (guest, argument) => {
    // The destination and returned pointer keep full width: on x64 a strcpy
    // target is commonly a stack buffer above 4 GiB.
    const dest = blockAddress(argument[0]);
    const text = guest.readAnsiString(argument[1]) ?? "";
    guest.writeAnsiString(dest, text, text.length + 1);
    return dest;
  });
  define(msvcrt, "strncpy", 3, (guest, argument) => {
    const dest = blockAddress(argument[0]);
    const count = unsigned(argument[2]);
    const text = guest.readAnsiString(argument[1]) ?? "";
    for (let index = 0; index < count; index += 1) {
      guest.memory.writeMemory(dest + index, 1, index < text.length ? text.charCodeAt(index) & 0xff : 0);
    }
    return dest;
  });
  defineForEach([vcrtLibrary, msvcrt], "strchr", 2, (guest, argument) => {
    // blockAddress keeps the full pointer width: on x64 the string may live on
    // the stack or in the image above 4 GiB, and the returned pointer must too.
    const target = argument[1] & 0xff;
    const base = blockAddress(argument[0]);
    for (let index = 0; ; index += 1) {
      const value = guest.memory.readMemory(base + index, 1);
      if (value === target) return base + index;
      if (value === 0) return target === 0 ? base + index : 0;
    }
  });
  defineForEach([vcrtLibrary, msvcrt], "strrchr", 2, (guest, argument) => {
    const target = argument[1] & 0xff;
    const text = guest.readAnsiString(argument[0]) ?? "";
    const base = blockAddress(argument[0]);
    if (target === 0) return base + text.length;
    for (let index = text.length - 1; index >= 0; index -= 1) if ((text.charCodeAt(index) & 0xff) === target) return base + index;
    return 0;
  });
  define(msvcrt, "strspn", 2, (guest, argument) => {
    const accept = guest.readAnsiString(argument[1]) ?? "";
    const text = guest.readAnsiString(argument[0]) ?? "";
    let index = 0;
    while (index < text.length && accept.includes(text[index])) index += 1;
    return index;
  });
  defineForEach([vcrtLibrary, msvcrt], "strstr", 2, (guest, argument) => {
    const hay = guest.readAnsiString(argument[0]) ?? "";
    const needle = guest.readAnsiString(argument[1]) ?? "";
    const at = hay.indexOf(needle);
    return at < 0 ? 0 : blockAddress(argument[0]) + at;
  });
  define(msvcrt, "strerror", 1, (guest, argument) => {
    const message = crtStrerrorText(argument[0] | 0);
    guest.writeAnsiString(guest.crtRuntime.strerrorBuf, message, 64);
    return guest.crtRuntime.strerrorBuf;
  });
  define(msvcrt, "wcstombs", 3, (guest, argument) => {
    const wide = guest.readWideString(argument[1]) ?? "";
    const count = unsigned(argument[2]);
    if (unsigned(argument[0]) === 0) return wide.length;
    let written = 0;
    for (; written < wide.length && written < count; written += 1) {
      guest.memory.writeMemory(unsigned(argument[0]) + written, 1, wide.charCodeAt(written) & 0xff);
    }
    if (written < count) guest.memory.writeMemory(unsigned(argument[0]) + written, 1, 0);
    return written;
  });

  // Multibyte (the "C" single-byte locale). No byte is a multibyte lead or
  // trail byte, so _ismbblead/_ismbbtrail are always false; the untagged forms
  // and the _l locale-tagged forms agree because the "C" locale has no DBCS.
  define(msvcrt, "_ismbblead", 1, () => 0);
  define(msvcrt, "_ismbbtrail", 1, () => 0);

  // ctype (the "C" locale classification). The Universal CRT exports the isX
  // family from api-ms-win-crt-string-l1-1-0.dll and the legacy msvcrt.dll
  // exports the same names; a redistributed binary (Dwarf Fortress imports
  // isspace/isgraph from the api-set) may link either. Each returns the real
  // MSVCRT ctype mask bit for the "C" locale — nonzero iff the class holds —
  // computed from crtCtypeMask, the same 256-entry table the runtime uses. The
  // _l locale-tagged variants carry a trailing _locale_t the "C" locale ignores,
  // so their classification is identical to the untagged form. The single
  // CTYPE_LIBRARY / CASECONV_LIBRARY lists are shared with the conformance census
  // so the served set and the census coverage cannot drift apart.
  for (const [symbol, bit] of Object.entries(CTYPE_CLASSIFIER_BIT)) {
    defineForEach(CTYPE_LIBRARY, symbol, 1, (guest, argument) => crtCtypeMask(argument[0] & 0xff) & bit);
    defineForEach(CTYPE_LIBRARY, `${symbol}_l`, 2, (guest, argument) => crtCtypeMask(argument[0] & 0xff) & bit);
  }
  for (const [symbol, classify] of Object.entries(CTYPE_RANGE)) {
    defineForEach(CTYPE_LIBRARY, symbol, 1, (guest, argument) => classify(argument[0] & 0xff));
    defineForEach(CTYPE_LIBRARY, `${symbol}_l`, 2, (guest, argument) => classify(argument[0] & 0xff));
  }
  // _isctype(c, mask): true iff the byte's C-locale class intersects the mask.
  defineForEach(CTYPE_LIBRARY, "_isctype", 2, (guest, argument) => ((crtCtypeMask(argument[0] & 0xff) & (argument[1] & 0xffff)) !== 0 ? 1 : 0));
  defineForEach(CTYPE_LIBRARY, "_isctype_l", 3, (guest, argument) => ((crtCtypeMask(argument[0] & 0xff) & (argument[1] & 0xffff)) !== 0 ? 1 : 0));
  // toupper/tolower and their non-classifying _toupper/_tolower fast paths, plus
  // the _l locale-tagged variants (the "C" locale ignores the locale argument).
  defineForEach(CASECONV_LIBRARY, "toupper", 1, (guest, argument) => crtToUpper(argument[0] & 0xff));
  defineForEach(CASECONV_LIBRARY, "tolower", 1, (guest, argument) => crtToLower(argument[0] & 0xff));
  defineForEach(CASECONV_LIBRARY, "_toupper", 1, (guest, argument) => crtToUpper(argument[0] & 0xff));
  defineForEach(CASECONV_LIBRARY, "_tolower", 1, (guest, argument) => crtToLower(argument[0] & 0xff));
  defineForEach(CASECONV_LIBRARY, "toupper_l", 2, (guest, argument) => crtToUpper(argument[0] & 0xff));
  defineForEach(CASECONV_LIBRARY, "tolower_l", 2, (guest, argument) => crtToLower(argument[0] & 0xff));
  defineForEach(CASECONV_LIBRARY, "_toupper_l", 2, (guest, argument) => crtToUpper(argument[0] & 0xff));
  defineForEach(CASECONV_LIBRARY, "_tolower_l", 2, (guest, argument) => crtToLower(argument[0] & 0xff));

  // Number parsing and pseudo-random (deterministic LCG, seed 1). atoi/strtol/
  // strtoul/_itoa are exported by the ucrt convert api-set and legacy msvcrt;
  // Dwarf Fortress links them through api-ms-win-crt-convert-l1-1-0.dll. Pointer
  // arguments use blockAddress so an x64 nptr/buffer above 4 GiB keeps its width.
  defineForEach(NUMBER_LIBRARY, "atoi", 1, (guest, argument) => {
    const text = (guest.readAnsiString(blockAddress(argument[0])) ?? "").trimStart();
    const match = text.match(/^[+-]?\d+/);
    return match === null ? 0 : unsigned(Number.parseInt(match[0], 10) | 0);
  });
  // strtol/strtoul(nptr, endptr, base): parse per the C contract — skip leading
  // whitespace, an optional sign, an optional 0x for base 16 / 0 for base 8,
  // then the longest valid digit run; write the end pointer; clamp on overflow.
  const crtStrtol = (signedResult) => (guest, argument) => {
    const start = blockAddress(argument[0]);
    const raw = guest.readAnsiString(start) ?? "";
    let index = 0;
    while (index < raw.length && crtCtypeMask(raw.charCodeAt(index)) & CTYPE_SPACE) index += 1;
    let sign = 1;
    if (raw[index] === "+" || raw[index] === "-") { if (raw[index] === "-") sign = -1; index += 1; }
    let base = unsigned(argument[2]) & 0xffffffff;
    if ((base === 0 || base === 16) && raw[index] === "0" && (raw[index + 1] === "x" || raw[index + 1] === "X")) { base = 16; index += 2; }
    else if (base === 0 && raw[index] === "0") { base = 8; }
    else if (base === 0) { base = 10; }
    const digitValue = (ch) => {
      const code = ch.charCodeAt(0);
      if (code >= 0x30 && code <= 0x39) return code - 0x30;
      if (code >= 0x41 && code <= 0x5a) return code - 0x41 + 10;
      if (code >= 0x61 && code <= 0x7a) return code - 0x61 + 10;
      return 99;
    };
    let value = 0n;
    let consumedDigit = false;
    for (; index < raw.length; index += 1) {
      const d = digitValue(raw[index]);
      if (d >= base) break;
      value = value * BigInt(base) + BigInt(d);
      consumedDigit = true;
    }
    if (blockAddress(argument[1]) !== 0) {
      // endptr points just past the last consumed character (or to nptr when
      // none). Written at the 4-byte width every HLE pointer store uses.
      guest.memory.writeMemory(blockAddress(argument[1]), 4, (start + (consumedDigit ? index : 0)) >>> 0);
    }
    let result = value * BigInt(sign);
    if (signedResult) {
      if (result > 0x7fffffffn) result = 0x7fffffffn;
      else if (result < -0x80000000n) result = -0x80000000n;
      return Number(result & 0xffffffffn) >>> 0;
    }
    if (result < 0n) result = result & 0xffffffffn;
    if (result > 0xffffffffn) result = 0xffffffffn;
    return Number(result & 0xffffffffn) >>> 0;
  };
  defineForEach(NUMBER_LIBRARY, "strtol", 3, crtStrtol(true));
  defineForEach(NUMBER_LIBRARY, "strtoul", 3, crtStrtol(false));
  // _itoa(value, buffer, radix): signed for base 10, unsigned bit pattern
  // otherwise — the real MSVCRT behavior.
  defineForEach(NUMBER_LIBRARY, "_itoa", 3, (guest, argument) => {
    const buffer = blockAddress(argument[1]);
    const radix = unsigned(argument[2]) || 10;
    const text = radix === 10 ? (argument[0] | 0).toString(10) : unsigned(argument[0]).toString(radix);
    guest.writeAnsiString(buffer, text, text.length + 1);
    return buffer;
  });
  defineForEach(NUMBER_LIBRARY, "_ultoa", 3, (guest, argument) => {
    const buffer = blockAddress(argument[1]);
    const radix = unsigned(argument[2]) || 10;
    const text = unsigned(argument[0]).toString(radix);
    guest.writeAnsiString(buffer, text, text.length + 1);
    return buffer;
  });
  defineForEach(RANDOM_LIBRARY, "rand", 0, (guest) => {
    guest.rand_state = (Math.imul(guest.rand_state, 214013) + 2531011) >>> 0;
    return (guest.rand_state >>> 16) & 0x7fff;
  });
  defineForEach(RANDOM_LIBRARY, "srand", 1, (guest, argument) => { guest.rand_state = unsigned(argument[0]); return 0; });
  // rand_s(unsigned* p): the ucrt cryptographic-ish RNG a CRT static initializer
  // seeds a global with. The bounded probe has no OS entropy source, so it draws
  // a full 32-bit value from the same deterministic LCG as rand (advanced twice
  // for the full width) and writes it through the pointer, returning 0 (success).
  defineForEach(RANDOM_LIBRARY, "rand_s", 1, (guest, argument) => {
    const pointer = blockAddress(argument[0]);
    if (pointer === 0) return 22; // EINVAL, as the ucrt contract specifies for a null pointer
    guest.rand_state = (Math.imul(guest.rand_state, 214013) + 2531011) >>> 0;
    const high = guest.rand_state;
    guest.rand_state = (Math.imul(guest.rand_state, 214013) + 2531011) >>> 0;
    const value = ((high & 0xffff0000) | (guest.rand_state >>> 16)) >>> 0;
    guest.memory.writeMemory(pointer, 4, value);
    return 0;
  });

  // Environment and locale.
  define(msvcrt, "getenv", 1, (guest, argument) => {
    const name = guest.readAnsiString(argument[0]);
    if (name === null) return 0;
    const value = guest.environment.get(name);
    if (value === undefined) return 0;
    const address = guest.crtMalloc(value.length + 1);
    if (address === 0) return 0;
    guest.writeAnsiString(address, value, value.length + 1);
    return address;
  });
  // _wgetenv: the wide getenv a ucrt game uses to read DOOMWADDIR / HOME /
  // USERPROFILE when it searches for its IWAD. Returns a pointer to a wide copy
  // of the value (allocated on the process heap, the ucrt-internal-buffer
  // contract a caller reads immediately), or NULL when the variable is unset.
  define(msvcrt, "_wgetenv", 1, (guest, argument) => {
    const name = guest.readWideString(blockAddress(argument[0]));
    if (name === null) return 0;
    const value = guest.environment.get(name);
    if (value === undefined) return 0;
    const address = guest.crtMalloc((value.length + 1) * 2);
    if (address === 0) return 0;
    guest.writeWideString(address, value, value.length + 1);
    return address;
  });
  define(msvcrt, "setlocale", 2, (guest) => guest.crtRuntime.localeName);
  define(msvcrt, "localeconv", 0, (guest) => guest.crtRuntime.lconv);

  // Math: an x87 double return the integer EAX dispatch cannot carry.
  for (const symbol of ["acos", "asin", "atan", "cosh", "sinh", "tan", "tanh", "log10"]) define(msvcrt, symbol, 2, refuseDouble(symbol));
  for (const symbol of ["_hypot", "_nextafter"]) define(msvcrt, symbol, 4, refuseDouble(symbol));
  for (const symbol of ["_j0", "_j1", "_y0", "_y1"]) define(msvcrt, symbol, 2, refuseDouble(symbol));
  for (const symbol of ["_jn", "_yn"]) define(msvcrt, symbol, 3, refuseDouble(symbol));

  // Time (one deterministic guest clock; UTC only).
  define(msvcrt, "time", 1, (guest, argument) => {
    const seconds = crtGuestUnixSecond();
    if (unsigned(argument[0]) !== 0) guest.memory.writeMemory(unsigned(argument[0]), 4, seconds);
    return seconds;
  });
  // _time64: the 64-bit time_t a ucrt game uses to seed its RNG / timestamp. The
  // one deterministic guest clock backs it; the out pointer keeps full width (on
  // x64 it is commonly a stack address above 4 GiB) and receives eight byte.
  define(msvcrt, "_time64", 1, (guest, argument) => {
    const seconds = crtGuestUnixSecond();
    const pointer = blockAddress(argument[0]);
    if (pointer !== 0) { guest.memory.writeMemory(pointer, 4, seconds); guest.memory.writeMemory(pointer + 4, 4, 0); }
    return seconds;
  });
  define(msvcrt, "gmtime", 1, (guest, argument) => crtWriteTm(guest, guest.memory.readMemory(unsigned(argument[0]), 4)));
  define(msvcrt, "localtime", 1, (guest, argument) => crtWriteTm(guest, guest.memory.readMemory(unsigned(argument[0]), 4)));
  define(msvcrt, "_mkgmtime32", 1, (guest, argument) => {
    const base = unsigned(argument[0]);
    const field = (offset) => signed32(guest.memory.readMemory(base + offset, 4));
    const epoch = Date.UTC(field(20) + 1900, field(16), field(12), field(8), field(4), field(0)) / 1000;
    return unsigned(epoch | 0);
  });
  define(msvcrt, "_tzset", 0, () => 0); // _tzname is already the UTC pair
  define(msvcrt, "strftime", 4, (guest, argument) => crtStrftime(guest, argument[0], unsigned(argument[1]), argument[2], argument[3]));

  // stdio the tool actually calls.
  // __acrt_iob_func(index) is the ucrt accessor for the standard stream table
  // (0=stdin, 1=stdout, 2=stderr). It returns the FILE at that slot of the same
  // _iob array the msvcrt _iob export hands back, so a ucrt game's stderr
  // logging routes through the identical bounded stdio surface (crtWriteStream
  // reads the fd from FILE+FILE_FD_OFFSET).
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "__acrt_iob_func", 1, (guest, argument) => unsigned(guest.crtRuntime.iobBase + (unsigned(argument[0]) % 3) * FILE_STRUCT_BYTE));
  define(msvcrt, "_fileno", 1, (guest, argument) => unsigned(guest.crtStreamFd(argument[0])));
  define(msvcrt, "_isatty", 1, (guest, argument) => (unsigned(argument[0]) <= 2 ? 1 : 0));
  define(msvcrt, "_get_osfhandle", 1, (guest, argument) => guest.crtOsHandle(argument[0] | 0));
  define(msvcrt, "_setmode", 2, () => 0x4000); // returns the previous _O_TEXT mode
  define(msvcrt, "_open", 3, (guest, argument) => unsigned(guest.crtOpen(argument[0], argument[1] | 0, false)));
  define(msvcrt, "_close", 1, (guest, argument) => unsigned(guest.crtClose(argument[0] | 0)));
  define(msvcrt, "_write", 3, (guest, argument) => {
    const count = unsigned(argument[2]);
    const buffer = count === 0 ? Buffer.alloc(0) : guest.memory.readBlock(unsigned(argument[1]), count);
    return unsigned(guest.crtWriteFd(argument[0] | 0, buffer));
  });
  define(msvcrt, "_fdopen", 2, (guest, argument) => guest.crtFdopen(argument[0] | 0));
  define(msvcrt, "_wfopen", 2, (guest, argument) => {
    const mode = guest.readWideString(blockAddress(argument[1]));
    const fd = guest.crtOpen(argument[0], crtFopenOflag(mode), true);
    return fd < 0 ? 0 : guest.crtFdopen(fd);
  });
  define(msvcrt, "fopen", 2, (guest, argument) => {
    const mode = guest.readAnsiString(blockAddress(argument[1]));
    const fd = guest.crtOpen(argument[0], crtFopenOflag(mode), false);
    return fd < 0 ? 0 : guest.crtFdopen(fd);
  });
  // _wmkdir/_mkdir: create the game's configuration/save directory. A ucrt
  // binary imports these from the api-ms-win-crt-filesystem api-set, which
  // forwards to the same routine msvcrt.dll exports (Chocolate Doom's config
  // path calls _wmkdir). Returns 0 on a valid c:\ path, -1 with errno set
  // otherwise; the directory is a recorded node in the bounded virtual drive.
  define(msvcrt, "_wmkdir", 1, (guest, argument) => unsigned(guest.crtMkdir(argument[0], true)));
  define(msvcrt, "_mkdir", 1, (guest, argument) => unsigned(guest.crtMkdir(argument[0], false)));
  define(msvcrt, "fwrite", 4, (guest, argument) => {
    const size = unsigned(argument[1]);
    const count = unsigned(argument[2]);
    const total = size * count;
    if (total === 0) return 0;
    const buffer = guest.memory.readBlock(unsigned(argument[0]), total);
    const written = guest.crtWriteStream(argument[3], buffer);
    return written < 0 ? 0 : Math.floor(written / (size || 1));
  });
  define(msvcrt, "fread", 4, (guest, argument) => guest.crtFread(blockAddress(argument[0]), unsigned(argument[1]), unsigned(argument[2]), argument[3]));
  define(msvcrt, "fseek", 3, (guest, argument) => unsigned(guest.crtFseek(argument[0], signed32(argument[1]), unsigned(argument[2]))));
  define(msvcrt, "ftell", 1, (guest, argument) => unsigned(guest.crtFtell(argument[0])));
  define(msvcrt, "rewind", 1, (guest, argument) => { guest.crtFseek(argument[0], 0, 0); return 0; });
  // freopen(path, mode, stream): a game redirects stderr/stdout to a log file at
  // startup (Dwarf Fortress opens gamelog/errorlog). The bounded world has no
  // host file, so the stream is returned unchanged — subsequent writes stay on
  // the same captured bounded stdio surface rather than a fabricated file.
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "freopen", 3, (guest, argument) => unsigned(argument[2]));
  // setvbuf(stream, buffer, mode, size): a game turns off log buffering at
  // startup. The bounded stdio surface is unbuffered already, so this succeeds
  // with no state change.
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "setvbuf", 4, () => 0);
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "setbuf", 2, () => 0);
  // The ucrt formatted-output backends. As with the existing printf/fprintf
  // surface, the bounded world writes the format string to the stream rather
  // than running the full varargs %-engine (the frame does not depend on log
  // text). __stdio_common_vfprintf(options, stream, format, locale, valist);
  // __stdio_common_vsprintf(options, buffer, count, format, locale, valist)
  // copies the format into the caller buffer bounded by count and returns the
  // length, which is what a game's snprintf-into-a-fixed-buffer path needs.
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "__stdio_common_vfprintf", 5, (guest, argument) => {
    // The format and va_list pointers keep their full width: on x64 the format
    // is a .rdata address above 4 GiB and the va_list a stack address, so
    // truncating either would miss the real bytes. The %-engine expands the
    // real variadic argument read from the va_list.
    const format = guest.readAnsiString(blockAddress(argument[2])) ?? "";
    const text = formatPrintf(guest, format, argument[4]);
    const written = guest.crtWriteStream(argument[1], Buffer.from(text, "latin1"));
    return written < 0 ? 0xffffffff : written;
  });
  const commonVsprintf = (guest, argument) => {
    const count = unsigned(argument[2]);
    // The format, destination, and va_list pointers keep their full width: on
    // x64 the format lives in .rdata, the buffer and va_list on the stack, all
    // above 4 GiB. The %-engine expands the real variadic argument; the result
    // is written bounded by count with a NUL, and the return is the length the
    // full conversion would have produced (C snprintf contract).
    const format = guest.readAnsiString(blockAddress(argument[3])) ?? "";
    const text = formatPrintf(guest, format, argument[5]);
    const truncated = count > 0 ? text.slice(0, count - 1) : "";
    const bytes = Buffer.from(truncated + "\0", "latin1");
    guest.memory.writeBlock(blockAddress(argument[1]), bytes);
    return text.length;
  };
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "__stdio_common_vsprintf", 6, commonVsprintf);
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "__stdio_common_vsprintf_s", 6, commonVsprintf);
  // The ucrt formatted-input backends. __stdio_common_vsscanf(options, buffer,
  // count, format, locale, va_list) reads from a string; __stdio_common_vfscanf
  // (options, FILE*, format, locale, va_list) reads from a real file. Both run
  // the shared bounded scanf engine over the real bytes and the real x64
  // va_list — Chocolate Doom parses its WAD's DEHACKED lump with
  // sscanf(line, "%19s", word) and sscanf(line, "%d", &value), so this is
  // load-bearing WAD-load control flow.
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "__stdio_common_vsscanf", 6, (guest, argument) => {
    const format = guest.readAnsiString(blockAddress(argument[3])) ?? "";
    const buffer = blockAddress(argument[1]);
    const count = unsigned(argument[2]);
    let offset = 0;
    const readByte = () => {
      if (offset >= count) return -1;
      const value = guest.memory.readMemory(buffer + offset, 1);
      if (value === 0) return -1;
      offset += 1;
      return value;
    };
    return scanfInput(guest, format, readByte, argument[5]);
  });
  defineForEach([crtStdioLibrary, "msvcrt.dll"], "__stdio_common_vfscanf", 5, (guest, argument) => {
    const format = guest.readAnsiString(blockAddress(argument[2])) ?? "";
    const record = guest.crtFileRecord(argument[1]);
    const readByte = () => {
      if (record === null || record.object.position >= record.object.data.length) return -1;
      return record.object.data[record.object.position++];
    };
    return scanfInput(guest, format, readByte, argument[4]);
  });
  define(msvcrt, "fputc", 2, (guest, argument) => {
    const written = guest.crtWriteStream(argument[1], Buffer.from([argument[0] & 0xff]));
    return written < 0 ? 0xffffffff : argument[0] & 0xff;
  });
  define(msvcrt, "putchar", 1, (guest, argument) => {
    const written = guest.crtWriteFd(1, Buffer.from([argument[0] & 0xff]));
    return written < 0 ? 0xffffffff : argument[0] & 0xff;
  });
  define(msvcrt, "puts", 1, (guest, argument) => {
    const text = guest.readAnsiString(argument[0]) ?? "";
    const written = guest.crtWriteFd(1, Buffer.from(`${text}\n`, "latin1"));
    return written < 0 ? 0xffffffff : written;
  });
  define(msvcrt, "getc", 1, () => 0xffffffff); // EOF: the bounded console is output-only
  define(msvcrt, "fgets", 3, () => 0); // NULL at end of an input-less stream
  define(msvcrt, "fflush", 1, () => 0);
  define(msvcrt, "fclose", 1, (guest, argument) => {
    const fd = guest.crtStreamFd(argument[0]);
    if (fd > 2) guest.crtClose(fd);
    return 0;
  });
  define(msvcrt, "feof", 1, (guest, argument) => guest.crtFeof(argument[0]));
  define(msvcrt, "ferror", 1, () => 0);
  define(msvcrt, "clearerr", 1, () => 0);
  define(msvcrt, "printf", 1, (guest, argument) => {
    const text = guest.readAnsiString(argument[0]) ?? "";
    const buffer = Buffer.from(text, "latin1");
    const written = guest.crtWriteFd(1, buffer);
    return written < 0 ? 0xffffffff : written;
  });
  define(msvcrt, "fprintf", 2, (guest, argument) => {
    const text = guest.readAnsiString(argument[1]) ?? "";
    const written = guest.crtWriteStream(argument[0], Buffer.from(text, "latin1"));
    return written < 0 ? 0xffffffff : written;
  });
  define(msvcrt, "vfprintf", 3, (guest, argument) => {
    const text = guest.readAnsiString(argument[1]) ?? "";
    const written = guest.crtWriteStream(argument[0], Buffer.from(text, "latin1"));
    return written < 0 ? 0xffffffff : written;
  });
  define(msvcrt, "perror", 1, (guest, argument) => {
    const prefix = guest.readAnsiString(argument[0]);
    const message = crtStrerrorText(guest.crtErrno() | 0);
    const line = `${prefix ? `${prefix}: ` : ""}${message}\n`;
    guest.crtWriteFd(2, Buffer.from(line, "latin1"));
    return 0;
  });
  define(msvcrt, "_fullpath", 3, (guest, argument) => {
    const relative = guest.readAnsiString(argument[1]) ?? "";
    const backslash = String.fromCharCode(92);
    const absolute = relative.length >= 2 && relative[1] === ":" ? relative : `${hleProfile.guest_root}${backslash}${relative}`;
    let dest = unsigned(argument[0]);
    if (dest === 0) {
      dest = guest.crtMalloc(absolute.length + 1);
      if (dest === 0) return 0;
    }
    guest.writeAnsiString(dest, absolute, absolute.length + 1);
    return dest;
  });
  define(msvcrt, "_stati64", 2, (guest, argument) => crtStat(guest, guest.readAnsiString(argument[0]), argument[1]));
  define(msvcrt, "_fstati64", 2, (guest, argument) => {
    const handle = guest.crt_fd_table.get(argument[0] | 0);
    if ((argument[0] | 0) > 2 && handle === undefined) { guest.crtErrno(crtErrnoValue.ebadf); return 0xffffffff; }
    guest.memory.writeBlock(unsigned(argument[1]), Buffer.alloc(88));
    return 0;
  });
  define(msvcrt, "qsort", 4, refuseCallback("qsort"));

  // --- shlwapi.dll (path helper for the i386 CLI corpus) --------------------
  define("shlwapi.dll", "PathIsRelativeA", 1, (guest, argument) => {
    const path = guest.readAnsiString(argument[0]);
    if (path === null || path.length === 0) return 1;
    const backslash = String.fromCharCode(92);
    if (path[0] === backslash || path[0] === "/") return 0;
    if (path.length >= 2 && path[1] === ":") return 0;
    return 1;
  });

  define("shlwapi.dll", "PathIsRelativeW", 1, (guest, argument) => {
    const path = guest.readWideString(blockAddress(argument[0]));
    if (path === null || path.length === 0) return 1;
    const backslash = String.fromCharCode(92);
    if (path[0] === backslash || path[0] === "/") return 0;
    if (path.length >= 2 && path[1] === ":") return 0;
    return 1;
  });

  // --- shell32.dll (the x86-64 game corpus command-line entry) ---------------
  // A game's main reads its command line through CommandLineToArgvW: the real
  // Windows tokenizer over the wide command line, the argv pointer array plus the
  // argument strings written into one heap block, and the argument count returned
  // through the out pointer. The block is the process default heap (crtMalloc),
  // so a later LocalFree/HeapFree over it is the same real allocation.
  define("shell32.dll", "CommandLineToArgvW", 2, (guest, argument) => {
    const commandLine = guest.readWideString(blockAddress(argument[0])) ?? "";
    const arg = parseCommandLineW(commandLine);
    if (arg.length === 0) arg.push("");
    let stringByte = 0;
    for (const value of arg) stringByte += (value.length + 1) * 2;
    const pointerSize = guest.pointer_size_byte ?? 8;
    const base = guest.crtMalloc(arg.length * pointerSize + stringByte);
    if (base === 0) { guest.setLastError(errorValue.not_enough_memory); return 0; }
    let stringCursor = base + arg.length * pointerSize;
    for (let index = 0; index < arg.length; index += 1) {
      guest.memory.writeMemory(base + index * pointerSize, 4, stringCursor >>> 0);
      if (pointerSize === 8) guest.memory.writeMemory(base + index * pointerSize + 4, 4, 0);
      guest.writeWideString(stringCursor, arg[index], arg[index].length + 1);
      stringCursor += (arg[index].length + 1) * 2;
    }
    // The out pointer (pNumArgs) keeps its full width: on x64 it is a stack
    // address above 4 GiB, so truncating it to a dword would fault a legitimate
    // write.
    const numArgsPointer = blockAddress(argument[1]);
    if (numArgsPointer !== 0) guest.memory.writeMemory(numArgsPointer, 4, arg.length);
    return base;
  });

  // --- kernel32.dll thread/semaphore breadth for the i386 CLI corpus --------
  // jq references a small thread and semaphore surface for its (unused in the
  // bounded run) worker pool. The single-thread probe serves the bounded
  // contract: affinity/priority are fixed, a semaphore is a counted handle, and
  // a wait on an already-signaled bounded object returns at once.
  define("kernel32.dll", "AreFileApisANSI", 0, () => 1);
  define("kernel32.dll", "IsDBCSLeadByteEx", 2, () => 0); // code page 1252 has no DBCS lead byte
  define("kernel32.dll", "GetThreadPriority", 1, () => 0); // THREAD_PRIORITY_NORMAL
  define("kernel32.dll", "SetThreadPriority", 2, () => 1);
  define("kernel32.dll", "SetThreadExecutionState", 1, (guest, argument) => {
    // ES_CONTINUOUS 0x80000000, ES_SYSTEM_REQUIRED 1, ES_DISPLAY_REQUIRED 2,
    // ES_USER_PRESENT 4, ES_AWAYMODE_REQUIRED 0x40. The host never sleeps;
    // CONTINUOUS is stored and returned, a one-shot is accepted and forgotten.
    // USER_PRESENT cannot combine with CONTINUOUS; AWAYMODE requires it.
    const flag = unsigned(argument[0]);
    const continuous = 0x80000000;
    const known_flag = continuous | 0x00000001 | 0x00000002 | 0x00000004 | 0x00000040;
    const is_continuous = (flag & continuous) !== 0;
    const is_user_present = (flag & 0x00000004) !== 0;
    const is_away_mode = (flag & 0x00000040) !== 0;
    if (flag === 0 || (flag & ~known_flag) !== 0 || (is_user_present && is_continuous) || (is_away_mode && !is_continuous)) {
      guest.setLastError(errorValue.invalid_parameter);
      return 0;
    }
    const previous = guest.execution_state >>> 0;
    if (is_continuous) guest.execution_state = flag;
    return previous;
  });
  define("kernel32.dll", "GetProcessAffinityMask", 3, (guest, argument) => {
    if (unsigned(argument[1]) !== 0) guest.memory.writeMemory(unsigned(argument[1]), 4, 1);
    if (unsigned(argument[2]) !== 0) guest.memory.writeMemory(unsigned(argument[2]), 4, 1);
    return 1;
  });
  define("kernel32.dll", "SetProcessAffinityMask", 2, () => 1);
  define("kernel32.dll", "GetHandleInformation", 2, (guest, argument) => {
    if (unsigned(argument[1]) !== 0) guest.memory.writeMemory(unsigned(argument[1]), 4, 0);
    return 1;
  });
  define("kernel32.dll", "DuplicateHandle", 7, (guest, argument) => {
    if (unsigned(argument[3]) !== 0) guest.memory.writeMemory(unsigned(argument[3]), 4, unsigned(argument[1]));
    return 1;
  });
  define("kernel32.dll", "CreateSemaphoreA", 4, (guest, argument) => guest.createSemaphore(argument[1] | 0, argument[2] | 0, argument[3], false));
  define("kernel32.dll", "ReleaseSemaphore", 3, (guest, argument) => guest.releaseSemaphore(argument[0], argument[1] | 0, argument[2]));
  define("kernel32.dll", "ResumeThread", 1, (guest, argument) => guest.resumeGuestThread(argument[0]));
  define("kernel32.dll", "SuspendThread", 1, () => 0);
  define("kernel32.dll", "GetThreadContext", 2, () => 1); // the one guest thread's context is the live register file
  define("kernel32.dll", "SetThreadContext", 2, () => 1);

  // --- USER32 and GDI32 (BPTK-011/012) --------------------------------------
  // Registration only: the rows are authored in lib/user.mjs and lib/gdi.mjs
  // and delegate to guest.user / guest.gdi.
  for (const entry of userExportTable) table.push(entry);
  for (const entry of gdiExportTable) table.push(entry);

  // --- SDL (lane W): the bounded SDL subset toward a first frame -------------
  // Registration only: the rows are authored in lib/sdl.mjs and delegate to
  // guest.sdl (the per-run SDL subsystem). A corpus x64 game that bundles SDL
  // (Dwarf Fortress / sdl.dll, Chocolate Doom / sdl2.dll) reaches these through
  // its IAT rather than stalling at the first SDL call.
  for (const entry of sdlExportTable) table.push(entry);
  for (const entry of glExportTable) table.push(entry);
  define("comdlg32.dll", "GetOpenFileNameA", 1, () => 0);
  define("comdlg32.dll", "GetSaveFileNameA", 1, () => 0);

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
  // i386 CRT walks char** as 4-byte slots. The default stays 8 so the x64
  // research lane and the table-driven conformance harness keep their
  // existing argv layout; the i386 probe passes 4.
  const pointerSizeByte = option.pointer_size_byte === 4 ? 4 : 8;
  const peImage = Buffer.isBuffer(option.image) || option.image instanceof Uint8Array ? option.image : null;
  const peImageBase = unsigned(option.image_base ?? 0);
  const peResourceRva = unsigned(option.resource_rva ?? 0);

  const readAnsiString = createAnsiReader(memory);
  const readWideString = createWideReader(memory);
  const writeAnsiString = createAnsiWriter(memory);
  const writeWideString = createWideWriter(memory);
  const arena = createArena(memory, layout);

  // The USER32/GDI subsystem, one per run, owning the window manager and the
  // 2D surface. The message queue keys on the single declared guest thread id
  // until the thread core lands and this run keys it on the real registry.
  const user = createUserSubsystem({ thread_id: hleProfile.thread_id });
  const gdi = createGdiSubsystem();
  // The bounded SDL subsystem (lane W): a real semaphore/mutex/atomic surface,
  // a real framebuffer the compositor presents, and a bounded empty event
  // trace. It allocates framebuffer pixels from the same arena and reads the
  // one guest clock for SDL_GetTicks / SDL_Delay.
  const sdl = createSdlSubsystem({ memory, layout, allocate: (sizeByte) => arena.allocate(sizeByte), clock });
  const gl = createGlSubsystem({ memory, allocate: (sizeByte) => arena.allocate(sizeByte) });
  // One offline-by-default Winsock per run: no consent, empty allowlist, so
  // every dial is refused with the ws2_32 access contract. The lifecycle,
  // handle table, and byte-order/address helpers are fully served; the dial
  // and transfer surface stays consent-gated.
  const net = createWinsock(createMediatedRelay(createTransportPolicy()));
  // One gamepad subsystem per run: every slot disconnected until a browser
  // Gamepad state is injected, so XInput honestly reports no controller.
  const gamepad = createGamepadSubsystem();

  let lastError = 0;
  let nextHandle = 0x00010000;
  function setLastError(value) {
    lastError = value & 0xffffffff;
  }
  const handleTable = new Map();
  const heapList = [];
  const virtualRegion = new Map();
  const tlsSlot = new Array(hleBound.tls_slot_count).fill(null);
  const flsSlot = new Array(hleBound.fls_slot_count).fill(null);
  const criticalSection = new Map();
  const environment = new Map();
  let currentDirectory = hleProfile.guest_root;
  const trace = [];
  const traceHash = createHash("sha256");
  const outputChunk = [];
  let outputByteCount = 0;
  let callCount = 0;
  let comApartment = null;
  let comRefcount = 0;
  let defaultHeap = null;
  let environmentBlockAddress = 0;
  // The bounded virtual drive and registry hive (BPTK-015 slice): guest
  // memory only, never host storage.
  const virtualDrive = new Map();
  // The set of directory paths the guest has created (crtMkdir). A directory is
  // a recorded node in the same c:\ path space as the file map, never a host
  // mkdir; it lets a later stat/create under the config dir agree it exists.
  const virtualDir = new Set();
  let driveTotalByte = 0;
  const registryHive = new Map();
  const registryOpenKey = new Map();
  const registryRoot = new Map([
    [0x80000000, "hkey_classes_root"],
    [0x80000001, "hkey_current_user"],
    [0x80000002, "hkey_local_machine"],
    [0x80000003, "hkey_users"],
  ]);
  const stdSlot = new Map();
  let threadHandle = 0;
  const eventTable = new Map();
  const findSession = new Map();
  // The Plink import-surface widening (BPTK-146): the file-mapping view table
  // keys a mapped guest address to its backing store so UnmapViewOfFile can
  // flush the view, and the console-mode override records a SetConsoleMode so
  // GetConsoleMode reflects it. Mutex, mapping, and pipe objects live in the
  // shared handle table under their own kind.
  const mapViewByAddress = new Map();
  const consoleModeOverride = new Map();
  let timerPeriod = 0;
  // The per-thread structured-exception machine (BPTK-053). The probe has no
  // mapped TEB yet — the thread lane owns that — so the chain runs on the
  // legacy in-object head until fs:[0] is wired; the vectored list and dispatch
  // order are identical either way.
  const sehThread = new SehThread();

  function normalizeDrivePath(name) {
    if (name === null || name.length === 0 || name.length > hleBound.string_byte) return null;
    const backslash = String.fromCharCode(92);
    let path = String(name).replace(/[\\/]+/g, backslash);
    if (path.startsWith(backslash + backslash)) return null;
    if (path.length >= 2 && path[1] === ":" && path[0].toLowerCase() !== "c") return null;
    if (!path.toLowerCase().startsWith("c:" + backslash) && path.toLowerCase() !== "c:") {
      if (path.startsWith(backslash)) path = `c:${path}`;
      else path = `${(currentDirectory || hleProfile.guest_root).replace(/[\\]+$/, "")}${backslash}${path}`;
    }
    const resolved = [];
    for (const part of path.toLowerCase().replace(/^c:/, "").split(backslash)) {
      if (part.length === 0 || part === ".") continue;
      if (part === "..") {
        if (resolved.length === 0) return null;
        resolved.pop();
        continue;
      }
      resolved.push(part);
    }
    return resolved.length === 0 ? "c:" : `c:\\${resolved.join(backslash)}`;
  }

  function formatGuestPath(path) {
    return path === "c:" ? "C:\\" : path.replace(/^c:/, "C:");
  }

  function isDirectoryPath(path) {
    if (path === "c:" || path === hleProfile.guest_root.toLowerCase() || virtualDir.has(path)) return true;
    const prefix = `${path}\\`;
    for (const filePath of virtualDrive.keys()) if (filePath.startsWith(prefix)) return true;
    for (const filePath of hostFile.keys()) if (filePath.startsWith(prefix)) return true;
    for (const filePath of virtualDir) if (filePath.startsWith(prefix)) return true;
    return false;
  }

  // The read-only host-file store: real bytes a game reads (its staged IWAD /
  // asset), keyed by normalized c:\ path. A read of one of these returns the
  // real bytes and its real size, bypassing the small writable-drive bounds; a
  // write still goes to the bounded writable virtualDrive, never back to the
  // host. Seeded once at construction from option.host_file, never mutated.
  const hostFile = new Map();
  if (option.host_file instanceof Map) {
    for (const [path, bytes] of option.host_file) {
      const norm = normalizeDrivePath(path);
      if (norm === null) continue;
      // Accept ANY byte view, not just a Node Buffer — the browser host reads
      // files through fetch().arrayBuffer(), which yields a plain Uint8Array.
      // Normalize to a Buffer over the SAME memory (zero-copy) so downstream
      // reads may still assume Buffer methods. A non-view value is skipped.
      if (Buffer.isBuffer(bytes)) hostFile.set(norm, bytes);
      else if (ArrayBuffer.isView(bytes)) hostFile.set(norm, Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength));
    }
  }
  // The initial environment (option.environment): a game reads DOOMWADDIR /
  // HOME / USERPROFILE through getenv/_wgetenv/GetEnvironmentVariable when it
  // searches for its IWAD. Every value is a plain string in guest-visible form.
  if (option.environment && typeof option.environment === "object") {
    for (const [name, value] of Object.entries(option.environment)) {
      if (typeof value === "string" && environment.size < hleBound.environment_entry_count) environment.set(name, value);
    }
  }

  // On Win32 the HMODULE *is* the load address. A CRT that does
  // GetModuleHandle(NULL) + RVA must land in the mapped image, not a
  // synthetic handle window. The 0x00020001 fallback is only for the
  // table-driven HLE harness that has no mapped PE.
  const mappedImageBase = Number.isSafeInteger(option.image_base) && option.image_base > 0
    ? option.image_base >>> 0
    : 0;
  const mainModuleHandle = mappedImageBase || 0x00020001;
  const moduleTable = [
    { name: basename(executableName).toLowerCase(), handle: mainModuleHandle, is_main: true },
    { name: "kernel32.dll", handle: 0x00020002, is_main: false },
    { name: "ole32.dll", handle: 0x00020003, is_main: false },
    { name: "user32.dll", handle: 0x00020004, is_main: false },
    { name: "gdi32.dll", handle: 0x00020005, is_main: false },
    // ws2_32.dll is a served library (the BPTK-099 Winsock lifecycle slice), so a
    // guest that loads it by name at startup (PuTTY probes for a WinSock library
    // before it opens its window) gets a real module handle and can resolve its
    // exports through GetProcAddress; the socket layer stays offline-by-default.
    { name: "ws2_32.dll", handle: 0x00020006, is_main: false },
    // comctl32.dll is a served library (the common-control init slice), so a
    // GUI program (PuTTY) that loads it and resolves InitCommonControls before
    // opening its window gets a real module handle.
    { name: "comctl32.dll", handle: 0x00020007, is_main: false },
    { name: "ntdll.dll", handle: 0x00020008, is_main: false },
    { name: "userenv.dll", handle: 0x00020009, is_main: false },
    { name: "bcryptprimitives.dll", handle: 0x0002000a, is_main: false },
    { name: "secur32.dll", handle: 0x0002000b, is_main: false },
  ];
  for (const module of option.sidecar ?? []) {
    if (module == null || typeof module.name !== "string") continue;
    if (!Number.isSafeInteger(module.load_base) || module.load_base <= 0) continue;
    const exportByName = new Map();
    for (const row of module.export ?? []) {
      if (row == null || typeof row.symbol !== "string") continue;
      exportByName.set(row.symbol, (module.load_base + (row.rva ?? 0)) >>> 0);
    }
    moduleTable.push({
      name: module.name.toLowerCase(),
      handle: module.load_base >>> 0,
      is_main: false,
      is_sidecar: true,
      image_size_byte: module.image_size_byte ?? 0,
      exportByName,
    });
  }
  const moduleByName = new Map(moduleTable.map((entry) => [entry.name, entry]));
  function moduleKey(name) {
    const leaf = name.split(/[\\/]/).pop().toLowerCase();
    const keyed = leaf.includes(".") ? leaf : `${leaf}.dll`;
    if (/^api-ms-win-core-[a-z0-9-]+\.dll$/.test(keyed) || keyed === "kernelbase.dll") return "kernel32.dll";
    if (/^api-ms-win-crt-[a-z0-9-]+\.dll$/.test(keyed)) return moduleByName.has("ucrtbase.dll") ? "ucrtbase.dll" : "kernel32.dll";
    return keyed;
  }

  const thunkByExport = new Map();
  for (let index = 0; index < win32HleExportTable.length; index += 1) {
    const entry = win32HleExportTable[index];
    thunkByExport.set(`${entry.library}!${entry.symbol}`, layout.thunk_base + index * 4);
  }
  const exportByThunk = new Map([...thunkByExport.entries()].map(([key, address]) => [address, win32HleExportTable.find((entry) => `${entry.library}!${entry.symbol}` === key)]));
  const sspiTable = hleCrtDataLayout(layout).sspi_table;
  memory.writeBlock(sspiTable, Buffer.alloc(128));
  memory.writeMemory(sspiTable, 4, 3);
  for (const [offset, symbol] of [
    [4, "EnumerateSecurityPackagesW"],
    [8, "QueryCredentialsAttributesW"],
    [12, "AcquireCredentialsHandleW"],
    [16, "FreeCredentialsHandle"],
    [24, "InitializeSecurityContextW"],
    [28, "AcceptSecurityContext"],
    [32, "CompleteAuthToken"],
    [36, "DeleteSecurityContext"],
    [40, "ApplyControlToken"],
    [44, "QueryContextAttributesW"],
    [48, "ImpersonateSecurityContext"],
    [52, "RevertSecurityContext"],
    [56, "MakeSignature"],
    [60, "VerifySignature"],
    [64, "FreeContextBuffer"],
    [68, "QuerySecurityPackageInfoW"],
    [80, "ExportSecurityContext"],
    [84, "ImportSecurityContextW"],
    [88, "AddCredentialsW"],
    [96, "QuerySecurityContextToken"],
    [100, "EncryptMessage"],
    [104, "DecryptMessage"],
    [108, "SetContextAttributesW"],
  ]) {
    memory.writeMemory(sspiTable + offset, 4, thunkByExport.get(`secur32.dll!${symbol}`) ?? 0);
  }

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
  // option.command_line: the program's argument tail (an array of argument
  // strings, e.g. ["-iwad", "C:\\game\\freedoom1.wad"]). A game reads it through
  // GetCommandLine and, more load-bearing, through the CRT argv the startup
  // hands its main(). Empty by default (a bare program launch); each argument is
  // a plain guest-visible string, never a host path.
  const commandArgument = Array.isArray(option.command_line)
    ? option.command_line.filter((value) => typeof value === "string")
    : [];
  const quoteArgument = (value) => (value.includes(" ") ? `"${value}"` : value);
  const commandLineText = [`"${mainModulePath}"`, ...commandArgument.map(quoteArgument)].join(" ");
  const commandLineAddressA = arena.allocate(commandLineText.length + 1);
  writeAnsiString(commandLineAddressA, commandLineText, commandLineText.length + 1);
  const commandLineAddressW = arena.allocate((commandLineText.length + 1) * 2);
  writeWideString(commandLineAddressW, commandLineText, commandLineText.length + 1);

  // The C runtime startup block (BPTK-031 Win64 CRT-init breadth). The ucrt
  // entry (mainCRTStartup/WinMainCRTStartup → __scrt_common_main_seh) reads the
  // program's argc/argv/envp and its errno/mode words through pointer-returning
  // CRT stubs (__p___argc, __p___argv, _errno, __p__commode …). Those pointers
  // must stay valid guest addresses for the whole run, so the block sits at a
  // fixed page near the top of the arena — deterministic per layout and clear of
  // the bump cursor that grows from the arena base, so no existing allocation
  // address shifts. One argument (the quoted program path) mirrors the command
  // line the same startup already reads; the environment and wide vectors are a
  // single null terminator (the bounded world exposes no inherited environment).
  const crtScratchBase = layout.arena_base + layout.arena_size_byte - 0x1000;
  const crtData = hleCrtDataLayout(layout);
  const crt = (() => {
    let cursor = crtScratchBase;
    const take = (sizeByte) => { const at = cursor; cursor += (sizeByte + 15) & ~15; return at; };
    // A guest pointer is pointerSizeByte wide. x64 writes a low dword plus a
    // zero high dword (every mapped region sits below 2^32). i386 writes the
    // low dword only — an 8-byte slot made argv[1] the high zero of argv[0],
    // so jq never saw --version.
    const writePtr = (at, value) => {
      memory.writeMemory(at, 4, value >>> 0);
      if (pointerSizeByte === 8) memory.writeMemory(at + 4, 4, 0);
    };
    // argv[0] is the program path (unquoted), followed by the argument tail.
    // Each argument string is written once (narrow and wide) and its address
    // placed in the argv/wargv arrays, terminated by a NULL — the exact vector a
    // game's main() walks (myargc/myargv in Chocolate Doom).
    const argList = [mainModulePath, ...commandArgument];
    const argCount = argList.length;
    const argAddress = argList.map((value) => {
      const at = take(value.length + 1);
      writeAnsiString(at, value, value.length + 1);
      return at;
    });
    const wargAddress = argList.map((value) => {
      const at = take((value.length + 1) * 2);
      writeWideString(at, value, value.length + 1);
      return at;
    });
    const argvArray = take((argCount + 1) * pointerSizeByte);
    argAddress.forEach((at, index) => writePtr(argvArray + index * pointerSizeByte, at));
    writePtr(argvArray + argCount * pointerSizeByte, 0);
    const wargvArray = take((argCount + 1) * pointerSizeByte);
    wargAddress.forEach((at, index) => writePtr(wargvArray + index * pointerSizeByte, at));
    writePtr(wargvArray + argCount * pointerSizeByte, 0);
    const environArray = take(pointerSizeByte);
    writePtr(environArray, 0);
    const wenvironArray = take(pointerSizeByte);
    writePtr(wenvironArray, 0);
    const winmainLine = take(1); // the WinMain command tail is empty (no arguments)
    memory.writeMemory(winmainLine, 1, 0);
    // Pointer cells the __p_* accessors return the address of.
    const argcCell = take(4); memory.writeMemory(argcCell, 4, argCount);
    const argvCell = take(8); writePtr(argvCell, argvArray);
    const wargvCell = take(8); writePtr(wargvCell, wargvArray);
    // _environ / __winitenv are data imports. Their cells live on the CRT
    // data page (hleCrtDataLayout) so the IAT can bind them before argv size
    // is known; the arrays themselves stay in this scratch block.
    const environCell = crtData.environ_cell; writePtr(environCell, environArray);
    const wenvironCell = crtData.wenviron_cell; writePtr(wenvironCell, wenvironArray);
    const errnoCell = take(4); memory.writeMemory(errnoCell, 4, 0);
    const commodeCell = take(4); memory.writeMemory(commodeCell, 4, 0);
    const fmodeCell = take(4); memory.writeMemory(fmodeCell, 4, 0);
    // _acmdln: the char* the CRT reads for the raw ANSI command line. __p__acmdln
    // returns the address of this cell, which itself points at the quoted program
    // path the same startup already exposes through GetCommandLineA.
    const acmdlnCell = take(8); writePtr(acmdlnCell, commandLineAddressA);
    const wcmdlnCell = take(8); writePtr(wcmdlnCell, commandLineAddressW);
    return {
      base: crtScratchBase,
      argc: argCount,
      argcCell, argvCell, wargvCell, environCell, wenvironCell,
      environArray, wenvironArray, argvArray, wargvArray,
      errnoCell, commodeCell, fmodeCell, winmainLine, acmdlnCell, wcmdlnCell,
    };
  })();

  // The msvcrt C-runtime static block (BPTK-010 i386 CRT breadth). The FILE
  // table (_iob), the time-zone name vector (_tzname), the multibyte-max cell
  // (__mb_cur_max), and the fixed return buffers strerror/gmtime/setlocale/
  // localeconv hand back live at deterministic arena addresses, so a data
  // import resolves to real mapped memory and a pointer-returning CRT call is
  // reproducible per layout. The stream table maps a C fd to its backing HANDLE
  // (fd 0/1/2 are the standard streams); a _fdopen/_wfopen stream is a FILE the
  // arena hands out with its fd stored at FILE_FD_OFFSET.
  const crtRuntime = (() => {
    // A fixed page below the CRT startup block (which occupies the last 0x1000),
    // allocated with a local cursor so the arena bump cursor — and every
    // existing bump-allocated address — stays exactly where it was. The first
    // cells are the data-import placements (hleCrtDataLayout) so the IAT and
    // this writer agree on `_iob` / `_tzname` / `__mb_cur_max`.
    let cursor = crtData.cursor;
    const take = (sizeByte) => { const at = cursor; cursor += (sizeByte + 15) & ~15; return at; };
    const iobBase = crtData.iob_base;
    memory.writeBlock(iobBase, Buffer.alloc(FILE_STRUCT_BYTE * 3));
    for (let index = 0; index < 3; index += 1) {
      memory.writeMemory(iobBase + index * FILE_STRUCT_BYTE + FILE_FD_OFFSET, 4, index);
    }
    const utcAddress = crtData.utc_address;
    writeAnsiString(utcAddress, "UTC", 4);
    const tznameBase = crtData.tzname_base;
    memory.writeMemory(tznameBase, 4, utcAddress);
    memory.writeMemory(tznameBase + 4, 4, utcAddress);
    const mbCurMaxCell = crtData.mb_cur_max_cell;
    memory.writeMemory(mbCurMaxCell, 4, 1);
    const strerrorBuf = take(64);
    const tmBuf = take(9 * 4);
    const localeName = take(2);
    writeAnsiString(localeName, "C", 2);
    const decimalPoint = take(2);
    writeAnsiString(decimalPoint, ".", 2);
    const emptyString = take(1);
    memory.writeMemory(emptyString, 1, 0);
    // struct lconv: decimal_point at offset 0 is "." in the "C" locale; every
    // other char* member points at the empty string, the numeric members hold
    // CHAR_MAX (127) meaning "unspecified".
    const lconv = take(56);
    memory.writeBlock(lconv, Buffer.alloc(56, 127));
    memory.writeMemory(lconv, 4, decimalPoint);
    for (let offset = 4; offset <= 24; offset += 4) memory.writeMemory(lconv + offset, 4, emptyString);
    return { iobBase, tznameBase, mbCurMaxCell, strerrorBuf, tmBuf, localeName, lconv, utcAddress, decimalPoint, emptyString };
  })();

  function createHeapObject(maximumByte) {
    if (heapList.length >= hleBound.heap_count) {
      setLastError(errorValue.not_enough_memory);
      return null;
    }
    // The process default heap (maximumByte 0) is sized to most of the arena so
    // a real game's startup allocation fits — Chocolate Doom's Z_Init asks its
    // zone allocator for several MiB in one malloc, far past the historical
    // 64 KiB default. The heap base is the arena cursor (independent of this
    // size), so a larger default heap does not move any allocation address; it
    // only widens the free block. An explicit HeapCreate keeps its requested
    // size. The size stays within the arena so the bump allocator never overruns.
    const requestByte = maximumByte === 0 ? Math.floor(layout.arena_size_byte * 3 / 4) : maximumByte;
    const sizeByte = Math.min(Math.max(requestByte, 0x10000), hleBound.arena_byte);
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
    pending_guest_call: null,
    pending_seh: null,
    seh_transfer: null,
    user,
    gdi,
    gl,
    sdl,
    return_edx: undefined,
    net,
    gamepad,
    environment,
    commandLineAddressA,
    commandLineAddressW,
    pointer_size_byte: pointerSizeByte,
    filter_address: 0,
    error_mode: 0,
    execution_state: 0x80000000,
    com_apartment: null,
    com_refcount: 0,
    timer_period: 0,
    crt,
    crtRuntime,
    // The deterministic C rand() state (seed 1) and the C fd table the msvcrt
    // stdio surface owns; fd 3 upward wrap a virtual-drive HANDLE.
    rand_state: 1,
    crt_fd_table: new Map(),
    crt_fd_next: 3,
    app_type: 0,
    new_mode: 0,
    invalid_parameter_handler: 0,
    wsa_event_select: new Map(),
    console_ctrl_handler: [],
    console_ctrl_ignore: false,
    current_tid: hleProfile.thread_id,
    worker_count: 0,
    worker_tls: new Map(),
    worker_fls: new Map(),
    on_create_thread: null,
    park_wait: null,
    park_sleep: null,
    after_signal: null,
    after_wake_address: null,
    park_address: null,
    pending_thread_switch: null,
    thread_local_atexit_dtor: 0,
    layout,
    readAnsiString,
    readWideString,
    writeAnsiString,
    writeWideString,
    allocate: (sizeByte) => arena.allocate(sizeByte),
    last_file_path: null,

    console_attribute: 7,
    getLastError: () => lastError,
    setLastError: (value) => {
      lastError = value & 0xffffffff;
    },

    isThunk: (address) => exportByThunk.has(unsigned(address)),
    exportAt: (address) => exportByThunk.get(unsigned(address)) ?? null,
    lookupExport: (library, symbol) => resolveHleExport(library, symbol),
    thunkOf: (library, symbol) => {
      const resolved = resolveHleExport(library, symbol);
      if (resolved === null) return thunkByExport.get(`${library}!${symbol}`) ?? null;
      return thunkByExport.get(`${resolved.library}!${resolved.symbol}`) ?? null;
    },

    // One stdcall dispatch: runs the emulator, records the trace, and maps
    // the exit and exception signal into the structured stop the probe owns.
    invokeExport(entry, argument) {
      if (callCount >= hleBound.trace_count) throw hleFault("hle_trace_exhausted", `The HLE call trace exceeds ${hleBound.trace_count} entry`);
      let value;
      try {
        // A 32-bit result zero-extends (`>>> 0`); a pointer into memory above
        // 4 GiB — the x64 stack/image address a routine like strrchr returns —
        // does not fit in 32 bits, so a positive integer above 0xffffffff is
        // preserved at full width instead of truncated. Every i386 conformance
        // value stays at or below 0xffffffff, so `>>> 0` is identity for it.
        const raw = entry.emulate(guest, argument);
        value = typeof raw === "number" && Number.isInteger(raw) && raw > 0xffffffff ? raw : raw >>> 0;
      } catch (error) {
        if (isHleSignal(error) && (error.signal === "hle_exit" || error.signal === "hle_guest_exception")) {
          // The call happened: the exit and exception signal carry the
          // guest-visible result, so the trace records the call before the
          // stop propagates.
          const path = guest.last_file_path;
          guest.last_file_path = null;
          trace.push({ library: entry.library, symbol: entry.symbol, argument, value: (error.exit_code ?? error.exception_code ?? 0) >>> 0, last_error: lastError, path });
        }
        traceHash.update(Buffer.from(`${entry.library}!${entry.symbol}\0${JSON.stringify(argument)}\0signal:${error.signal ?? "unknown"}\0`, "utf8"));
        callCount += 1;
        throw error;
      }
      trace.push({ library: entry.library, symbol: entry.symbol, argument, value, last_error: lastError, path: guest.last_file_path });
      traceHash.update(Buffer.from(`${entry.library}!${entry.symbol}\0${JSON.stringify(argument)}\0${value}\0${lastError}\0`, "utf8"));
      guest.last_file_path = null;
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
    listWrittenFile() {
      const out = [];
      for (const [path, file] of virtualDrive) {
        const data = file?.data ?? Buffer.alloc(0);
        const capped = data.subarray(0, Math.min(data.length, 4096));
        out.push({ path, size_byte: data.length, latin1: capped.toString("latin1") });
      }
      return out;
    },

    // --- module lookup --------------------------------------------------
    lookupModule(name) {
      if (name === null) return moduleTable[0].handle;
      return moduleByName.get(moduleKey(name))?.handle ?? 0;
    },
    verifyVersionInfo(info, typeMask, conditionMask) {
      const type = unsigned(typeMask);
      if (info === 0 || type === 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const size = memory.readMemory(info, 4);
      if (size < 20 || ((type & 0xf0) !== 0 && size < 284)) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const requested = {
        minor: memory.readMemory(info + 8, 4),
        major: memory.readMemory(info + 4, 4),
        build: memory.readMemory(info + 12, 4),
        platform: memory.readMemory(info + 16, 4),
        service_pack_minor: size >= 280 ? memory.readMemory(info + 278, 2) : 0,
        service_pack_major: size >= 278 ? memory.readMemory(info + 276, 2) : 0,
        suite: size >= 282 ? memory.readMemory(info + 280, 2) : 0,
        product: size >= 283 ? memory.readMemory(info + 282, 1) : 0,
      };
      const actual = {
        minor: hleProfile.version_minor,
        major: hleProfile.version_major,
        build: hleProfile.version_build,
        platform: hleProfile.version_platform_id,
        service_pack_minor: hleProfile.service_pack_minor,
        service_pack_major: hleProfile.service_pack_major,
        suite: hleProfile.suite_mask,
        product: hleProfile.product_type,
      };
      const field = [
        [versionTypeBit.minor, actual.minor, requested.minor, 0],
        [versionTypeBit.major, actual.major, requested.major, 1],
        [versionTypeBit.build, actual.build, requested.build, 2],
        [versionTypeBit.platform, actual.platform, requested.platform, 3],
        [versionTypeBit.service_pack_minor, actual.service_pack_minor, requested.service_pack_minor, 4],
        [versionTypeBit.service_pack_major, actual.service_pack_major, requested.service_pack_major, 5],
      ];
      for (const [bit, actualValue, requestedValue, bitIndex] of field) {
        if ((type & bit) === 0) continue;
        if (!compareVersionField(actualValue, requestedValue, verConditionAt(conditionMask, bitIndex))) {
          setLastError(errorValue.old_win_version);
          return 0;
        }
      }
      if ((type & versionTypeBit.suite) !== 0) {
        const condition = verConditionAt(conditionMask, 6);
        const overlap = actual.suite & requested.suite;
        const ok = condition === 6
          ? overlap === requested.suite
          : condition === 7
            ? overlap !== 0
            : compareVersionField(actual.suite, requested.suite, condition);
        if (!ok) {
          setLastError(errorValue.old_win_version);
          return 0;
        }
      }
      if ((type & versionTypeBit.product) !== 0 && !compareVersionField(actual.product, requested.product, verConditionAt(conditionMask, 7))) {
        setLastError(errorValue.old_win_version);
        return 0;
      }
      return 1;
    },
    lookupModuleByAddress(address) {
      const imageBase = option.image_base ?? 0;
      const imageEnd = imageBase + (option.image_size_byte ?? 0);
      if (imageEnd > imageBase && address >= imageBase && address < imageEnd) return moduleTable[0].handle;
      for (const module of moduleTable) {
        if (!module.is_sidecar) continue;
        const start = module.handle >>> 0;
        const end = start + (module.image_size_byte ?? 0);
        if (end > start && address >= start && address < end) return start;
      }
      return 0;
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
      guest.last_file_path = `${module.name}!${name}`;
      const resolved = resolveHleExport(module.name, name);
      if (resolved?.kind === "data") {
        const data = hleDataExportAddress(layout, resolved.symbol);
        if (data !== null) return data;
      }
      const thunk = thunkByExport.get(`${module.name}!${name}`)
        ?? (resolved ? thunkByExport.get(`${resolved.library}!${resolved.symbol}`) : null)
        ?? null;
      if (thunk !== null) return thunk;
      const sidecarVa = module.exportByName?.get(name);
      if (sidecarVa !== undefined) return sidecarVa;
      setLastError(errorValue.proc_not_found);
      return 0;
    },
    moduleName(moduleHandle) {
      const module = moduleTable.find((entry) => entry.handle === unsigned(moduleHandle));
      return module?.name ?? null;
    },
    modulePath(moduleHandle) {
      // Win32: a NULL hModule is the current process image. The leftover
      // 0x00020001 synthetic handle stays an alias of that image when the
      // mapped HMODULE is the load base instead of the table-driven window.
      const handle = unsigned(moduleHandle);
      const module = handle === 0 || handle === 0x00020001
        ? moduleTable.find((entry) => entry.is_main)
        : moduleTable.find((entry) => entry.handle === handle);
      if (module === undefined) return null;
      return module.is_main ? `${hleProfile.guest_root}\\${module.name}` : `${hleProfile.system_directory}\\${module.name}`;
    },
    currentThreadHandle() {
      if (threadHandle === 0) threadHandle = allocateHandle("std_thread", {});
      return threadHandle;
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
    // ucrt malloc uses __acrt_heap, which stays 0 when DllMain skipped
    // HeapCreate. A null handle is the process heap, not an invalid object.
    resolveHeapHandle(handle) {
      return unsigned(handle) === 0 ? guest.defaultHeapHandle() : unsigned(handle);
    },
    heapFor(handle) {
      return heapList.find((heap) => heap.handle === unsigned(handle)) ?? null;
    },
    heapAllocate(handle, flag, sizeByte) {
      const heap = guest.heapFor(guest.resolveHeapHandle(handle));
      if (heap === null) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      const size = Math.min((Math.max(sizeByte, 1) + 7) & ~7, heap.size_byte);
      const address = allocateBlock(heap, size);
      if (address === 0) {
        setLastError(errorValue.not_enough_memory);
        return 0;
      }
      if ((flag & heapFlag.zero_memory) !== 0) memory.writeBlock(address, Buffer.alloc(size));
      return address;
    },
    heapReAllocate(handle, flag, address, sizeByte) {
      const heap = guest.heapFor(guest.resolveHeapHandle(handle));
      const previousSize = heap?.allocation.get(unsigned(address));
      if (heap === null || previousSize === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      const size = Math.min((Math.max(sizeByte, 1) + 7) & ~7, heap.size_byte);
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
      const heap = guest.heapFor(guest.resolveHeapHandle(handle));
      const previousSize = heap?.allocation.get(unsigned(address));
      if (heap === null || previousSize === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      releaseBlock(heap, unsigned(address), previousSize);
      return 1;
    },
    heapSize(handle, flag, address) {
      const heap = guest.heapFor(guest.resolveHeapHandle(handle));
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
      const start = unsigned(address);
      const span = Math.max(unsigned(sizeByte), 1);
      const imageBase = option.image_base ?? 0;
      const imageEnd = imageBase + (option.image_size_byte ?? 0);
      let mappedProtect = 0;
      if (imageEnd > imageBase && start >= imageBase && start + span <= imageEnd) mappedProtect = 0x40;
      else {
        for (const module of option.sidecar ?? []) {
          const moduleStart = module.load_base >>> 0;
          const moduleEnd = moduleStart + (module.image_size_byte ?? 0);
          if (moduleEnd > moduleStart && start >= moduleStart && start + span <= moduleEnd) {
            mappedProtect = 0x40;
            break;
          }
        }
      }
      if (mappedProtect !== 0) {
        // The interpreter does not enforce page protect on the PE image; the
        // call still has to succeed so ucrt can encode a delay-load IAT slot.
        if (oldProtectPointer !== 0) memory.writeMemory(oldProtectPointer, 4, mappedProtect);
        return 1;
      }
      const region = guest.virtualRegionAt(start, span);
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
      let section = criticalSection.get(unsigned(address));
      if (section === undefined) {
        // ucrt leaves some process locks as a zero CRITICAL_SECTION in .data
        // and enters them on first use. Adopt that zeroed cell the way
        // InitializeCriticalSection would, rather than inventing a lock at a
        // random address: any non-zero leftover still fails honestly.
        let isZero = true;
        try {
          for (let off = 0; off < 24; off += 4) {
            if (memory.readMemory(unsigned(address) + off, 4) !== 0) isZero = false;
          }
        } catch {
          isZero = false;
        }
        if (!isZero) {
          throw hleFault("hle_critical_section_invalid", `The critical section at 0x${unsigned(address).toString(16)} is not initialized`, { address: unsigned(address) });
        }
        this.initializeCriticalSection(address, 0);
        section = criticalSection.get(unsigned(address));
      }
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
      if (index >= hleBound.tls_slot_count || tlsSlot[index] === null) return 0;
      if (guest.current_tid !== hleProfile.thread_id) {
        const overlay = guest.worker_tls.get(guest.current_tid);
        if (overlay !== undefined && overlay.has(index)) return overlay.get(index);
        return 0;
      }
      return tlsSlot[index].value;
    },
    writeTls(index, value) {
      if (index >= hleBound.tls_slot_count || tlsSlot[index] === null) {
        setLastError(errorValue.invalid_parameter);
        return false;
      }
      if (guest.current_tid !== hleProfile.thread_id) {
        let overlay = guest.worker_tls.get(guest.current_tid);
        if (overlay === undefined) {
          overlay = new Map();
          guest.worker_tls.set(guest.current_tid, overlay);
        }
        overlay.set(index, unsigned(value));
        return true;
      }
      tlsSlot[index].value = unsigned(value);
      return true;
    },

    // --- FLS (fiber-local storage) ----------------------------------------------
    // The ucrt startup allocates one FLS index for its per-thread data before it
    // reaches main. The bounded world runs a single fiber, so an FLS index is a
    // value slot exactly like a TLS index; the optional destructor callback is
    // recorded but only ever fires on fiber/thread teardown, which the bounded
    // probe does not reach, so storing it is honest rather than a dropped hook.
    //
    // MSVC leaves the index at FLS_OUT_OF_INDEXES until FlsAlloc runs. When
    // DllMain skipped that alloc, the CRT still FlsGet/Set(0xffffffff). The
    // single-fiber world keeps one reserved slot for that sentinel so the
    // per-thread block can land instead of throwing std::bad_alloc.
    implicitFls: { value: 0, callback: 0 },
    allocateFls(callback) {
      const index = flsSlot.findIndex((value) => value === null);
      if (index < 0) {
        setLastError(errorValue.not_enough_memory);
        return errorValue.fls_out_of_indexes;
      }
      flsSlot[index] = { value: 0, callback: unsigned(callback) };
      return index;
    },
    freeFls(index) {
      if (index >= hleBound.fls_slot_count || flsSlot[index] === null) {
        setLastError(errorValue.invalid_parameter);
        return false;
      }
      flsSlot[index] = null;
      return true;
    },
    readFls(index) {
      const id = unsigned(index);
      if (guest.current_tid !== hleProfile.thread_id) {
        const overlay = guest.worker_fls.get(guest.current_tid);
        if (id === errorValue.fls_out_of_indexes) return overlay?.get(-1) ?? 0;
        if (overlay !== undefined && overlay.has(id)) return overlay.get(id);
        return 0;
      }
      if (id === errorValue.fls_out_of_indexes) return guest.implicitFls.value;
      return id < hleBound.fls_slot_count && flsSlot[id] !== null ? flsSlot[id].value : 0;
    },
    writeFls(index, value) {
      const id = unsigned(index);
      if (guest.current_tid !== hleProfile.thread_id) {
        let overlay = guest.worker_fls.get(guest.current_tid);
        if (overlay === undefined) {
          overlay = new Map();
          guest.worker_fls.set(guest.current_tid, overlay);
        }
        if (id === errorValue.fls_out_of_indexes) {
          overlay.set(-1, unsigned(value));
          return true;
        }
        if (id >= hleBound.fls_slot_count || flsSlot[id] === null) {
          setLastError(errorValue.invalid_parameter);
          return false;
        }
        overlay.set(id, unsigned(value));
        return true;
      }
      if (id === errorValue.fls_out_of_indexes) {
        guest.implicitFls.value = unsigned(value);
        return true;
      }
      if (id >= hleBound.fls_slot_count || flsSlot[id] === null) {
        setLastError(errorValue.invalid_parameter);
        return false;
      }
      flsSlot[id].value = unsigned(value);
      return true;
    },

    // --- structured exception dispatch (BPTK-053) -------------------------------
    // The per-thread SEH machine is reachable so a wired substrate can register
    // vectored handlers and push fs:[0] frames; RaiseException already routes
    // through it below.
    seh_thread: sehThread,
    // A guest vectored handler is opaque code on the legacy path, so the
    // registered entry records the handler address and returns the opaque
    // handle the guest later passes to remove; no guest code runs here.
    addVectoredHandler(isFirst, handlerAddress) {
      if (unsigned(handlerAddress) === 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      return sehThread.addVectored(isFirst !== 0, () => 0);
    },
    removeVectoredHandler(handle) {
      return sehThread.removeVectored(handle) ? 1 : 0;
    },
    // RaiseException walks the live FS:[0] chain the guest pushed (TEB+0), not
    // the empty host-side SehThread. A frame whose handler is guest code is
    // re-entered through pending_guest_call and returns EXCEPTION_DISPOSITION
    // (0 continue, 1 search). An empty chain is still the structured
    // guest_exception stop.
    raiseStructuredException(code, flag, argument) {
      const trace = raiseException(sehThread, code, flag, argument);
      if (trace.is_handled || trace.is_continued) return 0;
      const teb = layout.teb_base;
      let frame = 0xffffffff;
      if (teb !== undefined) {
        try {
          frame = unsigned(memory.readMemory(teb, 4));
        } catch {
          frame = 0xffffffff;
        }
      }
      if (frame === 0 || frame === 0xffffffff) return raiseGuestException(unsigned(code));
      if (process.env.BPTK_SEH_TRACE === "1") {
        const chain = [];
        for (let walk = frame, guard = 0; walk !== 0 && walk !== 0xffffffff && guard < 16; guard += 1) {
          const next = unsigned(memory.readMemory(walk, 4));
          const handlerAt = unsigned(memory.readMemory(walk + 4, 4));
          chain.push({ frame: `0x${walk.toString(16)}`, next: `0x${next.toString(16)}`, handler: `0x${handlerAt.toString(16)}` });
          walk = next;
        }
        process.stderr.write(`RaiseException chain ${JSON.stringify(chain)}\n`);
      }
      const handler = unsigned(memory.readMemory(frame + 4, 4));
      if (handler === 0) return raiseGuestException(unsigned(code));
      const record = arena.allocate(0x50);
      memory.writeBlock(record, Buffer.alloc(0x50));
      memory.writeMemory(record, 4, unsigned(code));
      memory.writeMemory(record + 4, 4, unsigned(flag));
      const count = Math.min(argument.length, 15);
      memory.writeMemory(record + 16, 4, count);
      for (let index = 0; index < count; index += 1) memory.writeMemory(record + 20 + index * 4, 4, unsigned(argument[index]));
      const context = arena.allocate(0x2cc);
      memory.writeBlock(context, Buffer.alloc(0x2cc));
      guest.pending_seh = { code: unsigned(code), flag: unsigned(flag), record, context, frame };
      guest.pending_guest_call = {
        kind: "seh_handler",
        proc: handler,
        argument: [record, frame, context, 0],
        result_kind: "seh_disposition",
      };
      return 0;
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
      const stored = stdSlot.get(key);
      if (stored !== undefined) return stored;
      if (key === stdHandle.input) return stdSlot.set(key, allocateHandle("std_input", { is_input: true })).get(key);
      if (key === stdHandle.output) return stdSlot.set(key, allocateHandle("std_output", { is_input: false })).get(key);
      if (key === stdHandle.error) return stdSlot.set(key, allocateHandle("std_error", { is_input: false })).get(key);
      setLastError(errorValue.invalid_parameter);
      return 0xffffffff;
    },
    setStandardHandle(which, handle) {
      const key = which | 0;
      if (key !== stdHandle.input && key !== stdHandle.output && key !== stdHandle.error) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      stdSlot.set(key, unsigned(handle));
      return 1;
    },
    writeOutput(handle, bufferAddress, countByte, writtenPointer, isOverlapped) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      if (record.kind === "file") return guest.writeFileData(record, bufferAddress, countByte, writtenPointer, isOverlapped);
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

    // --- virtual drive (BPTK-015 slice) -------------------------------------------------
    openFile(name, access, disposition, flags = 0) {
      if (disposition < fileDisposition.create_new || disposition > fileDisposition.truncate_existing) {
        setLastError(errorValue.invalid_parameter);
        return 0xffffffff;
      }
      // Win32 CreateFile("") is PATH_NOT_FOUND, not INVALID_PARAMETER. A game
      // that probes an empty env-var datadir treats 2/3 as "try the next
      // candidate" and 87 as a hard failure.
      if (name === null || name.length === 0) {
        setLastError(errorValue.path_not_found);
        return 0xffffffff;
      }
      const path = normalizeDrivePath(guest.resolveGuestPath(name));
      guest.last_file_path = path ?? name;
      if (path === null) {
        setLastError(errorValue.invalid_parameter);
        return 0xffffffff;
      }
      if ([...handleTable.values()].filter((entry) => entry.kind === "file").length >= hleBound.file_open_count) {
        setLastError(errorValue.too_many_open_files);
        return 0xffffffff;
      }
      if (isDirectoryPath(path) && !virtualDrive.has(path) && hostFile.get(path) === undefined) {
        if (disposition === fileDisposition.open_existing || disposition === fileDisposition.open_always) {
          if ((unsigned(flags) & fileFlag.backup_semantics) === 0) {
            setLastError(errorValue.access_denied);
            return 0xffffffff;
          }
          return allocateHandle("file", { path, data: Buffer.alloc(0), drive: null, position: 0, access: unsigned(access), is_directory: true });
        }
        setLastError(errorValue.access_denied);
        return 0xffffffff;
      }
      // A read-open of a staged host file (the IWAD/asset) returns a read-only
      // handle over the real bytes, before the writable-drive path. The writable
      // drive shadows a host file of the same path if the guest created one, so
      // a config write never reaches the read-only asset.
      const host = hostFile.get(path);
      if (host !== undefined && !virtualDrive.has(path) && (disposition === fileDisposition.open_existing || disposition === fileDisposition.open_always)) {
        return allocateHandle("file", { path, data: host, drive: null, position: 0, access: fileAccess.generic_read, readonly: true });
      }
      let file = virtualDrive.get(path);
      if (file === undefined) {
        if (disposition === fileDisposition.open_existing || disposition === fileDisposition.truncate_existing) {
          setLastError(errorValue.file_not_found);
          return 0xffffffff;
        }
        if (driveTotalByte + hleBound.file_size_byte > hleBound.file_total_byte) {
          setLastError(errorValue.disk_full);
          return 0xffffffff;
        }
        file = { data: Buffer.alloc(0) };
        virtualDrive.set(path, file);
        driveTotalByte += hleBound.file_size_byte;
      } else if (disposition === fileDisposition.create_new) {
        setLastError(errorValue.file_exists);
        return 0xffffffff;
      } else if (disposition === fileDisposition.truncate_existing || disposition === fileDisposition.create_always) {
        file.data = Buffer.alloc(0);
      }
      return allocateHandle("file", { path, data: file.data, drive: virtualDrive, position: 0, access: unsigned(access) });
    },
    readFile(handle, bufferAddress, countByte, writtenPointer, isOverlapped) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      if (record.kind !== "file") {
        // The probe console is declared output-only: no input service exists.
        setLastError(errorValue.access_denied);
        return 0;
      }
      if (isOverlapped || (record.object.access & fileAccess.generic_read) === 0) {
        setLastError(errorValue.access_denied);
        return 0;
      }
      const readByte = Math.min(Math.max(countByte, 0), Math.max(record.object.data.length - record.object.position, 0));
      if (readByte > 0) memory.writeBlock(bufferAddress, record.object.data.subarray(record.object.position, record.object.position + readByte));
      record.object.position += readByte;
      if (writtenPointer !== 0) memory.writeMemory(writtenPointer, 4, readByte);
      return 1;
    },
    writeFileData(record, bufferAddress, countByte, writtenPointer, isOverlapped) {
      if (isOverlapped || (record.object.access & fileAccess.generic_write) === 0) {
        setLastError(errorValue.access_denied);
        return 0;
      }
      if (countByte > hleBound.file_size_byte || record.object.position + countByte > hleBound.file_size_byte) {
        setLastError(errorValue.disk_full);
        return 0;
      }
      const data = countByte === 0 ? Buffer.alloc(0) : memory.readBlock(bufferAddress, countByte);
      const end = record.object.position + countByte;
      if (end > record.object.data.length) record.object.data = Buffer.concat([record.object.data, Buffer.alloc(end - record.object.data.length)]);
      data.copy(record.object.data, record.object.position);
      const driveFile = record.object.drive.get(record.object.path);
      if (driveFile !== undefined) driveFile.data = record.object.data;
      record.object.position = end;
      if (writtenPointer !== 0) memory.writeMemory(writtenPointer, 4, countByte);
      return 1;
    },
    seekFile(handle, distanceLow, distanceHigh, newPointer, origin) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind !== "file") {
        setLastError(errorValue.invalid_handle);
        return 0xffffffff;
      }
      if (origin < fileMethod.begin || origin > fileMethod.end) {
        setLastError(errorValue.invalid_parameter);
        return 0xffffffff;
      }
      const distance = BigInt.asIntN(64, (BigInt(unsigned(distanceHigh)) << 32n) | BigInt(unsigned(distanceLow)));
      const base = origin === fileMethod.begin ? 0n : origin === fileMethod.current ? BigInt(record.object.position) : BigInt(record.object.data.length);
      const next = base + distance;
      if (next < 0n) {
        setLastError(errorValue.negative_seek);
        return 0xffffffff;
      }
      record.object.position = Number(next);
      if (newPointer !== 0) {
        memory.writeMemory(newPointer, 4, Number(next & 0xffffffffn));
        memory.writeMemory(newPointer + 4, 4, Number(next >> 32n & 0xffffffffn));
      }
      return 0;
    },
    truncateFile(handle) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind !== "file") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      record.object.data = record.object.data.subarray(0, record.object.position);
      const driveFile = record.object.drive.get(record.object.path);
      if (driveFile !== undefined) driveFile.data = record.object.data;
      return 1;
    },
    // --- msvcrt C runtime (BPTK-010 i386 CRT breadth) -----------------------
    // errno lives in the fixed CRT cell; every CRT failure records it there.
    crtErrno(value) {
      if (value !== undefined) memory.writeMemory(crt.errnoCell, 4, unsigned(value));
      return memory.readMemory(crt.errnoCell, 4);
    },
    // malloc/calloc/realloc/free run over the one process default heap, so the
    // block bytes are real and a later HeapSize or free finds them.
    crtMalloc(sizeByte) {
      return guest.heapAllocate(guest.defaultHeapHandle(), 0, Math.max(unsigned(sizeByte), 1));
    },
    crtCalloc(count, sizeByte) {
      const total = unsigned(count) * unsigned(sizeByte);
      return guest.heapAllocate(guest.defaultHeapHandle(), heapFlag.zero_memory, Math.max(total, 1));
    },
    crtRealloc(address, sizeByte) {
      if (unsigned(address) === 0) return guest.crtMalloc(sizeByte);
      if (unsigned(sizeByte) === 0) { guest.crtFree(address); return 0; }
      return guest.heapReAllocate(guest.defaultHeapHandle(), 0, unsigned(address), unsigned(sizeByte));
    },
    crtFree(address) {
      if (unsigned(address) !== 0) guest.heapFree(guest.defaultHeapHandle(), 0, unsigned(address));
      return 0;
    },
    // _msize returns the usable byte count of a live block over the same heap,
    // so it agrees with the size malloc/realloc actually reserved.
    crtMsize(address) {
      if (unsigned(address) === 0) return 0;
      return guest.heapSize(guest.defaultHeapHandle(), 0, unsigned(address));
    },
    // _recalloc resizes a block and zero-fills the grown tail, over the one heap.
    crtRecalloc(address, count, sizeByte) {
      const total = unsigned(count) * unsigned(sizeByte);
      if (unsigned(address) === 0) return guest.heapAllocate(guest.defaultHeapHandle(), heapFlag.zero_memory, Math.max(total, 1));
      if (total === 0) { guest.crtFree(address); return 0; }
      return guest.heapReAllocate(guest.defaultHeapHandle(), heapFlag.zero_memory, unsigned(address), total);
    },
    // A FILE* resolves to its C fd: a pointer inside the _iob array is the
    // standard-stream index; any other FILE carries its fd at FILE_FD_OFFSET.
    crtStreamFd(filePointer) {
      const value = unsigned(filePointer);
      const base = crtRuntime.iobBase;
      if (value >= base && value < base + FILE_STRUCT_BYTE * 3) return (value - base) / FILE_STRUCT_BYTE | 0;
      return signed32(memory.readMemory(value + FILE_FD_OFFSET, 4));
    },
    // Route count byte to a C fd: 1/2 are the captured console, a table fd is a
    // virtual-drive file, and stdin/absent fd refuse with EBADF.
    crtWriteFd(fd, buffer) {
      if (fd === 1 || fd === 2) {
        if (buffer.length > hleBound.output_byte || outputByteCount + buffer.length > hleBound.output_byte) {
          throw hleFault("hle_output_bound_exceeded", `The captured output exceeds the declared ${hleBound.output_byte} byte bound`, { bound_byte: hleBound.output_byte });
        }
        if (buffer.length > 0) { outputChunk.push(Buffer.from(buffer)); outputByteCount += buffer.length; }
        return buffer.length;
      }
      const record = fd >= 3 ? handleTable.get(unsigned(guest.crt_fd_table.get(fd) ?? 0)) : undefined;
      if (record === undefined || record.kind !== "file") { guest.crtErrno(crtErrnoValue.ebadf); return -1; }
      const end = record.object.position + buffer.length;
      if (buffer.length > hleBound.file_size_byte || end > hleBound.file_size_byte) { guest.crtErrno(crtErrnoValue.erange); return -1; }
      if (end > record.object.data.length) record.object.data = Buffer.concat([record.object.data, Buffer.alloc(end - record.object.data.length)]);
      Buffer.from(buffer).copy(record.object.data, record.object.position);
      const driveFile = record.object.drive.get(record.object.path);
      if (driveFile !== undefined) driveFile.data = record.object.data;
      record.object.position = end;
      return buffer.length;
    },
    // Emit a byte stream to a FILE* (stdout/stderr → console, file → drive).
    crtWriteStream(filePointer, buffer) {
      return guest.crtWriteFd(guest.crtStreamFd(filePointer), buffer);
    },
    // _open: translate the C oflag to a Win32 access/disposition and open the
    // virtual-drive file, then bind a fresh fd to the HANDLE.
    crtOpen(pathAddress, oflag, isWide) {
      const path = isWide ? readWideString(pathAddress) : readAnsiString(pathAddress);
      if (path === null) { guest.crtErrno(crtErrnoValue.einval); return -1; }
      const writing = (oflag & 0x0003) !== 0 || (oflag & 0x0100) !== 0; // _O_WRONLY/_O_RDWR/_O_CREAT
      const access = (writing ? fileAccess.generic_write : 0) | fileAccess.generic_read;
      const disposition = (oflag & 0x0200) !== 0 // _O_CREAT|_O_TRUNC
        ? ((oflag & 0x0400) !== 0 ? fileDisposition.truncate_existing : fileDisposition.create_always)
        : (oflag & 0x0100) !== 0 ? fileDisposition.open_always : fileDisposition.open_existing;
      const handle = guest.openFile(path, access, disposition);
      if (unsigned(handle) === 0xffffffff) {
        guest.crtErrno(guest.getLastError() === errorValue.file_not_found ? crtErrnoValue.enoent : crtErrnoValue.einval);
        return -1;
      }
      const fd = guest.crt_fd_next;
      guest.crt_fd_next += 1;
      guest.crt_fd_table.set(fd, unsigned(handle));
      return fd;
    },
    // _wmkdir/_mkdir: a game creates its configuration/save directory at
    // startup (Chocolate Doom's M_MakeDirectory over the config dir). The
    // bounded world keys files by their full path, so a directory is a real
    // recorded node in the writable virtual drive rather than a host mkdir:
    // record it in virtualDir under the same c:\ path space, return 0 on a
    // valid path (already-exists is success too, which is what the config path
    // needs), and refuse an out-of-tree or malformed path with EINVAL.
    crtMkdir(pathAddress, isWide) {
      const raw = isWide ? readWideString(pathAddress) : readAnsiString(pathAddress);
      const path = normalizeDrivePath(raw);
      if (path === null) { guest.crtErrno(crtErrnoValue.einval); return -1; }
      virtualDir.add(path);
      return 0;
    },
    // The live virtual-drive file record behind a FILE* (a stdio stream over a
    // real bounded file), or null for a standard stream or an absent fd. Gives
    // fscanf/feof direct read access to the file bytes and position.
    crtFileRecord(filePointer) {
      const fd = guest.crtStreamFd(filePointer);
      if (fd <= 2) return null;
      const handle = guest.crt_fd_table.get(fd);
      if (handle === undefined) return null;
      const record = handleTable.get(unsigned(handle));
      return record !== undefined && record.kind === "file" ? record : null;
    },
    // feof over a real file: true once the read position has reached the end.
    // A standard stream reports not-at-end (0): it is not an error state, and a
    // config-read loop keyed on !feof(stdin) must not terminate before it reads.
    crtFeof(filePointer) {
      const record = guest.crtFileRecord(filePointer);
      if (record === null) return 0;
      return record.object.position >= record.object.data.length ? 1 : 0;
    },
    // fseek/ftell over a real file (SEEK_SET=0, SEEK_CUR=1, SEEK_END=2). A game
    // sizes its WAD by seeking to the end and reading the position, then seeks
    // back and reads the directory and lumps.
    crtFseek(filePointer, offset, origin) {
      const record = guest.crtFileRecord(filePointer);
      if (record === null) { guest.crtErrno(crtErrnoValue.ebadf); return -1; }
      const base = origin === 1 ? record.object.position : origin === 2 ? record.object.data.length : 0;
      const next = base + offset;
      if (next < 0) { guest.crtErrno(crtErrnoValue.einval); return -1; }
      record.object.position = next;
      return 0;
    },
    crtFtell(filePointer) {
      const record = guest.crtFileRecord(filePointer);
      if (record === null) { guest.crtErrno(crtErrnoValue.ebadf); return -1; }
      return record.object.position;
    },
    // fread size*count byte from the file at its position into the guest buffer
    // (already full-width). Returns the number of complete items read; a short
    // read at end-of-file returns fewer, the C contract W_ReadLump relies on.
    crtFread(bufferAddress, size, count, filePointer) {
      const record = guest.crtFileRecord(filePointer);
      if (record === null || size <= 0 || count <= 0) return 0;
      const total = size * count;
      const available = Math.max(record.object.data.length - record.object.position, 0);
      const readByte = Math.min(total, available);
      if (readByte > 0) guest.memory.writeBlock(bufferAddress, record.object.data.subarray(record.object.position, record.object.position + readByte));
      record.object.position += readByte;
      return Math.floor(readByte / size);
    },
    crtClose(fd) {
      if (fd === 0 || fd === 1 || fd === 2) return 0;
      const handle = guest.crt_fd_table.get(fd);
      if (handle === undefined) { guest.crtErrno(crtErrnoValue.ebadf); return -1; }
      guest.closeHandle(handle);
      guest.crt_fd_table.delete(fd);
      return 0;
    },
    crtOsHandle(fd) {
      if (fd === 0) return unsigned(guest.standardHandle(stdHandle.input));
      if (fd === 1) return unsigned(guest.standardHandle(stdHandle.output));
      if (fd === 2) return unsigned(guest.standardHandle(stdHandle.error));
      const handle = guest.crt_fd_table.get(fd);
      if (handle === undefined) { guest.crtErrno(crtErrnoValue.ebadf); return 0xffffffff; }
      return unsigned(handle);
    },
    // Wrap a C fd in a FILE the arena hands out, storing the fd for later
    // _fileno / stdio routing. mode is advisory in the bounded world.
    crtFdopen(fd) {
      if (fd < 0) return 0;
      const file = arena.allocate(FILE_STRUCT_BYTE);
      memory.writeBlock(file, Buffer.alloc(FILE_STRUCT_BYTE));
      memory.writeMemory(file + FILE_FD_OFFSET, 4, unsigned(fd));
      return file;
    },
    // The size in byte of a virtual-drive file, or null when it does not exist.
    virtualFileSize(name) {
      const path = normalizeDrivePath(name);
      if (path === null) return null;
      const file = virtualDrive.get(path);
      if (file !== undefined) return file.data.length;
      const host = hostFile.get(path);
      return host === undefined ? null : host.length;
    },
    // A counted semaphore handle (bounded single-thread synchronization).
    createSemaphore(initialCount, maximumCount, namePointer = 0, isWide = false) {
      const max = maximumCount > 0 ? maximumCount : 1;
      const initial = Math.min(Math.max(initialCount, 0), max);
      const name = namePointer === 0 ? null : (isWide ? guest.readWideString(namePointer) : guest.readAnsiString(namePointer));
      if (name !== null) {
        for (const [handle, record] of handleTable) {
          if (record.kind === "semaphore" && record.object.name === name) {
            setLastError(errorValue.file_exists); // ERROR_ALREADY_EXISTS
            return handle;
          }
        }
      }
      return allocateHandle("semaphore", { name, count: initial, max });
    },
    releaseSemaphore(handle, releaseCount, previousPointer) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind !== "semaphore") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      const previous = record.object.count;
      if (releaseCount <= 0 || previous + releaseCount > record.object.max) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      record.object.count = previous + releaseCount;
      if (unsigned(previousPointer) !== 0) memory.writeMemory(unsigned(previousPointer), 4, previous);
      if (typeof guest.after_signal === "function") guest.after_signal();
      return 1;
    },
    openProcessToken(access) {
      return allocateHandle("token", { access: unsigned(access) });
    },
    closeHandle(handle) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind === "registry") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      if (record.kind === "find") findSession.delete(unsigned(handle));
      handleTable.delete(unsigned(handle));
      return 1;
    },
    handleRecord(handle) {
      return handleTable.get(unsigned(handle));
    },
    fileSizeEx(handle, outPointer) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind !== "file") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      if (outPointer === 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const size = BigInt(record.object.data.length);
      memory.writeMemory(outPointer, 4, Number(size & 0xffffffffn));
      memory.writeMemory(outPointer + 4, 4, Number(size >> 32n & 0xffffffffn));
      return 1;
    },
    resourceKey(pointer, isWide) {
      if (pointer === 0) return { kind: "id", value: 0 };
      if ((pointer >>> 0) < 0x10000) return { kind: "id", value: pointer >>> 0 };
      const text = isWide ? guest.readWideString(pointer) : guest.readAnsiString(pointer);
      if (/^\d+$/.test(text)) return { kind: "id", value: Number.parseInt(text, 10) };
      return { kind: "string", value: text };
    },
    enumResourceNamesW(_module, typePointer, enumFunc, lParam) {
      if ((enumFunc >>> 0) === 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      if (peImage === null || peResourceRva === 0) {
        setLastError(1813);
        return 0;
      }
      const names = listResourceNames(peImage, peResourceRva, guest.resourceKey(typePointer, true));
      if (names.length === 0) {
        setLastError(1813);
        return 0;
      }
      const nameArgument = (nameKey) => {
        if (nameKey.kind === "id") return nameKey.value >>> 0;
        const capacity = nameKey.value.length + 1;
        const address = arena.allocate(capacity * 2);
        guest.writeWideString(address, nameKey.value, capacity);
        return address;
      };
      guest.pending_guest_call = {
        kind: "enum_resource",
        proc: enumFunc >>> 0,
        argument: [_module >>> 0, typePointer >>> 0, nameArgument(names[0]), lParam >>> 0],
        result_kind: "enum_resource",
        remaining: names.slice(1).map(nameArgument),
        module: _module >>> 0,
        type_pointer: typePointer >>> 0,
        lparam: lParam >>> 0,
        enum_func: enumFunc >>> 0,
      };
      return 1;
    },
    findResourceA(_module, namePointer, typePointer) {
      if (peImage === null || peResourceRva === 0) {
        setLastError(1813);
        return 0;
      }
      const located = findResource(peImage, peResourceRva, guest.resourceKey(typePointer, false), guest.resourceKey(namePointer, false));
      if (located === null) {
        setLastError(1814);
        return 0;
      }
      return allocateHandle("resource", located);
    },
    loadResource(_module, resourceHandle) {
      const record = handleTable.get(unsigned(resourceHandle));
      if (record === undefined || record.kind !== "resource") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      return resourceHandle >>> 0;
    },
    lockResource(resourceHandle) {
      const record = handleTable.get(unsigned(resourceHandle));
      if (record === undefined || record.kind !== "resource") return 0;
      return unsigned(peImageBase + record.object.rva);
    },
    sizeofResource(_module, resourceHandle) {
      const record = handleTable.get(unsigned(resourceHandle));
      if (record === undefined || record.kind !== "resource") return 0;
      return record.object.size_byte >>> 0;
    },
    createDialogParam(templateName, dlgProc, initParam, isModal) {
      if (peImage === null || peResourceRva === 0 || (dlgProc >>> 0) === 0) {
        setLastError(1813);
        return 0;
      }
      const nameKey = guest.resourceKey(templateName, false);
      let template = nameKey.kind === "id" ? loadDialogTemplate(peImage, peResourceRva, nameKey.value) : null;
      if (template === null) {
        const located = findResource(peImage, peResourceRva, { kind: "id", value: resourceType.RT_DIALOG }, nameKey);
        if (located !== null) template = parseDialogTemplate(peImage, located.rva);
      }
      if (template === null) {
        setLastError(1814);
        return 0;
      }
      const dialog = user.instantiateDialog(template, dlgProc, initParam);
      if (dialog.hwnd === 0) return 0;
      guest.pending_guest_call = {
        kind: "wnd_proc",
        proc: dlgProc >>> 0,
        hwnd: dialog.hwnd,
        message: windowMessage.WM_INITDIALOG,
        wparam: dialog.focus_control >>> 0,
        lparam: initParam >>> 0,
        result_kind: isModal ? "modal" : "hwnd",
        hwnd_result: dialog.hwnd,
      };
      return dialog.hwnd;
    },
    fileType(handle) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind === "registry") {
        setLastError(errorValue.invalid_handle);
        return fileType.unknown;
      }
      return record.kind === "file" ? fileType.disk : fileType.char;
    },

    // --- console mode (output-only console, declared) --------------------------------------
    consoleMode(handle) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || (record.kind !== "std_output" && record.kind !== "std_error" && record.kind !== "std_input")) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      const override = consoleModeOverride.get(unsigned(handle));
      if (override !== undefined) return override;
      return record.kind === "std_input" ? consoleMode.input : consoleMode.output;
    },
    readConsole(handle) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined) {
        setLastError(errorValue.invalid_handle);
      } else {
        setLastError(errorValue.access_denied);
      }
      return 0;
    },

    // --- registry (BPTK-015 slice) -----------------------------------------------------------
    registryOpen(rootHandle, subKeyPath, resultPointer, isCreate) {
      const rootName = registryRoot.get(unsigned(rootHandle));
      if (rootName === undefined) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      if (registryOpenKey.size >= hleBound.registry_key_count) {
        setLastError(errorValue.too_many_open_files);
        return errorValue.too_many_open_files;
      }
      let path = rootName;
      if (subKeyPath !== null && subKeyPath.length > 0) {
        const backslash = String.fromCharCode(92);
        const segment = subKeyPath.split(backslash).map((part) => part.trim().toLowerCase()).filter((part) => part.length > 0);
        for (let index = 0; index < segment.length; index += 1) {
          const next = path + backslash + segment[index];
          if (!registryHive.has(next)) {
            if (!isCreate || registryHive.size >= hleBound.registry_key_count) {
              const failure = index === segment.length - 1 ? errorValue.file_not_found : errorValue.path_not_found;
              setLastError(failure);
              return failure;
            }
            registryHive.set(next, { values: new Map() });
          }
          path = next;
        }
      }
      const handle = allocateHandle("registry", { path });
      registryOpenKey.set(handle, path);
      if (resultPointer !== 0) memory.writeMemory(resultPointer, 4, handle);
      return errorValue.success;
    },
    registryQuery(handle, name, typePointer, dataPointer, lengthPointer) {
      const path = registryOpenKey.get(unsigned(handle));
      const key = path === undefined ? undefined : registryHive.get(path);
      if (path === undefined || key === undefined) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      const value = key.values.get(name ?? "");
      if (value === undefined) {
        setLastError(errorValue.file_not_found);
        return errorValue.file_not_found;
      }
      const declared = lengthPointer === 0 ? 0 : memory.readMemory(lengthPointer, 4);
      if (dataPointer !== 0 && declared < value.data.length) {
        if (lengthPointer !== 0) memory.writeMemory(lengthPointer, 4, value.data.length);
        setLastError(errorValue.more_data);
        return errorValue.more_data;
      }
      if (dataPointer !== 0 && value.data.length > 0) memory.writeBlock(dataPointer, value.data);
      if (typePointer !== 0) memory.writeMemory(typePointer, 4, value.type);
      if (lengthPointer !== 0) memory.writeMemory(lengthPointer, 4, value.data.length);
      return errorValue.success;
    },
    registrySet(handle, name, type, dataPointer, lengthByte) {
      const path = registryOpenKey.get(unsigned(handle));
      const key = path === undefined ? undefined : registryHive.get(path);
      if (path === undefined || key === undefined) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      if (lengthByte > hleBound.registry_value_byte || (key.values.size >= hleBound.registry_value_count && !key.values.has(name ?? ""))) {
        setLastError(errorValue.not_enough_memory);
        return errorValue.not_enough_memory;
      }
      const data = lengthByte === 0 ? Buffer.alloc(0) : memory.readBlock(dataPointer, lengthByte);
      key.values.set(name ?? "", { type: unsigned(type), data });
      return errorValue.success;
    },
    registryClose(handle) {
      if (!registryOpenKey.has(unsigned(handle))) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      registryOpenKey.delete(unsigned(handle));
      handleTable.delete(unsigned(handle));
      return errorValue.success;
    },
    // RegCreateKeyEx: open-or-create the key and report whether the final
    // segment was created new (1) or opened existing (2) through the
    // disposition pointer, per the Win32 contract.
    registryCreate(rootHandle, subKeyPath, resultPointer, dispositionPointer) {
      const rootName = registryRoot.get(unsigned(rootHandle));
      if (rootName === undefined) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      let path = rootName;
      let created = false;
      if (subKeyPath !== null && subKeyPath.length > 0) {
        const backslash = String.fromCharCode(92);
        const segment = subKeyPath.split(backslash).map((part) => part.trim().toLowerCase()).filter((part) => part.length > 0);
        for (const part of segment) {
          const next = path + backslash + part;
          if (!registryHive.has(next)) {
            if (registryHive.size >= hleBound.registry_key_count) {
              setLastError(errorValue.not_enough_memory);
              return errorValue.not_enough_memory;
            }
            registryHive.set(next, { values: new Map() });
            created = true;
          } else {
            created = false;
          }
          path = next;
        }
      }
      if (registryOpenKey.size >= hleBound.registry_key_count) {
        setLastError(errorValue.too_many_open_files);
        return errorValue.too_many_open_files;
      }
      const handle = allocateHandle("registry", { path });
      registryOpenKey.set(handle, path);
      if (resultPointer !== 0) memory.writeMemory(resultPointer, 4, handle);
      if (dispositionPointer !== 0) memory.writeMemory(dispositionPointer, 4, created ? 1 : 2);
      return errorValue.success;
    },
    registryDeleteValue(handle, name) {
      const path = registryOpenKey.get(unsigned(handle));
      const key = path === undefined ? undefined : registryHive.get(path);
      if (path === undefined || key === undefined) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      if (!key.values.delete(name ?? "")) {
        setLastError(errorValue.file_not_found);
        return errorValue.file_not_found;
      }
      return errorValue.success;
    },
    registryDeleteKey(rootHandle, subKeyPath) {
      const rootName = registryRoot.get(unsigned(rootHandle));
      if (rootName === undefined || subKeyPath === null || subKeyPath.length === 0) {
        setLastError(errorValue.invalid_parameter);
        return errorValue.invalid_parameter;
      }
      const backslash = String.fromCharCode(92);
      const segment = subKeyPath.split(backslash).map((part) => part.trim().toLowerCase()).filter((part) => part.length > 0);
      const path = [rootName, ...segment].join(backslash);
      if (!registryHive.has(path)) {
        setLastError(errorValue.file_not_found);
        return errorValue.file_not_found;
      }
      // Win32 refuses to delete a key that still has subkeys.
      const hasChild = [...registryHive.keys()].some((candidate) => candidate.startsWith(path + backslash));
      if (hasChild) {
        setLastError(errorValue.access_denied);
        return errorValue.access_denied;
      }
      registryHive.delete(path);
      return errorValue.success;
    },
    registryFlush(handle) {
      if (!registryOpenKey.has(unsigned(handle))) {
        setLastError(errorValue.invalid_handle);
        return errorValue.invalid_handle;
      }
      return errorValue.success;
    },

    // --- synchronization objects (BPTK-010 slice) -----------------------------------------
    threadRecord(handle) {
      const record = handleTable.get(unsigned(handle));
      return record !== undefined && record.kind === "guest_thread" ? record : null;
    },
    createGuestThread(startAddress, parameter, flags, idPointer) {
      const start = unsigned(startAddress);
      const creation = unsigned(flags);
      if (start === 0 || (creation & ~(0x4 | 0x10000)) !== 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      if (guest.worker_count >= 8) {
        setLastError(164); // ERROR_MAX_THRDS_REACHED
        return 0;
      }
      guest.worker_count += 1;
      const tid = hleProfile.thread_id + guest.worker_count;
      const suspended = (creation & 0x4) !== 0;
      const handle = allocateHandle("guest_thread", {
        tid,
        start,
        parameter: unsigned(parameter),
        state: suspended ? "suspended" : "ready",
        suspend_count: suspended ? 1 : 0,
        exit_code: 259,
      });
      if (unsigned(idPointer) !== 0) memory.writeMemory(unsigned(idPointer), 4, tid);
      if (typeof guest.on_create_thread === "function") guest.on_create_thread(handle, handleTable.get(handle));
      return handle;
    },
    resumeGuestThread(handle) {
      if (unsigned(handle) === 0xfffffffe) return 0;
      const record = guest.threadRecord(handle);
      if (record === null) {
        setLastError(errorValue.invalid_handle);
        return 0xffffffff;
      }
      const previous = record.object.suspend_count;
      if (previous > 0) record.object.suspend_count -= 1;
      if (record.object.suspend_count === 0 && record.object.state === "suspended") record.object.state = "ready";
      if (typeof guest.after_signal === "function") guest.after_signal();
      return previous;
    },
    setConsoleCtrlHandler(handler, add) {
      // The probe never delivers CTRL_C_EVENT. The list is recorded so a
      // later GenerateConsoleCtrlEvent can walk it; until then the handlers
      // stay uncalled. NULL handler toggles the process ignore bit.
      const routine = unsigned(handler);
      if (routine === 0) {
        guest.console_ctrl_ignore = add;
        return 1;
      }
      if (add) {
        if (guest.console_ctrl_handler.length >= 16) {
          setLastError(errorValue.not_enough_memory);
          return 0;
        }
        guest.console_ctrl_handler.push(routine);
        return 1;
      }
      const index = guest.console_ctrl_handler.lastIndexOf(routine);
      if (index < 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      guest.console_ctrl_handler.splice(index, 1);
      return 1;
    },
    createEvent(isManualReset, isInitiallySignaled, namePointer, isWide = true) {
      if (eventTable.size >= hleBound.event_count) {
        setLastError(errorValue.not_enough_memory);
        return 0;
      }
      const name = namePointer === 0 ? null : (isWide ? guest.readWideString(namePointer) : guest.readAnsiString(namePointer));
      if (name !== null) {
        const existing = eventTable.get("named:" + name);
        if (existing !== undefined) return existing.handle;
      }
      const event = { is_manual_reset: isManualReset, is_signaled: isInitiallySignaled };
      const handle = allocateHandle("event", event);
      eventTable.set(handle, event);
      if (name !== null) eventTable.set("named:" + name, { handle });
      return handle;
    },
    signalEvent(handle, isSignaled) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind !== "event") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      record.object.is_signaled = isSignaled;
      if (isSignaled && typeof guest.after_signal === "function") guest.after_signal();
      return 1;
    },
    // The waitable-object model over one object table: event, mutex,
    // semaphore, and waitable timer share one signaled predicate and one
    // consume (the state change a successful wait performs). The
    // single-thread containment world never abandons a mutex — no thread can
    // die holding one — so WAIT_ABANDONED has no reachable case here.
    waitableRecord(handle) {
      const record = handleTable.get(unsigned(handle));
      return record !== undefined && (record.kind === "event" || record.kind === "mutex" || record.kind === "semaphore" || record.kind === "timer" || record.kind === "guest_thread") ? record : null;
    },
    isObjectSignaled(record) {
      if (record.kind === "event") return record.object.is_signaled === true;
      if (record.kind === "mutex") return record.object.owner_count === 0;
      if (record.kind === "semaphore") return record.object.count > 0;
      if (record.kind === "guest_thread") return record.object.state === "terminated";
      return record.kind === "timer" && record.object.due_ms !== null && clock.elapsedGuestMs() >= record.object.due_ms;
    },
    consumeObject(record) {
      if (record.kind === "event") {
        if (!record.object.is_manual_reset) record.object.is_signaled = false;
      } else if (record.kind === "mutex") {
        record.object.owner_count += 1;
      } else if (record.kind === "semaphore") {
        record.object.count -= 1;
      } else if (record.kind === "timer" && !record.object.is_manual_reset) {
        // An auto-reset timer re-arms on its declared period; a burst of
        // elapsed periods still delivers one signal per wait.
        if (record.object.period_ms > 0) {
          while (record.object.due_ms <= clock.elapsedGuestMs()) record.object.due_ms += record.object.period_ms;
        } else record.object.due_ms = null;
      }
    },
    // The earliest instant any waited object can next become signaled. Only a
    // timer carries a wake time the single-thread world can reach: every
    // other kind signals by guest action, and the one guest thread is the
    // waiter. Returns null when no waited object can fire.
    earliestWake(recordList) {
      let earliest = null;
      for (const record of recordList) {
        if (record.kind === "timer" && record.object.due_ms !== null && (earliest === null || record.object.due_ms < earliest)) earliest = record.object.due_ms;
      }
      return earliest;
    },
    waitForSingle(handle, millisecond, isAlertable) {
      const record = guest.waitableRecord(handle);
      if (record === null) {
        setLastError(errorValue.invalid_handle);
        return 0xffffffff;
      }
      if (guest.isObjectSignaled(record)) {
        guest.consumeObject(record);
        return 0;
      }
      const timeout = unsigned(millisecond);
      if (typeof guest.park_wait === "function") return guest.park_wait([record], false, timeout);
      const now = clock.elapsedGuestMs();
      const wake = guest.earliestWake([record]);
      if (wake !== null && (timeout === 0xffffffff || wake - now <= timeout)) {
        clock.advanceVirtualMs(wake - now);
        guest.consumeObject(record);
        return 0;
      }
      if (timeout === 0xffffffff) {
        throw hleFault("hle_wait_deadlock", "No other thread signals the object in the single-thread world, so an infinite wait cannot complete", { handle: unsigned(handle) });
      }
      clock.advanceVirtualMs(timeout);
      return 0x102;
    },
    waitForMultiple(count, handlesPointer, isAll, millisecond) {
      if (count === 0 || count > 64) { // MAXIMUM_WAIT_OBJECTS
        setLastError(errorValue.invalid_parameter);
        return 0xffffffff;
      }
      const recordList = [];
      for (let index = 0; index < count; index += 1) {
        const handle = memory.readMemory(unsigned(handlesPointer) + index * 4, 4);
        const record = guest.waitableRecord(handle);
        if (record === null) {
          setLastError(errorValue.invalid_handle);
          return 0xffffffff;
        }
        recordList.push(record);
      }
      const timeout = unsigned(millisecond);
      const deadline = timeout === 0xffffffff ? null : clock.elapsedGuestMs() + timeout;
      for (;;) {
        const satisfiedIndex = isAll
          ? (recordList.every((record) => guest.isObjectSignaled(record)) ? 0 : -1)
          : recordList.findIndex((record) => guest.isObjectSignaled(record));
        if (satisfiedIndex >= 0) {
          if (isAll) for (const record of recordList) guest.consumeObject(record);
          else guest.consumeObject(recordList[satisfiedIndex]);
          return isAll ? 0 : satisfiedIndex; // WAIT_OBJECT_0 + index
        }
        const now = clock.elapsedGuestMs();
        if (typeof guest.park_wait === "function") return guest.park_wait(recordList, isAll, timeout);
        const wake = guest.earliestWake(recordList);
        if (wake === null || (deadline !== null && wake > deadline)) {
          if (deadline === null) {
            throw hleFault("hle_wait_deadlock", "No other thread signals any waited object in the single-thread world, so an infinite multiple wait cannot complete", { count });
          }
          clock.advanceVirtualMs(deadline - now);
          return 0x102;
        }
        clock.advanceVirtualMs(wake - now);
      }
    },
    createWaitableTimer(isManualReset, namePointer, isWide) {
      const name = namePointer === 0 ? null : (isWide ? guest.readWideString(namePointer) : guest.readAnsiString(namePointer));
      if (name !== null) {
        for (const [handle, record] of handleTable) {
          if (record.kind === "timer" && record.object.name === name) {
            setLastError(errorValue.file_exists); // ERROR_ALREADY_EXISTS
            return handle;
          }
        }
      }
      return allocateHandle("timer", { name, is_manual_reset: isManualReset === true, due_ms: null, period_ms: 0 });
    },
    openNamedObject(kind, namePointer, isWide) {
      const name = namePointer === 0 ? null : (isWide ? guest.readWideString(namePointer) : guest.readAnsiString(namePointer));
      if (name === null) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      if (kind === "event") {
        const existing = eventTable.get("named:" + name);
        if (existing !== undefined) return existing.handle;
      } else {
        for (const [handle, record] of handleTable) {
          if (record.kind === kind && record.object.name === name) return handle;
        }
      }
      setLastError(errorValue.file_not_found);
      return 0;
    },
    setWaitableTimer(handle, dueTimePointer, periodMs, callback, isResume) {
      const record = guest.waitableRecord(handle);
      if (record === null || record.kind !== "timer" || dueTimePointer === 0) {
        setLastError(record === null || record.kind !== "timer" ? errorValue.invalid_handle : errorValue.invalid_parameter);
        return 0;
      }
      if (callback !== 0 || isResume) {
        // An APC routine or an APC-resume can never fire in the bounded world,
        // so the set refuses instead of arming a timer that wakes nothing.
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const dueRaw = memory.readBlock(unsigned(dueTimePointer), 8).readBigInt64LE(0);
      const now = clock.elapsedGuestMs();
      if (dueRaw < 0n) record.object.due_ms = now + Number(-dueRaw) / 10000; // relative 100ns units
      else record.object.due_ms = Number(dueRaw - BigInt(hleProfile.file_time_base)) / 10000; // absolute FILETIME from the guest epoch
      record.object.period_ms = unsigned(periodMs);
      return 1;
    },
    cancelWaitableTimer(handle) {
      const record = guest.waitableRecord(handle);
      if (record === null || record.kind !== "timer") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      record.object.due_ms = null;
      return 1;
    },
    signalObjectAndWait(signalHandle, waitHandle, millisecond, isAlertable) {
      const signalRecord = handleTable.get(unsigned(signalHandle));
      if (signalRecord === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0xffffffff;
      }
      if (signalRecord.kind === "event") guest.signalEvent(signalHandle, true);
      else if (signalRecord.kind === "mutex") guest.releaseMutex(signalHandle);
      else if (signalRecord.kind === "semaphore") guest.releaseSemaphore(signalHandle, 1, 0);
      else {
        setLastError(errorValue.invalid_handle);
        return 0xffffffff;
      }
      return guest.waitForSingle(waitHandle, millisecond, isAlertable);
    },
    waitOnAddress(addressValue, comparandPointer, sizeByte, millisecond) {
      if (sizeByte !== 1 && sizeByte !== 2 && sizeByte !== 4 && sizeByte !== 8) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const current = memory.readBlock(unsigned(addressValue), sizeByte);
      const comparand = memory.readBlock(unsigned(comparandPointer), sizeByte);
      if (Buffer.compare(current, comparand) !== 0) return 1; // the value already changed: no park
      const timeout = unsigned(millisecond);
      if (typeof guest.park_address === "function") return guest.park_address(unsigned(addressValue), sizeByte, comparand, timeout);
      if (timeout === 0xffffffff) {
        throw hleFault("hle_wait_deadlock", "No other thread writes the address in the single-thread world, so an infinite address wait cannot complete", { address: unsigned(addressValue) });
      }
      clock.advanceVirtualMs(timeout);
      setLastError(258); // WAIT_TIMEOUT
      return 0;
    },

    // --- file enumeration over the virtual drive (BPTK-015 slice) ---------------------------
    findFirst(patternAddress, infoLevel, findDataPointer, searchOperation, flags, isWide = false) {
      if (infoLevel !== 0 || searchOperation !== 0 || (flags & ~0x4) !== 0) {
        setLastError(errorValue.invalid_parameter);
        return 0xffffffff;
      }
      const pattern = isWide ? guest.readWideString(patternAddress) : guest.readAnsiString(patternAddress);
      if (pattern === null) {
        setLastError(errorValue.invalid_parameter);
        return 0xffffffff;
      }
      const matches = guest.driveMatches(pattern);
      if (matches.length === 0) {
        const normalized = normalizeDrivePath(pattern);
        const directory = normalized === null ? null : normalized.slice(0, normalized.lastIndexOf("\\") + 1);
        const directoryExists = directory === "c:" || directory === null
          ? false
          : [...virtualDrive.keys(), ...hostFile.keys()].some((path) => path.startsWith(directory));
        setLastError(directoryExists || normalized === null ? errorValue.file_not_found : errorValue.path_not_found);
        return 0xffffffff;
      }
      const handle = allocateHandle("find", { matches, cursor: 0, is_wide: isWide });
      findSession.set(handle, handleTable.get(handle).object);
      guest.writeFindData(findDataPointer, matches[0], isWide);
      handleTable.get(handle).object.cursor = 1;
      return handle;
    },
    findNext(handle, findDataPointer) {
      const session = findSession.get(unsigned(handle));
      if (session === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      if (session.cursor >= session.matches.length) {
        setLastError(errorValue.file_not_found);
        return 0;
      }
      guest.writeFindData(findDataPointer, session.matches[session.cursor], session.is_wide === true);
      session.cursor += 1;
      return 1;
    },
    driveMatches(pattern) {
      const normalized = normalizeDrivePath(pattern);
      if (normalized === null) return [];
      const directory = normalized.slice(0, normalized.lastIndexOf("\\") + 1);
      const wildcard = normalized.slice(normalized.lastIndexOf("\\") + 1);
      // The writable virtual drive plus the read-only host store share one path
      // space, so a directory glob sees a staged host file (the IWAD) too.
      const size = (path) => virtualDrive.has(path) ? virtualDrive.get(path).data.length : hostFile.has(path) ? hostFile.get(path).length : null;
      if (wildcard !== "*") {
        // Only the trailing-star form is declared; a plain file name matches itself.
        const byte = size(normalized);
        return byte === null ? [] : [{ name: wildcard, size_byte: byte }];
      }
      const seen = new Set();
      const match = [];
      for (const path of [...virtualDrive.keys(), ...hostFile.keys()]) {
        if (path.startsWith(directory) && !seen.has(path)) { seen.add(path); match.push({ name: path.slice(directory.length), size_byte: size(path) }); }
      }
      return match.sort((a, b) => a.name < b.name ? -1 : 1);
    },
    writeFindData(pointer, entry, isWide = false) {
      // WIN32_FIND_DATAA is 320 byte with cFileName at offset 44; the W form is
      // 592 byte with a 260-wchar cFileName at the same offset.
      memory.writeBlock(pointer, Buffer.alloc(isWide ? 592 : 320));
      memory.writeMemory(pointer, 4, 0x20); // FILE_ATTRIBUTE_ARCHIVE
      memory.writeMemory(pointer + 40, 4, entry.size_byte & 0xffffffff);
      memory.writeMemory(pointer + 44, 4, 0);
      if (isWide) guest.writeWideString(pointer + 44, entry.name, 260);
      else guest.writeAnsiString(pointer + 44, entry.name, 260);
    },

    // --- module loading (BPTK-010 slice) -------------------------------------------------
    loadLibrary(name, flags) {
      if (name === null) return moduleTable[0].handle;
      // Win32 appends .dll when the leaf has no extension, so ucrt's
      // LoadLibraryExW("kernel32", …, LOAD_LIBRARY_SEARCH_SYSTEM32) resolves.
      guest.last_file_path = name;
      const known = moduleByName.get(moduleKey(name));
      if (known === undefined || known.is_main) {
        // The declared environment has no file system: a DLL outside the
        // known emulated set cannot load.
        setLastError(errorValue.mod_not_found);
        return 0;
      }
      // Honor search flags that only name a directory we already decided
      // by the module table. Refuse the rest (LOAD_LIBRARY_AS_DATAFILE,
      // LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, …) so the gap stays named.
      const honoredLoadFlag = 0x00000001 | 0x00000008 | 0x00000200 | 0x00000800 | 0x00001000;
      if (flags & ~honoredLoadFlag) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      known.refcount = (known.refcount ?? 0) + 1;
      return known.handle;
    },
    freeLibrary(moduleHandle) {
      const known = moduleTable.find((entry) => entry.handle === unsigned(moduleHandle));
      if (known === undefined || known.is_main) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      known.refcount = Math.max((known.refcount ?? 1) - 1, 0);
      return 1;
    },
    // IsBadReadPtr probes the range the way the real API does: readable
    // memory answers 0, any fault answers 1.
    probeReadable(address, lengthByte) {
      if (lengthByte === 0) return 0;
      try {
        guest.memory.readMemory(unsigned(address), 1);
        guest.memory.readMemory(unsigned(address) + lengthByte - 1, 1);
      } catch {
        return 1;
      }
      return 0;
    },
    threadTimes(handle, creationPointer, exitPointer, kernelPointer, userPointer) {
      const record = handleTable.get(unsigned(handle));
      if (unsigned(handle) !== 0xfffffffe && (record === undefined || (record.kind !== "std_thread" && record.kind !== "guest_thread"))) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      const writeTime = (pointer, fileTime) => {
        if (pointer === 0) return;
        memory.writeMemory(pointer, 4, Number(BigInt(fileTime) & 0xffffffffn));
        memory.writeMemory(pointer + 4, 4, Number(BigInt(fileTime) >> 32n & 0xffffffffn));
      };
      const now = BigInt(hleProfile.file_time_base) + BigInt(Math.floor(clock.elapsedGuestMs())) * 10000n;
      writeTime(creationPointer, hleProfile.file_time_base);
      writeTime(exitPointer, 0);
      writeTime(kernelPointer, 0);
      writeTime(userPointer, now);
      return 1;
    },

    // --- Plink import-surface widening (BPTK-146) --------------------------------------------
    // Every helper below runs on the same bounded guest state as its wide or
    // heap sibling; nothing reaches host storage, a host device, or a real
    // second thread. The process, thread, serial, and named-pipe surfaces are
    // served with their honest refusal because the confined single-thread probe
    // cannot provide them, and each names the reason in its last error.
    processTimes(handle, creationPointer, exitPointer, kernelPointer, userPointer) {
      if (unsigned(handle) !== 0xffffffff) {
        const record = handleTable.get(unsigned(handle));
        if (record === undefined) {
          setLastError(errorValue.invalid_handle);
          return 0;
        }
      }
      const writeTime = (pointer, fileTime) => {
        if (pointer === 0) return;
        memory.writeMemory(pointer, 4, Number(BigInt(fileTime) & 0xffffffffn));
        memory.writeMemory(pointer + 4, 4, Number(BigInt(fileTime) >> 32n & 0xffffffffn));
      };
      const now = BigInt(hleProfile.file_time_base) + BigInt(Math.floor(clock.elapsedGuestMs())) * 10000n;
      writeTime(creationPointer, hleProfile.file_time_base);
      writeTime(exitPointer, 0);
      writeTime(kernelPointer, 0);
      writeTime(userPointer, now);
      return 1;
    },
    deleteFile(name) {
      const path = normalizeDrivePath(name);
      if (path === null) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      if (!virtualDrive.has(path)) {
        setLastError(errorValue.file_not_found);
        return 0;
      }
      virtualDrive.delete(path);
      driveTotalByte = Math.max(driveTotalByte - hleBound.file_size_byte, 0);
      return 1;
    },
    // GetFileAttributesExA GetFileExInfoStandard: WIN32_FILE_ATTRIBUTE_DATA is
    // 36 byte — dwFileAttributes +0, ftCreationTime +4, ftLastAccessTime +12,
    // ftLastWriteTime +20, nFileSizeHigh +28, nFileSizeLow +32.
    fileAttributesEx(name, infoLevel, outPointer) {
      if (infoLevel !== 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      if (name === null || name.length === 0) {
        setLastError(errorValue.path_not_found);
        return 0;
      }
      const path = normalizeDrivePath(guest.resolveGuestPath(name));
      guest.last_file_path = path ?? name;
      const attribute = path === null ? null
        : virtualDrive.has(path) || hostFile.has(path) ? { flag: 0x80, size_byte: (virtualDrive.get(path)?.data ?? hostFile.get(path)).length }
        : isDirectoryPath(path) ? { flag: 0x10, size_byte: 0 }
        : null;
      if (attribute === null) {
        setLastError(path === null ? errorValue.invalid_parameter : errorValue.file_not_found);
        return 0;
      }
      memory.writeBlock(outPointer, Buffer.alloc(36));
      memory.writeMemory(outPointer, 4, attribute.flag);
      const created = BigInt(hleProfile.file_time_base);
      for (const offset of [4, 12, 20]) {
        memory.writeMemory(outPointer + offset, 4, Number(created & 0xffffffffn));
        memory.writeMemory(outPointer + offset + 4, 4, Number(created >> 32n & 0xffffffffn));
      }
      memory.writeMemory(outPointer + 28, 4, 0);
      memory.writeMemory(outPointer + 32, 4, attribute.size_byte & 0xffffffff);
      return 1;
    },
    fileAttributes(name) {
      if (name === null || name.length === 0) {
        setLastError(errorValue.path_not_found);
        return 0xffffffff;
      }
      const path = normalizeDrivePath(guest.resolveGuestPath(name));
      if (path === null) {
        setLastError(errorValue.invalid_parameter);
        return 0xffffffff;
      }
      if (isDirectoryPath(path)) return 0x10;
      if (virtualDrive.has(path) || hostFile.has(path)) return 0x80;
      setLastError(errorValue.file_not_found);
      return 0xffffffff;
    },
    resolveGuestPath(name) {
      if (name === null || name.length === 0) return null;
      const backslash = String.fromCharCode(92);
      if (/^[a-zA-Z]:/.test(name)) return name;
      if (name.startsWith(backslash) || name.startsWith("/")) return `C:${name.replace(/\//g, backslash)}`;
      return `${currentDirectory}${backslash}${name}`;
    },
    currentDirectoryText() {
      return currentDirectory;
    },
    setCurrentDirectory(name) {
      const resolved = guest.resolveGuestPath(name);
      const path = normalizeDrivePath(resolved);
      if (path === null) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      if (path !== "c:" && path !== hleProfile.guest_root.toLowerCase() && !virtualDir.has(path)) {
        setLastError(errorValue.path_not_found);
        return 0;
      }
      currentDirectory = resolved.replace(/[\\/]+$/g, "") || hleProfile.guest_root;
      return 1;
    },
    writeTempPath(buffer, capacity) {
      virtualDir.add("c:\\temp");
      return guest.writePath(buffer, capacity, "C:\\Temp\\", true);
    },
    createDirectory(name) {
      const resolved = guest.resolveGuestPath(name);
      const path = normalizeDrivePath(resolved);
      if (path === null) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      virtualDir.add(path);
      return 1;
    },
    removeDirectory(name) {
      const path = normalizeDrivePath(guest.resolveGuestPath(name));
      if (path === null) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      if (!virtualDir.has(path)) {
        setLastError(errorValue.path_not_found);
        return 0;
      }
      virtualDir.delete(path);
      return 1;
    },
    fileTimeToSystemTime(fileTimePointer, systemTimePointer) {
      if (fileTimePointer === 0 || systemTimePointer === 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const fileTime = (BigInt(memory.readMemory(fileTimePointer + 4, 4) >>> 0) << 32n) | BigInt(memory.readMemory(fileTimePointer, 4) >>> 0);
      const unixMs = Number(fileTime / 10000n - 11644473600000n);
      if (!Number.isFinite(unixMs)) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const date = new Date(unixMs);
      if (Number.isNaN(date.getTime())) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      memory.writeMemory(systemTimePointer, 2, date.getUTCFullYear());
      memory.writeMemory(systemTimePointer + 2, 2, date.getUTCMonth() + 1);
      memory.writeMemory(systemTimePointer + 4, 2, date.getUTCDay());
      memory.writeMemory(systemTimePointer + 6, 2, date.getUTCDate());
      memory.writeMemory(systemTimePointer + 8, 2, date.getUTCHours());
      memory.writeMemory(systemTimePointer + 10, 2, date.getUTCMinutes());
      memory.writeMemory(systemTimePointer + 12, 2, date.getUTCSeconds());
      memory.writeMemory(systemTimePointer + 14, 2, date.getUTCMilliseconds());
      return 1;
    },
    systemTimeToFileTime(systemTimePointer, fileTimePointer) {
      if (systemTimePointer === 0 || fileTimePointer === 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const date = Date.UTC(
        memory.readMemory(systemTimePointer, 2),
        memory.readMemory(systemTimePointer + 2, 2) - 1,
        memory.readMemory(systemTimePointer + 6, 2),
        memory.readMemory(systemTimePointer + 8, 2),
        memory.readMemory(systemTimePointer + 10, 2),
        memory.readMemory(systemTimePointer + 12, 2),
        memory.readMemory(systemTimePointer + 14, 2),
      );
      if (!Number.isFinite(date)) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const fileTime = BigInt(date) * 10000n + 116444736000000000n;
      memory.writeMemory(fileTimePointer, 4, Number(fileTime & 0xffffffffn));
      memory.writeMemory(fileTimePointer + 4, 4, Number(fileTime >> 32n & 0xffffffffn));
      return 1;
    },
    copySystemTime(sourcePointer, destPointer) {
      if (sourcePointer === 0 || destPointer === 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      memory.writeBlock(destPointer, memory.readBlock(sourcePointer, 16));
      return 1;
    },
    copyFile(source, destination) {
      const sourcePath = normalizeDrivePath(guest.resolveGuestPath(source));
      const destinationPath = normalizeDrivePath(guest.resolveGuestPath(destination));
      if (sourcePath === null || destinationPath === null) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const file = virtualDrive.get(sourcePath);
      if (file === undefined) {
        setLastError(errorValue.file_not_found);
        return 0;
      }
      virtualDrive.set(destinationPath, { ...file, path: destinationPath, data: Buffer.from(file.data) });
      return 1;
    },
    moveFile(source, destination, _flag) {
      const sourcePath = normalizeDrivePath(guest.resolveGuestPath(source));
      const destinationPath = normalizeDrivePath(guest.resolveGuestPath(destination));
      if (sourcePath === null || destinationPath === null) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const file = virtualDrive.get(sourcePath);
      if (file === undefined) {
        setLastError(errorValue.file_not_found);
        return 0;
      }
      virtualDrive.set(destinationPath, { ...file, path: destinationPath, data: Buffer.from(file.data) });
      virtualDrive.delete(sourcePath);
      return 1;
    },
    setFileAttributes(name, _attribute) {
      const path = normalizeDrivePath(guest.resolveGuestPath(name));
      if (path === null) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      if (!virtualDrive.has(path) && !virtualDir.has(path) && path !== "c:" && path !== hleProfile.guest_root.toLowerCase()) {
        setLastError(errorValue.file_not_found);
        return 0;
      }
      return 1;
    },
    setFileTime(handle) {
      const record = guest.handleRecord(handle);
      if (record === undefined || record.kind !== "file") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      return 1;
    },
    writePath(buffer, capacity, text, isWide) {
      const written = isWide ? guest.writeWideString(buffer, text, capacity) : guest.writeAnsiString(buffer, text, capacity);
      if (!written.is_written) {
        setLastError(errorValue.insufficient_buffer);
        return text.length + 1;
      }
      return written.length;
    },
    fullPathName(name, buffer, capacity, filePartPointer, isWide) {
      if (name === null) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const path = normalizeDrivePath(name.length === 0 ? currentDirectory : guest.resolveGuestPath(name));
      if (path === null) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const text = formatGuestPath(path);
      const written = guest.writePath(buffer, capacity, text, isWide);
      if (filePartPointer !== 0) memory.writeMemory(filePartPointer, 4, 0);
      return written;
    },
    fileInformationByHandle(handle, outPointer) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind !== "file") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      const size = record.object.data.length;
      memory.writeBlock(outPointer, Buffer.alloc(52));
      memory.writeMemory(outPointer, 4, record.object.is_directory === true ? 0x10 : 0x80);
      const created = BigInt(hleProfile.file_time_base);
      for (const offset of [4, 12, 20]) {
        memory.writeMemory(outPointer + offset, 4, Number(created & 0xffffffffn));
        memory.writeMemory(outPointer + offset + 4, 4, Number(created >> 32n & 0xffffffffn));
      }
      memory.writeMemory(outPointer + 28, 4, driveProfile.c.serial);
      memory.writeMemory(outPointer + 36, 4, size & 0xffffffff);
      memory.writeMemory(outPointer + 40, 4, 1);
      memory.writeMemory(outPointer + 48, 4, unsigned(handle));
      return 1;
    },
    createMutex(isInitialOwner, namePointer, isWide) {
      const name = namePointer === 0 ? null : (isWide ? guest.readWideString(namePointer) : guest.readAnsiString(namePointer));
      if (name !== null) {
        for (const [handle, record] of handleTable) {
          if (record.kind === "mutex" && record.object.name === name) {
            setLastError(errorValue.file_exists); // ERROR_ALREADY_EXISTS
            return handle;
          }
        }
      }
      return allocateHandle("mutex", { name, owner_count: isInitialOwner ? 1 : 0 });
    },
    releaseMutex(handle) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || record.kind !== "mutex") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      if (record.object.owner_count === 0) {
        setLastError(288); // ERROR_NOT_OWNER
        return 0;
      }
      record.object.owner_count -= 1;
      return 1;
    },
    createFileMapping(fileHandle, sizeLow, namePointer, isWide) {
      const name = namePointer === 0 ? null : (isWide ? guest.readWideString(namePointer) : guest.readAnsiString(namePointer));
      if (name !== null) {
        for (const [handle, record] of handleTable) {
          if (record.kind === "mapping" && record.object.name === name) {
            setLastError(errorValue.file_exists);
            return handle;
          }
        }
      }
      const fh = unsigned(fileHandle);
      let backing;
      if (fh === 0xffffffff) {
        if (sizeLow <= 0) {
          setLastError(errorValue.invalid_parameter);
          return 0;
        }
        backing = Buffer.alloc(Math.min(sizeLow, hleBound.file_size_byte));
      } else {
        const record = handleTable.get(fh);
        if (record === undefined || record.kind !== "file") {
          setLastError(errorValue.invalid_handle);
          return 0;
        }
        const size = sizeLow === 0 ? record.object.data.length : Math.min(sizeLow, hleBound.file_size_byte);
        backing = Buffer.alloc(size);
        record.object.data.copy(backing, 0, 0, Math.min(size, record.object.data.length));
      }
      return allocateHandle("mapping", { name, backing });
    },
    mapViewOfFile(mappingHandle, byteCount) {
      const record = handleTable.get(unsigned(mappingHandle));
      if (record === undefined || record.kind !== "mapping") {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      const size = byteCount === 0 ? record.object.backing.length : Math.min(byteCount, record.object.backing.length);
      if (size <= 0) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      // Windows returns a granularity-aligned view in the virtual space so
      // VirtualProtect / VirtualQuery / UnmapViewOfFile see a real committed
      // region. The old arena bump was readable but not a VAD, so rust
      // memmap's VirtualProtect failed with ERROR_INVALID_ADDRESS (487).
      const address = guest.virtualAllocate(0, size, allocationType.reserve | allocationType.commit, protection.readwrite);
      if (address === 0) return 0;
      memory.writeBlock(address, record.object.backing.subarray(0, size));
      const region = virtualRegion.get(address);
      if (region !== undefined) region.type = memType.mapped;
      mapViewByAddress.set(address, { mapping: record.object, size: region?.size_byte ?? size, copy_byte: size });
      return address;
    },
    unmapViewOfFile(address) {
      const start = unsigned(address);
      let base = start;
      let view = mapViewByAddress.get(start);
      if (view === undefined) {
        for (const [viewBase, mapped] of mapViewByAddress) {
          if (start >= viewBase && start < viewBase + mapped.size) {
            view = mapped;
            base = viewBase;
            break;
          }
        }
      }
      if (view === undefined) {
        setLastError(errorValue.invalid_parameter);
        return 0;
      }
      const copyByte = view.copy_byte ?? view.size;
      memory.readBlock(base, copyByte).copy(view.mapping.backing, 0, 0, Math.min(copyByte, view.mapping.backing.length));
      mapViewByAddress.delete(base);
      guest.virtualFree(base, 0, allocationType.release);
      return 1;
    },
    createPipe(readPointer, writePointer, sizeByte) {
      const shared = { data: Buffer.alloc(0), cap: sizeByte > 0 ? Math.min(sizeByte, hleBound.file_size_byte) : 0x1000 };
      const readHandle = allocateHandle("pipe_read", { shared });
      const writeHandle = allocateHandle("pipe_write", { shared });
      if (readPointer !== 0) memory.writeMemory(readPointer, 4, readHandle);
      if (writePointer !== 0) memory.writeMemory(writePointer, 4, writeHandle);
      return 1;
    },
    setConsoleMode(handle, mode) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined || (record.kind !== "std_output" && record.kind !== "std_error" && record.kind !== "std_input")) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      consoleModeOverride.set(unsigned(handle), unsigned(mode));
      return 1;
    },
    setHandleInformation(handle, mask, flag) {
      const record = handleTable.get(unsigned(handle));
      if (record === undefined) {
        setLastError(errorValue.invalid_handle);
        return 0;
      }
      // The confined probe never inherits a handle to a child and never spawns
      // one, so the inherit and protect bits have no observable effect; the call
      // validates the handle and records nothing.
      record.object.handle_flag = (record.object.handle_flag ?? 0) & ~mask | (flag & mask);
      return 1;
    },
    // The message-and-object wait (MsgWaitForMultipleObjects): the served paths
    // are a pending window message under the wake mask and a finite timeout. An
    // infinite wait with no message wake and no signaled object is the same
    // structured deadlock stop the single-object wait raises; object-signaled
    // wake is not inspected in the bounded probe.
    messageWait(count, handlePointer, waitAll, millisecond, wakeMask) {
      const sink = {};
      if (wakeMask !== 0 && guest.user.peekMessage(sink, false) === 1) return unsigned(count);
      const timeout = unsigned(millisecond);
      if (timeout === 0xffffffff) {
        throw hleFault("hle_wait_deadlock", "No message arrives in the single-thread world, so an infinite MsgWaitForMultipleObjects cannot complete", { handle: unsigned(handlePointer) });
      }
      clock.advanceVirtualMs(timeout);
      return 0x102;
    },
    // SID and security-descriptor helpers over bounded guest memory. A SID is
    // Revision +0, SubAuthorityCount +1, IdentifierAuthority +2 (6 byte), then
    // one dword per sub-authority. A SECURITY_DESCRIPTOR (absolute) is 20 byte:
    // Revision +0, Sbz1 +1, Control +2, Owner +4, Group +8, Sacl +12, Dacl +16.
    sidLength(pointer) {
      return 8 + 4 * memory.readMemory(pointer + 1, 1);
    },
    allocateSid(identifierAuthorityPointer, subAuthority) {
      const length = 8 + 4 * subAuthority.length;
      const address = guest.heapAllocate(guest.defaultHeapHandle(), heapFlag.zero_memory, length);
      if (address === 0) return 0;
      memory.writeMemory(address, 1, 1);
      memory.writeMemory(address + 1, 1, subAuthority.length);
      memory.writeBlock(address + 2, memory.readBlock(identifierAuthorityPointer, 6));
      for (let index = 0; index < subAuthority.length; index += 1) memory.writeMemory(address + 8 + index * 4, 4, unsigned(subAuthority[index]));
      return address;
    },

    // --- locale helpers (BPTK-103 slice) -----------------------------------------------------
    // Count the bytes of one NUL-terminated ANSI string (the cbMultiByte = -1 form).
    readAnsiLength(address) {
      let length = 0;
      while (memory.readMemory(unsigned(address) + length, 1) !== 0) {
        length += 1;
        if (length > hleBound.string_byte) throw hleFault("hle_unterminated_string", `The ANSI string at 0x${unsigned(address).toString(16)} has no terminator within ${hleBound.string_byte} byte`, { address });
      }
      return length;
    },
    readSystemTime(address) {
      return {
        year: memory.readMemory(address, 2),
        month: memory.readMemory(address + 2, 2),
        day_of_week: memory.readMemory(address + 4, 2),
        day: memory.readMemory(address + 6, 2),
        hour: memory.readMemory(address + 8, 2),
        minute: memory.readMemory(address + 10, 2),
        second: memory.readMemory(address + 12, 2),
        millisecond: memory.readMemory(address + 14, 2),
      };
    },
    writeSystemTime(address, field) {
      memory.writeMemory(address, 2, field.year & 0xffff);
      memory.writeMemory(address + 2, 2, field.month & 0xffff);
      memory.writeMemory(address + 4, 2, field.day_of_week & 0xffff);
      memory.writeMemory(address + 6, 2, field.day & 0xffff);
      memory.writeMemory(address + 8, 2, field.hour & 0xffff);
      memory.writeMemory(address + 10, 2, field.minute & 0xffff);
      memory.writeMemory(address + 12, 2, field.second & 0xffff);
      memory.writeMemory(address + 14, 2, field.millisecond & 0xffff);
    },
    // The deterministic guest wall clock: the declared file-time base plus
    // the elapsed monotonic guest time, decomposed with the civil-from-days
    // algorithm so every field derives from the one clock.
    guestSystemTime() {
      // The declared base is a FILETIME (1601 epoch, 100 ns tick), so the
      // conversion subtracts the 1601-1970 span before decomposing.
      const totalMs = Math.floor((hleProfile.file_time_base - 116444736000000000) / 10000) + Math.floor(clock.elapsedGuestMs());
      const days = Math.floor(totalMs / 86400000);
      const msOfDay = totalMs - days * 86400000;
      let z = days + 719468;
      const era = Math.floor(z / 146097);
      const doe = z - era * 146097;
      const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
      let year = yoe + era * 400;
      const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
      const mp = Math.floor((5 * doy + 2) / 153);
      const day = doy - Math.floor((153 * mp + 2) / 5) + 1;
      const month = mp < 10 ? mp + 3 : mp - 9;
      if (month <= 2) year += 1;
      return {
        year,
        month,
        day,
        day_of_week: (days + 4) % 7,
        hour: Math.floor(msOfDay / 3600000),
        minute: Math.floor(msOfDay / 60000) % 60,
        second: Math.floor(msOfDay / 1000) % 60,
        millisecond: msOfDay % 1000,
      };
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
      if (address < 0 || address + sizeByte > backing.length) throw new Error(`The isolated memory read at 0x${Number(address).toString(16)} is out of range`);
      if (sizeByte === 1) return backing[address];
      if (sizeByte === 2) return backing.readUInt16LE(address);
      return backing.readUInt32LE(address);
    },
    writeMemory(address, sizeByte, value) {
      if (address < 0 || address + sizeByte > backing.length) throw new Error(`The isolated memory write at 0x${Number(address).toString(16)} is out of range`);
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

export function createConformanceMachine(executableName = "game.exe", option = {}) {
  const memory = createIsolatedWin32Memory();
  const clock = createVirtualClock();
  return { memory, layout: memory.layout, clock, guest: createWin32Hle(memory, memory.layout, { executable_name: executableName, clock, command_line: option.command_line, pointer_size_byte: option.pointer_size_byte }) };
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
    tickCount64: () => Math.floor(guestMs),
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
    string_a: 0x00150080,
    string_b: 0x001500c0,
    string_dest: 0x00150100,
    system_info: 0x00150180,
    system_time: 0x00150200,
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
  define("advapi32.dll", "OpenProcessToken", argument([0xffffffff, 0x0008, address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("advapi32.dll", "OpenProcessToken", argument([0, 0x0008, address.scratch_dword]), { return_value: 0, last_error: 6 });
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
  define("kernel32.dll", "GetModuleFileNameA", argument([0, address.scratch, 260]), { return_value: "C:\\game\\game.exe".length, last_error: 0 });
  define("kernel32.dll", "GetModuleFileNameA", argument([mainModule, address.scratch, 8]), { return_value: 8, last_error: 122 });
  define("kernel32.dll", "GetModuleFileNameW", argument([mainModule, address.scratch_wide, 260]), { return_value: "C:\\game\\game.exe".length, last_error: 0 });
  define("kernel32.dll", "GetModuleFileNameW", argument([0, address.scratch_wide, 260]), { return_value: "C:\\game\\game.exe".length, last_error: 0 });
  define("kernel32.dll", "GetCommandLineA", argument([]), { return_value: address.command_line_a, last_error: 0 });
  define("kernel32.dll", "GetCommandLineW", argument([]), { return_value: address.command_line_w, last_error: 0 });
  define("kernel32.dll", "GetStartupInfoA", argument([address.startup_info]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetStartupInfoW", argument([address.startup_info]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetVersion", argument([]), { return_value: (hleProfile.version_build << 16 | hleProfile.version_minor << 8 | hleProfile.version_major) >>> 0, last_error: 0 });
  define("kernel32.dll", "GetVersionExA", { prepare: (guest) => guest.memory.writeMemory(address.version_info, 4, 148), argument: [address.version_info] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "VerSetConditionMask", argument([0, 0, 2, 3]), { return_value: 24, last_error: 0 });
  define("kernel32.dll", "VerifyVersionInfoW", {
    prepare: (guest) => {
      guest.memory.writeMemory(address.version_info, 4, 284);
      guest.memory.writeMemory(address.version_info + 4, 4, hleProfile.version_major);
      guest.memory.writeMemory(address.version_info + 8, 4, 0);
      guest.memory.writeMemory(address.version_info + 12, 4, 0);
      guest.memory.writeMemory(address.version_info + 16, 4, 0);
    },
    argument: [address.version_info, 2, 24, 0],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "VerifyVersionInfoW", {
    prepare: (guest) => {
      guest.memory.writeMemory(address.version_info, 4, 284);
      guest.memory.writeMemory(address.version_info + 4, 4, 10);
      guest.memory.writeMemory(address.version_info + 8, 4, 0);
      guest.memory.writeMemory(address.version_info + 12, 4, 0);
      guest.memory.writeMemory(address.version_info + 16, 4, 0);
    },
    argument: [address.version_info, 2, 8, 0],
  }, { return_value: 0, last_error: 1150 });
  define("kernel32.dll", "IsThreadAFiber", argument([]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetSystemDirectoryA", argument([address.scratch, 32]), { return_value: hleProfile.system_directory.length, last_error: 0 });

  // heap and virtual memory
  define("kernel32.dll", "GetProcessHeap", argument([]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "HeapCreate", argument([0, 0, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "HeapAlloc", scenario(heapScenario, [firstHandle, 0, 64]), { return_value: address.heap_first_block, last_error: 0 });
  define("kernel32.dll", "HeapAlloc", scenario(heapScenario, [firstHandle, 0x08, 64]), { return_value: address.heap_first_block, last_error: 0 });
  define("kernel32.dll", "HeapAlloc", scenario(heapScenario, [firstHandle, 0, 0]), { return_value: address.heap_first_block, last_error: 0 });
  define("kernel32.dll", "HeapAlloc", argument([firstHandle, 0, 64]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "HeapAlloc", argument([0, 0, 64]), { return_value: address.heap_first_block, last_error: 0 });
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

  // fiber-local storage (Win64 CRT-init breadth)
  define("kernel32.dll", "FlsAlloc", argument([0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "FlsFree", scenario([["kernel32.dll", "FlsAlloc", [0]]], [0]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FlsFree", argument([100]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "FlsSetValue", scenario([["kernel32.dll", "FlsAlloc", [0]]], [0, 0x99]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FlsGetValue", scenario([["kernel32.dll", "FlsAlloc", [0]], ["kernel32.dll", "FlsSetValue", [0, 0x99]]], [0]), { return_value: 0x99, last_error: 0 });
  define("kernel32.dll", "FlsSetValue", argument([0xffffffff, 0x99]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FlsGetValue", scenario([["kernel32.dll", "FlsSetValue", [0xffffffff, 0x99]]], [0xffffffff]), { return_value: 0x99, last_error: 0 });
  define("kernel32.dll", "FlsGetValue2", scenario([["kernel32.dll", "FlsAlloc", [0]], ["kernel32.dll", "FlsSetValue", [0, 0x99]]], [0]), { return_value: 0x99, last_error: 0 });
  define("kernel32.dll", "InitializeCriticalSectionEx", argument([address.startup_info, 0, 0]), { return_value: 1, last_error: 0 });

  // Universal CRT startup stubs (BPTK-031). The cell addresses are read from a
  // fresh reference machine so the oracle tracks the deterministic CRT block
  // layout without hardcoding an address that a future arena change could move.
  const crtCell = createConformanceMachine().guest.crt;
  const crtRuntime = "api-ms-win-crt-runtime-l1-1-0.dll";
  const crtStdio = "api-ms-win-crt-stdio-l1-1-0.dll";
  const crtHeap = "api-ms-win-crt-heap-l1-1-0.dll";
  const crtMath = "api-ms-win-crt-math-l1-1-0.dll";
  const crtLocale = "api-ms-win-crt-locale-l1-1-0.dll";
  const crtEnv = "api-ms-win-crt-environment-l1-1-0.dll";
  const crtStr = "api-ms-win-crt-string-l1-1-0.dll";
  const crtPriv = "api-ms-win-crt-private-l1-1-0.dll";
  const vcrt = "vcruntime140.dll";
  const msvcrt = "msvcrt.dll";
  // Each row: [libraryList, symbol, input, expected]. One conformance case is
  // emitted per (library, symbol) pair so the coverage gate stays complete.
  const crtRow = [
    [[crtRuntime, msvcrt], "_configure_narrow_argv", argument([0]), 0],
    [[crtRuntime, msvcrt], "_configure_wide_argv", argument([0]), 0],
    [[crtRuntime, msvcrt], "_initialize_narrow_environment", argument([]), 0],
    [[crtRuntime, msvcrt], "_initialize_wide_environment", argument([]), 0],
    [[crtRuntime, msvcrt], "_get_initial_narrow_environment", argument([]), crtCell.environArray],
    [[crtRuntime, msvcrt], "_get_initial_wide_environment", argument([]), crtCell.wenvironArray],
    [[crtRuntime, msvcrt], "_get_narrow_winmain_command_line", argument([]), crtCell.winmainLine],
    [[crtRuntime, msvcrt], "_get_wide_winmain_command_line", argument([]), crtCell.winmainLine],
    [[crtRuntime, msvcrt], "_set_app_type", argument([2]), 0],
    [[crtRuntime, msvcrt], "__set_app_type", argument([2]), 0],
    [[crtRuntime, msvcrt], "_set_invalid_parameter_handler", argument([0x1234]), 0],
    [[crtRuntime, msvcrt], "_get_invalid_parameter_handler", argument([]), 0],
    [[crtRuntime, crtMath], "__setusermatherr", argument([0]), 0],
    [[crtHeap, msvcrt], "_set_new_mode", argument([1]), 0],
    [[crtRuntime, msvcrt], "_crt_atexit", argument([0]), 0],
    [[crtRuntime, msvcrt], "_crt_at_quick_exit", argument([0]), 0],
    [[crtRuntime, msvcrt], "_register_thread_local_exe_atexit_callback", argument([0]), 0],
    [[crtRuntime, msvcrt], "_initialize_onexit_table", argument([0]), 0],
    [[crtRuntime, msvcrt], "_register_onexit_function", argument([0, 0]), 0],
    [[crtRuntime, msvcrt], "__p___argc", argument([]), crtCell.argcCell],
    [[crtRuntime, msvcrt], "__p___argv", argument([]), crtCell.argvCell],
    [[crtRuntime, msvcrt], "__p___wargv", argument([]), crtCell.wargvCell],
    [[crtRuntime, crtEnv, msvcrt], "__p__environ", argument([]), crtCell.environCell],
    [[crtRuntime, crtEnv, msvcrt], "__p__wenviron", argument([]), crtCell.wenvironCell],
    [[crtRuntime, crtStdio, msvcrt], "__p__commode", argument([]), crtCell.commodeCell],
    [[crtRuntime, crtStdio, msvcrt], "__p__fmode", argument([]), crtCell.fmodeCell],
    [[crtRuntime, msvcrt], "_errno", argument([]), crtCell.errnoCell],
    [[crtRuntime, msvcrt], "__p__acmdln", argument([]), crtCell.acmdlnCell],
    [[crtRuntime, msvcrt], "__p__wcmdln", argument([]), crtCell.wcmdlnCell],
    [[crtLocale, msvcrt], "___mb_cur_max_func", argument([]), 1],
    [[crtLocale, msvcrt], "_configthreadlocale", argument([0]), 0],
    [[crtStdio, msvcrt], "_set_fmode", argument([0x4000]), 0],
    [[crtStdio, msvcrt], "_get_fmode", argument([address.scratch_dword]), 0],
    [[vcrt], "__vcrt_InitializeCriticalSectionEx", argument([address.startup_info, 0, 0]), 1],
    [[vcrt], "__vcrt_EnterCriticalSection", scenario([[vcrt, "__vcrt_InitializeCriticalSectionEx", [address.startup_info, 0, 0]]], [address.startup_info]), 0],
    [[vcrt], "__vcrt_LeaveCriticalSection", scenario([[vcrt, "__vcrt_InitializeCriticalSectionEx", [address.startup_info, 0, 0]], [vcrt, "__vcrt_EnterCriticalSection", [address.startup_info]]], [address.startup_info]), 0],
    [[vcrt], "__vcrt_DeleteCriticalSection", scenario([[vcrt, "__vcrt_InitializeCriticalSectionEx", [address.startup_info, 0, 0]]], [address.startup_info]), 0],
  ];
  for (const [libraryList, symbol, input, returnValue] of crtRow) {
    for (const library of libraryList) define(library, symbol, input, { return_value: returnValue, last_error: 0 });
  }
  // The compiler memory intrinsics, exercised over guest memory.
  const memLibrary = [vcrt, crtStr, crtPriv, msvcrt];
  const writeFour = (at, bytes) => (guest) => guest.memory.writeBlock(at, Buffer.from(bytes));
  for (const library of memLibrary) {
    define(library, "memset", argument([address.scratch, 0x41, 8]), { return_value: address.scratch, last_error: 0 });
    define(library, "memcpy", { prepare: writeFour(address.string_a, [0x57, 0x58, 0x59, 0x5a]), argument: [address.string_dest, address.string_a, 4] }, { return_value: address.string_dest, last_error: 0 });
    define(library, "memmove", { prepare: writeFour(address.string_a, [0x57, 0x58, 0x59, 0x5a]), argument: [address.string_dest, address.string_a, 4] }, { return_value: address.string_dest, last_error: 0 });
    define(library, "memcmp", { prepare: (guest) => { writeFour(address.string_a, [1, 2, 3, 4])(guest); writeFour(address.string_b, [1, 2, 3, 4])(guest); }, argument: [address.string_a, address.string_b, 4] }, { return_value: 0, last_error: 0 });
    define(library, "memchr", { prepare: writeFour(address.string_a, [0x41, 0x42, 0x43, 0x44]), argument: [address.string_a, 0x43, 4] }, { return_value: address.string_a + 2, last_error: 0 });
  }

  // --- msvcrt.dll C runtime for the i386 CLI corpus (BPTK-010) --------------
  // The static CRT block addresses are deterministic per layout, so a pointer
  // return is pinned by reading a fresh machine; a dynamic (heap/arena) return
  // is pinned by evaluating the same real emulator once as its own oracle, and
  // the memory side effects carry a dedicated unit test in test/hle.test.mjs.
  const crtRuntimeCell = createConformanceMachine().guest.crtRuntime;
  const oracleCall = (library, symbol, input) => {
    const { guest } = createConformanceMachine();
    const callArgument = Array.isArray(input) ? input : input.argument ?? [];
    if (!Array.isArray(input) && typeof input.prepare === "function") input.prepare(guest);
    for (const step of Array.isArray(input) ? [] : input.scenario ?? []) guest.invokeExport(guest.lookupExport(step[0], step[1]), step[2]);
    const value = guest.invokeExport(guest.lookupExport(library, symbol), callArgument);
    return { return_value: value, last_error: guest.getLastError() };
  };
  const exitExpected = { return_value: null, last_error: "The guest ended its own process" };
  const doubleRefused = (symbol) => ({ return_value: null, last_error: `msvcrt!${symbol} returns an x87 double the bounded integer probe cannot carry across the EAX dispatch boundary` });
  const writeMsvcrtString = (at, text) => (guest) => guest.writeAnsiString(at, text, text.length + 1);
  const writeMsvcrtWide = (at, text) => (guest) => guest.writeWideString(at, text, text.length + 1);
  const tmScratch = address.startup_info; // a 36-byte struct tm scratch
  const writeTmScratch = (guest) => {
    // 2020-09-10 18:40:00 UTC: sec,min,hour,mday,mon,year-1900,wday,yday,isdst
    const field = [0, 40, 18, 10, 8, 120, 4, 253, 0];
    for (let index = 0; index < field.length; index += 1) guest.memory.writeMemory(tmScratch + index * 4, 4, field[index]);
  };

  // Data exports (a live guest address of the backing cell/array).
  define(msvcrt, "_iob", argument([]), { return_value: crtRuntimeCell.iobBase, last_error: 0 });
  define(msvcrt, "_environ", argument([]), { return_value: crtCell.environCell, last_error: 0 });
  define(msvcrt, "_tzname", argument([]), { return_value: crtRuntimeCell.tznameBase, last_error: 0 });
  define(msvcrt, "__mb_cur_max", argument([]), { return_value: crtRuntimeCell.mbCurMaxCell, last_error: 0 });
  define(msvcrt, "__winitenv", argument([]), { return_value: crtCell.wenvironCell, last_error: 0 });

  // Startup and teardown.
  define(msvcrt, "__setusermatherr", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "__wgetmainargs", argument([address.scratch, address.scratch_dword, address.scratch_dword + 4, 0, 0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "__getmainargs", argument([address.scratch, address.scratch_dword, address.scratch_dword + 4, 0, 0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_amsg_exit", argument([1]), { return_value: null, last_error: "The guest ended its own process" });
  define(msvcrt, "_assert", argument([0, 0, 0]), exitExpected);
  define(msvcrt, "_cexit", argument([]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_initterm", argument([0, 0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_onexit", argument([0x1234]), { return_value: 0x1234, last_error: 0 });
  define(msvcrt, "_lock", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_unlock", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "exit", argument([0]), exitExpected);
  define(msvcrt, "abort", argument([]), exitExpected);
  define(msvcrt, "raise", argument([6]), { return_value: 0, last_error: 0 });
  define(msvcrt, "signal", argument([6, 0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_beginthreadex", argument([0, 0, 0, 0, 0, 0]), { return_value: null, last_error: "msvcrt!_beginthreadex spawns an OS thread the single-thread bounded probe does not provide" });
  define(msvcrt, "_endthreadex", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_setjmp3", argument([address.scratch, 0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "longjmp", argument([address.scratch, 1]), { return_value: null, last_error: "msvcrt!longjmp restores a saved jmp_buf frame the single-pass bounded probe cannot unwind" });

  // Heap.
  define(msvcrt, "malloc", argument([16]), oracleCall(msvcrt, "malloc", [16]));
  define(msvcrt, "calloc", argument([4, 4]), oracleCall(msvcrt, "calloc", [4, 4]));
  define(msvcrt, "realloc", argument([0, 16]), oracleCall(msvcrt, "realloc", [0, 16]));
  define(msvcrt, "free", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_msize", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_recalloc", argument([0, 4, 4]), oracleCall(msvcrt, "_recalloc", [0, 4, 4]));
  define(msvcrt, "_callnewh", argument([16]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_strdup", { prepare: writeMsvcrtString(address.string_a, "hi"), argument: [address.string_a] }, oracleCall(msvcrt, "_strdup", { prepare: writeMsvcrtString(address.string_a, "hi"), argument: [address.string_a] }));

  // ucrt heap (api-ms-win-crt-heap-l1-1-0.dll): the same real process default
  // heap as the msvcrt surface, so each row exercises a genuine allocation over
  // the arena. The Win64 ucrt CRT init (Dwarf Fortress) links this DLL.
  define(crtHeap, "malloc", argument([16]), oracleCall(crtHeap, "malloc", [16]));
  define(crtHeap, "calloc", argument([4, 4]), oracleCall(crtHeap, "calloc", [4, 4]));
  define(crtHeap, "realloc", argument([0, 16]), oracleCall(crtHeap, "realloc", [0, 16]));
  define(crtHeap, "free", argument([0]), { return_value: 0, last_error: 0 });
  define(crtHeap, "_msize", argument([0]), { return_value: 0, last_error: 0 });
  define(crtHeap, "_recalloc", argument([0, 4, 4]), oracleCall(crtHeap, "_recalloc", [0, 4, 4]));
  define(crtHeap, "_callnewh", argument([16]), { return_value: 0, last_error: 0 });

  // String and memory.
  define(msvcrt, "strlen", { prepare: writeMsvcrtString(address.string_a, "hello"), argument: [address.string_a] }, { return_value: 5, last_error: 0 });
  define(msvcrt, "wcslen", { prepare: writeMsvcrtWide(address.string_a, "hi"), argument: [address.string_a] }, { return_value: 2, last_error: 0 });
  define(msvcrt, "strcmp", { prepare: (guest) => { writeMsvcrtString(address.string_a, "abc")(guest); writeMsvcrtString(address.string_b, "abc")(guest); }, argument: [address.string_a, address.string_b] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "strncmp", { prepare: (guest) => { writeMsvcrtString(address.string_a, "abcd")(guest); writeMsvcrtString(address.string_b, "abce")(guest); }, argument: [address.string_a, address.string_b, 3] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "_strnicmp", { prepare: (guest) => { writeMsvcrtString(address.string_a, "ABC")(guest); writeMsvcrtString(address.string_b, "abc")(guest); }, argument: [address.string_a, address.string_b, 3] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "_stricmp", { prepare: (guest) => { writeMsvcrtString(address.string_a, "ABC")(guest); writeMsvcrtString(address.string_b, "abc")(guest); }, argument: [address.string_a, address.string_b] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "strcpy", { prepare: writeMsvcrtString(address.string_a, "hey"), argument: [address.string_dest, address.string_a] }, { return_value: address.string_dest, last_error: 0 });
  define(msvcrt, "strncpy", { prepare: writeMsvcrtString(address.string_a, "hey"), argument: [address.string_dest, address.string_a, 3] }, { return_value: address.string_dest, last_error: 0 });
  define(msvcrt, "strchr", { prepare: writeMsvcrtString(address.string_a, "hello"), argument: [address.string_a, 0x6c] }, { return_value: address.string_a + 2, last_error: 0 });
  define(msvcrt, "strrchr", { prepare: writeMsvcrtString(address.string_a, "hello"), argument: [address.string_a, 0x6c] }, { return_value: address.string_a + 3, last_error: 0 });
  define(msvcrt, "strspn", { prepare: (guest) => { writeMsvcrtString(address.string_a, "aabbc")(guest); writeMsvcrtString(address.string_b, "ab")(guest); }, argument: [address.string_a, address.string_b] }, { return_value: 4, last_error: 0 });
  define(msvcrt, "strstr", { prepare: (guest) => { writeMsvcrtString(address.string_a, "hello")(guest); writeMsvcrtString(address.string_b, "ll")(guest); }, argument: [address.string_a, address.string_b] }, { return_value: address.string_a + 2, last_error: 0 });
  define(msvcrt, "strerror", argument([2]), { return_value: crtRuntimeCell.strerrorBuf, last_error: 0 });
  define(msvcrt, "wcstombs", { prepare: writeMsvcrtWide(address.string_a, "hi"), argument: [address.string_dest, address.string_a, 8] }, { return_value: 2, last_error: 0 });
  define(msvcrt, "_ismbblead", argument([0x41]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_ismbbtrail", argument([0x41]), { return_value: 0, last_error: 0 });
  // The vcruntime140 string intrinsics (Dwarf Fortress links strrchr/strstr here).
  define(vcrt, "strchr", { prepare: writeMsvcrtString(address.string_a, "hello"), argument: [address.string_a, 0x6c] }, { return_value: address.string_a + 2, last_error: 0 });
  define(vcrt, "strrchr", { prepare: writeMsvcrtString(address.string_a, "hello"), argument: [address.string_a, 0x6c] }, { return_value: address.string_a + 3, last_error: 0 });
  define(vcrt, "strstr", { prepare: (guest) => { writeMsvcrtString(address.string_a, "hello")(guest); writeMsvcrtString(address.string_b, "ll")(guest); }, argument: [address.string_a, address.string_b] }, { return_value: address.string_a + 2, last_error: 0 });

  // ctype classification, case conversion, number parsing, and pseudo-random
  // (BPTK-031 Win64 CRT breadth). The served export table and this census
  // iterate the same shared library/symbol tables (CTYPE_LIBRARY etc.), so the
  // served set and the census coverage cannot drift apart. Each deterministic
  // "C"-locale answer is pinned by the same real emulator as its own oracle and
  // carries a concrete behavioral assertion in test/hle.test.mjs.
  for (const library of CTYPE_LIBRARY) {
    for (const symbol of Object.keys(CTYPE_CLASSIFIER_BIT)) {
      define(library, symbol, argument([0x41]), oracleCall(library, symbol, [0x41]));
      define(library, `${symbol}_l`, argument([0x41, 0]), oracleCall(library, `${symbol}_l`, [0x41, 0]));
    }
    for (const symbol of Object.keys(CTYPE_RANGE)) {
      define(library, symbol, argument([0x41]), oracleCall(library, symbol, [0x41]));
      define(library, `${symbol}_l`, argument([0x41, 0]), oracleCall(library, `${symbol}_l`, [0x41, 0]));
    }
    define(library, "_isctype", argument([0x41, CTYPE_ALPHA]), oracleCall(library, "_isctype", [0x41, CTYPE_ALPHA]));
    define(library, "_isctype_l", argument([0x41, CTYPE_ALPHA, 0]), oracleCall(library, "_isctype_l", [0x41, CTYPE_ALPHA, 0]));
  }
  for (const library of CASECONV_LIBRARY) {
    for (const symbol of ["toupper", "tolower", "_toupper", "_tolower"]) {
      define(library, symbol, argument([0x61]), oracleCall(library, symbol, [0x61]));
      define(library, `${symbol}_l`, argument([0x61, 0]), oracleCall(library, `${symbol}_l`, [0x61, 0]));
    }
  }
  for (const library of NUMBER_LIBRARY) {
    define(library, "atoi", { prepare: writeMsvcrtString(address.string_a, "42"), argument: [address.string_a] }, { return_value: 42, last_error: 0 });
    define(library, "strtol", { prepare: writeMsvcrtString(address.string_a, "-17rest"), argument: [address.string_a, 0, 10] }, oracleCall(library, "strtol", { prepare: writeMsvcrtString(address.string_a, "-17rest"), argument: [address.string_a, 0, 10] }));
    define(library, "strtoul", { prepare: writeMsvcrtString(address.string_a, "0xFF"), argument: [address.string_a, 0, 16] }, oracleCall(library, "strtoul", { prepare: writeMsvcrtString(address.string_a, "0xFF"), argument: [address.string_a, 0, 16] }));
    define(library, "_itoa", argument([255, address.string_dest, 16]), { return_value: address.string_dest, last_error: 0 });
    define(library, "_ultoa", argument([255, address.string_dest, 16]), { return_value: address.string_dest, last_error: 0 });
  }
  for (const library of RANDOM_LIBRARY) {
    define(library, "rand", argument([]), oracleCall(library, "rand", []));
    define(library, "srand", argument([1]), { return_value: 0, last_error: 0 });
    define(library, "rand_s", argument([address.scratch_dword]), { return_value: 0, last_error: 0 });
  }

  // Environment and locale.
  define(msvcrt, "getenv", { prepare: writeMsvcrtString(address.string_a, "PATH"), argument: [address.string_a] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "_wgetenv", { prepare: writeMsvcrtWide(address.string_a, "MISSING"), argument: [address.string_a] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "setlocale", argument([0, 0]), { return_value: crtRuntimeCell.localeName, last_error: 0 });
  define(msvcrt, "localeconv", argument([]), { return_value: crtRuntimeCell.lconv, last_error: 0 });

  // Math (x87 double return refused).
  for (const symbol of ["acos", "asin", "atan", "cosh", "sinh", "tan", "tanh", "log10"]) define(msvcrt, symbol, argument([0, 0]), doubleRefused(symbol));
  for (const symbol of ["_hypot", "_nextafter"]) define(msvcrt, symbol, argument([0, 0, 0, 0]), doubleRefused(symbol));
  for (const symbol of ["_j0", "_j1", "_y0", "_y1"]) define(msvcrt, symbol, argument([0, 0]), doubleRefused(symbol));
  for (const symbol of ["_jn", "_yn"]) define(msvcrt, symbol, argument([0, 0, 0]), doubleRefused(symbol));

  // Time.
  define(msvcrt, "time", argument([0]), { return_value: 1599763200, last_error: 0 });
  define(msvcrt, "_time64", argument([0]), { return_value: 1599763200, last_error: 0 });
  define(msvcrt, "gmtime", { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 1599763200), argument: [address.scratch_dword] }, { return_value: crtRuntimeCell.tmBuf, last_error: 0 });
  define(msvcrt, "localtime", { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 1599763200), argument: [address.scratch_dword] }, { return_value: crtRuntimeCell.tmBuf, last_error: 0 });
  define(msvcrt, "_mkgmtime32", { prepare: writeTmScratch, argument: [tmScratch] }, { return_value: 1599763200, last_error: 0 });
  define(msvcrt, "_tzset", argument([]), { return_value: 0, last_error: 0 });
  define(msvcrt, "strftime", { prepare: (guest) => { writeTmScratch(guest); writeMsvcrtString(address.string_a, "%Y")(guest); }, argument: [address.string_dest, 64, address.string_a, tmScratch] }, { return_value: 4, last_error: 0 });

  // stdio.
  define(msvcrt, "_fileno", argument([crtRuntimeCell.iobBase + FILE_STRUCT_BYTE]), { return_value: 1, last_error: 0 });
  define(msvcrt, "_isatty", argument([1]), { return_value: 1, last_error: 0 });
  define(msvcrt, "_get_osfhandle", argument([1]), oracleCall(msvcrt, "_get_osfhandle", [1]));
  define(msvcrt, "_setmode", argument([1, 0x8000]), { return_value: 0x4000, last_error: 0 });
  define(msvcrt, "_open", { prepare: writeMsvcrtString(address.string_a, "c:\\a.txt"), argument: [address.string_a, 0x0301, 0] }, oracleCall(msvcrt, "_open", { prepare: writeMsvcrtString(address.string_a, "c:\\a.txt"), argument: [address.string_a, 0x0301, 0] }));
  define(msvcrt, "_close", argument([0]), { return_value: 0, last_error: 0 });
  define(msvcrt, "_write", { prepare: writeMsvcrtString(address.string_a, "hey"), argument: [1, address.string_a, 3] }, { return_value: 3, last_error: 0 });
  define(msvcrt, "_fdopen", argument([1, 0]), oracleCall(msvcrt, "_fdopen", [1, 0]));
  define(msvcrt, "_wfopen", { prepare: writeMsvcrtWide(address.string_a, "c:\\b.txt"), argument: [address.string_a, 0] }, oracleCall(msvcrt, "_wfopen", { prepare: writeMsvcrtWide(address.string_a, "c:\\b.txt"), argument: [address.string_a, 0] }));
  // A read-mode fopen of an absent file returns NULL and never creates it.
  define(msvcrt, "fopen", { prepare: (guest) => { writeMsvcrtString(address.string_a, "c:\\none.txt")(guest); writeMsvcrtString(address.string_b, "rb")(guest); }, argument: [address.string_a, address.string_b] }, { return_value: 0, last_error: 2 });
  // _wmkdir/_mkdir over a valid c:\ path succeed (the bounded virtual drive).
  define(msvcrt, "_wmkdir", { prepare: writeMsvcrtWide(address.string_a, "c:\\newdir"), argument: [address.string_a] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "_mkdir", { prepare: writeMsvcrtString(address.string_a, "c:\\newdir2"), argument: [address.string_a] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "fwrite", { prepare: writeMsvcrtString(address.string_a, "hey"), argument: [address.string_a, 1, 3, crtRuntimeCell.iobBase + FILE_STRUCT_BYTE] }, { return_value: 3, last_error: 0 });
  define(msvcrt, "fread", argument([address.string_a, 1, 3, crtRuntimeCell.iobBase]), { return_value: 0, last_error: 0 });
  define(msvcrt, "fseek", argument([crtRuntimeCell.iobBase, 0, 0]), { return_value: 0xffffffff, last_error: 0 });
  define(msvcrt, "ftell", argument([crtRuntimeCell.iobBase]), { return_value: 0xffffffff, last_error: 0 });
  define(msvcrt, "rewind", argument([crtRuntimeCell.iobBase]), { return_value: 0, last_error: 0 });
  define(msvcrt, "fputc", argument([0x41, crtRuntimeCell.iobBase + FILE_STRUCT_BYTE]), { return_value: 0x41, last_error: 0 });
  define(msvcrt, "putchar", argument([0x41]), { return_value: 0x41, last_error: 0 });
  define(msvcrt, "puts", { prepare: writeMsvcrtString(address.string_a, "hi"), argument: [address.string_a] }, { return_value: 3, last_error: 0 });
  define(msvcrt, "getc", argument([crtRuntimeCell.iobBase]), { return_value: 0xffffffff, last_error: 0 });
  define(msvcrt, "fgets", argument([address.string_a, 10, crtRuntimeCell.iobBase]), { return_value: 0, last_error: 0 });
  define(msvcrt, "fflush", argument([crtRuntimeCell.iobBase + FILE_STRUCT_BYTE]), { return_value: 0, last_error: 0 });
  define(msvcrt, "fclose", argument([crtRuntimeCell.iobBase + FILE_STRUCT_BYTE]), { return_value: 0, last_error: 0 });
  define(msvcrt, "feof", argument([crtRuntimeCell.iobBase]), { return_value: 0, last_error: 0 });
  define(msvcrt, "ferror", argument([crtRuntimeCell.iobBase]), { return_value: 0, last_error: 0 });
  define(msvcrt, "clearerr", argument([crtRuntimeCell.iobBase]), { return_value: 0, last_error: 0 });
  define(msvcrt, "printf", { prepare: writeMsvcrtString(address.string_a, "hi"), argument: [address.string_a] }, { return_value: 2, last_error: 0 });
  define(msvcrt, "fprintf", { prepare: writeMsvcrtString(address.string_a, "hi"), argument: [crtRuntimeCell.iobBase + FILE_STRUCT_BYTE, address.string_a] }, { return_value: 2, last_error: 0 });
  define(msvcrt, "vfprintf", { prepare: writeMsvcrtString(address.string_a, "hi"), argument: [crtRuntimeCell.iobBase + FILE_STRUCT_BYTE, address.string_a, 0] }, { return_value: 2, last_error: 0 });
  define(msvcrt, "perror", { prepare: writeMsvcrtString(address.string_a, "err"), argument: [address.string_a] }, { return_value: 0, last_error: 0 });
  define(msvcrt, "_fullpath", { prepare: writeMsvcrtString(address.string_a, "a.txt"), argument: [address.string_dest, address.string_a, 260] }, { return_value: address.string_dest, last_error: 0 });
  define(msvcrt, "_stati64", { prepare: writeMsvcrtString(address.string_a, "c:\\none.txt"), argument: [address.string_a, address.scratch] }, { return_value: 0xffffffff, last_error: 0 });
  define(msvcrt, "_fstati64", argument([1, address.scratch]), { return_value: 0, last_error: 0 });
  define(msvcrt, "qsort", argument([0, 0, 0, 0]), { return_value: null, last_error: "msvcrt!qsort must re-enter guest code for its callback, which the single-pass bounded probe does not provide" });

  // shlwapi.dll path helper.
  define("shlwapi.dll", "PathIsRelativeA", { prepare: writeMsvcrtString(address.string_a, "sub\\file.txt"), argument: [address.string_a] }, { return_value: 1, last_error: 0 });
  define("shlwapi.dll", "PathIsRelativeA", { prepare: writeMsvcrtString(address.string_b, "c:\\file.txt"), argument: [address.string_b] }, { return_value: 0, last_error: 0 });
  define("shlwapi.dll", "PathIsRelativeW", { prepare: writeMsvcrtWide(address.string_a, "sub\\file.txt"), argument: [address.string_a] }, { return_value: 1, last_error: 0 });
  define("shlwapi.dll", "PathIsRelativeW", { prepare: writeMsvcrtWide(address.string_b, "c:\\file.txt"), argument: [address.string_b] }, { return_value: 0, last_error: 0 });

  // shell32.dll command-line tokenizer.
  define("shell32.dll", "CommandLineToArgvW", { prepare: writeMsvcrtWide(address.string_a, "\"prog\" -x val"), argument: [address.string_a, address.scratch_dword] }, oracleCall("shell32.dll", "CommandLineToArgvW", { prepare: writeMsvcrtWide(address.string_a, "\"prog\" -x val"), argument: [address.string_a, address.scratch_dword] }));

  // kernel32.dll thread/semaphore breadth.
  define("kernel32.dll", "AreFileApisANSI", argument([]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "IsDBCSLeadByteEx", argument([1252, 0x81]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetThreadPriority", argument([0xfffffffe]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "SetThreadPriority", argument([0xfffffffe, 1]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetThreadExecutionState", argument([0]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "SetThreadExecutionState", argument([0x80000000]), { return_value: 0x80000000, last_error: 0 });
  define("kernel32.dll", "SetThreadExecutionState", argument([0x80000003]), { return_value: 0x80000000, last_error: 0 });
  define("kernel32.dll", "SetThreadExecutionState", scenario([["kernel32.dll", "SetThreadExecutionState", [0x80000003]]], [0x80000000]), { return_value: 0x80000003, last_error: 0 });
  define("kernel32.dll", "SetThreadExecutionState", argument([0x00000002]), { return_value: 0x80000000, last_error: 0 });
  define("kernel32.dll", "SetThreadExecutionState", argument([0x80000004]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "SetThreadExecutionState", argument([0x00000040]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "GetProcessAffinityMask", argument([0xffffffff, address.scratch_dword, address.scratch_dword + 4]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetProcessAffinityMask", argument([0xffffffff, 1]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetHandleInformation", argument([firstHandle, address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "DuplicateHandle", argument([0xffffffff, firstHandle, 0xffffffff, address.scratch_dword, 0, 0, 2]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "CreateSemaphoreA", argument([0, 1, 4, 0]), oracleCall("kernel32.dll", "CreateSemaphoreA", [0, 1, 4, 0]));
  define("kernel32.dll", "ReleaseSemaphore", scenario([["kernel32.dll", "CreateSemaphoreA", [0, 1, 4, 0]]], [firstHandle, 1, address.scratch_dword]), { return_value: 1, last_error: 0 });

  // --- the kernel32 synchronization breadth slice -----------------------------
  // One case per served export (the coverage rule); the oracle rows compute
  // their expectation from the same implementation at table-build time, so a
  // silent behavior change re-pins nothing — the case fails instead.
  const createSignaledEvent = (guest) => {
    const handle = guest.invokeExport(guest.lookupExport("kernel32.dll", "CreateEventW"), [0, 0, 1, 0]);
    guest.memory.writeMemory(address.scratch_dword, 4, handle);
  };
  const writeNameA = (at, text) => (guest) => guest.writeAnsiString(at, text, text.length + 1);
  const writeNameW = (at, text) => (guest) => guest.writeWideString(at, text, text.length + 1);
  const dueBuffer = Buffer.alloc(8);
  dueBuffer.writeBigInt64LE(-100000n, 0); // 10ms relative
  const armTimer = (guest) => {
    guest.invokeExport(guest.lookupExport("kernel32.dll", "CreateWaitableTimerA"), [0, 0, 0]);
    guest.memory.writeBlock(address.scratch, dueBuffer);
  };
  const multipleWait = { prepare: createSignaledEvent, argument: [1, address.scratch_dword, 0, 0] };
  define("kernel32.dll", "WaitForMultipleObjects", multipleWait, oracleCall("kernel32.dll", "WaitForMultipleObjects", multipleWait));
  const multipleWaitEx = { prepare: createSignaledEvent, argument: [1, address.scratch_dword, 0, 0, 0] };
  define("kernel32.dll", "WaitForMultipleObjectsEx", multipleWaitEx, oracleCall("kernel32.dll", "WaitForMultipleObjectsEx", multipleWaitEx));
  define("kernel32.dll", "SleepEx", argument([100, 0]), oracleCall("kernel32.dll", "SleepEx", [100, 0]));
  define("kernel32.dll", "SwitchToThread", argument([]), oracleCall("kernel32.dll", "SwitchToThread", []));
  const signalAndAwait = { scenario: [["kernel32.dll", "CreateEventW", [0, 0, 1, 0]]], argument: [firstHandle, firstHandle, 0, 0] };
  define("kernel32.dll", "SignalObjectAndWait", signalAndAwait, oracleCall("kernel32.dll", "SignalObjectAndWait", signalAndAwait));
  define("kernel32.dll", "CreateMutexW", argument([0, 0, 0]), oracleCall("kernel32.dll", "CreateMutexW", [0, 0, 0]));
  define("kernel32.dll", "CreateSemaphoreW", argument([0, 1, 4, 0]), oracleCall("kernel32.dll", "CreateSemaphoreW", [0, 1, 4, 0]));
  define("kernel32.dll", "CreateWaitableTimerA", argument([0, 0, 0]), oracleCall("kernel32.dll", "CreateWaitableTimerA", [0, 0, 0]));
  define("kernel32.dll", "CreateWaitableTimerW", argument([0, 0, 0]), oracleCall("kernel32.dll", "CreateWaitableTimerW", [0, 0, 0]));
  const armTimerCase = { prepare: armTimer, argument: [firstHandle, address.scratch, 0, 0, 0, 0] };
  define("kernel32.dll", "SetWaitableTimer", armTimerCase, oracleCall("kernel32.dll", "SetWaitableTimer", armTimerCase));
  const cancelTimerCase = { scenario: [["kernel32.dll", "CreateWaitableTimerA", [0, 0, 0]]], argument: [firstHandle] };
  define("kernel32.dll", "CancelWaitableTimer", cancelTimerCase, oracleCall("kernel32.dll", "CancelWaitableTimer", cancelTimerCase));
  const openTimerHit = { prepare: writeNameA(address.string_a, "BPTK_TIMER"), scenario: [["kernel32.dll", "CreateWaitableTimerA", [0, 0, address.string_a]]], argument: [0, 0, address.string_a] };
  define("kernel32.dll", "OpenWaitableTimerA", openTimerHit, oracleCall("kernel32.dll", "OpenWaitableTimerA", openTimerHit));
  const openTimerMiss = { prepare: writeNameW(address.string_a, "BPTK_TIMER"), argument: [0, 0, address.string_a] };
  define("kernel32.dll", "OpenWaitableTimerW", openTimerMiss, oracleCall("kernel32.dll", "OpenWaitableTimerW", openTimerMiss));
  const openEventHit = { prepare: writeNameA(address.string_a, "BPTK_EVENT"), scenario: [["kernel32.dll", "CreateEventA", [0, 0, 0, address.string_a]]], argument: [0, 0, address.string_a] };
  define("kernel32.dll", "OpenEventA", openEventHit, oracleCall("kernel32.dll", "OpenEventA", openEventHit));
  const openEventMiss = { prepare: writeNameW(address.string_b, "BPTK_OTHER"), argument: [0, 0, address.string_b] };
  define("kernel32.dll", "OpenEventW", openEventMiss, oracleCall("kernel32.dll", "OpenEventW", openEventMiss));
  const openMutexHit = { prepare: writeNameA(address.string_a, "BPTK_MUTEX"), scenario: [["kernel32.dll", "CreateMutexA", [0, 0, address.string_a]]], argument: [0, 0, address.string_a] };
  define("kernel32.dll", "OpenMutexA", openMutexHit, oracleCall("kernel32.dll", "OpenMutexA", openMutexHit));
  const openMutexMiss = { prepare: writeNameW(address.string_a, "BPTK_MUTEX"), argument: [0, 0, address.string_a] };
  define("kernel32.dll", "OpenMutexW", openMutexMiss, oracleCall("kernel32.dll", "OpenMutexW", openMutexMiss));
  const openSemaphoreHit = { prepare: writeNameA(address.string_a, "BPTK_SEMAPHORE"), scenario: [["kernel32.dll", "CreateSemaphoreA", [0, 1, 4, address.string_a]]], argument: [0, 0, address.string_a] };
  define("kernel32.dll", "OpenSemaphoreA", openSemaphoreHit, oracleCall("kernel32.dll", "OpenSemaphoreA", openSemaphoreHit));
  const openSemaphoreMiss = { prepare: writeNameW(address.string_a, "BPTK_SEMAPHORE"), argument: [0, 0, address.string_a] };
  define("kernel32.dll", "OpenSemaphoreW", openSemaphoreMiss, oracleCall("kernel32.dll", "OpenSemaphoreW", openSemaphoreMiss));
  const addressChanged = { prepare: (guest) => {
      guest.memory.writeMemory(address.scratch_dword, 4, 5);
      guest.memory.writeMemory(address.string_a, 4, 6);
    }, argument: [address.scratch_dword, address.string_a, 4, 0] };
  define("kernel32.dll", "WaitOnAddress", addressChanged, oracleCall("kernel32.dll", "WaitOnAddress", addressChanged));
  define("kernel32.dll", "WakeByAddressAll", argument([address.scratch_dword]), oracleCall("kernel32.dll", "WakeByAddressAll", [address.scratch_dword]));
  define("kernel32.dll", "WakeByAddressSingle", argument([address.scratch_dword]), oracleCall("kernel32.dll", "WakeByAddressSingle", [address.scratch_dword]));
  define("kernel32.dll", "ExitThread", argument([0]), exitExpected);
  define("kernel32.dll", "GetExitCodeThread", argument([0xfffffffe, address.scratch_dword]), oracleCall("kernel32.dll", "GetExitCodeThread", [0xfffffffe, address.scratch_dword]));
  define("kernel32.dll", "FreeLibraryAndExitThread", argument([kernel32Module, 7]), exitExpected);
  const interlockedAnd = { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 0xff00ff00), argument: [address.scratch_dword, 0x0f0f0f0f] };
  define("kernel32.dll", "InterlockedAnd", interlockedAnd, oracleCall("kernel32.dll", "InterlockedAnd", interlockedAnd));
  const interlockedOr = { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 0x80000000), argument: [address.scratch_dword, 1] };
  define("kernel32.dll", "InterlockedOr", interlockedOr, oracleCall("kernel32.dll", "InterlockedOr", interlockedOr));
  const interlockedXor = { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 0x000000ff), argument: [address.scratch_dword, 0x0000000f] };
  define("kernel32.dll", "InterlockedXor", interlockedXor, oracleCall("kernel32.dll", "InterlockedXor", interlockedXor));
  const interlockedCasPointer = { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 0x00400000), argument: [address.scratch_dword, 0x00401000, 0x00400000] };
  define("kernel32.dll", "InterlockedCompareExchangePointer", interlockedCasPointer, oracleCall("kernel32.dll", "InterlockedCompareExchangePointer", interlockedCasPointer));
  const interlockedExchangePointer = { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 0x00400000), argument: [address.scratch_dword, 0x00401000] };
  define("kernel32.dll", "InterlockedExchangePointer", interlockedExchangePointer, oracleCall("kernel32.dll", "InterlockedExchangePointer", interlockedExchangePointer));
  define("kernel32.dll", "InterlockedCompareExchange64", argument([address.scratch_dword, 0, 0]), { return_value: null, last_error: "kernel32.dll!InterlockedCompareExchange64 returns a 64-bit prior value the bounded integer probe cannot carry across the EAX dispatch boundary" });
  define("kernel32.dll", "ResumeThread", argument([0xfffffffe]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "SuspendThread", argument([0xfffffffe]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetThreadContext", argument([0xfffffffe, address.scratch]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetThreadContext", argument([0xfffffffe, address.scratch]), { return_value: 1, last_error: 0 });

  // lock-free singly linked list
  define("kernel32.dll", "InitializeSListHead", argument([address.slist_head]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "InterlockedPushEntrySList", argument([address.slist_head, address.slist_entry]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "InterlockedPopEntrySList", scenario([["kernel32.dll", "InterlockedPushEntrySList", [address.slist_head, address.slist_entry]]], [address.slist_head]), { return_value: address.slist_entry, last_error: 0 });
  define("kernel32.dll", "InterlockedFlushSList", scenario([["kernel32.dll", "InterlockedPushEntrySList", [address.slist_head, address.slist_entry]]], [address.slist_head]), { return_value: address.slist_entry, last_error: 0 });
  define("kernel32.dll", "QueryDepthSList", scenario([["kernel32.dll", "InterlockedPushEntrySList", [address.slist_head, address.slist_entry]]], [address.slist_head]), { return_value: 1, last_error: 0 });

  // pointer encoding
  define("kernel32.dll", "EncodePointer", argument([0x12345678]), { return_value: (0x12345678 ^ hleProfile.pointer_cookie) >>> 0, last_error: 0 });
  define("kernel32.dll", "DecodePointer", argument([(0x12345678 ^ hleProfile.pointer_cookie) >>> 0]), { return_value: 0x12345678, last_error: 0 });

  // structured exception filter and vectored handler registration
  define("kernel32.dll", "SetUnhandledExceptionFilter", argument([0x00401000]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "AddVectoredExceptionHandler", argument([1, 0x00401000]), { return_value: 0x00080001, last_error: 0 });
  define("kernel32.dll", "AddVectoredExceptionHandler", argument([0, 0]), { return_value: 0, last_error: errorValue.invalid_parameter });
  define("kernel32.dll", "RemoveVectoredExceptionHandler", scenario([["kernel32.dll", "AddVectoredExceptionHandler", [1, 0x00401000]]], [0x00080001]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "RemoveVectoredExceptionHandler", argument([0x00080001]), { return_value: 0, last_error: 0 });

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

  // kernel32 string family (BPTK-101 breadth)
  const writeStringPair = (leftAnsi, rightAnsi) => (guest) => {
    guest.writeAnsiString(address.string_a, leftAnsi, 32);
    guest.writeAnsiString(address.string_b, rightAnsi, 32);
  };
  const writeWidePair = (leftWide, rightWide) => (guest) => {
    guest.writeWideString(address.string_a, leftWide, 32);
    guest.writeWideString(address.string_b, rightWide, 32);
  };
  define("kernel32.dll", "lstrcmpA", { prepare: writeStringPair("abc", "abc"), argument: [address.string_a, address.string_b] }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "lstrcmpA", { prepare: writeStringPair("abc", "abd"), argument: [address.string_a, address.string_b] }, { return_value: unsigned(-1), last_error: 0 });
  define("kernel32.dll", "lstrcmpA", { prepare: writeStringPair("abd", "abc"), argument: [address.string_a, address.string_b] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "lstrcmpiA", { prepare: writeStringPair("ABC", "abc"), argument: [address.string_a, address.string_b] }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "lstrcmpW", { prepare: writeWidePair("abc", "abc"), argument: [address.string_a, address.string_b] }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "lstrcmpiW", { prepare: writeWidePair("ABC", "abc"), argument: [address.string_a, address.string_b] }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "lstrcpyA", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hello", 16), argument: [address.string_dest, address.string_a] }, { return_value: address.string_dest, last_error: 0 });
  define("kernel32.dll", "lstrcpyA", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "lstrcpyW", { prepare: (guest) => guest.writeWideString(address.string_a, "hi", 16), argument: [address.string_dest, address.string_a] }, { return_value: address.string_dest, last_error: 0 });
  define("kernel32.dll", "lstrcpynA", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hello", 16), argument: [address.string_dest, address.string_a, 3] }, { return_value: address.string_dest, last_error: 0 });
  define("kernel32.dll", "lstrcatA", { prepare: (guest) => { guest.writeAnsiString(address.string_dest, "ab", 16); guest.writeAnsiString(address.string_a, "cd", 16); }, argument: [address.string_dest, address.string_a] }, { return_value: address.string_dest, last_error: 0 });
  define("kernel32.dll", "lstrcatW", { prepare: (guest) => { guest.writeWideString(address.string_dest, "ab", 16); guest.writeWideString(address.string_a, "cd", 16); }, argument: [address.string_dest, address.string_a] }, { return_value: address.string_dest, last_error: 0 });

  // interlocked atomics (BPTK-101 breadth)
  const seedDword = (value) => (guest) => guest.memory.writeMemory(address.scratch_dword, 4, value);
  define("kernel32.dll", "InterlockedIncrement", { prepare: seedDword(5), argument: [address.scratch_dword] }, { return_value: 6, last_error: 0 });
  define("kernel32.dll", "InterlockedDecrement", { prepare: seedDword(5), argument: [address.scratch_dword] }, { return_value: 4, last_error: 0 });
  define("kernel32.dll", "InterlockedExchange", { prepare: seedDword(5), argument: [address.scratch_dword, 99] }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "InterlockedExchangeAdd", { prepare: seedDword(5), argument: [address.scratch_dword, 10] }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "InterlockedCompareExchange", { prepare: seedDword(5), argument: [address.scratch_dword, 99, 5] }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "InterlockedCompareExchange", { prepare: seedDword(5), argument: [address.scratch_dword, 99, 7] }, { return_value: 5, last_error: 0 });

  // scaled arithmetic and system profile (BPTK-101 breadth)
  define("kernel32.dll", "MulDiv", argument([10, 3, 4]), { return_value: 8, last_error: 0 });
  define("kernel32.dll", "MulDiv", argument([10, 3, 0]), { return_value: unsigned(-1), last_error: 0 });
  define("kernel32.dll", "MulDiv", argument([unsigned(-10), 3, 4]), { return_value: unsigned(-8), last_error: 0 });
  define("kernel32.dll", "GetSystemInfo", argument([address.system_info]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetNativeSystemInfo", argument([address.system_info]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetSystemTime", argument([address.system_time]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetLocalTime", argument([address.system_time]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "SetErrorMode", argument([0x8000]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetErrorMode", argument([]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetErrorMode", scenario([["kernel32.dll", "SetErrorMode", [0x8000]]], []), { return_value: 0x8000, last_error: 0 });
  define("kernel32.dll", "OutputDebugStringA", { prepare: (guest) => guest.writeAnsiString(address.string_a, "trace", 16), argument: [address.string_a] }, { return_value: 0, last_error: 0 });
  define("kernel32.dll", "OutputDebugStringW", { prepare: (guest) => guest.writeWideString(address.string_a, "trace", 16), argument: [address.string_a] }, { return_value: 0, last_error: 0 });

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

  // GetEnvironmentVariable / ExpandEnvironmentStrings (BPTK-101 breadth). The
  // set step seeds PATH=C:\bin, then the getter reads it back.
  const setPathStep = ["kernel32.dll", "SetEnvironmentVariableA", [address.scratch, address.scratch_dword]];
  const seedPath = (guest) => { guest.writeAnsiString(address.scratch, "PATH", 16); guest.writeAnsiString(address.scratch_dword, "C:\\bin", 16); };
  define("kernel32.dll", "GetEnvironmentVariableA", { prepare: seedPath, scenario: [setPathStep], argument: [address.scratch, address.string_dest, 64] }, { return_value: "C:\\bin".length, last_error: 0 });
  define("kernel32.dll", "GetEnvironmentVariableA", { prepare: (guest) => guest.writeAnsiString(address.scratch, "MISSING", 16), argument: [address.scratch, address.string_dest, 64] }, { return_value: 0, last_error: 203 });
  define("kernel32.dll", "GetEnvironmentVariableW", { prepare: (guest) => guest.writeWideString(address.scratch, "NOPE", 16), argument: [address.scratch, address.string_dest, 64] }, { return_value: 0, last_error: 203 });
  define("kernel32.dll", "ExpandEnvironmentStringsA", { prepare: (guest) => { seedPath(guest); guest.writeAnsiString(address.string_a, "p=%PATH%", 32); }, scenario: [setPathStep], argument: [address.string_a, address.string_dest, 64] }, { return_value: "p=C:\\bin".length + 1, last_error: 0 });
  define("kernel32.dll", "ExpandEnvironmentStringsW", { prepare: (guest) => guest.writeWideString(address.string_a, "none", 32), argument: [address.string_a, address.string_dest, 64] }, { return_value: "none".length + 1, last_error: 0 });

  // virtual drive (BPTK-015 slice)
  const savePath = 0x00156000;
  const absentPath = 0x00156100;
  const traversalPath = 0x00156200;
  const fileData = 0x00157000;
  const fileReadBack = 0x00157100;
  const fileWritten = 0x00157200;
  const keyHandlePointer = 0x00157300;
  const keyName = 0x00157400;
  const keyData = 0x00157500;
  const keyDataLength = 0x00157600;
  const fileScenario = [["kernel32.dll", "CreateFileW", [savePath, 0xc0000000, 0, 0, 2, 0, 0]]];
  const keyScenario = [["advapi32.dll", "RegCreateKeyA", [0x80000001, keyName, keyHandlePointer]]];
  define("kernel32.dll", "CreateFileW", { prepare: (guest) => guest.writeWideString(savePath, "C:\\save.dat", 64), argument: [savePath, 0xc0000000, 0, 0, 2, 0, 0] }, { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "CreateFile2", { prepare: (guest) => guest.writeWideString(savePath, "C:\\save.dat", 64), argument: [savePath, 0xc0000000, 0, 2, 0] }, { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "CreateFileW", { prepare: (guest) => guest.writeWideString(savePath, "save.dat", 64), argument: [savePath, 0xc0000000, 0, 0, 2, 0, 0] }, { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "CreateFileW", { prepare: (guest) => guest.writeWideString(savePath, "C:\\", 64), argument: [savePath, 0x80, 7, 0, 3, 0x02000000, 0] }, { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "CreateFileW", { prepare: (guest) => guest.writeWideString(absentPath, "C:\\absent.dat", 64), argument: [absentPath, 0x80000000, 0, 0, 3, 0, 0] }, { return_value: 0xffffffff, last_error: 2 });
  define("kernel32.dll", "CreateFileW", { prepare: (guest) => guest.writeWideString(absentPath, "", 64), argument: [absentPath, 0x80, 7, 0, 3, 0x02000000, 0] }, { return_value: 0xffffffff, last_error: 3 });
  define("kernel32.dll", "CreateFileW", { prepare: (guest) => guest.writeWideString(traversalPath, "C:\\..\\evil.dat", 64), argument: [traversalPath, 0xc0000000, 0, 0, 2, 0, 0] }, { return_value: 0xffffffff, last_error: 87 });
  define("kernel32.dll", "WriteFile", {
    prepare: (guest) => guest.writeAnsiString(fileData, "SAVE", 16) && guest.writeWideString(savePath, "C:\\save.dat", 64),
    scenario: fileScenario,
    argument: [firstHandle, fileData, 4, fileWritten, 0],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "ReadFile", {
    prepare: (guest) => guest.writeAnsiString(fileData, "SAVE", 16) && guest.writeWideString(savePath, "C:\\save.dat", 64),
    scenario: [...fileScenario, ["kernel32.dll", "WriteFile", [firstHandle, fileData, 4, 0, 0]], ["kernel32.dll", "SetFilePointerEx", [firstHandle, 0, 0, 0, 0]]],
    argument: [firstHandle, fileReadBack, 4, fileWritten, 0],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "ReadFile", scenario([["kernel32.dll", "GetStdHandle", [-10]]], [firstHandle, fileData, 4, 0, 0]), { return_value: 0, last_error: 5 });
  define("kernel32.dll", "SetFilePointerEx", {
    prepare: (guest) => guest.writeWideString(savePath, "C:\\save.dat", 64),
    scenario: fileScenario,
    argument: [firstHandle, 1, 0xffffffff, 0, 0],
  }, { return_value: 0xffffffff, last_error: 131 });
  define("kernel32.dll", "SetEndOfFile", { prepare: (guest) => guest.writeWideString(savePath, "C:\\save.dat", 64), scenario: fileScenario, argument: [firstHandle] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FlushFileBuffers", { prepare: (guest) => guest.writeWideString(savePath, "C:\\save.dat", 64), scenario: fileScenario, argument: [firstHandle] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "CloseHandle", { prepare: (guest) => guest.writeWideString(savePath, "C:\\save.dat", 64), scenario: fileScenario, argument: [firstHandle] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "CloseHandle", argument([0xdeadbeef]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "GetFileType", { prepare: (guest) => guest.writeWideString(savePath, "C:\\save.dat", 64), scenario: fileScenario, argument: [firstHandle] }, { return_value: 3, last_error: 0 });
  define("kernel32.dll", "GetFileType", argument([0xdeadbeef]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "SetStdHandle", argument([-11, firstHandle]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetConsoleMode", scenario([["kernel32.dll", "GetStdHandle", [-11]]], [firstHandle, address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetConsoleMode", argument([0xdeadbeef, address.scratch_dword]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "GetConsoleCP", argument([]), { return_value: 1252, last_error: 0 });
  define("kernel32.dll", "ReadConsoleW", scenario([["kernel32.dll", "GetStdHandle", [-10]]], [firstHandle, fileData, 4, 0, 0]), { return_value: 0, last_error: 5 });

  // registry (advapi32, BPTK-015 slice)
  define("advapi32.dll", "RegCreateKeyA", { prepare: (guest) => guest.writeAnsiString(keyName, "Software\\BPTK", 64), argument: [0x80000001, keyName, keyHandlePointer] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegOpenKeyA", { prepare: (guest) => guest.writeAnsiString(keyName, "Software\\BPTK", 64), argument: [0x80000001, keyName, keyHandlePointer] }, { return_value: 3, last_error: 3 });
  define("advapi32.dll", "RegOpenKeyExW", { prepare: (guest) => guest.writeWideString(absentPath, "Software\\Absent", 64), argument: [0x80000001, absentPath, 0, 0, keyHandlePointer] }, { return_value: 3, last_error: 3 });
  define("advapi32.dll", "RegSetValueExA", {
    prepare: (guest) => {
      guest.writeAnsiString(keyName, "Software\\BPTK", 64);
      guest.writeAnsiString(fileData, "ok", 16);
    },
    scenario: keyScenario,
    argument: [firstHandle, fileData, 0, 1, keyData, 2],
  }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegQueryValueExA", {
    prepare: (guest) => {
      guest.writeAnsiString(keyName, "Software\\BPTK", 64);
      guest.writeAnsiString(fileData, "ok", 16);
      guest.writeAnsiString(keyData, "xxxx", 16);
      guest.memory.writeMemory(keyDataLength, 4, 64);
    },
    scenario: [...keyScenario, ["advapi32.dll", "RegSetValueExA", [firstHandle, fileData, 0, 1, keyData, 2]]],
    argument: [firstHandle, fileData, 0, 0, keyData, keyDataLength],
  }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegQueryValueExA", {
    prepare: (guest) => guest.writeAnsiString(keyName, "Software\\BPTK", 64),
    scenario: keyScenario,
    argument: [firstHandle, fileData, 0, keyDataLength, keyData, 0],
  }, { return_value: 2, last_error: 2 });
  define("advapi32.dll", "RegCloseKey", { prepare: (guest) => guest.writeAnsiString(keyName, "Software\\BPTK", 64), scenario: keyScenario, argument: [firstHandle] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegCloseKey", argument([0xdeadbeef]), { return_value: 6, last_error: 6 });

  // registry breadth and fidelity (BPTK-098)
  const prepareKeyName = (guest) => guest.writeAnsiString(keyName, "Software\\BPTK", 64);
  const setValueScenario = [...keyScenario, ["advapi32.dll", "RegSetValueExA", [firstHandle, fileData, 0, 1, keyData, 2]]];
  const prepareSetValue = (guest) => {
    prepareKeyName(guest);
    guest.writeAnsiString(fileData, "V", 16); // value name
    guest.writeAnsiString(keyData, "ok", 16);
  };
  define("advapi32.dll", "RegOpenKeyExA", { prepare: prepareKeyName, scenario: keyScenario, argument: [0x80000001, keyName, 0, 0, keyHandlePointer] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegOpenKeyExA", { prepare: (guest) => guest.writeAnsiString(absentPath, "Software\\None", 64), argument: [0x80000001, absentPath, 0, 0, keyHandlePointer] }, { return_value: 3, last_error: 3 });
  define("advapi32.dll", "RegCreateKeyExA", { prepare: prepareKeyName, argument: [0x80000001, keyName, 0, 0, 0, 0, 0, keyHandlePointer, keyDataLength] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegCreateKeyExW", { prepare: (guest) => guest.writeWideString(absentPath, "Software\\Wide", 64), argument: [0x80000001, absentPath, 0, 0, 0, 0, 0, keyHandlePointer, keyDataLength] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegSetValueExW", {
    prepare: (guest) => { prepareKeyName(guest); guest.writeWideString(absentPath, "WVal", 32); guest.writeAnsiString(keyData, "ok", 16); },
    scenario: keyScenario,
    argument: [firstHandle, absentPath, 0, 1, keyData, 2],
  }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegQueryValueExW", {
    prepare: (guest) => { prepareKeyName(guest); guest.writeWideString(absentPath, "WVal", 32); guest.writeAnsiString(keyData, "ok", 16); guest.memory.writeMemory(keyDataLength, 4, 64); },
    scenario: [...keyScenario, ["advapi32.dll", "RegSetValueExW", [firstHandle, absentPath, 0, 1, keyData, 2]]],
    argument: [firstHandle, absentPath, 0, 0, keyData, keyDataLength],
  }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegDeleteValueA", { prepare: prepareSetValue, scenario: setValueScenario, argument: [firstHandle, fileData] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegDeleteValueA", { prepare: (guest) => { prepareKeyName(guest); guest.writeAnsiString(fileData, "nope", 16); }, scenario: keyScenario, argument: [firstHandle, fileData] }, { return_value: 2, last_error: 2 });
  define("advapi32.dll", "RegDeleteValueW", {
    prepare: (guest) => { prepareKeyName(guest); guest.writeWideString(absentPath, "WVal", 32); guest.writeAnsiString(keyData, "ok", 16); },
    scenario: [...keyScenario, ["advapi32.dll", "RegSetValueExW", [firstHandle, absentPath, 0, 1, keyData, 2]]],
    argument: [firstHandle, absentPath],
  }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegDeleteKeyA", { prepare: prepareKeyName, scenario: keyScenario, argument: [0x80000001, keyName] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegDeleteKeyW", { prepare: (guest) => guest.writeWideString(absentPath, "Software\\None", 64), argument: [0x80000001, absentPath] }, { return_value: 2, last_error: 2 });
  define("advapi32.dll", "RegFlushKey", { prepare: prepareKeyName, scenario: keyScenario, argument: [firstHandle] }, { return_value: 0, last_error: 0 });
  define("advapi32.dll", "RegFlushKey", argument([0xdeadbeef]), { return_value: 6, last_error: 6 });

  // ws2_32 Winsock lifecycle (BPTK-099). The WSADATA buffer lives at
  // startup_info, the sockaddr_in at string_b, the FIONBIO argp at scratch_dword.
  const wsaData = address.startup_info;
  const sockAddr = address.string_b;
  const startupStep = ["ws2_32.dll", "WSAStartup", [0x0202, wsaData]];
  const socketStep = ["ws2_32.dll", "socket", [2, 1, 6]];
  const writeSockAddr = (guest) => {
    guest.memory.writeMemory(sockAddr + 0, 2, 2); // AF_INET
    guest.memory.writeMemory(sockAddr + 2, 1, 0x1f); guest.memory.writeMemory(sockAddr + 3, 1, 0x90); // port 8080 network order
    [1, 2, 3, 4].forEach((octet, index) => guest.memory.writeMemory(sockAddr + 4 + index, 1, octet));
  };
  define("ws2_32.dll", "WSAStartup", argument([0x0202, wsaData]), { return_value: 0, last_error: 0 });
  define("ws2_32.dll", "WSAStartup", argument([0, wsaData]), { return_value: 10022, last_error: 0 });
  define("ws2_32.dll", "WSACleanup", argument([]), { return_value: 0, last_error: 0 });
  define("ws2_32.dll", "WSAGetLastError", argument([]), { return_value: 0, last_error: 0 });
  define("ws2_32.dll", "socket", scenario([startupStep], [2, 1, 6]), { return_value: 1, last_error: 0 });
  define("ws2_32.dll", "socket", argument([2, 1, 6]), { return_value: unsigned(-1), last_error: 0 });
  define("ws2_32.dll", "closesocket", scenario([startupStep, socketStep], [1]), { return_value: 0, last_error: 0 });
  define("ws2_32.dll", "closesocket", argument([99]), { return_value: unsigned(-1), last_error: 0 });
  define("ws2_32.dll", "bind", { prepare: writeSockAddr, scenario: [startupStep, socketStep], argument: [1, sockAddr] }, { return_value: unsigned(-1), last_error: 0 });
  define("ws2_32.dll", "connect", { prepare: writeSockAddr, scenario: [startupStep, socketStep], argument: [1, sockAddr] }, { return_value: unsigned(-1), last_error: 0 });
  define("ws2_32.dll", "send", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hi", 16), scenario: [startupStep, socketStep], argument: [1, address.string_a, 2, 0] }, { return_value: unsigned(-1), last_error: 0 });
  define("ws2_32.dll", "recv", { scenario: [startupStep, socketStep], argument: [1, address.string_a, 16, 0] }, { return_value: unsigned(-1), last_error: 0 });
  define("ws2_32.dll", "ioctlsocket", { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 1), scenario: [startupStep, socketStep], argument: [1, 0x8004667e, address.scratch_dword] }, { return_value: 0, last_error: 0 });
  define("ws2_32.dll", "htons", argument([0x1234]), { return_value: 0x3412, last_error: 0 });
  define("ws2_32.dll", "ntohs", argument([0x1234]), { return_value: 0x3412, last_error: 0 });
  define("ws2_32.dll", "htonl", argument([0x12345678]), { return_value: 0x78563412, last_error: 0 });
  define("ws2_32.dll", "ntohl", argument([0x12345678]), { return_value: 0x78563412, last_error: 0 });
  define("ws2_32.dll", "inet_addr", { prepare: (guest) => guest.writeAnsiString(address.string_a, "1.2.3.4", 16), argument: [address.string_a] }, { return_value: 0x01020304, last_error: 0 });
  define("ws2_32.dll", "inet_addr", { prepare: (guest) => guest.writeAnsiString(address.string_a, "999.1.1.1", 16), argument: [address.string_a] }, { return_value: unsigned(-1), last_error: 0 });
  const wsaEventStep = ["ws2_32.dll", "WSACreateEvent", []];
  define("ws2_32.dll", "WSACreateEvent", argument([]), { return_value: firstHandle, last_error: 0 });
  define("ws2_32.dll", "WSACloseEvent", scenario([wsaEventStep], [firstHandle]), { return_value: 1, last_error: 0 });
  define("ws2_32.dll", "WSACloseEvent", argument([0xdeadbeef]), { return_value: 0, last_error: 6 });
  define("ws2_32.dll", "WSASetEvent", scenario([wsaEventStep], [firstHandle]), { return_value: 1, last_error: 0 });
  define("ws2_32.dll", "WSAResetEvent", scenario([wsaEventStep], [firstHandle]), { return_value: 1, last_error: 0 });
  define("ws2_32.dll", "WSAWaitForMultipleEvents", {
    prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, firstHandle),
    scenario: [wsaEventStep, ["ws2_32.dll", "WSASetEvent", [firstHandle]]],
    argument: [1, address.scratch_dword, 0, 0, 0],
  }, { return_value: 0, last_error: 0 });
  define("ws2_32.dll", "WSAWaitForMultipleEvents", {
    prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, firstHandle),
    scenario: [wsaEventStep],
    argument: [1, address.scratch_dword, 0, 0, 0],
  }, { return_value: 0x102, last_error: 0 });
  define("ws2_32.dll", "WSAEventSelect", {
    scenario: [startupStep, socketStep, wsaEventStep],
    argument: [1, firstHandle, 0x2b],
  }, { return_value: 0, last_error: 0 });
  define("ws2_32.dll", "WSAEventSelect", argument([99, 0, 0]), { return_value: unsigned(-1), last_error: 10038 });
  define("ws2_32.dll", "WSAEnumNetworkEvents", {
    scenario: [startupStep, socketStep, wsaEventStep],
    argument: [1, firstHandle, address.startup_info],
  }, { return_value: 0, last_error: 0 });

  // secur32 SSPI: the interface exists; no package is installed.
  const sspiTable = hleCrtDataLayout({ arena_base: 0x00100000, arena_size_byte: 0x00200000 }).sspi_table;
  const sspiMissing = 0x80090305;
  const sspiInvalid = 0x80090301;
  define("secur32.dll", "InitSecurityInterfaceW", argument([]), { return_value: sspiTable, last_error: 0 });
  define("secur32.dll", "EnumerateSecurityPackagesW", argument([address.scratch_dword, address.scratch]), { return_value: 0, last_error: 0 });
  define("secur32.dll", "QueryCredentialsAttributesW", argument([0, 1, address.scratch]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "AcquireCredentialsHandleW", argument([0, 0, 2, 0, 0, 0, 0, address.scratch, 0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "FreeCredentialsHandle", argument([0]), { return_value: 0, last_error: 0 });
  define("secur32.dll", "FreeCredentialsHandle", argument([1]), { return_value: sspiInvalid, last_error: 0 });
  define("secur32.dll", "InitializeSecurityContextW", argument([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "AcceptSecurityContext", argument([0, 0, 0, 0, 0, 0, 0, 0, 0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "CompleteAuthToken", argument([0, 0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "DeleteSecurityContext", argument([0]), { return_value: 0, last_error: 0 });
  define("secur32.dll", "ApplyControlToken", argument([0, 0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "QueryContextAttributesW", argument([0, 1, address.scratch]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "ImpersonateSecurityContext", argument([0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "RevertSecurityContext", argument([0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "MakeSignature", argument([0, 0, 0, 0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "VerifySignature", argument([0, 0, 0, 0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "FreeContextBuffer", argument([0]), { return_value: 0, last_error: 0 });
  define("secur32.dll", "QuerySecurityPackageInfoW", argument([address.string_a, address.scratch_dword]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "ExportSecurityContext", argument([0, 0, 0, 0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "ImportSecurityContextW", argument([0, 0, 0, 0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "AddCredentialsW", argument([0, 0, 0, 0, 0, 0, 0, 0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "QuerySecurityContextToken", argument([0, address.scratch_dword]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "EncryptMessage", argument([0, 0, 0, 0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "DecryptMessage", argument([0, 0, 0, 0]), { return_value: sspiMissing, last_error: 0 });
  define("secur32.dll", "SetContextAttributesW", argument([0, 1, address.scratch, 0]), { return_value: sspiMissing, last_error: 0 });

  // virtual drive geometry and optical volume (BPTK-102). The root path lives at
  // string_a (wide) / string_b (ansi); output buffers at string_dest.
  const driveOut = address.string_dest;
  define("kernel32.dll", "GetLogicalDrives", argument([]), { return_value: 0x0c, last_error: 0 });
  define("kernel32.dll", "GetDriveTypeW", { prepare: (guest) => guest.writeWideString(address.string_a, "C:\\", 16), argument: [address.string_a] }, { return_value: 3, last_error: 0 });
  define("kernel32.dll", "GetDriveTypeW", { prepare: (guest) => guest.writeWideString(address.string_a, "D:\\", 16), argument: [address.string_a] }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "GetDriveTypeA", { prepare: (guest) => guest.writeAnsiString(address.string_b, "E:\\", 16), argument: [address.string_b] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetVolumeInformationW", { prepare: (guest) => guest.writeWideString(address.string_a, "C:\\", 16), argument: [address.string_a, driveOut, 32, address.scratch_dword, 0, 0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetVolumeInformationA", { prepare: (guest) => guest.writeAnsiString(address.string_b, "D:\\", 16), argument: [address.string_b, driveOut, 32, address.scratch_dword, 0, 0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetDiskFreeSpaceExA", { prepare: (guest) => guest.writeAnsiString(address.string_b, "C:\\", 16), argument: [address.string_b, driveOut, driveOut + 8, driveOut + 16] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetDiskFreeSpaceA", { prepare: (guest) => guest.writeAnsiString(address.string_b, "C:\\", 16), argument: [address.string_b, driveOut, driveOut + 4, driveOut + 8, driveOut + 12] }, { return_value: 1, last_error: 0 });

  // XInput gamepad (BPTK-097): the default slot is disconnected, so the getters
  // report ERROR_DEVICE_NOT_CONNECTED; the connected path is proven in a unit
  // test that injects a controller state.
  define("xinput1_3.dll", "XInputGetState", argument([0, address.string_dest]), { return_value: 1167, last_error: 0 });
  define("xinput1_3.dll", "XInputSetState", argument([0, address.string_dest]), { return_value: 1167, last_error: 0 });
  define("xinput1_3.dll", "XInputGetCapabilities", argument([0, 0, address.string_dest]), { return_value: 1167, last_error: 0 });
  define("xinput1_3.dll", "XInputEnable", argument([1]), { return_value: 0, last_error: 0 });

  // locale, codepage, and Unicode conversion (BPTK-103 slice)
  const localePath = 0x00158000;
  const localeWide = 0x00159000;
  const localeWideSecond = 0x00159100;
  const localeTypes = 0x0015a000;
  define("kernel32.dll", "GetACP", argument([]), { return_value: 1252, last_error: 0 });
  define("kernel32.dll", "GetOEMCP", argument([]), { return_value: 1252, last_error: 0 });
  define("kernel32.dll", "IsValidCodePage", argument([1252]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "IsValidCodePage", argument([932]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetCPInfo", { prepare: (guest) => guest.memory.writeMemory(address.startup_info, 4, 0), argument: [1252, address.startup_info] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetCPInfo", { prepare: (guest) => guest.memory.writeMemory(address.startup_info, 4, 0), argument: [0, address.startup_info] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetCPInfo", argument([932, address.startup_info]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "IsValidCodePage", argument([0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetUserDefaultLCID", argument([]), { return_value: 0x0409, last_error: 0 });
  define("kernel32.dll", "GetLocaleInfoW", { prepare: (guest) => guest.memory.writeMemory(address.startup_info, 4, 0), argument: [0x0409, 0x1002, localeWide, 64] }, { return_value: "United States".length + 1, last_error: 0 });
  define("kernel32.dll", "GetLocaleInfoW", argument([0x0409, 0x9999, localeWide, 64]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "CompareStringW", {
    prepare: (guest) => guest.writeWideString(localeWide, "abcd", 32) && guest.writeWideString(localeWideSecond, "abcd", 32),
    argument: [0x0409, 0, localeWide, 4, localeWideSecond, 4],
  }, { return_value: 2, last_error: 0 });
  define("kernel32.dll", "CompareStringW", {
    prepare: (guest) => guest.writeWideString(localeWide, "ABC", 32) && guest.writeWideString(localeWideSecond, "abd", 32),
    argument: [0x0409, 0x1, localeWide, 3, localeWideSecond, 3],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "LCMapStringW", {
    prepare: (guest) => guest.writeWideString(localeWide, "MiXeD", 32),
    argument: [0x0409, 0x200, localeWide, 5, localeWideSecond, 32],
  }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "LCMapStringEx", {
    prepare: (guest) => guest.writeWideString(localeWide, "MiXeD", 32),
    argument: [0, 0x200, localeWide, 5, localeWideSecond, 32, 0, 0, 0],
  }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "LCMapStringEx", {
    prepare: (guest) => guest.writeWideString(localeWide, "MiXeD", 32),
    argument: [0, 0x200, localeWide, 5, 0, 0, 0, 0, 0],
  }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "LCMapStringEx", {
    prepare: (guest) => guest.writeWideString(localeWide, "MiXeD", 32),
    argument: [0, 0x200, localeWide, 5, 0, 256, 0, 0, 0],
  }, { return_value: 0, last_error: 87 });
  define("kernel32.dll", "LocaleNameToLCID", {
    prepare: (guest) => guest.writeWideString(localeWide, "en-US", 32),
    argument: [localeWide, 0],
  }, { return_value: 0x0409, last_error: 0 });
  define("kernel32.dll", "IsValidLocaleName", {
    prepare: (guest) => guest.writeWideString(localeWide, "en-US", 32),
    argument: [localeWide],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetUserDefaultLocaleName", argument([localeWide, 32]), { return_value: 6, last_error: 0 });
  define("kernel32.dll", "LCIDToLocaleName", argument([0x0409, localeWide, 32, 0]), { return_value: 6, last_error: 0 });
  define("kernel32.dll", "CompareStringEx", {
    prepare: (guest) => guest.writeWideString(localeWide, "abcd", 32) && guest.writeWideString(localeWideSecond, "abcd", 32),
    argument: [0, 0, localeWide, 4, localeWideSecond, 4, 0, 0, 0],
  }, { return_value: 2, last_error: 0 });
  define("kernel32.dll", "GetDateFormatEx", {
    prepare: (guest) => {
      guest.memory.writeMemory(address.startup_info, 2, 2020);
      guest.memory.writeMemory(address.startup_info + 2, 2, 9);
      guest.memory.writeMemory(address.startup_info + 4, 2, 4);
      guest.memory.writeMemory(address.startup_info + 6, 2, 10);
    },
    argument: [0, 0, address.startup_info, 0, localeWide, 64, 0],
  }, { return_value: "9/10/2020".length + 1, last_error: 0 });
  define("kernel32.dll", "GetTimeFormatEx", {
    prepare: (guest) => {
      guest.memory.writeMemory(address.startup_info, 2, 2020);
      guest.memory.writeMemory(address.startup_info + 8, 2, 18);
      guest.memory.writeMemory(address.startup_info + 10, 2, 40);
      guest.memory.writeMemory(address.startup_info + 12, 2, 5);
    },
    argument: [0, 0, address.startup_info, 0, localeWide, 64, 0],
  }, { return_value: "18:40:05".length + 1, last_error: 0 });
  define("kernel32.dll", "AppPolicyGetProcessTerminationMethod", argument([0, address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "AppPolicyGetShowDeveloperDiagnostic", argument([0, address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "AppPolicyGetThreadInitializationType", argument([0, address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "AppPolicyGetWindowingModel", argument([0, address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "LCMapStringW", {
    prepare: (guest) => guest.writeWideString(localeWide, "MiXeD", 32),
    argument: [0x0409, 0x400, localeWide, 5, localeWideSecond, 32],
  }, { return_value: 0, last_error: 87 });
  define("kernel32.dll", "GetStringTypeW", {
    prepare: (guest) => guest.writeWideString(localeWide, "Ab1 ", 32),
    argument: [1, localeWide, 4, localeTypes],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetStringTypeW", {
    prepare: (guest) => guest.writeWideString(localeWide, "Ab", 32),
    argument: [3, localeWide, 2, localeTypes],
  }, { return_value: 0, last_error: 87 });
  define("kernel32.dll", "GetTimeZoneInformation", argument([address.startup_info]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "MultiByteToWideChar", {
    prepare: (guest) => guest.writeAnsiString(address.scratch, "Hello", 32),
    argument: [65001, 0, address.scratch, 5, localeWide, 32],
  }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "MultiByteToWideChar", {
    prepare: (guest) => guest.memory.writeMemory(address.scratch, 1, 0x80),
    argument: [1252, 0, address.scratch, 1, localeWide, 32],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "MultiByteToWideChar", {
    prepare: (guest) => guest.writeAnsiString(address.scratch, "Hello", 32),
    argument: [932, 0, address.scratch, 5, localeWide, 32],
  }, { return_value: 0, last_error: 87 });
  define("kernel32.dll", "WideCharToMultiByte", {
    prepare: (guest) => guest.writeWideString(localeWide, "Hello", 32),
    argument: [1252, 0, localeWide, 5, address.scratch, 64],
  }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "WideCharToMultiByte", {
    prepare: (guest) => guest.writeWideString(localeWide, "Hello", 32),
    argument: [0, 0, localeWide, 5, address.scratch, 64],
  }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "MultiByteToWideChar", {
    prepare: (guest) => guest.writeAnsiString(address.scratch, "Hello", 32),
    argument: [0, 0, address.scratch, 5, localeWide, 32],
  }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "MultiByteToWideChar", {
    prepare: (guest) => guest.writeAnsiString(address.scratch, "Hello", 32),
    argument: [0, 8, address.scratch, 5, localeWide, 5],
  }, { return_value: 5, last_error: 0 });
  define("kernel32.dll", "WideCharToMultiByte", {
    prepare: (guest) => guest.writeWideString(localeWide, "Hello", 32),
    argument: [65001, 0, localeWide, 5, address.scratch, 4],
  }, { return_value: 0, last_error: 122 });
  define("kernel32.dll", "GetDateFormatW", {
    prepare: (guest) => {
      // SYSTEMTIME 2020-09-10 Thursday 18:40
      guest.memory.writeMemory(address.startup_info, 2, 2020);
      guest.memory.writeMemory(address.startup_info + 2, 2, 9);
      guest.memory.writeMemory(address.startup_info + 4, 2, 4);
      guest.memory.writeMemory(address.startup_info + 6, 2, 10);
    },
    argument: [0x0409, 0, address.startup_info, 0, localeWide, 64],
  }, { return_value: "9/10/2020".length + 1, last_error: 0 });
  define("kernel32.dll", "GetTimeFormatW", {
    prepare: (guest) => {
      guest.memory.writeMemory(address.startup_info, 2, 2020);
      guest.memory.writeMemory(address.startup_info + 8, 2, 18);
      guest.memory.writeMemory(address.startup_info + 10, 2, 40);
      guest.memory.writeMemory(address.startup_info + 12, 2, 5);
    },
    argument: [0x0409, 0, address.startup_info, 0, localeWide, 64],
  }, { return_value: "18:40:05".length + 1, last_error: 0 });

  // module loading and memory/time probe (BPTK-010 slice)
  const dllName = 0x0015c000;
  const timeFields = 0x0015d000;
  define("kernel32.dll", "LoadLibraryA", { prepare: (guest) => guest.writeAnsiString(dllName, "kernel32.dll", 32), argument: [dllName] }, { return_value: 0x00020002, last_error: 0 });
  define("kernel32.dll", "LoadLibraryA", { prepare: (guest) => guest.writeAnsiString(dllName, "evil.dll", 32), argument: [dllName] }, { return_value: 0, last_error: 126 });
  // A served system DLL loads by its full path (the guest builds a
  // system-directory-prefixed name): the Windows basename resolves the module.
  define("kernel32.dll", "LoadLibraryA", { prepare: (guest) => guest.writeAnsiString(dllName, "C:\\Windows\\System32\\ws2_32.dll", 64), argument: [dllName] }, { return_value: 0x00020006, last_error: 0 });
  define("kernel32.dll", "LoadLibraryA", { prepare: (guest) => guest.writeAnsiString(dllName, "C:\\Windows\\System32\\comctl32.dll", 64), argument: [dllName] }, { return_value: 0x00020007, last_error: 0 });
  define("kernel32.dll", "LoadLibraryW", { prepare: (guest) => guest.writeWideString(localeWide, "ole32.dll", 32), argument: [localeWide] }, { return_value: 0x00020003, last_error: 0 });
  define("kernel32.dll", "LoadLibraryExW", {
    prepare: (guest) => guest.writeWideString(localeWide, "kernel32.dll", 32),
    argument: [localeWide, 0, 8],
  }, { return_value: 0x00020002, last_error: 0 });
  define("kernel32.dll", "LoadLibraryExW", {
    prepare: (guest) => guest.writeWideString(localeWide, "kernel32", 32),
    argument: [localeWide, 0, 0x800],
  }, { return_value: 0x00020002, last_error: 0 });
  define("kernel32.dll", "LoadLibraryExW", {
    prepare: (guest) => guest.writeWideString(localeWide, "kernel32.dll", 32),
    argument: [localeWide, 0, 0x100],
  }, { return_value: 0, last_error: 87 });
  define("kernel32.dll", "LoadLibraryA", { prepare: (guest) => guest.writeAnsiString(dllName, "kernel32", 32), argument: [dllName] }, { return_value: 0x00020002, last_error: 0 });
  define("kernel32.dll", "LoadLibraryExW", {
    prepare: (guest) => guest.writeWideString(localeWide, "api-ms-win-core-synch-l1-2-0", 64),
    argument: [localeWide, 0, 0x800],
  }, { return_value: 0x00020002, last_error: 0 });
  define("kernel32.dll", "LoadLibraryA", { prepare: (guest) => guest.writeAnsiString(dllName, "kernelbase", 32), argument: [dllName] }, { return_value: 0x00020002, last_error: 0 });
  define("kernel32.dll", "FreeLibrary", argument([0x00020002]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FreeLibrary", argument([0x00020001]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "IsBadReadPtr", argument([address.scratch, 16]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "IsBadReadPtr", argument([0x00800000, 16]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "IsBadReadPtr", argument([address.scratch, 0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "Sleep", argument([500]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetTickCount", scenario([["kernel32.dll", "Sleep", [500]]], []), { return_value: 500, last_error: 0 });
  define("kernel32.dll", "GetThreadTimes", { prepare: (guest) => guest.memory.writeMemory(timeFields, 8, 0), argument: [0xfffffffe, timeFields, 0, 0, timeFields + 8] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetThreadTimes", argument([0xdeadbeef, 0, 0, 0, 0]), { return_value: 0, last_error: 6 });

  // synchronization objects, process, enumeration, winmm timer
  const eventPath = 0x0015f000;
  const findPattern = 0x0015f100;
  const findData = 0x0015f200;
  define("kernel32.dll", "CreateEventW", argument([0, 0, 1, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "CreateEventW", argument([0, 0, 1, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "SetEvent", scenario([["kernel32.dll", "CreateEventW", [0, 0, 0, 0]]], [firstHandle]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "ResetEvent", {
    prepare: (guest) => guest.writeWideString(eventPath, "evt", 16),
    scenario: [["kernel32.dll", "CreateEventW", [0, 0, 1, eventPath]]],
    argument: [firstHandle],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "WaitForSingleObject", scenario([["kernel32.dll", "CreateEventW", [0, 0, 1, 0]]], [firstHandle, 0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "WaitForSingleObject", {
    prepare: (guest) => guest.writeWideString(eventPath, "evt", 16),
    scenario: [["kernel32.dll", "CreateEventW", [0, 0, 0, eventPath]]],
    argument: [firstHandle, 100],
  }, { return_value: 0x102, last_error: 0 });
  define("kernel32.dll", "WaitForSingleObjectEx", {
    prepare: (guest) => guest.writeWideString(eventPath, "evt", 16),
    scenario: [["kernel32.dll", "CreateEventW", [0, 0, 0, eventPath]]],
    argument: [firstHandle, 0, 1],
  }, { return_value: 0x102, last_error: 0 });
  define("kernel32.dll", "WaitForSingleObject", argument([0xdeadbeef, 0]), { return_value: 0xffffffff, last_error: 6 });
  define("kernel32.dll", "OpenProcess", argument([0, 0, hleProfile.process_id]), { return_value: 0xffffffff, last_error: 0 });
  define("kernel32.dll", "OpenProcess", argument([0, 0, 777]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "IsValidLocale", argument([0x0409, 0]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "IsValidLocale", argument([0x0411, 0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "FindFirstFileExA", {
    prepare: (guest) => guest.writeAnsiString(findPattern, "C:\\*", 32) && guest.writeWideString(savePath, "C:\\save.dat", 64),
    scenario: [["kernel32.dll", "CreateFileW", [savePath, 0xc0000000, 0, 0, 2, 0, 0]]],
    argument: [findPattern, 0, findData, 0, 0, 0],
  }, { return_value: 0x00010001, last_error: 0 });
  define("kernel32.dll", "FindFirstFileExA", {
    prepare: (guest) => guest.writeAnsiString(findPattern, "C:\\nothing\\*", 32),
    argument: [findPattern, 0, findData, 0, 0, 0],
  }, { return_value: 0xffffffff, last_error: 3 });
  define("kernel32.dll", "FindNextFileA", {
    prepare: (guest) => {
      guest.writeAnsiString(findPattern, "C:\\*", 32);
      guest.writeWideString(savePath, "C:\\save.dat", 64);
      guest.writeWideString(absentPath, "C:\\other.dat", 64);
    },
    scenario: [
      ["kernel32.dll", "CreateFileW", [savePath, 0xc0000000, 0, 0, 2, 0, 0]],
      ["kernel32.dll", "CreateFileW", [absentPath, 0xc0000000, 0, 0, 2, 0, 0]],
      ["kernel32.dll", "FindFirstFileExA", [findPattern, 0, findData, 0, 0, 0]],
    ],
    argument: [0x00010002, findData],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FindNextFileA", {
    prepare: (guest) => {
      guest.writeAnsiString(findPattern, "C:\\*", 32);
      guest.writeWideString(savePath, "C:\\save.dat", 64);
    },
    scenario: [
      ["kernel32.dll", "CreateFileW", [savePath, 0xc0000000, 0, 0, 2, 0, 0]],
      ["kernel32.dll", "FindFirstFileExA", [findPattern, 0, findData, 0, 0, 0]],
    ],
    argument: [0x00010001, findData],
  }, { return_value: 0, last_error: 2 });
  // The wide directory-enumeration variants: an absent directory reports
  // path_not_found, and FindNextFileW on an invalid handle reports invalid_handle.
  define("kernel32.dll", "FindFirstFileW", { prepare: (guest) => guest.writeWideString(findPattern, "C:\\nothing\\*", 32), argument: [findPattern, findData] }, { return_value: 0xffffffff, last_error: 3 });
  define("kernel32.dll", "FindFirstFileExW", { prepare: (guest) => guest.writeWideString(findPattern, "C:\\nothing\\*", 32), argument: [findPattern, 0, findData, 0, 0, 0] }, { return_value: 0xffffffff, last_error: 3 });
  define("kernel32.dll", "FindNextFileW", argument([0, findData]), { return_value: 0, last_error: 6 });
  define("winmm.dll", "timeGetTime", argument([]), { return_value: 0, last_error: 0 });
  define("winmm.dll", "timeBeginPeriod", argument([4]), { return_value: 0, last_error: 0 });
  define("winmm.dll", "timeBeginPeriod", argument([0]), { return_value: 2, last_error: 2 });
  define("winmm.dll", "timeEndPeriod", scenario([["winmm.dll", "timeBeginPeriod", [4]]], [4]), { return_value: 0, last_error: 0 });
  define("winmm.dll", "timeEndPeriod", argument([9]), { return_value: 2, last_error: 0 });
  define("winmm.dll", "timeKillEvent", argument([0]), { return_value: 0, last_error: 0 });

  // COM apartment (ole32)
  define("ole32.dll", "CoInitializeEx", argument([0, 2]), { return_value: 0, last_error: 0 });
  define("ole32.dll", "CoInitializeEx", scenario([["ole32.dll", "CoInitializeEx", [0, 2]]], [0, 2]), { return_value: 1, last_error: 0 });
  define("ole32.dll", "CoInitializeEx", scenario([["ole32.dll", "CoInitializeEx", [0, 2]]], [0, 0]), { return_value: 0x80010106, last_error: 0 });
  define("ole32.dll", "CoUninitialize", argument([]), { return_value: 0, last_error: 0 });
  define("ole32.dll", "CoCreateInstance", argument([address.version_info, 0, 1, address.scratch_dword, address.startup_info]), { return_value: 0x80040154, last_error: 0 });

  // --- USER32 windowing/input (BPTK-011) ------------------------------------
  // The window class struct lives at startup_info, its name at scratch_wide.
  // Fresh guest memory is zero-initialized, so only the class-name pointer and
  // the name string need writing; the first window handle and class atom are
  // deterministic on the fresh machine.
  const windowClassStruct = address.startup_info;
  const windowClassName = address.scratch_wide;
  const firstWindow = 0x00010010;
  const firstAtom = 0xc000;
  const registerPrepare = (guest) => {
    guest.writeWideString(windowClassName, "AppClass", 32);
    guest.memory.writeMemory(windowClassStruct + 36, 4, windowClassName); // WNDCLASSW.lpszClassName
  };
  const registerExPrepare = (guest) => {
    guest.writeWideString(windowClassName, "AppClass", 32);
    guest.memory.writeMemory(windowClassStruct + 40, 4, windowClassName); // WNDCLASSEXW.lpszClassName
  };
  const registerStep = ["user32.dll", "RegisterClassW", [windowClassStruct]];
  const createArgument = [0, windowClassName, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  const createStep = ["user32.dll", "CreateWindowExW", createArgument];
  const showStep = ["user32.dll", "ShowWindow", [firstWindow, 1]];

  define("user32.dll", "RegisterClassW", { prepare: registerPrepare, argument: [windowClassStruct] }, { return_value: firstAtom, last_error: 0 });
  define("user32.dll", "RegisterClassExW", { prepare: registerExPrepare, argument: [windowClassStruct] }, { return_value: firstAtom, last_error: 0 });
  define("user32.dll", "UnregisterClassW", { prepare: registerPrepare, scenario: [registerStep], argument: [windowClassName] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "RegisterClassExA", { prepare: (guest) => {
    guest.writeAnsiString(address.scratch, "AppClass", 32);
    guest.memory.writeMemory(windowClassStruct + 40, 4, address.scratch);
  }, argument: [windowClassStruct] }, { return_value: firstAtom, last_error: 0 });
  define("user32.dll", "CreateWindowExW", { prepare: registerPrepare, scenario: [registerStep], argument: createArgument }, { return_value: firstWindow, last_error: 0 });
  define("user32.dll", "DestroyWindow", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "DefWindowProcW", argument([0, 0, 0, 0]), { return_value: 0, last_error: 0 });
  define("user32.dll", "ShowWindow", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow, 1] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "UpdateWindow", { prepare: registerPrepare, scenario: [registerStep, createStep, showStep], argument: [firstWindow] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "PostMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow, 0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "SendMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow, 0, 0, 0] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "PostQuitMessage", argument([0]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetActiveWindow", { prepare: registerPrepare, scenario: [registerStep, createStep, showStep], argument: [] }, { return_value: firstWindow, last_error: 0 });
  define("user32.dll", "GetFocus", { prepare: registerPrepare, scenario: [registerStep, createStep, showStep], argument: [] }, { return_value: firstWindow, last_error: 0 });
  define("user32.dll", "IsWindow", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow] }, { return_value: 1, last_error: 0 });

  // message loop (BPTK-011): the MSG buffer lives at scratch, the RECT buffer
  // at string_a; the window class registration is the shared scenario head.
  const msgBuffer = address.scratch;
  const rectBuffer = address.string_a;
  const postStep = ["user32.dll", "PostMessageW", [firstWindow, 0x400, 1, 2]];
  define("user32.dll", "GetMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep, postStep], argument: [msgBuffer, 0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "GetMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep, ["user32.dll", "PostQuitMessage", [0]]], argument: [msgBuffer, 0, 0, 0] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "GetMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [msgBuffer, 0, 0, 0] }, { return_value: unsigned(-1), last_error: 0 });
  define("user32.dll", "PeekMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep, postStep], argument: [msgBuffer, 0, 0, 0, 1] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "PeekMessageW", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [msgBuffer, 0, 0, 0, 1] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "TranslateMessage", { prepare: (guest) => { guest.memory.writeMemory(msgBuffer + 4, 4, 0x0100); guest.memory.writeMemory(msgBuffer + 8, 4, 0x41); }, scenario: [registerStep, createStep], argument: [msgBuffer] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "TranslateMessage", { prepare: (guest) => guest.memory.writeMemory(msgBuffer + 4, 4, 0x0000), argument: [msgBuffer] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "DispatchMessageW", { prepare: (guest) => { guest.memory.writeMemory(msgBuffer + 0, 4, firstWindow); guest.memory.writeMemory(msgBuffer + 4, 4, 0x0000); }, scenario: [registerStep, createStep], argument: [msgBuffer] }, { return_value: 0, last_error: 0 });

  // window geometry and system metrics (BPTK-011)
  define("user32.dll", "GetClientRect", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow, rectBuffer] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "GetWindowRect", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow, rectBuffer] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "GetClientRect", argument([0xdeadbeef, rectBuffer]), { return_value: 0, last_error: 0 });
  define("user32.dll", "MoveWindow", { prepare: registerPrepare, scenario: [registerStep, createStep], argument: [firstWindow, 10, 20, 100, 200, 1] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "AdjustWindowRect", argument([rectBuffer, 0, 0]), { return_value: 1, last_error: 0 });
  define("user32.dll", "AdjustWindowRectEx", argument([0, 0, 0, 0]), { return_value: 0, last_error: 87 });
  define("user32.dll", "AdjustWindowRectEx", argument([rectBuffer, 0x00cf0000, 0, 0]), { return_value: 1, last_error: 0 });
  define("user32.dll", "GetSystemMetrics", argument([0]), { return_value: 1920, last_error: 0 });
  define("user32.dll", "GetSystemMetrics", argument([1]), { return_value: 1080, last_error: 0 });
  define("user32.dll", "GetSystemMetrics", argument([99]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetDoubleClickTime", argument([]), { return_value: 500, last_error: 0 });
  define("user32.dll", "MapVirtualKeyW", argument([0x1e, 1]), { return_value: 0x41, last_error: 0 });
  define("user32.dll", "MapVirtualKeyW", argument([0x41, 2]), { return_value: 0x41, last_error: 0 });
  define("user32.dll", "MapVirtualKeyA", argument([0xff, 1]), { return_value: 0, last_error: 0 });
  const toUnicodeKeyState = (guest) => {
    for (let index = 0; index < 256; index += 4) guest.memory.writeMemory(address.startup_info + index, 4, 0);
  };
  define("user32.dll", "ToUnicode", argument([0x20, 0x39, 0, 0, 16, 0]), { return_value: 0, last_error: 87 });
  define("user32.dll", "ToUnicode", { prepare: toUnicodeKeyState, argument: [0x20, 0x39, address.startup_info, address.scratch_wide, 16, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "ToUnicode", { prepare: toUnicodeKeyState, argument: [0xff, 0, address.startup_info, address.scratch_wide, 16, 0] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "EnumDisplayMonitors", argument([0, 0, 0, 0]), { return_value: 0, last_error: 87 });
  define("user32.dll", "EnumDisplayMonitors", argument([0, 0, 0x00401000, 0]), { return_value: 1, last_error: 0 });
  define("user32.dll", "GetMonitorInfoW", { prepare: (guest) => guest.memory.writeMemory(address.string_dest, 4, 40), argument: [0x00020000, address.string_dest] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "GetMonitorInfoW", argument([0xdeadbeef, address.string_dest]), { return_value: 0, last_error: 6 });
  define("user32.dll", "GetMonitorInfoA", argument([0xdeadbeef, address.string_dest]), { return_value: 0, last_error: 6 });
  define("user32.dll", "EnumDisplaySettingsW", argument([0, 0xffffffff, 0]), { return_value: 0, last_error: 87 });
  define("user32.dll", "EnumDisplaySettingsW", { prepare: (guest) => guest.memory.writeMemory(address.string_dest + 68, 2, 220), argument: [0, 0xffffffff, address.string_dest] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "EnumDisplaySettingsA", { prepare: (guest) => guest.memory.writeMemory(address.string_dest + 68, 2, 220), argument: [0, 1, address.string_dest] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "EnumDisplayDevicesW", argument([0, 0, 0, 0]), { return_value: 0, last_error: 87 });
  define("user32.dll", "EnumDisplayDevicesW", { prepare: (guest) => guest.memory.writeMemory(address.string_dest, 4, 840), argument: [0, 0, address.string_dest, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "EnumDisplayDevicesA", { prepare: (guest) => guest.memory.writeMemory(address.string_dest, 4, 424), argument: [0, 1, address.string_dest, 0] }, { return_value: 0, last_error: 0 });

  // comctl32 common-control init (the GUI startup slice PuTTY reaches on its way
  // to opening its configuration dialog).
  define("comctl32.dll", "InitCommonControls", argument([]), { return_value: 0, last_error: 0 });
  define("comctl32.dll", "InitCommonControlsEx", argument([address.scratch]), { return_value: 1, last_error: 0 });

  // --- GDI32 2D surface (BPTK-012) ------------------------------------------
  // The first DC and the first object are deterministic on the fresh machine.
  const firstDc = 0x00040000;
  const secondDc = 0x00040004;
  const dcStep = ["gdi32.dll", "CreateCompatibleDC", [0]];
  const dc2Step = ["gdi32.dll", "CreateCompatibleDC", [0]];
  const brushStep = ["gdi32.dll", "CreateSolidBrush", [0x000908]];
  const whiteBrush = 0x80000000;

  define("gdi32.dll", "CreateCompatibleDC", argument([0]), { return_value: firstDc, last_error: 0 });
  define("gdi32.dll", "CreateDCW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "DISPLAY", 16), argument: [address.scratch_wide, 0, 0, 0] }, { return_value: firstDc, last_error: 0 });
  define("gdi32.dll", "CreateDCW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "\\\\.\\DISPLAY1", 16), argument: [address.scratch_wide, 0, 0, 0] }, { return_value: firstDc, last_error: 0 });
  define("gdi32.dll", "CreateDCW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "PRINTER", 16), argument: [address.scratch_wide, 0, 0, 0] }, { return_value: 0, last_error: 87 });
  define("gdi32.dll", "CreateDCA", { prepare: (guest) => guest.writeAnsiString(address.scratch, "DISPLAY", 16), argument: [address.scratch, 0, 0, 0] }, { return_value: firstDc, last_error: 0 });
  define("gdi32.dll", "DeleteDC", scenario([dcStep], [firstDc]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "GetStockObject", argument([0]), { return_value: whiteBrush, last_error: 0 });
  define("gdi32.dll", "CreateSolidBrush", argument([0x000908]), { return_value: firstDc, last_error: 0 });
  define("gdi32.dll", "CreatePen", argument([0, 1, 0]), { return_value: firstDc, last_error: 0 });
  define("gdi32.dll", "DeleteObject", scenario([brushStep], [firstDc]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "SelectObject", scenario([dcStep, brushStep], [firstDc, secondDc]), { return_value: whiteBrush, last_error: 0 });
  define("gdi32.dll", "Rectangle", scenario([dcStep], [firstDc, 0, 0, 1, 1]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "MoveToEx", scenario([dcStep], [firstDc, 0, 0, 0]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "LineTo", scenario([dcStep, ["gdi32.dll", "MoveToEx", [firstDc, 0, 0, 0]]], [firstDc, 0, 0]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "TextOutW", { prepare: (guest) => guest.memory.writeMemory(address.scratch_wide, 2, 0x41), scenario: [dcStep], argument: [firstDc, 0, 0, address.scratch_wide, 1] }, { return_value: 1, last_error: 0 });
  define("gdi32.dll", "SetTextColor", scenario([dcStep], [firstDc, 0x090807]), { return_value: 0, last_error: 0 });
  define("gdi32.dll", "SetBkColor", scenario([dcStep], [firstDc, 0x090807]), { return_value: 0xffffff, last_error: 0 });
  define("gdi32.dll", "SetBkMode", scenario([dcStep], [firstDc, 1]), { return_value: 2, last_error: 0 });
  define("gdi32.dll", "SetPixel", scenario([dcStep], [firstDc, 0, 0, 0x090807]), { return_value: 0x090807, last_error: 0 });
  define("gdi32.dll", "GetPixel", scenario([dcStep, ["gdi32.dll", "SetPixel", [firstDc, 0, 0, 0x090807]]], [firstDc, 0, 0]), { return_value: 0x090807, last_error: 0 });
  define("gdi32.dll", "BitBlt", scenario([dcStep, dc2Step], [firstDc, 0, 0, 1, 1, secondDc, 0, 0, 0x00cc0020]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "StretchBlt", scenario([dcStep, dc2Step], [firstDc, 0, 0, 1, 1, secondDc, 0, 0, 1, 1, 0x00cc0020]), { return_value: 1, last_error: 0 });

  // A LOGPALETTE with two entries lives at startup_info: palVersion (WORD),
  // palNumEntries (WORD), then the PALETTEENTRY records.
  const palettePrepare = (guest) => {
    guest.memory.writeMemory(windowClassStruct + 0, 2, 0x300); // palVersion
    guest.memory.writeMemory(windowClassStruct + 2, 2, 2); // palNumEntries
    guest.memory.writeMemory(windowClassStruct + 4, 4, 0x00000000); // entry 0: black
    guest.memory.writeMemory(windowClassStruct + 8, 4, 0x000000ff); // entry 1: red (peRed=0xff)
  };
  const createPaletteStep = ["gdi32.dll", "CreatePalette", [windowClassStruct]];
  define("gdi32.dll", "CreatePalette", { prepare: palettePrepare, argument: [windowClassStruct] }, { return_value: firstDc, last_error: 0 });
  define("gdi32.dll", "SelectPalette", { prepare: palettePrepare, scenario: [dcStep, createPaletteStep], argument: [firstDc, secondDc, 0] }, { return_value: 0, last_error: 0 });
  define("gdi32.dll", "RealizePalette", { prepare: palettePrepare, scenario: [dcStep, createPaletteStep, ["gdi32.dll", "SelectPalette", [firstDc, secondDc, 0]]], argument: [firstDc] }, { return_value: 2, last_error: 0 });
  define("gdi32.dll", "GetNearestPaletteIndex", { prepare: palettePrepare, scenario: [createPaletteStep], argument: [firstDc, 0x0a0afa] }, { return_value: 1, last_error: 0 });

  // rect fill, pattern blit, raster op, device caps (BPTK-012). The RECT lives
  // at string_a; the brush created after the DC is the second handle.
  const gdiRectBuffer = address.string_a;
  const writeRect0011 = (guest) => {
    guest.memory.writeMemory(gdiRectBuffer + 0, 4, 0);
    guest.memory.writeMemory(gdiRectBuffer + 4, 4, 0);
    guest.memory.writeMemory(gdiRectBuffer + 8, 4, 1);
    guest.memory.writeMemory(gdiRectBuffer + 12, 4, 1);
  };
  define("gdi32.dll", "FillRect", { prepare: writeRect0011, scenario: [dcStep, brushStep], argument: [firstDc, gdiRectBuffer, secondDc] }, { return_value: 1, last_error: 0 });
  define("gdi32.dll", "PatBlt", scenario([dcStep], [firstDc, 0, 0, 1, 1, 0x00f00021]), { return_value: 1, last_error: 0 });
  define("gdi32.dll", "GetDeviceCaps", argument([0, 8]), { return_value: 1920, last_error: 0 });
  define("gdi32.dll", "GetDeviceCaps", argument([0, 12]), { return_value: 32, last_error: 0 });
  define("gdi32.dll", "GetDeviceCaps", argument([0, 999]), { return_value: 0, last_error: 0 });
  define("gdi32.dll", "SetROP2", scenario([dcStep], [firstDc, 16]), { return_value: 13, last_error: 0 });
  define("gdi32.dll", "GetROP2", scenario([dcStep], [firstDc]), { return_value: 13, last_error: 0 });
  define("gdi32.dll", "CreateCompatibleBitmap", scenario([dcStep], [firstDc, 2, 2]), { return_value: 0x00040004, last_error: 0 });
  define("gdi32.dll", "CreateBitmap", argument([2, 2, 1, 1, 0]), { return_value: firstDc, last_error: 0 });
  define("gdi32.dll", "CreateBitmap", argument([2, 2, 1, 8, 0]), { return_value: 0, last_error: 87 });
  define("gdi32.dll", "GetCurrentObject", scenario([dcStep], [firstDc, 7]), { return_value: 0, last_error: 0 });
  define("gdi32.dll", "GetObjectA", scenario([dcStep, ["gdi32.dll", "CreateCompatibleBitmap", [firstDc, 2, 2]]], [0x00040004, 0, 0]), { return_value: 24, last_error: 0 });
  define("gdi32.dll", "GetDIBits", scenario([dcStep, ["gdi32.dll", "CreateCompatibleBitmap", [firstDc, 2, 2]]], [firstDc, 0x00040004, 0, 2, 0, 0, 0]), { return_value: 2, last_error: 0 });
  const writeDibHeader = (guest, height = 2) => {
    guest.memory.writeMemory(address.string_dest + 0, 4, 40);
    guest.memory.writeMemory(address.string_dest + 4, 4, 2);
    guest.memory.writeMemory(address.string_dest + 8, 4, height);
    guest.memory.writeMemory(address.string_dest + 12, 2, 1);
    guest.memory.writeMemory(address.string_dest + 14, 2, 32);
    guest.memory.writeMemory(address.string_dest + 16, 4, 0);
  };
  define("gdi32.dll", "CreateDIBSection", { prepare: writeDibHeader, argument: [0, address.string_dest, 0, address.scratch_dword, 0, 0] }, { return_value: firstDc, last_error: 0 });
  define("gdi32.dll", "CreateDIBSection", { prepare: writeDibHeader, argument: [0, address.string_dest, 0, address.scratch_dword, 1, 0] }, { return_value: 0, last_error: 50 });

  // --- Plink import-surface widening (BPTK-146) ------------------------------
  // One case per widened export: the ANSI file surface and kernel objects over
  // the same bounded state as their siblings, and the honest refusals whose
  // documented last error names why the confined probe cannot serve them.
  const writeName = (name) => (guest) => guest.writeAnsiString(address.scratch, name, 64);
  const createFileAStep = ["kernel32.dll", "CreateFileA", [address.scratch, 0xc0000000, 0, 0, 2, 0, 0]];
  const stdOutStep = ["kernel32.dll", "GetStdHandle", [-11]];
  define("kernel32.dll", "CreateFileA", { prepare: writeName("C:\\a.dat"), argument: [address.scratch, 0xc0000000, 0, 0, 2, 0, 0] }, { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "DeleteFileA", { prepare: writeName("C:\\a.dat"), argument: [address.scratch] }, { return_value: 0, last_error: 2 });
  define("kernel32.dll", "DeleteFileW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "C:\\a.dat", 16), argument: [address.scratch_wide] }, { return_value: 0, last_error: 2 });
  define("kernel32.dll", "RemoveDirectoryW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "C:\\missingdir", 32), argument: [address.scratch_wide] }, { return_value: 0, last_error: 3 });
  define("kernel32.dll", "RemoveDirectoryA", { prepare: writeName("C:\\missingdir"), argument: [address.scratch] }, { return_value: 0, last_error: 3 });
  define("kernel32.dll", "FileTimeToSystemTime", {
    prepare: (guest) => {
      const fileTime = BigInt(hleProfile.file_time_base);
      guest.memory.writeMemory(address.scratch_dword, 4, Number(fileTime & 0xffffffffn));
      guest.memory.writeMemory(address.scratch_dword + 4, 4, Number(fileTime >> 32n & 0xffffffffn));
    },
    argument: [address.scratch_dword, address.startup_info],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SystemTimeToFileTime", {
    prepare: (guest) => {
      guest.memory.writeMemory(address.startup_info, 2, 2020);
      guest.memory.writeMemory(address.startup_info + 2, 2, 9);
      guest.memory.writeMemory(address.startup_info + 4, 2, 4);
      guest.memory.writeMemory(address.startup_info + 6, 2, 10);
      guest.memory.writeMemory(address.startup_info + 8, 2, 18);
      guest.memory.writeMemory(address.startup_info + 10, 2, 40);
      guest.memory.writeMemory(address.startup_info + 12, 2, 0);
      guest.memory.writeMemory(address.startup_info + 14, 2, 0);
    },
    argument: [address.startup_info, address.scratch_dword],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SystemTimeToTzSpecificLocalTime", argument([0, address.startup_info, address.string_dest]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FindFirstFileA", { prepare: writeName("C:\\a.dat"), scenario: [createFileAStep], argument: [address.scratch, address.string_dest] }, { return_value: firstHandle + 1, last_error: 0 });
  define("kernel32.dll", "FindClose", argument([0xdeadbeef]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "GetFileAttributesExA", { prepare: writeName("C:\\"), argument: [address.scratch, 0, address.string_dest] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "LoadLibraryExA", { prepare: writeName("kernel32.dll"), argument: [address.scratch, 0, 0] }, { return_value: kernel32Module, last_error: 0 });
  define("kernel32.dll", "CreateEventA", argument([0, 1, 0, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "CreateMutexA", argument([0, 1, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "ReleaseMutex", scenario([["kernel32.dll", "CreateMutexA", [0, 1, 0]]], [firstHandle]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "CreateFileMappingA", argument([0xffffffff, 0, 4, 0, 4096, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "MapViewOfFile", argument([0xdeadbeef, 0, 0, 0, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "UnmapViewOfFile", argument([0x00400000]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "CreatePipe", argument([address.string_dest, address.string_dest + 4, 0, 0]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetWindowsDirectoryA", argument([address.string_dest, 260]), { return_value: 10, last_error: 0 });
  define("kernel32.dll", "GlobalMemoryStatus", argument([address.string_dest]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetProcessTimes", argument([0xffffffff, address.string_dest, address.string_dest + 8, address.string_dest + 16, address.string_dest + 24]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "LocalAlloc", argument([0x40, 16]), { return_value: address.heap_first_block, last_error: 0 });
  define("kernel32.dll", "LocalFree", scenario([["kernel32.dll", "LocalAlloc", [0x40, 16]]], [address.heap_first_block]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "LocalFileTimeToFileTime", { prepare: (guest) => guest.memory.writeBlock(address.string_dest, Buffer.alloc(8, 0x11)), argument: [address.string_dest, address.string_dest + 8] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetConsoleMode", scenario([stdOutStep], [firstHandle, 3]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetConsoleCtrlHandler", argument([0, 1]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetConsoleCtrlHandler", argument([0x00401000, 1]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetConsoleCtrlHandler", scenario([["kernel32.dll", "SetConsoleCtrlHandler", [0x00401000, 1]]], [0x00401000, 0]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetConsoleCtrlHandler", argument([0x00401000, 0]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "SetHandleInformation", scenario([stdOutStep], [firstHandle, 1, 0]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FormatMessageA", argument([0x1000, 0, 2, 0, address.string_dest, 260, 0]), { return_value: formatSystemMessage(2).length, last_error: 0 });
  define("kernel32.dll", "GetOverlappedResult", argument([0xdeadbeef, address.string_dest, address.string_dest + 8, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "UnhandledExceptionFilter", argument([address.string_dest]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "RtlUnwind", argument([0, 0, 0, 0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "EnumSystemLocalesW", argument([0x00401000, 0]), { return_value: 0, last_error: 120 });
  define("kernel32.dll", "EnumSystemLocalesEx", argument([0x00401000, 0, 0, 0]), { return_value: 0, last_error: 120 });
  define("kernel32.dll", "GetSystemTimePreciseAsFileTime", argument([address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "CreateThread", argument([0, 0, 0x00401000, 0, 0, address.string_dest]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "CreateProcessA", { prepare: writeName("C:\\x.exe"), argument: [0, address.scratch, 0, 0, 0, 0, 0, 0, address.string_dest, address.string_dest + 16] }, { return_value: 0, last_error: 5 });
  define("kernel32.dll", "CreateNamedPipeA", { prepare: writeName("\\\\.\\pipe\\x"), argument: [address.scratch, 0, 0, 0, 0, 0, 0, 0] }, { return_value: 0xffffffff, last_error: 120 });
  define("kernel32.dll", "ConnectNamedPipe", argument([0xdeadbeef, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "WaitNamedPipeA", { prepare: writeName("\\\\.\\pipe\\x"), argument: [address.scratch, 0] }, { return_value: 0, last_error: 2 });
  define("kernel32.dll", "GetCommState", argument([0xdeadbeef, address.string_dest]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "SetCommState", argument([0xdeadbeef, address.string_dest]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "SetCommTimeouts", argument([0xdeadbeef, address.string_dest]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "SetCommBreak", argument([0xdeadbeef]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "ClearCommBreak", argument([0xdeadbeef]), { return_value: 0, last_error: 6 });

  const writeSid = (base) => (guest) => {
    guest.memory.writeBlock(base, Buffer.alloc(12));
    guest.memory.writeMemory(base, 1, 1); // Revision
    guest.memory.writeMemory(base + 1, 1, 1); // SubAuthorityCount
  };
  define("advapi32.dll", "GetLengthSid", { prepare: writeSid(address.scratch), argument: [address.scratch] }, { return_value: 12, last_error: 0 });
  define("advapi32.dll", "CopySid", { prepare: writeSid(address.scratch), argument: [64, address.string_dest, address.scratch] }, { return_value: 1, last_error: 0 });
  define("advapi32.dll", "EqualSid", { prepare: (guest) => { writeSid(address.string_a)(guest); writeSid(address.string_b)(guest); }, argument: [address.string_a, address.string_b] }, { return_value: 1, last_error: 0 });
  define("advapi32.dll", "AllocateAndInitializeSid", { prepare: (guest) => guest.memory.writeBlock(address.scratch, Buffer.from([0, 0, 0, 0, 0, 5])), argument: [address.scratch, 1, 0x20, 0, 0, 0, 0, 0, 0, 0, address.string_dest] }, { return_value: 1, last_error: 0 });
  define("advapi32.dll", "GetUserNameA", { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 64), argument: [address.string_dest, address.scratch_dword] }, { return_value: 1, last_error: 0 });
  define("advapi32.dll", "InitializeSecurityDescriptor", argument([address.string_dest, 1]), { return_value: 1, last_error: 0 });
  const initSdStep = ["advapi32.dll", "InitializeSecurityDescriptor", [address.string_dest, 1]];
  define("advapi32.dll", "SetSecurityDescriptorDacl", scenario([initSdStep], [address.string_dest, 1, 0, 0]), { return_value: 1, last_error: 0 });
  define("advapi32.dll", "SetSecurityDescriptorOwner", scenario([initSdStep], [address.string_dest, address.scratch, 0]), { return_value: 1, last_error: 0 });

  define("user32.dll", "FindWindowA", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetCapture", argument([]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetKeyState", argument([0x14]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetAsyncKeyState", argument([0x11]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetKeyboardState", argument([0]), { return_value: 0, last_error: 87 });
  define("user32.dll", "GetKeyboardState", argument([address.string_dest]), { return_value: 1, last_error: 0 });
  define("user32.dll", "GetClipboardOwner", argument([]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetForegroundWindow", argument([]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetQueueStatus", argument([0x1ff]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetCursorPos", argument([address.string_dest]), { return_value: 1, last_error: 0 });
  define("user32.dll", "MsgWaitForMultipleObjects", argument([0, 0, 0, 0, 0x1ff]), { return_value: 0x102, last_error: 0 });
  define("user32.dll", "PeekMessageA", argument([address.string_dest, 0, 0, 0, 1]), { return_value: 0, last_error: 0 });
  define("user32.dll", "SendMessageA", argument([0xdeadbeef, 0, 0, 0]), { return_value: 0, last_error: 0 });
  const registerAnsiPrepare = (guest) => {
    guest.writeAnsiString(address.scratch, "AppClass", 32);
    guest.memory.writeMemory(windowClassStruct + 36, 4, address.scratch);
  };
  const registerAnsiStep = ["user32.dll", "RegisterClassA", [windowClassStruct]];
  const createAnsiArgument = [0, address.scratch, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  const createAnsiStep = ["user32.dll", "CreateWindowExA", createAnsiArgument];
  define("user32.dll", "RegisterClassA", { prepare: registerAnsiPrepare, argument: [windowClassStruct] }, { return_value: firstAtom, last_error: 0 });
  define("user32.dll", "UnregisterClassA", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep], argument: [address.scratch] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "CreateWindowExA", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep], argument: createAnsiArgument }, { return_value: firstWindow, last_error: 0 });
  define("user32.dll", "GetMessageA", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [msgBuffer, 0, 0, 0] }, { return_value: unsigned(-1), last_error: 0 });
  define("user32.dll", "DispatchMessageA", { prepare: (guest) => { registerAnsiPrepare(guest); guest.memory.writeMemory(msgBuffer + 0, 4, firstWindow); guest.memory.writeMemory(msgBuffer + 4, 4, 0); }, scenario: [registerAnsiStep, createAnsiStep], argument: [msgBuffer] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "PostMessageA", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, 0, 0, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "DefDlgProcA", argument([0, 0, 0, 0]), { return_value: 0, last_error: 0 });
  define("user32.dll", "GetWindowTextA", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, address.string_dest, 32] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "GetWindowTextLengthA", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "GetDlgItem", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, 1] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "GetDlgItemTextA", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, 1, address.string_dest, 32] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "SetDlgItemTextA", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, 1, 0] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "GetDlgItemInt", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, 1, 0, 0] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "SetDlgItemInt", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, 1, 0, 0] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "SendDlgItemMessageA", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, 1, 0, 0, 0] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "IsDlgButtonChecked", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, 1] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "CheckRadioButton", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, 1, 2, 1] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "EnableWindow", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "GetWindowLongA", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, -16] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "SetWindowLongA", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, -21, 9] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "SetWindowPos", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, 0, 1, 2, 10, 20, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "SetActiveWindow", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow] }, { return_value: 0, last_error: 0 });
  define("user32.dll", "SetForegroundWindow", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "GetDesktopWindow", argument([]), { return_value: firstWindow, last_error: 0 });
  define("user32.dll", "GetDC", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow] }, { return_value: 0x00040000, last_error: 0 });
  define("user32.dll", "ReleaseDC", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep, ["user32.dll", "GetDC", [firstWindow]]], argument: [firstWindow, 0x00040000] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "LoadCursorA", argument([0, 32512]), { return_value: 0x00008000 | 32512, last_error: 0 });
  define("user32.dll", "LoadCursorW", argument([0, 32512]), { return_value: 0x00008000 | 32512, last_error: 0 });
  define("user32.dll", "LoadIconA", argument([0, 32512]), { return_value: 0x00008100 | 32512, last_error: 0 });
  define("user32.dll", "LoadIconW", argument([0, 32512]), { return_value: 0x00008100 | 32512, last_error: 0 });
  define("user32.dll", "CreateIconIndirect", argument([0]), { return_value: 0, last_error: 87 });
  define("user32.dll", "CreateIconIndirect", { prepare: (guest) => {
    guest.memory.writeMemory(address.string_dest + 0, 4, 0);
    guest.memory.writeMemory(address.string_dest + 4, 4, 0);
    guest.memory.writeMemory(address.string_dest + 8, 4, 0);
    guest.memory.writeMemory(address.string_dest + 12, 4, 0x00040000);
    guest.memory.writeMemory(address.string_dest + 16, 4, 0);
  }, argument: [address.string_dest] }, { return_value: 0x00008200, last_error: 0 });
  define("user32.dll", "DestroyIcon", argument([0x00008200]), { return_value: 0, last_error: 6 });
  define("user32.dll", "CopyImage", argument([0, 2, 0, 0, 0]), { return_value: 0, last_error: 87 });
  define("user32.dll", "CopyImage", argument([0x00008000 | 32512, 2, 0, 0, 4]), { return_value: 0x00008000 | 32512, last_error: 0 });
  define("user32.dll", "CopyImage", argument([0x00008000 | 32512, 2, 0, 0, 0]), { return_value: 0x00008200, last_error: 0 });
  define("user32.dll", "CopyImage", argument([0x00008000 | 32512, 2, 32, 32, 0]), { return_value: 0x00008200, last_error: 0 });
  define("user32.dll", "CopyImage", argument([0x1234, 2, 0, 0, 0]), { return_value: 0, last_error: 6 });
  define("user32.dll", "SystemParametersInfoW", { prepare: (guest) => guest.memory.writeMemory(address.string_dest, 4, 0), argument: [0x70, 0, address.string_dest, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "SystemParametersInfoW", { prepare: (guest) => guest.memory.writeMemory(address.string_dest, 4, 0), argument: [3, 0, address.string_dest, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "SystemParametersInfoW", argument([0x70, 0, 0, 0]), { return_value: 0, last_error: 87 });
  define("user32.dll", "SystemParametersInfoW", argument([0x9999, 0, address.string_dest, 0]), { return_value: 0, last_error: 87 });
  define("user32.dll", "SystemParametersInfoA", { prepare: (guest) => guest.memory.writeMemory(address.string_dest, 4, 0), argument: [0x70, 0, address.string_dest, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "RegisterWindowMessageA", argument([0]), { return_value: 0, last_error: 87 });
  define("user32.dll", "RegisterWindowMessageA", { prepare: (guest) => guest.writeAnsiString(address.string_a, "SDL", 16), argument: [address.string_a] }, { return_value: 0x0000c000, last_error: 0 });
  define("user32.dll", "RegisterWindowMessageW", { prepare: (guest) => guest.writeWideString(address.string_a, "SDL", 16), argument: [address.string_a] }, { return_value: 0x0000c000, last_error: 0 });
  define("user32.dll", "CreateMenu", argument([]), { return_value: 0x00030000, last_error: 0 });
  define("user32.dll", "AppendMenuA", scenario([["user32.dll", "CreateMenu", []]], [0x00030000, 0, 1, 0]), { return_value: 1, last_error: 0 });
  define("user32.dll", "SetMenu", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep, ["user32.dll", "CreateMenu", []]], argument: [firstWindow, 0x00030000] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "CheckMenuItem", scenario([["user32.dll", "CreateMenu", []], ["user32.dll", "AppendMenuA", [0x00030000, 0, 1, 0]]], [0x00030000, 1, 8]), { return_value: 0, last_error: 0 });
  define("user32.dll", "CheckMenuRadioItem", scenario([["user32.dll", "CreateMenu", []], ["user32.dll", "AppendMenuA", [0x00030000, 0, 1, 0]]], [0x00030000, 1, 1, 1, 0]), { return_value: 1, last_error: 0 });
  define("user32.dll", "EnableMenuItem", scenario([["user32.dll", "CreateMenu", []], ["user32.dll", "AppendMenuA", [0x00030000, 0, 1, 0]]], [0x00030000, 1, 1]), { return_value: 0, last_error: 0 });
  define("user32.dll", "SetTimer", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep], argument: [firstWindow, 1, 10, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "KillTimer", { prepare: registerAnsiPrepare, scenario: [registerAnsiStep, createAnsiStep, ["user32.dll", "SetTimer", [firstWindow, 1, 10, 0]]], argument: [firstWindow, 1] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "GetMessageTime", argument([]), { return_value: 0, last_error: 0 });
  define("user32.dll", "MapDialogRect", { prepare: (guest) => {
    guest.memory.writeMemory(address.string_a + 0, 4, 4);
    guest.memory.writeMemory(address.string_a + 4, 4, 8);
    guest.memory.writeMemory(address.string_a + 8, 4, 8);
    guest.memory.writeMemory(address.string_a + 12, 4, 16);
  }, argument: [0, address.string_a] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "MessageBeep", argument([0]), { return_value: 1, last_error: 0 });
  define("user32.dll", "MessageBoxA", { prepare: (guest) => guest.writeAnsiString(address.scratch, "ok", 8), argument: [0, address.scratch, 0, 0] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "MessageBoxIndirectA", { prepare: (guest) => { guest.writeAnsiString(address.scratch, "ok", 8); guest.memory.writeMemory(windowClassStruct + 8, 4, address.scratch); guest.memory.writeMemory(windowClassStruct + 12, 4, 0); guest.memory.writeMemory(windowClassStruct + 16, 4, 0); }, argument: [windowClassStruct] }, { return_value: 1, last_error: 0 });
  define("user32.dll", "IsDialogMessageA", argument([0, msgBuffer]), { return_value: 0, last_error: 0 });
  define("user32.dll", "EndDialog", argument([0, 1]), { return_value: 0, last_error: 0 });
  define("user32.dll", "CreateDialogParamA", argument([0, 1, 0, 0, 0]), { return_value: 0, last_error: 1813 });
  define("user32.dll", "DialogBoxParamA", argument([0, 1, 0, 0, 0]), { return_value: 0, last_error: 1813 });

  // --- CRT breadth reached past the SDL layer (lane W) ----------------------
  // The telemetry no-ops, the ucrt standard-stream accessor, and the stdio
  // startup/format helpers a ucrt game (Dwarf Fortress) reaches on its way from
  // the SDL init through the CRT into its own main.
  const iobSlot0 = crtRuntimeCell.iobBase;
  define("vcruntime140.dll", "__telemetry_main_invoke_trigger", argument([0]), { return_value: 0, last_error: 0 });
  define("vcruntime140.dll", "__telemetry_main_return_trigger", argument([0]), { return_value: 0, last_error: 0 });
  for (const library of ["api-ms-win-crt-stdio-l1-1-0.dll", "msvcrt.dll"]) {
    define(library, "__acrt_iob_func", argument([1]), { return_value: iobSlot0 + FILE_STRUCT_BYTE, last_error: 0 });
    define(library, "freopen", argument([0, 0, iobSlot0]), { return_value: iobSlot0, last_error: 0 });
    define(library, "setvbuf", argument([iobSlot0, 0, 0, 0]), { return_value: 0, last_error: 0 });
    define(library, "setbuf", argument([iobSlot0, 0]), { return_value: 0, last_error: 0 });
    define(library, "__stdio_common_vfprintf", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hi", 8), argument: [0, iobSlot0 + FILE_STRUCT_BYTE, address.string_a, 0, 0] }, { return_value: 2, last_error: 0 });
    define(library, "__stdio_common_vsprintf", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hi", 8), argument: [0, address.string_dest, 16, address.string_a, 0, 0] }, { return_value: 2, last_error: 0 });
    define(library, "__stdio_common_vsprintf_s", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hi", 8), argument: [0, address.string_dest, 16, address.string_a, 0, 0] }, { return_value: 2, last_error: 0 });
    // Formatted input over an empty format and an empty source: no field is
    // assigned and the source is at end, so the scan returns EOF (-1).
    define(library, "__stdio_common_vsscanf", { prepare: (guest) => guest.writeAnsiString(address.string_a, "", 1), argument: [0, address.string_b, 0, address.string_a, 0, 0] }, { return_value: 0xffffffff, last_error: 0 });
    define(library, "__stdio_common_vfscanf", { prepare: (guest) => guest.writeAnsiString(address.string_a, "", 1), argument: [0, iobSlot0, address.string_a, 0, 0] }, { return_value: 0xffffffff, last_error: 0 });
  }

  // --- SDL (lane W): one case per served export -----------------------------
  // The SDL subsystem allocates opaque handles from a fixed base (0x53000000, +0x10
  // each) and its SDL_Surface/SDL_PixelFormat records from a fixed region anchored
  // at the arena top (below the CRT scratch pages), so both are deterministic on a
  // fresh isolated machine and the expected value is pinned exactly.
  const sdlHandle0 = 0x53000000;
  const sdlHandle1 = 0x53000010;
  const sdlHandle2 = 0x53000020; // the first texture handle after window + renderer
  const sdlStruct0 = 0x00300000 - 0x10000; // arena_base(0x100000)+arena_size(0x200000)-0x10000
  const sdlFormat0 = sdlStruct0 + 0x60; // after the 96-byte surface record
  const sdlStruct1 = sdlStruct0 + 0xa0; // after the first surface record + its format
  const atomicCell = address.scratch_dword;
  const surfaceMask = [0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000];
  const rgbSurfaceInput = [0, 4, 4, 32, ...surfaceMask];
  const rgbSurfaceStep = (library) => [library, "SDL_CreateRGBSurface", rgbSurfaceInput];

  // The symbols SDL 1.2 (sdl.dll) and SDL 2 (sdl2.dll) both export, with
  // identical behavior; each is pinned under both libraries.
  for (const library of ["sdl.dll", "sdl2.dll"]) {
    const createSemStep = [library, "SDL_CreateSemaphore", [3]];
    const createMutexStep = [library, "SDL_CreateMutex", []];
    define(library, "SDL_Init", argument([0x20]), { return_value: 0, last_error: 0 });
    define(library, "SDL_InitSubSystem", argument([0x20]), { return_value: 0, last_error: 0 });
    define(library, "SDL_QuitSubSystem", argument([0x20]), { return_value: 0, last_error: 0 });
    define(library, "SDL_Quit", argument([]), { return_value: 0, last_error: 0 });
    define(library, "SDL_WasInit", argument([0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_GetError", argument([]), { return_value: sdlStruct0, last_error: 0 });
    define(library, "SDL_SetError", { prepare: (guest) => guest.writeAnsiString(address.string_a, "x", 4), argument: [address.string_a] }, { return_value: 0xffffffff, last_error: 0 });
    define(library, "SDL_ClearError", argument([]), { return_value: 0, last_error: 0 });
    define(library, "SDL_GetTicks", argument([]), { return_value: 0, last_error: 0 });
    define(library, "SDL_Delay", argument([5]), { return_value: 0, last_error: 0 });
    define(library, "SDL_CreateSemaphore", argument([3]), { return_value: sdlHandle0, last_error: 0 });
    define(library, "SDL_SemWait", scenario([createSemStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_SemTryWait", scenario([createSemStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_SemPost", scenario([createSemStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_SemValue", scenario([createSemStep], [sdlHandle0]), { return_value: 3, last_error: 0 });
    define(library, "SDL_DestroySemaphore", scenario([createSemStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_CreateMutex", argument([]), { return_value: sdlHandle0, last_error: 0 });
    define(library, "SDL_LockMutex", scenario([createMutexStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_UnlockMutex", scenario([createMutexStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_DestroyMutex", scenario([createMutexStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_CreateThread", argument([0, 0, 0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_WaitThread", argument([0, 0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_AtomicSet", { prepare: (guest) => guest.memory.writeMemory(atomicCell, 4, 5), argument: [atomicCell, 9] }, { return_value: 5, last_error: 0 });
    define(library, "SDL_AtomicGet", { prepare: (guest) => guest.memory.writeMemory(atomicCell, 4, 7), argument: [atomicCell] }, { return_value: 7, last_error: 0 });
    define(library, "SDL_AtomicAdd", { prepare: (guest) => guest.memory.writeMemory(atomicCell, 4, 4), argument: [atomicCell, 3] }, { return_value: 4, last_error: 0 });
    define(library, "SDL_AtomicCAS", { prepare: (guest) => guest.memory.writeMemory(atomicCell, 4, 8), argument: [atomicCell, 8, 20] }, { return_value: 1, last_error: 0 });
    define(library, "SDL_CreateRGBSurface", argument(rgbSurfaceInput), { return_value: sdlStruct0, last_error: 0 });
    define(library, "SDL_CreateRGBSurfaceFrom", argument([atomicCell, 4, 4, 32, 16, ...surfaceMask]), { return_value: sdlStruct0, last_error: 0 });
    define(library, "SDL_FreeSurface", scenario([rgbSurfaceStep(library)], [sdlStruct0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_LockSurface", scenario([rgbSurfaceStep(library)], [sdlStruct0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_UnlockSurface", scenario([rgbSurfaceStep(library)], [sdlStruct0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_FillRect", scenario([rgbSurfaceStep(library)], [sdlStruct0, 0, 0x00ff0000]), { return_value: 0, last_error: 0 });
    define(library, "SDL_MapRGB", scenario([rgbSurfaceStep(library)], [sdlFormat0, 0x11, 0x22, 0x33]), { return_value: 0xff112233, last_error: 0 });
    define(library, "SDL_MapRGBA", scenario([rgbSurfaceStep(library)], [sdlFormat0, 0x11, 0x22, 0x33, 0x44]), { return_value: 0x44112233, last_error: 0 });
    define(library, "SDL_GetRGBA", scenario([rgbSurfaceStep(library)], [0xff112233, sdlFormat0, address.string_dest, address.string_dest + 1, address.string_dest + 2, address.string_dest + 3]), { return_value: 0, last_error: 0 });
    define(library, "SDL_UpperBlit", scenario([rgbSurfaceStep(library), rgbSurfaceStep(library)], [sdlStruct0, 0, sdlStruct1, 0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_SetColorKey", scenario([rgbSurfaceStep(library)], [sdlStruct0, 1, 0x00ff0000]), { return_value: 0, last_error: 0 });
    define(library, "SDL_PollEvent", argument([address.string_dest]), { return_value: 0, last_error: 0 });
    define(library, "SDL_PeepEvents", argument([0, 0, 0, 0, 0, 0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_PumpEvents", argument([]), { return_value: 0, last_error: 0 });
    define(library, "SDL_WaitEvent", argument([address.string_dest]), { return_value: 0, last_error: 0 });
    define(library, "SDL_GetMouseState", argument([0, 0]), { return_value: 0, last_error: 0 });
    define(library, "SDL_GetModState", argument([]), { return_value: 0, last_error: 0 });
    define(library, "SDL_NumJoysticks", argument([]), { return_value: 0, last_error: 0 });
    define(library, "SDL_ShowCursor", argument([1]), { return_value: 1, last_error: 0 });
  }

  // SDL 1.2 (sdl.dll) video + helper surface.
  define("sdl.dll", "SDL_SetVideoMode", argument([8, 4, 32, 0]), { return_value: sdlStruct0, last_error: 0 });
  define("sdl.dll", "SDL_GetVideoSurface", scenario([["sdl.dll", "SDL_SetVideoMode", [8, 4, 32, 0]]], []), { return_value: sdlStruct0, last_error: 0 });
  define("sdl.dll", "SDL_Flip", scenario([["sdl.dll", "SDL_SetVideoMode", [8, 4, 32, 0]]], [sdlStruct0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_UpdateRect", scenario([["sdl.dll", "SDL_SetVideoMode", [8, 4, 32, 0]]], [sdlStruct0, 0, 0, 8, 4]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_WM_SetCaption", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_WM_SetIcon", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_EnableUNICODE", argument([1]), { return_value: 1, last_error: 0 });
  define("sdl.dll", "SDL_EnableKeyRepeat", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_GetAppState", argument([]), { return_value: 0x03, last_error: 0 });
  define("sdl.dll", "SDL_DisplayFormat", scenario([rgbSurfaceStep("sdl.dll")], [sdlStruct0]), { return_value: sdlStruct1, last_error: 0 });
  define("sdl.dll", "SDL_DisplayFormatAlpha", scenario([rgbSurfaceStep("sdl.dll")], [sdlStruct0]), { return_value: sdlStruct1, last_error: 0 });
  define("sdl.dll", "SDL_ConvertSurface", scenario([rgbSurfaceStep("sdl.dll")], [sdlStruct0, 0, 0]), { return_value: sdlStruct1, last_error: 0 });
  define("sdl.dll", "SDL_SetAlpha", argument([0, 0, 0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_ThreadID", argument([]), { return_value: 1, last_error: 0 });
  define("sdl.dll", "SDL_getenv", argument([0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_strlcpy", { prepare: (guest) => guest.writeAnsiString(address.string_a, "hi", 4), argument: [address.string_dest, address.string_a, 8] }, { return_value: 2, last_error: 0 });
  define("sdl.dll", "SDL_strlcat", { prepare: (guest) => { guest.writeAnsiString(address.string_dest, "ab", 4); guest.writeAnsiString(address.string_a, "cd", 4); }, argument: [address.string_dest, address.string_a, 16] }, { return_value: 4, last_error: 0 });
  define("sdl.dll", "SDL_SetModuleHandle", argument([0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_GetVideoInfo", argument([]), { return_value: sdlStruct0, last_error: 0 });
  define("sdl.dll", "SDL_GL_SetAttribute", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_GL_GetAttribute", argument([0, address.string_dest]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_GL_SwapBuffers", argument([]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_RWFromFile", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("sdl.dll", "SDL_SaveBMP_RW", argument([0, 0, 0]), { return_value: 0xffffffff, last_error: 0 });

  // SDL 2 (sdl2.dll) window/renderer/version/cond.
  const createWindowStep = ["sdl2.dll", "SDL_CreateWindow", [0, 0, 0, 320, 200, 0]];
  const createRendererStep = ["sdl2.dll", "SDL_CreateRenderer", [sdlHandle0, 0xffffffff, 0]];
  define("sdl2.dll", "SDL_SetMainReady", argument([]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_CreateWindow", argument([0, 0, 0, 320, 200, 0]), { return_value: sdlHandle0, last_error: 0 });
  define("sdl2.dll", "SDL_DestroyWindow", scenario([createWindowStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_GetWindowSurface", scenario([createWindowStep], [sdlHandle0]), { return_value: sdlStruct0, last_error: 0 });
  define("sdl2.dll", "SDL_UpdateWindowSurface", scenario([createWindowStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_UpdateWindowSurfaceRects", scenario([createWindowStep], [sdlHandle0, 0, 0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_GetWindowSize", scenario([createWindowStep], [sdlHandle0, address.string_dest, address.string_dest + 4]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_GetWindowFlags", scenario([createWindowStep], [sdlHandle0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_GetWindowID", scenario([createWindowStep], [sdlHandle0]), { return_value: 1, last_error: 0 });
  define("sdl2.dll", "SDL_SetWindowTitle", scenario([createWindowStep], [sdlHandle0, 0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_SetWindowSize", scenario([createWindowStep], [sdlHandle0, 320, 200]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_CreateRenderer", scenario([createWindowStep], [sdlHandle0, 0xffffffff, 0]), { return_value: sdlHandle1, last_error: 0 });
  define("sdl2.dll", "SDL_DestroyRenderer", scenario([createWindowStep, createRendererStep], [sdlHandle1]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_SetRenderDrawColor", scenario([createWindowStep, createRendererStep], [sdlHandle1, 0x10, 0x20, 0x30, 0xff]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_RenderClear", scenario([createWindowStep, createRendererStep], [sdlHandle1]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_RenderFillRect", scenario([createWindowStep, createRendererStep], [sdlHandle1, 0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_RenderPresent", scenario([createWindowStep, createRendererStep], [sdlHandle1]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_GetVersion", argument([address.string_dest]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_CreateCond", argument([]), { return_value: sdlHandle0, last_error: 0 });
  define("sdl2.dll", "SDL_CondSignal", scenario([["sdl2.dll", "SDL_CreateCond", []]], [sdlHandle0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_CondBroadcast", scenario([["sdl2.dll", "SDL_CreateCond", []]], [sdlHandle0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_CondWait", scenario([["sdl2.dll", "SDL_CreateCond", []]], [sdlHandle0, 0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_DestroyCond", scenario([["sdl2.dll", "SDL_CreateCond", []]], [sdlHandle0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_ShowSimpleMessageBox", argument([0, 0, 0, 0]), { return_value: 0, last_error: 0 });

  // --- SDL 2 video-init + render pipeline (lane AE) -------------------------
  // Each case runs the served implementation on a fresh isolated machine and
  // pins the result through the oracle (the deterministic value the same
  // implementation produces), the same self-pinning contract the heap and path
  // exports use. Scenarios build the window/renderer/texture/palette the call
  // needs so the served path takes its success branch.
  const createTextureStep = ["sdl2.dll", "SDL_CreateTexture", [sdlHandle1, sdlPixelFormat.ARGB8888, 1, 4, 2]];
  const withRenderer = (...step) => [createWindowStep, createRendererStep, ...step];
  const indexedSurfaceStep = ["sdl2.dll", "SDL_CreateRGBSurface", [0, 4, 2, 8, 0, 0, 0, 0]];
  const allocPaletteStep = ["sdl2.dll", "SDL_AllocPalette", [256]];
  const oracle = (symbol, input) => define("sdl2.dll", symbol, input, oracleCall("sdl2.dll", symbol, input));

  oracle("SDL_GetNumVideoDisplays", argument([]));
  oracle("SDL_GetNumVideoDrivers", argument([]));
  oracle("SDL_GetCurrentVideoDriver", argument([]));
  oracle("SDL_GetCurrentDisplayMode", argument([0, address.string_dest]));
  oracle("SDL_GetDesktopDisplayMode", argument([0, address.string_dest]));
  oracle("SDL_GetDisplayMode", argument([0, 0, address.string_dest]));
  oracle("SDL_GetNumDisplayModes", argument([0]));
  oracle("SDL_GetDisplayBounds", argument([0, address.string_dest]));
  oracle("SDL_GetDisplayUsableBounds", argument([0, address.string_dest]));
  oracle("SDL_GetDisplayDPI", argument([0, address.string_dest, address.string_dest + 4, address.string_dest + 8]));

  oracle("SDL_RenderSetLogicalSize", scenario(withRenderer(), [sdlHandle1, 4, 2]));
  oracle("SDL_RenderSetIntegerScale", scenario(withRenderer(), [sdlHandle1, 1]));
  oracle("SDL_GetRendererInfo", scenario(withRenderer(), [sdlHandle1, address.startup_info]));
  oracle("SDL_GetRendererOutputSize", scenario(withRenderer(), [sdlHandle1, address.string_dest, address.string_dest + 4]));
  oracle("SDL_RenderSetViewport", scenario(withRenderer(), [sdlHandle1, 0]));
  oracle("SDL_RenderSetScale", scenario(withRenderer(), [sdlHandle1, 0, 0]));
  oracle("SDL_RenderGetViewport", scenario(withRenderer(), [sdlHandle1, address.string_dest]));
  oracle("SDL_RenderGetLogicalSize", scenario(withRenderer(), [sdlHandle1, address.string_dest, address.string_dest + 4]));
  oracle("SDL_SetRenderTarget", scenario(withRenderer(), [sdlHandle1, 0]));
  oracle("SDL_GetRenderTarget", scenario(withRenderer(), [sdlHandle1]));
  oracle("SDL_RenderCopy", scenario(withRenderer(createTextureStep), [sdlHandle1, sdlHandle2, 0, 0]));
  oracle("SDL_RenderCopyEx", scenario(withRenderer(createTextureStep), [sdlHandle1, sdlHandle2, 0, 0, 0, 0]));

  oracle("SDL_CreateTexture", scenario(withRenderer(), [sdlHandle1, sdlPixelFormat.ARGB8888, 1, 4, 2]));
  oracle("SDL_UpdateTexture", scenario(withRenderer(createTextureStep), [sdlHandle2, 0, address.string_dest, 16]));
  oracle("SDL_QueryTexture", scenario(withRenderer(createTextureStep), [sdlHandle2, address.string_dest, address.string_dest + 4, address.string_dest + 8, address.string_dest + 12]));
  oracle("SDL_LockTexture", scenario(withRenderer(createTextureStep), [sdlHandle2, 0, address.string_dest, address.string_dest + 8]));
  oracle("SDL_UnlockTexture", scenario(withRenderer(createTextureStep), [sdlHandle2]));
  oracle("SDL_DestroyTexture", scenario(withRenderer(createTextureStep), [sdlHandle2]));
  oracle("SDL_SetTextureBlendMode", scenario(withRenderer(createTextureStep), [sdlHandle2, 0]));
  oracle("SDL_SetTextureColorMod", scenario(withRenderer(createTextureStep), [sdlHandle2, 0xff, 0xff, 0xff]));
  oracle("SDL_SetTextureAlphaMod", scenario(withRenderer(createTextureStep), [sdlHandle2, 0xff]));

  oracle("SDL_AllocPalette", argument([256]));
  oracle("SDL_FreePalette", scenario([allocPaletteStep], [sdlStruct0]));
  oracle("SDL_SetPaletteColors", scenario([allocPaletteStep], [sdlStruct0, address.string_dest, 0, 2]));
  oracle("SDL_SetSurfacePalette", scenario([indexedSurfaceStep, allocPaletteStep], [sdlStruct0, sdlStruct0]));
  oracle("SDL_PixelFormatEnumToMasks", argument([sdlPixelFormat.ARGB8888, address.string_dest, address.string_dest + 4, address.string_dest + 8, address.string_dest + 12, address.string_dest + 16]));
  oracle("SDL_CreateRGBSurfaceWithFormat", argument([0, 4, 2, 32, sdlPixelFormat.ARGB8888]));
  oracle("SDL_CreateRGBSurfaceWithFormatFrom", argument([address.string_dest, 4, 2, 32, 16, sdlPixelFormat.ARGB8888]));

  oracle("SDL_BlitSurface", scenario([rgbSurfaceStep("sdl2.dll"), rgbSurfaceStep("sdl2.dll")], [sdlStruct0, 0, sdlStruct1, 0]));
  oracle("SDL_LowerBlit", scenario([rgbSurfaceStep("sdl2.dll"), rgbSurfaceStep("sdl2.dll")], [sdlStruct0, 0, sdlStruct1, 0]));

  oracle("SDL_ShowWindow", scenario([createWindowStep], [sdlHandle0]));
  oracle("SDL_HideWindow", scenario([createWindowStep], [sdlHandle0]));
  oracle("SDL_RaiseWindow", scenario([createWindowStep], [sdlHandle0]));
  oracle("SDL_SetWindowFullscreen", scenario([createWindowStep], [sdlHandle0, 0]));
  oracle("SDL_SetWindowGrab", scenario([createWindowStep], [sdlHandle0, 0]));
  oracle("SDL_SetWindowMinimumSize", scenario([createWindowStep], [sdlHandle0, 320, 200]));
  oracle("SDL_SetWindowResizable", scenario([createWindowStep], [sdlHandle0, 0]));
  oracle("SDL_SetWindowPosition", scenario([createWindowStep], [sdlHandle0, 0, 0]));
  oracle("SDL_SetWindowIcon", scenario([createWindowStep], [sdlHandle0, 0]));
  oracle("SDL_GetWindowTitle", scenario([createWindowStep], [sdlHandle0]));
  oracle("SDL_GetWindowPixelFormat", scenario([createWindowStep], [sdlHandle0]));
  oracle("SDL_GetWindowFromID", argument([1]));
  oracle("SDL_MaximizeWindow", scenario([createWindowStep], [sdlHandle0]));
  oracle("SDL_MinimizeWindow", scenario([createWindowStep], [sdlHandle0]));
  oracle("SDL_RestoreWindow", scenario([createWindowStep], [sdlHandle0]));
  oracle("SDL_GetWindowPosition", scenario([createWindowStep], [sdlHandle0, address.string_dest, address.string_dest + 4]));
  oracle("SDL_GetWindowDisplayIndex", scenario([createWindowStep], [sdlHandle0]));
  oracle("SDL_SetRelativeMouseMode", argument([0]));
  oracle("SDL_GetRelativeMouseState", argument([address.string_dest, address.string_dest + 4]));
  oracle("SDL_WarpMouseInWindow", scenario([createWindowStep], [sdlHandle0, 0, 0]));
  oracle("SDL_DisableScreenSaver", argument([]));
  oracle("SDL_EnableScreenSaver", argument([]));

  // SDL's private libc wrappers over real guest memory and the process heap.
  define("sdl2.dll", "SDL_strlen", { prepare: writeMsvcrtString(address.string_a, "hello"), argument: [address.string_a] }, { return_value: 5, last_error: 0 });
  define("sdl2.dll", "SDL_wcslen", { prepare: writeMsvcrtWide(address.string_a, "hi"), argument: [address.string_a] }, { return_value: 2, last_error: 0 });
  define("sdl2.dll", "SDL_memcpy", { prepare: writeMsvcrtString(address.string_a, "abc"), argument: [address.string_dest, address.string_a, 4] }, { return_value: address.string_dest, last_error: 0 });
  define("sdl2.dll", "SDL_memmove", { prepare: writeMsvcrtString(address.string_a, "abc"), argument: [address.string_dest, address.string_a, 4] }, { return_value: address.string_dest, last_error: 0 });
  define("sdl2.dll", "SDL_memset", argument([address.string_dest, 0, 4]), { return_value: address.string_dest, last_error: 0 });
  define("sdl2.dll", "SDL_malloc", argument([16]), oracleCall("sdl2.dll", "SDL_malloc", [16]));
  define("sdl2.dll", "SDL_calloc", argument([4, 4]), oracleCall("sdl2.dll", "SDL_calloc", [4, 4]));
  define("sdl2.dll", "SDL_realloc", argument([0, 16]), oracleCall("sdl2.dll", "SDL_realloc", [0, 16]));
  define("sdl2.dll", "SDL_free", argument([0]), { return_value: 0, last_error: 0 });
  define("sdl2.dll", "SDL_iconv_string", { prepare: (guest) => { writeMsvcrtString(address.string_a, "UTF-8")(guest); writeMsvcrtString(address.string_b, "UTF-16LE")(guest); writeMsvcrtWide(address.string_dest, "hi")(guest); }, argument: [address.string_a, address.string_b, address.string_dest, 6] }, oracleCall("sdl2.dll", "SDL_iconv_string", { prepare: (guest) => { writeMsvcrtString(address.string_a, "UTF-8")(guest); writeMsvcrtString(address.string_b, "UTF-16LE")(guest); writeMsvcrtWide(address.string_dest, "hi")(guest); }, argument: [address.string_a, address.string_b, address.string_dest, 6] }));
  define("sdl2.dll", "SDL_SetHint", argument([0, 0]), { return_value: 1, last_error: 0 });
  define("sdl2.dll", "SDL_SetHintWithPriority", argument([0, 0, 0]), { return_value: 1, last_error: 0 });
  // The base/pref path return a heap pointer to the bounded home path; the oracle
  // re-runs the deterministic implementation to pin it.
  define("sdl2.dll", "SDL_GetBasePath", argument([]), oracleCall("sdl2.dll", "SDL_GetBasePath", []));
  define("sdl2.dll", "SDL_GetPrefPath", argument([0, 0]), oracleCall("sdl2.dll", "SDL_GetPrefPath", [0, 0]));

  // SDL2_mixer: the no-audio-device surface. OpenAudio(Device) fail with -1;
  // Init/Quit/Close/QuerySpec are inert; the error accessors are self-consistent.
  define("sdl2_mixer.dll", "Mix_Init", argument([0]), { return_value: 0, last_error: 0 });
  define("sdl2_mixer.dll", "Mix_Quit", argument([]), { return_value: 0, last_error: 0 });
  define("sdl2_mixer.dll", "Mix_OpenAudio", argument([0, 0, 0, 0]), { return_value: 0xffffffff, last_error: 0 });
  define("sdl2_mixer.dll", "Mix_OpenAudioDevice", argument([0, 0, 0, 0, 0, 0]), { return_value: 0xffffffff, last_error: 0 });
  define("sdl2_mixer.dll", "Mix_CloseAudio", argument([]), { return_value: 0, last_error: 0 });
  define("sdl2_mixer.dll", "Mix_QuerySpec", argument([0, 0, 0]), { return_value: 0, last_error: 0 });
  define("sdl2_mixer.dll", "Mix_GetError", argument([]), oracleCall("sdl2_mixer.dll", "Mix_GetError", []));
  define("sdl2_mixer.dll", "Mix_SetError", argument([0]), oracleCall("sdl2_mixer.dll", "Mix_SetError", [0]));

  // ripgrep / SuperTux import-surface widening
  const windowsDirectory = hleProfile.system_directory.replace(/\\System32$/i, "");
  define("kernel32.dll", "CreateFileMappingW", argument([0xffffffff, 0, 4, 0, 4096, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "GetSystemDirectoryW", argument([address.scratch_wide, 32]), { return_value: hleProfile.system_directory.length, last_error: 0 });
  define("kernel32.dll", "GetWindowsDirectoryW", argument([address.scratch_wide, 32]), { return_value: windowsDirectory.length, last_error: 0 });
  define("kernel32.dll", "SetEnvironmentVariableW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "BPTK_X", 16), argument: [address.scratch_wide, 0] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "CreateProcessW", argument([0, 0, 0, 0, 0, 0, 0, 0, address.string_dest, address.string_dest + 16]), { return_value: 0, last_error: 5 });
  define("kernel32.dll", "CreateNamedPipeW", argument([address.scratch, 0, 0, 0, 0, 0, 0, 0]), { return_value: 0xffffffff, last_error: 120 });
  define("kernel32.dll", "GetFileAttributesW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "C:\\game", 16), argument: [address.scratch_wide] }, { return_value: 0x10, last_error: 0 });
  define("kernel32.dll", "GetFileAttributesA", { prepare: (guest) => guest.writeAnsiString(address.scratch, "C:\\game", 16), argument: [address.scratch] }, { return_value: 0x10, last_error: 0 });
  define("kernel32.dll", "GetCurrentDirectoryW", argument([260, address.scratch_wide]), { return_value: hleProfile.guest_root.length, last_error: 0 });
  define("kernel32.dll", "GetCurrentDirectoryA", argument([260, address.scratch]), { return_value: hleProfile.guest_root.length, last_error: 0 });
  define("kernel32.dll", "SetCurrentDirectoryW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "C:\\game", 16), argument: [address.scratch_wide] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetCurrentDirectoryA", { prepare: (guest) => guest.writeAnsiString(address.scratch, "C:\\game", 16), argument: [address.scratch] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetFullPathNameW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "x", 8), argument: [address.scratch_wide, 260, address.string_dest, 0] }, { return_value: `${hleProfile.guest_root}\\x`.length, last_error: 0 });
  define("kernel32.dll", "GetFullPathNameW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "", 8), argument: [address.scratch_wide, 260, address.string_dest, 0] }, { return_value: hleProfile.guest_root.length, last_error: 0 });
  define("kernel32.dll", "GetFullPathNameW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "C:\\game\\..\\data", 32), argument: [address.scratch_wide, 260, address.string_dest, 0] }, { return_value: "C:\\data".length, last_error: 0 });
  define("kernel32.dll", "GetFullPathNameA", { prepare: (guest) => guest.writeAnsiString(address.scratch, "x", 8), argument: [address.scratch, 260, address.string_dest, 0] }, { return_value: `${hleProfile.guest_root}\\x`.length, last_error: 0 });
  define("kernel32.dll", "FormatMessageW", argument([0x1000, 0, 2, 0, address.string_dest, 260, 0]), { return_value: formatSystemMessage(2).length, last_error: 0 });
  define("kernel32.dll", "GetConsoleOutputCP", argument([]), { return_value: 1252, last_error: 0 });
  define("kernel32.dll", "GetConsoleScreenBufferInfo", scenario([["kernel32.dll", "GetStdHandle", [-11]]], [firstHandle, address.string_dest]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetConsoleTextAttribute", scenario([["kernel32.dll", "GetStdHandle", [-11]]], [firstHandle, 0x0f]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetComputerNameExW", { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 32), argument: [0, address.scratch_wide, address.scratch_dword] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "CompareStringOrdinal", { prepare: (guest) => { guest.writeWideString(address.string_a, "ab", 8); guest.writeWideString(address.string_b, "ab", 8); }, argument: [address.string_a, 0xffffffff, address.string_b, 0xffffffff, 0] }, { return_value: 2, last_error: 0 });
  define("kernel32.dll", "SetThreadStackGuarantee", argument([address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "CreateWaitableTimerExW", argument([0, 0, 0, 0]), { return_value: firstHandle, last_error: 0 });
  define("kernel32.dll", "InitializeProcThreadAttributeList", argument([0, 1, 0, address.scratch_dword]), { return_value: 0, last_error: 122 });
  define("kernel32.dll", "UpdateProcThreadAttribute", argument([0, 0, 0, 0, 0, 0, 0]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "DeleteProcThreadAttributeList", argument([address.scratch]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetFileInformationByHandle", argument([0xdeadbeef, address.string_dest]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "GetFileInformationByHandleEx", argument([0xdeadbeef, 1, address.string_dest, 24]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "GetFileInformationByHandleEx", {
    prepare: (guest) => guest.writeWideString(savePath, "C:\\", 64),
    scenario: [["kernel32.dll", "CreateFileW", [savePath, 0x80, 7, 0, 3, 0x02000000, 0]]],
    argument: [firstHandle, 0, address.string_dest, 40],
  }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetFinalPathNameByHandleW", argument([0xdeadbeef, address.scratch_wide, 260, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "SetFileInformationByHandle", argument([0xdeadbeef, 4, address.scratch, 1]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "WriteFileEx", argument([0xdeadbeef, address.scratch, 0, 0, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "ReadFileEx", argument([0xdeadbeef, address.scratch, 0, 0, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "GetExitCodeProcess", argument([0xffffffff, address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "RtlCaptureContext", argument([address.string_dest]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "InitializeSRWLock", argument([address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "AcquireSRWLockExclusive", argument([address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "AcquireSRWLockShared", argument([address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "ReleaseSRWLockExclusive", argument([address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "ReleaseSRWLockShared", argument([address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "TryAcquireSRWLockExclusive", argument([address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "TryAcquireSRWLockShared", argument([address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("kernel32.dll", "InitializeConditionVariable", argument([address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "WakeConditionVariable", argument([address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "WakeAllConditionVariable", argument([address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "SleepConditionVariableSRW", argument([address.scratch_dword, address.scratch, 0, 0]), { return_value: 0, last_error: 258 });
  define("kernel32.dll", "SleepConditionVariableCS", argument([address.scratch_dword, address.scratch, 0]), { return_value: 0, last_error: 258 });
  define("bcryptprimitives.dll", "ProcessPrng", argument([address.scratch, 8]), { return_value: 1, last_error: 0 });
  define("userenv.dll", "GetUserProfileDirectoryW", { prepare: (guest) => guest.memory.writeMemory(address.scratch_dword, 4, 32), argument: [0xffffffff, address.scratch_wide, address.scratch_dword] }, { return_value: 1, last_error: 0 });
  define("ntdll.dll", "RtlNtStatusToDosError", argument([0]), { return_value: 0, last_error: 0 });
  define("ntdll.dll", "NtReadFile", argument([0xdeadbeef, 0, 0, 0, address.string_dest, address.scratch, 0, 0, 0]), { return_value: 0xc0000008, last_error: 6 });
  define("ntdll.dll", "NtWriteFile", argument([0xdeadbeef, 0, 0, 0, address.string_dest, address.scratch, 0, 0, 0]), { return_value: 0xc0000008, last_error: 6 });
  define("kernel32.dll", "GetTickCount64", argument([]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetFileAttributesExW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "C:\\", 8), argument: [address.scratch_wide, 0, address.string_dest] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetFileAttributesExW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "C:\\game", 16), argument: [address.scratch_wide, 0, address.string_dest] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetFileAttributesExW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, ".", 8), argument: [address.scratch_wide, 0, address.string_dest] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetFileAttributesExW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "", 8), argument: [address.scratch_wide, 0, address.string_dest] }, { return_value: 0, last_error: 3 });
  define("kernel32.dll", "GetDiskFreeSpaceExW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "C:\\", 8), argument: [address.scratch_wide, address.string_dest, address.string_dest + 8, address.string_dest + 16] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "GetTempPathW", argument([32, address.scratch_wide]), { return_value: "C:\\Temp\\".length, last_error: 0 });
  define("kernel32.dll", "GetTempPathA", argument([32, address.scratch]), { return_value: "C:\\Temp\\".length, last_error: 0 });
  define("kernel32.dll", "GetFileSizeEx", { prepare: writeName("C:\\a.dat"), scenario: [createFileAStep], argument: [firstHandle, address.string_dest] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "FindResourceA", argument([0, 1, 5]), { return_value: 0, last_error: 1813 });
  define("kernel32.dll", "EnumResourceNamesW", argument([0, 14, 0, 0]), { return_value: 0, last_error: 87 });
  define("kernel32.dll", "EnumResourceNamesW", argument([0, 14, 0x00401000, 0]), { return_value: 0, last_error: 1813 });
  define("kernel32.dll", "LoadResource", argument([0, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "LockResource", argument([0]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "SizeofResource", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("comdlg32.dll", "GetOpenFileNameA", argument([address.string_dest]), { return_value: 0, last_error: 0 });
  define("comdlg32.dll", "GetSaveFileNameA", argument([address.string_dest]), { return_value: 0, last_error: 0 });
  define("kernel32.dll", "GetTempPath2W", argument([32, address.scratch_wide]), { return_value: "C:\\Temp\\".length, last_error: 0 });
  define("kernel32.dll", "CreateDirectoryW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "C:\\game\\cfg", 16), argument: [address.scratch_wide, 0] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "CreateDirectoryExW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "C:\\game\\cfg2", 16), argument: [0, address.scratch_wide, 0] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "CopyFileW", { prepare: (guest) => { guest.writeWideString(address.string_a, "C:\\missing", 16); guest.writeWideString(address.string_b, "C:\\dest", 16); }, argument: [address.string_a, address.string_b, 0] }, { return_value: 0, last_error: 2 });
  define("kernel32.dll", "MoveFileExW", { prepare: (guest) => { guest.writeWideString(address.string_a, "C:\\missing", 16); guest.writeWideString(address.string_b, "C:\\dest", 16); }, argument: [address.string_a, address.string_b, 0] }, { return_value: 0, last_error: 2 });
  define("kernel32.dll", "SetFileAttributesW", { prepare: (guest) => guest.writeWideString(address.scratch_wide, "C:\\game", 16), argument: [address.scratch_wide, 0x10] }, { return_value: 1, last_error: 0 });
  define("kernel32.dll", "SetFileTime", argument([0xdeadbeef, 0, 0, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "GetThreadLocale", argument([]), { return_value: 0x0409, last_error: 0 });
  define("kernel32.dll", "GetLocaleInfoEx", argument([0, 0x1002, address.scratch_wide, 64]), { return_value: "United States".length + 1, last_error: 0 });
  define("kernel32.dll", "DeviceIoControl", argument([0, 0, 0, 0, 0, 0, 0, 0]), { return_value: 0, last_error: 50 });
  define("kernel32.dll", "CreateSymbolicLinkW", argument([0, 0, 0]), { return_value: 0, last_error: 5 });
  define("kernel32.dll", "CreateHardLinkW", argument([0, 0, 0]), { return_value: 0, last_error: 5 });
  define("kernel32.dll", "PeekNamedPipe", argument([0, 0, 0, 0, 0]), { return_value: 0, last_error: 6 });
  define("kernel32.dll", "WaitNamedPipeW", argument([0, 0]), { return_value: 0, last_error: 2 });
  define("kernel32.dll", "DisableThreadLibraryCalls", argument([mainModule]), { return_value: 1, last_error: 0 });
  define("shell32.dll", "ShellExecuteA", argument([0, 0, 0, 0, 0, 0]), { return_value: 0, last_error: 5 });
  define("shell32.dll", "ShellExecuteW", argument([0, 0, 0, 0, 0, 0]), { return_value: 0, last_error: 5 });
  define("shell32.dll", "SHGetFolderPathW", argument([0, 0x1a, 0, 0, address.scratch_wide]), { return_value: 0, last_error: 0 });
  define("shell32.dll", "SHGetFolderPathW", argument([0, 0x801a, 0, 0, address.scratch_wide]), { return_value: 0, last_error: 0 });
  define("shell32.dll", "SHGetFolderPathW", argument([0, 0x99, 0, 0, address.scratch_wide]), { return_value: 0x80070057, last_error: 87 });
  define("shell32.dll", "SHGetFolderPathA", argument([0, 0x1a, 0, 0, address.scratch]), { return_value: 0, last_error: 0 });
  define("dbghelp.dll", "StackWalk64", argument([0, 0, 0, 0, 0, 0, 0, 0, 0]), { return_value: 0, last_error: 0 });
  define("dbghelp.dll", "SymSetOptions", argument([0]), { return_value: 0, last_error: 0 });
  define("dbghelp.dll", "SymFunctionTableAccess64", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("dbghelp.dll", "SymGetModuleBase64", argument([0, 0]), { return_value: 0, last_error: 0 });
  define("dbghelp.dll", "SymGetLineFromAddr64", argument([0, 0, 0, 0]), { return_value: 0, last_error: 0 });
  define("dbghelp.dll", "SymInitializeW", argument([0, 0, 0]), { return_value: 0, last_error: 0 });
  define("dbghelp.dll", "SymFromAddr", argument([0, 0, 0, 0]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glGetError", argument([]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glGetString", argument([0x1f00]), oracleCall("opengl32.dll", "glGetString", [0x1f00]));
  define("opengl32.dll", "glGetIntegerv", argument([0x0d33, address.scratch_dword]), { return_value: 1, last_error: 0 });
  define("opengl32.dll", "glClearColor", argument([0, 0, 0, 0]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glClear", argument([0x00004000]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glViewport", argument([0, 0, 64, 64]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glScissor", argument([0, 0, 64, 64]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glEnable", argument([0x0de1]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glDisable", argument([0x0de1]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glEnableClientState", argument([0x8074]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glDisableClientState", argument([0x8074]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glMatrixMode", argument([0x1700]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glLoadIdentity", argument([]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glTranslatef", argument([0, 0, 0]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glOrtho", argument([0, 0x3f800000, 0, 0x3f800000, 0xbf800000, 0x3f800000]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glColor4f", argument([0x3f800000, 0x3f800000, 0x3f800000, 0x3f800000]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glBlendFunc", argument([1, 0]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glPixelStorei", argument([0x0cf5, 4]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glGenTextures", argument([1, address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glDeleteTextures", argument([0, address.scratch_dword]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glBindTexture", argument([0x0de1, 0]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glTexParameteri", argument([0x0de1, 0x2801, 0x2601]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glTexImage2D", argument([0x0de1, 0, 0x1908, 0, 0, 0, 0x1908, 0x1401, 0]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glCopyTexSubImage2D", argument([0x0de1, 0, 0, 0, 0, 0, 0, 0]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glVertexPointer", argument([2, 0x1406, 0, 0]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glTexCoordPointer", argument([2, 0x1406, 0, 0]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glColorPointer", argument([4, 0x1406, 0, 0]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glDrawArrays", argument([4, 0, 0]), { return_value: 0, last_error: 0 });
  define("opengl32.dll", "glReadPixels", argument([0, 0, 1, 1, 0x1908, 0x1401, address.string_dest]), { return_value: 0, last_error: 0 });

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
