// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// A zero-dependency Buffer shim over Uint8Array covering only the surface the
// bounded runtime uses (lib/pe.mjs, lib/pe64.mjs, lib/exec64.mjs, lib/runtime.mjs,
// lib/hle.mjs, lib/user.mjs, lib/gdi.mjs, lib/lift64.mjs). Every method matches
// node:buffer semantics byte-for-byte; test/present.test.mjs proves each one
// against the real node:buffer on identical input. Node's Buffer is itself a
// Uint8Array subclass, so BufferShim extends Uint8Array and reads/writes through
// a DataView for exact little-endian and IEEE-754 behavior.

const encoder = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", { fatal: false });

function hexToBytes(text) {
  // Node stops at the first non-hex character and ignores a trailing nibble.
  const out = [];
  for (let index = 0; index + 1 < text.length + 1; index += 2) {
    const pair = text.slice(index, index + 2);
    if (pair.length < 2) break;
    const value = Number.parseInt(pair, 16);
    if (Number.isNaN(value)) break;
    out.push(value);
  }
  return out;
}

const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const base64Lookup = (() => {
  const table = new Int16Array(256).fill(-1);
  for (let index = 0; index < base64Alphabet.length; index += 1) table[base64Alphabet.charCodeAt(index)] = index;
  return table;
})();

function base64ToBytes(text) {
  const out = [];
  let accumulator = 0;
  let bits = 0;
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code === 0x3d) break; // '=' padding ends the stream
    const value = base64Lookup[code];
    if (value < 0) continue; // Node skips whitespace and other non-alphabet bytes
    accumulator = (accumulator << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((accumulator >> bits) & 0xff);
    }
  }
  return out;
}

function bytesToBase64(bytes, start, end) {
  let out = "";
  let index = start;
  for (; index + 2 < end; index += 3) {
    const triple = (bytes[index] << 16) | (bytes[index + 1] << 8) | bytes[index + 2];
    out += base64Alphabet[(triple >> 18) & 0x3f] + base64Alphabet[(triple >> 12) & 0x3f] + base64Alphabet[(triple >> 6) & 0x3f] + base64Alphabet[triple & 0x3f];
  }
  const remaining = end - index;
  if (remaining === 1) {
    const triple = bytes[index] << 16;
    out += base64Alphabet[(triple >> 18) & 0x3f] + base64Alphabet[(triple >> 12) & 0x3f] + "==";
  } else if (remaining === 2) {
    const triple = (bytes[index] << 16) | (bytes[index + 1] << 8);
    out += base64Alphabet[(triple >> 18) & 0x3f] + base64Alphabet[(triple >> 12) & 0x3f] + base64Alphabet[(triple >> 6) & 0x3f] + "=";
  }
  return out;
}

function normalizeEncoding(encoding) {
  const name = (encoding ?? "utf8").toLowerCase();
  if (name === "utf-8") return "utf8";
  if (name === "binary") return "latin1";
  if (name === "ucs2" || name === "ucs-2") return "utf16le";
  return name;
}

// Encode a JS string to a byte array under the named encoding, matching Node.
function stringToBytes(text, encoding) {
  const name = normalizeEncoding(encoding);
  if (name === "utf8") return Array.from(encoder.encode(text));
  if (name === "hex") return hexToBytes(text);
  if (name === "base64") return base64ToBytes(text);
  const out = new Array(text.length);
  if (name === "ascii") {
    for (let index = 0; index < text.length; index += 1) out[index] = text.charCodeAt(index) & 0x7f;
    return out;
  }
  // latin1 / default one-byte: low 8 bits of each code unit.
  for (let index = 0; index < text.length; index += 1) out[index] = text.charCodeAt(index) & 0xff;
  return out;
}

function bytesToString(bytes, encoding, start, end) {
  const name = normalizeEncoding(encoding);
  const from = start ?? 0;
  const to = end ?? bytes.length;
  const lo = Math.max(0, Math.min(from, bytes.length));
  const hi = Math.max(lo, Math.min(to, bytes.length));
  if (name === "utf8") return utf8Decoder.decode(bytes.subarray(lo, hi));
  if (name === "hex") {
    let out = "";
    for (let index = lo; index < hi; index += 1) out += bytes[index].toString(16).padStart(2, "0");
    return out;
  }
  if (name === "base64") return bytesToBase64(bytes, lo, hi);
  let out = "";
  if (name === "ascii") {
    for (let index = lo; index < hi; index += 1) out += String.fromCharCode(bytes[index] & 0x7f);
    return out;
  }
  for (let index = lo; index < hi; index += 1) out += String.fromCharCode(bytes[index]);
  return out;
}

export class BufferShim extends Uint8Array {
  static alloc(size, fill, encoding) {
    const buffer = new BufferShim(size);
    if (fill !== undefined && fill !== 0) buffer.fill(fill, 0, size, encoding);
    return buffer;
  }

  static allocUnsafe(size) {
    return new BufferShim(size);
  }

  static from(value, encodingOrOffset, length) {
    if (typeof value === "string") return new BufferShim(stringToBytes(value, encodingOrOffset));
    if (value instanceof ArrayBuffer) {
      return length === undefined
        ? new BufferShim(value, encodingOrOffset ?? 0)
        : new BufferShim(value, encodingOrOffset ?? 0, length);
    }
    if (ArrayBuffer.isView(value)) {
      const view = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      const copy = new BufferShim(view.length);
      copy.set(view);
      return copy;
    }
    if (Array.isArray(value)) {
      const copy = new BufferShim(value.length);
      for (let index = 0; index < value.length; index += 1) copy[index] = value[index] & 0xff;
      return copy;
    }
    throw new TypeError("BufferShim.from expects a string, ArrayBuffer, typed array, or array");
  }

  static concat(list, totalLength) {
    let total = totalLength;
    if (total === undefined) {
      total = 0;
      for (const entry of list) total += entry.length;
    }
    const out = new BufferShim(total);
    let offset = 0;
    for (const entry of list) {
      if (offset >= total) break;
      const slice = entry.length + offset > total ? entry.subarray(0, total - offset) : entry;
      out.set(slice, offset);
      offset += slice.length;
    }
    return out;
  }

  static isBuffer(value) {
    return value instanceof BufferShim;
  }

  static byteLength(value, encoding) {
    if (typeof value !== "string") return value.byteLength ?? value.length;
    return stringToBytes(value, encoding).length;
  }

  static compare(a, b) {
    const length = Math.min(a.length, b.length);
    for (let index = 0; index < length; index += 1) {
      if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1;
    }
    if (a.length === b.length) return 0;
    return a.length < b.length ? -1 : 1;
  }

  get #view() {
    return new DataView(this.buffer, this.byteOffset, this.byteLength);
  }

  subarray(start, end) {
    const view = super.subarray(start, end);
    return new BufferShim(view.buffer, view.byteOffset, view.length);
  }

  slice(start, end) {
    return this.subarray(start, end);
  }

  copy(target, targetStart = 0, sourceStart = 0, sourceEnd = this.length) {
    const from = Math.max(0, sourceStart);
    const to = Math.min(this.length, sourceEnd);
    let written = 0;
    for (let index = from; index < to && targetStart + written < target.length; index += 1) {
      target[targetStart + written] = this[index];
      written += 1;
    }
    return written;
  }

  equals(other) {
    if (this.length !== other.length) return false;
    for (let index = 0; index < this.length; index += 1) if (this[index] !== other[index]) return false;
    return true;
  }

  compare(other) {
    return BufferShim.compare(this, other);
  }

  fill(value, start = 0, end = this.length, encoding) {
    const lo = Math.max(0, start);
    const hi = Math.min(this.length, end);
    if (typeof value === "number") {
      for (let index = lo; index < hi; index += 1) this[index] = value & 0xff;
      return this;
    }
    const pattern = typeof value === "string" ? stringToBytes(value, encoding) : Array.from(value);
    if (pattern.length === 0) return this;
    for (let index = lo; index < hi; index += 1) this[index] = pattern[(index - lo) % pattern.length] & 0xff;
    return this;
  }

  toString(encoding, start, end) {
    return bytesToString(this, encoding, start, end);
  }

  write(string, offset, length, encoding) {
    let realOffset = 0;
    let realLength = this.length;
    let realEncoding = "utf8";
    if (typeof offset === "string") {
      realEncoding = offset;
    } else if (offset !== undefined) {
      realOffset = offset;
      if (typeof length === "string") realEncoding = length;
      else {
        if (length !== undefined) realLength = length;
        if (encoding !== undefined) realEncoding = encoding;
      }
    }
    const bytes = stringToBytes(string, realEncoding);
    const limit = Math.min(bytes.length, realLength, this.length - realOffset);
    for (let index = 0; index < limit; index += 1) this[realOffset + index] = bytes[index] & 0xff;
    return limit;
  }

  indexOf(value, byteOffset, encoding) {
    const start = typeof byteOffset === "number" ? Math.max(0, byteOffset) : 0;
    const pattern = typeof value === "number"
      ? [value & 0xff]
      : typeof value === "string"
        ? stringToBytes(value, typeof byteOffset === "string" ? byteOffset : encoding)
        : Array.from(value);
    if (pattern.length === 0) return start > this.length ? this.length : start;
    for (let index = start; index + pattern.length <= this.length; index += 1) {
      let match = true;
      for (let offset = 0; offset < pattern.length; offset += 1) {
        if (this[index + offset] !== pattern[offset]) { match = false; break; }
      }
      if (match) return index;
    }
    return -1;
  }

  includes(value, byteOffset, encoding) {
    return this.indexOf(value, byteOffset, encoding) !== -1;
  }

  readUInt8(offset = 0) { return this.#view.getUint8(offset); }
  readInt8(offset = 0) { return this.#view.getInt8(offset); }
  readUInt16LE(offset = 0) { return this.#view.getUint16(offset, true); }
  readInt16LE(offset = 0) { return this.#view.getInt16(offset, true); }
  readUInt32LE(offset = 0) { return this.#view.getUint32(offset, true); }
  readInt32LE(offset = 0) { return this.#view.getInt32(offset, true); }
  readBigUInt64LE(offset = 0) { return this.#view.getBigUint64(offset, true); }
  readBigInt64LE(offset = 0) { return this.#view.getBigInt64(offset, true); }
  readFloatLE(offset = 0) { return this.#view.getFloat32(offset, true); }
  readDoubleLE(offset = 0) { return this.#view.getFloat64(offset, true); }

  writeUInt8(value, offset = 0) { this.#view.setUint8(offset, Number(value) & 0xff); return offset + 1; }
  writeInt8(value, offset = 0) { this.#view.setInt8(offset, Number(value)); return offset + 1; }
  writeUInt16LE(value, offset = 0) { this.#view.setUint16(offset, Number(value) & 0xffff, true); return offset + 2; }
  writeInt16LE(value, offset = 0) { this.#view.setInt16(offset, Number(value), true); return offset + 2; }
  writeUInt32LE(value, offset = 0) { this.#view.setUint32(offset, Number(value) >>> 0, true); return offset + 4; }
  writeInt32LE(value, offset = 0) { this.#view.setInt32(offset, Number(value), true); return offset + 4; }
  writeBigUInt64LE(value, offset = 0) { this.#view.setBigUint64(offset, BigInt.asUintN(64, BigInt(value)), true); return offset + 8; }
  writeBigInt64LE(value, offset = 0) { this.#view.setBigInt64(offset, BigInt.asIntN(64, BigInt(value)), true); return offset + 8; }
  writeFloatLE(value, offset = 0) { this.#view.setFloat32(offset, value, true); return offset + 4; }
  writeDoubleLE(value, offset = 0) { this.#view.setFloat64(offset, value, true); return offset + 8; }
}

export const Buffer = BufferShim;
export default { Buffer: BufferShim };
