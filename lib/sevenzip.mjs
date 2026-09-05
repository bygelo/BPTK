// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Bounded 7z (.7z) archive reader for the archive-import surface. The module
// parses the 7z signature header, the (optionally LZMA-encoded) end header, the
// streams and folder coder graph, and the file table, then recovers each file's
// real bytes. No archive code is executed and no external decoder is pulled: the
// LZMA and BCJ2 codecs are implemented here in pure, bounded JavaScript. Every
// decompression is capped by the declared extraction bound from lib/bound.mjs,
// path traversal is refused, and an encrypted or unsupported coder is refused
// with a named structured reason rather than emitting garbage. Format support is
// pinned to the LZMA (03 01 01), BCJ2 (03 03 01 1B), BCJ x86 (03 03 01 03), and
// Copy (00) coders that the lawful freeware corpus payload and 7-Zip's own exe
// packaging emit; every other coder, including AES-256 encryption
// (06 F1 07 01), is a structured refusal.

import { createHash } from "node:crypto";
import {
  assertChunkInputBound,
  assertChunkRatioBound,
  assertDepthBound,
  assertEntryBound,
  assertOutputBound,
  chunkOutputCap,
  createExtractionBound,
} from "./bound.mjs";
import { InputError } from "./input.mjs";

export const sevenZipMagic = Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);

function sevenZipError(code, message) {
  return new InputError(code, message);
}

// Recognizes the 7z signature from a bounded prefix without opening the file.
export function isSevenZip(prefix) {
  return Buffer.isBuffer(prefix) && prefix.length >= 6 && prefix.subarray(0, 6).equals(sevenZipMagic);
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

function crc32(buffer, start = 0, end = buffer.length) {
  let value = 0xffffffff;
  for (let index = start; index < end; index += 1) value = crcTable[(value ^ buffer[index]) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

// Property identifiers from the 7z header grammar.
const kEnd = 0x00;
const kHeader = 0x01;
const kMainStreamsInfo = 0x04;
const kFilesInfo = 0x05;
const kPackInfo = 0x06;
const kUnpackInfo = 0x07;
const kSubStreamsInfo = 0x08;
const kSize = 0x09;
const kCRC = 0x0a;
const kFolder = 0x0b;
const kCodersUnpackSize = 0x0c;
const kNumUnpackStream = 0x0d;
const kEmptyStream = 0x0e;
const kEmptyFile = 0x0f;
const kName = 0x11;
const kWinAttributes = 0x15;
const kEncodedHeader = 0x17;
const kDummy = 0x19;

// Coder identifiers as lowercase hex of their id byte sequence.
const CODER_LZMA = "030101";
const CODER_BCJ2 = "0303011b";
const CODER_BCJ_X86 = "03030103";
const CODER_COPY = "00";
const CODER_AES = "06f10701";

// A forward cursor over a header buffer that reads the 7z variable-length
// number encoding and refuses a read past the buffer end.
class HeaderCursor {
  constructor(buffer) {
    this.buffer = buffer;
    this.position = 0;
  }

  ensure(count) {
    if (this.position + count > this.buffer.length) {
      throw sevenZipError("archive_header_truncated", "The 7z header ended before its declared structure");
    }
  }

  readByte() {
    this.ensure(1);
    const value = this.buffer[this.position];
    this.position += 1;
    return value;
  }

  readBytes(count) {
    this.ensure(count);
    const value = this.buffer.subarray(this.position, this.position + count);
    this.position += count;
    return value;
  }

  readUInt32() {
    return this.readBytes(4).readUInt32LE(0);
  }

  // The 7z REAL_UINT64 encoding: the count of high one-bits in the first byte
  // gives the number of little-endian extra byte, and the remaining low bits of
  // the first byte contribute the highest byte of the value.
  readNumber() {
    const first = this.readByte();
    let mask = 0x80;
    let value = 0;
    for (let index = 0; index < 8; index += 1) {
      if ((first & mask) === 0) {
        value += (first & (mask - 1)) * 2 ** (8 * index);
        return value;
      }
      value += this.readByte() * 2 ** (8 * index);
      mask >>= 1;
    }
    return value;
  }

  // A bit vector of `count` bits packed MSB first inside each byte.
  readBitVector(count) {
    const bit = new Array(count);
    let value = 0;
    let mask = 0;
    for (let index = 0; index < count; index += 1) {
      if (mask === 0) {
        value = this.readByte();
        mask = 0x80;
      }
      bit[index] = (value & mask) !== 0;
      mask >>= 1;
    }
    return bit;
  }

  // A bit vector prefixed by an all-defined byte: when set every bit is true.
  readOptionalBitVector(count) {
    const allDefined = this.readByte();
    if (allDefined !== 0) return new Array(count).fill(true);
    return this.readBitVector(count);
  }
}

// ---------------------------------------------------------------------------
// LZMA1 decoder. A faithful range-coder implementation over a bounded output
// whose size is declared by the folder header, so it never grows unbounded.
// ---------------------------------------------------------------------------

const kNumPosBitsMax = 4;
const kNumStates = 12;

// Probability model offsets inside one flat Uint16Array.
const P_IsMatch = 0;
const P_IsRep = P_IsMatch + (kNumStates << kNumPosBitsMax);
const P_IsRepG0 = P_IsRep + kNumStates;
const P_IsRepG1 = P_IsRepG0 + kNumStates;
const P_IsRepG2 = P_IsRepG1 + kNumStates;
const P_IsRep0Long = P_IsRepG2 + kNumStates;
const P_PosSlot = P_IsRep0Long + (kNumStates << kNumPosBitsMax);
const P_SpecPos = P_PosSlot + 4 * 64;
const P_Align = P_SpecPos + 128;
const P_LenChoice = P_Align + 16;
const P_LenChoice2 = P_LenChoice + 1;
const P_LenLow = P_LenChoice2 + 1;
const P_LenMid = P_LenLow + (1 << kNumPosBitsMax) * 8;
const P_LenHigh = P_LenMid + (1 << kNumPosBitsMax) * 8;
const P_RepLenChoice = P_LenHigh + 256;
const P_RepLenChoice2 = P_RepLenChoice + 1;
const P_RepLenLow = P_RepLenChoice2 + 1;
const P_RepLenMid = P_RepLenLow + (1 << kNumPosBitsMax) * 8;
const P_RepLenHigh = P_RepLenMid + (1 << kNumPosBitsMax) * 8;
const P_Literal = P_RepLenHigh + 256;

function lzmaDecode(input, lc, lp, pb, unpackSize) {
  const literalSize = 0x300 << (lc + lp);
  const probs = new Uint16Array(P_Literal + literalSize).fill(1024);
  const out = Buffer.alloc(unpackSize);

  let inPos = 0;
  const nextByte = () => (inPos < input.length ? input[inPos++] : 0);
  // Range decoder init: the first byte is a discarded zero and the following
  // four byte seed the code word.
  nextByte();
  let code = ((nextByte() << 24) | (nextByte() << 16) | (nextByte() << 8) | nextByte()) >>> 0;
  let range = 0xffffffff;

  const normalize = () => {
    if (range < 0x1000000) {
      range = (range << 8) >>> 0;
      code = ((code << 8) | nextByte()) >>> 0;
    }
  };
  const decodeBit = (index) => {
    normalize();
    const bound = (range >>> 11) * probs[index];
    if ((code >>> 0) < bound) {
      range = bound;
      probs[index] += (2048 - probs[index]) >> 5;
      return 0;
    }
    code = (code - bound) >>> 0;
    range = (range - bound) >>> 0;
    probs[index] -= probs[index] >> 5;
    return 1;
  };
  const decodeTree = (base, numBits) => {
    let m = 1;
    for (let index = 0; index < numBits; index += 1) m = (m << 1) | decodeBit(base + m);
    return m - (1 << numBits);
  };
  const decodeLen = (choice, choice2, low, mid, high, posState) => {
    if (decodeBit(choice) === 0) return decodeTree(low + posState * 8, 3);
    if (decodeBit(choice2) === 0) return 8 + decodeTree(mid + posState * 8, 3);
    return 16 + decodeTree(high, 8);
  };

  let state = 0;
  let rep0 = 0;
  let rep1 = 0;
  let rep2 = 0;
  let rep3 = 0;
  const pbMask = (1 << pb) - 1;
  const lpMask = (1 << lp) - 1;
  let outPos = 0;

  while (outPos < unpackSize) {
    const posState = outPos & pbMask;
    if (decodeBit(P_IsMatch + (state << kNumPosBitsMax) + posState) === 0) {
      const prevByte = outPos > 0 ? out[outPos - 1] : 0;
      const litState = ((outPos & lpMask) << lc) + (prevByte >>> (8 - lc));
      const litBase = P_Literal + 0x300 * litState;
      let symbol = 1;
      if (state >= 7) {
        let matchByte = out[outPos - rep0 - 1];
        do {
          const matchBit = (matchByte >> 7) & 1;
          matchByte = (matchByte << 1) & 0xff;
          const bit = decodeBit(litBase + ((1 + matchBit) << 8) + symbol);
          symbol = (symbol << 1) | bit;
          if (matchBit !== bit) break;
        } while (symbol < 0x100);
      }
      while (symbol < 0x100) symbol = (symbol << 1) | decodeBit(litBase + symbol);
      out[outPos++] = symbol & 0xff;
      state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
      continue;
    }

    let len;
    if (decodeBit(P_IsRep + state) === 1) {
      if (decodeBit(P_IsRepG0 + state) === 0) {
        if (decodeBit(P_IsRep0Long + (state << kNumPosBitsMax) + posState) === 0) {
          state = state < 7 ? 9 : 11;
          out[outPos] = out[outPos - rep0 - 1];
          outPos += 1;
          continue;
        }
      } else {
        let dist;
        if (decodeBit(P_IsRepG1 + state) === 0) {
          dist = rep1;
        } else {
          if (decodeBit(P_IsRepG2 + state) === 0) {
            dist = rep2;
          } else {
            dist = rep3;
            rep3 = rep2;
          }
          rep2 = rep1;
        }
        rep1 = rep0;
        rep0 = dist;
      }
      len = decodeLen(P_RepLenChoice, P_RepLenChoice2, P_RepLenLow, P_RepLenMid, P_RepLenHigh, posState) + 2;
      state = state < 7 ? 8 : 11;
    } else {
      rep3 = rep2;
      rep2 = rep1;
      rep1 = rep0;
      len = decodeLen(P_LenChoice, P_LenChoice2, P_LenLow, P_LenMid, P_LenHigh, posState);
      state = state < 7 ? 7 : 10;
      const lenState = len < 4 ? len : 3;
      const posSlot = decodeTree(P_PosSlot + lenState * 64, 6);
      if (posSlot < 4) {
        rep0 = posSlot;
      } else {
        const numDirect = (posSlot >> 1) - 1;
        if (posSlot < 14) {
          // Distances 4..127: the base is shifted by the full direct-bit count
          // and the low bits come from the reverse SpecPos bit tree.
          rep0 = (2 | (posSlot & 1)) << numDirect;
          const specBase = P_SpecPos + rep0 - posSlot - 1;
          let m = 1;
          let mask = 1;
          for (let index = 0; index < numDirect; index += 1) {
            const bit = decodeBit(specBase + m);
            m = (m << 1) | bit;
            if (bit) rep0 += mask;
            mask <<= 1;
          }
        } else {
          // Distances >=128: the base accumulates the high direct bits first,
          // then the low four bits from the reverse Align bit tree.
          rep0 = 2 | (posSlot & 1);
          let direct = numDirect - 4;
          while (direct > 0) {
            normalize();
            range = range >>> 1;
            code = (code - range) >>> 0;
            const t = (0 - (code >>> 31)) >>> 0;
            code = (code + (range & t)) >>> 0;
            rep0 = ((rep0 << 1) + (t + 1)) >>> 0;
            direct -= 1;
          }
          rep0 = (rep0 << 4) >>> 0;
          let m = 1;
          for (const addend of [1, 2, 4, 8]) {
            const bit = decodeBit(P_Align + m);
            m = (m << 1) | bit;
            if (bit) rep0 = (rep0 + addend) >>> 0;
          }
        }
      }
      if (rep0 === 0xffffffff) {
        // The end-of-stream marker; a size-declared stream stops at its bound.
        break;
      }
      len += 2;
    }
    // Copy the back-reference; len already carries the minimum match length.
    for (let index = 0; index < len; index += 1) {
      out[outPos] = out[outPos - rep0 - 1];
      outPos += 1;
      if (outPos >= unpackSize) break;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// BCJ2 decoder. Recombines the four BCJ2 streams — main, call, jump, and the
// range-coded control — back into a converted x86 image of the declared size.
// ---------------------------------------------------------------------------

function bcj2Decode(main, call, jump, rc, outSize) {
  const out = Buffer.alloc(outSize);
  const probs = new Uint16Array(2 + 256).fill(1024);
  let rcPos = 0;
  const nextRc = () => (rcPos < rc.length ? rc[rcPos++] : 0);
  nextRc();
  let code = ((nextRc() << 24) | (nextRc() << 16) | (nextRc() << 8) | nextRc()) >>> 0;
  let range = 0xffffffff;
  const decodeBit = (index) => {
    if (range < 0x1000000) {
      range = (range << 8) >>> 0;
      code = ((code << 8) | nextRc()) >>> 0;
    }
    const bound = (range >>> 11) * probs[index];
    if ((code >>> 0) < bound) {
      range = bound;
      probs[index] += (2048 - probs[index]) >> 5;
      return 0;
    }
    code = (code - bound) >>> 0;
    range = (range - bound) >>> 0;
    probs[index] -= probs[index] >> 5;
    return 1;
  };

  let outPos = 0;
  let mainPos = 0;
  let callPos = 0;
  let jumpPos = 0;
  let prevByte = 0;
  while (outPos < outSize) {
    const b = mainPos < main.length ? main[mainPos++] : 0;
    out[outPos++] = b;
    const isBranch = (b & 0xfe) === 0xe8 || (prevByte === 0x0f && (b & 0xf0) === 0x80);
    if (isBranch && outPos + 4 <= outSize) {
      const probIndex = b === 0xe8 ? prevByte : b === 0xe9 ? 256 : 257;
      if (decodeBit(probIndex) === 1) {
        const src = b === 0xe8 ? call : jump;
        const sp = b === 0xe8 ? callPos : jumpPos;
        const absolute = ((src[sp] << 24) | (src[sp + 1] << 16) | (src[sp + 2] << 8) | src[sp + 3]) >>> 0;
        if (b === 0xe8) callPos += 4;
        else jumpPos += 4;
        const relative = (absolute - (outPos + 4)) >>> 0;
        out[outPos] = relative & 0xff;
        out[outPos + 1] = (relative >>> 8) & 0xff;
        out[outPos + 2] = (relative >>> 16) & 0xff;
        out[outPos + 3] = (relative >>> 24) & 0xff;
        outPos += 4;
        prevByte = (relative >>> 24) & 0xff;
        continue;
      }
    }
    prevByte = b;
  }
  return out;
}

// ---------------------------------------------------------------------------
// BCJ x86 filter (03 03 01 03). The single-stream branch converter that 7-Zip
// applies to x86 executables, undone here for the decode direction with a zero
// start address. It rewrites E8/E9 relative operands back from the absolute
// form the filter produced; a length-preserving, deterministic transform.
// ---------------------------------------------------------------------------

function bcjX86Decode(input) {
  const data = Buffer.from(input);
  const test = (b) => b === 0x00 || b === 0xff;
  const size = data.length;
  if (size < 5) return data;
  const limit = size - 4;
  let pos = 0;
  let mask = 0;
  let ip = 5;
  for (;;) {
    let p = pos;
    while (p < limit && (data[p] & 0xfe) !== 0xe8) p += 1;
    const d = p - pos;
    pos = p;
    if (p >= limit) return data;
    if (d > 2) {
      mask = 0;
    } else {
      mask >>= d;
      if (mask !== 0 && (mask > 4 || mask === 3 || test(data[p + (mask >> 1) + 1]))) {
        mask = (mask >> 1) | 4;
        pos += 1;
        continue;
      }
    }
    if (test(data[p + 4])) {
      let v = ((data[p + 4] << 24) | (data[p + 3] << 16) | (data[p + 2] << 8) | data[p + 1]) >>> 0;
      const cur = (ip + pos) >>> 0;
      v = (v - cur) >>> 0;
      if (mask !== 0) {
        const sh = (mask & 6) << 2;
        if (test((v >>> sh) & 0xff)) {
          v = (v ^ (((0x100 << sh) - 1) >>> 0)) >>> 0;
          v = (v - cur) >>> 0;
        }
        mask = 0;
      }
      data[p + 1] = v & 0xff;
      data[p + 2] = (v >>> 8) & 0xff;
      data[p + 3] = (v >>> 16) & 0xff;
      data[p + 4] = (0 - ((v >>> 24) & 1)) & 0xff;
      pos += 5;
    } else {
      mask = (mask >> 1) | 4;
      pos += 1;
    }
  }
}

// ---------------------------------------------------------------------------
// Header parsing.
// ---------------------------------------------------------------------------

function readPackInfo(cursor) {
  const packPos = cursor.readNumber();
  const numPackStreams = cursor.readNumber();
  let packSize = null;
  for (;;) {
    const id = cursor.readNumber();
    if (id === kEnd) break;
    if (id === kSize) {
      packSize = new Array(numPackStreams);
      for (let index = 0; index < numPackStreams; index += 1) packSize[index] = cursor.readNumber();
    } else if (id === kCRC) {
      const defined = cursor.readOptionalBitVector(numPackStreams);
      for (let index = 0; index < numPackStreams; index += 1) if (defined[index]) cursor.readUInt32();
    } else {
      throw sevenZipError("archive_header_unsupported", `Unsupported pack-info property 0x${id.toString(16)}`);
    }
  }
  if (packSize === null) throw sevenZipError("archive_header_unsupported", "The pack info declares no stream sizes");
  return { packPos, numPackStreams, packSize };
}

function readFolder(cursor) {
  const numCoders = cursor.readNumber();
  const coder = [];
  let totalIn = 0;
  let totalOut = 0;
  for (let index = 0; index < numCoders; index += 1) {
    const flag = cursor.readByte();
    const idSize = flag & 0x0f;
    const id = Buffer.from(cursor.readBytes(idSize)).toString("hex");
    let numIn = 1;
    let numOut = 1;
    if ((flag & 0x10) !== 0) {
      numIn = cursor.readNumber();
      numOut = cursor.readNumber();
    }
    let property = Buffer.alloc(0);
    if ((flag & 0x20) !== 0) {
      const propSize = cursor.readNumber();
      property = Buffer.from(cursor.readBytes(propSize));
    }
    if ((flag & 0x80) !== 0) {
      throw sevenZipError("archive_header_unsupported", "An alternative-method coder flag is outside the supported census");
    }
    coder.push({ id, numIn, numOut, property, inStart: totalIn, outStart: totalOut });
    totalIn += numIn;
    totalOut += numOut;
  }
  const numBindPairs = totalOut - 1;
  const bindPair = [];
  for (let index = 0; index < numBindPairs; index += 1) {
    const inIndex = cursor.readNumber();
    const outIndex = cursor.readNumber();
    bindPair.push({ inIndex, outIndex });
  }
  const numPackedStreams = totalIn - numBindPairs;
  const packedIndex = [];
  if (numPackedStreams === 1) {
    // The single packed stream is the one input not named by a bind pair.
    const bound = new Set(bindPair.map((pair) => pair.inIndex));
    for (let index = 0; index < totalIn; index += 1) {
      if (!bound.has(index)) {
        packedIndex.push(index);
        break;
      }
    }
  } else {
    for (let index = 0; index < numPackedStreams; index += 1) packedIndex.push(cursor.readNumber());
  }
  return { coder, totalIn, totalOut, bindPair, packedIndex, unpackSize: [] };
}

function readUnpackInfo(cursor) {
  let id = cursor.readNumber();
  if (id !== kFolder) throw sevenZipError("archive_header_unsupported", "The unpack info does not begin with a folder record");
  const numFolders = cursor.readNumber();
  const external = cursor.readByte();
  if (external !== 0) throw sevenZipError("archive_header_unsupported", "External folder definitions are outside the supported census");
  const folder = [];
  for (let index = 0; index < numFolders; index += 1) folder.push(readFolder(cursor));
  id = cursor.readNumber();
  if (id !== kCodersUnpackSize) throw sevenZipError("archive_header_unsupported", "The unpack info is missing coder unpack sizes");
  for (const current of folder) {
    for (let index = 0; index < current.totalOut; index += 1) current.unpackSize.push(cursor.readNumber());
  }
  for (;;) {
    id = cursor.readNumber();
    if (id === kEnd) break;
    if (id === kCRC) {
      const defined = cursor.readOptionalBitVector(numFolders);
      for (let index = 0; index < numFolders; index += 1) {
        if (defined[index]) folder[index].crc = cursor.readUInt32();
      }
    } else {
      throw sevenZipError("archive_header_unsupported", `Unsupported unpack-info property 0x${id.toString(16)}`);
    }
  }
  return folder;
}

// The final output stream of a folder is the one coder output that no bind pair
// consumes; its declared size is the folder's total unpacked size.
function folderFinalOutIndex(folder) {
  const bound = new Set(folder.bindPair.map((pair) => pair.outIndex));
  for (let index = 0; index < folder.totalOut; index += 1) if (!bound.has(index)) return index;
  throw sevenZipError("archive_header_unsupported", "The folder declares no terminal output stream");
}

function folderUnpackSize(folder) {
  return folder.unpackSize[folderFinalOutIndex(folder)];
}

function readSubStreamsInfo(cursor, folder) {
  let numUnpackStreams = folder.map(() => 1);
  let id = cursor.readNumber();
  if (id === kNumUnpackStream) {
    numUnpackStreams = folder.map(() => cursor.readNumber());
    id = cursor.readNumber();
  }
  const size = [];
  for (let folderIndex = 0; folderIndex < folder.length; folderIndex += 1) {
    const count = numUnpackStreams[folderIndex];
    if (count === 0) continue;
    let sum = 0;
    const folderSize = folderUnpackSize(folder[folderIndex]);
    const local = [];
    if (id === kSize) {
      for (let streamIndex = 0; streamIndex < count - 1; streamIndex += 1) {
        const value = cursor.readNumber();
        local.push(value);
        sum += value;
      }
    } else if (count > 1) {
      throw sevenZipError("archive_header_unsupported", "A multi-stream folder is missing its substream sizes");
    }
    local.push(folderSize - sum);
    for (const value of local) size.push({ folderIndex, size: value });
  }
  if (id === kSize) id = cursor.readNumber();

  // Count the digests already known from single-stream folders.
  const digest = new Array(size.length).fill(null);
  let numUnknown = 0;
  const streamOffset = [];
  {
    let cursorIndex = 0;
    for (let folderIndex = 0; folderIndex < folder.length; folderIndex += 1) {
      const count = numUnpackStreams[folderIndex];
      streamOffset.push(cursorIndex);
      if (count === 1 && folder[folderIndex].crc !== undefined) {
        digest[cursorIndex] = folder[folderIndex].crc;
      } else {
        numUnknown += count;
      }
      cursorIndex += count;
    }
  }
  if (id === kCRC) {
    const defined = cursor.readOptionalBitVector(numUnknown);
    let definedIndex = 0;
    for (let index = 0; index < size.length; index += 1) {
      if (digest[index] !== null) continue;
      if (defined[definedIndex]) digest[index] = cursor.readUInt32();
      definedIndex += 1;
    }
    id = cursor.readNumber();
  }
  while (id !== kEnd) {
    // Skip any unrecognized substreams property by consuming its size body is
    // unsafe, so an unknown property is refused rather than guessed.
    throw sevenZipError("archive_header_unsupported", `Unsupported substreams property 0x${id.toString(16)}`);
  }
  return { numUnpackStreams, size, digest };
}

function readStreamsInfo(cursor) {
  const info = { pack: null, folder: null, sub: null };
  let id = cursor.readNumber();
  if (id === kPackInfo) {
    info.pack = readPackInfo(cursor);
    id = cursor.readNumber();
  }
  if (id === kUnpackInfo) {
    info.folder = readUnpackInfo(cursor);
    id = cursor.readNumber();
  }
  if (id === kSubStreamsInfo) {
    info.sub = readSubStreamsInfo(cursor, info.folder ?? []);
    id = cursor.readNumber();
  }
  if (info.folder && !info.sub) {
    info.sub = {
      numUnpackStreams: info.folder.map(() => 1),
      size: info.folder.map((folder, index) => ({ folderIndex: index, size: folderUnpackSize(folder) })),
      digest: info.folder.map((folder) => (folder.crc !== undefined ? folder.crc : null)),
    };
  }
  if (id !== kEnd) throw sevenZipError("archive_header_unsupported", "The streams info is not terminated");
  return info;
}

function readFilesInfo(cursor) {
  const numFiles = cursor.readNumber();
  const file = [];
  for (let index = 0; index < numFiles; index += 1) file.push({ name: null, hasStream: true, isEmptyFile: false, attributes: null });
  let emptyStream = new Array(numFiles).fill(false);
  for (;;) {
    const propertyType = cursor.readNumber();
    if (propertyType === kEnd) break;
    const size = cursor.readNumber();
    const end = cursor.position + size;
    if (propertyType === kEmptyStream) {
      emptyStream = cursor.readBitVector(numFiles);
      for (let index = 0; index < numFiles; index += 1) file[index].hasStream = !emptyStream[index];
    } else if (propertyType === kEmptyFile) {
      const emptyCount = emptyStream.filter(Boolean).length;
      const emptyFile = cursor.readBitVector(emptyCount);
      let emptyIndex = 0;
      for (let index = 0; index < numFiles; index += 1) {
        if (emptyStream[index]) {
          file[index].isEmptyFile = emptyFile[emptyIndex];
          emptyIndex += 1;
        }
      }
    } else if (propertyType === kName) {
      const external = cursor.readByte();
      if (external !== 0) throw sevenZipError("archive_header_unsupported", "External file names are outside the supported census");
      const nameBuffer = cursor.readBytes(end - cursor.position);
      let start = 0;
      let fileIndex = 0;
      for (let offset = 0; offset + 1 < nameBuffer.length; offset += 2) {
        if (nameBuffer[offset] === 0 && nameBuffer[offset + 1] === 0) {
          file[fileIndex].name = nameBuffer.toString("utf16le", start, offset);
          fileIndex += 1;
          start = offset + 2;
        }
      }
    } else if (propertyType === kWinAttributes) {
      const defined = cursor.readOptionalBitVector(numFiles);
      const external = cursor.readByte();
      if (external !== 0) throw sevenZipError("archive_header_unsupported", "External attributes are outside the supported census");
      for (let index = 0; index < numFiles; index += 1) if (defined[index]) file[index].attributes = cursor.readUInt32();
    } else if (propertyType === kDummy) {
      cursor.readBytes(end - cursor.position);
    } else {
      cursor.readBytes(end - cursor.position);
    }
    cursor.position = end;
  }
  return { numFiles, file };
}

function readHeader(cursor) {
  const id = cursor.readNumber();
  if (id !== kHeader) throw sevenZipError("archive_header_unsupported", "The decoded 7z header does not begin with a header record");
  const header = { streamsInfo: null, filesInfo: null };
  let propertyType = cursor.readNumber();
  if (propertyType === 0x02 || propertyType === 0x03) {
    throw sevenZipError("archive_header_unsupported", "Archive or additional-stream properties are outside the supported census");
  }
  if (propertyType === kMainStreamsInfo) {
    header.streamsInfo = readStreamsInfo(cursor);
    propertyType = cursor.readNumber();
  }
  if (propertyType === kFilesInfo) {
    header.filesInfo = readFilesInfo(cursor);
    propertyType = cursor.readNumber();
  }
  return header;
}

// ---------------------------------------------------------------------------
// Folder decoding: resolve the coder graph and recover the folder bytes.
// ---------------------------------------------------------------------------

function assertCoderSupported(id) {
  if (id === CODER_AES) {
    throw sevenZipError("archive_entry_encrypted", "The 7z folder uses AES-256 encryption, and encrypted payload is refused");
  }
  if (id !== CODER_LZMA && id !== CODER_BCJ2 && id !== CODER_BCJ_X86 && id !== CODER_COPY) {
    throw sevenZipError("archive_coder_unsupported", `The 7z folder uses coder ${id}, which is outside the LZMA, BCJ2, BCJ x86, and Copy census`);
  }
}

function runCoder(coder, inputBuffer, outputSize, bound) {
  assertCoderSupported(coder.id);
  if (coder.id === CODER_COPY) {
    return Buffer.from(inputBuffer[0].subarray(0, outputSize));
  }
  if (coder.id === CODER_LZMA) {
    const property = coder.property;
    if (property.length < 5) throw sevenZipError("archive_header_unsupported", "The LZMA coder is missing its property byte");
    const d = property[0];
    const lc = d % 9;
    const remainder = Math.floor(d / 9);
    const lp = remainder % 5;
    const pb = Math.floor(remainder / 5);
    const input = inputBuffer[0];
    assertChunkInputBound(bound, input.length);
    if (outputSize > chunkOutputCap(bound, input.length)) {
      throw sevenZipError("bound_output_exceeded", "The LZMA folder output exceeds its declared amplification cap");
    }
    assertChunkRatioBound(bound, input.length, outputSize);
    return lzmaDecode(input, lc, lp, pb, outputSize);
  }
  if (coder.id === CODER_BCJ_X86) {
    return bcjX86Decode(inputBuffer[0].subarray(0, outputSize));
  }
  // BCJ2: four inputs in the order main, call, jump, control.
  return bcj2Decode(inputBuffer[0], inputBuffer[1], inputBuffer[2], inputBuffer[3], outputSize);
}

// Decodes one folder into its terminal output buffer. Packed streams for the
// folder are provided in folder order; coder outputs are memoized so a shared
// input is decoded once.
function decodeFolder(folder, packStream, bound) {
  const coderOutput = new Map();
  const inputToOutput = new Map();
  for (const pair of folder.bindPair) inputToOutput.set(pair.inIndex, pair.outIndex);
  const packedForInput = new Map();
  folder.packedIndex.forEach((globalIn, order) => packedForInput.set(globalIn, order));

  const coderForOutput = (outIndex) => folder.coder.find((coder) => outIndex >= coder.outStart && outIndex < coder.outStart + coder.numOut);

  const resolveInput = (globalIn) => {
    if (packedForInput.has(globalIn)) return packStream[packedForInput.get(globalIn)];
    if (inputToOutput.has(globalIn)) return decodeCoderOutput(inputToOutput.get(globalIn));
    throw sevenZipError("archive_header_unsupported", "A folder input is neither packed nor bound");
  };

  function decodeCoderOutput(outIndex) {
    if (coderOutput.has(outIndex)) return coderOutput.get(outIndex);
    const coder = coderForOutput(outIndex);
    const input = [];
    for (let index = 0; index < coder.numIn; index += 1) input.push(resolveInput(coder.inStart + index));
    const outputSize = folder.unpackSize[coder.outStart];
    const output = runCoder(coder, input, outputSize, bound);
    coderOutput.set(coder.outStart, output);
    return output;
  }

  return decodeCoderOutput(folderFinalOutIndex(folder));
}

// ---------------------------------------------------------------------------
// Top-level extraction.
// ---------------------------------------------------------------------------

function sanitizeArchivePath(name, bound) {
  const normalized = name.replace(/\\/g, "/");
  if (/^[a-zA-Z]:/.test(normalized) || normalized.startsWith("/")) {
    throw sevenZipError("archive_path_escape", `The 7z entry ${name} is an absolute path`);
  }
  const part = normalized.split("/").filter((segment) => segment.length > 0 && segment !== ".");
  if (part.some((segment) => segment === "..")) {
    throw sevenZipError("archive_path_escape", `The 7z entry ${name} escapes the output directory`);
  }
  assertDepthBound(bound, part.length);
  return part.join("/");
}

// Parses and fully recovers a bounded 7z archive from a buffer. Returns the
// recovered file list with real bytes and a per-file checksum state.
export function readSevenZip(data, option = {}) {
  const bound = createExtractionBound(option.bound);
  if (data.length < 32 || !data.subarray(0, 6).equals(sevenZipMagic)) {
    throw sevenZipError("archive_format_unsupported", "The input does not carry the 7z signature");
  }
  const startHeaderCrc = data.readUInt32LE(8);
  const startHeader = data.subarray(12, 32);
  if (crc32(startHeader) !== startHeaderCrc) {
    throw sevenZipError("archive_header_checksum", "The 7z start header CRC32 does not match");
  }
  const nextHeaderOffset = Number(data.readBigUInt64LE(12));
  const nextHeaderSize = Number(data.readBigUInt64LE(20));
  const nextHeaderCrc = data.readUInt32LE(28);
  const base = 32;
  if (base + nextHeaderOffset + nextHeaderSize > data.length) {
    throw sevenZipError("archive_header_truncated", "The 7z end header extends past the archive");
  }
  let headerBuffer = data.subarray(base + nextHeaderOffset, base + nextHeaderOffset + nextHeaderSize);
  if (nextHeaderSize === 0) {
    return { file: [], output_byte: 0, folder_count: 0, entry_count: 0, evidence: ["The 7z archive declares no header and no payload"] };
  }
  if (crc32(headerBuffer) !== nextHeaderCrc) {
    throw sevenZipError("archive_header_checksum", "The 7z end header CRC32 does not match");
  }

  // An encoded header is itself a bounded streams-info payload that decodes to
  // the real header buffer through the same folder pipeline.
  let cursor = new HeaderCursor(headerBuffer);
  let firstId = cursor.readNumber();
  if (firstId === kEncodedHeader) {
    const streamsInfo = readStreamsInfo(cursor);
    const decoded = extractPackedFolders(data, base, streamsInfo, bound, { headerMode: true });
    headerBuffer = Buffer.concat(decoded);
    if (headerBuffer.length > bound.chunk_input_byte) {
      throw sevenZipError("bound_input_exceeded", "The decoded 7z header exceeds the declared read bound");
    }
    cursor = new HeaderCursor(headerBuffer);
    firstId = cursor.readNumber();
    cursor.position = 0;
  } else {
    cursor.position = 0;
  }

  const header = readHeader(cursor);
  const streamsInfo = header.streamsInfo;
  const filesInfo = header.filesInfo;
  if (!filesInfo) throw sevenZipError("archive_header_unsupported", "The 7z header declares no file table");
  assertEntryBound(bound, filesInfo.numFiles);

  // Recover the payload folders on demand, keyed by folder index.
  const folderCache = new Map();
  const packLayout = streamsInfo && streamsInfo.pack
    ? buildPackLayout(base, streamsInfo)
    : null;
  const decodeOne = (folderIndex) => {
    if (folderCache.has(folderIndex)) return folderCache.get(folderIndex);
    const folder = streamsInfo.folder[folderIndex];
    const packStream = sliceFolderPackStreams(data, packLayout, streamsInfo, folderIndex, bound);
    const decoded = decodeFolder(folder, packStream, bound);
    if (folder.crc !== undefined && crc32(decoded) !== folder.crc) {
      throw sevenZipError("archive_folder_checksum", `The 7z folder ${folderIndex} failed its CRC32`);
    }
    folderCache.set(folderIndex, decoded);
    return decoded;
  };

  const sub = streamsInfo ? streamsInfo.sub : null;
  // Track the running byte offset inside each folder for its substreams.
  const folderStreamOffset = new Map();
  let subCursor = 0;
  const recovered = [];
  let outputByte = 0;
  for (const entry of filesInfo.file) {
    if (entry.name === null) throw sevenZipError("archive_header_unsupported", "A 7z entry carries no name");
    const isDirectory = !entry.hasStream && !entry.isEmptyFile;
    const attributeDirectory = entry.attributes !== null && (entry.attributes & 0x10) !== 0;
    if (!entry.hasStream) {
      // An empty-stream entry is a directory or a zero-byte file; neither is a
      // payload the packaging step consumes, so it is recorded without bytes.
      recovered.push({
        path: sanitizeArchivePath(entry.name, bound),
        size_byte: 0,
        checksum_state: "undeclared",
        type: isDirectory || attributeDirectory ? "directory" : "file",
        content: Buffer.alloc(0),
      });
      continue;
    }
    const streamRecord = sub.size[subCursor];
    const digest = sub.digest[subCursor];
    subCursor += 1;
    const folderIndex = streamRecord.folderIndex;
    const folderBytes = decodeOne(folderIndex);
    const offset = folderStreamOffset.get(folderIndex) ?? 0;
    if (offset + streamRecord.size > folderBytes.length) {
      throw sevenZipError("archive_file_out_of_folder", `The 7z entry ${entry.name} extends past its decoded folder`);
    }
    const content = Buffer.from(folderBytes.subarray(offset, offset + streamRecord.size));
    folderStreamOffset.set(folderIndex, offset + streamRecord.size);
    let checksumState = "undeclared";
    if (digest !== null && digest !== undefined) {
      if (crc32(content) !== (digest >>> 0)) {
        throw sevenZipError("archive_file_checksum", `The 7z entry ${entry.name} failed its CRC32`);
      }
      checksumState = "verified";
    }
    outputByte += content.length;
    assertOutputBound(bound, outputByte);
    recovered.push({
      path: sanitizeArchivePath(entry.name, bound),
      size_byte: content.length,
      checksum_state: checksumState,
      type: "file",
      content,
    });
  }
  return {
    file: recovered,
    output_byte: outputByte,
    folder_count: streamsInfo ? streamsInfo.folder.length : 0,
    entry_count: filesInfo.numFiles,
    evidence: [
      `The 7z archive was extracted under the declared bound across ${streamsInfo ? streamsInfo.folder.length : 0} folder`,
      "Coder census: LZMA (03 01 01), BCJ2 (03 03 01 1B), BCJ x86 (03 03 01 03), and Copy (00); every other coder is refused",
    ],
  };
}

// Builds the absolute pack-stream offset table from the pack info.
function buildPackLayout(base, streamsInfo) {
  const pack = streamsInfo.pack;
  const offset = [];
  let cursor = base + pack.packPos;
  for (let index = 0; index < pack.numPackStreams; index += 1) {
    offset.push({ start: cursor, size: pack.packSize[index] });
    cursor += pack.packSize[index];
  }
  return offset;
}

// Maps folders to their consumed pack streams in folder order.
function folderPackStreamCounts(streamsInfo) {
  return streamsInfo.folder.map((folder) => folder.packedIndex.length);
}

function sliceFolderPackStreams(data, packLayout, streamsInfo, folderIndex, bound) {
  const counts = folderPackStreamCounts(streamsInfo);
  let packStart = 0;
  for (let index = 0; index < folderIndex; index += 1) packStart += counts[index];
  const count = counts[folderIndex];
  const slice = [];
  for (let index = 0; index < count; index += 1) {
    const record = packLayout[packStart + index];
    if (!record || record.start + record.size > data.length) {
      throw sevenZipError("archive_header_truncated", "A 7z pack stream extends past the archive");
    }
    assertChunkInputBound(bound, record.size);
    slice.push(data.subarray(record.start, record.start + record.size));
  }
  return slice;
}

// Decodes the folders described by a streams-info payload directly, used for the
// encoded-header case where the header is itself a compressed folder.
function extractPackedFolders(data, base, streamsInfo, bound, option = {}) {
  const packLayout = buildPackLayout(base, streamsInfo);
  const output = [];
  for (let folderIndex = 0; folderIndex < streamsInfo.folder.length; folderIndex += 1) {
    const folder = streamsInfo.folder[folderIndex];
    const packStream = sliceFolderPackStreams(data, packLayout, streamsInfo, folderIndex, bound);
    const decoded = decodeFolder(folder, packStream, bound);
    if (folder.crc !== undefined && crc32(decoded) !== folder.crc) {
      throw sevenZipError("archive_folder_checksum", `The 7z ${option.headerMode ? "encoded header" : "folder"} failed its CRC32`);
    }
    output.push(decoded);
  }
  return output;
}
