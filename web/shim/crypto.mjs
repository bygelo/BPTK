// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// A zero-dependency createHash("sha256") shim. The runtime uses SHA-256 only
// (lib/pe.mjs image digest, lib/runtime.mjs trace/memory digest, lib/hle.mjs
// output digest), always .update(data).digest("hex"). This pure-JS FIPS-180-4
// SHA-256 produces the exact digest node:crypto does; test/present.test.mjs
// proves equality on the empty input, "abc", and a long buffer.

const roundConstant = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(value, count) {
  return (value >>> count) | (value << (32 - count));
}

function toBytes(data) {
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  throw new TypeError("sha256 update expects a string, ArrayBuffer, or typed array");
}

class Sha256 {
  constructor() {
    this.state = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    this.block = new Uint8Array(64);
    this.blockLength = 0;
    this.byteLength = 0;
    this.finished = false;
  }

  update(data) {
    if (this.finished) throw new Error("sha256 digest already produced");
    const bytes = toBytes(data);
    this.byteLength += bytes.length;
    let offset = 0;
    while (offset < bytes.length) {
      const take = Math.min(64 - this.blockLength, bytes.length - offset);
      this.block.set(bytes.subarray(offset, offset + take), this.blockLength);
      this.blockLength += take;
      offset += take;
      if (this.blockLength === 64) {
        this.#compress(this.block);
        this.blockLength = 0;
      }
    }
    return this;
  }

  #compress(block) {
    const w = new Uint32Array(64);
    for (let index = 0; index < 16; index += 1) {
      const base = index * 4;
      w[index] = (block[base] << 24) | (block[base + 1] << 16) | (block[base + 2] << 8) | block[base + 3];
    }
    for (let index = 16; index < 64; index += 1) {
      const s0 = rotr(w[index - 15], 7) ^ rotr(w[index - 15], 18) ^ (w[index - 15] >>> 3);
      const s1 = rotr(w[index - 2], 17) ^ rotr(w[index - 2], 19) ^ (w[index - 2] >>> 10);
      w[index] = (w[index - 16] + s0 + w[index - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = this.state;
    for (let index = 0; index < 64; index += 1) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + ch + roundConstant[index] + w[index]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) >>> 0;
      h = g; g = f; f = e;
      e = (d + temp1) >>> 0;
      d = c; c = b; b = a;
      a = (temp1 + temp2) >>> 0;
    }
    this.state[0] = (this.state[0] + a) >>> 0;
    this.state[1] = (this.state[1] + b) >>> 0;
    this.state[2] = (this.state[2] + c) >>> 0;
    this.state[3] = (this.state[3] + d) >>> 0;
    this.state[4] = (this.state[4] + e) >>> 0;
    this.state[5] = (this.state[5] + f) >>> 0;
    this.state[6] = (this.state[6] + g) >>> 0;
    this.state[7] = (this.state[7] + h) >>> 0;
  }

  #finish() {
    const bitLength = this.byteLength * 8;
    const pad = [];
    pad.push(0x80);
    const total = this.blockLength + 1;
    const zeroCount = (total <= 56 ? 56 : 120) - total;
    for (let index = 0; index < zeroCount; index += 1) pad.push(0);
    const high = Math.floor(bitLength / 0x100000000);
    const low = bitLength >>> 0;
    pad.push((high >>> 24) & 0xff, (high >>> 16) & 0xff, (high >>> 8) & 0xff, high & 0xff);
    pad.push((low >>> 24) & 0xff, (low >>> 16) & 0xff, (low >>> 8) & 0xff, low & 0xff);
    this.update(new Uint8Array(pad));
    this.finished = true;
  }

  digest(encoding) {
    if (!this.finished) this.#finish();
    const out = new Uint8Array(32);
    for (let index = 0; index < 8; index += 1) {
      out[index * 4] = (this.state[index] >>> 24) & 0xff;
      out[index * 4 + 1] = (this.state[index] >>> 16) & 0xff;
      out[index * 4 + 2] = (this.state[index] >>> 8) & 0xff;
      out[index * 4 + 3] = this.state[index] & 0xff;
    }
    if (encoding === "hex") {
      let hex = "";
      for (const byte of out) hex += byte.toString(16).padStart(2, "0");
      return hex;
    }
    return out;
  }
}

export function createHash(algorithm) {
  const name = String(algorithm).toLowerCase();
  if (name !== "sha256") throw new Error(`crypto shim serves only sha256, not ${algorithm}`);
  return new Sha256();
}

export default { createHash };
