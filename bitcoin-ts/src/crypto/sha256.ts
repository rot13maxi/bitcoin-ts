/**
 * Bitcoin Core cryptographic primitives - SHA-256
 * Ported from src/crypto/sha256.h/cpp
 * 
 * @module crypto/sha256
 */

/**
 * CSHA256 - A hasher class for SHA-256
 * Uses Web Crypto API for native implementation where available
 */
export class CSHA256 {
  private s: Uint32Array;
  private buf: Uint8Array;
  private bytes: bigint;

  static readonly OUTPUT_SIZE = 32;

  constructor() {
    this.s = new Uint32Array(8);
    this.buf = new Uint8Array(64);
    this.bytes = 0n;
    this.Reset();
  }

  /**
   * Write data to the hasher
   */
  Write(data: Uint8Array): CSHA256 {
    let offset = 0;
    const len = data.length;

    if (this.bytes % 64n && len > 0) {
      const spaceLeft = 64 - Number(this.bytes % 64n);
      const toCopy = Math.min(spaceLeft, len);
      this.buf.set(data.subarray(0, toCopy), Number(this.bytes % 64n));
      this.bytes += BigInt(toCopy);
      offset = toCopy;

      if (this.bytes % 64n === 0n) {
        this.transform(this.buf);
        this.buf.fill(0);
      }
    }

    while (offset + 64 <= len) {
      this.transform(data.subarray(offset, offset + 64));
      this.bytes += 64n;
      offset += 64;
    }

    if (offset < len) {
      this.buf.set(data.subarray(offset), Number(this.bytes % 64n));
      this.bytes += BigInt(len - offset);
    }

    return this;
  }

  /**
   * Finalize the hash and return the result
   */
  Finalize(hash: Uint8Array): void {
    const totalBits = this.bytes * 8n;
    const padLen = this.bytes % 64n < 56n ? 56n - (this.bytes % 64n) : 120n - (this.bytes % 64n);
    
    const padding = new Uint8Array(Number(padLen) + 1);
    padding[0] = 0x80;
    this.Write(padding);

    const bitLen = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      bitLen[7 - i] = Number((totalBits >> BigInt(i * 8)) & 0xffn);
    }
    this.Write(bitLen);

    for (let i = 0; i < 8; i++) {
      hash[i * 4] = (this.s[i] >> 24) & 0xff;
      hash[i * 4 + 1] = (this.s[i] >> 16) & 0xff;
      hash[i * 4 + 2] = (this.s[i] >> 8) & 0xff;
      hash[i * 4 + 3] = this.s[i] & 0xff;
    }
  }

  /**
   * Reset the hasher to initial state
   */
  Reset(): CSHA256 {
    this.s = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    this.bytes = 0n;
    return this;
  }

  /**
   * Core SHA-256 transform operation
   */
  private transform(block: Uint8Array): void {
    const w = new Uint32Array(64);

    // Message schedule
    for (let i = 0; i < 16; i++) {
      w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
             (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }

    for (let i = 16; i < 64; i++) {
      const s0 = this.rotr(w[i - 15], 7) ^ this.rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = this.rotr(w[i - 2], 17) ^ this.rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, h] = this.s;

    for (let i = 0; i < 64; i++) {
      const S1 = this.rotr(e, 6) ^ this.rotr(e, 11) ^ this.rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + CSHA256.K[i] + w[i]) >>> 0;
      const S0 = this.rotr(a, 2) ^ this.rotr(a, 13) ^ this.rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    this.s[0] = (this.s[0] + a) >>> 0;
    this.s[1] = (this.s[1] + b) >>> 0;
    this.s[2] = (this.s[2] + c) >>> 0;
    this.s[3] = (this.s[3] + d) >>> 0;
    this.s[4] = (this.s[4] + e) >>> 0;
    this.s[5] = (this.s[5] + f) >>> 0;
    this.s[6] = (this.s[6] + g) >>> 0;
    this.s[7] = (this.s[7] + h) >>> 0;
  }

  private rotr(n: number, r: number): number {
    return ((n >>> r) | (n << (32 - r))) >>> 0;
  }

  private static readonly K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);
}

/**
 * Compute SHA-256 hash using Web Crypto API when available
 * Falls back to pure JS implementation for environments without Web Crypto
 */
export async function sha256WebCrypto(data: Uint8Array): Promise<Uint8Array> {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const hash = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
  }
  // Fallback to pure JS
  const hasher = new CSHA256();
  hasher.Write(data);
  const hash = new Uint8Array(CSHA256.OUTPUT_SIZE);
  hasher.Finalize(hash);
  return hash;
}

/**
 * Synchronous SHA-256 using pure JS implementation
 */
export function sha256(data: Uint8Array): Uint8Array {
  const hasher = new CSHA256();
  hasher.Write(data);
  const hash = new Uint8Array(CSHA256.OUTPUT_SIZE);
  hasher.Finalize(hash);
  return hash;
}

/**
 * Compute double SHA-256 (Hash256)
 */
export function hash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

/**
 * Compute SHA-256 of multiple 64-byte blobs
 * output: pointer to a blocks*32 byte output buffer
 * input: pointer to a blocks*64 byte input buffer
 */
export function SHA256D64(output: Uint8Array, input: Uint8Array, blocks: number): void {
  for (let i = 0; i < blocks; i++) {
    const block = input.subarray(i * 64, i * 64 + 64);
    const hash = sha256(block);
    output.set(hash, i * 32);
  }
}
