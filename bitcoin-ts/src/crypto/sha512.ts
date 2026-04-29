/**
 * Bitcoin Core cryptographic primitives - SHA-512
 * Ported from src/crypto/sha512.h/cpp
 * 
 * @module crypto/sha512
 */

/**
 * CSHA512 - A hasher class for SHA-512
 */
export class CSHA512 {
  private s: BigUint64Array;
  private buf: Uint8Array;
  private bytes: bigint;

  static readonly OUTPUT_SIZE = 64;

  constructor() {
    this.s = new BigUint64Array(8);
    this.buf = new Uint8Array(128);
    this.bytes = 0n;
    this.Reset();
  }

  /**
   * Write data to the hasher
   */
  Write(data: Uint8Array): CSHA512 {
    let offset = 0;
    const len = data.length;

    if (this.bytes % 128n && len > 0) {
      const spaceLeft = 128 - Number(this.bytes % 128n);
      const toCopy = Math.min(spaceLeft, len);
      this.buf.set(data.subarray(0, toCopy), Number(this.bytes % 128n));
      this.bytes += BigInt(toCopy);
      offset = toCopy;

      if (this.bytes % 128n === 0n) {
        this.transform(this.buf);
        this.buf.fill(0);
      }
    }

    while (offset + 128 <= len) {
      this.transform(data.subarray(offset, offset + 128));
      this.bytes += 128n;
      offset += 128;
    }

    if (offset < len) {
      this.buf.set(data.subarray(offset), Number(this.bytes % 128n));
      this.bytes += BigInt(len - offset);
    }

    return this;
  }

  /**
   * Finalize the hash and return the result
   */
  Finalize(hash: Uint8Array): void {
    const totalBits = this.bytes * 8n;
    const padLen = this.bytes % 128n < 112n ? 112n - (this.bytes % 128n) : 240n - (this.bytes % 128n);
    
    const padding = new Uint8Array(Number(padLen) + 1);
    padding[0] = 0x80;
    this.Write(padding);

    const bitLen = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      bitLen[15 - i] = Number((totalBits >> BigInt(i * 8)) & 0xffn);
    }
    this.Write(bitLen);

    for (let i = 0; i < 8; i++) {
      const val = this.s[i];
      hash[i * 8] = Number((val >> 56n) & 0xffn);
      hash[i * 8 + 1] = Number((val >> 48n) & 0xffn);
      hash[i * 8 + 2] = Number((val >> 40n) & 0xffn);
      hash[i * 8 + 3] = Number((val >> 32n) & 0xffn);
      hash[i * 8 + 4] = Number((val >> 24n) & 0xffn);
      hash[i * 8 + 5] = Number((val >> 16n) & 0xffn);
      hash[i * 8 + 6] = Number((val >> 8n) & 0xffn);
      hash[i * 8 + 7] = Number(val & 0xffn);
    }
  }

  /**
   * Reset the hasher to initial state
   */
  Reset(): CSHA512 {
    this.s = new BigUint64Array([
      0x6a09e667f3bcc908n, 0xb67ae8584caa73b2n,
      0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
      0x510e527fade682d1n, 0x9b05688c2b3e6c1fn,
      0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
    ]);
    this.bytes = 0n;
    return this;
  }

  /**
   * Core SHA-512 transform operation
   */
  private transform(block: Uint8Array): void {
    const w = new BigUint64Array(80);

    // Message schedule
    for (let i = 0; i < 16; i++) {
      w[i] = 0n;
      for (let j = 0; j < 8; j++) {
        w[i] = (w[i] << 8n) | BigInt(block[i * 8 + j]);
      }
    }

    for (let i = 16; i < 80; i++) {
      const s0 = this.rotr(w[i - 15], 1) ^ this.rotr(w[i - 15], 8) ^ (w[i - 15] >> 7n);
      const s1 = this.rotr(w[i - 2], 19) ^ this.rotr(w[i - 2], 61) ^ (w[i - 2] >> 6n);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffffffffffffn;
    }

    let [a, b, c, d, e, f, g, h] = this.s;

    for (let i = 0; i < 80; i++) {
      const S1 = this.rotr(e, 14) ^ this.rotr(e, 18) ^ this.rotr(e, 41);
      const ch = (e & f) ^ (~e & g);
      const temp1 = h + S1 + ch + CSHA512.K[i] + w[i];
      const S0 = this.rotr(a, 28) ^ this.rotr(a, 34) ^ this.rotr(a, 39);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = S0 + maj;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) & 0xffffffffffffffffn;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & 0xffffffffffffffffn;
    }

    this.s[0] = (this.s[0] + a) & 0xffffffffffffffffn;
    this.s[1] = (this.s[1] + b) & 0xffffffffffffffffn;
    this.s[2] = (this.s[2] + c) & 0xffffffffffffffffn;
    this.s[3] = (this.s[3] + d) & 0xffffffffffffffffn;
    this.s[4] = (this.s[4] + e) & 0xffffffffffffffffn;
    this.s[5] = (this.s[5] + f) & 0xffffffffffffffffn;
    this.s[6] = (this.s[6] + g) & 0xffffffffffffffffn;
    this.s[7] = (this.s[7] + h) & 0xffffffffffffffffn;
  }

  private rotr(n: bigint, r: number): bigint {
    return ((n >> BigInt(r)) | (n << BigInt(64 - r))) & 0xffffffffffffffffn;
  }

  private static readonly K = new BigUint64Array([
    0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
    0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
    0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
    0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
    0xe49b69c19ef14ad2n, 0xefbe4786e7b779a4n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
    0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
    0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
    0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
    0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
    0x650a73548baf63den, 0x766a0abb3a81b2c2n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
    0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
    0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
    0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
    0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbdn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
    0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
    0x90befff438150499n, 0xa4506cebde82bde9n, 0xbef9a3f76b2c0e5dn, 0xc67178f2e372532bn,
    0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
    0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daefn, 0x1b710b35131c471bn,
    0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c59c37ad2an,
    0x4cc5d4becb3e42b6n, 0x597f299cfc657e2fn, 0x5fcb6fab3ad6fae3n, 0x6c44198c4a475817n
  ]);
}

/**
 * Compute SHA-512 hash
 */
export function sha512(data: Uint8Array): Uint8Array {
  const hasher = new CSHA512();
  hasher.Write(data);
  const hash = new Uint8Array(CSHA512.OUTPUT_SIZE);
  hasher.Finalize(hash);
  return hash;
}

/**
 * Compute SHA-512/256 (truncated SHA-512)
 */
export function sha512_256(data: Uint8Array): Uint8Array {
  const hasher = new CSHA512();
  hasher.Write(data);
  const hash = new Uint8Array(CSHA512.OUTPUT_SIZE);
  hasher.Finalize(hash);
  // Return first 32 bytes
  return hash.subarray(0, 32);
}
