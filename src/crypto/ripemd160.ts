// Copyright (c) 2014-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * RIPEMD-160 hash implementation.
 * This is a TypeScript port of Bitcoin Core's crypto/ripemd160.h
 * Based on the ISO C++ implementation by Kaushal M.
 */

const R = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    5, 13, 8, 4, 7, 9, 14, 2, 0, 6, 10, 1, 15, 12, 11, 3,
];

const RJ = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

const S = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

const SJ = [
    8, 6, 5, 15, 13, 12, 14, 15, 14, 15, 9, 8, 13, 6, 5, 12,
    9, 15, 5, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6, 9,
    9, 12, 5, 15, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5,
    15, 13, 11, 11, 5, 7, 12, 5, 8, 9, 5, 6, 6, 9, 12, 9,
    15, 2, 3, 12, 5, 14, 6, 8, 9, 5, 11, 6, 6, 14, 6, 9,
];

const K = 0x00000000;
const KJ = 0x50a28be6;

function f(x: number, y: number, z: number, j: number): number {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
}

function rotl32(x: number, n: number): number {
    return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function compress(h: number[], x: number[]): number[] {
    const X = new Array<number>(16);
    for (let i = 0; i < 16; i++) {
        X[i] = (x[i * 4] | (x[i * 4 + 1] << 8) | (x[i * 4 + 2] << 16) | (x[i * 4 + 3] << 24)) >>> 0;
    }

    let al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    let ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];

    for (let j = 0; j < 64; j++) {
        const r = R[j];
        const s = S[j];
        const tl = (K + f(bl, cl, dl, j) + X[r] + 0) >>> 0;
        al = (rotl32(tl, s) + el) >>> 0;
        bl = rotl32(bl, 10);
        const tr = (KJ + f(br, cr, dr, 63 - j) + X[RJ[j]] + 0) >>> 0;
        ar = (rotl32(tr, s) + er) >>> 0;
        br = rotl32(br, 10);

        const temp = el;
        el = dl;
        dl = rotl32(cl, 10);
        cl = bl;
        bl = al;
        al = temp;

        const temp2 = er;
        er = dr;
        dr = rotl32(cr, 10);
        cr = br;
        br = ar;
        ar = temp2;
    }

    h[0] = (h[1] + cl + dr) >>> 0;
    h[1] = (h[2] + dl + er) >>> 0;
    h[2] = (h[3] + el + ar) >>> 0;
    h[3] = (h[4] + al + br) >>> 0;
    h[4] = (h[0] + bl + cr) >>> 0;

    return h;
}

/**
 * CRIPEMD160 - RIPEMD-160 hasher class
 * Compatible with Bitcoin Core's CRIPEMD160 interface
 */
export class CRIPEMD160 {
    static readonly OUTPUT_SIZE = 20;

    private s: number[];
    private buf: number[];
    private buflen: number;
    private totalBytes: number;

    constructor() {
        this.s = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        this.buf = new Array(64).fill(0);
        this.buflen = 0;
        this.totalBytes = 0;
    }

    Write(data: Uint8Array | readonly number[]): CRIPEMD160 {
        let offset = 0;
        const len = data.length;
        
        // Process any buffered data first
        if (this.buflen > 0) {
            const needed = 64 - this.buflen;
            const take = Math.min(needed, len);
            for (let i = 0; i < take; i++) {
                this.buf[this.buflen + i] = data[i] as number;
            }
            this.buflen += take;
            offset += take;
            
            if (this.buflen === 64) {
                this.s = compress(this.s, this.buf);
                this.buflen = 0;
            }
        }
        
        // Process full blocks
        while (offset + 64 <= len) {
            for (let i = 0; i < 64; i++) {
                this.buf[i] = data[offset + i] as number;
            }
            this.s = compress(this.s, this.buf);
            offset += 64;
        }
        
        // Buffer remaining
        if (offset < len) {
            for (let i = offset; i < len; i++) {
                this.buf[this.buflen++] = data[i] as number;
            }
        }
        
        this.totalBytes += len;
        return this;
    }

    Finalize(hash: Uint8Array | number[]): void {
        // Pad
        this.buf[this.buflen] = 0x80;
        
        // Zero pad
        for (let i = this.buflen + 1; i < 56; i++) {
            this.buf[i] = 0;
        }
        
        // Append length in bits (little-endian)
        const bits = this.totalBytes * 8;
        for (let i = 0; i < 8; i++) {
            this.buf[56 + i] = (bits >> (i * 8)) & 0xff;
        }
        
        this.s = compress(this.s, this.buf);
        
        // Write output (little-endian)
        for (let i = 0; i < 5; i++) {
            hash[i * 4] = this.s[i] & 0xff;
            hash[i * 4 + 1] = (this.s[i] >> 8) & 0xff;
            hash[i * 4 + 2] = (this.s[i] >> 16) & 0xff;
            hash[i * 4 + 3] = (this.s[i] >> 24) & 0xff;
        }
    }

    Reset(): CRIPEMD160 {
        this.s = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        this.buf = new Array(64).fill(0);
        this.buflen = 0;
        this.totalBytes = 0;
        return this;
    }
}

/**
 * Compute RIPEMD-160 hash of data
 */
export function ripemd160(data: Uint8Array | readonly number[] | string): Uint8Array {
    const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hash = new Uint8Array(CRIPEMD160.OUTPUT_SIZE);
    
    const ripemd = new CRIPEMD160();
    ripemd.Write(input as Uint8Array);
    ripemd.Finalize(hash);
    
    return hash;
}

/**
 * Compute RIPEMD-160 hash and return as hex string
 */
export function ripemd160Hex(data: Uint8Array | readonly number[] | string): string {
    const hash = ripemd160(data);
    return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
}
