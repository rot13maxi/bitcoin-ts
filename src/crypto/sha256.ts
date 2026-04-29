// Copyright (c) 2014-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * SHA-256 hash implementation.
 * This is a TypeScript port of Bitcoin Core's crypto/sha256.h
 */

const ROUND_CONSTANTS: number[] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITIAL_STATE: number[] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

function ch(x: number, y: number, z: number): number {
    return (x & y) ^ (~x & z);
}

function maj(x: number, y: number, z: number): number {
    return (x & y) ^ (x & z) ^ (y & z);
}

function rotr(n: number, x: number): number {
    return (x >>> n) | (x << (32 - n));
}

function sigma0(x: number): number {
    return rotr(2, x) ^ rotr(13, x) ^ rotr(22, x);
}

function sigma1(x: number): number {
    return rotr(6, x) ^ rotr(11, x) ^ rotr(25, x);
}

function gamma0(x: number): number {
    return rotr(7, x) ^ rotr(18, x) ^ (x >>> 3);
}

function gamma1(x: number): number {
    return rotr(17, x) ^ rotr(19, x) ^ (x >>> 10);
}

function compress(state: number[], block: number[]): number[] {
    const w = new Array<number>(64);
    
    // Copy block to w with big-endian to little-endian conversion
    for (let i = 0; i < 16; i++) {
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    
    // Extend the first 16 words into the remaining 48 words
    for (let i = 16; i < 64; i++) {
        w[i] = (gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]) >>> 0;
    }
    
    let [a, b, c, d, e, f, g, h] = state;
    
    for (let i = 0; i < 64; i++) {
        const t1 = (h + sigma1(e) + ch(e, f, g) + ROUND_CONSTANTS[i] + w[i]) >>> 0;
        const t2 = (sigma0(a) + maj(a, b, c)) >>> 0;
        h = g;
        g = f;
        f = e;
        e = (d + t1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) >>> 0;
    }
    
    return [
        (state[0] + a) >>> 0,
        (state[1] + b) >>> 0,
        (state[2] + c) >>> 0,
        (state[3] + d) >>> 0,
        (state[4] + e) >>> 0,
        (state[5] + f) >>> 0,
        (state[6] + g) >>> 0,
        (state[7] + h) >>> 0,
    ];
}

/**
 * CSHA256 - SHA-256 hasher class
 * Compatible with Bitcoin Core's CSHA256 interface
 */
export class CSHA256 {
    static readonly OUTPUT_SIZE = 32;

    private s: number[];
    private buf: number[];
    private buflen: number;
    private totalBytes: number;

    constructor() {
        this.s = [...INITIAL_STATE];
        this.buf = new Array(64).fill(0);
        this.buflen = 0;
        this.totalBytes = 0;
    }

    Write(data: Uint8Array | readonly number[]): CSHA256 {
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
        // Finalize is destructive, so make a copy of state
        const s = [...this.s];
        const buf = [...this.buf];
        const buflen = this.buflen;
        
        // Pad
        buf[buflen] = 0x80;
        
        // Zero pad
        for (let i = buflen + 1; i < 56; i++) {
            buf[i] = 0;
        }
        
        // Append length in bits (big-endian)
        const bits = BigInt(this.totalBytes * 8);
        for (let i = 0; i < 8; i++) {
            buf[56 + i] = Number((bits >> BigInt(56 - i * 8)) & 0xffn);
        }
        
        s[0] = s[0]; // keep reference
        const result = compress(s, buf);
        
        // Write output (big-endian)
        for (let i = 0; i < 8; i++) {
            hash[i * 4] = (result[i] >> 24) & 0xff;
            hash[i * 4 + 1] = (result[i] >> 16) & 0xff;
            hash[i * 4 + 2] = (result[i] >> 8) & 0xff;
            hash[i * 4 + 3] = result[i] & 0xff;
        }
    }

    Reset(): CSHA256 {
        this.s = [...INITIAL_STATE];
        this.buf = new Array(64).fill(0);
        this.buflen = 0;
        this.totalBytes = 0;
        return this;
    }
}

/**
 * Compute SHA-256 hash of data
 */
export function sha256(data: Uint8Array | readonly number[] | string): Uint8Array {
    const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hash = new Uint8Array(CSHA256.OUTPUT_SIZE);
    
    const sha = new CSHA256();
    sha.Write(input as Uint8Array);
    sha.Finalize(hash);
    
    return hash;
}

/**
 * Compute double SHA-256 hash
 */
export function sha256d(data: Uint8Array | readonly number[]): Uint8Array {
    const hash1 = sha256(data);
    return sha256(hash1);
}

/**
 * Compute SHA-256 hash and return as hex string
 */
export function sha256Hex(data: Uint8Array | readonly number[] | string): string {
    const hash = sha256(data);
    return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
}
