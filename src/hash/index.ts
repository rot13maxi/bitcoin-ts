// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Hash functions for Bitcoin.
 * This is a TypeScript port of Bitcoin Core's hash.h
 */

import { CSHA256, sha256, CRIPEMD160, ripemd160 } from '../crypto';
import { uint256, uint160 } from '../uint256';
import { Stream, Uint8ArrayStream } from '../serialize';

/**
 * CHash256 - double SHA-256 hasher
 */
export class CHash256 {
    static readonly OUTPUT_SIZE = CSHA256.OUTPUT_SIZE;

    private sha: CSHA256;

    constructor() {
        this.sha = new CSHA256();
    }

    Write(data: Uint8Array | readonly number[]): CHash256 {
        this.sha.Write(data);
        return this;
    }

    Finalize(output: Uint8Array | number[]): void {
        if (output.length !== CHash256.OUTPUT_SIZE) {
            throw new Error('Invalid output size');
        }
        const buf = new Uint8Array(CSHA256.OUTPUT_SIZE);
        this.sha.Finalize(buf);
        this.sha.Reset().Write(buf).Finalize(output);
    }

    Reset(): CHash256 {
        this.sha.Reset();
        return this;
    }
}

/**
 * CHash160 - SHA-256 + RIPEMD-160 hasher
 */
export class CHash160 {
    static readonly OUTPUT_SIZE = CRIPEMD160.OUTPUT_SIZE;

    private sha: CSHA256;

    constructor() {
        this.sha = new CSHA256();
    }

    Write(data: Uint8Array | readonly number[]): CHash160 {
        this.sha.Write(data);
        return this;
    }

    Finalize(output: Uint8Array | number[]): void {
        if (output.length !== CHash160.OUTPUT_SIZE) {
            throw new Error('Invalid output size');
        }
        const buf = new Uint8Array(CSHA256.OUTPUT_SIZE);
        this.sha.Finalize(buf);
        const ripemd = new CRIPEMD160();
        ripemd.Write(buf).Finalize(output);
    }

    Reset(): CHash160 {
        this.sha.Reset();
        return this;
    }
}

/**
 * Compute 256-bit hash of an object using double SHA-256
 */
export function Hash(data: Uint8Array | readonly number[] | string): uint256 {
    const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hasher = new CHash256();
    const hash = new Uint8Array(32);
    hasher.Write(input).Finalize(hash);
    return new uint256(hash);
}

/**
 * Compute 160-bit hash (SHA-256 + RIPEMD-160)
 */
export function Hash160(data: Uint8Array | readonly number[] | string): uint160 {
    const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hasher = new CHash160();
    const hash = new Uint8Array(20);
    hasher.Write(input).Finalize(hash);
    return new uint160(hash);
}

/**
 * Compute 160-bit RIPEMD-160 hash
 */
export function RIPEMD160(data: Uint8Array | readonly number[] | string): uint160 {
    const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hash = ripemd160(input);
    return new uint160(hash);
}

/**
 * HashWriter - a writer stream that computes a 256-bit hash
 * Used for tagged hashes and serialization-based hashing
 */
export class HashWriter {
    private ctx: CSHA256;

    constructor() {
        this.ctx = new CSHA256();
    }

    write(src: Uint8Array | readonly number[]): void {
        this.ctx.Write(src);
    }

    /**
     * Compute the double-SHA256 hash of all data written
     */
    getHash(): uint256 {
        const intermediate = new Uint8Array(CSHA256.OUTPUT_SIZE);
        this.ctx.Finalize(intermediate);
        this.ctx.Reset().Write(intermediate).Finalize(intermediate);
        return new uint256(intermediate);
    }

    /**
     * Compute the SHA256 hash of all data written
     */
    getSHA256(): uint256 {
        const hash = new Uint8Array(CSHA256.OUTPUT_SIZE);
        this.ctx.Finalize(hash);
        return new uint256(hash);
    }

    /**
     * Returns the first 64 bits from the resulting hash
     */
    getCheapHash(): bigint {
        const result = this.getHash();
        let hash = 0n;
        for (let i = 0; i < 8; i++) {
            hash |= BigInt(result.data()[i]) << BigInt(i * 8);
        }
        return hash;
    }
}

/**
 * HashVerifier - reads from a stream while hashing the read data
 */
export class HashVerifier<Source extends { read(dst: Uint8Array): void }> {
    private source: Source;
    private hashWriter: HashWriter;

    constructor(source: Source) {
        this.source = source;
        this.hashWriter = new HashWriter();
    }

    write(_src: Uint8Array | readonly number[]): void {
        throw new Error('Use read() instead');
    }

    read(dst: Uint8Array): void {
        this.source.read(dst);
        this.hashWriter.write(dst);
    }

    ignore(numBytes: number): void {
        const data = new Uint8Array(Math.min(numBytes, 1024));
        while (numBytes > 0) {
            const now = Math.min(numBytes, 1024);
            this.read(data.slice(0, now));
            numBytes -= now;
        }
    }

    getHash(): uint256 {
        return this.hashWriter.getHash();
    }

    getSHA256(): uint256 {
        return this.hashWriter.getSHA256();
    }

    getCheapHash(): bigint {
        return this.hashWriter.getCheapHash();
    }
}

/**
 * Single-SHA256 a 32-byte input (represented as uint256)
 */
export function SHA256Uint256(input: uint256): uint256 {
    return new uint256(sha256(input.data()));
}

/**
 * MurmurHash3 - used for Bloom filter hash
 */
export function MurmurHash3(nHashSeed: number, vDataToHash: Uint8Array | readonly number[]): number {
    // The following is MurmurHash3 x86_32
    const c1 = 0xcc9e2d51;
    const c2 = 0x1b873593;

    let h1 = nHashSeed;
    const len = vDataToHash.length;
    const roundedLen = Math.floor(len / 4) * 4;
    
    // Body
    for (let i = 0; i < roundedLen; i += 4) {
        let k1 = 
            (vDataToHash[i] & 0xff) |
            ((vDataToHash[i + 1] & 0xff) << 8) |
            ((vDataToHash[i + 2] & 0xff) << 16) |
            ((vDataToHash[i + 3] & 0xff) << 24);
        
        k1 = Math.imul(k1, c1);
        k1 = (k1 << 15) | (k1 >>> 17);
        k1 = Math.imul(k1, c2);
        
        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >>> 19);
        h1 = Math.imul(h1, 5) + 0xe6546b64;
    }

    // Tail
    let k1 = 0;
    switch (len & 3) {
        case 3: k1 ^= (vDataToHash[roundedLen + 2] & 0xff) << 16;
        case 2: k1 ^= (vDataToHash[roundedLen + 1] & 0xff) << 8;
        case 1: k1 ^= (vDataToHash[roundedLen] & 0xff);
            k1 = Math.imul(k1, c1);
            k1 = (k1 << 15) | (k1 >>> 17);
            k1 = Math.imul(k1, c2);
            h1 ^= k1;
    }

    // Finalization
    h1 ^= len;
    h1 ^= h1 >>> 16;
    h1 = Math.imul(h1, 0x85ebca6b);
    h1 ^= h1 >>> 13;
    h1 = Math.imul(h1, 0xc2b2ae35);
    h1 ^= h1 >>> 16;

    return h1 >>> 0;
}

/**
 * BIP32Hash - HMAC-SHA256 based key derivation
 */
export function BIP32Hash(
    chainCode: Uint8Array | readonly number[],
    nChild: number,
    header: number,
    data: Uint8Array | readonly number[]
): Uint8Array {
    // Use HMAC-SHA256
    const key = chainCode;
    const msg = new Uint8Array(1 + data.length + 4);
    msg[0] = header;
    msg.set(data, 1);
    const childBytes = [
        (nChild >> 24) & 0xff,
        (nChild >> 16) & 0xff,
        (nChild >> 8) & 0xff,
        nChild & 0xff,
    ];
    msg.set(childBytes, 1 + data.length);

    // Simple HMAC-SHA256 implementation
    const blockSize = 64;
    const ipad = new Uint8Array(blockSize);
    const opad = new Uint8Array(blockSize);
    
    for (let i = 0; i < blockSize; i++) {
        ipad[i] = 0x36;
        opad[i] = 0x5c;
    }
    
    for (let i = 0; i < key.length; i++) {
        ipad[i] ^= key[i] as number;
        opad[i] ^= key[i] as number;
    }
    
    const inner = new Uint8Array(blockSize + msg.length);
    inner.set(ipad);
    inner.set(msg, blockSize);
    const innerHash = sha256(inner);
    
    const outer = new Uint8Array(blockSize + 32);
    outer.set(opad);
    outer.set(innerHash, blockSize);
    const hmac = sha256(outer);
    
    return hmac;
}

/**
 * TaggedHash - computes a BIP 340 tagged hash
 */
export function TaggedHash(tag: string): HashWriter {
    const tagBytes = new TextEncoder().encode(tag);
    const tagHash = sha256(tagBytes);
    const twoTagHash = sha256(new Uint8Array([...tagHash, ...tagHash]));
    
    const writer = new HashWriter();
    writer.write(twoTagHash);
    return writer;
}
