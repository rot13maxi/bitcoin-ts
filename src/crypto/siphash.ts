// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * SipHash-2-4 implementation for Bitcoin Core.
 * This is a TypeScript port of Bitcoin Core's crypto/siphash.h
 * 
 * SipHash provides a keyed hash useful for hash tables and other data structures
 * that need protection against hash flooding attacks.
 */

import { uint256 } from '../uint256';

/**
 * Internal constants for SipHash-2-4
 */
const ROTL = (x: bigint, b: bigint | number): bigint => (x << BigInt(b)) | (x >> (64n - BigInt(b)));

const U64LE = (bs: Uint8Array, off: number): bigint => {
    return BigInt(bs[off]) |
        (BigInt(bs[off + 1]) << 8n) |
        (BigInt(bs[off + 2]) << 16n) |
        (BigInt(bs[off + 3]) << 24n) |
        (BigInt(bs[off + 4]) << 32n) |
        (BigInt(bs[off + 5]) << 40n) |
        (BigInt(bs[off + 6]) << 48n) |
        (BigInt(bs[off + 7]) << 56n);
};

/**
 * SipHash-2-4 keyed hash function.
 * Produces a 64-bit hash value from a message.
 */
export class CSipHasher {
    /** The state: v0, v1, v2, v3 */
    private v0: bigint = 0n;
    private v1: bigint = 0n;
    private v2: bigint = 0n;
    private v3: bigint = 0n;
    
    /** Compression count and tail bytes */
    private count: number = 0;
    private tmp: bigint = 0n;
    private nbytes: number = 0;

    constructor(k0: bigint, k1: bigint) {
        // Set up initial state
        this.v0 = 0x736f6d6570736575n ^ k0;
        this.v1 = 0x646f72616e646f6dn ^ k1;
        this.v2 = 0x5f726f6b6570736575n ^ k0;
        this.v3 = 0x6a7f6f6b6570736575n ^ k1;
    }

    private sipRound(): void {
        this.v0 += this.v1;
        this.v1 = ROTL(this.v1, 13n);
        this.v1 ^= this.v0;
        this.v0 = ROTL(this.v0, 32n);
        this.v2 += this.v3;
        this.v3 = ROTL(this.v3, 16n);
        this.v3 ^= this.v2;
        this.v0 += this.v3;
        this.v3 = ROTL(this.v3, 24n);
        this.v3 ^= this.v0;
        this.v2 += this.v1;
        this.v1 = ROTL(this.v1, 17n);
        this.v1 ^= this.v2;
        this.v2 = ROTL(this.v2, 32n);
    }

    /**
     * Update the hash with 8 bytes (a uint64_t)
     */
    WriteU64LE(value: bigint): CSipHasher {
        this.tmp |= value << BigInt(8 * this.nbytes);
        this.nbytes += 8;
        if (this.nbytes === 8) {
            this.v3 ^= this.tmp;
            this.sipRound();
            this.sipRound();
            this.v0 ^= this.tmp;
            this.tmp = 0n;
            this.nbytes = 0;
            this.count += 2;
        }
        return this;
    }

    /**
     * Update the hash with a uint64_t value
     */
    Write(v: bigint): CSipHasher {
        return this.WriteU64LE(v);
    }

    /**
     * Update the hash with arbitrary bytes
     */
    WriteData(data: readonly number[] | Uint8Array): CSipHasher {
        for (let i = 0; i < data.length; i++) {
            this.tmp |= BigInt(data[i]) << BigInt(8 * this.nbytes);
            this.nbytes++;
            if (this.nbytes === 8) {
                this.v3 ^= this.tmp;
                this.sipRound();
                this.sipRound();
                this.v0 ^= this.tmp;
                this.tmp = 0n;
                this.nbytes = 0;
                this.count += 2;
            }
        }
        return this;
    }

    /**
     * Finalize the hash and return the 64-bit result
     */
    Finalize(): bigint {
        this.tmp |= BigInt(this.nbytes) << 56n;
        this.v3 ^= this.tmp;
        this.sipRound();
        this.sipRound();
        this.v0 ^= this.tmp;
        this.v2 ^= 0xffn;
        this.sipRound();
        this.sipRound();
        this.sipRound();
        this.sipRound();
        return this.v0 ^ this.v1 ^ this.v2 ^ this.v3;
    }

    /**
     * Finalize and return as a uint64_t number
     */
    FinalizeAsNumber(): number {
        return Number(this.Finalize() & BigInt(Number.MAX_SAFE_INTEGER));
    }

    /**
     * Finalize and return as a BigInt (for use in other hash computations).
     */
    FinalizeAsBigint(): bigint {
        return this.Finalize();
    }
}

/**
 * Compute SipHash-2-4 with the given keys and data.
 * Returns a 64-bit bigint hash.
 */
export function SipHash_2_4(
    k0: bigint,
    k1: bigint,
    data: readonly number[] | Uint8Array
): bigint {
    return new CSipHasher(k0, k1).WriteData(data).Finalize();
}

/**
 * Compute SipHash-2-4 with the given keys and data, returning a number.
 */
export function SipHash_2_4_AsNumber(
    k0: bigint,
    k1: bigint,
    data: readonly number[] | Uint8Array
): number {
    return Number(SipHash_2_4(k0, k1, data) & BigInt(Number.MAX_SAFE_INTEGER));
}
