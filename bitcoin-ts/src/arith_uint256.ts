// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Arbitrary precision unsigned integer for hash arithmetic
 * 
 * This is a TypeScript implementation of arith_uint256 for Bitcoin Core
 * used in proof-of-work calculations.
 */

import { uint256 } from './uint256';

/**
 * arith_uint256 - unsigned 256-bit integer
 */
export class arith_uint256 {
    private data: bigint;
    private static readonly MASK: bigint = (1n << 256n) - 1n;

    constructor(value: bigint | number = 0n) {
        this.data = BigInt(value) & arith_uint256.MASK;
    }

    /**
     * Convert from uint256 (Uint8Array)
     */
    static fromuint256(val: uint256): arith_uint256 {
        let result: bigint = 0n;
        for (let i = 0; i < 32; i++) {
            result = (result << 8n) | BigInt(val[i]);
        }
        return new arith_uint256(result);
    }

    /**
     * Get as uint256
     */
    getuint256(): uint256 {
        const result = new Uint8Array(32);
        let val: bigint = this.data;
        for (let i = 31; i >= 0; i--) {
            result[i] = Number(val & 0xffn);
            val >>= 8n;
        }
        return result;
    }

    /**
     * Get as BigInt (low 64 bits)
     */
    GetLow64(): bigint {
        return this.data & 0xffffffffffffffffn;
    }

    /**
     * Get value
     */
    getValue(): bigint {
        return this.data;
    }

    /**
     * Convert to hex string
     */
    GetHex(): string {
        return this.data.toString(16).padStart(64, '0');
    }

    /**
     * Set from hex string
     */
    SetHex(hex: string): void {
        this.data = BigInt('0x' + hex.replace(/^0x/, '')) & arith_uint256.MASK;
    }

    /**
     * Set from decimal string
     */
    SetDec(dec: string): void {
        this.data = BigInt(dec) & arith_uint256.MASK;
    }

    /**
     * Equality comparison
     */
    eq(other: arith_uint256): boolean {
        return this.data === other.data;
    }

    /**
     * Less than comparison
     */
    lt(other: arith_uint256): boolean {
        return this.data < other.data;
    }

    /**
     * Less than or equal comparison
     */
    lte(other: arith_uint256): boolean {
        return this.data <= other.data;
    }

    /**
     * Greater than comparison
     */
    gt(other: arith_uint256): boolean {
        return this.data > other.data;
    }

    /**
     * Greater than or equal comparison
     */
    gte(other: arith_uint256): boolean {
        return this.data >= other.data;
    }

    /**
     * Addition
     */
    add(other: arith_uint256): arith_uint256 {
        return new arith_uint256((this.data + other.data) & arith_uint256.MASK);
    }

    /**
     * Subtraction with wrap
     */
    sub(other: arith_uint256): arith_uint256 {
        return new arith_uint256((this.data - other.data) & arith_uint256.MASK);
    }

    /**
     * Multiplication with wrap
     */
    mul(other: arith_uint256): arith_uint256 {
        return new arith_uint256((this.data * other.data) & arith_uint256.MASK);
    }

    /**
     * Division (integer)
     */
    div(other: arith_uint256): arith_uint256 {
        if (other.data === 0n) return new arith_uint256(0n);
        return new arith_uint256(this.data / other.data);
    }

    /**
     * Modulo
     */
    mod(other: arith_uint256): arith_uint256 {
        if (other.data === 0n) return new arith_uint256(0n);
        return new arith_uint256(this.data % other.data);
    }

    /**
     * Bitwise AND
     */
    and(other: arith_uint256): arith_uint256 {
        return new arith_uint256(this.data & other.data);
    }

    /**
     * Bitwise OR
     */
    or(other: arith_uint256): arith_uint256 {
        return new arith_uint256(this.data | other.data);
    }

    /**
     * Bitwise XOR
     */
    xor(other: arith_uint256): arith_uint256 {
        return new arith_uint256(this.data ^ other.data);
    }

    /**
     * Bitwise NOT
     */
    not(): arith_uint256 {
        return new arith_uint256((~this.data) & arith_uint256.MASK);
    }

    /**
     * Left shift
     */
    shiftLeft(bits: number): arith_uint256 {
        return new arith_uint256((this.data << BigInt(bits)) & arith_uint256.MASK);
    }

    /**
     * Right shift
     */
    shiftRight(bits: number): arith_uint256 {
        return new arith_uint256(this.data >> BigInt(bits));
    }

    /**
     * Check if zero
     */
    IsZero(): boolean {
        return this.data === 0n;
    }

    /**
     * Check if one
     */
    IsOne(): boolean {
        return this.data === 1n;
    }

    /**
     * Get number of bits needed to represent
     */
    bits(): number {
        if (this.data === 0n) return 0;
        return 256 - this.data.toString(2).length;
    }

    /**
     * Get 32-bit word at position
     */
    Get32(bits: number): number {
        return Number((this.data >> BigInt(bits)) & 0xffffffffn);
    }

    /**
     * Set 32-bit word at position
     */
    Set32(bits: number, word: number): void {
        const mask: bigint = 0xffffffffn << BigInt(bits);
        this.data = (this.data & ~mask) | (BigInt(word) << BigInt(bits));
        this.data &= arith_uint256.MASK;
    }

    /**
     * Compare to another arith_uint256
     * Returns: -1 if less, 0 if equal, 1 if greater
     */
    compareTo(other: arith_uint256): number {
        if (this.data < other.data) return -1;
        if (this.data > other.data) return 1;
        return 0;
    }

    /**
     * Set from compact representation (used for nBits)
     */
    setCompact(bits: number): boolean {
        if (bits === 0) {
            this.data = 0n;
            return true;
        }
        
        const nSize = bits >> 24;
        let nWord = bits & 0x007fffff;
        
        if (nSize <= 3) {
            nWord >>= 8 * (3 - nSize);
            this.data = BigInt(nWord);
        } else {
            this.data = BigInt(nWord);
            this.data <<= 8n * BigInt(nSize - 3);
        }
        
        return true;
    }

    /**
     * Get compact representation (for nBits)
     */
    getCompact(): number {
        if (this.data === 0n) {
            return 0;
        }
        
        let nSize = Math.floor((this.bits() + 8) / 8);
        if (nSize > 3) {
            // Shift right to get significant bytes
            const shift = (nSize - 3) * 8;
            let shifted = this.data >> BigInt(shift);
            return (nSize << 24) | Number(shifted & 0xffffffffn);
        } else {
            return (nSize << 24) | Number(this.data & 0xffffffffn);
        }
    }

    /**
     * Multiply by small integer
     */
    multiply32(val: number): arith_uint256 {
        return this.mul(new arith_uint256(BigInt(val)));
    }

    /**
     * Divide by integer
     */
    divide(val: arith_uint256): arith_uint256 {
        return this.div(val);
    }

    /**
     * Divide by number
     */
    divideNumber(val: number): arith_uint256 {
        return this.div(new arith_uint256(BigInt(val)));
    }
}

/**
 * Convert uint256 to arith_uint256
 */
export function uintToArith256(val: uint256): arith_uint256 {
    return arith_uint256.fromuint256(val);
}

/**
 * Hash a value and return as arith_uint256
 */
export function HashToArith256(hash: uint256): arith_uint256 {
    return arith_uint256.fromuint256(hash);
}
