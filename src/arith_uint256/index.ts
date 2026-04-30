// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * 256-bit unsigned big integer with full arithmetic operations.
 */

import { uint256, readLE32, writeLE32, bytesToHex } from '../uint256';

export class UintError extends Error {
    constructor(str: string) {
        super(str);
        this.name = 'UintError';
    }
}

/**
 * Base class for unsigned big integers using 32-bit digits.
 */
export class BaseUint {
    readonly WIDTH: number;
    pn: Uint32Array;

    constructor(width: number) {
        this.WIDTH = width;
        this.pn = new Uint32Array(width);
    }

    protected fromBigInt(value: bigint): void {
        for (let i = 0; i < this.WIDTH; i++) {
            this.pn[i] = Number(value >> BigInt(i * 32)) & 0xffffffff;
        }
    }

    toBigInt(): bigint {
        let result = 0n;
        for (let i = this.WIDTH - 1; i >= 0; i--) {
            result = (result << 32n) | BigInt(this.pn[i]);
        }
        return result;
    }

    bitwiseNot(): BaseUint {
        const result = this.clone();
        for (let i = 0; i < this.WIDTH; i++) {
            result.pn[i] = ~this.pn[i];
        }
        return result;
    }

    negate(): BaseUint {
        const result = this.clone();
        for (let i = 0; i < this.WIDTH; i++) {
            result.pn[i] = ~this.pn[i];
        }
        result.increment();
        return result;
    }

    increment(): this {
        let i = 0;
        while (i < this.WIDTH) {
            this.pn[i] = (this.pn[i] + 1) & 0xffffffff;
            if (this.pn[i] !== 0) break;
            i++;
        }
        return this;
    }

    decrement(): this {
        let i = 0;
        const max32 = 0xffffffff;
        while (i < this.WIDTH) {
            if (this.pn[i] === 0) {
                this.pn[i] = max32;
            } else {
                this.pn[i]--;
                break;
            }
            i++;
        }
        return this;
    }

    shiftLeft(shift: number): BaseUint {
        const result = new BaseUint(this.WIDTH);
        const k = Math.floor(shift / 32);
        const s = shift % 32;
        
        for (let i = 0; i < this.WIDTH; i++) {
            if (i + k < this.WIDTH) {
                result.pn[i + k] |= (this.pn[i] << s) & 0xffffffff;
            }
            if (i + k + 1 < this.WIDTH && s !== 0) {
                result.pn[i + k + 1] |= (this.pn[i] >>> (32 - s));
            }
        }
        return result;
    }

    shiftRight(shift: number): BaseUint {
        const result = new BaseUint(this.WIDTH);
        const k = Math.floor(shift / 32);
        const s = shift % 32;
        
        for (let i = 0; i < this.WIDTH; i++) {
            if (i - k >= 0) {
                result.pn[i - k] |= (this.pn[i] >>> s);
            }
            if (i - k - 1 >= 0 && s !== 0) {
                result.pn[i - k - 1] |= (this.pn[i] << (32 - s));
            }
        }
        return result;
    }

    add(other: BaseUint): BaseUint {
        const result = new BaseUint(this.WIDTH);
        let carry = 0n;
        for (let i = 0; i < this.WIDTH; i++) {
            const sum = BigInt(this.pn[i]) + BigInt(other.pn[i]) + carry;
            result.pn[i] = Number(sum & 0xffffffffn);
            carry = sum >> 32n;
        }
        return result;
    }

    subtract(other: BaseUint): BaseUint {
        return this.add(other.negate());
    }

    multiply(other: BaseUint): BaseUint {
        const result = new BaseUint(this.WIDTH);
        for (let j = 0; j < this.WIDTH; j++) {
            let carry = 0n;
            for (let i = 0; i + j < this.WIDTH; i++) {
                const sum = BigInt(result.pn[i + j]) + 
                           BigInt(this.pn[j]) * BigInt(other.pn[i]) + 
                           carry;
                result.pn[i + j] = Number(sum & 0xffffffffn);
                carry = sum >> 32n;
            }
        }
        return result;
    }

    multiply32(other: number): BaseUint {
        const result = new BaseUint(this.WIDTH);
        let carry = 0n;
        for (let i = 0; i < this.WIDTH; i++) {
            const sum = BigInt(this.pn[i]) * BigInt(other & 0xffffffff) + carry;
            result.pn[i] = Number(sum & 0xffffffffn);
            carry = sum >> 32n;
        }
        return result;
    }

    divide(other: BaseUint): BaseUint {
        const result = new BaseUint(this.WIDTH);
        const div = other.clone();
        const num = this.clone();
        
        if (num.bits() < div.bits()) {
            return result;
        }
        
        let shift = num.bits() - div.bits();
        if (shift > 0) {
            const idx = Math.floor(shift / 32);
            const bit = shift % 32;
            if (idx < div.WIDTH) {
                div.pn[idx] |= (1 << bit);
            }
        }
        
        for (let s = shift; s >= 0; s--) {
            if (num.compareTo(div) >= 0) {
                const idx = Math.floor(s / 32);
                const bit = s % 32;
                if (idx < num.WIDTH) {
                    num.pn[idx] |= (1 << bit);
                }
                const divResult = num.subtract(div);
                num.pn.set(divResult.pn);
            }
            if (s > 0) {
                const prevIdx = Math.floor((s - 1) / 32);
                const prevBit = (s - 1) % 32;
                if (prevIdx >= 0 && prevIdx < div.WIDTH) {
                    div.pn[prevIdx] &= ~(1 << prevBit);
                }
            } else if (div.WIDTH > 0) {
                div.pn[0] &= ~1;
            }
        }
        
        result.pn.set(num.pn);
        return result;
    }

    compareTo(other: BaseUint): number {
        for (let i = this.WIDTH - 1; i >= 0; i--) {
            if (this.pn[i] < other.pn[i]) return -1;
            if (this.pn[i] > other.pn[i]) return 1;
        }
        return 0;
    }

    equalTo64(value: number): boolean {
        const high = Math.floor(value / 0x100000000);
        const low = value & 0xffffffff;
        
        for (let i = this.WIDTH - 1; i >= 2; i--) {
            if (this.pn[i] !== 0) return false;
        }
        if (this.pn[1] !== high) return false;
        if (this.pn[0] !== low) return false;
        return true;
    }

    getDouble(): number {
        let result = 0.0;
        let factor = 1.0;
        for (let i = 0; i < this.WIDTH; i++) {
            result += factor * this.pn[i];
            factor *= 4294967296.0;
        }
        return result;
    }

    getHex(): string {
        // Build byte array from 32-bit little-endian words and display without reversal.
        // arith_uint256 stores values in LE (pn[0]=lowest-order 32 bits), and we display
        // in the same order — matching uint256's non-reversing getHex() convention.
        const blob = new Uint8Array(this.WIDTH * 4);
        for (let i = 0; i < this.WIDTH; i++) {
            writeLE32(blob, i * 4, this.pn[i]);
        }
        return bytesToHex(blob);
    }

    toString(): string {
        return this.getHex();
    }

    bits(): number {
        for (let pos = this.WIDTH - 1; pos >= 0; pos--) {
            if (this.pn[pos]) {
                for (let nbits = 31; nbits > 0; nbits--) {
                    if (this.pn[pos] & (1 << nbits)) {
                        return 32 * pos + nbits + 1;
                    }
                }
                return 32 * pos + 1;
            }
        }
        return 0;
    }

    getLow64(): bigint {
        return BigInt(this.pn[0]) | (BigInt(this.pn[1]) << 32n);
    }

    size(): number {
        return this.WIDTH * 4;
    }

    clone(): BaseUint {
        const result = new BaseUint(this.WIDTH);
        result.pn.set(this.pn);
        return result;
    }

    bitwiseXorAssign(other: BaseUint): this {
        for (let i = 0; i < this.WIDTH; i++) {
            this.pn[i] ^= other.pn[i];
        }
        return this;
    }

    bitwiseAndAssign(other: BaseUint): this {
        for (let i = 0; i < this.WIDTH; i++) {
            this.pn[i] &= other.pn[i];
        }
        return this;
    }

    bitwiseOrAssign(other: BaseUint): this {
        for (let i = 0; i < this.WIDTH; i++) {
            this.pn[i] |= other.pn[i];
        }
        return this;
    }
}

/**
 * 256-bit unsigned big integer
 */
export class arith_uint256 extends BaseUint {
    constructor(value?: bigint | number | BaseUint) {
        super(8);
        
        if (value !== undefined) {
            if (typeof value === 'bigint') {
                this.fromBigInt(value);
            } else if (typeof value === 'number') {
                this.pn[0] = value & 0xffffffff;
                this.pn[1] = Math.floor(value / 0x100000000);
            } else if (value instanceof BaseUint) {
                this.pn.set(value.pn);
            }
        }
    }

    clone(): arith_uint256 {
        const result = new arith_uint256();
        result.pn.set(this.pn);
        return result;
    }

    setCompact(nCompact: number, options?: { negative?: boolean; overflow?: boolean }): arith_uint256 {
        const nSize = nCompact >> 24;
        let nWord = nCompact & 0x007fffff;
        
        if (nSize <= 3) {
            nWord >>= 8 * (3 - nSize);
            this.pn[0] = nWord & 0xffffffff;
            this.pn[1] = 0;
        } else {
            this.pn[0] = nWord & 0xffffffff;
            for (let i = 1; i < 8; i++) {
                this.pn[i] = 0;
            }
            const shifted = this.shiftLeft(8 * (nSize - 3));
            for (let i = 0; i < 8; i++) {
                this.pn[i] = shifted.pn[i];
            }
        }
        
        if (options) {
            options.negative = nWord !== 0 && (nCompact & 0x00800000) !== 0;
            options.overflow = nWord !== 0 && (
                (nSize > 34) ||
                (nWord > 0xff && nSize > 33) ||
                (nWord > 0xffff && nSize > 32)
            );
        }
        
        return this;
    }

    getCompact(negative: boolean = false): number {
        let nSize = Math.ceil(this.bits() / 8);
        let nCompact: number;
        
        if (nSize <= 3) {
            nCompact = Number(this.getLow64()) << (8 * (3 - nSize));
        } else {
            const shifted = this.shiftRight(8 * (nSize - 3));
            nCompact = Number(shifted.getLow64());
        }
        
        if (nCompact & 0x00800000) {
            nCompact >>= 8;
            nSize++;
        }
        
        nCompact |= (nSize << 24);
        nCompact |= (negative && (nCompact & 0x007fffff) ? 0x00800000 : 0);
        
        return nCompact;
    }
}

export function arithToUint256(a: arith_uint256): uint256 {
    const data = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
        writeLE32(data, i * 4, a.pn[i]);
    }
    return new uint256(data);
}

export function uintToArith256(a: uint256): arith_uint256 {
    const result = new arith_uint256();
    for (let i = 0; i < 8; i++) {
        result.pn[i] = readLE32(a.data(), i * 4);
    }
    return result;
}

export function uintAdd(a: arith_uint256, b: arith_uint256): arith_uint256 {
    return a.add(b) as arith_uint256;
}

export function uintSubtract(a: arith_uint256, b: arith_uint256): arith_uint256 {
    return a.subtract(b) as arith_uint256;
}

export function uintMultiply(a: arith_uint256, b: arith_uint256): arith_uint256 {
    return a.multiply(b) as arith_uint256;
}

export function uintDivide(a: arith_uint256, b: arith_uint256): arith_uint256 {
    return a.divide(b) as arith_uint256;
}

export function uintBitwiseOr(a: arith_uint256, b: arith_uint256): arith_uint256 {
    const result = a.clone();
    result.bitwiseOrAssign(b);
    return result;
}

export function uintBitwiseAnd(a: arith_uint256, b: arith_uint256): arith_uint256 {
    const result = a.clone();
    result.bitwiseAndAssign(b);
    return result;
}

export function uintBitwiseXor(a: arith_uint256, b: arith_uint256): arith_uint256 {
    const result = a.clone();
    result.bitwiseXorAssign(b);
    return result;
}

export function uintShiftRight(a: arith_uint256, shift: number): arith_uint256 {
    return a.shiftRight(shift) as arith_uint256;
}

export function uintShiftLeft(a: arith_uint256, shift: number): arith_uint256 {
    return a.shiftLeft(shift) as arith_uint256;
}

export function uintEquals(a: arith_uint256, b: arith_uint256): boolean {
    return a.compareTo(b) === 0;
}

export function uintLessThan(a: arith_uint256, b: arith_uint256): boolean {
    return a.compareTo(b) < 0;
}

export function uintLessThanOrEqual(a: arith_uint256, b: arith_uint256): boolean {
    return a.compareTo(b) <= 0;
}

export function uintGreaterThan(a: arith_uint256, b: arith_uint256): boolean {
    return a.compareTo(b) > 0;
}

export function uintGreaterThanOrEqual(a: arith_uint256, b: arith_uint256): boolean {
    return a.compareTo(b) >= 0;
}
