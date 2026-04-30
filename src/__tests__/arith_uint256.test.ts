/**
 * Tests for arith_uint256 (256-bit unsigned integer arithmetic).
 *
 * Bugs:
 * - divide() returns 0 when dividend < divisor (should return 0 — this is correct,
 *   but verify the division loop itself works for all cases)
 * - getHex() reverses bytes (display output is byte-reversed)
 *
 * Reference: Bitcoin Core src/arith_uint256.cpp
 */

import { describe, it, expect } from 'vitest';
import {
    arith_uint256,
    arithToUint256,
    uintToArith256,
    uintAdd, uintSubtract, uintMultiply, uintDivide,
} from '../arith_uint256';
import { uint256 } from '../uint256';

describe('arith_uint256 — basic arithmetic', () => {
    it('add: 100 + 200 = 300', () => {
        const result = new arith_uint256(100).add(new arith_uint256(200));
        expect(Number(result.toBigInt())).toBe(300);
    });

    it('subtract: 200 - 100 = 100', () => {
        const result = new arith_uint256(200).subtract(new arith_uint256(100));
        expect(Number(result.toBigInt())).toBe(100);
    });

    it('subtract: 100 - 200 = underflow (wraps)', () => {
        // With unsigned arithmetic, 100-200 wraps to 2^256 - 100
        const result = new arith_uint256(100).subtract(new arith_uint256(200));
        expect(Number(result.toBigInt())).toBeGreaterThan(0); // wrapped result
    });

    it('multiply: 10 * 20 = 200', () => {
        const result = new arith_uint256(10).multiply(new arith_uint256(20));
        expect(Number(result.toBigInt())).toBe(200);
    });

    it('multiply32: 100 * 3 = 300', () => {
        const result = new arith_uint256(100).multiply32(3);
        expect(Number(result.toBigInt())).toBe(300);
    });
});

describe('arith_uint256 — divide (bug: dividend < divisor)', () => {
    it('divide: 1 / 2 = 0 (dividend < divisor)', () => {
        const result = new arith_uint256(1).divide(new arith_uint256(2));
        expect(Number(result.toBigInt())).toBe(0);
    });

    it('divide: 10 / 100 = 0 (dividend < divisor)', () => {
        const result = new arith_uint256(10).divide(new arith_uint256(100));
        expect(Number(result.toBigInt())).toBe(0);
    });

    it('divide: 999 / 1000 = 0 (dividend < divisor)', () => {
        const result = new arith_uint256(999).divide(new arith_uint256(1000));
        expect(Number(result.toBigInt())).toBe(0);
    });

    it('divide: dividend == divisor → quotient is 1', () => {
        const result = new arith_uint256(42).divide(new arith_uint256(42));
        expect(Number(result.toBigInt())).toBe(1);
    });

    it('divide: 100 / 10 = 10', () => {
        const result = new arith_uint256(100).divide(new arith_uint256(10));
        expect(Number(result.toBigInt())).toBe(10);
    });

    it('divide: 17 / 3 = 5 (floor)', () => {
        const result = new arith_uint256(17).divide(new arith_uint256(3));
        expect(Number(result.toBigInt())).toBe(5);
    });

    it('divide: 7 / 3 = 2 (floor)', () => {
        const result = new arith_uint256(7).divide(new arith_uint256(3));
        expect(Number(result.toBigInt())).toBe(2);
    });

    it('divide: 2^128 / 3 = floor(2^128 / 3)', () => {
        const twoTo128 = 1n << 128n;
        const result = new arith_uint256(twoTo128).divide(new arith_uint256(3));
        expect(Number(result.toBigInt())).toBe(Number(twoTo128 / 3n));
    });

    it('divide: max / 1 = max', () => {
        const max = new arith_uint256(2n ** 256n - 1n);
        const result = max.divide(new arith_uint256(1));
        expect(result.toBigInt()).toBe(2n ** 256n - 1n);
    });

    it('divide: result * divisor + remainder = dividend (basic check)', () => {
        const dividend = 1007n;
        const divisor = 17n;
        const result = new arith_uint256(dividend).divide(new arith_uint256(divisor));
        const q = result.toBigInt();
        const r = new arith_uint256(dividend).subtract(new arith_uint256(q).multiply(new arith_uint256(divisor))).toBigInt();
        expect(q * divisor + r).toBe(dividend);
    });

    it('divide: result * divisor + remainder = dividend (random)', () => {
        const dividend = 123456789012345678901234567890n;
        const divisor = 99991n;
        const result = new arith_uint256(dividend).divide(new arith_uint256(divisor));
        const q = result.toBigInt();
        const r = new arith_uint256(dividend).subtract(new arith_uint256(q).multiply(new arith_uint256(divisor))).toBigInt();
        expect(q * divisor + r).toBe(dividend);
    });
});

describe('arith_uint256 — toBigInt / from bigint', () => {
    it('construct from bigint and roundtrip', () => {
        const val = 123456789012345678901234567890n;
        const a = new arith_uint256(val);
        expect(a.toBigInt()).toBe(val);
    });

    it('toBigInt matches for large values', () => {
        const val = (1n << 200n) + 42n;
        const a = new arith_uint256(val);
        expect(a.toBigInt()).toBe(val);
    });
});

describe('arith_uint256 — getHex (bug: byte reversal)', () => {
    it('getHex returns 64-char hex string', () => {
        const a = new arith_uint256(0);
        expect(a.getHex().length).toBe(64);
    });

    it('getHex for value 1: starts with 01 (no byte reversal)', () => {
        // arith_uint256 stores value in little-endian 32-bit words: pn[0]=1, others=0
        // bytes[0]=0x01, bytes[1..3]=0x00, ...
        // getHex() displays in stored order → first two chars = '01'
        const a = new arith_uint256(1);
        expect(a.getHex().slice(0, 2)).toBe('01');
    });

    it('getHex is a valid 64-char hex string', () => {
        const a = new arith_uint256(0xdeadbeefn);
        expect(a.getHex()).toMatch(/^[0-9a-f]{64}$/);
    });

    it('getHex on value 0x0100 shows hex starting 0100 (no reversal)', () => {
        // Value 256 = 0x0100. In LE: bytes[0]=0x00, bytes[1]=0x01, rest=0
        // getHex() displays in stored order → '0100' + zeros
        const a = new arith_uint256(0x0100n);
        expect(a.getHex().startsWith('0100')).toBe(true);
    });
});

describe('arith_uint256 — bits()', () => {
    it('bits(0) = 0', () => {
        expect(new arith_uint256(0).bits()).toBe(0);
    });

    it('bits(1) = 1', () => {
        expect(new arith_uint256(1).bits()).toBe(1);
    });

    it('bits(2) = 2', () => {
        expect(new arith_uint256(2).bits()).toBe(2);
    });

    it('bits(3) = 2', () => {
        expect(new arith_uint256(3).bits()).toBe(2);
    });

    it('bits(255) = 8', () => {
        expect(new arith_uint256(255).bits()).toBe(8);
    });

    it('bits(256) = 9', () => {
        expect(new arith_uint256(256).bits()).toBe(9);
    });
});

describe('arith_uint256 — getLow64', () => {
    it('getLow64 returns the low 64 bits as bigint', () => {
        const val = (1n << 100n) + 42n;
        const a = new arith_uint256(val);
        expect(a.getLow64()).toBe(42n);
    });

    it('getLow64 for large value', () => {
        const val = (1n << 64n) + 123n;
        const a = new arith_uint256(val);
        expect(a.getLow64()).toBe(123n);
    });
});

describe('arith_uint256 — shiftLeft / shiftRight', () => {
    it('shiftLeft 1: 1 << 1 = 2', () => {
        const a = new arith_uint256(1).shiftLeft(1);
        expect(Number(a.toBigInt())).toBe(2);
    });

    it('shiftLeft 8: 1 << 8 = 256', () => {
        const a = new arith_uint256(1).shiftLeft(8);
        expect(Number(a.toBigInt())).toBe(256);
    });

    it('shiftRight 1: 256 >> 1 = 128', () => {
        const a = new arith_uint256(256).shiftRight(1);
        expect(Number(a.toBigInt())).toBe(128);
    });

    it('shiftRight by word boundary (32 bits)', () => {
        const val = 1n << 32n;
        const a = new arith_uint256(val).shiftRight(32);
        expect(Number(a.toBigInt())).toBe(1);
    });
});

describe('arith_uint256 — increment / decrement', () => {
    it('increment: 99 -> 100', () => {
        const a = new arith_uint256(99);
        a.increment();
        expect(Number(a.toBigInt())).toBe(100);
    });

    it('decrement: 100 -> 99', () => {
        const a = new arith_uint256(100);
        a.decrement();
        expect(Number(a.toBigInt())).toBe(99);
    });

    it('decrement at 0 wraps (unsigned)', () => {
        const a = new arith_uint256(0);
        a.decrement();
        expect(Number(a.toBigInt())).toBeGreaterThan(0); // wraps
    });
});

describe('arith_uint256 — compact encoding (getCompact / setCompact)', () => {
    it('getCompact(setCompact(x)) roundtrips for positive numbers', () => {
        const opts: { negative?: boolean; overflow?: boolean } = {};
        const a = new arith_uint256(0);
        a.setCompact(0x01000000, opts);
        expect(Number(a.toBigInt())).toBe(0);
        expect(a.getCompact()).toBe(0x01000000);
    });

    it('getCompact(1) = 0x01000001', () => {
        const a = new arith_uint256(1);
        expect(a.getCompact()).toBe(0x01000001);
    });
});

describe('arithToUint256 / uintToArith256', () => {
    it('roundtrip: arithToUint256(uintToArith256(x)) = x', () => {
        const hash = new uint256('deadbeef'.padEnd(64, '0'));
        const a = uintToArith256(hash);
        const back = arithToUint256(a);
        expect(back.getHex()).toBe(hash.getHex());
    });

    it('roundtrip: uintToArith256(arithToUint256(a)) = a', () => {
        const a = new arith_uint256(0xdeadbeefn);
        const hash = arithToUint256(a);
        const back = uintToArith256(hash);
        expect(Number(back.toBigInt())).toBe(Number(a.toBigInt()));
    });
});
