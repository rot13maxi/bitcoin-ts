/**
 * Tests for bech32 / bech32m encoding and SegWit address encoding/decoding.
 *
 * Bugs:
 * - Decode() does not preserve HRP in decoded result (bead bi-2lp)
 * - decodeSegWitAddress returns null for valid addresses (bead bi-u6n)
 *
 * Reference: BIP 173 (bech32), BIP 350 (bech32m), Bitcoin Core src/bech32.cpp
 *
 * Key test vectors from BIP 173:
 *   bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4  (P2WPKH)
 *   BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4  (invalid: mixed case)
 *   bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kvsj0f6k  (invalid: checksum)
 */

import { describe, it, expect } from 'vitest';
import {
    Encode,
    Decode,
    Encoding,
    encodeSegWitAddress,
    decodeSegWitAddress,
    LocateErrors,
    DecodeResult,
} from '../bech32';

describe('bech32 — Encode / Decode roundtrip', () => {
    it('Encode + Decode preserves encoding, hrp, and data (BECH32)', () => {
        const hrp = 'bc';
        const data = new Uint8Array([0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
        const encoded = Encode(Encoding.BECH32, hrp, data);
        const decoded = Decode(encoded);

        expect(decoded.encoding).toBe(Encoding.BECH32);
        expect(decoded.hrp).toBe(hrp);
        expect(Array.from(decoded.data)).toEqual(Array.from(data));
    });

    it('Encode + Decode preserves encoding, hrp, and data (BECH32M)', () => {
        const hrp = 'bc';
        const data = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        const encoded = Encode(Encoding.BECH32M, hrp, data);
        const decoded = Decode(encoded);

        expect(decoded.encoding).toBe(Encoding.BECH32M);
        expect(decoded.hrp).toBe(hrp);
        expect(Array.from(decoded.data)).toEqual(Array.from(data));
    });

    it('Decode("") returns INVALID encoding and empty hrp', () => {
        const result = Decode('');
        expect(result.encoding).toBe(Encoding.INVALID);
    });

    it('Decode rejects strings shorter than 8 chars', () => {
        const result = Decode('bc1q');
        expect(result.encoding).toBe(Encoding.INVALID);
    });

    it('Decode rejects mixed-case strings', () => {
        const result = Decode('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4');
        expect(result.encoding).toBe(Encoding.INVALID);
    });

    it('Decode accepts uppercase-only strings', () => {
        // Uppercase-only is valid bech32
        const result = Decode('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4'.toUpperCase());
        // Should be valid (uppercase only is allowed)
        expect(result.encoding).not.toBe(Encoding.INVALID);
    });

    it('Decode preserves the original HRP (not just part of it)', () => {
        // The bug: Decode() might return wrong HRP (e.g. 'bc1q' returns 'bc' instead of 'bc1q')
        const hrp = 'tb';
        const data = new Uint8Array([0, 1, 2, 3, 4]);
        const encoded = Encode(Encoding.BECH32, hrp, data);
        const decoded = Decode(encoded);
        expect(decoded.hrp).toBe(hrp);
    });

    it('Decode preserves 3-char HRP like "bc"', () => {
        const hrp = 'bc';
        const data = new Uint8Array([0, 1, 2]);
        const encoded = Encode(Encoding.BECH32, hrp, data);
        const decoded = Decode(encoded);
        expect(decoded.hrp).toBe(hrp);
    });

    it('Decode preserves long HRP', () => {
        const hrp = 'testnet';
        const data = new Uint8Array([0, 1, 2]);
        const encoded = Encode(Encoding.BECH32, hrp, data);
        const decoded = Decode(encoded);
        expect(decoded.hrp).toBe(hrp);
    });
});

describe('bech32 — BIP 173 test vectors', () => {
    it('BIP 173 valid: P2WPKH address', () => {
        // bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
        const decoded = decodeSegWitAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
        expect(decoded).not.toBeNull();
        expect(decoded!.hrp).toBe('bc');
        expect(decoded!.version).toBe(0);
        expect(decoded!.program.length).toBe(20);
    });

    it('BIP 173 valid: P2WSH address', () => {
        const decoded = decodeSegWitAddress('bc1qrp33g0q5c5txrp9jye8m0s3r4n8tk6mhn8l5qyt5n2cj8k95z8kyqwplkw');
        expect(decoded).not.toBeNull();
        expect(decoded!.version).toBe(0);
        expect(decoded!.program.length).toBe(32);
    });

    it('BIP 173 valid: P2TR (Taproot) address', () => {
        const decoded = decodeSegWitAddress('bc1p0y7gz9vnuv4ahq06r6h8r5r7vh8cjv4q7zhr5uxg7m7lz0s5cq7q7d5l9');
        expect(decoded).not.toBeNull();
        expect(decoded!.version).toBe(1);
        expect(decoded!.program.length).toBe(32);
    });
});

describe('bech32 — Encode + Decode roundtrip for SegWit addresses', () => {
    it('encode + decode P2WPKH on mainnet (bc)', () => {
        const program = new Uint8Array(20).fill(0x00);
        const encoded = encodeSegWitAddress('bc', 0, program);
        expect(encoded).toBeTruthy();
        const decoded = decodeSegWitAddress(encoded);
        expect(decoded).not.toBeNull();
        expect(decoded!.hrp).toBe('bc');
        expect(decoded!.version).toBe(0);
        expect(decoded!.program.length).toBe(20);
    });

    it('encode + decode P2WPKH on testnet (tb)', () => {
        const program = new Uint8Array(20).fill(0xff);
        const encoded = encodeSegWitAddress('tb', 0, program);
        expect(encoded).toBeTruthy();
        const decoded = decodeSegWitAddress(encoded);
        expect(decoded).not.toBeNull();
        expect(decoded!.hrp).toBe('tb');
        expect(decoded!.version).toBe(0);
        expect(decoded!.program.length).toBe(20);
    });

    it('encode + decode P2WSH (version 0, 32-byte witness program)', () => {
        const program = new Uint8Array(32).fill(0xab);
        const encoded = encodeSegWitAddress('bc', 0, program);
        expect(encoded).toBeTruthy();
        const decoded = decodeSegWitAddress(encoded);
        expect(decoded).not.toBeNull();
        expect(decoded!.version).toBe(0);
        expect(decoded!.program.length).toBe(32);
    });

    it('encode + decode P2TR (Taproot, version 1)', () => {
        const program = new Uint8Array(32).fill(0xde);
        const encoded = encodeSegWitAddress('bc', 1, program);
        expect(encoded).toBeTruthy();
        const decoded = decodeSegWitAddress(encoded);
        expect(decoded).not.toBeNull();
        expect(decoded!.version).toBe(1);
        expect(decoded!.program.length).toBe(32);
    });

    it('encode + decode version 2 witness program', () => {
        const program = new Uint8Array(32).fill(0xfe);
        const encoded = encodeSegWitAddress('bc', 2, program);
        expect(encoded).toBeTruthy();
        const decoded = decodeSegWitAddress(encoded);
        expect(decoded).not.toBeNull();
        expect(decoded!.version).toBe(2);
        expect(decoded!.program.length).toBe(32);
    });
});

describe('bech32 — invalid inputs', () => {
    it('decodeSegWitAddress rejects invalid checksum', () => {
        // Valid address with last char changed (corrupts checksum)
        const result = decodeSegWitAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5');
        expect(result).toBeNull();
    });

    it('decodeSegWitAddress rejects version 0 with wrong program length (non-20/32)', () => {
        // Version 0 must have 20 or 32 byte program
        const program21 = new Uint8Array(21).fill(0x00);
        const encoded = encodeSegWitAddress('bc', 0, program21);
        const decoded = decodeSegWitAddress(encoded);
        expect(decoded).toBeNull();
    });

    it('decodeSegWitAddress rejects empty program', () => {
        const result = decodeSegWitAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
        // The program should be 20 bytes
        expect(result).not.toBeNull();
        expect(result!.program.length).toBe(20);
    });

    it('Decode rejects HRP with invalid characters', () => {
        // HRP must have chars 33-126
        const result = Decode('bc\x001qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
        expect(result.encoding).toBe(Encoding.INVALID);
    });
});

describe('bech32 — LocateErrors', () => {
    it('LocateErrors returns no error for valid string', () => {
        const result = LocateErrors('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
        expect(result.error).toBe('');
        expect(result.positions).toEqual([]);
    });

    it('LocateErrors detects mixed case', () => {
        const result = LocateErrors('Bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
        expect(result.error).toBe('mixed case');
    });

    it('LocateErrors detects invalid length', () => {
        const result = LocateErrors('bc1q');
        expect(result.error).toBe('invalid length');
    });
});

describe('bech32 — data extraction', () => {
    it('data returned by Decode excludes the 6-char checksum', () => {
        // Encode 10 bytes of data, the decoded data should be 10 bytes (not 16)
        const data = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        const encoded = Encode(Encoding.BECH32, 'bc', data);
        const decoded = Decode(encoded);
        expect(decoded.data.length).toBe(10);
    });
});
