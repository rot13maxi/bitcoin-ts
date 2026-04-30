/**
 * Tests for Base58 and Base58Check encoding/decoding.
 *
 * Bug: DecodeBase58Check returns null for valid inputs when leading '1'
 * chars in the address consume part of the maxRetLen budget, causing
 * the checksum bytes to be cut off before verification.
 *
 * Reference: Bitcoin Core src/base58.h/cpp
 */

import { describe, it, expect } from 'vitest';
import {
    EncodeBase58,
    DecodeBase58,
    EncodeBase58Check,
    DecodeBase58Check,
    decodeBase58Check,
    encodeBase58Check,
} from '../base58';

describe('Base58 — Encode / Decode basic', () => {
    it('empty string encodes to empty', () => {
        expect(EncodeBase58(new Uint8Array(0))).toBe('');
    });

    it('DecodeBase58("") returns empty array', () => {
        const result = DecodeBase58('');
        expect(result).not.toBeNull();
        expect(result!.length).toBe(0);
    });

    it('Encode + Decode is lossless (roundtrip)', () => {
        const data = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
        const encoded = EncodeBase58(data);
        const decoded = DecodeBase58(encoded);
        expect(decoded).not.toBeNull();
        expect(Array.from(decoded!)).toEqual(Array.from(data));
    });

    it('Encode + Decode is lossless for all-zero input', () => {
        const data = new Uint8Array(10);
        const encoded = EncodeBase58(data);
        expect(encoded).toBe('1111111111'); // 10 leading ones
        const decoded = DecodeBase58(encoded);
        expect(decoded).not.toBeNull();
        expect(Array.from(decoded!)).toEqual(Array.from(data));
    });

    it('Encode + Decode for random-ish data', () => {
        const data = new Uint8Array([0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8]);
        const encoded = EncodeBase58(data);
        const decoded = DecodeBase58(encoded);
        expect(decoded).not.toBeNull();
        expect(Array.from(decoded!)).toEqual(Array.from(data));
    });

    it('DecodeBase58("111") returns [0,0,0]', () => {
        const result = DecodeBase58('111');
        expect(result).not.toBeNull();
        expect(result!.length).toBe(3);
        expect(Array.from(result!)).toEqual([0, 0, 0]);
    });

    it('DecodeBase58 rejects invalid characters', () => {
        expect(DecodeBase58('0' + 'I' + 'O'.repeat(10))).toBeNull();
        expect(DecodeBase58('l' + 'I'.repeat(10))).toBeNull();
    });
});

describe('Base58 — maxRetLen parameter', () => {
    it('DecodeBase58 with maxRetLen returns array of at most that length', () => {
        const result = DecodeBase58('111111111111', 3);
        expect(result).not.toBeNull();
        expect(result!.length).toBeLessThanOrEqual(3);
    });

    it('DecodeBase58 with maxRetLen=0 returns full array', () => {
        // maxRetLen=0 means no limit
        const result = DecodeBase58('111111111111', 0);
        expect(result).not.toBeNull();
        expect(result!.length).toBe(12);
    });
});

describe('Base58Check — P2PKH address roundtrip', () => {
    // Mainnet P2PKH version byte + 20-byte hash + 4-byte checksum
    const versionByte = 0x00;
    const pubkeyHash = new Uint8Array(20).fill(0x00);
    const addressData = new Uint8Array(21);
    addressData[0] = versionByte;
    addressData.set(pubkeyHash, 1);
    const address = EncodeBase58Check(addressData);

    it('EncodeBase58Check produces a non-empty string', () => {
        expect(address.length).toBeGreaterThan(0);
    });

    it('DecodeBase58Check without maxRetLen returns the full data (version + payload)', () => {
        const decoded = DecodeBase58Check(address);
        expect(decoded).not.toBeNull();
        expect(decoded!.length).toBe(21); // 1 version + 20 payload
    });

    it('DecodeBase58Check without maxRetLen returns version=0 for P2PKH', () => {
        const decoded = DecodeBase58Check(address);
        expect(decoded).not.toBeNull();
        expect(decoded![0]).toBe(0x00);
    });

    it('DecodeBase58Check without maxRetLen preserves all payload bytes', () => {
        const decoded = DecodeBase58Check(address);
        expect(decoded).not.toBeNull();
        // Check the payload (version=0, hash=20 zeros)
        expect(decoded![0]).toBe(0x00);
        for (let i = 1; i <= 20; i++) {
            expect(decoded![i]).toBe(0x00);
        }
    });

    it('DecodeBase58Check with maxRetLen=20 returns the correct payload', () => {
        // maxRetLen=20 means we expect 20 bytes of payload (after version)
        // The function should decode full data, then return data without checksum
        const decoded = DecodeBase58Check(address, 20);
        expect(decoded).not.toBeNull(); // ← Bug: returns null due to checksum truncation
        if (decoded) {
            expect(decoded.length).toBe(20);
        }
    });

    it('decodeBase58Check returns {version, payload}', () => {
        const result = decodeBase58Check(address);
        expect(result).not.toBeNull();
        expect(result!.version).toBe(0x00);
        expect(result!.payload.length).toBe(20);
    });
});

describe('Base58Check — testnet P2PKH address roundtrip', () => {
    const versionByte = 0x6f; // testnet P2PKH
    const hash = new Uint8Array(20).fill(0xff);
    const data = new Uint8Array(21);
    data[0] = versionByte;
    data.set(hash, 1);
    const address = EncodeBase58Check(data);

    it('DecodeBase58Check roundtrips testnet address', () => {
        const decoded = DecodeBase58Check(address);
        expect(decoded).not.toBeNull();
        expect(decoded![0]).toBe(0x6f);
    });

    it('DecodeBase58Check with maxRetLen=20 roundtrips testnet address', () => {
        const decoded = DecodeBase58Check(address, 20);
        expect(decoded).not.toBeNull();
    });
});

describe('Base58Check — encodeBase58Check / decodeBase58Check', () => {
    it('encodeBase58Check(0, payload) + decodeBase58Check roundtrips', () => {
        const payload = new Uint8Array(20).fill(0xab);
        const encoded = encodeBase58Check(0x00, payload);
        const decoded = decodeBase58Check(encoded);
        expect(decoded).not.toBeNull();
        expect(decoded!.version).toBe(0x00);
        expect(Array.from(decoded!.payload)).toEqual(Array.from(payload));
    });

    it('encodeBase58Check(5, payload) for P2SH address', () => {
        const payload = new Uint8Array(20).fill(0xcd);
        const encoded = encodeBase58Check(0x05, payload);
        const decoded = decodeBase58Check(encoded);
        expect(decoded).not.toBeNull();
        expect(decoded!.version).toBe(0x05);
    });

    it('encodeBase58Check(0x6f, payload) for testnet P2PKH', () => {
        const payload = new Uint8Array(20).fill(0xef);
        const encoded = encodeBase58Check(0x6f, payload);
        const decoded = decodeBase58Check(encoded);
        expect(decoded).not.toBeNull();
        expect(decoded!.version).toBe(0x6f);
    });
});

describe('Base58Check — invalid inputs', () => {
    it('DecodeBase58Check rejects corrupted checksum', () => {
        const data = new Uint8Array([0x00, ...new Uint8Array(20)]);
        const encoded = EncodeBase58Check(data);
        // Corrupt the last character
        const corrupted = encoded.slice(0, -1) + '2'; // '2' is a valid char, just wrong checksum
        const decoded = DecodeBase58Check(corrupted);
        expect(decoded).toBeNull();
    });

    it('DecodeBase58Check rejects empty string', () => {
        expect(DecodeBase58Check('')).toBeNull();
    });

    it('DecodeBase58Check rejects input shorter than 4 bytes decoded', () => {
        // A Base58Check string that decodes to < 4 bytes (can't have a checksum)
        const result = DecodeBase58Check('1111'); // 4 leading ones = 4 zero bytes
        expect(result).toBeNull();
    });
});

describe('Base58Check — real Bitcoin address test vectors', () => {
    // Known valid Bitcoin mainnet P2PKH address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
    // Version: 0x00, Hash: [the pubkey hash bytes]
    it('decodes known P2PKH address without maxRetLen', () => {
        const decoded = DecodeBase58Check('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2');
        expect(decoded).not.toBeNull();
        expect(decoded![0]).toBe(0x00); // P2PKH version
        expect(decoded!.length).toBe(25);
    });

    it('decodes known P2PKH address with maxRetLen=20', () => {
        // This is the bug case: P2PKH with leading ones
        const decoded = DecodeBase58Check('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', 20);
        expect(decoded).not.toBeNull(); // ← Bug: returns null
    });
});
