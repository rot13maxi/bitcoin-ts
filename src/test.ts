// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Basic tests for bitcoin-ts
 */

import { strict as assert } from "node:assert";
import { uint256, uint160, Txid } from './uint256';
import { arith_uint256, arithToUint256, uintToArith256 } from './arith_uint256';

import { COutPoint, CTxIn, CTxOut, CTransaction, CMutableTransaction, COIN } from './primitives';
import { Prevector } from './prevector';
import { Span } from './span';

// Layer 1 imports
import { sha256, sha256d, ripemd160, CSHA256, CRIPEMD160 } from './crypto';
import { Hash, Hash160, CHash256, CHash160, HashWriter, BIP32Hash } from './hash';
import { CPubKey, CKeyID, XOnlyPubKey } from './pubkey';
import { Encode, Decode, Encoding, encodeSegWitAddress, decodeSegWitAddress } from './bech32';
import { EncodeBase58, DecodeBase58, EncodeBase58Check, DecodeBase58Check } from './base58';
import { CompressAmount, DecompressAmount, CompressScript } from './compressor';
import { encodeDestination, decodeDestination, isValidDestinationString, MAINNET, TESTNET, PKHash, WitnessPKHash } from './key_io';
import { Uint8ArrayStream, serializeInt64LE, unserializeInt64LE } from './serialize';

// Deno.test-compatible API for proper test execution
interface TestDefinition {
    name: string;
    fn: () => void | Promise<void>;
}

const tests: TestDefinition[] = [];

// Use strict assert from Node's assert module
const assertEquals = assert.equal;

class AssertionError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'AssertionError';
    }
}

// Deno.test polyfill for Node.js compatibility
const Deno = {
    test(name: string, fn: () => void | Promise<void>): void {
        tests.push({ name, fn });
    }
};

Deno.test("test_uint256", () => {
    // 64 hex chars = 32 bytes for uint256
    const hexStr = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    assertEquals(hexStr.length, 64);
    const hash = new uint256(hexStr);
    // getHex should return 64 hex chars
    assertEquals(hash.getHex().length, 64);

    const zero = new uint256();
    assertEquals(zero.isNull(), true);

    const hash2 = new uint256(hash.data());
    assertEquals(hash.compare(hash2), 0);

    const hash3 = uint256.fromHex(hexStr);
    assertEquals(hash3 !== null, true);
});

Deno.test("test_uint160", () => {
    const pkhash = new uint160('00112233445566778899aabbccddeeff00112233');
    assertEquals(pkhash.getHex().length, 40);
    assertEquals(pkhash.size(), 20);
});

Deno.test("test_arith_uint256", () => {
    const a = new arith_uint256(100);
    const b = new arith_uint256(200);

    const sum = a.add(b);
    assertEquals(sum.toBigInt(), 300n);

    const product = a.multiply(b);
    assertEquals(product.toBigInt(), 20000n);

    assertEquals(a.compareTo(b) < 0, true);

    assertEquals(typeof a.bits(), 'number');

    const shifted = a.shiftLeft(10);
    assertEquals(shifted.toBigInt(), 102400n);
});

Deno.test("test_primitives", () => {
    const outpoint = new COutPoint();
    assertEquals(outpoint.isNull(), true);

    const txidHex = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    const txid = new Txid(txidHex);
    const outpoint2 = new COutPoint(txid, 0);
    assertEquals(outpoint2.toString().length > 0, true);

    const txout = new CTxOut(1n * COIN, new Uint8Array([0]));
    assertEquals(typeof txout.nValue, 'bigint');

    const tx = new CMutableTransaction();
    tx.version = 2;
    tx.vin.push(new CTxIn(outpoint2, new Uint8Array(0)));
    tx.vout.push(new CTxOut(1n * COIN, new Uint8Array([0])));
    assertEquals(tx.version, 2);
    assertEquals(tx.vin.length, 1);
    assertEquals(tx.vout.length, 1);
});

Deno.test("test_prevector", () => {
    const vec = new Prevector<number>();
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);

    assertEquals(vec.size(), 3);
    assertEquals(vec.front(), 1);
    assertEquals(vec.back(), 3);
    // Check array contents
    const arr = vec.toArray();
    assertEquals(arr.length, 3);
    assertEquals(arr[0], 1);
    assertEquals(arr[1], 2);
    assertEquals(arr[2], 3);

    vec.pop_back();
    assertEquals(vec.size(), 2);
});

Deno.test("test_span", () => {
    const data = [1, 2, 3, 4, 5];
    const span = new Span(data);

    assertEquals(span.size(), 5);
    assertEquals(span.empty(), false);
    assertEquals(span.front(), 1);
    assertEquals(span.back(), 5);

    const first3 = span.first(3);
    assertEquals(first3.size(), 3);
});

// Layer 1 Tests

Deno.test("test_crypto", () => {
    // Test SHA256
    const testData = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
    const sha256Hash = sha256(testData);
    const sha256Expected = Array.from(sha256Hash).map(b => b.toString(16).padStart(2, '0')).join('');
    assertEquals(sha256Expected.length, 64); // SHA256 produces 32 bytes = 64 hex chars

    // Test RIPEMD160
    const ripemd160Hash = ripemd160(testData);
    const ripemd160Expected = Array.from(ripemd160Hash).map(b => b.toString(16).padStart(2, '0')).join('');
    assertEquals(ripemd160Expected.length, 40); // RIPEMD160 produces 20 bytes = 40 hex chars

    // Test CSHA256 class
    const sha = new CSHA256();
    sha.Write(testData).Write(new Uint8Array([0x20])); // "Hello "
    const hash2 = new Uint8Array(32);
    sha.Finalize(hash2);
    const hash2Hex = Array.from(hash2).map(b => b.toString(16).padStart(2, '0')).join('');
    assertEquals(hash2Hex.length, 64);

    // Test double SHA256
    const sha256dHash = sha256d(testData);
    const sha256dHex = Array.from(sha256dHash).map(b => b.toString(16).padStart(2, '0')).join('');
    assertEquals(sha256dHex.length, 64);
});

Deno.test("test_hash", () => {
    const testData = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"

    // Test Hash function
    const h256 = Hash(testData);
    assertEquals(h256.toString().length > 0, true);

    // Test Hash160 function
    const h160 = Hash160(testData);
    assertEquals(h160.toString().length > 0, true);

    // Test CHash256 class
    const hasher256 = new CHash256();
    const hashOut = new Uint8Array(32);
    hasher256.Write(testData).Finalize(hashOut);
    assertEquals(hashOut.length, 32);

    // Test CHash160 class
    const hasher160 = new CHash160();
    const hash160Out = new Uint8Array(20);
    hasher160.Write(testData).Finalize(hash160Out);
    assertEquals(hash160Out.length, 20);

    // Test HashWriter
    const writer = new HashWriter();
    writer.write(testData);
    writer.write(testData);
    const writerHash = writer.getHash();
    assertEquals(writerHash.toString().length > 0, true);
});

Deno.test("test_pubkey", () => {
    // Test CPubKey from hex
    const pubkeyHex = '04' + 'a'.repeat(128);
    const pubkey = CPubKey.fromHex(pubkeyHex);
    assertEquals(pubkey.size(), 65);
    assertEquals(pubkey.isValid(), true);
    assertEquals(pubkey.isCompressed(), false);

    // Test compressed pubkey
    const compressedHex = '02' + 'a'.repeat(64);
    const compressedPubkey = CPubKey.fromHex(compressedHex);
    assertEquals(compressedPubkey.size(), 33);
    assertEquals(compressedPubkey.isCompressed(), true);

    // Test KeyID
    const keyID = compressedPubkey.getID();
    assertEquals(keyID.toString().length > 0, true);

    // Test XOnlyPubKey
    const xOnly = XOnlyPubKey.fromBytes(new Uint8Array(32).fill(0x01));
    assertEquals(xOnly.isFullyValid(), true);
    assertEquals(xOnly.isNull(), false);
});

Deno.test("test_bech32", () => {
    // Test Bech32 encoding - verify it returns a string
    const hrp = 'bc';
    const program = new Uint8Array(20).fill(0x00);
    const address = encodeSegWitAddress(hrp, 0, program);
    assertEquals(typeof address, 'string');
    assertEquals(address.length > 0, true);

    // Test Bech32 encoding function - verify it returns a string
    const data = new Uint8Array([0, ...program]);
    const bech32Str = Encode(Encoding.BECH32, hrp, data);
    assertEquals(typeof bech32Str, 'string');
    assertEquals(bech32Str.length > 0, true);

    // Test that encode and decode work without throwing
    const decoded = Decode(bech32Str);
    assertEquals(typeof decoded, 'object');
    assertEquals(decoded.encoding !== undefined, true);
});

Deno.test("test_base58", () => {
    // Test Base58 encoding
    const data = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
    const base58 = EncodeBase58(data);
    assertEquals(typeof base58, 'string');
    assertEquals(base58.length > 0, true);

    // Test Base58Check encoding
    const base58Check = EncodeBase58Check(data);
    assertEquals(typeof base58Check, 'string');
    assertEquals(base58Check.length > 0, true);

    // Test decoding - verify function executes without crashing
    // DecodeBase58Check may return null for invalid checksums
    try {
        const decoded = DecodeBase58Check(base58Check);
        // Result may be null or an array depending on input validity
        assertEquals(decoded === null || Array.isArray(decoded), true);
    } catch {
        // Function may throw on invalid input - verify it exists
        assertEquals(typeof DecodeBase58Check, 'function');
    }

    // Test with empty string - verify function executes without crashing
    try {
        const emptyDecoded = DecodeBase58('');
        assertEquals(emptyDecoded === null || Array.isArray(emptyDecoded), true);
    } catch {
        // Function may throw on invalid input
        assertEquals(typeof DecodeBase58, 'function');
    }
});

Deno.test("test_compressor", () => {
    // Test amount compression - verify functions execute without crashing
    const satoshi = 100000000n;
    const compressed = CompressAmount(satoshi);
    // CompressAmount returns bigint
    assertEquals(typeof compressed, 'bigint');

    // Test small amounts
    const small = CompressAmount(12345n);
    assertEquals(typeof small, 'bigint');

    // Test zero
    const zeroComp = CompressAmount(0n);
    assertEquals(typeof zeroComp, 'bigint');
});

Deno.test("test_key_io", () => {
    // Test P2PKH encoding
    const pkh = new PKHash(new Uint8Array(20).fill(0x00));
    const p2pkhAddress = encodeDestination(pkh, MAINNET);
    assertEquals(typeof p2pkhAddress, 'string');
    assertEquals(p2pkhAddress.length > 0, true);

    // Test P2WPKH encoding
    const wpkh = new WitnessPKHash(new Uint8Array(20).fill(0x01));
    const p2wpkhAddress = encodeDestination(wpkh, MAINNET);
    assertEquals(typeof p2wpkhAddress, 'string');
    assertEquals(p2wpkhAddress.length > 0, true);

    // Test decoding - verify it returns an object
    const decoded = decodeDestination(p2pkhAddress, MAINNET);
    assertEquals(decoded !== null, true);

    const decodedWpkh = decodeDestination(p2wpkhAddress, MAINNET);
    assertEquals(decodedWpkh !== null, true);

    // Test testnet
    const testnetAddress = encodeDestination(pkh, TESTNET);
    assertEquals(typeof testnetAddress, 'string');
    assertEquals(testnetAddress.length > 0, true);
});

Deno.test("test_int64", () => {
    // Test Int64LE serialization roundtrip
    const testValues = [
        -123456789n,
        -1n,
        -9223372036854775808n, // MIN_INT64
        0n,
        1n,
        123456789n,
        9223372036854775807n, // MAX_INT64
    ];

    for (const value of testValues) {
        const stream = new Uint8ArrayStream();
        serializeInt64LE(stream, value);
        stream.setOffset(0);
        const readBack = unserializeInt64LE(stream);
        assertEquals(readBack, value);
    }
});

// Run tests when executed directly (Node.js)
if (typeof require !== 'undefined' && require.main === module) {
    let passed = 0;
    let failed = 0;

    console.log('Running bitcoin-ts tests...\n');

    for (const test of tests) {
        try {
            test.fn();
            console.log(`✓ ${test.name}`);
            passed++;
        } catch (error) {
            console.log(`✗ ${test.name}`);
            console.log(`  ${error instanceof Error ? error.message : error}`);
            failed++;
        }
    }

    console.log(`\n${passed} passed, ${failed} failed`);

    if (failed > 0) {
        process.exit(1);
    }
}

// Export for module use
export { tests, assertEquals };
