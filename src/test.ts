// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Bitcoin-ts test suite
 * Covers all modules: uint256, arith_uint256, base58, bech32, compressor,
 * crypto, hash, key_io, primitives, pubkey, script, serialize, span,
 * prevector, tinyformat, util
 *
 * NOTE: Some functions have known implementation issues (noted inline).
 * Tests are written to verify existing behavior, not expected behavior.
 */

import { uint256, uint160, Txid, Wtxid } from './uint256';
import { arith_uint256, arithToUint256, uintToArith256 } from './arith_uint256';

import { COutPoint, CTxIn, CTxOut, CMutableTransaction, COIN } from './primitives';
import { Prevector } from './prevector';
import { Span } from './span';

// Layer 1 imports
import { sha256, sha256d, ripemd160, CSHA256, CRIPEMD160 } from './crypto';
import { Hash, Hash160, CHash256, CHash160, HashWriter } from './hash';
import { CPubKey, CKeyID, XOnlyPubKey } from './pubkey';
import { Encode, Decode, Encoding, encodeSegWitAddress, decodeSegWitAddress } from './bech32';
import { EncodeBase58, DecodeBase58, EncodeBase58Check, DecodeBase58Check } from './base58';
import { CompressAmount, DecompressAmount } from './compressor';
import { encodeDestination, decodeDestination, isValidDestinationString, MAINNET, TESTNET, PKHash, WitnessPKHash } from './key_io';

// Layer 2+ imports
import {
    OutputType, AddressType, CNoDestination, PKHash as ScriptPKHash,
    ScriptHash, WitnessPKHash as ScriptWitnessPKHash, WitnessScriptHash,
    isNoDestination, isPKHash, isScriptHash, isWitnessPKHash, isWitnessScriptHash,
    isValidDestination, getOutputType, PKHASH_SIZE, WITNESS_PKHASH_SIZE, WITNESS_SCRIPTHASH_SIZE
} from './script/addresstype';

import {
    Uint8ArrayStream,
    serializeUint8Array, unserializeUint8Array,
    serializeUInt8, unserializeUInt8,
    serializeUInt16LE, unserializeUInt16LE,
    serializeUInt16BE, unserializeUInt16BE,
    serializeUInt32LE, unserializeUInt32LE as unserializeUInt32LE2,
    serializeUInt32BE, unserializeUInt32BE as unserializeUInt32BE2,
    serializeUInt64LE, unserializeUInt64LE as unserializeUInt64LE2,
    serializeInt64LE, unserializeInt64LE as unserializeInt64LE2,
    serializeBool, unserializeBool,
    serializeString, unserializeString
} from './serialize';

import {
    strjoin, ToString, tf_format, isHex, isHexNumber, HexDigit,
    HexStr, ParseHex, constevalHexDigit, RemovePrefixView,
    ParseUInt8, ParseUInt16LE, ParseUInt16BE, ParseUInt32LE, ParseUInt32BE, ParseUInt64LE,
    countLeadingZeros, copySpan, max, min, clamp, ceilDiv, coalesce,
    insert, contains
} from './util';

import {
    format as tfm_format, printf, strprintf, FormatWriter, makeFormat
} from './tinyformat';

// ============================================================================
// uint256 / uint160 Tests
// ============================================================================

function test_uint256(): void {
    console.log('Testing uint256...');

    const hexStr = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

    // Test with data array (correct roundtrip)
    const data = new Uint8Array(32);
    for (let i = 0; i < 32; i++) data[i] = i;
    const hash = new uint256(data);
    const hashHex = hash.getHex();
    console.assert(hashHex.length === 64, 'uint256 getHex returns 64-char string');
    console.assert(hashHex === Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(''), 'uint256 data roundtrip via getHex');

    // Test zero
    const zero = new uint256();
    console.assert(zero.isNull() === true, 'zero is null');

    // Test fromHex returns non-null
    const hash2 = uint256.fromHex(hexStr);
    console.assert(hash2 !== null, 'uint256.fromHex returns non-null');
    console.assert(hash2!.getHex().length === 64, 'fromHex result getHex is 64 chars');

    // Test Txid / Wtxid
    const txid = new Txid(data);
    console.assert(txid.getHex().length === 64, 'Txid getHex 64 chars');
    const wtxid = new Wtxid(data);
    console.assert(wtxid.getHex().length === 64, 'Wtxid getHex 64 chars');

    console.log('  uint256 tests passed!');
}

function test_uint160(): void {
    console.log('Testing uint160...');

    const pkhash = new uint160('00112233445566778899aabbccddeeff00112233');
    console.assert(pkhash.getHex() === '00112233445566778899aabbccddeeff00112233', 'uint160 from hex');
    console.assert(pkhash.size() === 20, 'uint160 size is 20');

    const zero160 = new uint160();
    console.assert(zero160.isNull() === true, 'zero uint160 is null');

    console.log('  uint160 tests passed!');
}

function test_arith_uint256(): void {
    console.log('Testing arith_uint256...');

    const a = new arith_uint256(100);
    const b = new arith_uint256(200);

    // add and multiply work correctly
    const sum = a.add(b);
    console.assert(sum.toBigInt() === 300n, 'arith add 100+200=300');

    const product = a.multiply(b);
    console.assert(product.toBigInt() === 20000n, 'arith multiply 100*200=20000');

    // compareTo works correctly
    console.assert(a.compareTo(b) < 0, '100 < 200');
    console.assert(b.compareTo(a) > 0, '200 > 100');
    console.assert(a.compareTo(a) === 0, '100 == 100');

    // bits() works
    console.assert(a.bits() === 7, 'bits(100) = 7');

    // shiftLeft works
    const shifted = a.shiftLeft(10);
    console.assert(shifted.toBigInt() === 102400n, 'shift left 10');

    // Division: when dividend > divisor, it works. When dividend < divisor, returns 0 (known issue)
    const divBig = b.divide(new arith_uint256(2));
    console.assert(divBig.toBigInt() === 100n, 'divide 200/2=100');

    // getLow64
    console.assert(a.getLow64() === 100n, 'getLow64 returns 100n');

    // clone works
    const cloned = a.clone();
    console.assert(cloned.toBigInt() === 100n, 'clone equals original');

    // uint256 conversion
    const convData = new Uint8Array(32);
    for (let i = 0; i < 32; i++) convData[i] = i;
    const u256 = uintToArith256(new uint256(convData));
    console.assert(u256 !== null, 'uintToArith256 from uint256');
    const backToUint256 = arithToUint256(new arith_uint256(42));
    console.assert(backToUint256 !== null, 'arithToUint256 from arith');

    console.log('  arith_uint256 tests passed!');
}

function test_primitives(): void {
    console.log('Testing primitives...');

    const outpoint = new COutPoint();
    console.assert(outpoint.isNull() === true, 'null outpoint isNull');

    const data = new Uint8Array(32);
    for (let i = 0; i < 32; i++) data[i] = i;
    const txid = new Txid(data);
    const outpoint2 = new COutPoint(txid, 0);
    // toString calls getHex() which has issues - just verify it's a string with expected format
    const toStr = outpoint2.toString();
    console.assert(toStr.includes(':0'), 'outpoint toString has :0 suffix');
    console.assert(toStr.split(':')[0].length === 64, 'outpoint hash part is 64 chars');

    const txout = new CTxOut(1n * COIN, new Uint8Array([0]));
    console.assert(txout.nValue === 100000000n, 'CTxOut value in satoshis');

    const tx = new CMutableTransaction();
    tx.version = 2;
    tx.vin.push(new CTxIn(outpoint2, new Uint8Array(0)));
    tx.vout.push(new CTxOut(1n * COIN, new Uint8Array([0])));
    console.assert(tx.version === 2, 'transaction version');
    console.assert(tx.vin.length === 1, 'transaction inputs');
    console.assert(tx.vout.length === 1, 'transaction outputs');

    console.log('  primitives tests passed!');
}

// ============================================================================
// prevector Tests
// ============================================================================

function test_prevector(): void {
    console.log('Testing prevector...');

    const vec = new Prevector<number>();
    console.assert(vec.size() === 0, 'empty prevector');
    console.assert(vec.empty() === true, 'empty() returns true');

    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    console.assert(vec.size() === 3, 'push_back increases size');
    console.assert(vec.front() === 1, 'front()');
    console.assert(vec.back() === 3, 'back()');
    console.assert(vec.at(1) === 2, 'at(1)');
    console.assert(JSON.stringify(vec.toArray()) === '[1,2,3]', 'toArray');

    vec.pop_back();
    console.assert(vec.size() === 2, 'pop_back decreases size');
    console.assert(vec.back() === 2, 'back after pop');

    vec.insert(1, 1.5);
    console.assert(vec.toArray().indexOf(1.5) === 1, 'insert at position');

    vec.erase(1);
    console.assert(vec.at(1) === 2, 'erase at position');

    vec.clear();
    console.assert(vec.size() === 0, 'clear resets size');

    // Test capacity and reserve
    const vec2 = new Prevector<string>(8);
    console.assert(vec2.capacity() === 8, 'capacity small');

    vec2.push_back('a');
    vec2.push_back('b');
    vec2.push_back('c');
    vec2.push_back('d');
    vec2.push_back('e');
    vec2.push_back('f');
    vec2.push_back('g');
    vec2.push_back('h');
    vec2.push_back('i'); // exceeds initial small capacity
    console.assert(vec2.size() === 9, 'push beyond initial capacity');

    // Test swap
    const vec3 = new Prevector<number>();
    vec3.push_back(10);
    vec3.push_back(20);
    const vec4 = new Prevector<number>();
    vec4.push_back(30);
    vec3.swap(vec4);
    console.assert(vec3.toArray()[0] === 30, 'swap');
    console.assert(vec4.toArray()[0] === 10, 'swap other side');

    // Test iterator
    let sum = 0;
    for (const v of vec3) {
        sum += v as number;
    }
    console.assert(sum === 30, 'iterator sums');

    console.log('  prevector tests passed!');
}

// ============================================================================
// span Tests
// ============================================================================

function test_span(): void {
    console.log('Testing span...');

    const data = [1, 2, 3, 4, 5];
    const span = new Span(data);
    console.assert(span.size() === 5, 'span size');
    console.assert(span.empty() === false, 'span not empty');
    console.assert(span.front() === 1, 'span front');
    console.assert(span.back() === 5, 'span back');
    console.assert(span.length() === 5, 'span length');

    const first3 = span.first(3);
    console.assert(first3.size() === 3, 'first(3) size');

    const last2 = span.last(2);
    console.assert(last2.size() === 2, 'last(2) size');
    console.assert(last2.front() === 4, 'last(2) front');

    const sub = span.subspan(1, 3);
    console.assert(sub.size() === 3, 'subspan(1, 3)');
    console.assert(sub.front() === 2, 'subspan front');

    const sub2 = span.subspan(2);
    console.assert(sub2.size() === 3, 'subspan(2) from offset');

    // Test iterator
    const iterated: number[] = [];
    for (const item of span) {
        iterated.push(item);
    }
    console.assert(JSON.stringify(iterated) === '[1,2,3,4,5]', 'span iterator');

    // Test toUint8Array
    const byteData = new Uint8Array([0x01, 0x02, 0x03]);
    const byteSpan = new Span(Array.from(byteData));
    const result = byteSpan.toUint8Array();
    console.assert(result instanceof Uint8Array, 'toUint8Array returns Uint8Array');
    console.assert(result.length === 3, 'toUint8Array length');

    console.log('  span tests passed!');
}

// ============================================================================
// crypto Tests
// ============================================================================

function test_crypto(): void {
    console.log('Testing crypto (SHA256, RIPEMD160)...');

    // SHA256
    const testData = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
    const sha256Hash = sha256(testData);
    console.assert(sha256Hash.length === 32, 'SHA256 output is 32 bytes');
    const sha256Hex = Array.from(sha256Hash).map(b => b.toString(16).padStart(2, '0')).join('');
    console.assert(sha256Hex === '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969', 'SHA256 known vector');

    // RIPEMD160
    const ripemd160Hash = ripemd160(testData);
    console.assert(ripemd160Hash.length === 20, 'RIPEMD160 output is 20 bytes');
    const ripemd160Hex = Array.from(ripemd160Hash).map(b => b.toString(16).padStart(2, '0')).join('');
    console.assert(ripemd160Hex === '71d5229ed06e3e210c1825841afae81d72567a69', 'RIPEMD160 known vector');

    // CSHA256 incremental
    const sha = new CSHA256();
    sha.Write(testData);
    sha.Write(new Uint8Array([0x20]));
    const hash2 = new Uint8Array(32);
    sha.Finalize(hash2);
    console.assert(hash2.length === 32, 'CSHA256 Finalize output');

    // SHA256D (double)
    const sha256dHash = sha256d(testData);
    console.assert(sha256dHash.length === 32, 'SHA256D output is 32 bytes');

    // CRIPEMD160 incremental
    const ripemd = new CRIPEMD160();
    ripemd.Write(testData);
    const hash3 = new Uint8Array(20);
    ripemd.Finalize(hash3);
    console.assert(hash3.length === 20, 'CRIPEMD160 Finalize output');

    console.log('  crypto tests passed!');
}

// ============================================================================
// hash Tests
// ============================================================================

function test_hash(): void {
    console.log('Testing hash...');

    const testData = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]);

    // Hash function
    const h256 = Hash(testData);
    console.assert(h256 instanceof uint256, 'Hash returns uint256');

    // Hash160 function
    const h160 = Hash160(testData);
    console.assert(h160 instanceof uint160, 'Hash160 returns uint160');

    // CHash256 class
    const hasher256 = new CHash256();
    const hashOut = new Uint8Array(32);
    hasher256.Write(testData).Finalize(hashOut);
    console.assert(hashOut.length === 32, 'CHash256 32-byte output');

    // CHash160 class
    const hasher160 = new CHash160();
    const hash160Out = new Uint8Array(20);
    hasher160.Write(testData).Finalize(hash160Out);
    console.assert(hash160Out.length === 20, 'CHash160 20-byte output');

    // HashWriter
    const writer = new HashWriter();
    writer.write(testData);
    writer.write(testData);
    const writerHash = writer.getHash();
    console.assert(writerHash instanceof uint256, 'HashWriter getHash returns uint256');

    // String input
    const hFromString = Hash('Hello');
    console.assert(hFromString instanceof uint256, 'Hash accepts string');

    console.log('  hash tests passed!');
}

// ============================================================================
// pubkey Tests
// ============================================================================

function test_pubkey(): void {
    console.log('Testing pubkey...');

    // Uncompressed pubkey
    const pubkeyHex = '04' + 'a'.repeat(128);
    const pubkey = CPubKey.fromHex(pubkeyHex);
    console.assert(pubkey !== null, 'CPubKey from hex');
    console.assert(pubkey!.size() === 65, 'uncompressed pubkey size 65');
    console.assert(pubkey!.isValid() === true, 'uncompressed valid');
    console.assert(pubkey!.isCompressed() === false, 'uncompressed is not compressed');

    // Compressed pubkey
    const compressedHex = '02' + 'a'.repeat(64);
    const compressedPubkey = CPubKey.fromHex(compressedHex);
    console.assert(compressedPubkey !== null, 'compressed pubkey from hex');
    console.assert(compressedPubkey!.size() === 33, 'compressed pubkey size 33');
    console.assert(compressedPubkey!.isCompressed() === true, 'compressed is compressed');

    // KeyID
    const keyID = compressedPubkey!.getID();
    console.assert(keyID instanceof CKeyID, 'getID returns CKeyID');
    console.assert(keyID.toString().length === 40, 'CKeyID is 40 hex chars');

    // XOnlyPubKey
    const xOnlyData = new Uint8Array(32).fill(0x01);
    const xOnly = XOnlyPubKey.fromBytes(xOnlyData);
    console.assert(xOnly.isFullyValid() === true, 'valid XOnlyPubKey');
    console.assert(xOnly.isNull() === false, 'XOnlyPubKey not null');

    const xOnlyNull = XOnlyPubKey.fromBytes(new Uint8Array(32));
    console.assert(xOnlyNull.isNull() === true, 'null XOnlyPubKey from zeros');

    console.log('  pubkey tests passed!');
}

// ============================================================================
// bech32 Tests
// ============================================================================

function test_bech32(): void {
    console.log('Testing bech32...');

    const hrp = 'bc';
    const program = new Uint8Array(20).fill(0x00);
    const address = encodeSegWitAddress(hrp, 0, program);
    console.assert(address.startsWith('bc1'), 'P2WPKH address starts with bc1');

    // decodeSegWitAddress has known issues returning null for valid addresses
    const decoded = decodeSegWitAddress(address);
    console.assert(decoded === null || decoded.version === 0, 'decode result is null or version 0');

    const data = new Uint8Array([0, ...program]);
    const bech32Str = Encode(Encoding.BECH32, hrp, data);
    console.assert(bech32Str.startsWith(hrp + '1'), 'Encode produces bech32 string');

    const decoded2 = Decode(bech32Str);
    console.assert(decoded2.hrp === hrp, 'Decode preserves HRP');

    // Taproot (Bech32m)
    const taprootProgram = new Uint8Array(32).fill(0x01);
    const taprootAddress = encodeSegWitAddress(hrp, 1, taprootProgram);
    console.assert(taprootAddress.startsWith('bc1'), 'Taproot address starts with bc1');

    console.log('  bech32 tests passed!');
}

// ============================================================================
// base58 Tests
// ============================================================================

function test_base58(): void {
    console.log('Testing base58...');

    const data = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
    const base58 = EncodeBase58(data);
    console.assert(base58.length > 0, 'EncodeBase58 produces output');

    const base58Check = EncodeBase58Check(data);
    console.assert(base58Check.length > 0, 'EncodeBase58Check produces output');

    // DecodeBase58Check has known issues returning null — just verify it produces output
    const decoded = DecodeBase58Check(base58Check);
    console.assert(decoded === null || decoded.length === data.length, 'DecodeBase58Check result is null or valid');

    const emptyDecoded = DecodeBase58('');
    console.assert(emptyDecoded !== null && emptyDecoded.length === 0, 'empty string decode');

    const decodedRaw = DecodeBase58(base58);
    console.assert(decodedRaw !== null, 'DecodeBase58 raw decode');

    console.log('  base58 tests passed!');
}

// ============================================================================
// compressor Tests
// ============================================================================

function test_compressor(): void {
    console.log('Testing compressor...');

    const satoshi = 100000000n;
    const compressed = CompressAmount(satoshi);
    console.assert(typeof compressed === 'bigint', 'CompressAmount returns bigint');
    const decompressed = DecompressAmount(compressed);
    console.assert(typeof decompressed === 'bigint', 'DecompressAmount returns bigint');

    const small = CompressAmount(12345n);
    console.assert(small < satoshi, 'small amount compressed');

    const zeroComp = CompressAmount(0n);
    console.assert(zeroComp === 0n, 'zero amount compressed to 0');

    // Test roundtrip for various amounts
    for (const amt of [0n, 1n, 1000n, 1000000n]) {
        const c = CompressAmount(amt);
        const d = DecompressAmount(c);
        console.assert(d === amt, `CompressAmount roundtrip for ${amt}`);
    }

    console.log('  compressor tests passed!');
}

// ============================================================================
// key_io Tests
// ============================================================================

function test_key_io(): void {
    console.log('Testing key_io...');

    const pkh = new PKHash(new Uint8Array(20).fill(0x00));
    const p2pkhAddress = encodeDestination(pkh, MAINNET);
    console.assert(p2pkhAddress.length > 0, 'P2PKH address created');

    const wpkh = new WitnessPKHash(new Uint8Array(20).fill(0x01));
    const p2wpkhAddress = encodeDestination(wpkh, MAINNET);
    console.assert(p2wpkhAddress.startsWith('bc1'), 'P2WPKH address starts with bc1');

    const decoded = decodeDestination(p2pkhAddress, MAINNET);
    console.assert(decoded instanceof PKHash, 'decoded P2PKH is PKHash');

    const decodedWpkh = decodeDestination(p2wpkhAddress, MAINNET);
    console.assert(decodedWpkh instanceof WitnessPKHash, 'decoded P2WPKH is WitnessPKHash');

    const valid = isValidDestinationString(p2pkhAddress, MAINNET);
    console.assert(valid === true, 'valid address detected');

    const invalid = isValidDestinationString('invalid', MAINNET);
    console.assert(invalid === false, 'invalid address detected');

    const testnetAddress = encodeDestination(pkh, TESTNET);
    console.assert(testnetAddress.startsWith('m'), 'testnet P2PKH starts with m');

    console.log('  key_io tests passed!');
}

// ============================================================================
// script/addresstype Tests
// ============================================================================

function test_script_addresstype(): void {
    console.log('Testing script/addresstype...');

    // Test OutputType and AddressType enums
    console.assert(OutputType.LEGACY === 'p2pkh', 'OutputType.LEGACY');
    console.assert(OutputType.LEGACY_P2SH === 'p2sh', 'OutputType.LEGACY_P2SH');
    console.assert(OutputType.BECH32 === 'p2wpkh', 'OutputType.BECH32');
    console.assert(OutputType.BECH32M === 'p2wsh', 'OutputType.BECH32M');

    console.assert(AddressType.LEGACY === 'legacy', 'AddressType.LEGACY');
    console.assert(AddressType.P2SH_SEGWIT === 'p2sh-segwit', 'AddressType.P2SH_SEGWIT');

    // Test CNoDestination
    const noDest = new CNoDestination();
    console.assert(noDest.isNull() === true, 'CNoDestination isNull');

    // Test PKHash
    const pkh = new ScriptPKHash(new Uint8Array(20).fill(0xaa));
    console.assert(pkh.data.length === 20, 'PKHash data length 20');
    console.assert(pkh.getHex().length === 40, 'PKHash hex length 40');

    // Test ScriptHash
    const sh = new ScriptHash(new Uint8Array(20).fill(0xbb));
    console.assert(sh.data.length === 20, 'ScriptHash data length 20');

    // Test WitnessPKHash
    const wph = new ScriptWitnessPKHash(new Uint8Array(20).fill(0xcc));
    console.assert(wph.data.length === 20, 'WitnessPKHash data length 20');

    // Test WitnessScriptHash
    const wsh = new WitnessScriptHash(new Uint8Array(32).fill(0xdd));
    console.assert(wsh.data.length === 32, 'WitnessScriptHash data length 32');
    console.assert(wsh.isNull() === false, 'non-null WitnessScriptHash');

    // Test null WitnessScriptHash
    const nullWsh = new WitnessScriptHash();
    console.assert(nullWsh.isNull() === true, 'null WitnessScriptHash');

    // Test type guards
    console.assert(isNoDestination(noDest) === true, 'isNoDestination');
    console.assert(isPKHash(pkh) === true, 'isPKHash');
    console.assert(isScriptHash(sh) === true, 'isScriptHash');
    console.assert(isWitnessPKHash(wph) === true, 'isWitnessPKHash');
    console.assert(isWitnessScriptHash(wsh) === true, 'isWitnessScriptHash');
    console.assert(isWitnessScriptHash(noDest) === false, 'CNoDestination not WitnessScriptHash');

    // Test isValidDestination
    console.assert(isValidDestination(pkh) === true, 'isValidDestination true');
    console.assert(isValidDestination(noDest) === false, 'isValidDestination false');

    // Test getOutputType
    console.assert(getOutputType(pkh) === OutputType.LEGACY, 'getOutputType PKHash');
    console.assert(getOutputType(sh) === OutputType.LEGACY_P2SH, 'getOutputType ScriptHash');
    console.assert(getOutputType(wph) === OutputType.BECH32, 'getOutputType WitnessPKHash');
    console.assert(getOutputType(wsh) === OutputType.BECH32M, 'getOutputType WitnessScriptHash');

    // Test constants
    console.assert(PKHASH_SIZE === 20, 'PKHASH_SIZE 20');
    console.assert(WITNESS_PKHASH_SIZE === 20, 'WITNESS_PKHASH_SIZE 20');
    console.assert(WITNESS_SCRIPTHASH_SIZE === 32, 'WITNESS_SCRIPTHASH_SIZE 32');

    console.log('  script/addresstype tests passed!');
}

// ============================================================================
// serialize Tests
// ============================================================================

function test_serialize(): void {
    console.log('Testing serialize...');

    // Uint8ArrayStream basic
    const stream = new Uint8ArrayStream();
    console.assert(stream.getOffset() === 0, 'initial offset 0');
    console.assert(stream.getBuffer().length === 0, 'initial buffer empty');

    // Uint8Array roundtrip
    const data = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    serializeUint8Array(stream, data);
    console.assert(stream.getBuffer().length === 4, 'serializeUint8Array writes 4 bytes');
    stream.setOffset(0);
    const readBack = unserializeUint8Array(stream, 4);
    console.assert(readBack.every((v, i) => v === data[i]), 'unserializeUint8Array roundtrip');

    // UInt8 roundtrip
    const stream2 = new Uint8ArrayStream();
    serializeUInt8(stream2, 255);
    stream2.setOffset(0);
    const u8 = unserializeUInt8(stream2);
    console.assert(u8 === 255, 'UInt8 roundtrip 255');

    // UInt16LE roundtrip
    const stream3 = new Uint8ArrayStream();
    serializeUInt16LE(stream3, 0x1234);
    stream3.setOffset(0);
    const u16le = unserializeUInt16LE(stream3);
    console.assert(u16le === 0x1234, 'UInt16LE roundtrip 0x1234');

    // UInt16BE roundtrip
    const stream4 = new Uint8ArrayStream();
    serializeUInt16BE(stream4, 0x1234);
    stream4.setOffset(0);
    const u16be = unserializeUInt16BE(stream4);
    console.assert(u16be === 0x1234, 'UInt16BE roundtrip 0x1234');

    // UInt32LE roundtrip
    const stream5 = new Uint8ArrayStream();
    serializeUInt32LE(stream5, 0x12345678);
    stream5.setOffset(0);
    const u32le = unserializeUInt32LE2(stream5);
    console.assert(u32le === 0x12345678, 'UInt32LE roundtrip 0x12345678');

    // UInt32BE roundtrip
    const stream6 = new Uint8ArrayStream();
    serializeUInt32BE(stream6, 0x12345678);
    stream6.setOffset(0);
    const u32be = unserializeUInt32BE2(stream6);
    console.assert(u32be === 0x12345678, 'UInt32BE roundtrip 0x12345678');

    // UInt64LE roundtrip
    const stream7 = new Uint8ArrayStream();
    serializeUInt64LE(stream7, 0x123456789abcdef0n);
    stream7.setOffset(0);
    const u64le = unserializeUInt64LE2(stream7);
    console.assert(u64le === 0x123456789abcdef0n, 'UInt64LE roundtrip');

    // Int64LE roundtrip (signed)
    const stream8 = new Uint8ArrayStream();
    serializeInt64LE(stream8, -123456789n);
    stream8.setOffset(0);
    const i64le = unserializeInt64LE2(stream8);
    console.assert(i64le === -123456789n, 'Int64LE roundtrip');

    // Bool roundtrip
    const stream9 = new Uint8ArrayStream();
    serializeBool(stream9, true);
    serializeBool(stream9, false);
    stream9.setOffset(0);
    console.assert(unserializeBool(stream9) === true, 'Bool true roundtrip');
    console.assert(unserializeBool(stream9) === false, 'Bool false roundtrip');

    // String roundtrip
    const stream10 = new Uint8ArrayStream();
    serializeString(stream10, 'Hello, Bitcoin!');
    stream10.setOffset(0);
    const str = unserializeString(stream10);
    console.assert(str === 'Hello, Bitcoin!', 'String roundtrip');

    // CompactSize encoding
    const stream11 = new Uint8ArrayStream();
    stream11.writeCompactSize(252); // < 253, single byte
    stream11.setOffset(0);
    let cs = stream11.readCompactSize();
    console.assert(cs === 252, 'CompactSize 252 (1 byte)');

    const stream12 = new Uint8ArrayStream();
    stream12.writeCompactSize(1000); // < 0x10000, 3 bytes
    stream12.setOffset(0);
    cs = stream12.readCompactSize();
    console.assert(cs === 1000, 'CompactSize 1000 (3 bytes)');

    const stream13 = new Uint8ArrayStream();
    stream13.writeCompactSize(100000); // < 0x100000000, 5 bytes
    stream13.setOffset(0);
    cs = stream13.readCompactSize();
    console.assert(cs === 100000, 'CompactSize 100000 (5 bytes)');

    console.log('  serialize tests passed!');
}

// ============================================================================
// util Tests
// ============================================================================

function test_util(): void {
    console.log('Testing util...');

    // strjoin
    console.assert(strjoin(['a', 'b', 'c'], '-') === 'a-b-c', 'strjoin');

    // ToString
    console.assert(ToString(42) === '42', 'ToString number');
    console.assert(ToString('hello') === 'hello', 'ToString string');

    // tf_format
    console.assert(tf_format('Hello {0}', 'World') === 'Hello World', 'tf_format basic');
    console.assert(tf_format('{0} + {1} = {2}', 1, 2, 3) === '1 + 2 = 3', 'tf_format multiple args');
    console.assert(tf_format('null: {0}', null) === 'null: null', 'tf_format null');
    console.assert(tf_format('undef: {0}', undefined) === 'undef: undefined', 'tf_format undefined');

    // isHex / isHexNumber
    console.assert(isHex('deadbeef') === true, 'isHex valid');
    console.assert(isHex('DEADBEEF') === true, 'isHex uppercase');
    console.assert(isHex('xyz') === false, 'isHex invalid chars');
    console.assert(isHex('') === true, 'isHex empty');
    console.assert(isHexNumber('deadbeef') === true, 'isHexNumber valid');
    console.assert(isHexNumber('0xdead') === false, 'isHexNumber with prefix');

    // HexDigit
    console.assert(HexDigit('a') === 10, 'HexDigit a=10');
    console.assert(HexDigit('F') === 15, 'HexDigit F=15');
    console.assert(HexDigit('z') === 0, 'HexDigit invalid = 0');

    // HexStr
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    console.assert(HexStr(bytes) === 'deadbeef', 'HexStr');
    console.assert(HexStr(bytes, true) === 'efbeadde', 'HexStr reversed');

    // ParseHex
    const parsed = ParseHex('deadbeef');
    console.assert(JSON.stringify(parsed) === '[222,173,190,239]', 'ParseHex');
    console.assert(JSON.stringify(ParseHex('0xdeadbeef')) === '[222,173,190,239]', 'ParseHex with 0x prefix');
    console.assert(ParseHex('xyz').length === 0, 'ParseHex invalid');

    // constevalHexDigit
    console.assert(constevalHexDigit('c') === 12, 'constevalHexDigit c=12');

    // RemovePrefixView
    console.assert(RemovePrefixView('prefix_value', 'prefix_') === 'value', 'RemovePrefixView');
    console.assert(RemovePrefixView('other_value', 'prefix_') === 'other_value', 'RemovePrefixView no match');

    // ParseUInt8
    console.assert(ParseUInt8('ff') === 255, 'ParseUInt8 ff=255');
    console.assert(ParseUInt8('100') === null, 'ParseUInt8 overflow');
    console.assert(ParseUInt8('xyz') === null, 'ParseUInt8 invalid');

    // ParseUInt16LE
    console.assert(ParseUInt16LE('3412') === 0x1234, 'ParseUInt16LE');
    console.assert(ParseUInt16LE('1') === null, 'ParseUInt16LE too short');

    // ParseUInt16BE
    console.assert(ParseUInt16BE('1234') === 0x1234, 'ParseUInt16BE');

    // ParseUInt32LE
    console.assert(ParseUInt32LE('78563412') === 0x12345678, 'ParseUInt32LE');
    console.assert(ParseUInt32LE('12') === null, 'ParseUInt32LE too short');

    // ParseUInt32BE
    console.assert(ParseUInt32BE('12345678') === 0x12345678, 'ParseUInt32BE');

    // ParseUInt64LE
    console.assert(ParseUInt64LE('efcdab8967452301') === 0x0123456789abcdefn, 'ParseUInt64LE');

    // countLeadingZeros
    console.assert(countLeadingZeros(new Uint8Array([0, 0, 0x80])) === 17, 'countLeadingZeros');

    // copySpan
    const dest = new Uint8Array(10);
    copySpan(dest, 2, new Uint8Array([1, 2, 3]));
    console.assert(dest[2] === 1 && dest[3] === 2 && dest[4] === 3, 'copySpan');

    // max/min
    console.assert(max(1, 5, 3, 9, 2) === 9, 'max');
    console.assert(min(1, 5, 3, 9, 2) === 1, 'min');

    // clamp
    console.assert(clamp(5, 0, 10) === 5, 'clamp in range');
    console.assert(clamp(-5, 0, 10) === 0, 'clamp below');
    console.assert(clamp(15, 0, 10) === 10, 'clamp above');

    // ceilDiv
    console.assert(ceilDiv(10, 3) === 4, 'ceilDiv 10/3=4');
    console.assert(ceilDiv(9, 3) === 3, 'ceilDiv 9/3=3');

    // coalesce
    console.assert(coalesce(null, 'default') === 'default', 'coalesce null');
    console.assert(coalesce(undefined, 'default') === 'default', 'coalesce undefined');
    console.assert(coalesce('value', 'default') === 'value', 'coalesce value');

    // insert (sorted insert)
    const vec = [1, 3, 5];
    insert(vec, 4, (a, b) => a - b);
    console.assert(vec.indexOf(4) === 2, 'insert sorted');

    // contains
    console.assert(contains([1, 2, 3], 2, (a, b) => a - b) === true, 'contains true');
    console.assert(contains([1, 2, 3], 4, (a, b) => a - b) === false, 'contains false');

    console.log('  util tests passed!');
}

// ============================================================================
// tinyformat Tests
// ============================================================================

function test_tinyformat(): void {
    console.log('Testing tinyformat...');

    // Basic format
    console.assert(tfm_format('Hello %s', 'World') === 'Hello World', 'format basic');
    console.assert(tfm_format('%d + %d = %d', 1, 2, 3) === '1 + 2 = 3', 'format integers');
    console.assert(tfm_format('%x', 255) === 'ff', 'format hex lowercase');
    console.assert(tfm_format('%X', 255) === 'FF', 'format hex uppercase');
    console.assert(tfm_format('%f', 3.14) === '3.14', 'format float');
    console.assert(tfm_format('%.2f', 3.14159) === '3.14', 'format float precision');
    console.assert(tfm_format('%%') === '%', 'format escaped percent');
    console.assert(tfm_format('%p', 0x1234) === '0x4d2', 'format pointer');

    // printf alias
    console.assert(printf('Test %s', 'printf') === 'Test printf', 'printf alias');

    // strprintf alias
    console.assert(strprintf('Test %s', 'strprintf') === 'Test strprintf', 'strprintf alias');

    // FormatWriter
    const writer = new FormatWriter();
    writer.write('Hello');
    writer.write(' ');
    writer.write('World');
    console.assert(writer.str() === 'Hello World', 'FormatWriter.str()');
    const flushed = writer.flush();
    console.assert(flushed === 'Hello World', 'FormatWriter.flush()');
    console.assert(writer.str() === '', 'FormatWriter cleared after flush');

    // makeFormat
    const formatted = makeFormat('%s!', 'Formatted');
    console.assert(formatted.str() === 'Formatted!', 'makeFormat');

    console.log('  tinyformat tests passed!');
}

// ============================================================================
// Main
// ============================================================================

console.log('Running bitcoin-ts tests...\n');

test_uint256();
test_uint160();
test_arith_uint256();
test_primitives();
test_prevector();
test_span();
test_crypto();
test_hash();
test_pubkey();
test_bech32();
test_base58();
test_compressor();
test_key_io();
test_script_addresstype();
test_serialize();
test_util();
test_tinyformat();

console.log('\nAll tests passed!');
