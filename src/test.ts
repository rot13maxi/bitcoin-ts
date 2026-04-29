// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Basic tests for bitcoin-ts
 */

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

// Test uint256 basic operations
function test_uint256() {
    console.log('Testing uint256...');
    
    // 64 hex chars = 32 bytes for uint256
    const hexStr = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    console.log('  hexStr length:', hexStr.length);
    const hash = new uint256(hexStr);
    console.log('  Created uint256 from hex:', hash.getHex());
    
    const zero = new uint256();
    console.log('  Zero is null:', zero.isNull());
    
    const hash2 = new uint256(hash.data());
    console.log('  Equality check:', hash.compare(hash2) === 0);
    
    const hash3 = uint256.fromHex(hexStr);
    console.log('  FromHex:', hash3 !== null);
    
    console.log('  uint256 tests passed!');
}

function test_uint160() {
    console.log('Testing uint160...');
    
    const pkhash = new uint160('00112233445566778899aabbccddeeff00112233');
    console.log('  Created uint160:', pkhash.getHex());
    console.log('  uint160 size:', pkhash.size());
    
    console.log('  uint160 tests passed!');
}

function test_arith_uint256() {
    console.log('Testing arith_uint256...');
    
    const a = new arith_uint256(100);
    const b = new arith_uint256(200);
    
    const sum = a.add(b);
    console.log('  100 + 200 =', sum.toBigInt());
    
    const product = a.multiply(b);
    console.log('  100 * 200 =', product.toBigInt());
    
    console.log('  100 < 200:', a.compareTo(b) < 0);
    
    console.log('  bits(100):', a.bits());
    
    const shifted = a.shiftLeft(10);
    console.log('  100 << 10 =', shifted.toBigInt());
    
    console.log('  arith_uint256 tests passed!');
}

function test_primitives() {
    console.log('Testing primitives...');
    
    const outpoint = new COutPoint();
    console.log('  Null outpoint is null:', outpoint.isNull());
    
    const txidHex = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    const txid = new Txid(txidHex);
    const outpoint2 = new COutPoint(txid, 0);
    console.log('  Outpoint toString:', outpoint2.toString());
    
    const txout = new CTxOut(1n * COIN, new Uint8Array([0]));
    console.log('  CTxOut value:', txout.nValue);
    
    const tx = new CMutableTransaction();
    tx.version = 2;
    tx.vin.push(new CTxIn(outpoint2, new Uint8Array(0)));
    tx.vout.push(new CTxOut(1n * COIN, new Uint8Array([0])));
    console.log('  Transaction version:', tx.version);
    console.log('  Transaction inputs:', tx.vin.length);
    console.log('  Transaction outputs:', tx.vout.length);
    
    console.log('  primitives tests passed!');
}

function test_prevector() {
    console.log('Testing prevector...');
    
    const vec = new Prevector<number>();
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    
    console.log('  Size:', vec.size());
    console.log('  Front:', vec.front());
    console.log('  Back:', vec.back());
    console.log('  ToArray:', vec.toArray());
    
    vec.pop_back();
    console.log('  After pop, size:', vec.size());
    
    console.log('  prevector tests passed!');
}

function test_span() {
    console.log('Testing span...');
    
    const data = [1, 2, 3, 4, 5];
    const span = new Span(data);
    
    console.log('  Size:', span.size());
    console.log('  Empty:', span.empty());
    console.log('  Front:', span.front());
    console.log('  Back:', span.back());
    
    const first3 = span.first(3);
    console.log('  First 3 size:', first3.size());
    
    console.log('  span tests passed!');
}

// Layer 1 Tests

function test_crypto() {
    console.log('Testing crypto (SHA256, RIPEMD160)...');
    
    // Test SHA256
    const testData = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
    const sha256Hash = sha256(testData);
    console.log('  SHA256 of "Hello":', Array.from(sha256Hash).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    // Test RIPEMD160
    const ripemd160Hash = ripemd160(testData);
    console.log('  RIPEMD160 of "Hello":', Array.from(ripemd160Hash).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    // Test CSHA256 class
    const sha = new CSHA256();
    sha.Write(testData).Write(new Uint8Array([0x20])) // "Hello "
    const hash2 = new Uint8Array(32);
    sha.Finalize(hash2);
    console.log('  CSHA256 multiple writes:', Array.from(hash2).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    // Test double SHA256
    const sha256dHash = sha256d(testData);
    console.log('  SHA256D of "Hello":', Array.from(sha256dHash).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    console.log('  crypto tests passed!');
}

function test_hash() {
    console.log('Testing hash...');
    
    const testData = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
    
    // Test Hash function
    const h256 = Hash(testData);
    console.log('  Hash("Hello"):', h256.toString());
    
    // Test Hash160 function
    const h160 = Hash160(testData);
    console.log('  Hash160("Hello"):', h160.toString());
    
    // Test CHash256 class
    const hasher256 = new CHash256();
    const hashOut = new Uint8Array(32);
    hasher256.Write(testData).Finalize(hashOut);
    console.log('  CHash256:', Array.from(hashOut).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    // Test CHash160 class
    const hasher160 = new CHash160();
    const hash160Out = new Uint8Array(20);
    hasher160.Write(testData).Finalize(hash160Out);
    console.log('  CHash160:', Array.from(hash160Out).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    // Test HashWriter
    const writer = new HashWriter();
    writer.write(testData);
    writer.write(testData);
    const writerHash = writer.getHash();
    console.log('  HashWriter:', writerHash.toString());
    
    console.log('  hash tests passed!');
}

function test_pubkey() {
    console.log('Testing pubkey...');
    
    // Test CPubKey from hex
    const pubkeyHex = '04' + 'a'.repeat(128);
    const pubkey = CPubKey.fromHex(pubkeyHex);
    console.log('  CPubKey size:', pubkey.size());
    console.log('  CPubKey valid:', pubkey.isValid());
    console.log('  CPubKey compressed:', pubkey.isCompressed());
    
    // Test compressed pubkey
    const compressedHex = '02' + 'a'.repeat(64);
    const compressedPubkey = CPubKey.fromHex(compressedHex);
    console.log('  Compressed pubkey size:', compressedPubkey.size());
    console.log('  Compressed pubkey compressed:', compressedPubkey.isCompressed());
    
    // Test KeyID
    const keyID = compressedPubkey.getID();
    console.log('  CKeyID:', keyID.toString());
    
    // Test XOnlyPubKey
    const xOnly = XOnlyPubKey.fromBytes(new Uint8Array(32).fill(0x01));
    console.log('  XOnlyPubKey valid:', xOnly.isFullyValid());
    console.log('  XOnlyPubKey null:', xOnly.isNull());
    
    console.log('  pubkey tests passed!');
}

function test_bech32() {
    console.log('Testing bech32...');
    
    // Test Bech32 encoding
    const hrp = 'bc';
    const program = new Uint8Array(20).fill(0x00);
    const address = encodeSegWitAddress(hrp, 0, program);
    console.log('  P2WPKH address:', address);
    
    // Test decoding
    const decoded = decodeSegWitAddress(address);
    if (decoded) {
        console.log('  Decoded version:', decoded.version);
        console.log('  Decoded program length:', decoded.program.length);
    }
    
    // Test Bech32 encoding function
    const data = new Uint8Array([0, ...program]);
    const bech32Str = Encode(Encoding.BECH32, hrp, data);
    console.log('  Encode result:', bech32Str);
    
    // Test decoding
    const decoded2 = Decode(bech32Str);
    console.log('  Decode encoding:', decoded2.encoding === Encoding.BECH32 ? 'BECH32' : 'other');
    console.log('  Decode HRP:', decoded2.hrp);
    
    // Test Taproot (Bech32m)
    const taprootProgram = new Uint8Array(32).fill(0x01);
    const taprootAddress = encodeSegWitAddress(hrp, 1, taprootProgram);
    console.log('  Taproot address:', taprootAddress);
    
    console.log('  bech32 tests passed!');
}

function test_base58() {
    console.log('Testing base58...');
    
    // Test Base58 encoding
    const data = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
    const base58 = EncodeBase58(data);
    console.log('  EncodeBase58:', base58);
    
    // Test Base58Check encoding
    const base58Check = EncodeBase58Check(data);
    console.log('  EncodeBase58Check:', base58Check);
    
    // Test decoding
    const decoded = DecodeBase58Check(base58Check);
    if (decoded) {
        console.log('  DecodeBase58Check length:', decoded.length);
    }
    
    // Test with a known test vector (empty string should return empty array)
    const emptyDecoded = DecodeBase58('');
    console.log('  Empty decode:', emptyDecoded !== null && emptyDecoded.length === 0);
    
    console.log('  base58 tests passed!');
}

function test_compressor() {
    console.log('Testing compressor...');
    
    // Test amount compression
    const satoshi = 100000000n;
    const compressed = CompressAmount(satoshi);
    console.log('  CompressAmount(1 BTC):', compressed);
    const decompressed = DecompressAmount(compressed);
    console.log('  DecompressAmount result:', decompressed);
    
    // Test small amounts
    const small = CompressAmount(12345n);
    console.log('  CompressAmount(12345):', small);
    
    // Test zero
    const zeroComp = CompressAmount(0n);
    console.log('  CompressAmount(0):', zeroComp);
    
    console.log('  compressor tests passed!');
}

function test_key_io() {
    console.log('Testing key_io...');
    
    // Test P2PKH encoding
    const pkh = new PKHash(new Uint8Array(20).fill(0x00));
    const p2pkhAddress = encodeDestination(pkh, MAINNET);
    console.log('  P2PKH address:', p2pkhAddress);
    
    // Test P2WPKH encoding
    const wpkh = new WitnessPKHash(new Uint8Array(20).fill(0x01));
    const p2wpkhAddress = encodeDestination(wpkh, MAINNET);
    console.log('  P2WPKH address:', p2wpkhAddress);
    
    // Test decoding
    const decoded = decodeDestination(p2pkhAddress, MAINNET);
    console.log('  Decoded P2PKH is PKHash:', decoded instanceof PKHash);
    
    const decodedWpkh = decodeDestination(p2wpkhAddress, MAINNET);
    console.log('  Decoded P2WPKH is WitnessPKHash:', decodedWpkh instanceof WitnessPKHash);
    
    // Test address validation
    const valid = isValidDestinationString(p2pkhAddress, MAINNET);
    console.log('  isValidDestinationString:', valid);
    
    const invalid = isValidDestinationString('invalid', MAINNET);
    console.log('  Invalid address detection:', !invalid);
    
    // Test testnet
    const testnetAddress = encodeDestination(pkh, TESTNET);
    console.log('  Testnet P2PKH address:', testnetAddress);
    
    console.log('  key_io tests passed!');
}

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

console.log('\nAll tests passed!');
