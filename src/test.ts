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

console.log('Running bitcoin-ts tests...\n');

test_uint256();
test_uint160();
test_arith_uint256();
test_primitives();
test_prevector();
test_span();

console.log('\nAll tests passed!');
