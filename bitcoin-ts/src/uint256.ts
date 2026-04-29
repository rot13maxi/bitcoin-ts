// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Uint256 type definition
 * 
 * Represents a 256-bit unsigned integer used for hashes and block heights.
 * This is a TypeScript stub - the actual SHA256 hash functions are in crypto/sha256.ts
 */

export type uint256 = Uint8Array;

/**
 * Create a zero uint256
 */
export function uint256Zero(): uint256 {
    return new Uint8Array(32);
}

/**
 * Create a uint256 from hex string
 */
export function uint256FromStr(hex: string): uint256 {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        const pos = clean.length - (32 - i) * 2;
        if (pos >= 0) {
            bytes[31 - i] = parseInt(clean.substring(pos, pos + 2), 16);
        }
    }
    return bytes;
}

/**
 * Convert uint256 to hex string
 */
export function uint256ToStr(hash: uint256): string {
    return Array.from(hash).reverse().map(b => b.toString(16).padStart(2, '0')).join('');
}
