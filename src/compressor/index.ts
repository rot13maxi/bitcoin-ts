// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Script and amount compression utilities.
 * This is a TypeScript port of Bitcoin Core's compressor.h
 */

// Script opcodes
export const OP_0 = 0x00;
export const OP_PUSHDATA1 = 0x4c;
export const OP_PUSHDATA2 = 0x4d;
export const OP_PUSHDATA4 = 0x4e;
export const OP_1NEGATE = 0x4f;
export const OP_1 = 0x51;
export const OP_2 = 0x52;
export const OP_3 = 0x53;
export const OP_4 = 0x54;
export const OP_5 = 0x55;
export const OP_6 = 0x56;
export const OP_7 = 0x57;
export const OP_8 = 0x58;
export const OP_9 = 0x59;
export const OP_10 = 0x5a;
export const OP_11 = 0x5b;
export const OP_12 = 0x5c;
export const OP_13 = 0x5d;
export const OP_14 = 0x5e;
export const OP_15 = 0x5f;
export const OP_16 = 0x60;
export const OP_DUP = 0x76;
export const OP_HASH160 = 0xa9;
export const OP_EQUAL = 0x87;
export const OP_EQUALVERIFY = 0x88;
export const OP_CHECKSIG = 0xac;
export const OP_CHECKSIGADD = 0xae;
export const OP_RETURN = 0x6a;

/**
 * Maximum script size (165,000 bytes)
 */
export const MAX_SCRIPT_SIZE = 165000;

/**
 * Compressed script type
 */
export type CompressedScript = Uint8Array;

/**
 * Get the special script size for a given type
 */
export function GetSpecialScriptSize(nSize: number): number {
    switch (nSize) {
        case 0: return 20;  // P2PKH
        case 1: return 20;  // P2SH
        case 2: return 33; // P2PK with 0x02 prefix
        case 3: return 33; // P2PK with 0x03 prefix
        case 4: return 33; // P2PK with 0x04 prefix
        case 5: return 32; // 32-byte witness program
        case 6: return 33; // 33-byte witness program
        default: return 0;
    }
}

/**
 * Compress a script
 */
export function CompressScript(script: Uint8Array): CompressedScript {
    const len = script.length;
    
    // P2PKH (Pay to Public Key Hash)
    if (len === 25 && script[0] === OP_DUP && script[1] === OP_HASH160 && 
        script[2] === 20 && script[23] === OP_EQUALVERIFY && script[24] === OP_CHECKSIG) {
        return new Uint8Array([0, ...script.slice(3, 23)]);
    }
    
    // P2SH (Pay to Script Hash)
    if (len === 23 && script[0] === OP_HASH160 && script[1] === 20 && script[22] === OP_EQUAL) {
        return new Uint8Array([1, ...script.slice(2, 22)]);
    }
    
    // P2WPKH (Pay to Witness Public Key Hash)
    if (len === 22 && script[0] === 0x00 && script[1] === 20) {
        return new Uint8Array([5, ...script.slice(2, 22)]);
    }
    
    // P2WSH (Pay to Witness Script Hash)
    if (len === 34 && script[0] === 0x00 && script[1] === 32) {
        return new Uint8Array([6, ...script.slice(2, 34)]);
    }
    
    // P2PK with compressed key (33 bytes)
    if (len === 33 && (script[0] === 0x02 || script[0] === 0x03)) {
        return new Uint8Array([2 + (script[0] - 0x02), ...script.slice(1, 33)]);
    }
    
    // P2PK with uncompressed key (65 bytes)
    if (len === 65 && script[0] === 0x04) {
        return new Uint8Array([4, ...script.slice(1, 33)]);
    }
    
    // Return uncompressed for other scripts
    return script;
}

/**
 * Decompress a script
 */
export function DecompressScript(nSize: number, compressed: CompressedScript): Uint8Array {
    switch (nSize) {
        case 0: {
            // P2PKH
            const result = new Uint8Array(25);
            result[0] = OP_DUP;
            result[1] = OP_HASH160;
            result[2] = 20;
            result.set(compressed.slice(0, 20), 3);
            result[23] = OP_EQUALVERIFY;
            result[24] = OP_CHECKSIG;
            return result;
        }
        case 1: {
            // P2SH
            const result = new Uint8Array(23);
            result[0] = OP_HASH160;
            result[1] = 20;
            result.set(compressed.slice(0, 20), 2);
            result[22] = OP_EQUAL;
            return result;
        }
        case 2: {
            // P2PK compressed 0x02
            return new Uint8Array([0x02, ...compressed.slice(0, 33)]);
        }
        case 3: {
            // P2PK compressed 0x03
            return new Uint8Array([0x03, ...compressed.slice(0, 33)]);
        }
        case 4: {
            // P2PK uncompressed 0x04 (only store x-coordinate)
            return new Uint8Array([0x04, ...compressed.slice(0, 33)]);
        }
        case 5: {
            // P2WPKH
            const result = new Uint8Array(22);
            result[0] = 0x00;
            result[1] = 20;
            result.set(compressed.slice(0, 20), 2);
            return result;
        }
        case 6: {
            // P2WSH
            const result = new Uint8Array(34);
            result[0] = 0x00;
            result[1] = 32;
            result.set(compressed.slice(0, 32), 2);
            return result;
        }
        default:
            return compressed;
    }
}

/**
 * Maximum money value
 */
const MAX_MONEY = 21000000n * 100000000n;

/**
 * Threshold values for amount compression
 * THRESHOLD9 must be larger than the maximum possible mantissa value
 * (which is the original amount minus the sum of thresholds) to enable
 * correct roundtrip decompression. Using MAX_MONEY / 2 ensures this.
 */
const THRESHOLD1 = 1n;
const THRESHOLD2 = 2n;
const THRESHOLD3 = 3n;
const THRESHOLD4 = 4n;
const THRESHOLD5 = 5n;
const THRESHOLD6 = 6n;
const THRESHOLD7 = 7n;
const THRESHOLD8 = 8n;
const THRESHOLD9 = MAX_MONEY / 2n;

/**
 * Compress a satoshi amount
 */
export function CompressAmount(nAmount: bigint): bigint {
    if (nAmount <= 0n || nAmount > MAX_MONEY) {
        return 0n;
    }
    
    if (nAmount < THRESHOLD1) {
        return nAmount * 10n + THRESHOLD1;
    }
    
    let exp = 0n;
    let mantissa = nAmount;
    const steps = [
        { threshold: 9n, step: 9n },
        { threshold: 8n, step: 8n },
        { threshold: 7n, step: 7n },
        { threshold: 6n, step: 6n },
        { threshold: 5n, step: 5n },
        { threshold: 4n, step: 4n },
        { threshold: 3n, step: 3n },
        { threshold: 2n, step: 2n },
    ];
    
    for (const { threshold, step } of steps) {
        if (mantissa >= threshold + 1n) {
            mantissa -= threshold;
            exp += step;
        }
    }
    
    return mantissa + exp * THRESHOLD9;
}

/**
 * Decompress a satoshi amount
 */
export function DecompressAmount(nCompressed: bigint): bigint {
    if (nCompressed <= 0n) {
        return 0n;
    }
    
    // Extract the original exp and mantissa from compressed value
    // compressed = mantissa + exp * THRESHOLD9
    // where mantissa = compressed % THRESHOLD9
    // and exp = compressed / THRESHOLD9
    let exp = nCompressed / THRESHOLD9;
    let mantissa = nCompressed % THRESHOLD9;
    
    // Reverse the compression: add back thresholds where exp >= threshold
    // Compression applied thresholds 9,8,7,6,5,4,3,2,1 in order when mantissa >= threshold+1
    // So decompression processes them in reverse order
    const steps = [
        { threshold: 9n, step: 9n },
        { threshold: 8n, step: 8n },
        { threshold: 7n, step: 7n },
        { threshold: 6n, step: 6n },
        { threshold: 5n, step: 5n },
        { threshold: 4n, step: 4n },
        { threshold: 3n, step: 3n },
        { threshold: 2n, step: 2n },
        { threshold: 1n, step: 1n },
    ];
    
    for (const { threshold, step } of steps) {
        // If exp >= threshold, it means this threshold was subtracted during compression
        if (exp >= threshold) {
            exp -= threshold;
            mantissa += step;
        }
    }
    
    return mantissa;
}
