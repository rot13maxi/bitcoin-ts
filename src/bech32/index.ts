// Copyright (c) 2017, 2021 Pieter Wuille
// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Bech32 and Bech32m encoding/decoding.
 * This is a TypeScript port of Bitcoin Core's bech32.cpp
 * See BIP 173 and BIP 350 for specifications.
 */

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const CHARSET_LOWER = 'QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L';

// Gray code for the bech32 charset
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

/**
 * Convert bits to 5-bit groups
 */
function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): Uint8Array | null {
    let acc = 0;
    let bits = 0;
    const maxv = (1 << toBits) - 1;
    const maxacc = (1 << (fromBits + toBits - 1)) - 1;
    const result: number[] = [];

    for (let i = 0; i < data.length; i++) {
        const value = data[i];
        if (value < 0 || (value >> fromBits) !== 0) return null;
        acc = ((acc << fromBits) | value) & maxacc;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            result.push((acc >> bits) & maxv);
        }
    }

    if (pad) {
        if (bits > 0) result.push((acc << (toBits - bits)) & maxv);
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
        return null;
    }

    return new Uint8Array(result);
}

/**
 * Create checksum for bech32/bech32m
 */
function createChecksum(encoding: Encoding, hrp: string, data: Uint8Array): Uint8Array {
    const values = new Uint8Array(data.length + 6);
    for (let i = 0; i < data.length; i++) values[i] = data[i];
    
    // Expand the HRP
    const expansion: number[] = [];
    for (let i = 0; i < hrp.length; i++) {
        expansion.push(hrp.charCodeAt(i) >> 5);
    }
    expansion.push(0);
    for (let i = 0; i < hrp.length; i++) {
        expansion.push(hrp.charCodeAt(i) & 31);
    }
    
    for (let i = 0; i < values.length; i++) {
        expansion.push(values[i]);
    }
    
    let polymod = 1;
    for (const value of expansion) {
        const top = polymod >> 25;
        polymod = ((polymod & 0x1ffffff) << 5) ^ value;
        for (let j = 0; j < 5; j++) {
            if ((top >> j) & 1) {
                polymod ^= GENERATOR[j];
            }
        }
    }
    
    const encodingConstant = encoding === Encoding.BECH32M ? 0x2bc830a3 : 1;
    polymod ^= encodingConstant;
    const result = new Uint8Array(6);
    for (let i = 0; i < 6; i++) {
        result[i] = (polymod >> (5 * (5 - i))) & 31;
    }
    
    return result;
}

/**
 * Verify checksum
 */
function verifyChecksum(encoding: Encoding, hrp: string, data: Uint8Array): boolean {
    const expansion: number[] = [];
    for (let i = 0; i < hrp.length; i++) {
        expansion.push(hrp.charCodeAt(i) >> 5);
    }
    expansion.push(0);
    for (let i = 0; i < hrp.length; i++) {
        expansion.push(hrp.charCodeAt(i) & 31);
    }
    
    for (const value of data) {
        expansion.push(value);
    }
    
    let polymod = 1;
    for (const value of expansion) {
        const top = polymod >> 25;
        polymod = ((polymod & 0x1ffffff) << 5) ^ value;
        for (let j = 0; j < 5; j++) {
            if ((top >> j) & 1) {
                polymod ^= GENERATOR[j];
            }
        }
    }
    
    if (encoding === Encoding.BECH32) {
        return polymod === 1;
    } else {
        return polymod === 0x2bc830a3;
    }
}

/**
 * Encoding types
 */
export enum Encoding {
    INVALID = 0,
    BECH32 = 1,
    BECH32M = 2,
}

/**
 * Character limit for Bech32m encoded addresses
 */
export enum CharLimit {
    BECH32 = 90,
}

/**
 * DecodeResult structure
 */
export class DecodeResult {
    encoding: Encoding;
    hrp: string;
    data: Uint8Array;

    constructor() {
        this.encoding = Encoding.INVALID;
        this.hrp = '';
        this.data = new Uint8Array(0);
    }
}

/**
 * Encode a Bech32 or Bech32m string
 */
export function Encode(
    encoding: Encoding,
    hrp: string,
    values: Uint8Array | readonly number[]
): string {
    if (encoding === Encoding.INVALID) return '';
    
    const data = new Uint8Array(values);
    const checksum = createChecksum(encoding, hrp, data);
    const combined = new Uint8Array(data.length + checksum.length);
    combined.set(data);
    combined.set(checksum, data.length);
    
    let result = hrp + '1';
    for (const value of combined) {
        result += CHARSET[value];
    }
    
    return result;
}

/**
 * Decode a Bech32 or Bech32m string
 */
export function Decode(str: string, limit: CharLimit = CharLimit.BECH32): DecodeResult {
    const result = new DecodeResult();
    
    if (str.length < 8 || str.length > limit) return result;
    if (str.toLowerCase() !== str && str.toUpperCase() !== str) return result;
    
    str = str.toLowerCase();
    
    // Find position of separator
    const pos = str.lastIndexOf('1');
    if (pos < 1 || pos + 7 > str.length) return result;
    
    const hrp = str.slice(0, pos);
    if (hrp.length < 1) return result;
    
    // Validate HRP characters
    for (let i = 0; i < hrp.length; i++) {
        const c = hrp.charCodeAt(i);
        if (c < 33 || c > 126) return result;
    }
    
    const dataStr = str.slice(pos + 1);
    
    // Validate data characters
    for (let i = 0; i < dataStr.length; i++) {
        const idx = CHARSET.indexOf(dataStr[i]);
        if (idx === -1) return result;
    }
    
    // Convert characters to values
    const data = new Uint8Array(dataStr.length);
    for (let i = 0; i < dataStr.length; i++) {
        data[i] = CHARSET.indexOf(dataStr[i]);
    }
    
    // Check checksum
    if (!verifyChecksum(Encoding.BECH32, hrp, data)) {
        if (verifyChecksum(Encoding.BECH32M, hrp, data)) {
            result.encoding = Encoding.BECH32M;
        } else {
            return result;
        }
    } else {
        result.encoding = Encoding.BECH32;
    }
    
    result.hrp = hrp;
    result.data = data.slice(0, data.length - 6);
    
    return result;
}

/**
 * Find the positions of errors in a Bech32 string
 */
export function LocateErrors(str: string, limit: CharLimit = CharLimit.BECH32): { error: string; positions: number[] } {
    if (str.length < 8 || str.length > limit) {
        return { error: 'invalid length', positions: [] };
    }
    
    const hasLower = str !== str.toUpperCase();
    const hasUpper = str !== str.toLowerCase();
    
    if (hasLower && hasUpper) {
        return { error: 'mixed case', positions: [] };
    }
    
    str = str.toLowerCase();
    
    const pos = str.lastIndexOf('1');
    if (pos < 1 || pos + 7 > str.length) {
        return { error: 'invalid separator position', positions: [] };
    }
    
    const hrp = str.slice(0, pos);
    const dataStr = str.slice(pos + 1);
    const positions: number[] = [];
    
    // Check HRP
    for (let i = 0; i < hrp.length; i++) {
        const c = hrp.charCodeAt(i);
        if (c < 33 || c > 126) {
            positions.push(i);
        }
    }
    
    // Check data
    for (let i = 0; i < dataStr.length; i++) {
        if (CHARSET.indexOf(dataStr[i]) === -1) {
            positions.push(pos + 1 + i);
        }
    }
    
    if (positions.length > 0) {
        return { error: 'invalid characters', positions };
    }
    
    // Convert to values
    const data = new Uint8Array(dataStr.length);
    for (let i = 0; i < dataStr.length; i++) {
        data[i] = CHARSET.indexOf(dataStr[i]);
    }
    
    // Check checksum
    if (!verifyChecksum(Encoding.BECH32, hrp, data) && !verifyChecksum(Encoding.BECH32M, hrp, data)) {
        return { error: 'invalid checksum', positions: [] };
    }
    
    return { error: '', positions: [] };
}

/**
 * Encode a SegWit address (Bech32)
 */
export function encodeSegWitAddress(hrp: string, version: number, witprog: Uint8Array): string {
    if (version > 16) return '';
    if (witprog.length < 2 || witprog.length > 40) return '';
    if (version === 0 && witprog.length !== 20 && witprog.length !== 32) return '';
    
    const encoding = version === 0 ? Encoding.BECH32 : Encoding.BECH32M;
    
    // Convert to 5-bit groups
    const bits = convertBits(witprog, 8, 5, true);
    if (!bits) return '';
    
    // Prepend version bit
    const data = new Uint8Array(bits.length + 1);
    data[0] = version;
    data.set(bits, 1);
    
    return Encode(encoding, hrp, data);
}

/**
 * Decode a SegWit address
 */
export function decodeSegWitAddress(str: string): { hrp: string; version: number; program: Uint8Array } | null {
    const result = Decode(str);
    if (result.encoding === Encoding.INVALID) return null;
    
    if (result.data.length === 0) return null;
    
    const version = result.data[0];
    if (version > 16) return null;
    
    const program = convertBits(result.data.slice(1), 5, 8, false);
    if (!program) return null;
    
    if (version === 0) {
        if (program.length !== 20 && program.length !== 32) return null;
    } else {
        if (program.length < 2 || program.length > 40) return null;
    }
    
    return { hrp: result.hrp, version, program };
}

// Convenience export
export const SEPARATOR = '1';
export const CHECKSUM_SIZE = 6;
