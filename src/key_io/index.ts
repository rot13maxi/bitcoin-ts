// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Key I/O - encoding/decoding of keys and addresses.
 * This is a TypeScript port of Bitcoin Core's key_io.h/cpp
 */

import { PKHash, ScriptHash, WitnessPKHash, WitnessScriptHash, CTxDestination, CNoDestination, isValidDestination, isPKHash, isScriptHash, isWitnessPKHash, isWitnessScriptHash } from '../script/addresstype';
import { EncodeBase58Check, DecodeBase58Check, decodeBase58Check, encodeBase58Check } from '../base58';
import { encodeSegWitAddress, decodeSegWitAddress, Encoding } from '../bech32';

/**
 * Chain parameters for address encoding
 */
export interface ChainParams {
    pubkeyAddress: number;      // Version byte for P2PKH addresses
    scriptAddress: number;      // Version byte for P2SH addresses
    bech32HRP: string;          // HRP for Bech32 addresses (bc for mainnet)
}

/**
 * Mainnet chain parameters
 */
export const MAINNET: ChainParams = {
    pubkeyAddress: 0x00,
    scriptAddress: 0x05,
    bech32HRP: 'bc',
};

/**
 * Testnet chain parameters
 */
export const TESTNET: ChainParams = {
    pubkeyAddress: 0x6f,
    scriptAddress: 0xc4,
    bech32HRP: 'tb',
};

/**
 * Signet chain parameters
 */
export const SIGNET: ChainParams = {
    pubkeyAddress: 0x6f,
    scriptAddress: 0xc4,
    bech32HRP: 'tb',
};

/**
 * Regtest chain parameters
 */
export const REGTEST: ChainParams = {
    pubkeyAddress: 0x6f,
    scriptAddress: 0xc4,
    bech32HRP: 'bcrt',
};

/**
 * Encode a PKHash destination to address string
 */
export function encodePKHash(pkh: PKHash, params: ChainParams = MAINNET): string {
    const data = new Uint8Array(1 + PKHash.SIZE);
    data[0] = params.pubkeyAddress;
    data.set(pkh.data, 1);
    return EncodeBase58Check(data);
}

/**
 * Encode a ScriptHash destination to address string
 */
export function encodeScriptHash(sh: ScriptHash, params: ChainParams = MAINNET): string {
    const data = new Uint8Array(1 + ScriptHash.SIZE);
    data[0] = params.scriptAddress;
    data.set(sh.data, 1);
    return EncodeBase58Check(data);
}

/**
 * Encode a WitnessPKHash (P2WPKH) to Bech32 address
 */
export function encodeWitnessPKHash(wpkh: WitnessPKHash, params: ChainParams = MAINNET): string {
    return encodeSegWitAddress(params.bech32HRP, 0, wpkh.data);
}

/**
 * Encode a WitnessScriptHash (P2WSH) to Bech32m address
 */
export function encodeWitnessScriptHash(wsh: WitnessScriptHash, params: ChainParams = MAINNET): string {
    return encodeSegWitAddress(params.bech32HRP, 0, wsh.data);
}

/**
 * Encode any CTxDestination to address string
 */
export function encodeDestination(dest: CTxDestination, params: ChainParams = MAINNET): string {
    if (isPKHash(dest)) {
        return encodePKHash(dest, params);
    } else if (isScriptHash(dest)) {
        return encodeScriptHash(dest, params);
    } else if (isWitnessPKHash(dest)) {
        return encodeWitnessPKHash(dest, params);
    } else if (isWitnessScriptHash(dest)) {
        return encodeWitnessScriptHash(dest, params);
    }
    return '';
}

/**
 * Decode a P2PKH or P2SH address string to PKHash or ScriptHash
 */
export function decodeBase58Address(
    str: string,
    params: ChainParams = MAINNET,
    errorMsg?: string[]
): CTxDestination {
    const decoded = decodeBase58Check(str);
    
    if (!decoded) {
        if (errorMsg) errorMsg.push('Invalid Base58Check encoding');
        return new CNoDestination();
    }
    
    const version = decoded.version;
    const payload = decoded.payload;
    
    // Check for P2PKH (version 0)
    if (version === params.pubkeyAddress && payload.length === 20) {
        return new PKHash(payload);
    }
    
    // Check for P2SH (version 5)
    if (version === params.scriptAddress && payload.length === 20) {
        return new ScriptHash(payload);
    }
    
    if (errorMsg) {
        if (version === params.pubkeyAddress || version === params.scriptAddress) {
            errorMsg.push('Invalid length for address (expected 20 bytes)');
        } else {
            errorMsg.push('Invalid or unsupported Base58-encoded address');
        }
    }
    
    return new CNoDestination();
}

/**
 * Decode a Bech32 or Bech32m address string
 */
export function decodeBech32Address(
    str: string,
    params: ChainParams = MAINNET,
    errorMsg?: string[]
): CTxDestination {
    const decoded = decodeSegWitAddress(str);
    
    if (!decoded) {
        if (errorMsg) errorMsg.push('Invalid Bech32/Bech32m encoding');
        return new CNoDestination();
    }
    
    // Check HRP matches
    if (decoded.hrp.toLowerCase() !== params.bech32HRP.toLowerCase()) {
        if (errorMsg) errorMsg.push(`Invalid HRP (expected ${params.bech32HRP}, got ${decoded.hrp})`);
        return new CNoDestination();
    }
    
    const { version, program } = decoded;
    
    // Version 0 witness programs
    if (version === 0) {
        if (program.length === 20) {
            return new WitnessPKHash(program);
        }
        if (program.length === 32) {
            return new WitnessScriptHash(program);
        }
        if (errorMsg) errorMsg.push(`Invalid v0 program size (expected 20 or 32, got ${program.length})`);
        return new CNoDestination();
    }
    
    // Version 1 (Taproot) - 32 bytes
    if (version === 1 && program.length === 32) {
        return new WitnessScriptHash(program);
    }
    
    // Other versions - return as unknown witness
    if (version > 16) {
        if (errorMsg) errorMsg.push('Invalid witness version');
        return new CNoDestination();
    }
    
    if (program.length < 2 || program.length > 40) {
        if (errorMsg) errorMsg.push(`Invalid witness program size (got ${program.length})`);
        return new CNoDestination();
    }
    
    // Return as witness unknown for version > 0 with valid program
    return new CNoDestination();
}

/**
 * Decode any Bitcoin address string to CTxDestination
 */
export function decodeDestination(
    str: string,
    params: ChainParams = MAINNET,
    errorMsg?: string[]
): CTxDestination {
    const errors: string[] = [];
    
    // Try Bech32 first (check HRP prefix)
    const hrpLower = str.substring(0, params.bech32HRP.length).toLowerCase();
    if (hrpLower === params.bech32HRP.toLowerCase()) {
        const result = decodeBech32Address(str, params, errors);
        if (!(result instanceof CNoDestination) || errors.length === 0) {
            if (errorMsg && errors.length > 0) errorMsg.push(...errors);
            return result;
        }
    }
    
    // Try Base58Check
    errors.length = 0;
    const result = decodeBase58Address(str, params, errors);
    if (!(result instanceof CNoDestination) || errors.length === 0) {
        if (errorMsg && errors.length > 0) errorMsg.push(...errors);
        return result;
    }
    
    if (errorMsg) errorMsg.push('Invalid or unsupported address encoding');
    return new CNoDestination();
}

/**
 * Check if a string is a valid Bitcoin address
 */
export function isValidDestinationString(str: string, params: ChainParams = MAINNET): boolean {
    const dest = decodeDestination(str, params);
    return !(dest instanceof CNoDestination);
}

// Re-export for convenience
export { PKHash, ScriptHash, WitnessPKHash, WitnessScriptHash, CNoDestination };
export type { CTxDestination };
export { isPKHash, isScriptHash, isWitnessPKHash, isWitnessScriptHash, isValidDestination } from '../script/addresstype';
