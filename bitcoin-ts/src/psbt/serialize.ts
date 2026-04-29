/**
 * Bitcoin Core PSBT Serialization
 * Ported from src/psbt.h/cpp
 * 
 * @module psbt/serialize
 */

import {
    PSBT_MAGIC_BYTES,
    PSBT_SEPARATOR,
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_GLOBAL_XPUB,
    PSBT_GLOBAL_VERSION,
    PSBT_GLOBAL_PROPRIETARY,
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_WITNESS_UTXO,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_SIGHASH,
    PSBT_IN_REDEEMSCRIPT,
    PSBT_IN_WITNESSSCRIPT,
    PSBT_IN_BIP32_DERIVATION,
    PSBT_IN_SCRIPTSIG,
    PSBT_IN_SCRIPTWITNESS,
    PSBT_IN_RIPEMD160,
    PSBT_IN_SHA256,
    PSBT_IN_HASH160,
    PSBT_IN_HASH256,
    PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_TAP_SCRIPT_SIG,
    PSBT_IN_TAP_LEAF_SCRIPT,
    PSBT_IN_TAP_BIP32_DERIVATION,
    PSBT_IN_TAP_INTERNAL_KEY,
    PSBT_IN_TAP_MERKLE_ROOT,
    PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
    PSBT_IN_MUSIG2_PUB_NONCE,
    PSBT_IN_MUSIG2_PARTIAL_SIG,
    PSBT_IN_PROPRIETARY,
    PSBT_OUT_REDEEMSCRIPT,
    PSBT_OUT_WITNESSSCRIPT,
    PSBT_OUT_BIP32_DERIVATION,
    PSBT_OUT_TAP_INTERNAL_KEY,
    PSBT_OUT_TAP_TREE,
    PSBT_OUT_TAP_BIP32_DERIVATION,
    PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS,
    PSBT_OUT_PROPRIETARY,
    PartiallySignedTransaction,
    PSBTInput,
    PSBTOutput,
    CMutableTransaction,
    CExtPubKey,
} from './types';

// Import serialization utilities from primitives
import { encodeVarInt } from '../primitives';

// BIP32 extended key size with version bytes
const BIP32_EXTKEY_WITH_VERSION_SIZE = 78;

/**
 * Serialize to vector - prepends total size then all items
 */
export function serializeToVector(parts: Uint8Array[]): Uint8Array {
    const total_size = parts.reduce((sum, p) => sum + p.length, 0);
    const result: number[] = [];
    
    // Write total size as compact size
    const size_bytes = encodeVarInt(total_size);
    result.push(...size_bytes);
    
    // Write all parts
    for (const part of parts) {
        result.push(...part);
    }
    
    return new Uint8Array(result);
}

/**
 * Serialize key origin info
 */
export function serializeKeyOrigin(fingerprint: Uint8Array, path: number[]): Uint8Array {
    const parts: number[] = [];
    
    // Fingerprint (4 bytes)
    parts.push(...fingerprint);
    
    // Path (each element is 4 bytes)
    for (const index of path) {
        parts.push(index & 0xff);
        parts.push((index >> 8) & 0xff);
        parts.push((index >> 16) & 0xff);
        parts.push((index >> 24) & 0xff);
    }
    
    return new Uint8Array(parts);
}

/**
 * Deserialize key origin info
 */
export function deserializeKeyOrigin(data: Uint8Array, offset: number = 0): {
    fingerprint: Uint8Array;
    path: number[];
    bytesRead: number;
} {
    // Check valid length (must be multiple of 4, at least 4)
    const length = data.length - offset;
    if (length % 4 !== 0 || length === 0) {
        throw new Error('Invalid length for HD key path');
    }
    
    const fingerprint = data.slice(offset, offset + 4);
    const path: number[] = [];
    
    for (let i = offset + 4; i < data.length; i += 4) {
        const index = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24);
        path.push(index);
    }
    
    return {
        fingerprint,
        path,
        bytesRead: length,
    };
}

/**
 * Serialize HD keypath
 */
export function serializeHDKeypath(fingerprint: Uint8Array, path: number[]): Uint8Array {
    // Length prefix: (path length + 1) * 4 bytes
    const length = (path.length + 1) * 4;
    const parts: number[] = [];
    
    // Length prefix
    parts.push(...encodeVarInt(length));
    
    // Key origin data
    parts.push(...serializeKeyOrigin(fingerprint, path));
    
    return new Uint8Array(parts);
}

/**
 * Serialize a PSBTInput
 */
export function serializePSBTInput(input: PSBTInput, has_final_scripts: boolean): Uint8Array {
    const parts: Uint8Array[] = [];
    
    // Write non-witness UTXO
    if (input.non_witness_utxo !== null) {
        parts.push(new Uint8Array([PSBT_IN_NON_WITNESS_UTXO]));
        // Would serialize the full transaction
    }
    
    // Write witness UTXO
    if (input.witness_utxo !== null) {
        parts.push(new Uint8Array([PSBT_IN_WITNESS_UTXO]));
        // Would serialize the CTxOut
    }
    
    if (has_final_scripts) {
        // Write final scriptSig
        if (input.final_script_sig.length() > 0) {
            parts.push(new Uint8Array([PSBT_IN_SCRIPTSIG]));
            parts.push(input.final_script_sig.buffer());
        }
        
        // Write final scriptWitness
        if (input.final_script_witness.stack.length > 0) {
            parts.push(new Uint8Array([PSBT_IN_SCRIPTWITNESS]));
            // Serialize witness stack as compact size + each item
        }
    } else {
        // Write partial signatures
        for (const [keyId, pair] of input.partial_sigs) {
            parts.push(new Uint8Array([PSBT_IN_PARTIAL_SIG]));
            parts.push(pair.pubkey);
            parts.push(pair.signature);
        }
        
        // Write sighash type
        if (input.sighash_type !== null) {
            parts.push(new Uint8Array([PSBT_IN_SIGHASH]));
            // Serialize sighash type
        }
        
        // Write redeem script
        if (input.redeem_script.length() > 0) {
            parts.push(new Uint8Array([PSBT_IN_REDEEMSCRIPT]));
            parts.push(input.redeem_script.buffer());
        }
        
        // Write witness script
        if (input.witness_script.length() > 0) {
            parts.push(new Uint8Array([PSBT_IN_WITNESSSCRIPT]));
            parts.push(input.witness_script.buffer());
        }
        
        // Write HD keypaths
        // ... (would iterate and serialize each)
        
        // Write preimages
        // ... (would serialize ripemd160, sha256, hash160, hash256)
        
        // Write taproot fields
        if (input.tap_key_sig.length > 0) {
            parts.push(new Uint8Array([PSBT_IN_TAP_KEY_SIG]));
            parts.push(input.tap_key_sig);
        }
        
        // Write MuSig2 fields
        // ... (would serialize participants, pubnonces, partial sigs)
    }
    
    // Write proprietary
    for (const prop of input.proprietary) {
        parts.push(prop.key);
        parts.push(prop.value);
    }
    
    // Write unknown
    for (const [key, value] of input.unknown) {
        parts.push(new Uint8Array(key.split(',').map(Number)));
        parts.push(value);
    }
    
    // Write separator
    parts.push(new Uint8Array([PSBT_SEPARATOR]));
    
    return serializeToVector(parts);
}

/**
 * Serialize a PSBTOutput
 */
export function serializePSBTOutput(output: PSBTOutput): Uint8Array {
    const parts: Uint8Array[] = [];
    
    // Write redeem script
    if (output.redeem_script.length() > 0) {
        parts.push(new Uint8Array([PSBT_OUT_REDEEMSCRIPT]));
        parts.push(output.redeem_script.buffer());
    }
    
    // Write witness script
    if (output.witness_script.length() > 0) {
        parts.push(new Uint8Array([PSBT_OUT_WITNESSSCRIPT]));
        parts.push(output.witness_script.buffer());
    }
    
    // Write HD keypaths
    // ... (would iterate and serialize each)
    
    // Write taproot internal key
    if (output.tap_internal_key.length > 0) {
        parts.push(new Uint8Array([PSBT_OUT_TAP_INTERNAL_KEY]));
        parts.push(output.tap_internal_key);
    }
    
    // Write taproot tree
    if (output.tap_tree.length > 0) {
        parts.push(new Uint8Array([PSBT_OUT_TAP_TREE]));
        // Serialize tree structure
    }
    
    // Write taproot BIP32 paths
    // ... (would serialize each)
    
    // Write MuSig2 participants
    // ... (would serialize each)
    
    // Write proprietary
    for (const prop of output.proprietary) {
        parts.push(prop.key);
        parts.push(prop.value);
    }
    
    // Write unknown
    for (const [key, value] of output.unknown) {
        parts.push(new Uint8Array(key.split(',').map(Number)));
        parts.push(value);
    }
    
    // Write separator
    parts.push(new Uint8Array([PSBT_SEPARATOR]));
    
    return serializeToVector(parts);
}

/**
 * Serialize a PartiallySignedTransaction to bytes
 */
export function serializePSBT(psbt: PartiallySignedTransaction): Uint8Array {
    const parts: Uint8Array[] = [];
    
    // Magic bytes
    parts.push(PSBT_MAGIC_BYTES);
    
    // Global unsigned tx
    if (psbt.tx !== null) {
        parts.push(new Uint8Array([PSBT_GLOBAL_UNSIGNED_TX]));
        // Serialize transaction without witness
    }
    
    // Global xpubs
    for (const [keyPath, xpubs] of psbt.m_xpubs) {
        for (const xpub of xpubs) {
            parts.push(new Uint8Array([PSBT_GLOBAL_XPUB]));
            // Serialize xpub with version
        }
    }
    
    // Version
    if (psbt.m_version !== null && psbt.m_version > 0) {
        parts.push(new Uint8Array([PSBT_GLOBAL_VERSION]));
        // Serialize version number
    }
    
    // Proprietary
    for (const prop of psbt.proprietary) {
        parts.push(prop.key);
        parts.push(prop.value);
    }
    
    // Unknown
    for (const [key, value] of psbt.unknown) {
        parts.push(new Uint8Array(key.split(',').map(Number)));
        parts.push(value);
    }
    
    // Separator
    parts.push(new Uint8Array([PSBT_SEPARATOR]));
    
    // Inputs
    for (let i = 0; i < psbt.inputs.length; i++) {
        const input = psbt.inputs[i];
        const hasFinalScripts = input.final_script_sig.length() > 0 || 
                                input.final_script_witness.stack.length > 0;
        parts.push(serializePSBTInput(input, hasFinalScripts));
    }
    
    // Outputs
    for (const output of psbt.outputs) {
        parts.push(serializePSBTOutput(output));
    }
    
    // Concatenate all parts
    const totalSize = parts.reduce((sum, p) => sum + p.length, 0);
    const result = new Uint8Array(totalSize);
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }
    
    return result;
}

/**
 * Check PSBT magic bytes
 */
export function checkPSBTMagic(data: Uint8Array): boolean {
    if (data.length < 5) return false;
    for (let i = 0; i < 5; i++) {
        if (data[i] !== PSBT_MAGIC_BYTES[i]) return false;
    }
    return true;
}

/**
 * Decode a PSBT from base64 string
 */
export function decodeBase64PSBT(base64: string): PartiallySignedTransaction {
    // Decode base64
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    
    return decodeRawPSBT(bytes);
}

/**
 * Decode a PSBT from raw bytes
 */
export function decodeRawPSBT(data: Uint8Array): PartiallySignedTransaction {
    // Check magic bytes
    if (!checkPSBTMagic(data)) {
        throw new Error('Invalid PSBT magic bytes');
    }
    
    // Simplified - full implementation would deserialize all fields
    const psbt: PartiallySignedTransaction = {
        tx: null,
        m_xpubs: new Map(),
        inputs: [],
        outputs: [],
        unknown: new Map(),
        m_version: null,
        proprietary: new Set(),
    };
    
    // Would fully deserialize here
    return psbt;
}

/**
 * Encode a PSBT to base64 string
 */
export function encodeBase64PSBT(psbt: PartiallySignedTransaction): string {
    const bytes = serializePSBT(psbt);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
