// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Bitcoin Core Primitives - TypeScript port of Bitcoin Core primitives/transaction.h
 * 
 * Core transaction types: COutPoint, CTxIn, CTxOut, CTransaction
 */

/**
 * OutPoint refers to a specific spendable output of a transaction.
 * It combines the transaction ID (hash) with the output index (n).
 */
export interface COutPoint {
    /** The hash of the containing transaction */
    hash: Uint8Array;  // uint256
    /** The index of the output within the transaction (0 = first output) */
    n: number;
}

/**
 * Create a new COutPoint
 */
export function outpoint(hash: Uint8Array, n: number): COutPoint {
    return { hash: hash.slice(), n };
}

/**
 * Txid is a transaction id (hash of the transaction, without witness data)
 */
export type Txid = Uint8Array;

/**
 * Wtxid is a transaction id including witness data
 */
export type Wtxid = Uint8Array;

/**
 * Script identifier (hash of the script)
 */
export type ScriptHash = Uint8Array;

/**
 * WitProgram is an indexed witness program
 */
export interface WitProgram {
    version: number;
    program: Uint8Array;
}

/**
 * CTxIn defines a transaction input (spending an output)
 */
export interface CTxIn {
    /** The previous outpoint being spent */
    prevout: COutPoint;
    /** The script that satisfies the spending conditions */
    scriptSig: Uint8Array;
    /** Sequence number (used for RBF, timelocks) */
    nSequence: number;
    /** Witness data (for SegWit transactions) */
    scriptWitness?: Uint8Array[];
}

/**
 * CTxOut defines a transaction output (receiving coins)
 */
export interface CTxOut {
    /** The value of this output in satoshis */
    nValue: bigint;
    /** The script that must be satisfied to spend this output */
    scriptPubKey: Uint8Array;
}

/**
 * Check if a CTxOut is null (spent)
 */
export function txoutIsNull(txout: CTxOut): boolean {
    return txout.nValue === 0n && txout.scriptPubKey.length === 0;
}

/**
 * Default nSequence for transactions with no inputs marked as final
 */
export const SEQUENCE_FINAL = 0xffffffff;

/**
 * Sequence number disable flag (allows input to be excluded from relative locktime)
 */
export const SEQUENCE_LOCKTIME_DISABLE_FLAG = 0x80000000;

/**
 * Sequence number type flag (uses time-based locktime rather than height)
 */
export const SEQUENCE_LOCKTIME_TYPE_FLAG = 0x40000000;

/**
 * Mask for extracting sequence number (lower 16 bits)
 */
export const SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

/**
 * Granularity for time-based locktime (in seconds)
 */
export const SEQUENCE_LOCKTIME_GRANULARITY = 9;

/**
 * CTxOutCompressor - wraps CTxOut for variable-length value encoding
 */
export class CTxOutCompressor {
    static serialize(txout: CTxOut): Uint8Array {
        // Serialize with compressed value encoding
        const value = txout.nValue;
        const script = txout.scriptPubKey;
        
        // For compact encoding, use VarInt for small values
        // This is a simplified version - full implementation uses special encoding
        const result: number[] = [];
        
        // Simple VarInt for value (most values will fit in a few bytes)
        let v = value;
        while (v > 0x7f) {
            result.push((Number(v) & 0x7f) | 0x80);
            v >>= 7n;
        }
        result.push(Number(v));
        
        // Push script as length-prefixed data
        result.push(script.length, ...script);
        
        return new Uint8Array(result);
    }

    static deserialize(data: Uint8Array, offset: number = 0): { txout: CTxOut; bytesRead: number } {
        // Simplified - read VarInt for value, then script
        let value = 0n;
        let shift = 0;
        let pos = offset;
        
        while (pos < data.length) {
            const byte = data[pos++];
            value |= BigInt(byte & 0x7f) << BigInt(shift);
            if (!(byte & 0x80)) break;
            shift += 7;
        }
        
        const scriptLen = data[pos++];
        const script = data.slice(pos, pos + scriptLen);
        
        return {
            txout: { nValue: value, scriptPubKey: script },
            bytesRead: pos + scriptLen - offset
        };
    }
}

/**
 * CTransaction represents a complete Bitcoin transaction
 */
export interface CTransaction {
    /** Input transactions */
    vin: CTxIn[];
    /** Output transactions */
    vout: CTxOut[];
    /** Lock time - earliest block height or timestamp when this tx can be mined */
    nLockTime: number;
    /** Transaction version number */
    version: number;
    
    /** Check if this is a coinbase transaction */
    isCoinBase(): boolean;
    
    /** Get total value of outputs */
    getValueOut(): bigint;
    
    /** Check if transaction has witness data */
    hasWitness(): boolean;
    
    /** Compute total serialized size */
    computeTotalSize(): number;
}

/**
 * Check if transaction is a coinbase transaction (first input spends non-existent output)
 */
export function isCoinBase(tx: CTransaction, prevoutIndex: number = 0): boolean {
    if (tx.vin.length === 0) return false;
    if (prevoutIndex >= tx.vin.length) return false;
    const vin0 = tx.vin[prevoutIndex];
    // Coinbase has empty prevout hash (all zeros) and max sequence
    const hashEmpty = vin0.prevout.hash.every(b => b === 0);
    return hashEmpty && vin0.prevout.n === 0xffffffff && vin0.nSequence === 0xffffffff;
}

/**
 * Get total output value
 */
export function getValueOut(tx: CTransaction): bigint {
    return tx.vout.reduce((sum, vout) => sum + vout.nValue, 0n);
}

/**
 * Check if transaction has witness data
 */
export function hasWitness(tx: CTransaction): boolean {
    return tx.vin.some(vin => vin.scriptWitness && vin.scriptWitness.length > 0);
}

/**
 * Compute total serialized size including witness
 */
export function computeTotalSize(tx: CTransaction): number {
    return serializeTransaction(tx).length;
}

/**
 * Get the wit hash (hash with witness data) for witness commit
 */
export function getWitnessCommitment(tx: CTransaction): Uint8Array | null {
    // Calculate witness commit: SHA256 of witness root + witness reserved value
    // This is part of the witness commitment calculation for SegWit
    // Simplified - full implementation is more complex
    return null;
}

/**
 * Basic transaction to its string representation
 */
export function txidToString(txid: Txid): string {
    return Array.from(txid).reverse().map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Get the transaction hash (hash of the serialized transaction)
 */
export function getTransactionHash(tx: CTransaction): Uint8Array {
    // Serialize and hash - using simple SHA256
    // This is a placeholder - full implementation requires proper serialization
    const data = serializeTransaction(tx);
    return sha256(sha256(data));
}

// Import sha256 for hashing
import { sha256 } from './crypto/sha256';

/**
 * Serialize a transaction to bytes (basic implementation)
 */
export function serializeTransaction(tx: CTransaction): Uint8Array {
    const parts: number[] = [];
    
    // Version
    const version = new Uint8Array(4);
    new DataView(version.buffer).setUint32(0, tx.version, true);
    parts.push(...version);
    
    // Inputs
    const vinLen = encodeVarInt(tx.vin.length);
    parts.push(...vinLen);
    for (const vin of tx.vin) {
        parts.push(...vin.prevout.hash);
        const nBuf = new Uint8Array(4);
        new DataView(nBuf.buffer).setUint32(0, vin.prevout.n, true);
        parts.push(...nBuf);
        parts.push(...encodeVarInt(vin.scriptSig.length));
        parts.push(...vin.scriptSig);
        const seqBuf = new Uint8Array(4);
        new DataView(seqBuf.buffer).setUint32(0, vin.nSequence, true);
        parts.push(...seqBuf);
    }
    
    // Outputs
    const voutLen = encodeVarInt(tx.vout.length);
    parts.push(...voutLen);
    for (const vout of tx.vout) {
        // Value as VarInt
        let v = vout.nValue;
        while (v > 0x7fn) {
            parts.push(Number(v & 0x7fn) | 0x80);
            v >>= 7n;
        }
        parts.push(Number(v));
        // ScriptPubKey
        parts.push(...encodeVarInt(vout.scriptPubKey.length));
        parts.push(...vout.scriptPubKey);
    }
    
    // LockTime
    const lockBuf = new Uint8Array(4);
    new DataView(lockBuf.buffer).setUint32(0, tx.nLockTime, true);
    parts.push(...lockBuf);
    
    return new Uint8Array(parts);
}

/**
 * Encode a number as a Bitcoin VarInt (variable-length integer)
 */
export function encodeVarInt(n: number): number[] {
    const result: number[] = [];
    while (n > 0x7f) {
        result.push((n & 0x7f) | 0x80);
        n >>= 7;
    }
    result.push(n);
    return result;
}

/**
 * Decode a Bitcoin VarInt from bytes
 */
export function decodeVarInt(data: Uint8Array, offset: number = 0): { value: number; bytesRead: number } {
    let result = 0;
    let shift = 0;
    let pos = offset;
    while (pos < data.length) {
        const byte = data[pos++];
        result |= (byte & 0x7f) << shift;
        if (!(byte & 0x80)) break;
        shift += 7;
    }
    return { value: result, bytesRead: pos - offset };
}

/**
 * Calculate the base size of a transaction (without witness data)
 */
export function getTransactionBaseSize(tx: CTransaction): number {
    // Weight / 4 (stripped of witness data)
    let size = 4; // version
    size += encodeVarInt(tx.vin.length).length;
    for (const vin of tx.vin) {
        size += 32 + 4 + encodeVarInt(vin.scriptSig.length).length + vin.scriptSig.length + 4;
    }
    size += encodeVarInt(tx.vout.length).length;
    for (const vout of tx.vout) {
        size += 8 + encodeVarInt(vout.scriptPubKey.length).length + vout.scriptPubKey.length;
    }
    size += 4; // locktime
    return size;
}

/**
 * Calculate the total size of a transaction including witness data
 */
export function getTransactionTotalSize(tx: CTransaction): number {
    // Get stripped size + witness data (1 byte per input/output, compact uint for witness item count, then each witness item)
    return getTransactionBaseSize(tx) + getWitnessSize(tx);
}

/**
 * Calculate witness data size
 */
export function getWitnessSize(tx: CTransaction): number {
    let size = 2; // marker and flag
    size += encodeVarInt(tx.vin.length).length;
    for (const vin of tx.vin) {
        if (vin.scriptWitness) {
            size += encodeVarInt(vin.scriptWitness.length).length;
            for (const item of vin.scriptWitness) {
                size += encodeVarInt(item.length).length + item.length;
            }
        }
    }
    return size;
}

/**
 * Calculate the virtual transaction size (for fee estimation)
 */
export function getVirtualTransactionSize(tx: CTransaction, sigOpCount: number = 0): number {
    const baseSize = getTransactionBaseSize(tx);
    const witnessSize = getWitnessSize(tx);
    const totalSize = baseSize + witnessSize;
    const weight = totalSize * 3 + baseSize;
    return Math.floor(weight / 4) + sigOpCount;
}
