// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Bitcoin Core primitive types
 */

import { Stream, serializeUInt32LE, unserializeUInt32LE, serializeInt64LE, unserializeInt64LE } from '../serialize';
import { uint256, Txid, Wtxid } from '../uint256';

export const COIN = 100000000n;
export const SATOSHI = 1n;

export type CAmount = bigint;

export class COutPoint {
    static readonly NULL_INDEX = 0xffffffff;

    hash: Txid;
    n: number;

    constructor(hash?: Txid, n?: number) {
        this.hash = hash ?? new Txid();
        this.n = n ?? COutPoint.NULL_INDEX;
    }

    setNull(): void {
        this.hash.setNull();
        this.n = COutPoint.NULL_INDEX;
    }

    isNull(): boolean {
        return this.hash.isNull() && this.n === COutPoint.NULL_INDEX;
    }

    serialize(stream: Stream): void {
        stream.write(this.hash.data());
        serializeUInt32LE(stream, this.n);
    }

    unserialize(stream: Stream): void {
        const data = stream.read(32);
        this.hash = new Txid(data);
        this.n = unserializeUInt32LE(stream);
    }

    toString(): string {
        return `${this.hash.toString()}:${this.n}`;
    }
}

export const SEQUENCE_FINAL = 0xffffffff;
export const MAX_SEQUENCE_NONFINAL = SEQUENCE_FINAL - 1;
export const SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31;
export const SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22;
export const SEQUENCE_LOCKTIME_MASK = 0x0000ffff;
export const SEQUENCE_LOCKTIME_GRANULARITY = 9;

export class CTxIn {
    prevout: COutPoint;
    scriptSig: Uint8Array;
    nSequence: number;
    scriptWitness: CScriptWitness;

    constructor(prevout?: COutPoint, scriptSig?: Uint8Array, nSequence?: number) {
        this.prevout = prevout ?? new COutPoint();
        this.scriptSig = scriptSig ?? new Uint8Array(0);
        this.nSequence = nSequence ?? SEQUENCE_FINAL;
        this.scriptWitness = new CScriptWitness();
    }

    serialize(stream: Stream): void {
        this.prevout.serialize(stream);
        stream.write(this.scriptSig);
        serializeUInt32LE(stream, this.nSequence);
    }

    unserialize(stream: Stream): void {
        this.prevout = new COutPoint();
        this.prevout.unserialize(stream);
        const scriptSigLen = stream.readCompactSize();
        this.scriptSig = stream.read(scriptSigLen);
        this.nSequence = unserializeUInt32LE(stream);
    }

    toString(): string {
        return `CTxIn(prevout=${this.prevout.toString()}, nSequence=${this.nSequence})`;
    }
}

export class CTxOut {
    nValue: CAmount;
    scriptPubKey: Uint8Array;

    constructor(nValue?: CAmount, scriptPubKey?: Uint8Array) {
        this.nValue = nValue ?? -1n;
        this.scriptPubKey = scriptPubKey ?? new Uint8Array(0);
    }

    setNull(): void {
        this.nValue = -1n;
        this.scriptPubKey = new Uint8Array(0);
    }

    isNull(): boolean {
        return this.nValue === -1n;
    }

    serialize(stream: Stream): void {
        serializeInt64LE(stream, this.nValue);
        stream.writeCompactSize(this.scriptPubKey.length);
        stream.write(this.scriptPubKey);
    }

    unserialize(stream: Stream): void {
        this.nValue = unserializeInt64LE(stream);
        const scriptPubKeyLen = stream.readCompactSize();
        this.scriptPubKey = stream.read(scriptPubKeyLen);
    }

    toString(): string {
        return `CTxOut(value=${this.nValue})`;
    }
}

export class CScriptWitness {
    stack: Uint8Array[];

    constructor() {
        this.stack = [];
    }

    isNull(): boolean {
        return this.stack.length === 0;
    }

    serialize(stream: Stream): void {
        stream.writeCompactSize(this.stack.length);
        for (const item of this.stack) {
            stream.writeCompactSize(item.length);
            stream.write(item);
        }
    }

    unserialize(stream: Stream): void {
        const count = stream.readCompactSize();
        this.stack = [];
        for (let i = 0; i < count; i++) {
            const itemLen = stream.readCompactSize();
            this.stack.push(stream.read(itemLen));
        }
    }
}

export interface TransactionSerParams {
    allowWitness: boolean;
}

export const TX_WITH_WITNESS: TransactionSerParams = { allowWitness: true };
export const TX_NO_WITNESS: TransactionSerParams = { allowWitness: false };

export class CMutableTransaction {
    vin: CTxIn[];
    vout: CTxOut[];
    version: number;
    nLockTime: number;

    constructor() {
        this.vin = [];
        this.vout = [];
        this.version = 2;
        this.nLockTime = 0;
    }

    hasWitness(): boolean {
        for (const input of this.vin) {
            if (!input.scriptWitness.isNull()) {
                return true;
            }
        }
        return false;
    }

    serialize(stream: Stream): void {
        const params = stream.getParams<TransactionSerParams>() ?? TX_WITH_WITNESS;
        serializeTransaction(this, stream, params);
    }

    getHash(): Txid {
        return new Txid();
    }
}

export class CTransaction {
    static readonly CURRENT_VERSION = 2;

    readonly vin: readonly CTxIn[];
    readonly vout: readonly CTxOut[];
    readonly version: number;
    readonly nLockTime: number;
    private readonly m_hasWitness: boolean;
    private readonly m_hash: Txid;
    private readonly m_witnessHash: Wtxid;

    constructor(tx: CMutableTransaction) {
        this.vin = Object.freeze(tx.vin.slice());
        this.vout = Object.freeze(tx.vout.slice());
        this.version = tx.version;
        this.nLockTime = tx.nLockTime;
        this.m_hasWitness = tx.hasWitness();
        this.m_hash = new Txid();
        this.m_witnessHash = new Wtxid();
    }

    isNull(): boolean {
        return this.vin.length === 0 && this.vout.length === 0;
    }

    getHash(): Txid {
        return this.m_hash;
    }

    getWitnessHash(): Wtxid {
        return this.m_witnessHash;
    }

    getValueOut(): CAmount {
        let total = 0n;
        for (const output of this.vout) {
            total += output.nValue;
        }
        return total;
    }

    computeTotalSize(): number {
        const baseSize = 4 + this.vin.length * 32 + this.vin.length * 4 + 
            this.vout.length * 8 + this.vout.reduce((sum, out) => sum + out.scriptPubKey.length + 8, 0) + 4;
        return baseSize;
    }

    isCoinBase(): boolean {
        return this.vin.length === 1 && this.vin[0].prevout.isNull();
    }

    hasWitness(): boolean {
        return this.m_hasWitness;
    }

    toString(): string {
        return `CTransaction(hash=${this.m_hash.toString()})`;
    }
}

function serializeTransaction<T extends CMutableTransaction>(
    tx: T,
    stream: Stream,
    params: TransactionSerParams
): void {
    serializeUInt32LE(stream, tx.version);
    let flags = 0;

    if (params.allowWitness && tx.hasWitness()) {
        flags |= 1;
    }

    if (flags !== 0) {
        stream.writeCompactSize(0);
        stream.write(new Uint8Array([flags]));
    }

    stream.writeCompactSize(tx.vin.length);
    for (const input of tx.vin) {
        input.serialize(stream);
    }

    stream.writeCompactSize(tx.vout.length);
    for (const output of tx.vout) {
        output.serialize(stream);
    }

    if (flags & 1) {
        for (const input of tx.vin) {
            input.scriptWitness.serialize(stream);
        }
    }

    serializeUInt32LE(stream, tx.nLockTime);
}

export type CTransactionRef = CTransaction;

export function makeTransactionRef(tx: CMutableTransaction | CTransaction): CTransactionRef {
    if (tx instanceof CMutableTransaction) {
        return new CTransaction(tx);
    }
    return tx;
}

/**
 * Represents a transaction identifier, either a txid or wtxid.
 * Used throughout the transaction request tracking system.
 */
export class GenTxid {
    private readonly m_is_wtxid: boolean;
    private readonly m_hash: uint256;

    constructor(is_wtxid: boolean, hash: uint256) {
        this.m_is_wtxid = is_wtxid;
        this.m_hash = hash;
    }

    /** Create a GenTxid from a txid */
    static fromTxid(txid: Txid): GenTxid {
        return new GenTxid(false, txid);
    }

    /** Create a GenTxid from a wtxid */
    static fromWtxid(wtxid: Wtxid): GenTxid {
        return new GenTxid(true, wtxid);
    }

    isWtxid(): boolean {
        return this.m_is_wtxid;
    }

    getHash(): uint256 {
        return this.m_hash;
    }

    /** Convert to Uint256 for use as a key in maps */
    ToUint256(): uint256 {
        return this.m_hash;
    }

    equals(other: GenTxid): boolean {
        return this.m_is_wtxid === other.m_is_wtxid &&
            this.m_hash.compare(other.m_hash) === 0;
    }

    toString(): string {
        return this.m_is_wtxid ? `wtxid:${this.m_hash.toString()}` : `txid:${this.m_hash.toString()}`;
    }
}

/**
 * A reference to a transaction output (CTransaction wrapper).
 * This is a lightweight reference type used throughout the codebase.
 */
export type TxRef = CTransactionRef;

/**
 * Check if a transaction is a standard coinbase transaction.
 */
export function IsCoinBase(tx: CTransaction): boolean {
    return tx.isCoinBase();
}

/**
 * Transaction input sequence number constants.
 */
export const DEFAULT_MAX_REPLACEMENT_FEE = 0; // RBF disabled by default

/**
 * Calculate the virtual transaction size (weight / 4).
 */
export function GetVirtualTransactionSize(tx: CTransaction): number {
    // Weight is computed as: base_size * 3 + total_size
    // Virtual size = weight / 4 = (base_size * 3 + total_size) / 4
    // For simplicity, approximate as total_size (since most txs don't have witness)
    return Math.ceil(tx.computeTotalSize() / 4);
}
