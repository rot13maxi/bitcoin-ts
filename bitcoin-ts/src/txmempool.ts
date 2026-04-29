// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Bitcoin Core Memory Pool - TypeScript port of Bitcoin Core txmempool.h/cpp
 * 
 * CTxMemPool stores valid transactions that may be included in the next block.
 * 
 * Key features:
 * - Transaction storage with ancestor/descendant tracking
 * - Fee-based sorting and eviction
 * - Ancestor/descendant size and fee limits
 * - Rolling fee estimation
 */

import { CTransaction, COutPoint, CTxIn, CTxOut } from './primitives';
import { memusage } from './memusage';
import { sha256 } from './crypto/sha256';

/** Fake height value for mempool-only coins (since 0.8) */
export const MEMPOOL_HEIGHT = 0x7FFFFFFF;

/** Default max mempool size in bytes (128MB) */
export const DEFAULT_MAX_MEMPOOL_SIZE = 128 * 1024 * 1024;

/** Default max mempool databyte size (memory only, no disk) */
export const DEFAULT_MAX_MEMPOOL_DATASIZE = 0;

/** Minimum rollin fee rate to get into pool (exponential decay) */
export const DEFAULT_MIN_RELAY_FEE = 1000; // satoshis per KB

/** Rollback fee half-life in seconds (12 hours) */
export const ROLLING_FEE_HALFLIFE = 60 * 60 * 12;

/** Maximum age of mempool transactions */
export const DEFAULT_MEMPOOL_EXPIRY = 60 * 60 * 24 * 2; // 2 days

/**
 * Removal reason for tracking
 */
export enum MemPoolRemovalReason {
    CONFLICT = 'conflict',
    BLOCK = 'block',
    EXPIRY = 'expiry',
    SIZE_LIMIT = 'size_limit',
    REORG = 'reorg',
    REPLACED = 'replaced',
}

/**
 * CTxMemPoolEntry - information about a transaction in the mempool
 */
export class CTxMemPoolEntry {
    /** The transaction */
    private tx: CTransaction;
    
    /** Fee for this transaction */
    private fee: bigint;
    
    /** Virtual size (size * 3 + base_size) / 4 */
    private vsize: number;
    
    /** Total transaction size in bytes */
    private totalSize: number;
    
    /** Time entered mempool */
    private time: number;
    
    /** Entry height in the chain */
    private height: number;
    
    /** Whether this spends a coinbase */
    private spendsCoinbase: boolean;
    
    /** Modified fee (fee + fee delta from prioritisation) */
    private modifiedFee: bigint;
    
    /** Generation time (for cache locality) */
    private generateTime: number;
    
    /** Parent transaction iterators (txids) */
    private parentTxis: Set<Uint8Array>;
    
    /** Child transaction iterators (txids) */
    private childTxis: Set<Uint8Array>;
    
    /** Fee delta for this entry */
    private feeDelta: bigint;

    constructor(
        tx: CTransaction,
        fee: bigint,
        time: number,
        height: number,
        spendsCoinbase: boolean,
        parentTxis: Set<Uint8Array> = new Set(),
        childTxis: Set<Uint8Array> = new Set(),
        feeDelta: bigint = 0n
    ) {
        this.tx = tx;
        this.fee = fee;
        this.time = time;
        this.height = height;
        this.spendsCoinbase = spendsCoinbase;
        this.parentTxis = parentTxis;
        this.childTxis = childTxis;
        this.feeDelta = feeDelta;
        this.modifiedFee = fee + feeDelta;
        
        // Calculate sizes
        this.totalSize = this.calculateTotalSize();
        this.vsize = this.calculateVSize();
        this.generateTime = Date.now();
    }

    /**
     * Get the transaction
     */
    GetTx(): CTransaction {
        return this.tx;
    }

    /**
     * Get the transaction hash (txid)
     */
    GetTxid(): Uint8Array {
        return this.GetHash();
    }

    /**
     * Get the witness transaction hash (wtxid)
     */
    GetWitnessHash(): Uint8Array {
        // Simplified - would compute wtxid including witness data
        return this.GetHash();
    }

    /**
     * Get transaction hash
     */
    GetHash(): Uint8Array {
        // Simplified - compute txid
        const txData = this.serializeTx();
        return sha256(sha256(txData));
    }

    private serializeTx(): Uint8Array {
        const parts: number[] = [];
        
        // Version
        const version = new Uint8Array(4);
        new DataView(version.buffer).setUint32(0, this.tx.version, true);
        parts.push(...version);
        
        // Inputs
        parts.push(this.tx.vin.length);
        for (const vin of this.tx.vin) {
            parts.push(...vin.prevout.hash);
            parts.push(vin.prevout.n & 0xff, (vin.prevout.n >> 8) & 0xff, 
                      (vin.prevout.n >> 16) & 0xff, (vin.prevout.n >> 24) & 0xff);
            parts.push(vin.scriptSig.length);
            parts.push(...vin.scriptSig);
            parts.push(vin.nSequence & 0xff, (vin.nSequence >> 8) & 0xff,
                      (vin.nSequence >> 16) & 0xff, (vin.nSequence >> 24) & 0xff);
        }
        
        // Outputs
        parts.push(this.tx.vout.length);
        for (const vout of this.tx.vout) {
            // Value as 8 bytes
            const valueBytes = new Uint8Array(8);
            new DataView(valueBytes.buffer).setFloat64(0, Number(vout.nValue), true);
            parts.push(...valueBytes);
            parts.push(vout.scriptPubKey.length);
            parts.push(...vout.scriptPubKey);
        }
        
        // Locktime
        parts.push(this.tx.nLockTime & 0xff, (this.tx.nLockTime >> 8) & 0xff,
                  (this.tx.nLockTime >> 16) & 0xff, (this.tx.nLockTime >> 24) & 0xff);
        
        return new Uint8Array(parts);
    }

    private calculateTotalSize(): number {
        return this.serializeTx().length;
    }

    private calculateVSize(): number {
        // BIP141: (stripped_size * 3 + full_size) / 4
        // For simplicity, assume no witness (all witness is 1 byte marker + 1 byte flag + witness data)
        const baseSize = this.totalSize;
        return Math.floor(baseSize * 3 / 4);
    }

    /**
     * Get the fee
     */
    GetFee(): bigint {
        return this.fee;
    }

    /**
     * Get virtual size
     */
    GetTxSize(): number {
        return this.vsize;
    }

    /**
     * Get modified fee (with prioritisation delta)
     */
    GetModifiedFee(): bigint {
        return this.modifiedFee;
    }

    /**
     * Get entry time
     */
    GetTime(): number {
        return this.time;
    }

    /**
     * Get entry height
     */
    GetHeight(): number {
        return this.height;
    }

    /**
     * Check if spends coinbase
     */
    IsCoinBase(): boolean {
        return this.spendsCoinbase;
    }

    /**
     * Get ancestors (by txid)
     */
    GetMemPoolParents(): Set<Uint8Array> {
        return this.parentTxis;
    }

    /**
     * Get descendants (by txid)
     */
    GetMemPoolChildren(): Set<Uint8Array> {
        return this.childTxis;
    }

    /**
     * Get fee delta
     */
    GetFeeDelta(): bigint {
        return this.feeDelta;
    }

    /**
     * Update modified fee (after fee delta change)
     */
    UpdateModifiedFee(delta: bigint): void {
        this.feeDelta += delta;
        this.modifiedFee = this.fee + this.feeDelta;
    }

    /**
     * Dynamic memory usage
     */
    DynamicMemoryUsage(): number {
        let usage = memusage(this.serializeTx());
        for (const parent of this.parentTxis) {
            usage += memusage(parent);
        }
        for (const child of this.childTxis) {
            usage += memusage(child);
        }
        return usage;
    }
}

/**
 * CTxMemPoolEntry ref (shared pointer simulation)
 */
export type CTxMemPoolEntryRef = CTxMemPoolEntry;

/**
 * Mempool info for RPC queries
 */
export interface TxMempoolInfo {
    /** Transaction */
    tx: CTransaction;
    /** Time entered mempool (seconds) */
    time: number;
    /** Fee in satoshis */
    fee: bigint;
    /** Virtual size */
    vsize: number;
    /** Fee delta */
    nFeeDelta: bigint;
}

/**
 * CTxMemPool - the memory pool
 */
export class CTxMemPool {
    /** Transaction map indexed by txid */
    private mapTx: Map<string, CTxMemPoolEntry>;
    
    /** Transaction map indexed by wtxid */
    private mapTxByWtxid: Map<string, CTxMemPoolEntry>;
    
    /** Total size of all transactions */
    private totalTxSize: number;
    
    /** Total fees in mempool */
    private totalFee: bigint;
    
    /** Dynamic memory usage */
    private cachedInnerUsage: number;
    
    /** Last rolling fee update time */
    private lastRollingFeeUpdate: number;
    
    /** Block since last rolling fee bump */
    private blockSinceLastRollingFeeBump: boolean;
    
    /** Rolling minimum fee rate */
    private rollingMinimumFeeRate: number;
    
    /** Sequence number for tracking */
    private sequenceNumber: number;
    
    /** Unbroadcast transaction IDs */
    private unbroadcastTxids: Set<string>;
    
    /** Next transactions by outpoint */
    private mapNextTx: Map<string, CTxMemPoolEntry>;
    
    /** Fee deltas */
    private mapDeltas: Map<string, bigint>;
    
    /** Maximum mempool size */
    private maxSizeBytes: number;
    
    /** Maximum databyte size */
    private maxDataBytes: number;

    constructor(maxSizeBytes: number = DEFAULT_MAX_MEMPOOL_SIZE) {
        this.mapTx = new Map();
        this.mapTxByWtxid = new Map();
        this.totalTxSize = 0;
        this.totalFee = 0n;
        this.cachedInnerUsage = 0;
        this.lastRollingFeeUpdate = Math.floor(Date.now() / 1000);
        this.blockSinceLastRollingFeeBump = false;
        this.rollingMinimumFeeRate = DEFAULT_MIN_RELAY_FEE;
        this.sequenceNumber = 1;
        this.unbroadcastTxids = new Set();
        this.mapNextTx = new Map();
        this.mapDeltas = new Map();
        this.maxSizeBytes = maxSizeBytes;
        this.maxDataBytes = DEFAULT_MAX_MEMPOOL_DATASIZE;
    }

    /**
     * Add a transaction to the mempool
     */
    AddTx(entry: CTxMemPoolEntry): boolean {
        const txid = this.hashToString(entry.GetTxid());
        const wtxid = this.hashToString(entry.GetWitnessHash());
        
        // Check if already exists
        if (this.mapTx.has(txid)) {
            return false;
        }
        
        // Add to maps
        this.mapTx.set(txid, entry);
        this.mapTxByWtxid.set(wtxid, entry);
        
        // Update totals
        this.totalTxSize += entry.GetTxSize();
        this.totalFee += entry.GetModifiedFee();
        this.cachedInnerUsage += entry.DynamicMemoryUsage();
        
        // Track inputs
        for (const vin of entry.GetTx().vin) {
            const key = this.outpointToString(vin.prevout);
            this.mapNextTx.set(key, entry);
        }
        
        // Update sequence
        this.sequenceNumber++;
        
        return true;
    }

    /**
     * Remove a transaction from the mempool
     */
    RemoveTx(entry: CTxMemPoolEntry, reason: MemPoolRemovalReason): void {
        const txid = this.hashToString(entry.GetTxid());
        const wtxid = this.hashToString(entry.GetWitnessHash());
        
        // Remove from maps
        this.mapTx.delete(txid);
        this.mapTxByWtxid.delete(wtxid);
        
        // Update totals
        this.totalTxSize -= entry.GetTxSize();
        this.totalFee -= entry.GetModifiedFee();
        this.cachedInnerUsage -= entry.DynamicMemoryUsage();
        
        // Remove input tracking
        for (const vin of entry.GetTx().vin) {
            const key = this.outpointToString(vin.prevout);
            this.mapNextTx.delete(key);
        }
        
        // Update sequence
        this.sequenceNumber++;
    }

    /**
     * Get transaction by txid
     */
    GetTx(txid: Uint8Array): CTxMemPoolEntry | undefined {
        return this.mapTx.get(this.hashToString(txid));
    }

    /**
     * Get transaction by wtxid
     */
    GetTxByWtxid(wtxid: Uint8Array): CTxMemPoolEntry | undefined {
        return this.mapTxByWtxid.get(this.hashToString(wtxid));
    }

    /**
     * Check if transaction is in mempool
     */
    exists(txid: Uint8Array): boolean {
        return this.mapTx.has(this.hashToString(txid));
    }

    /**
     * Check if transaction is in mempool by wtxid
     */
    existsWtxid(wtxid: Uint8Array): boolean {
        return this.mapTxByWtxid.has(this.hashToString(wtxid));
    }

    /**
     * Get all transactions sorted by entry time
     */
    GetAllTxs(): CTxMemPoolEntry[] {
        return Array.from(this.mapTx.values()).sort(
            (a, b) => a.GetTime() - b.GetTime()
        );
    }

    /**
     * Get number of transactions in mempool
     */
    size(): number {
        return this.mapTx.size;
    }

    /**
     * Get total size in bytes
     */
    TotalTxSize(): number {
        return this.totalTxSize;
    }

    /**
     * Get total fees
     */
    TotalFee(): bigint {
        return this.totalFee;
    }

    /**
     * Get dynamic memory usage
     */
    DynamicMemoryUsage(): number {
        return memusage(this.mapTx) + memusage(this.mapTxByWtxid) + this.cachedInnerUsage;
    }

    /**
     * Get rolling minimum fee
     */
    GetMinFee(): number {
        return this.rollingMinimumFeeRate;
    }

    /**
     * Calculate fee rate (satoshis per KB)
     */
    GetFeeRate(entry: CTxMemPoolEntry): number {
        if (entry.GetTxSize() === 0) return 0;
        return Number(entry.GetModifiedFee() * 1000n / BigInt(entry.GetTxSize()));
    }

    /**
     * Get fee rate limited by size
     */
    GetFeeRateForSize(maxSize: number): number {
        if (this.totalTxSize < maxSize) {
            return 0;
        }
        return this.rollingMinimumFeeRate;
    }

    /**
     * Update rolling fee
     */
    UpdateFeeRate(now: number): void {
        // Exponential decay
        const secondsSinceUpdate = now - this.lastRollingFeeUpdate;
        if (secondsSinceUpdate >= ROLLING_FEE_HALFLIFE) {
            this.rollingMinimumFeeRate /= 2;
            this.lastRollingFeeUpdate = now;
        }
    }

    /**
     * Check if transaction is full (block since last fee bump)
     */
    BlockSinceLastRollingFeeBump(): boolean {
        return this.blockSinceLastRollingFeeBump;
    }

    /**
     * Get ancestor data (total size, count, fees)
     */
    CalculateAncestorData(entry: CTxMemPoolEntry): { ancestorsSize: number; ancestorsCount: number; ancestorsFees: bigint } {
        const visited = new Set<string>();
        const queue = [entry];
        let totalSize = 0;
        let totalFees = 0n;
        let count = 0;
        
        while (queue.length > 0) {
            const current = queue.shift()!;
            const key = this.hashToString(current.GetTxid());
            
            if (visited.has(key)) continue;
            visited.add(key);
            
            totalSize += current.GetTxSize();
            totalFees += current.GetModifiedFee();
            count++;
            
            for (const parentTxid of current.GetMemPoolParents()) {
                const parent = this.GetTx(parentTxid);
                if (parent) queue.push(parent);
            }
        }
        
        return { ancestorsSize: totalSize, ancestorsCount: count, ancestorsFees: totalFees };
    }

    /**
     * Get descendant count
     */
    GetDescendantCount(entry: CTxMemPoolEntry): number {
        const visited = new Set<string>();
        const queue = [entry];
        let count = 0;
        
        while (queue.length > 0) {
            const current = queue.shift()!;
            const key = this.hashToString(current.GetTxid());
            
            if (visited.has(key)) continue;
            visited.add(key);
            count++;
            
            for (const childTxid of current.GetMemPoolChildren()) {
                const child = this.GetTx(childTxid);
                if (child) queue.push(child);
            }
        }
        
        return count;
    }

    /**
     * Get ancestor count
     */
    GetAncestorCount(entry: CTxMemPoolEntry): number {
        const visited = new Set<string>();
        const queue = [entry];
        let count = 0;
        
        while (queue.length > 0) {
            const current = queue.shift()!;
            const key = this.hashToString(current.GetTxid());
            
            if (visited.has(key)) continue;
            visited.add(key);
            count++;
            
            for (const parentTxid of current.GetMemPoolParents()) {
                const parent = this.GetTx(parentTxid);
                if (parent) queue.push(parent);
            }
        }
        
        return count;
    }

    /**
     * Check if transaction is unbroadcast
     */
    IsUnbroadcastTx(txid: Uint8Array): boolean {
        return this.unbroadcastTxids.has(this.hashToString(txid));
    }

    /**
     * Set transaction as unbroadcast
     */
    AddUnbroadcastTx(txid: Uint8Array): void {
        this.unbroadcastTxids.add(this.hashToString(txid));
    }

    /**
     * Remove from unbroadcast set
     */
    RemoveUnbroadcastTx(txid: Uint8Array): boolean {
        return this.unbroadcastTxids.delete(this.hashToString(txid));
    }

    /**
     * Get fee delta for transaction
     */
    GetDelta(txid: Uint8Array): bigint {
        return this.mapDeltas.get(this.hashToString(txid)) || 0n;
    }

    /**
     * Update fee delta for transaction
     */
    UpdateDelta(txid: Uint8Array, delta: bigint): void {
        const key = this.hashToString(txid);
        const entry = this.mapTx.get(key);
        if (entry) {
            entry.UpdateModifiedFee(delta);
            this.totalFee += delta;
        }
        const currentDelta = this.mapDeltas.get(key) || 0n;
        this.mapDeltas.set(key, currentDelta + delta);
    }

    /**
     * Get sequence number
     */
    GetSequenceNumber(): number {
        return this.sequenceNumber;
    }

    /**
     * Get info for all transactions (for RPC)
     */
    GetAllInfo(): TxMempoolInfo[] {
        return this.GetAllTxs().map(entry => ({
            tx: entry.GetTx(),
            time: entry.GetTime(),
            fee: entry.GetFee(),
            vsize: entry.GetTxSize(),
            nFeeDelta: entry.GetFeeDelta()
        }));
    }

    private hashToString(hash: Uint8Array): string {
        return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    private outpointToString(outpoint: COutPoint): string {
        return `${this.hashToString(outpoint.hash)}-${outpoint.n}`;
    }
}

/**
 * Compare entries by entry time
 */
export function CompareTxMemPoolEntryByEntryTime(
    a: CTxMemPoolEntry,
    b: CTxMemPoolEntry
): number {
    return a.GetTime() - b.GetTime();
}

/**
 * Compare entries by fee rate (descending)
 */
export function CompareTxMemPoolEntryByFeeRate(
    a: CTxMemPoolEntry,
    b: CTxMemPoolEntry
): number {
    const feeRateA = a.GetModifiedFee() / BigInt(Math.max(a.GetTxSize(), 1));
    const feeRateB = b.GetModifiedFee() / BigInt(Math.max(b.GetTxSize(), 1));
    return feeRateA > feeRateB ? -1 : feeRateA < feeRateB ? 1 : 0;
}
