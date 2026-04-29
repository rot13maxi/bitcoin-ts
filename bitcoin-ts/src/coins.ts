// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Bitcoin Core UTXO Management - TypeScript port of Bitcoin Core coins.h/cpp
 * 
 * This module provides UTXO (Unspent Transaction Output) management:
 * - Coin: represents a spendable output
 * - CCoinsView: abstract UTXO database interface
 * - CCoinsViewCache: cached UTXO view with write support
 */

import { COutPoint, CTxOut, CTransaction } from './primitives';
import { memusage } from './memusage';

/**
 * A Coin represents a spendable transaction output.
 * 
 * Serialized format:
 * - VARINT((height << 1) | (coinbase ? 1 : 0))
 * - The non-spent CTxOut (with compressed value encoding)
 */
export class Coin {
    /** The unspent transaction output */
    out: CTxOut;
    
    /** Whether containing transaction was a coinbase */
    fCoinBase: boolean;
    
    /** The height at which this output was included in a block */
    nHeight: number;

    /**
     * Construct a Coin from a CTxOut and metadata
     */
    constructor(out: CTxOut, nHeight: number, fCoinBase: boolean);
    /**
     * Create an empty/spent coin
     */
    constructor();
    constructor(out?: CTxOut, nHeight?: number, fCoinBase?: boolean) {
        if (out !== undefined && nHeight !== undefined && fCoinBase !== undefined) {
            this.out = { ...out };
            this.nHeight = nHeight;
            this.fCoinBase = fCoinBase;
        } else {
            this.out = { nValue: 0n, scriptPubKey: new Uint8Array(0) };
            this.nHeight = 0;
            this.fCoinBase = false;
        }
    }

    /**
     * Reset to spent state
     */
    Clear(): void {
        this.out = { nValue: 0n, scriptPubKey: new Uint8Array(0) };
        this.fCoinBase = false;
        this.nHeight = 0;
    }

    /**
     * Check if this is a coinbase transaction output
     */
    IsCoinBase(): boolean {
        return this.fCoinBase;
    }

    /**
     * Check if this coin has been spent
     */
    IsSpent(): boolean {
        return this.out.nValue === 0n && this.out.scriptPubKey.length === 0;
    }

    /**
     * Calculate dynamic memory usage
     */
    DynamicMemoryUsage(): number {
        return memusage(this.out.scriptPubKey);
    }

    /**
     * Serialize this coin
     */
    Serialize(): Uint8Array {
        if (this.IsSpent()) {
            throw new Error('Cannot serialize spent coin');
        }
        
        // Pack height and coinbase flag: (height << 1) | coinbase
        const code = (this.nHeight << 1) | (this.fCoinBase ? 1 : 0);
        const result: number[] = [];
        
        // VarInt encoding for code
        let v = code;
        while (v > 0x7f) {
            result.push((v & 0x7f) | 0x80);
            v >>= 7;
        }
        result.push(v);
        
        // Serialize CTxOut (compressed)
        result.push(...this.serializeTxOut());
        
        return new Uint8Array(result);
    }

    /**
     * Deserialize into this coin
     */
    Unserialize(data: Uint8Array): void {
        let pos = 0;
        
        // Read VarInt for code
        let code = 0;
        let shift = 0;
        while (pos < data.length) {
            const byte = data[pos++];
            code |= (byte & 0x7f) << shift;
            if (!(byte & 0x80)) break;
            shift += 7;
        }
        
        this.nHeight = code >> 1;
        this.fCoinBase = (code & 1) === 1;
        
        // Deserialize CTxOut
        const { txout, bytesRead } = this.deserializeTxOut(data, pos);
        this.out = txout;
    }

    private serializeTxOut(): number[] {
        const result: number[] = [];
        
        // Value as VarInt
        let v = this.out.nValue;
        while (v > 0x7fn) {
            result.push(Number(v & 0x7fn) | 0x80);
            v >>= 7n;
        }
        result.push(Number(v));
        
        // ScriptPubKey as length-prefixed data
        result.push(this.out.scriptPubKey.length);
        result.push(...this.out.scriptPubKey);
        
        return result;
    }

    private deserializeTxOut(data: Uint8Array, offset: number): { txout: CTxOut; bytesRead: number } {
        let pos = offset;
        
        // Read value as VarInt
        let value = 0n;
        let shift = 0;
        while (pos < data.length) {
            const byte = data[pos++];
            value |= BigInt(byte & 0x7f) << BigInt(shift);
            if (!(byte & 0x80)) break;
            shift += 7;
        }
        
        // Read scriptPubKey length and data
        const scriptLen = data[pos++];
        const scriptPubKey = data.slice(pos, pos + scriptLen);
        
        return {
            txout: { nValue: value, scriptPubKey },
            bytesRead: pos + scriptLen - offset
        };
    }
}

/**
 * An empty/spent coin constant
 */
export const coinEmpty = new Coin();

/**
 * CCoinsCacheEntry flags
 */
export const enum CCoinsCacheEntryFlags {
    DIRTY = (1 << 0),
    FRESH = (1 << 1),
}

/**
 * Cache entry for coins
 */
export interface CCoinsCacheEntry {
    coin: Coin;
    flags: number;
}

/**
 * Salted outpoint hasher for cache map keys
 */
export class SaltedOutpointHasher {
    private salt: Uint8Array;

    constructor() {
        this.salt = new Uint8Array(16);
        crypto.getRandomValues(this.salt);
    }

    hash(outpoint: COutPoint): number {
        // Simple hash combining salt and outpoint data
        let hash = 0;
        for (let i = 0; i < 8 && i < outpoint.hash.length; i++) {
            hash = (hash * 31 + outpoint.hash[i]) >>> 0;
            hash ^= (this.salt[i] << (i * 4));
        }
        hash = (hash * 31 + outpoint.n) >>> 0;
        return hash;
    }

    equals(a: COutPoint, b: COutPoint): boolean {
        if (a.hash.length !== b.hash.length || a.n !== b.n) return false;
        for (let i = 0; i < a.hash.length; i++) {
            if (a.hash[i] !== b.hash[i]) return false;
        }
        return true;
    }
}

/**
 * CCoinsMap - unordered map of COutPoint to CCoinsCacheEntry
 */
export class CCoinsMap {
    private entries: Map<string, CCoinsCacheEntry>;
    private hasher: SaltedOutpointHasher;

    constructor() {
        this.entries = new Map();
        this.hasher = new SaltedOutpointHasher();
    }

    private keyForOutpoint(outpoint: COutPoint): string {
        const hash = this.hasher.hash(outpoint);
        return `${hash}-${Array.from(outpoint.hash).map(b => b.toString(16).padStart(2, '0')).join('')}-${outpoint.n}`;
    }

    get(outpoint: COutPoint): CCoinsCacheEntry | undefined {
        return this.entries.get(this.keyForOutpoint(outpoint));
    }

    set(outpoint: COutPoint, entry: CCoinsCacheEntry): void {
        this.entries.set(this.keyForOutpoint(outpoint), entry);
    }

    has(outpoint: COutPoint): boolean {
        return this.entries.has(this.keyForOutpoint(outpoint));
    }

    delete(outpoint: COutPoint): boolean {
        return this.entries.delete(this.keyForOutpoint(outpoint));
    }

    clear(): void {
        this.entries.clear();
    }

    get size(): number {
        return this.entries.size;
    }

    *[Symbol.iterator](): Iterator<[COutPoint, CCoinsCacheEntry]> {
        // Note: Without the full key, we can't iterate back to COutPoint
        // This is a limitation of the simplified implementation
    }

    entriesIterable(): IterableIterator<CCoinsCacheEntry> {
        return this.entries.values();
    }
}

/**
 * CCoinsView - abstract interface for UTXO database
 */
export interface CCoinsView {
    /** Get coin at an outpoint (may return spent coin as empty) */
    GetCoin(outpoint: COutPoint): Coin | null;
    
    /** Check if a coin exists (and is not spent) */
    HaveCoin(outpoint: COutPoint): boolean;
    
    /** Get the best block hash */
    GetBestBlock(): Uint8Array;
    
    /** Get blocks that may be partially written */
    GetHeadBlocks(): Uint8Array[];
    
    /** Estimate database size */
    EstimateSize(): number;
}

/**
 * Empty coins view (returns nothing)
 */
export class CoinsViewEmpty implements CCoinsView {
    GetCoin(_outpoint: COutPoint): Coin | null {
        return null;
    }

    HaveCoin(_outpoint: COutPoint): boolean {
        return false;
    }

    GetBestBlock(): Uint8Array {
        return new Uint8Array(32);
    }

    GetHeadBlocks(): Uint8Array[] {
        return [];
    }

    EstimateSize(): number {
        return 0;
    }
}

/**
 * CCoinsView backed by another CCoinsView
 */
export class CCoinsViewBacked implements CCoinsView {
    protected base: CCoinsView;

    constructor(base: CCoinsView) {
        this.base = base;
    }

    GetCoin(outpoint: COutPoint): Coin | null {
        return this.base.GetCoin(outpoint);
    }

    HaveCoin(outpoint: COutPoint): boolean {
        return this.base.HaveCoin(outpoint);
    }

    GetBestBlock(): Uint8Array {
        return this.base.GetBestBlock();
    }

    GetHeadBlocks(): Uint8Array[] {
        return this.base.GetHeadBlocks();
    }

    EstimateSize(): number {
        return this.base.EstimateSize();
    }
}

/**
 * CCoinsViewCache - cached UTXO view with write support
 */
export class CCoinsViewCache extends CCoinsViewBacked {
    private cacheCoins: CCoinsMap;
    private cachedCoinsUsage: number;
    private m_dirty_count: number;
    private dirtyCache: Map<string, Coin>;
    private m_block_hash: Uint8Array;

    constructor(in_base: CCoinsView) {
        super(in_base);
        this.cacheCoins = new CCoinsMap();
        this.cachedCoinsUsage = 0;
        this.m_dirty_count = 0;
        this.dirtyCache = new Map();
        this.m_block_hash = new Uint8Array(32);
    }

    /**
     * Get a coin from cache or base view
     */
    GetCoin(outpoint: COutPoint): Coin | null {
        const entry = this.cacheCoins.get(outpoint);
        if (entry) {
            if (entry.coin.IsSpent()) {
                return null;
            }
            return entry.coin;
        }
        
        // Cache miss - fetch from base
        const coin = this.base.GetCoin(outpoint);
        if (coin === null) {
            return null;
        }
        
        // Cache the coin
        this.cacheCoins.set(outpoint, { coin: new Coin(coin.out, coin.nHeight, coin.fCoinBase), flags: 0 });
        return coin;
    }

    /**
     * Check if we have a coin (in cache or base)
     */
    HaveCoin(outpoint: COutPoint): boolean {
        const entry = this.cacheCoins.get(outpoint);
        if (entry) {
            return !entry.coin.IsSpent();
        }
        return this.base.HaveCoin(outpoint);
    }

    /**
     * Get coin without caching (only from base)
     */
    PeekCoin(outpoint: COutPoint): Coin | null {
        if (this.cacheCoins.has(outpoint)) {
            const entry = this.cacheCoins.get(outpoint)!;
            if (!entry.coin.IsSpent()) {
                return entry.coin;
            }
        }
        return this.base.GetCoin(outpoint);
    }

    /**
     * Get the current best block hash
     */
    GetBestBlock(): Uint8Array {
        return this.m_block_hash;
    }

    /**
     * Set the best block hash
     */
    SetBestBlock(block_hash: Uint8Array): void {
        this.m_block_hash = block_hash.slice();
    }

    /**
     * Access a coin (returns empty coin if not found)
     */
    AccessCoin(outpoint: COutPoint): Coin {
        const entry = this.cacheCoins.get(outpoint);
        if (entry) {
            return entry.coin;
        }
        return coinEmpty;
    }

    /**
     * Check if coin is in cache (regardless of spent status)
     */
    HaveCoinInCache(outpoint: COutPoint): boolean {
        return this.cacheCoins.has(outpoint);
    }

    /**
     * Add a coin to the cache
     */
    AddCoin(outpoint: COutPoint, coin: Coin, possible_overwrite: boolean): void {
        // Check if already exists
        const existing = this.cacheCoins.get(outpoint);
        if (existing) {
            if (possible_overwrite) {
                // Update existing - mark as dirty
                const prevUsage = existing.coin.DynamicMemoryUsage();
                existing.coin.out = { ...coin.out };
                existing.coin.nHeight = coin.nHeight;
                existing.coin.fCoinBase = coin.fCoinBase;
                existing.flags = CCoinsCacheEntryFlags.DIRTY;
                this.cachedCoinsUsage += existing.coin.DynamicMemoryUsage() - prevUsage;
                this.markDirty(outpoint);
            }
            return;
        }
        
        // New coin
        const entry: CCoinsCacheEntry = {
            coin: new Coin(coin.out, coin.nHeight, coin.fCoinBase),
            flags: CCoinsCacheEntryFlags.DIRTY | CCoinsCacheEntryFlags.FRESH
        };
        this.cacheCoins.set(outpoint, entry);
        this.cachedCoinsUsage += entry.coin.DynamicMemoryUsage();
        this.m_dirty_count++;
        this.markDirty(outpoint);
    }

    /**
     * Spend a coin (remove from cache)
     */
    SpendCoin(outpoint: COutPoint, moveto?: Coin): boolean {
        const entry = this.cacheCoins.get(outpoint);
        if (!entry) {
            return false;
        }
        
        if (moveto) {
            moveto.out = { ...entry.coin.out };
            moveto.nHeight = entry.coin.nHeight;
            moveto.fCoinBase = entry.coin.fCoinBase;
        }
        
        const prevUsage = entry.coin.DynamicMemoryUsage();
        entry.coin.Clear();
        entry.flags = CCoinsCacheEntryFlags.DIRTY;
        this.cachedCoinsUsage -= prevUsage;
        this.markDirty(outpoint);
        return true;
    }

    /**
     * Flush changes to the base view
     */
    Flush(reallocate_cache: boolean = true): void {
        // Batch write all dirty entries to base
        // This is a simplified implementation
        if (this.m_dirty_count > 0) {
            // In full implementation, would batch write to base
            this.m_dirty_count = 0;
        }
        
        if (reallocate_cache) {
            this.cacheCoins.clear();
            this.dirtyCache.clear();
            this.cachedCoinsUsage = 0;
        }
    }

    /**
     * Remove a UTXO from cache if not modified
     */
    Uncache(outpoint: COutPoint): void {
        const entry = this.cacheCoins.get(outpoint);
        if (entry && !(entry.flags & CCoinsCacheEntryFlags.DIRTY)) {
            this.cachedCoinsUsage -= entry.coin.DynamicMemoryUsage();
            this.cacheCoins.delete(outpoint);
        }
    }

    /**
     * Get number of entries in cache
     */
    GetCacheSize(): number {
        return this.cacheCoins.size;
    }

    /**
     * Get number of dirty entries
     */
    GetDirtyCount(): number {
        return this.m_dirty_count;
    }

    /**
     * Calculate memory usage
     */
    DynamicMemoryUsage(): number {
        return memusage(this.dirtyCache) + this.cachedCoinsUsage;
    }

    /**
     * Check if transaction inputs are available
     */
    HaveInputs(tx: CTransaction): boolean {
        if (tx.vin.length === 0) {
            return false;
        }
        
        // Coinbase transactions have no inputs
        if (tx.vin.length === 1) {
            const vin0 = tx.vin[0];
            const hashEmpty = vin0.prevout.hash.every(b => b === 0);
            if (hashEmpty && vin0.prevout.n === 0xffffffff && vin0.nSequence === 0xffffffff) {
                return true;
            }
        }
        
        for (const txin of tx.vin) {
            if (!this.HaveCoin(txin.prevout)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Reset the cache (discard all modifications)
     */
    Reset(): void {
        this.cacheCoins.clear();
        this.dirtyCache.clear();
        this.cachedCoinsUsage = 0;
        this.m_dirty_count = 0;
    }

    private markDirty(outpoint: COutPoint): void {
        const key = Array.from(outpoint.hash).map(b => b.toString(16).padStart(2, '0')).join('') + '-' + outpoint.n;
        const entry = this.cacheCoins.get(outpoint);
        if (entry) {
            this.dirtyCache.set(key, entry.coin);
        }
    }

    /**
     * Sanity check on the cache
     */
    SanityCheck(): void {
        // Verify cache consistency
        // This is a placeholder for the full implementation
    }
}

/**
 * CoinsViewErrorCatcher - wraps a CCoinsView and catches read errors
 */
export class CCoinsViewErrorCatcher extends CCoinsViewBacked {
    private err_callbacks: Array<() => void>;

    constructor(view: CCoinsView) {
        super(view);
        this.err_callbacks = [];
    }

    AddReadErrCallback(f: () => void): void {
        this.err_callbacks.push(f);
    }

    GetCoin(outpoint: COutPoint): Coin | null {
        try {
            return this.base.GetCoin(outpoint);
        } catch (e) {
            for (const callback of this.err_callbacks) {
                callback();
            }
            return null;
        }
    }

    HaveCoin(outpoint: COutPoint): boolean {
        try {
            return this.base.HaveCoin(outpoint);
        } catch (e) {
            for (const callback of this.err_callbacks) {
                callback();
            }
            return false;
        }
    }
}

/**
 * Add all transaction outputs to a cache
 */
export function AddCoins(cache: CCoinsViewCache, tx: CTransaction, nHeight: number, check: boolean = false): void {
    // Check if this would be an overwrite
    if (check) {
        // When check is true, query base to verify it's not an overwrite
        // Simplified: always allow
    }
    
    for (let i = 0; i < tx.vout.length; i++) {
        const outpoint: COutPoint = {
            hash: new Uint8Array(32), // Would be txid
            n: i
        };
        const coin = new Coin(tx.vout[i], nHeight, false);
        cache.AddCoin(outpoint, coin, check);
    }
}

/**
 * Access coin by transaction id (find any unspent output)
 */
export function AccessByTxid(cache: CCoinsViewCache, txid: Uint8Array): Coin {
    // This is expensive - scans for any output matching txid
    // Simplified implementation
    // Full implementation would search through cache
    return coinEmpty;
}

/**
 * Cursor interface for iterating over coins
 */
export interface CCoinsViewCursor {
    GetKey(): COutPoint;
    GetValue(): Coin;
    Valid(): boolean;
    Next(): void;
    GetBestBlock(): Uint8Array;
}
