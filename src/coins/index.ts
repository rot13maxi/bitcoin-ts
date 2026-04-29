// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * UTXO set management (coins database).
 * This is a TypeScript port of Bitcoin Core's coins.h and coins.cpp.
 * 
 * Port Layer 4: in-memory state management. Manages the UTXO set (coins view).
 * 
 * Key types:
 * - Coin: A UTXO entry (output value, height, coinbase flag)
 * - CCoinsView: Abstract interface for UTXO storage
 * - CCoinsViewCache: Cached view with modification tracking
 */

import { uint256, Txid, Wtxid } from '../uint256';
import { COutPoint, CTxOut, CTransaction, CTransactionRef, GenTxid } from '../primitives';
import { MallocUsage, DynamicMemoryUsage, DynamicUsageUnorderedMap } from '../memusage';
import { Stream, serializeUInt32LE, unserializeUInt32LE, serializeInt64LE, unserializeInt64LE, writeVarInt, readVarInt } from '../serialize';
import { CSipHasher } from '../crypto/siphash';

/**
 * A UTXO entry (coin).
 * Represents an unspent transaction output with metadata.
 */
export class Coin {
    /** The unspent transaction output */
    out: CTxOut;
    
    /** Whether the containing transaction was a coinbase */
    fCoinBase: boolean;
    
    /** The height at which this output was included in the active chain */
    nHeight: number;

    /**
     * Construct a Coin from a CTxOut and height/coinbase information.
     * @param out - The CTxOut (transaction output)
     * @param nHeightIn - Block height where this output was created
     * @param fCoinBaseIn - Whether this is a coinbase transaction output
     */
    constructor(out?: CTxOut, nHeightIn?: number, fCoinBaseIn?: boolean) {
        this.out = out ?? new CTxOut();
        this.fCoinBase = fCoinBaseIn ?? false;
        this.nHeight = nHeightIn ?? 0;
    }

    clear(): void {
        this.out.setNull();
        this.fCoinBase = false;
        this.nHeight = 0;
    }

    isCoinBase(): boolean {
        return this.fCoinBase;
    }

    isSpent(): boolean {
        return this.out.isNull();
    }

    /**
     * Serialize the coin to a stream.
     * Format: VARINT((height << 1) | coinbase) + compressed CTxOut
     */
    serialize(stream: Stream): void {
        const code = (this.nHeight << 1) | (this.fCoinBase ? 1 : 0);
        writeVarInt(stream, code);
        this.out.serialize(stream);
    }

    /**
     * Unserialize the coin from a stream.
     */
    unserialize(stream: Stream): void {
        const code = readVarInt(stream);
        this.nHeight = code >> 1;
        this.fCoinBase = (code & 1) === 1;
        this.out = new CTxOut();
        this.out.unserialize(stream);
    }

    /**
     * Estimate dynamic memory usage.
     * Only counts the scriptPubKey since the rest is fixed-size.
     */
    dynamicMemoryUsage(): number {
        return DynamicMemoryUsage(this.out.scriptPubKey);
    }
}

/** Cache entry flags */
export enum CCoinsCacheEntryFlags {
    DIRTY = 1 << 0,
    FRESH = 1 << 1,
}

/**
 * A coin in one level of the coins database caching hierarchy.
 * 
 * A coin can either be:
 * - unspent or spent (coin object nulled out)
 * - DIRTY or not DIRTY
 * - FRESH or not FRESH
 */
export interface CCoinsCacheEntry {
    coin: Coin;
    flags: number; // CCoinsCacheEntryFlags combination

    isDirty(): boolean;
    isFresh(): boolean;
    setDirty(): void;
    setFresh(): void;
    clearFlags(): void;
}

/**
 * Implementation of CCoinsCacheEntry methods.
 */
export function makeCoinsCacheEntry(coin: Coin, flags = 0): CCoinsCacheEntry {
    return {
        coin,
        flags,
        isDirty() { return (this.flags & CCoinsCacheEntryFlags.DIRTY) !== 0; },
        isFresh() { return (this.flags & CCoinsCacheEntryFlags.FRESH) !== 0; },
        setDirty() { this.flags |= CCoinsCacheEntryFlags.DIRTY; },
        setFresh() { this.flags |= CCoinsCacheEntryFlags.FRESH; },
        clearFlags() { this.flags = 0; },
    };
}

/**
 * Hash function for COutPoint, with a per-seed salt for DoS protection.
 */
export class SaltedOutpointHasher {
    private k0: bigint;
    private k1: bigint;

    constructor(deterministic = false) {
        if (deterministic) {
            this.k0 = 0n;
            this.k1 = 0n;
        } else {
            // Random 64-bit values
            this.k0 = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) |
                (BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) << 53n);
            this.k1 = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) |
                (BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) << 53n);
        }
    }

    hash(outpoint: COutPoint): bigint {
        return new CSipHasher(this.k0, this.k1)
            .WriteData(outpoint.hash.getDataBE())
            .WriteU64LE(BigInt(outpoint.n))
            .FinalizeAsBigint();
    }
}

/**
 * CCoinsMap - a map from COutPoint to CCoinsCacheEntry with salted hashing.
 * This replaces the C++ std::unordered_map with PoolAllocator.
 */
export class CCoinsMap {
    private entries: Map<string, CCoinsCacheEntry> = new Map();
    private hasher: SaltedOutpointHasher;

    constructor(deterministic = false) {
        this.hasher = new SaltedOutpointHasher(deterministic);
    }

    private key(outpoint: COutPoint): string {
        return outpoint.toString();
    }

    find(outpoint: COutPoint): CCoinsCacheEntry | undefined {
        return this.entries.get(this.key(outpoint));
    }

    has(outpoint: COutPoint): boolean {
        return this.entries.has(this.key(outpoint));
    }

    get(outpoint: COutPoint): CCoinsCacheEntry | undefined {
        return this.entries.get(this.key(outpoint));
    }

    set(outpoint: COutPoint, entry: CCoinsCacheEntry): this {
        this.entries.set(this.key(outpoint), entry);
        return this;
    }

    delete(outpoint: COutPoint): boolean {
        return this.entries.delete(this.key(outpoint));
    }

    clear(): void {
        this.entries.clear();
    }

    size(): number {
        return this.entries.size;
    }

    /**
     * Get the first entry, or undefined if empty.
     */
    begin(): [string, CCoinsCacheEntry] | undefined {
        const iter = this.entries.entries().next();
        return iter.value;
    }

    /**
     * Return undefined as end marker.
     */
    end(): undefined {
        return undefined;
    }

    /**
     * Iterate over entries.
     */
    [Symbol.iterator](): Iterator<[COutPoint, CCoinsCacheEntry]> {
        const entries = Array.from(this.entries.entries()).map(([key, entry]) => {
            const [hash, n] = key.split(':');
            return [new COutPoint(Txid.fromHex(hash) as Txid, parseInt(n)), entry] as [COutPoint, CCoinsCacheEntry];
        });
        return entries[Symbol.iterator]();
    }

    /**
     * Dynamic memory usage estimate.
     */
    dynamicMemoryUsage(): number {
        return DynamicUsageUnorderedMap(this.entries);
    }

    /**
     * Get all dirty entries.
     */
    getDirtyEntries(): Array<[COutPoint, CCoinsCacheEntry]> {
        const result: Array<[COutPoint, CCoinsCacheEntry]> = [];
        for (const [key, entry] of this.entries) {
            if (entry.isDirty()) {
                const [hash, n] = key.split(':');
                result.push([new COutPoint(Txid.fromHex(hash) as Txid, parseInt(n)), entry]);
            }
        }
        return result;
    }
}

/**
 * Cursor for iterating over CoinsView state.
 */
export abstract class CCoinsViewCursor {
    constructor(public readonly blockHash: uint256) {}

    abstract getKey(): COutPoint | null;
    abstract getValue(): Coin | null;
    abstract valid(): boolean;
    abstract next(): void;
}

/**
 * Iterator result for coins cache iteration.
 */
export interface CoinsCachePair {
    first: COutPoint;
    second: CCoinsCacheEntry;
}

/**
 * Cursor for iterating over the linked list of flagged entries in CCoinsViewCache.
 * This is a helper for the BatchWrite operation.
 */
export interface CoinsViewCacheCursor {
    /** Get the number of dirty entries */
    getDirtyCount(): number;
    /** Get the total number of entries */
    getTotalCount(): number;
    /** Begin iteration */
    begin(): CoinsCachePair | null;
    /** End iteration (sentinel) */
    end(): null;
    /** Get the next entry, optionally erasing the current one */
    nextAndMaybeErase(current: CoinsCachePair): CoinsCachePair | null;
    /** Check if the current entry will be erased */
    willErase(current: CoinsCachePair): boolean;
}

/**
 * Abstract interface for UTXO storage.
 * Implementations provide read access to the coin set.
 */
export interface CCoinsView {
    /**
     * Get a coin (unspent transaction output) by outpoint.
     * Returns null if the coin is spent or doesn't exist.
     */
    getCoin(outpoint: COutPoint): Coin | null;

    /**
     * Get a coin without caching results in parent views.
     */
    peekCoin(outpoint: COutPoint): Coin | null;

    /**
     * Check whether a coin is unspent.
     */
    haveCoin(outpoint: COutPoint): boolean;

    /**
     * Get the best block hash.
     */
    getBestBlock(): uint256;

    /**
     * Get the range of blocks that may have been partially written.
     */
    getHeadBlocks(): uint256[];

    /**
     * Bulk modification of coins and best block.
     */
    batchWrite(cursor: CoinsViewCacheCursor, blockHash: uint256): void;

    /**
     * Get a cursor to iterate over the state.
     */
    cursor(): CCoinsViewCursor | null;

    /**
     * Estimate database size.
     */
    estimateSize(): number;
}

/**
 * Noop (empty) coins view - returns null for all lookups.
 */
export class CoinsViewEmpty implements CCoinsView {
    getCoin(_outpoint: COutPoint): Coin | null { return null; }
    peekCoin(outpoint: COutPoint): Coin | null { return this.getCoin(outpoint); }
    haveCoin(outpoint: COutPoint): boolean { return false; }
    getBestBlock(): uint256 { return new uint256(); }
    getHeadBlocks(): uint256[] { return []; }
    batchWrite(_cursor: CoinsViewCacheCursor, _blockHash: uint256): void {
        // Do nothing - empty view ignores writes
    }
    cursor(): CCoinsViewCursor | null { return null; }
    estimateSize(): number { return 0; }
}

/**
 * Singleton instance of CoinsViewEmpty.
 */
let emptyInstance: CoinsViewEmpty | null = null;
export function getEmptyCoinsView(): CoinsViewEmpty {
    if (!emptyInstance) {
        emptyInstance = new CoinsViewEmpty();
    }
    return emptyInstance;
}

/**
 * CCoinsView backed by another CCoinsView.
 * Delegates all operations to the base view.
 */
export class CCoinsViewBacked implements CCoinsView {
    protected base: CCoinsView;

    constructor(base: CCoinsView) {
        this.base = base;
    }

    getCoin(outpoint: COutPoint): Coin | null {
        return this.base.getCoin(outpoint);
    }

    peekCoin(outpoint: COutPoint): Coin | null {
        return this.base.peekCoin(outpoint);
    }

    haveCoin(outpoint: COutPoint): boolean {
        return this.base.haveCoin(outpoint);
    }

    getBestBlock(): uint256 {
        return this.base.getBestBlock();
    }

    getHeadBlocks(): uint256[] {
        return this.base.getHeadBlocks();
    }

    batchWrite(cursor: CoinsViewCacheCursor, blockHash: uint256): void {
        this.base.batchWrite(cursor, blockHash);
    }

    cursor(): CCoinsViewCursor | null {
        return this.base.cursor();
    }

    estimateSize(): number {
        return this.base.estimateSize();
    }
}

/**
 * CCoinsView that adds a memory cache on top of another CCoinsView.
 * Tracks dirty/fresh flags for efficient flushing.
 */
export class CCoinsViewCache extends CCoinsViewBacked {
    /** The current block hash this view represents */
    protected mBlockHash: uint256 = new uint256();
    
    /** Map from COutPoint to cache entry */
    protected cacheCoins: CCoinsMap;
    
    /** Dynamic memory usage of cached coins */
    protected cachedCoinsUsage: number = 0;
    
    /** Number of dirty entries */
    protected mDirtyCount: number = 0;
    
    /** Whether to use deterministic hashing */
    private readonly deterministic: boolean;

    constructor(inBase: CCoinsView, deterministic = false) {
        super(inBase);
        this.deterministic = deterministic;
        this.cacheCoins = new CCoinsMap(deterministic);
    }

    /**
     * Get a coin from the cache, falling back to the base view.
     */
    getCoin(outpoint: COutPoint): Coin | null {
        const entry = this.fetchCoin(outpoint);
        if (entry && !entry.coin.isSpent()) {
            return entry.coin;
        }
        return null;
    }

    /**
     * Peek at a coin without caching.
     */
    peekCoin(outpoint: COutPoint): Coin | null {
        const entry = this.cacheCoins.get(outpoint);
        if (entry) {
            return entry.coin.isSpent() ? null : entry.coin;
        }
        return this.base.peekCoin(outpoint);
    }

    /**
     * Check if we have a coin (including in cache).
     */
    haveCoin(outpoint: COutPoint): boolean {
        const entry = this.fetchCoin(outpoint);
        return entry !== null && !entry.coin.isSpent();
    }

    /**
     * Check if we have a coin in the cache only (not base view).
     */
    haveCoinInCache(outpoint: COutPoint): boolean {
        const entry = this.cacheCoins.get(outpoint);
        return entry !== undefined && !entry.coin.isSpent();
    }

    /**
     * Get a coin from the cache, returning an empty/spent coin if not found.
     */
    accessCoin(outpoint: COutPoint): Coin {
        const entry = this.cacheCoins.get(outpoint);
        if (entry) {
            return entry.coin;
        }
        // Return empty coin (spent)
        return new Coin();
    }

    /**
     * Add a coin to the cache.
     */
    addCoin(outpoint: COutPoint, coin: Coin, possibleOverwrite: boolean): void {
        if (coin.isSpent()) return;
        if (coin.out.scriptPubKey.length === 0 && coin.out.isNull()) return;

        const existing = this.cacheCoins.get(outpoint);
        let fresh = false;

        if (!possibleOverwrite) {
            if (existing && !existing.coin.isSpent()) {
                // Attempted to overwrite an unspent coin
                throw new Error('Attempted to overwrite an unspent coin (when possible_overwrite is false)');
            }
            // If existing entry is dirty, we can't mark as FRESH
            fresh = !existing || !existing.isDirty();
        }

        // Update memory usage
        if (existing) {
            this.cachedCoinsUsage -= existing.coin.dynamicMemoryUsage();
            this.mDirtyCount -= existing.isDirty() ? 1 : 0;
        }

        const entry: CCoinsCacheEntry = makeCoinsCacheEntry(coin, CCoinsCacheEntryFlags.DIRTY);

        this.cacheCoins.set(outpoint, entry);
        this.cachedCoinsUsage += coin.dynamicMemoryUsage();
        this.mDirtyCount += 1;

        if (fresh) {
            entry.setFresh();
        }
    }

    /**
     * Spend a coin (mark as spent).
     */
    spendCoin(outpoint: COutPoint, moveTo?: Coin): boolean {
        const entry = this.cacheCoins.get(outpoint);
        if (!entry) return false;

        if (moveTo) {
            moveTo.out = entry.coin.out;
            moveTo.fCoinBase = entry.coin.fCoinBase;
            moveTo.nHeight = entry.coin.nHeight;
        }

        this.cachedCoinsUsage -= entry.coin.dynamicMemoryUsage();
        this.mDirtyCount -= entry.isDirty() ? 1 : 0;

        if (entry.isFresh()) {
            this.cacheCoins.delete(outpoint);
        } else {
            entry.coin.clear();
            entry.setDirty();
            this.mDirtyCount += 1;
        }
        return true;
    }

    getBestBlock(): uint256 {
        if (this.mBlockHash.isNull()) {
            this.mBlockHash = this.base.getBestBlock();
        }
        return this.mBlockHash;
    }

    setBestBlock(blockHash: uint256): void {
        this.mBlockHash = blockHash;
    }

    /**
     * Flush modifications to the base view.
     * When reallocateCache is true, the cache memory is released.
     */
    flush(reallocateCache = true): void {
        this.batchWrite(this.createCursor(true), this.mBlockHash);
        this.mDirtyCount = 0;
        this.cachedCoinsUsage = 0;
        this.mBlockHash = new uint256();
        if (reallocateCache) {
            this.reallocateCache();
        }
    }

    /**
     * Sync with the base view, keeping cached data.
     */
    sync(): void {
        this.batchWrite(this.createCursor(false), this.mBlockHash);
        this.mDirtyCount = 0;
        this.mBlockHash = new uint256();
    }

    /**
     * Reset the cache without flushing.
     */
    reset(): void {
        this.cacheCoins.clear();
        this.cachedCoinsUsage = 0;
        this.mDirtyCount = 0;
        this.mBlockHash = new uint256();
    }

    /**
     * Remove an uncached (non-dirty) entry.
     */
    uncache(outpoint: COutPoint): void {
        const entry = this.cacheCoins.get(outpoint);
        if (entry && !entry.isDirty()) {
            this.cachedCoinsUsage -= entry.coin.dynamicMemoryUsage();
            this.cacheCoins.delete(outpoint);
        }
    }

    /**
     * Get the number of entries in the cache.
     */
    getCacheSize(): number {
        return this.cacheCoins.size();
    }

    /**
     * Get the number of dirty entries.
     */
    getDirtyCount(): number {
        return this.mDirtyCount;
    }

    /**
     * Calculate dynamic memory usage of the cache.
     */
    dynamicMemoryUsage(): number {
        return DynamicMemoryUsage(this.cacheCoins) + this.cachedCoinsUsage;
    }

    /**
     * Check whether all inputs of a transaction are present in the UTXO set.
     */
    haveInputs(tx: CTransaction): boolean {
        if (!tx.isCoinBase()) {
            for (const txin of tx.vin) {
                if (!this.haveCoin(txin.prevout)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Reallocate the cache map to free memory.
     */
    reallocateCache(): void {
        this.cacheCoins = new CCoinsMap(this.deterministic);
    }

    /**
     * Run an internal sanity check.
     */
    sanityCheck(): void {
        let recomputedUsage = 0;
        let countDirty = 0;
        for (const [_outpoint, entry] of this.cacheCoins) {
            if (entry.coin.isSpent()) {
                // A spent coin must be dirty and cannot be fresh
                if (!entry.isDirty()) throw new Error('Spent coin not marked dirty');
                if (entry.isFresh()) throw new Error('Spent coin marked fresh');
            }
            recomputedUsage += entry.coin.dynamicMemoryUsage();
            if (entry.isDirty()) countDirty++;
        }
        if (recomputedUsage !== this.cachedCoinsUsage) {
            throw new Error(`Memory usage mismatch: computed ${recomputedUsage}, cached ${this.cachedCoinsUsage}`);
        }
        if (countDirty !== this.mDirtyCount) {
            throw new Error(`Dirty count mismatch: computed ${countDirty}, cached ${this.mDirtyCount}`);
        }
    }

    /**
     * Batch write operations helper.
     */
    batchWrite(cursor: CoinsViewCacheCursor, blockHash: uint256): void {
        // Fetch all dirty entries
        const dirtyEntries = this.cacheCoins.getDirtyEntries();
        for (const [outpoint, entry] of dirtyEntries) {
            const existing = this.cacheCoins.get(outpoint);
            if (!entry.coin.isSpent()) {
                if (existing) {
                    this.cachedCoinsUsage -= existing.coin.dynamicMemoryUsage();
                }
                this.cachedCoinsUsage += entry.coin.dynamicMemoryUsage();
            } else {
                // Spent - remove from cache
                if (existing) {
                    this.cachedCoinsUsage -= existing.coin.dynamicMemoryUsage();
                }
                this.cacheCoins.delete(outpoint);
            }
        }
        this.mDirtyCount = 0;
        this.mBlockHash = blockHash;
    }

    // ─── Internal helpers ───

    private fetchCoin(outpoint: COutPoint): CCoinsCacheEntry | null {
        let entry = this.cacheCoins.get(outpoint);
        if (entry) {
            return entry;
        }
        const coin = this.base.getCoin(outpoint);
        if (coin) {
            const newEntry: CCoinsCacheEntry = makeCoinsCacheEntry(coin, 0);
            this.cacheCoins.set(outpoint, newEntry);
            this.cachedCoinsUsage += coin.dynamicMemoryUsage();
            return newEntry;
        }
        return null;
    }

    private createCursor(willErase: boolean): CoinsViewCacheCursor {
        const self = this;
        const dirtyEntries = this.cacheCoins.getDirtyEntries();
        let index = 0;

        return {
            getDirtyCount() { return self.mDirtyCount; },
            getTotalCount() { return self.cacheCoins.size(); },
            begin() {
                if (index < dirtyEntries.length) {
                    const [outpoint, entry] = dirtyEntries[index];
                    return { first: outpoint, second: entry };
                }
                return null;
            },
            end() { return null; },
            nextAndMaybeErase(current) {
                if (willErase && current.second.coin.isSpent()) {
                    self.cacheCoins.delete(current.first);
                } else {
                    current.second.clearFlags();
                }
                index++;
                if (index < dirtyEntries.length) {
                    const [outpoint, entry] = dirtyEntries[index];
                    return { first: outpoint, second: entry };
                }
                return null;
            },
            willErase(_current) { return willErase; },
        };
    }
}

/**
 * CCoinsViewCache overlay that doesn't populate parent caches on cache misses.
 * Used during ConnectBlock for ephemeral validation views.
 */
export class CoinsViewOverlay extends CCoinsViewCache {
    protected fetchCoinFromBase(outpoint: COutPoint): Coin | null {
        return this.base.peekCoin(outpoint);
    }
}

/**
 * Add all of a transaction's outputs to a cache.
 * When check is false, assumes overwrites are only possible for coinbase.
 * When check is true, queries the underlying view for overwrite detection.
 */
export function addCoins(cache: CCoinsViewCache, tx: CTransaction, nHeight: number, check = false): void {
    const fCoinbase = tx.isCoinBase();
    const txid = tx.getHash();
    
    for (let i = 0; i < tx.vout.length; i++) {
        const overwrite = check ? cache.haveCoin(new COutPoint(txid, i)) : fCoinbase;
        cache.addCoin(new COutPoint(txid, i), new Coin(tx.vout[i], nHeight, fCoinbase), overwrite);
    }
}

/**
 * Find any unspent output with a given txid.
 * Searches up to MAX_OUTPUTS_PER_BLOCK outputs.
 */
export function accessByTxid(cache: CCoinsViewCache, txid: Txid): Coin {
    const MAX_OUTPUTS_PER_BLOCK = 1000; // Approximation of MAX_BLOCK_WEIGHT / MIN_TRANSACTION_OUTPUT_WEIGHT
    
    for (let n = 0; n < MAX_OUTPUTS_PER_BLOCK; n++) {
        const coin = cache.accessCoin(new COutPoint(txid, n));
        if (!coin.isSpent()) {
            return coin;
        }
    }
    return new Coin();
}

/**
 * CCoinsView that wraps another view and catches read errors.
 * Used for graceful handling of database read failures.
 */
export class CCoinsViewErrorCatcher extends CCoinsViewBacked {
    private readErrorCallbacks: Array<() => void> = [];

    constructor(view: CCoinsView) {
        super(view);
    }

    addReadErrCallback(f: () => void): void {
        this.readErrorCallbacks.push(f);
    }

    getCoin(outpoint: COutPoint): Coin | null {
        try {
            return super.getCoin(outpoint);
        } catch (e) {
            for (const f of this.readErrorCallbacks) {
                f();
            }
            throw e;
        }
    }

    haveCoin(outpoint: COutPoint): boolean {
        try {
            return super.haveCoin(outpoint);
        } catch (e) {
            for (const f of this.readErrorCallbacks) {
                f();
            }
            throw e;
        }
    }

    peekCoin(outpoint: COutPoint): Coin | null {
        try {
            return super.peekCoin(outpoint);
        } catch (e) {
            for (const f of this.readErrorCallbacks) {
                f();
            }
            throw e;
        }
    }
}
