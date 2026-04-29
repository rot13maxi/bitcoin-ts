// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Bitcoin Core Memory Usage Tracking - TypeScript port of Bitcoin Core memusage.h
 * 
 * Tracks dynamic memory usage for Bitcoin Core data structures.
 * Uses in-place size calculations where possible.
 */

/**
 * Base overhead for any allocated object
 * Assuming 16 bytes on 64-bit systems:
 * - 8 bytes for allocator metadata
 * - 8 bytes for malloc overhead
 */
export const MALLOC_OVERHEAD = 16;

/**
 * Size of a typical cache entry overhead
 */
export const CACHE_ENTRY_SIZE = 32;

/**
 * Size of script check queue entry
 */
export const SCRIPT_CHECK_ENTRY_SIZE = 32;

/**
 * Calculate basic malloc size for a given number of bytes
 */
export function MallocUsage(n: number): number {
    return n + MALLOC_OVERHEAD;
}

/**
 * Estimate memory usage for a string
 */
export function memusageStr(str: string): number {
    // Each char in JS string is 2 bytes (UTF-16)
    // Plus object overhead
    return (str.length * 2) + MALLOC_OVERHEAD + 8; // +8 for string header
}

/**
 * Estimate memory usage for a Uint8Array
 */
export function memusageArr(arr: Uint8Array): number {
    // ArrayBuffer overhead + data + header
    return arr.byteLength + MALLOC_OVERHEAD + 16;
}

/**
 * Estimate memory usage for an array
 */
export function memusageArray<T>(arr: T[]): number {
    // Array overhead + pointer per element + element sizes
    let usage = MALLOC_OVERHEAD + 8; // Array header
    for (const item of arr) {
        if (item instanceof Uint8Array) {
            usage += memusageArr(item);
        } else if (item instanceof Array) {
            usage += memusageArray(item);
        } else {
            usage += 8; // Pointer size
        }
    }
    return usage;
}

/**
 * Estimate memory usage for a Map
 */
export function memusageMap<K, V>(map: Map<K, V>): number {
    // Map overhead + node size per entry
    let usage = MALLOC_OVERHEAD + 8; // Map header
    for (const [, value] of map) {
        usage += MALLOC_OVERHEAD + CACHE_ENTRY_SIZE; // Node size
        if (value instanceof Uint8Array) {
            usage += memusageArr(value);
        } else if (value instanceof Array) {
            usage += memusageArray(value);
        }
    }
    return usage;
}

/**
 * Estimate memory usage for a Set
 */
export function memusageSet<T>(set: Set<T>): number {
    let usage = MALLOC_OVERHEAD + 8; // Set header
    for (const item of set) {
        usage += MALLOC_OVERHEAD + 8; // Node size
        if (item instanceof Uint8Array) {
            usage += memusageArr(item);
        }
    }
    return usage;
}

/**
 * Generic memory usage function
 */
export function memusage(data: Uint8Array | string | object | any): number {
    if (data instanceof Uint8Array) {
        return memusageArr(data);
    }
    if (typeof data === 'string') {
        return memusageStr(data);
    }
    if (data instanceof Map) {
        return memusageMap(data);
    }
    if (data instanceof Set) {
        return memusageSet(data);
    }
    if (Array.isArray(data)) {
        return memusageArray(data);
    }
    // For unknown types, estimate based on size
    if (data && data.buffer instanceof ArrayBuffer) {
        return memusageArr(new Uint8Array(data.buffer));
    }
    // Fallback
    return MALLOC_OVERHEAD + 64;
}

/**
 * Memory usage for scriptPubKey calculation
 * This calculates the overhead for script storage
 */
export function memusageScript(scriptPubKey: Uint8Array): number {
    // Script data + overhead for storage in cache
    return memusageArr(scriptPubKey) + CACHE_ENTRY_SIZE;
}

/**
 * Memory usage for an optional uint256
 */
export function memusageUInt256(data: Uint8Array | null): number {
    if (data === null) {
        return 0;
    }
    return memusageArr(data);
}

/**
 * Calculate memory usage for coins cache entry
 */
export function memusageCoinEntry(coin: { out: { scriptPubKey: Uint8Array } }): number {
    return memusageScript(coin.out.scriptPubKey) + CACHE_ENTRY_SIZE;
}

/**
 * Calculate total memory for the inner Coin objects in cache
 */
export function CCoinsCacheUsage(
    cachedCoinsUsage: number,
    dirtyCacheSize: number,
    entriesCount: number
): number {
    // cachedCoinsUsage already accounts for scriptPubKey sizes
    // Add overhead for the cache entries themselves
    return cachedCoinsUsage + (entriesCount * CACHE_ENTRY_SIZE) + (dirtyCacheSize * 16);
}

/**
 * Memory usage for block undo data
 */
export function blockUndoSize(undotx: Array<{ out: { scriptPubKey: Uint8Array } }>): number {
    let size = 8; // overhead
    for (const tx of undotx) {
        size += memusageCoinEntry(tx);
    }
    return size;
}

/**
 * Estimate memory usage of a transaction
 */
export function memusageTx(tx: {
    vin: Array<{ scriptSig: Uint8Array; scriptWitness?: Uint8Array[] }>;
    vout: Array<{ scriptPubKey: Uint8Array }>;
}): number {
    let size = MALLOC_OVERHEAD + 8; // tx header
    
    // Inputs
    for (const input of tx.vin) {
        size += memusageArr(input.scriptSig);
        if (input.scriptWitness) {
            for (const item of input.scriptWitness) {
                size += memusageArr(item);
            }
        }
    }
    
    // Outputs
    for (const output of tx.vout) {
        size += memusageArr(output.scriptPubKey);
    }
    
    return size;
}

/**
 * Memory usage for mempool entries
 */
export function mempoolUsage(
    updates: number,
    ticketSetSize: number,
    shortidMapSize: number,
    prefCacheUsage: number
): number {
    return MALLOC_OVERHEAD + 
           MallocUsage(updates) +
           MallocUsage(ticketSetSize) +
           MallocUsage(shortidMapSize) +
           MallocUsage(prefCacheUsage);
}

/**
 * Memory usage for leveldb database estimate
 */
export function estimateDBUsage(
    leveldb_tables: number,
    entry_size: number,
    overhead_per_entry: number
): number {
    return leveldb_tables * (entry_size + overhead_per_entry);
}

/**
 * Memory usage for coin stats index
 */
export function estimateCoinsDBSize(
    coins_count: number,
    avg_coin_size: number
): number {
    return coins_count * (avg_coin_size + CACHE_ENTRY_SIZE);
}
