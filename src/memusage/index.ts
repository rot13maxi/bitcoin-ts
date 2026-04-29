// Copyright (c) 2015-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Dynamic memory usage estimation for Bitcoin Core data structures.
 * This is a TypeScript port of Bitcoin Core's memusage.h.
 * 
 * These functions estimate the memory used by dynamically allocated
 * data structures. They are not recursive by default, for efficiency.
 */

import { Prevector } from '../prevector';

/**
 * Compute the total memory used by allocating `alloc` bytes.
 * This accounts for allocator overhead and alignment.
 */
export function MallocUsage(alloc: number): number {
    if (alloc === 0) {
        return 0;
    }
    // On 64-bit platforms, allocate in 16-byte chunks.
    // TypeScript typically runs on 64-bit.
    return Math.ceil(alloc / 16) * 16;
}

/**
 * Compute dynamic memory usage for various types.
 * Returns 0 for primitive types (number, bigint, boolean, null, undefined).
 */
export function DynamicMemoryUsage(v: Uint8Array): number;
export function DynamicMemoryUsage(v: string): number;
export function DynamicMemoryUsage(v: Set<unknown>): number;
export function DynamicMemoryUsage(v: Map<unknown, unknown>): number;
export function DynamicMemoryUsage(v: unknown[]): number;
export function DynamicMemoryUsage(v: Prevector<unknown>): number;
export function DynamicMemoryUsage(v: object): number;
export function DynamicMemoryUsage(_v: unknown): number {
    if (_v === null || _v === undefined) {
        return 0;
    }
    if (typeof _v === 'number' || typeof _v === 'bigint' || typeof _v === 'boolean') {
        return 0;
    }
    if (_v instanceof Uint8Array) {
        return MallocUsage(_v.byteLength);
    }
    if (typeof _v === 'string') {
        // TypeScript strings are immutable and don't expose capacity.
        // Strings in small-string optimization (up to 15 chars) return 0.
        if (_v.length <= 15) return 0;
        return MallocUsage(_v.length * 2); // Worst case: 2 bytes/char
    }
    if (_v instanceof Set) {
        return MallocUsage(_v.size * 24); // Approximate: node + pointer
    }
    if (_v instanceof Map) {
        return MallocUsage(_v.size * 32); // Approximate: node + key/val pointers
    }
    if (Array.isArray(_v)) {
        return MallocUsage(_v.length * 16); // Rough estimate per element
    }
    if (_v && typeof _v === 'object' && 'allocated_memory' in _v) {
        return MallocUsage((_v as Prevector<unknown>).allocated_memory());
    }
    if (typeof _v === 'object') {
        return MallocUsage(64); // Default estimate for object
    }
    return 0;
}

/**
 * Alias for compatibility with Bitcoin Core naming.
 */
export const memusage = {
    MallocUsage,
    DynamicUsage: DynamicMemoryUsage,
};

/**
 * STL tree node structure size (approximation).
 * Used for std::set, std::map, etc.
 */
export const STL_TREE_NODE_SIZE = MallocUsage(32);

/**
 * Compute dynamic memory usage for a std::set-like structure.
 */
export function DynamicUsageSet<K>(s: Set<K>): number {
    return STL_TREE_NODE_SIZE * s.size;
}

/**
 * Compute dynamic memory usage for a std::map-like structure.
 */
export function DynamicUsageMap<K, V>(m: Map<K, V>): number {
    return STL_TREE_NODE_SIZE * m.size;
}

/**
 * Compute dynamic memory usage for an unordered_set (std::unordered_set-like).
 */
export function DynamicUsageUnorderedSet<K>(s: Set<K>): number {
    if (s.size === 0) return 0;
    const bucketCount = Math.ceil(s.size / 0.75);
    return MallocUsage(s.size * 24 + bucketCount * 8);
}

/**
 * Compute dynamic memory usage for an unordered_map (std::unordered_map-like).
 */
export function DynamicUsageUnorderedMap<K, V>(m: Map<K, V>): number {
    if (m.size === 0) return 0;
    const bucketCount = Math.ceil(m.size / 0.75);
    return MallocUsage(m.size * 32 + bucketCount * 8);
}
