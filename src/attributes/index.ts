// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * C++ attribute macros ported to TypeScript.
 * This is a TypeScript port of Bitcoin Core's attributes.h.
 */

/**
 * Lifetime bounds annotation (TypeScript uses reference semantics, so this is a no-op)
 */
export const LIFETIMEBOUND = '';

/**
 * Always inline hint (TypeScript always inlines, so this is a no-op)
 */
export function ALWAYS_INLINE<T extends (...args: unknown[]) => unknown>(fn: T): T {
    return fn;
}

/**
 * Fallthrough annotation - used to suppress warnings
 */
export function FALLTHROUGH(): void {
    // No-op
}

/**
 * Likely/unlikely branch hints (TypeScript doesn't support these)
 */
export function LIKELY(x: boolean): boolean {
    return x;
}

export function UNLIKELY(x: boolean): boolean {
    return x;
}

/**
 * Noexcept specifier
 */
export function NOEXCEPT<T extends (...args: unknown[]) => unknown>(fn: T): T {
    return fn;
}

/**
 * Maybe unused annotation
 */
export function MAYBE_UNUSED<T>(x: T): T {
    return x;
}

/**
 * Returns the number of elements in a static array
 */
export function ARRAY_SIZE(arr: readonly unknown[]): number {
    return arr.length;
}

/**
 * Static assert
 */
export function static_assert(condition: boolean, message?: string): void {
    if (!condition) {
        throw new Error(message ?? 'Static assertion failed');
    }
}
