// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Compatibility headers for portability across platforms.
 * This is a TypeScript port of Bitcoin Core's compat/ headers.
 */

/**
 * Byte swap utilities for endianness conversion
 */
export function bswap16(x: number): number {
    return ((x & 0x00ff) << 8) | ((x & 0xff00) >> 8);
}

export function bswap32(x: number): number {
    return (
        ((x & 0x000000ff) << 24) |
        ((x & 0x0000ff00) << 8) |
        ((x & 0x00ff0000) >> 8) |
        ((x & 0xff000000) >> 24)
    );
}

export function bswap64(x: bigint): bigint {
    return (
        ((x & 0x00000000000000ffn) << 56n) |
        ((x & 0x000000000000ff00n) << 40n) |
        ((x & 0x0000000000ff0000n) << 24n) |
        ((x & 0x00000000ff000000n) << 8n) |
        ((x & 0x000000ff00000000n) >> 8n) |
        ((x & 0x0000ff0000000000n) >> 24n) |
        ((x & 0x00ff000000000000n) >> 40n) |
        ((x & 0xff00000000000000n) >> 56n)
    );
}

/**
 * CPU detection for SIMD support
 */
export class CPUID {
    private static ecx: number = 0;
    
    static detect(): void {
        // In TypeScript/JavaScript, we can't directly access CPUID
        // This is a placeholder - actual detection would need wasm/native
        this.ecx = 0;
    }
    
    static hasSSE2(): boolean {
        return (this.ecx & (1 << 26)) !== 0;
    }
    
    static hasSSE42(): boolean {
        return (this.ecx & (1 << 19)) !== 0;
    }
}

/**
 * Endianness conversion helpers
 */
export function htole16(x: number): number {
    return x;
}

export function htole32(x: number): number {
    return x;
}

export function htole64(x: bigint): bigint {
    return x;
}

export function le16toh(x: number): number {
    return x;
}

export function le32toh(x: number): number {
    return x;
}

export function le64toh(x: bigint): bigint {
    return x;
}

export function htobe16(x: number): number {
    return bswap16(x);
}

export function htobe32(x: number): number {
    return bswap32(x);
}

export function htobe64(x: bigint): bigint {
    return bswap64(x);
}

export function be16toh(x: number): number {
    return bswap16(x);
}

export function be32toh(x: number): number {
    return bswap32(x);
}

export function be64toh(x: bigint): bigint {
    return bswap64(x);
}

// Detect native endianness (assume little-endian for most modern systems)
export const GBYTE_ORDER = 0x1234n;
export const HTONL_TEST = 0x1234n;
export const ENDIANNESS = (() => {
    const test: number[] = [0x12, 0x34];
    const view = new DataView(new ArrayBuffer(2));
    view.setUint16(0, 0x1234);
    const bytes = new Uint8Array(view.buffer);
    return bytes[0] === 0x12 ? 'big' : 'little';
})();

/**
 * Assumption macros for compiler hints
 */
export function assume(condition: boolean): void {
    if (!condition) {
        throw new Error('Assumption failed');
    }
}

/**
 * Prevent compiler from inlining a function
 */
export function NOINLINE<T extends (...args: unknown[]) => unknown>(fn: T): T {
    return fn;
}

/**
 * Compiler branch prediction hints
 */
export function LIKELY(x: boolean): boolean {
    return x;
}

export function UNLIKELY(x: boolean): boolean {
    return x;
}

// Compatibility types
export type uint8_t = number;
export type uint16_t = number;
export type int16_t = number;
export type uint32_t = number;
export type int32_t = number;
export type uint64_t = bigint;
export type int64_t = bigint;
export type size_t = number;
export type ssize_t = number;

// Common compatibility macros
export const UNUSED = (x: unknown): unknown => x;
export const NORETURN = (): never => { throw new Error('unreachable'); };
