// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Span type for working with contiguous sequences of objects.
 * This is a TypeScript port of Bitcoin Core's span.h.
 */

/**
 * A Span is an object that can refer to a contiguous sequence of objects.
 * Similar to std::span in C++20.
 */
export class Span<T = number> {
    private _data: T[];
    private _offset: number;
    private _size: number;

    constructor(data: T[]);
    constructor(span: Span<T>);
    constructor(data: T[], offset: number, size: number);
    constructor(dataOrSpan: T[] | Span<T>, offset?: number, size?: number) {
        if (dataOrSpan instanceof Span) {
            this._data = dataOrSpan._data;
            this._offset = dataOrSpan._offset;
            this._size = dataOrSpan._size;
        } else {
            this._data = dataOrSpan;
            this._offset = offset ?? 0;
            this._size = size ?? dataOrSpan.length;
        }
    }

    data(): T[] {
        return this._data.slice(this._offset, this._offset + this._size);
    }

    size(): number {
        return this._size;
    }

    length(): number {
        return this._size;
    }

    empty(): boolean {
        return this._size === 0;
    }

    first(count: number): Span<T> {
        return new Span(this._data, this._offset, Math.min(count, this._size));
    }

    last(count: number): Span<T> {
        const start = Math.max(this._offset, this._offset + this._size - count);
        return new Span(this._data, start, this._offset + this._size - start);
    }

    subspan(offset: number, count?: number): Span<T> {
        const newOffset = this._offset + offset;
        const newSize = count !== undefined ? Math.min(count, this._size - offset) : this._size - offset;
        return new Span(this._data, newOffset, newSize);
    }

    front(): T {
        return this._data[this._offset];
    }

    back(): T {
        return this._data[this._offset + this._size - 1];
    }

    /**
     * Convert span to Uint8Array (only for number spans)
     */
    toUint8Array(): Uint8Array {
        if (typeof this._data[0] === 'number') {
            const result = new Uint8Array(this._size);
            for (let i = 0; i < this._size; i++) {
                result[i] = this._data[this._offset + i] as number;
            }
            return result;
        }
        throw new Error('Cannot convert non-number span to Uint8Array');
    }

    /**
     * Iterator support
     */
    [Symbol.iterator](): Iterator<T> {
        let index = this._offset;
        const end = this._offset + this._size;
        return {
            next: (): IteratorResult<T> => {
                if (index < end) {
                    return { done: false, value: this._data[index++] };
                }
                return { done: true, value: undefined as unknown as T };
            }
        };
    }
}

/**
 * Pop the last element off a span, and return a reference to that element.
 */
export function spanPopBack<T>(span: Span<T>): T {
    const size = span.size();
    const back = span.back();
    return back;
}

/**
 * Create a span from an array-like object
 */
export function makeSpan<T>(data: T[]): Span<T>;
export function makeSpan(data: Uint8Array): Span<number>;
export function makeSpan(data: Uint8Array | number[]): Span<number> {
    return new Span(Array.from(data));
}

/**
 * Convert any Span to a ReadonlySpan<number> (bytes)
 */
export function makeByteSpan(data: Uint8Array | number[]): Span<number> {
    return new Span(Array.from(data));
}

/**
 * Convert any Span to a writable Span<number> (bytes)
 */
export function makeWritableByteSpan(data: Uint8Array | number[]): Span<number> {
    return new Span(Array.from(data));
}

/**
 * Cast a span to const unsigned char
 */
export function asBytes<T>(span: Span<T>): Span<number> {
    if (typeof span.data()[0] === 'number') {
        return span as unknown as Span<number>;
    }
    throw new Error('Cannot convert non-number span to bytes');
}

/**
 * Check if a value is a span
 */
export function isSpan<T>(value: unknown): value is Span<T> {
    return value instanceof Span;
}

/**
 * Create a Uint8Array from various input types
 */
export function toUint8Array(data: Uint8Array | readonly number[] | number[]): Uint8Array {
    if (data instanceof Uint8Array) {
        return data;
    }
    return new Uint8Array(data);
}

/**
 * Convert a Uint8Array to a number array
 */
export function toNumberArray(data: Uint8Array | readonly number[]): number[] {
    return Array.from(data);
}
