// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Pre-allocated vector - a vector with inline storage for small sizes.
 * This is a TypeScript port of Bitcoin Core's prevector.h.
 */

/**
 * Prevector - a vector that stores elements inline when small, and
 * dynamically allocates when large.
 */
export class Prevector<T> {
    private _size: number;
    private _capacitySmall: number;
    private _capacity: number;
    private _data: (T | undefined)[];
    private _inlineData: (T | undefined)[];
    private _isInline: boolean;

    constructor(capacitySmall: number = 4) {
        this._size = 0;
        this._capacitySmall = capacitySmall;
        this._capacity = capacitySmall;
        this._inlineData = new Array(capacitySmall);
        this._data = this._inlineData;
        this._isInline = true;
    }

    static fromArray<T>(capacitySmall: number, array: readonly T[]): Prevector<T> {
        const result = new Prevector<T>(capacitySmall);
        result._size = array.length;
        result._capacity = Math.max(capacitySmall, array.length);
        if (!result._isInline && result._capacity > capacitySmall) {
            result._data = new Array(result._capacity);
            result._isInline = false;
        }
        for (let i = 0; i < array.length; i++) {
            result._data[i] = array[i];
        }
        return result;
    }

    size(): number {
        return this._size;
    }

    empty(): boolean {
        return this._size === 0;
    }

    capacity(): number {
        return this._capacity;
    }

    front(): T {
        return this._data[0] as T;
    }

    back(): T {
        return this._data[this._size - 1] as T;
    }

    at(index: number): T | undefined {
        if (index < 0 || index >= this._size) {
            return undefined;
        }
        return this._data[index];
    }

    [index: number]: T | undefined;

    data(): (T | undefined)[] {
        return this._data;
    }

    [Symbol.iterator](): Iterator<T> {
        let index = 0;
        return {
            next: (): IteratorResult<T> => {
                if (index < this._size) {
                    return { done: false, value: this._data[index++] as T };
                }
                return { done: true, value: undefined as unknown as T };
            }
        };
    }

    begin(): Iterator<T> {
        return this[Symbol.iterator]();
    }

    resize(newSize: number, fillValue?: T): void {
        if (newSize > this._size) {
            this.reserve(newSize);
            for (let i = this._size; i < newSize; i++) {
                this._data[i] = fillValue ?? undefined;
            }
        }
        this._size = newSize;
    }

    reserve(newCapacity: number): void {
        if (newCapacity <= this._capacity) {
            return;
        }

        const newData: (T | undefined)[] = new Array(newCapacity);
        for (let i = 0; i < this._size; i++) {
            newData[i] = this._data[i];
        }
        this._data = newData;
        this._capacity = newCapacity;
        this._isInline = false;
    }

    push_back(value: T): void {
        if (this._size === this._capacity) {
            this.reserve(Math.max(this._capacity * 2, this._capacitySmall * 2));
        }
        this._data[this._size++] = value;
    }

    pop_back(): T | undefined {
        if (this._size === 0) {
            return undefined;
        }
        return this._data[--this._size];
    }

    insert(position: number, value: T): void {
        if (position < 0 || position > this._size) {
            throw new Error('Position out of range');
        }
        
        if (this._size === this._capacity) {
            this.reserve(Math.max(this._capacity * 2, this._capacitySmall * 2));
        }
        
        for (let i = this._size; i > position; i--) {
            this._data[i] = this._data[i - 1];
        }
        
        this._data[position] = value;
        this._size++;
    }

    erase(position: number, count: number = 1): void {
        if (position < 0 || position + count > this._size) {
            throw new Error('Position out of range');
        }
        
        for (let i = position; i + count < this._size; i++) {
            this._data[i] = this._data[i + count];
        }
        
        this._size -= count;
    }

    clear(): void {
        this._size = 0;
    }

    swap(other: Prevector<T>): void {
        const tempSize = this._size;
        const tempCapacity = this._capacity;
        const tempData = this._data;
        const tempIsInline = this._isInline;

        this._size = other._size;
        this._capacity = other._capacity;
        this._data = other._data;
        this._isInline = other._isInline;

        other._size = tempSize;
        other._capacity = tempCapacity;
        other._data = tempData;
        other._isInline = tempIsInline;
        other._isInline = tempIsInline;
    }

    toArray(): T[] {
        return this._data.slice(0, this._size) as T[];
    }

    /**
     * Get the total allocated memory in bytes.
     * Returns 0 for inline storage (no dynamic allocation).
     */
    allocated_memory(): number {
        if (this._isInline) {
            return 0; // Inline storage - no dynamic allocation
        }
        // Dynamic storage: capacity * element size (estimate 16 bytes per element)
        return this._capacity * 16;
    }
}

export function prevector<T>(...items: T[]): Prevector<T> {
    const result = new Prevector<T>();
    for (const item of items) {
        result.push_back(item);
    }
    return result;
}
