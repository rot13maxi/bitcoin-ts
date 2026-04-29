// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * 256-bit opaque blob type for Bitcoin Core.
 * This is the TypeScript port of Bitcoin Core's uint256 class.
 */

const HEX_CHARS = '0123456789abcdef';
const HEX_MAP: { [key: string]: number } = {};
for (let i = 0; i < HEX_CHARS.length; i++) {
    HEX_MAP[HEX_CHARS[i]] = i;
    HEX_MAP[HEX_CHARS[i].toUpperCase()] = i;
}

export function isHexString(str: string): boolean {
    if (str.length % 2 !== 0) return false;
    for (let i = 0; i < str.length; i++) {
        if (HEX_MAP[str[i]] === undefined) return false;
    }
    return true;
}

export function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        const hi = HEX_MAP[hex[i * 2]] ?? 0;
        const lo = HEX_MAP[hex[i * 2 + 1]] ?? 0;
        bytes[i] = (hi << 4) | lo;
    }
    return bytes;
}

export function bytesToHex(bytes: Uint8Array | number[]): string {
    let result = '';
    for (let i = 0; i < bytes.length; i++) {
        result += HEX_CHARS[(bytes[i] >> 4) & 0xf];
        result += HEX_CHARS[bytes[i] & 0xf];
    }
    return result;
}

export function readLE64(data: Uint8Array | number[], offset: number = 0): bigint {
    const view = new DataView(new ArrayBuffer(8));
    for (let i = 0; i < 8; i++) {
        view.setUint8(i, data[offset + i] ?? 0);
    }
    return view.getBigUint64(0, true);
}

export function writeLE64(data: Uint8Array | number[], offset: number, value: bigint): void {
    const view = new DataView(new ArrayBuffer(8));
    view.setBigUint64(0, value, true);
    for (let i = 0; i < 8; i++) {
        data[offset + i] = view.getUint8(i);
    }
}

export function readLE32(data: Uint8Array | number[], offset: number = 0): number {
    return (
        (data[offset] ?? 0) |
        ((data[offset + 1] ?? 0) << 8) |
        ((data[offset + 2] ?? 0) << 16) |
        ((data[offset + 3] ?? 0) << 24)
    );
}

export function writeLE32(data: Uint8Array | number[], offset: number, value: number): void {
    data[offset] = value & 0xff;
    data[offset + 1] = (value >> 8) & 0xff;
    data[offset + 2] = (value >> 16) & 0xff;
    data[offset + 3] = (value >> 24) & 0xff;
}

/**
 * Base class for fixed-sized opaque blobs
 */
export abstract class BaseBlob {
    protected m_data: Uint8Array;

    constructor() {
        this.m_data = new Uint8Array(0); // Will be overridden in subclasses
    }

    protected abstract get WIDTH(): number;

    isNull(): boolean {
        for (let i = 0; i < this.m_data.length; i++) {
            if (this.m_data[i] !== 0) return false;
        }
        return true;
    }

    setNull(): void {
        this.m_data.fill(0);
    }

    compare(other: BaseBlob): number {
        const width = Math.max(this.WIDTH, other.WIDTH);
        for (let i = 0; i < width; i++) {
            const a = i < this.WIDTH ? this.m_data[i] : 0;
            const b = i < other.WIDTH ? (other as any).m_data[i] : 0;
            if (a < b) return -1;
            if (a > b) return 1;
        }
        return 0;
    }

    data(): Uint8Array {
        return this.m_data;
    }

    /**
     * Get the data as a big-endian Uint8Array.
     * Returns a copy to avoid mutation.
     */
    getDataBE(): Uint8Array {
        const result = new Uint8Array(this.WIDTH);
        for (let i = 0; i < this.WIDTH; i++) {
            result[i] = this.m_data[this.WIDTH - 1 - i];
        }
        return result;
    }

    begin(): Uint8Array {
        return this.m_data;
    }

    end(): Uint8Array {
        return this.m_data;
    }

    size(): number {
        return this.WIDTH;
    }

    getUint64(pos: number): bigint {
        return readLE64(this.m_data, pos * 8);
    }

    getHex(): string {
        const reversed = new Uint8Array(this.WIDTH);
        for (let i = 0; i < this.WIDTH; i++) {
            reversed[i] = this.m_data[this.WIDTH - 1 - i];
        }
        return bytesToHex(reversed);
    }

    toString(): string {
        return this.getHex();
    }

    static fromHex(str: string): BaseBlob | null {
        throw new Error('Must be implemented by subclass');
    }
}

/**
 * 160-bit opaque blob
 */
export class uint160 extends BaseBlob {
    protected get WIDTH(): number { return 20; }

    constructor(data?: Uint8Array | readonly number[] | string) {
        super();
        this.m_data = new Uint8Array(20);
        if (data !== undefined) {
            if (typeof data === 'string') {
                if (data.length !== 40) throw new Error('Hex string must be 40 characters');
                let i = data.length;
                for (let j = 0; j < 20; j++) {
                    i -= 2;
                    const hi = HEX_MAP[data[i + 1]] ?? 0;
                    const lo = HEX_MAP[data[i]] ?? 0;
                    this.m_data[j] = (hi << 4) | lo;
                }
            } else {
                if (data.length !== 20) throw new Error('Data must be 20 bytes');
                this.m_data.set(data);
            }
        }
    }

    static fromHex(str: string): uint160 | null {
        if (!isHexString(str) || str.length !== 40) return null;
        return new uint160(str);
    }
}

/**
 * 256-bit opaque blob
 */
export class uint256 extends BaseBlob {
    protected get WIDTH(): number { return 32; }
    static readonly ZERO = new uint256();
    static readonly ONE = new uint256(1);

    constructor(value?: Uint8Array | readonly number[] | string | number) {
        super();
        this.m_data = new Uint8Array(32);
        if (value !== undefined) {
            if (typeof value === 'number') {
                if (value === 0) {
                    // Already initialized to zeros
                } else if (value === 1) {
                    this.m_data[0] = 1;
                } else {
                    let remaining = value;
                    for (let i = 0; i < 32 && remaining > 0; i++) {
                        this.m_data[i] = remaining & 0xff;
                        remaining = Math.floor(remaining / 256);
                    }
                }
            } else if (typeof value === 'string') {
                if (value.length !== 64) throw new Error('Hex string must be 64 characters');
                let i = value.length;
                for (let j = 0; j < 32; j++) {
                    i -= 2;
                    const hi = HEX_MAP[value[i + 1]] ?? 0;
                    const lo = HEX_MAP[value[i]] ?? 0;
                    this.m_data[j] = (hi << 4) | lo;
                }
            } else {
                if (value.length !== 32) throw new Error('Data must be 32 bytes');
                this.m_data.set(value);
            }
        }
    }

    static fromHex(str: string): uint256 | null {
        if (!isHexString(str) || str.length !== 64) return null;
        return new uint256(str);
    }

    static fromUserHex(str: string): uint256 | null {
        let input = str.startsWith('0x') ? str.slice(2) : str;
        if (input.length < 64) {
            input = input.padStart(64, '0');
        }
        return uint256.fromHex(input);
    }
}

export function blobEquals(a: BaseBlob, b: BaseBlob): boolean {
    return a.compare(b) === 0;
}

export function blobLessThan(a: BaseBlob, b: BaseBlob): boolean {
    return a.compare(b) < 0;
}

export class Txid extends uint256 {
    constructor(value?: Uint8Array | readonly number[] | string) {
        super(value as Uint8Array | readonly number[] | string);
    }
}

export class Wtxid extends uint256 {
    constructor(value?: Uint8Array | readonly number[] | string) {
        super(value as Uint8Array | readonly number[] | string);
    }
}

/** @deprecated Use Txid.fromHex instead */
export { Txid as uint256Txid };
/** @deprecated Use Wtxid.fromHex instead */
export { Wtxid as uint256Wtxid };
