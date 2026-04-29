// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Address types for Bitcoin scripts.
 */

export enum OutputType {
    LEGACY = 'p2pkh',
    LEGACY_P2SH = 'p2sh',
    BECH32 = 'p2wpkh',
    BECH32M = 'p2wsh',
}

export enum AddressType {
    LEGACY = 'legacy',
    P2SH_SEGWIT = 'p2sh-segwit',
    BECH32 = 'bech32',
    BECH32M = 'bech32m',
}

export type CTxDestination = 
    | PKHash
    | ScriptHash
    | WitnessPKHash
    | WitnessScriptHash;

export class PKHash {
    static readonly SIZE = 20;
    readonly data: Uint8Array;

    constructor(data?: Uint8Array | readonly number[] | string) {
        this.data = new Uint8Array(20);
        if (data !== undefined) {
            if (typeof data === 'string') {
                let offset = 0;
                for (let i = 0; i < 20; i++) {
                    const hi = parseInt(data[offset++], 16);
                    const lo = parseInt(data[offset++], 16);
                    this.data[i] = (hi << 4) | lo;
                }
            } else {
                this.data.set(data);
            }
        }
    }

    getHex(): string {
        return Array.from(this.data).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    toString(): string {
        return this.getHex();
    }
}

export class ScriptHash {
    static readonly SIZE = 20;
    readonly data: Uint8Array;

    constructor(data?: Uint8Array | readonly number[] | string) {
        this.data = new Uint8Array(20);
        if (data !== undefined) {
            if (typeof data === 'string') {
                let offset = 0;
                for (let i = 0; i < 20; i++) {
                    const hi = parseInt(data[offset++], 16);
                    const lo = parseInt(data[offset++], 16);
                    this.data[i] = (hi << 4) | lo;
                }
            } else {
                this.data.set(data);
            }
        }
    }

    getHex(): string {
        return Array.from(this.data).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    toString(): string {
        return this.getHex();
    }
}

export class WitnessPKHash {
    static readonly SIZE = 20;
    readonly data: Uint8Array;

    constructor(data?: Uint8Array | readonly number[] | string) {
        this.data = new Uint8Array(20);
        if (data !== undefined) {
            if (typeof data === 'string') {
                let offset = 0;
                for (let i = 0; i < 20; i++) {
                    const hi = parseInt(data[offset++], 16);
                    const lo = parseInt(data[offset++], 16);
                    this.data[i] = (hi << 4) | lo;
                }
            } else {
                this.data.set(data);
            }
        }
    }

    getHex(): string {
        return Array.from(this.data).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    toString(): string {
        return this.getHex();
    }
}

export class WitnessScriptHash {
    static readonly SIZE = 32;
    readonly data: Uint8Array;

    constructor(data?: Uint8Array | readonly number[] | string) {
        this.data = new Uint8Array(32);
        if (data !== undefined) {
            if (typeof data === 'string') {
                let offset = 0;
                for (let i = 0; i < 32; i++) {
                    const hi = parseInt(data[offset++], 16);
                    const lo = parseInt(data[offset++], 16);
                    this.data[i] = (hi << 4) | lo;
                }
            } else {
                this.data.set(data);
            }
        }
    }

    isNull(): boolean {
        for (let i = 0; i < 32; i++) {
            if (this.data[i] !== 0) return false;
        }
        return true;
    }

    getHex(): string {
        return Array.from(this.data).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    toString(): string {
        return this.getHex();
    }
}

export function isPKHash(dest: CTxDestination): dest is PKHash {
    return dest instanceof PKHash;
}

export function isScriptHash(dest: CTxDestination): dest is ScriptHash {
    return dest instanceof ScriptHash;
}

export function isWitnessPKHash(dest: CTxDestination): dest is WitnessPKHash {
    return dest instanceof WitnessPKHash;
}

export function isWitnessScriptHash(dest: CTxDestination): dest is WitnessScriptHash {
    return dest instanceof WitnessScriptHash;
}

export function getOutputType(dest: CTxDestination): OutputType {
    if (isPKHash(dest)) {
        return OutputType.LEGACY;
    } else if (isScriptHash(dest)) {
        return OutputType.LEGACY_P2SH;
    } else if (isWitnessPKHash(dest)) {
        return OutputType.BECH32;
    } else if (isWitnessScriptHash(dest)) {
        return OutputType.BECH32M;
    }
    throw new Error('Unknown destination type');
}

export const PKHASH_SIZE = 20;
export const WITNESS_PKHASH_SIZE = 20;
export const WITNESS_SCRIPTHASH_SIZE = 32;
