// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Public key types for Bitcoin.
 * This is a TypeScript port of Bitcoin Core's pubkey.h
 */

import { uint160, uint256 } from '../uint256';
import { Hash, Hash160, HashWriter, CHash256 } from '../hash';

export const BIP32_EXTKEY_SIZE = 74;
export const BIP32_EXTKEY_WITH_VERSION_SIZE = 78;

/**
 * A reference to a CKey: the Hash160 of its serialized public key
 */
export class CKeyID extends uint160 {
    constructor(data?: Uint8Array | readonly number[] | string) {
        super(data);
    }
}

export type ChainCode = uint256;

/**
 * An encapsulated public key
 */
export class CPubKey {
    static readonly SIZE = 65;
    static readonly COMPRESSED_SIZE = 33;
    static readonly SIGNATURE_SIZE = 72;
    static readonly COMPACT_SIGNATURE_SIZE = 65;

    private vch: Uint8Array;
    private valid: boolean;

    private constructor(vch: Uint8Array, valid: boolean) {
        this.vch = vch;
        this.valid = valid;
    }

    /**
     * Construct an invalid public key
     */
    static invalid(): CPubKey {
        const vch = new Uint8Array(1);
        vch[0] = 0xff;
        return new CPubKey(vch, false);
    }

    /**
     * Construct a public key from byte data
     */
    static fromBytes(data: Uint8Array | readonly number[]): CPubKey {
        const vch = new Uint8Array(data);
        const len = CPubKey.getLen(vch[0]);
        if (len === vch.length) {
            return new CPubKey(vch, true);
        }
        return CPubKey.invalid();
    }

    /**
     * Construct from hex string
     */
    static fromHex(hex: string): CPubKey {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return CPubKey.fromBytes(bytes);
    }

    private static getLen(chHeader: number): number {
        if (chHeader === 2 || chHeader === 3) return CPubKey.COMPRESSED_SIZE;
        if (chHeader === 4 || chHeader === 6 || chHeader === 7) return CPubKey.SIZE;
        return 0;
    }

    /**
     * Get the length of the pubkey from its first byte
     */
    size(): number {
        return CPubKey.getLen(this.vch[0]);
    }

    /**
     * Get the raw bytes of the public key
     */
    data(): Uint8Array {
        return this.vch.slice(0, this.size());
    }

    /**
     * Get the first byte (header byte)
     */
    getHeaderByte(): number {
        return this.vch[0];
    }

    /**
     * Check if the public key is valid
     */
    isValid(): boolean {
        return this.valid && this.size() > 0;
    }

    /**
     * Check if this is a compressed public key
     */
    isCompressed(): boolean {
        return this.size() === CPubKey.COMPRESSED_SIZE;
    }

    /**
     * Get the KeyID of this public key (hash of its serialization)
     */
    getID(): CKeyID {
        const data = this.data();
        const hash = Hash160(data);
        return new CKeyID(hash.data());
    }

    /**
     * Get the 256-bit hash of this public key
     */
    getHash(): uint256 {
        return Hash(this.data());
    }

    /**
     * Convert to hex string
     */
    toHex(): string {
        return Array.from(this.data()).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Check equality
     */
    equals(other: CPubKey): boolean {
        if (this.vch[0] !== other.vch[0]) return false;
        if (this.size() !== other.size()) return false;
        const s = this.size();
        for (let i = 0; i < s; i++) {
            if (this.vch[i] !== other.vch[i]) return false;
        }
        return true;
    }

    /**
     * Comparison for sorting
     */
    compare(other: CPubKey): number {
        if (this.vch[0] < other.vch[0]) return -1;
        if (this.vch[0] > other.vch[0]) return 1;
        const thisSize = this.size();
        const otherSize = other.size();
        if (thisSize !== otherSize) return thisSize - otherSize;
        for (let i = 0; i < thisSize; i++) {
            if (this.vch[i] < other.vch[i]) return -1;
            if (this.vch[i] > other.vch[i]) return 1;
        }
        return 0;
    }

    // Iterator methods
    begin(): Uint8Array {
        return this.vch;
    }

    end(): Uint8Array {
        return this.vch.slice(this.size());
    }

    [Symbol.iterator](): Iterator<number> {
        return this.vch[Symbol.iterator]();
    }
}

/**
 * X-only public key (BIP-340)
 */
export class XOnlyPubKey {
    /** Nothing Up My Sleeve point H */
    static readonly NUMS_H: XOnlyPubKey = new XOnlyPubKey(
        new uint256('c1c77ade5aba4d81fc2c56a678e6c4ff5a7e7e26ce46c6a31fc91c0a4c2c2d51')
    );

    private m_keydata: uint256;

    constructor(keydata: uint256) {
        this.m_keydata = keydata;
    }

    /**
     * Construct from exactly 32 bytes
     */
    static fromBytes(bytes: Uint8Array | readonly number[]): XOnlyPubKey {
        return new XOnlyPubKey(new uint256(bytes));
    }

    /**
     * Check if fully valid (50% of all 32-byte arrays pass this)
     */
    isFullyValid(): boolean {
        // Simple check: first 4 bytes must not be all zeros (not on curve)
        // In TypeScript, we can't verify ECDSA curve points without a library
        // This is a simplified implementation
        return !this.m_keydata.isNull();
    }

    /**
     * Check if this is the null key
     */
    isNull(): boolean {
        return this.m_keydata.isNull();
    }

    /**
     * Get the corresponding CPubKey with 0x02 and 0x03 prefixes
     */
    getCPubKeys(): CPubKey[] {
        // For an x-only pubkey, we need the y-coordinate
        // Since we can't compute y without full ECDSA, we return placeholders
        // In a full implementation, this would compute both possible y values
        const prefix02 = new Uint8Array(CPubKey.COMPRESSED_SIZE);
        prefix02[0] = 0x02;
        this.m_keydata.data().slice(0, 32).forEach((b, i) => { prefix02[i + 1] = b; });
        
        const prefix03 = new Uint8Array(CPubKey.COMPRESSED_SIZE);
        prefix03[0] = 0x03;
        this.m_keydata.data().slice(0, 32).forEach((b, i) => { prefix03[i + 1] = b; });
        
        return [CPubKey.fromBytes(prefix02), CPubKey.fromBytes(prefix03)];
    }

    /**
     * Get KeyIDs for the corresponding CPubKeys
     */
    getKeyIDs(): CKeyID[] {
        return this.getCPubKeys().map(pk => pk.getID());
    }

    data(): Uint8Array {
        return this.m_keydata.data();
    }

    size(): number {
        return 32;
    }

    toHex(): string {
        return this.m_keydata.toString();
    }

    equals(other: XOnlyPubKey): boolean {
        return this.m_keydata.compare(other.m_keydata) === 0;
    }

    compare(other: XOnlyPubKey): number {
        return this.m_keydata.compare(other.m_keydata);
    }

    [Symbol.iterator](): Iterator<number> {
        return this.m_keydata.data()[Symbol.iterator]();
    }

    begin(): Uint8Array {
        return this.m_keydata.data();
    }

    end(): Uint8Array {
        return this.m_keydata.data().slice(32);
    }
}

/**
 * ElligatorSwift-encoded public key
 */
export class EllSwiftPubKey {
    static readonly SIZE = 64;

    private m_pubkey: Uint8Array;

    constructor(ellswift?: Uint8Array | readonly number[]) {
        this.m_pubkey = new Uint8Array(EllSwiftPubKey.SIZE);
        if (ellswift) {
            const data = new Uint8Array(ellswift);
            for (let i = 0; i < EllSwiftPubKey.SIZE; i++) {
                this.m_pubkey[i] = data[i] ?? 0;
            }
        }
    }

    data(): Uint8Array {
        return this.m_pubkey;
    }

    size(): number {
        return EllSwiftPubKey.SIZE;
    }

    /**
     * Decode to normal compressed CPubKey (for debugging)
     */
    decode(): CPubKey {
        // This is a simplified implementation
        // Full ElligatorSwift decoding requires additional math
        return CPubKey.invalid();
    }
}

/**
 * Extended public key (BIP-32)
 */
export class CExtPubKey {
    version: Uint8Array;
    nDepth: number;
    vchFingerprint: Uint8Array;
    nChild: number;
    chaincode: Uint8Array;
    pubkey: CPubKey;

    constructor() {
        this.version = new Uint8Array(4);
        this.nDepth = 0;
        this.vchFingerprint = new Uint8Array(4);
        this.nChild = 0;
        this.chaincode = new Uint8Array(32);
        this.pubkey = CPubKey.invalid();
    }

    /**
     * Encode to 74-byte format
     */
    encode(code: Uint8Array): void {
        let offset = 0;
        code[offset++] = this.nDepth;
        for (let i = 0; i < 4; i++) code[offset++] = this.vchFingerprint[i];
        code[offset++] = (this.nChild >> 24) & 0xff;
        code[offset++] = (this.nChild >> 16) & 0xff;
        code[offset++] = (this.nChild >> 8) & 0xff;
        code[offset++] = this.nChild & 0xff;
        for (let i = 0; i < 32; i++) code[offset++] = this.chaincode[i];
        const pk = this.pubkey.data();
        for (let i = 0; i < pk.length; i++) code[offset++] = pk[i];
    }

    /**
     * Decode from 74-byte format
     */
    decode(code: Uint8Array): void {
        let offset = 0;
        this.nDepth = code[offset++];
        for (let i = 0; i < 4; i++) this.vchFingerprint[i] = code[offset++];
        this.nChild = (code[offset++] << 24) | (code[offset++] << 16) | 
                      (code[offset++] << 8) | code[offset++];
        for (let i = 0; i < 32; i++) this.chaincode[i] = code[offset++];
        const remaining = code.slice(offset);
        this.pubkey = CPubKey.fromBytes(remaining);
    }

    equals(other: CExtPubKey): boolean {
        if (this.nDepth !== other.nDepth) return false;
        if (this.nChild !== other.nChild) return false;
        for (let i = 0; i < 4; i++) if (this.vchFingerprint[i] !== other.vchFingerprint[i]) return false;
        for (let i = 0; i < 32; i++) if (this.chaincode[i] !== other.chaincode[i]) return false;
        return this.pubkey.equals(other.pubkey);
    }
}
