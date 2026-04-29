// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Ban Management
 * TypeScript port of Bitcoin Core's src/banman.h
 * 
 * BanMan manages two related concepts:
 * 1. Banning — User-configured permanent (or timed) blocks of IPs/subnets
 * 2. Discouragement — Automatic marking of misbehaving peers
 * 
 * Banned addresses are persisted to disk and restored on startup.
 * Discouraged peers are kept in a bloom filter (probabilistic, not listed).
 */

// Import CSubNet from netaddress (must be at top-level for type usage)
import type { CSubNet, CNetAddr, CService } from "../netaddress";
import { CSubNet as CSubNetType } from "../netaddress";

export { CSubNet, CNetAddr, CService };

/** Default ban duration: 24 hours (in seconds). */
export const DEFAULT_MISBEHAVING_BANTIME = 60 * 60 * 24;

/** How often to dump banned addresses to disk (in minutes). */
export const DUMP_BANS_INTERVAL_MINUTES = 15;

/**
 * CBanEntry — A single ban record for a subnet.
 * Stored in the ban database (banlist.json).
 */
export interface CBanEntry {
    /** Serialization format version. */
    nVersion: number;
    /** When this ban was created (Unix timestamp). */
    nCreateTime: number;
    /** When this ban expires (Unix timestamp). 0 = permanent. */
    nBanUntil: number;
}

/** Current serialization version for CBanEntry. */
export const CBAN_ENTRY_CURRENT_VERSION = 1;

/**
 * Create a new CBanEntry.
 */
export function newCBanEntry(nCreateTime: number): CBanEntry {
    return {
        nVersion: CBAN_ENTRY_CURRENT_VERSION,
        nCreateTime,
        nBanUntil: 0,
    };
}

/**
 * Create a timed ban entry.
 */
export function newTimedBanEntry(nCreateTime: number, nBanUntil: number): CBanEntry {
    return {
        nVersion: CBAN_ENTRY_CURRENT_VERSION,
        nCreateTime,
        nBanUntil,
    };
}

/**
 * Check if a ban entry is currently active.
 */
export function CBanEntry_IsActive(entry: CBanEntry, nowSeconds: number): boolean {
    if (entry.nBanUntil === 0) return true; // Permanent
    return nowSeconds < entry.nBanUntil;
}

/**
 * Convert a CBanEntry to JSON for serialization.
 */
export function CBanEntry_ToJson(entry: CBanEntry): Record<string, unknown> {
    return {
        version: entry.nVersion,
        create_time: entry.nCreateTime,
        ban_until: entry.nBanUntil,
    };
}

/**
 * Parse a CBanEntry from JSON.
 */
export function CBanEntry_FromJson(json: Record<string, unknown>): CBanEntry {
    return {
        nVersion: (json["version"] as number) ?? CBAN_ENTRY_CURRENT_VERSION,
        nCreateTime: (json["create_time"] as number) ?? 0,
        nBanUntil: (json["ban_until"] as number) ?? 0,
    };
}

/**
 * banmap_t — Map of subnets to ban entries.
 * The on-disk representation of the ban list.
 */
export type banmap_t = Map<CSubNet, CBanEntry>;

/**
 * Convert a banmap_t to JSON for RPC responses.
 */
export function BanMapToJson(banmap: banmap_t): Array<Record<string, unknown>> {
    const result: Array<Record<string, unknown>> = [];
    for (const [subnet, entry] of banmap) {
        result.push({
            address: CSubNet_ToString(subnet),
            banned_until: entry.nBanUntil,
            ban_created: entry.nCreateTime,
            ban_reason: "manual",
        });
    }
    return result;
}

/**
 * Serialize a CSubNet to a string key for map lookup.
 */
export function CSubNet_ToString(subnet: CSubNet): string {
    if (!subnet.valid) return "";
    return `${subnet.network.m_net}:${Array.from(subnet.network.m_addr)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")}/${subnet.netmask[0] === 255 ? 8 : subnet.netmask[0] === 0 ? 0 : "?"}`;
}

/**
 * BanMan interface — manages banning and discouragement.
 */
export interface BanMan {
    /**
     * Ban an address or subnet.
     * @param subnet CNetAddr (single address) or CSubNet.
     * @param banTimeOffset Seconds to add to current time (0 = use default).
     * @param sinceUnixEpoch If true, banTimeOffset is added to Unix epoch.
     */
    Ban(subnet: CNetAddr | CSubNet, banTimeOffset?: number, sinceUnixEpoch?: boolean): void;

    /**
     * Discourage a peer (mark as undesirable without banning).
     * Discouraged peers are kept in a bloom filter and preferred for eviction.
     * @param netAddr Address to discourage.
     */
    Discourage(netAddr: CNetAddr): void;

    /**
     * Clear all bans and discouragement.
     */
    ClearBanned(): void;

    /**
     * Check if an address or subnet is banned.
     * @param subnet Address or subnet to check.
     * @returns true if banned.
     */
    IsBanned(subnet: CNetAddr | CSubNet): boolean;

    /**
     * Check if an address is discouraged.
     * @param netAddr Address to check.
     * @returns true if discouraged (probabilistic).
     */
    IsDiscouraged(netAddr: CNetAddr): boolean;

    /**
     * Unban an address or subnet.
     * @param subnet Address or subnet to unban.
     * @returns true if found and removed.
     */
    Unban(subnet: CNetAddr | CSubNet): boolean;

    /**
     * Get all banned entries.
     * @param banmap Output map to fill with current bans.
     */
    GetBanned(banmap: banmap_t): void;

    /**
     * Dump ban list to disk.
     */
    DumpBanlist(): void;
}

/**
 * CRollingBloomFilter — Probabilistic set for address tracking.
 * 
 * Used for the "discouraged" set: we can test membership but not enumerate.
 * False positives are possible; false negatives are not.
 * 
 * This is a space-efficient probabilistic data structure based on
 * multiple hash functions. The real Bitcoin Core implementation uses
 * MurmurHash3 in double-hashing mode.
 */
export class CRollingBloomFilter {
    private data: Uint8Array;
    private nHashFuncs: number;
    private nTweak: number;
    private size: number;

    /**
     * @param nElementsRough Expected number of elements.
     * @param nFpRate False positive rate (e.g. 0.000001 for 0.0001%).
     */
    constructor(nElementsRough: number, nFpRate: number) {
        // Calculate optimal size in bits
        const nBits = Math.ceil(
            -nElementsRough * Math.log(nFpRate) / (Math.LN2 * Math.LN2),
        );
        this.size = Math.ceil(nBits / 8);
        this.data = new Uint8Array(this.size);
        this.nHashFuncs = Math.max(1, Math.round((nBits / nElementsRough) * Math.LN2));
        this.nTweak = Math.floor(Math.random() * 0xffffffff);
    }

    /**
     * MurmurHash3 — hash a key with two seed values.
     */
    private murmurHash3(data: Uint8Array, seed0: number, seed1: number): number {
        const c1 = 0xcc9e2d51;
        const c2 = 0x1b873593;

        let h1 = seed0;
        let h2 = seed1;

        // Process in 4-byte chunks
        const len = data.length;
        const nblocks = Math.floor(len / 4);

        for (let i = 0; i < nblocks; i++) {
            let k1 =
                (data[i * 4] |
                    (data[i * 4 + 1] << 8) |
                    (data[i * 4 + 2] << 16) |
                    (data[i * 4 + 3] << 24)) >>>
                0;

            k1 = Math.imul(k1, c1);
            k1 = (k1 << 15) | (k1 >>> 17);
            k1 = Math.imul(k1, c2);

            h1 ^= k1;
            h1 = (h1 << 13) | (h1 >>> 19);
            h1 = Math.imul(h1, 5) + 0xe6546b64;
        }

        // Handle remaining bytes
        let k1 = 0;
        let k2 = 0;
        const tail = len - nblocks * 4;
        if (tail >= 3) k1 ^= data[nblocks * 4 + 2] << 16;
        if (tail >= 2) k1 ^= data[nblocks * 4 + 1] << 8;
        if (tail >= 1) {
            k1 ^= data[nblocks * 4];
            k1 = Math.imul(k1, c1);
            k1 = (k1 << 15) | (k1 >>> 17);
            k1 = Math.imul(k1, c2);
            h1 ^= k1;
        }

        // Finalization
        h1 ^= len;
        h2 ^= len;
        h1 = h1 ^ (h1 >>> 16);
        h1 = Math.imul(h1, 0x85ebca6b);
        h1 = h1 ^ (h1 >>> 13);
        h1 = Math.imul(h1, 0xc2b2ae35);
        h1 = h1 ^ (h1 >>> 16);
        h2 = h2 ^ (h2 >>> 16);
        h2 = Math.imul(h2, 0x85ebca6b);
        h2 = h2 ^ (h2 >>> 13);
        h2 = Math.imul(h2, 0xc2b2ae35);
        h2 = h2 ^ (h2 >>> 16);

        return ((h1 >>> 0) << 32) | (h2 >>> 0);
    }

    /**
     * Insert a key into the filter.
     */
    insert(key: Uint8Array): void {
        const totalBits = this.size * 8;
        let hash0 = this.murmurHash3(key, 0x00000000, this.nTweak);
        let hash1 = this.murmurHash3(key, hash0 >>> 32, hash0 & 0xffffffff);

        for (let i = 0; i < this.nHashFuncs; i++) {
            const bit = Number((BigInt(hash0) + BigInt(i) * BigInt(hash1)) % BigInt(totalBits));
            this.data[Math.floor(bit / 8)] |= 1 << (bit % 8);
        }
    }

    /**
     * Check if a key might be in the filter.
     * @returns true if possibly present, false if definitely absent.
     */
    contains(key: Uint8Array): boolean {
        const totalBits = this.size * 8;
        let hash0 = this.murmurHash3(key, 0x00000000, this.nTweak);
        let hash1 = this.murmurHash3(key, hash0 >>> 32, hash0 & 0xffffffff);

        for (let i = 0; i < this.nHashFuncs; i++) {
            const bit = Number((BigInt(hash0) + BigInt(i) * BigInt(hash1)) % BigInt(totalBits));
            if (!(this.data[Math.floor(bit / 8)] & (1 << (bit % 8)))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Reset the filter to empty state.
     */
    reset(): void {
        this.data.fill(0);
    }
}

/**
 * BanManStub — A stub implementation of BanMan for TypeScript environments.
 */
export class BanManStub implements BanMan {
    private banned: Map<string, CBanEntry> = new Map();
    private discouraged: CRollingBloomFilter;
    private defaultBanTime: number;
    private isDirty = false;

    constructor(defaultBanTime: number = DEFAULT_MISBEHAVING_BANTIME) {
        this.defaultBanTime = defaultBanTime;
        // Default: 50000 elements, 0.000001 false positive rate
        this.discouraged = new CRollingBloomFilter(50000, 0.000001);
    }

    Ban(subnet: CNetAddr | CSubNet, banTimeOffset = 0, sinceUnixEpoch = false): void {
        const now = Math.floor(Date.now() / 1000);
        const banTime = sinceUnixEpoch
            ? banTimeOffset
            : now + (banTimeOffset || this.defaultBanTime);

        // Extract address bytes for the map key
        let key: string;
        if ("m_addr" in subnet && "m_net" in subnet) {
            // It's a CNetAddr
            key = `${subnet.m_net}:${Array.from(subnet.m_addr)
                .map((b: number) => b.toString(16).padStart(2, "0"))
                .join("")}`;
        } else {
            // It's a CSubNet
            key = `${subnet.network.m_net}:${Array.from(subnet.network.m_addr)
                .map((b: number) => b.toString(16).padStart(2, "0"))
                .join("")}`;
        }

        this.banned.set(key, newCBanEntry(now));
        this.banned.get(key)!.nBanUntil = banTime;
        this.isDirty = true;
    }

    Discourage(netAddr: CNetAddr): void {
        const key = `${netAddr.m_net}:${Array.from(netAddr.m_addr)
            .map((b: number) => b.toString(16).padStart(2, "0"))
            .join("")}`;
        this.discouraged.insert(new TextEncoder().encode(key));
        this.isDirty = true;
    }

    ClearBanned(): void {
        this.banned.clear();
        this.discouraged.reset();
        this.isDirty = true;
    }

    IsBanned(subnet: CNetAddr | CSubNet): boolean {
        const now = Math.floor(Date.now() / 1000);
        const key = this.subnetKey(subnet);
        const entry = this.banned.get(key);
        if (!entry) return false;
        return CBanEntry_IsActive(entry, now);
    }

    IsDiscouraged(netAddr: CNetAddr): boolean {
        const key = `${netAddr.m_net}:${Array.from(netAddr.m_addr)
            .map((b: number) => b.toString(16).padStart(2, "0"))
            .join("")}`;
        return this.discouraged.contains(new TextEncoder().encode(key));
    }

    Unban(subnet: CNetAddr | CSubNet): boolean {
        const key = this.subnetKey(subnet);
        const existed = this.banned.has(key);
        this.banned.delete(key);
        if (existed) this.isDirty = true;
        return existed;
    }

    GetBanned(banmap: banmap_t): void {
        banmap.clear();
        for (const [key, entry] of this.banned) {
            // Parse key back to CSubNet (simplified)
            const parts = key.split(":");
            if (parts.length >= 2) {
                const netBytes = Uint8Array.from(
                    (parts[1].match(/.{1,2}/g) as RegExpMatchArray).map((h: string) => parseInt(h, 16)),
                );
                const subnet: CSubNetType = {
                    network: {
                        m_addr: netBytes,
                        m_net: parseInt(parts[0], 10),
                        m_scope_id: 0,
                    },
                    netmask: new Uint8Array(16),
                    valid: true,
                };
                banmap.set(subnet, entry);
            }
        }
    }

    DumpBanlist(): void {
        // In a real implementation, this would write to banlist.dat
        this.isDirty = false;
    }

    private subnetKey(subnet: CNetAddr | CSubNet): string {
        if ("m_addr" in subnet && "m_net" in subnet && !("netmask" in subnet)) {
            return `${subnet.m_net}:${Array.from(subnet.m_addr)
                .map((b: number) => b.toString(16).padStart(2, "0"))
                .join("")}`;
        }
        const sn = subnet as CSubNet;
        return `${sn.network.m_net}:${Array.from(sn.network.m_addr)
            .map((b: number) => b.toString(16).padStart(2, "0"))
            .join("")}`;
    }
}
