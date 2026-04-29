// Copyright (c) 2012 Pieter Wuille
// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Address Manager
 * TypeScript port of Bitcoin Core's src/addrman.h
 * 
 * Stochastic address manager — maintains known peer addresses, organized into
 * "new" (untested) and "tried" (successfully connected) buckets.
 * 
 * Design goals:
 * - Keep address tables in-memory (asynchronously persisted to peers.dat)
 * - Prevent localized attackers from filling the table with their nodes
 * 
 * The implementation uses:
 * - 1024 "new" buckets for untested addresses (grouped by /16 for IPv4)
 * - 256 "tried" buckets for successfully connected addresses
 * - Cryptographic hashing for bucket selection
 */

// Import types needed by AddrMan
import type { CNetAddr, CService } from "../netaddress";
import { CAddress, ServiceFlags, Network } from "../protocol";

// Re-export key types for consumers of this module
export { CAddress, ServiceFlags, Network };

// AddrMan configuration constants
export const ADDRMAN_TRIED_BUCKETS_PER_GROUP = 8;
export const ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64;
export const ADDRMAN_NEW_BUCKETS_PER_ADDRESS = 8;
export const ADDRMAN_HORIZON = 30 * 24; // 30 days in hours
export const ADDRMAN_RETRIES = 3;
export const ADDRMAN_MAX_FAILURES = 10;
export const ADDRMAN_MIN_FAIL = 7 * 24; // 7 days in hours
export const ADDRMAN_REPLACEMENT = 4; // 4 hours
export const ADDRMAN_SET_TRIED_COLLISION_SIZE = 10;
export const ADDRMAN_TEST_WINDOW = 40; // 40 minutes

/** Default -checkaddrman interval (0 = disabled). */
export const DEFAULT_ADDRMAN_CONSISTENCY_CHECKS = 0;

/**
 * Location information for an address in AddrMan.
 */
export interface AddressPosition {
    /** Whether the address is in the tried table. */
    tried: boolean;
    /**
     * Multiplicity: tried entries are always 1.
     * New entries can have multiplicity 1..ADDRMAN_NEW_BUCKETS_PER_ADDRESS.
     */
    multiplicity: number;
    /** Bucket index. */
    bucket: number;
    /** Position within the bucket. */
    position: number;
}

/**
 * Create an AddressPosition.
 */
export function newAddressPosition(
    tried: boolean,
    multiplicity: number,
    bucket: number,
    position: number,
): AddressPosition {
    return { tried, multiplicity, bucket, position };
}

/**
 * AddrInfo — Information about a single address stored in AddrMan.
 */
export interface AddrInfo {
    /** The address itself. */
    addr: CAddress;
    /** Source of this address (who told us about it). */
    source: CNetAddr;
    /** Time we last successfully connected to this address. */
    nLastSuccess: number;
    /** Last attempt time (successful or not). */
    nLastTry: number;
    /** Total number of attempts to this address. */
    nAttempts: number;
    /** Reference count (how many buckets this address is in). */
    nRefCount: number;
    /** Network group (hashed to determine bucket). */
    nNetwork: number;
    /** Whether this address is in the tried table. */
    fInTried: boolean;
    /** Whether we have a collision pending for this address. */
    fInCollision: boolean;
}

/**
 * Create a new AddrInfo from a CAddress and source.
 */
export function newAddrInfo(addr: CAddress, source: CNetAddr): AddrInfo {
    return {
        addr,
        source,
        nLastSuccess: 0,
        nLastTry: 0,
        nAttempts: 0,
        nRefCount: 0,
        nNetwork: 0,
        fInTried: false,
        fInCollision: false,
    };
}

/**
 * Whether an address is considered "terrible" (should be evicted).
 * An address becomes terrible if:
 * - It's been failing too many times, OR
 * - It's been on our "new" list too long without being tried, OR
 * - It's been too long since last successful connection
 */
export function AddrInfo_IsTerrible(info: AddrInfo, nowSeconds: number): boolean {
    // Too many failures
    if (info.nAttempts >= ADDRMAN_MAX_FAILURES) {
        // But only if failures are recent enough
        if (info.nLastTry > 0 && nowSeconds - info.nLastTry < ADDRMAN_MIN_FAIL) {
            return false;
        }
        return true;
    }

    // Too old without being tried
    if (info.nRefCount === 0 && info.nLastSuccess === 0 && info.nAttempts === 0) {
        // New entry that's never been tried
        if (nowSeconds - info.nLastTry > ADDRMAN_HORIZON) {
            return true;
        }
    }

    // Too old since last success
    if (info.nLastSuccess > 0 && nowSeconds - info.nLastSuccess > ADDRMAN_HORIZON) {
        return true;
    }

    return false;
}

/**
 * Calculate the score (priority) for selecting this address.
 * Higher score = more desirable.
 */
export function AddrInfo_GetScore(info: AddrInfo, nowSeconds: number): number {
    let score = 0;

    if (info.fInTried) {
        score += 1000;
    }

    if (info.nRefCount > 0) {
        score += 200;
    }

    // Recent success increases score
    if (info.nLastSuccess > 0) {
        const age = nowSeconds - info.nLastSuccess;
        score += Math.max(0, 300 - Math.floor(age / 3600));
    }

    // Fewer attempts = higher score
    score += Math.max(0, 100 - info.nAttempts * 2);

    return score;
}

/**
 * AddrMan — Stochastic address manager interface.
 * 
 * Port interface for managing peer address knowledge:
 * - Add(): Add addresses to the "new" table
 * - Good(): Mark address as successfully connected (move to "tried")
 * - Attempt(): Record connection attempt
 * - Select(): Choose address to connect to
 * - GetAddr(): Get random addresses to advertise to peers
 * 
 * The actual implementation uses complex probabilistic data structures
 * that don't translate cleanly to TypeScript. This interface documents
 * the API and behavior contracts.
 */
export interface AddrMan {
    /**
     * Add addresses to addrman's new table.
     * @param vAddr Addresses to add.
     * @param source The peer that told us about these addresses.
     * @param timePenalty Seconds to subtract from address timestamps (rewards recent info).
     * @returns true if at least one address was successfully added.
     */
    Add(vAddr: CAddress[], source: CNetAddr, timePenalty?: number): boolean;

    /**
     * Mark an address as successfully connected and move it to the tried table.
     * @param addr Address to mark as good.
     * @param time Time of successful connection.
     * @returns true if the address was moved to tried.
     */
    Good(addr: CService, time?: number): boolean;

    /**
     * Record a connection attempt to an address.
     * @param addr Address that was attempted.
     * @param fCountFailure Whether to count this as a failure.
     * @param time Time of attempt.
     */
    Attempt(addr: CService, fCountFailure: boolean, time?: number): void;

    /**
     * Choose an address to connect to.
     * @param newOnly If true, only return addresses from the new table.
     * @param networks Filter to specific networks.
     * @returns [address, last attempt time] or [null, 0] if none available.
     */
    Select(newOnly?: boolean, networks?: Network[]): [CAddress | null, number];

    /**
     * Get random addresses to gossip to peers.
     * @param maxAddresses Maximum number to return (0 = all).
     * @param maxPct Maximum percentage of total addresses (0 = all).
     * @param network Filter to specific network.
     * @param filtered Only return "good" quality addresses.
     * @returns Vector of random addresses.
     */
    GetAddr(
        maxAddresses: number,
        maxPct: number,
        network?: Network,
        filtered?: boolean,
    ): CAddress[];

    /**
     * Get size information.
     * @param net Filter to specific network.
     * @param inNew Filter to new (true) or tried (false) table.
     * @returns Number of unique addresses matching criteria.
     */
    Size(net?: Network, inNew?: boolean): number;

    /**
     * Called when we successfully connect to a peer.
     * Updates the address timestamp (used for gossiping).
     * @param addr Address of peer we connected to.
     * @param time Connection time.
     */
    Connected(addr: CService, time?: number): void;

    /**
     * Update service bits for an address.
     * @param addr Address to update.
     * @param nServices New service flags.
     */
    SetServices(addr: CService, nServices: ServiceFlags): void;

    /**
     * Resolve any collisions in the tried table.
     * Called after connection attempts.
     */
    ResolveCollisions(): void;

    /**
     * Get an address being evicted from the tried table due to collision.
     * @returns [address, last attempt time] or [null, 0] if none.
     */
    SelectTriedCollision(): [CAddress | null, number];

    /**
     * Get all entries in addrman's tables.
     * @param fromTried If true, return tried table entries. If false, new table.
     * @returns Vector of [AddrInfo, AddressPosition] pairs.
     */
    GetEntries(fromTried: boolean): [AddrInfo, AddressPosition][];

    /**
     * Find an address in addrman.
     * @param addr Address to find.
     * @returns Position or null if not found.
     */
    FindAddressEntry(addr: CAddress): AddressPosition | null;
}

/**
 * Serialization format version for AddrMan on-disk storage.
 */
export const ADDR_MAN_VERSION = 1;

/**
 * Minimum number of seconds to wait before evicting a tried table entry
 * due to a new entry's collision.
 */
export const ADDRMAN_COLLISION_EVICTION_THRESHOLD_SECS = 60 * 60; // 1 hour

/**
 * Create a stub AddrMan implementation for use in TypeScript environments.
 * 
 * Note: The real AddrMan uses complex C++ data structures (prevector, unordered_map,
 * bucket hashing with SipHash) that would require native-level implementations.
 * This stub provides the interface contract and basic behavior.
 */
export class AddrManStub implements AddrMan {
    private newAddresses: Map<string, AddrInfo> = new Map();
    private triedAddresses: Map<string, AddrInfo> = new Map();
    private lookupKey: Map<string, string> = new Map(); // addr key -> id

    private addressKey(addr: CService): string {
        const key = CService_GetKey(addr);
        return Array.from(key).map((b) => b.toString(16).padStart(2, "0")).join("");
    }

    Add(vAddr: CAddress[], source: CNetAddr, timePenalty = 0): boolean {
        let added = false;
        for (const addr of vAddr) {
            const key = this.addressKey(addr.addr);
            if (this.lookupKey.has(key)) continue;

            const info = newAddrInfo(addr, source);
            info.nRefCount = 1;
            this.newAddresses.set(key, info);
            this.lookupKey.set(key, key);
            added = true;
        }
        return added;
    }

    Good(addr: CService, time?: number): boolean {
        const key = this.addressKey(addr);
        const info = this.newAddresses.get(key);
        if (!info) return false;

        info.fInTried = true;
        info.nLastSuccess = time ?? Math.floor(Date.now() / 1000);
        this.newAddresses.delete(key);
        this.triedAddresses.set(key, info);
        return true;
    }

    Attempt(addr: CService, fCountFailure: boolean, time?: number): void {
        const key = this.addressKey(addr);
        const now = time ?? Math.floor(Date.now() / 1000);

        const info = this.newAddresses.get(key) || this.triedAddresses.get(key);
        if (!info) return;

        info.nLastTry = now;
        info.nAttempts++;

        if (fCountFailure && info.nAttempts >= ADDRMAN_MAX_FAILURES) {
            // Don't evict yet — AddrMan uses probabilistic logic here
        }
    }

    Select(newOnly = false, networks: Network[] = []): [CAddress | null, number] {
        const candidates = newOnly
            ? Array.from(this.newAddresses.values())
            : [...Array.from(this.newAddresses.values()), ...Array.from(this.triedAddresses.values())];

        if (networks.length > 0) {
            const filtered = candidates.filter(
                (c) => networks.includes(c.addr.addr.m_net),
            );
            if (filtered.length === 0) return [null, 0];
            const chosen = filtered[Math.floor(Math.random() * filtered.length)];
            return [chosen.addr, chosen.nLastTry];
        }

        if (candidates.length === 0) return [null, 0];
        const chosen = candidates[Math.floor(Math.random() * candidates.length)];
        return [chosen.addr, chosen.nLastTry];
    }

    GetAddr(
        maxAddresses = 1,
        maxPct = 10,
        network?: Network,
        filtered = true,
    ): CAddress[] {
        const now = Math.floor(Date.now() / 1000);
        const all = [
            ...Array.from(this.newAddresses.values()),
            ...Array.from(this.triedAddresses.values()),
        ].filter((a) => !AddrInfo_IsTerrible(a, now));

        let result = all;
        if (network !== undefined) {
            result = result.filter((a) => a.addr.addr.m_net === network);
        }
        if (filtered) {
            result = result.filter((a) => a.nAttempts < ADDRMAN_MAX_FAILURES);
        }

        // Shuffle
        for (let i = result.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [result[i], result[j]] = [result[j], result[i]];
        }

        const limit = Math.min(
            maxAddresses || result.length,
            Math.floor((result.length * maxPct) / 100) || result.length,
        );
        return result.slice(0, limit).map((a) => a.addr);
    }

    Size(net?: Network, inNew?: boolean): number {
        const addrs =
            inNew === true
                ? Array.from(this.newAddresses.values())
                : inNew === false
                    ? Array.from(this.triedAddresses.values())
                    : [...Array.from(this.newAddresses.values()), ...Array.from(this.triedAddresses.values())];

        if (net !== undefined) {
            return addrs.filter((a) => a.addr.addr.m_net === net).length;
        }
        return addrs.length;
    }

    Connected(addr: CService, time?: number): void {
        const key = this.addressKey(addr);
        const now = time ?? Math.floor(Date.now() / 1000);
        const info = this.newAddresses.get(key) || this.triedAddresses.get(key);
        if (info) {
            info.nLastSuccess = now;
        }
    }

    SetServices(addr: CService, nServices: ServiceFlags): void {
        const key = this.addressKey(addr);
        const info = this.newAddresses.get(key) || this.triedAddresses.get(key);
        if (info) {
            info.addr.nServices = nServices;
        }
    }

    ResolveCollisions(): void {
        // Stub: real implementation uses collision detection logic
    }

    SelectTriedCollision(): [CAddress | null, number] {
        return [null, 0];
    }

    GetEntries(fromTried: boolean): [AddrInfo, AddressPosition][] {
        const entries = fromTried
            ? Array.from(this.triedAddresses.entries())
            : Array.from(this.newAddresses.entries());

        return entries.map(([key, info], i) => {
            const pos = newAddressPosition(fromTried, 1, i % 64, i);
            return [info, pos] as [AddrInfo, AddressPosition];
        });
    }

    FindAddressEntry(addr: CAddress): AddressPosition | null {
        const key = this.addressKey(addr.addr);
        if (this.newAddresses.has(key)) {
            const idx = Array.from(this.newAddresses.keys()).indexOf(key);
            return newAddressPosition(true, 1, idx % 64, idx);
        }
        if (this.triedAddresses.has(key)) {
            const idx = Array.from(this.triedAddresses.keys()).indexOf(key);
            return newAddressPosition(true, 1, idx % 64, idx);
        }
        return null;
    }
}

function CService_GetKey(svc: CService): Uint8Array {
    const result = new Uint8Array(svc.m_addr.length + 2);
    result.set(svc.m_addr);
    const portBuf = new Uint8Array(2);
    new DataView(portBuf.buffer).setUint16(0, svc.port, false);
    result.set(portBuf, svc.m_addr.length);
    return result;
}
