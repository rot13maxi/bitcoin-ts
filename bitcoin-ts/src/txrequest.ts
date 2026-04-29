// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Bitcoin Core Transaction Request Tracker - TypeScript port of Bitcoin Core txrequest.h
 * 
 * Data structure to keep track of, and schedule, transaction downloads from peers.
 * 
 * Key concepts:
 * - CANDIDATE: Transactions announced by a peer, available for download after reqtime
 * - REQUESTED: Transactions we've requested and are awaiting a response
 * - COMPLETED: Transactions we've received or that timed out
 */



/** Node ID type */
export type NodeId = number;

/** Request state for a peer/txhash combination */
export enum TxRequestState {
    /** Transaction announced, waiting for reqtime */
    CANDIDATE = 0,
    /** Transaction requested, awaiting response */
    REQUESTED = 1,
    /** Transaction received or request failed */
    COMPLETED = 2,
}

/** A tracked transaction request */
interface TxRequestEntry {
    peer: NodeId;
    txhash: Uint8Array;
    isWtxid: boolean;
    state: TxRequestState;
    reqtime: number;  // microseconds
    expiry: number;   // microseconds (for REQUESTED state)
    preferred: boolean;
}

/** Transaction request tracker */
export class TxRequestTracker {
    private entries: Map<string, TxRequestEntry>;
    private peers: Map<NodeId, Set<string>>;
    private txhashes: Map<string, Set<string>>;
    private salt: Uint8Array;
    private deterministic: boolean;

    constructor(deterministic: boolean = false) {
        this.entries = new Map();
        this.peers = new Map();
        this.txhashes = new Map();
        this.deterministic = deterministic;
        if (!deterministic) {
            this.salt = new Uint8Array(16);
            crypto.getRandomValues(this.salt);
        } else {
            this.salt = new Uint8Array(16);
        }
    }

    /**
     * Generate a unique key for an entry
     */
    private key(peer: NodeId, txhash: Uint8Array): string {
        const hashStr = Array.from(txhash).map(b => b.toString(16).padStart(2, '0')).join('');
        return `${peer}-${hashStr}`;
    }

    /**
     * Get the txhash key (ignoring txid vs wtxid)
     */
    private txhashKey(txhash: Uint8Array): string {
        return Array.from(txhash).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Add a new CANDIDATE announcement
     */
    ReceivedInv(
        peer: NodeId,
        txhash: Uint8Array,
        isWtxid: boolean,
        preferred: boolean,
        reqtime: number  // microseconds
    ): void {
        const k = this.key(peer, txhash);
        
        // Don't add if one already exists
        if (this.entries.has(k)) {
            return;
        }
        
        const entry: TxRequestEntry = {
            peer,
            txhash: txhash.slice(),
            isWtxid,
            state: TxRequestState.CANDIDATE,
            reqtime,
            expiry: 0,
            preferred,
        };
        
        this.entries.set(k, entry);
        
        // Update peer index
        if (!this.peers.has(peer)) {
            this.peers.set(peer, new Set());
        }
        this.peers.get(peer)!.add(k);
        
        // Update txhash index
        const thk = this.txhashKey(txhash);
        if (!this.txhashes.has(thk)) {
            this.txhashes.set(thk, new Set());
        }
        this.txhashes.get(thk)!.add(k);
    }

    /**
     * Delete all announcements for a peer
     */
    DisconnectedPeer(peer: NodeId): void {
        const keys = this.peers.get(peer);
        if (!keys) return;
        
        for (const k of keys) {
            const entry = this.entries.get(k);
            if (entry) {
                // Remove from txhashes index
                const thk = this.txhashKey(entry.txhash);
                const thSet = this.txhashes.get(thk);
                if (thSet) {
                    thSet.delete(k);
                    if (thSet.size === 0) {
                        this.txhashes.delete(thk);
                    }
                }
            }
            this.entries.delete(k);
        }
        
        this.peers.delete(peer);
    }

    /**
     * Delete all announcements for a txhash
     */
    ForgetTxHash(txhash: Uint8Array): void {
        const thk = this.txhashKey(txhash);
        const keys = this.txhashes.get(thk);
        if (!keys) return;
        
        for (const k of keys) {
            const entry = this.entries.get(k);
            if (entry) {
                // Remove from peers index
                const peerSet = this.peers.get(entry.peer);
                if (peerSet) {
                    peerSet.delete(k);
                    if (peerSet.size === 0) {
                        this.peers.delete(entry.peer);
                    }
                }
            }
            this.entries.delete(k);
        }
        
        this.txhashes.delete(thk);
    }

    /**
     * Get the peer to request from for a given txhash
     */
    private selectPeer(txhash: Uint8Array, candidates: TxRequestEntry[]): TxRequestEntry | null {
        if (candidates.length === 0) return null;
        
        // Filter to preferred if any exist
        const preferred = candidates.filter(e => e.preferred);
        const pool = preferred.length > 0 ? preferred : candidates;
        
        // Sort by deterministic hash for consistent selection
        pool.sort((a, b) => {
            const hashA = this.deterministicHash(a.peer, txhash);
            const hashB = this.deterministicHash(b.peer, txhash);
            return hashA - hashB;
        });
        
        return pool[0];
    }

    /**
     * Calculate deterministic hash for peer/txhash combination
     */
    private deterministicHash(peer: NodeId, txhash: Uint8Array): number {
        let hash = 0;
        // Combine salt
        for (let i = 0; i < this.salt.length; i++) {
            hash ^= this.salt[i];
            hash = (hash * 31 + this.salt[i]) >>> 0;
        }
        // Combine peer id
        hash = (hash * 31 + (peer & 0xff)) >>> 0;
        hash = (hash * 31 + ((peer >> 8) & 0xff)) >>> 0;
        hash = (hash * 31 + ((peer >> 16) & 0xff)) >>> 0;
        hash = (hash * 31 + ((peer >> 24) & 0xff)) >>> 0;
        // Combine txhash
        for (let i = 0; i < Math.min(txhash.length, 8); i++) {
            hash = (hash * 31 + txhash[i]) >>> 0;
        }
        return hash;
    }

    /**
     * Check if a txhash has an active REQUESTED announcement from any peer
     */
    private hasRequested(txhash: Uint8Array, excludePeer?: NodeId): boolean {
        const thk = this.txhashKey(txhash);
        const keys = this.txhashes.get(thk);
        if (!keys) return false;
        
        for (const k of keys) {
            const entry = this.entries.get(k);
            if (entry && entry.state === TxRequestState.REQUESTED) {
                if (excludePeer === undefined || entry.peer !== excludePeer) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Get transactions that can be requested from a peer
     */
    GetRequestable(
        peer: NodeId,
        now: number,  // microseconds
        expired?: Array<[NodeId, Uint8Array]>
    ): Array<{ txhash: Uint8Array; isWtxid: boolean }> {
        const result: Array<{ txhash: Uint8Array; isWtxid: boolean }> = [];
        
        // First, expire all REQUESTED entries past their expiry
        for (const [k, entry] of this.entries) {
            if (entry.state === TxRequestState.REQUESTED && entry.expiry <= now) {
                entry.state = TxRequestState.COMPLETED;
                if (expired) {
                    expired.push([entry.peer, entry.txhash]);
                }
            }
        }
        
        // Clean up txhashes with only COMPLETED entries
        this.gcCompletedEntries();
        
        // Find CANDIDATE entries for this peer that are ready
        const peerKeys = this.peers.get(peer);
        if (!peerKeys) return result;
        
        // Group by txhash for selection
        const byTxhash = new Map<string, TxRequestEntry[]>();
        
        for (const k of peerKeys) {
            const entry = this.entries.get(k);
            if (!entry) continue;
            
            if (entry.state !== TxRequestState.CANDIDATE) continue;
            if (entry.reqtime > now) continue;
            if (this.hasRequested(entry.txhash)) continue;
            
            const thk = this.txhashKey(entry.txhash);
            if (!byTxhash.has(thk)) {
                byTxhash.set(thk, []);
            }
            byTxhash.get(thk)!.push(entry);
        }
        
        // Select one peer per txhash
        for (const [thk, candidates] of byTxhash) {
            const selected = this.selectPeer(candidates[0].txhash, candidates);
            if (selected && selected.peer === peer) {
                const entry = selected;
                entry.state = TxRequestState.REQUESTED;
                result.push({ txhash: entry.txhash, isWtxid: entry.isWtxid });
            }
        }
        
        return result;
    }

    /**
     * Mark a transaction as requested
     */
    RequestedTx(peer: NodeId, txhash: Uint8Array, expiry: number): void {
        const k = this.key(peer, txhash);
        const entry = this.entries.get(k);
        
        if (!entry || entry.state !== TxRequestState.CANDIDATE) {
            return;
        }
        
        // Convert to REQUESTED
        entry.state = TxRequestState.REQUESTED;
        entry.expiry = expiry;
        
        // If another REQUESTED exists for same txhash, mark it as COMPLETED
        const thk = this.txhashKey(txhash);
        const keys = this.txhashes.get(thk);
        if (keys) {
            for (const otherK of keys) {
                if (otherK === k) continue;
                const other = this.entries.get(otherK);
                if (other && other.state === TxRequestState.REQUESTED) {
                    other.state = TxRequestState.COMPLETED;
                }
            }
        }
    }

    /**
     * Mark response received (transaction or NOTFOUND)
     */
    ReceivedResponse(peer: NodeId, txhash: Uint8Array): void {
        const k = this.key(peer, txhash);
        const entry = this.entries.get(k);
        
        if (!entry) return;
        
        if (entry.state === TxRequestState.CANDIDATE || entry.state === TxRequestState.REQUESTED) {
            entry.state = TxRequestState.COMPLETED;
        }
        
        // Clean up if only COMPLETED entries remain
        this.gcCompletedEntries();
    }

    /**
     * Garbage collect txhashes that only have COMPLETED entries
     */
    private gcCompletedEntries(): void {
        for (const [thk, keys] of this.txhashes) {
            const hasActive = Array.from(keys).some(k => {
                const entry = this.entries.get(k);
                return entry && entry.state !== TxRequestState.COMPLETED;
            });
            
            if (!hasActive) {
                // Delete all COMPLETED entries for this txhash
                for (const k of keys) {
                    const entry = this.entries.get(k);
                    if (entry) {
                        const peerSet = this.peers.get(entry.peer);
                        if (peerSet) {
                            peerSet.delete(k);
                            if (peerSet.size === 0) {
                                this.peers.delete(entry.peer);
                            }
                        }
                    }
                    this.entries.delete(k);
                }
                this.txhashes.delete(thk);
            }
        }
    }

    /**
     * Count in-flight (REQUESTED) entries for a peer
     */
    CountInFlight(peer: NodeId): number {
        const keys = this.peers.get(peer);
        if (!keys) return 0;
        
        let count = 0;
        for (const k of keys) {
            const entry = this.entries.get(k);
            if (entry && entry.state === TxRequestState.REQUESTED) {
                count++;
            }
        }
        return count;
    }

    /**
     * Count CANDIDATE entries for a peer
     */
    CountCandidates(peer: NodeId): number {
        const keys = this.peers.get(peer);
        if (!keys) return 0;
        
        let count = 0;
        for (const k of keys) {
            const entry = this.entries.get(k);
            if (entry && entry.state === TxRequestState.CANDIDATE) {
                count++;
            }
        }
        return count;
    }

    /**
     * Count all entries for a peer
     */
    Count(peer: NodeId): number {
        const keys = this.peers.get(peer);
        return keys ? keys.size : 0;
    }

    /**
     * Total number of tracked entries
     */
    Size(): number {
        return this.entries.size;
    }
}

/**
 * Create a GenTxid (generalized txid - either txid or wtxid)
 */
export interface GenTxid {
    isWtxid: boolean;
    hash: Uint8Array;
}

/**
 * Create a GenTxid from txid
 */
export function genTxid(hash: Uint8Array): GenTxid {
    return { isWtxid: false, hash: hash.slice() };
}

/**
 * Create a GenTxid from wtxid
 */
export function genWtxid(hash: Uint8Array): GenTxid {
    return { isWtxid: true, hash: hash.slice() };
}
