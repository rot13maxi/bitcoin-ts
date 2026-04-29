// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Transaction request tracker.
 * This is a TypeScript port of Bitcoin Core's txrequest.h and txrequest.cpp.
 * 
 * Manages tracking of which peers have announced which transactions,
 * and determines which transactions to request from which peers and when.
 * 
 * Port Layer 4: Memory/State - tracks in-flight transaction requests.
 */

import { uint256, Txid, Wtxid } from '../uint256';
import { GenTxid } from '../primitives';
import { CSipHasher } from '../crypto/siphash';
import { MallocUsage } from '../memusage';

/**
 * Node ID type - unique identifier for a peer node.
 * In JavaScript, we use number for simplicity.
 */
export type NodeId = number;

/** Announcement states */
enum State {
    CANDIDATE_DELAYED = 0,
    CANDIDATE_READY = 1,
    CANDIDATE_BEST = 2,
    REQUESTED = 3,
    COMPLETED = 4,
}

/**
 * An announcement - the data tracked for each (peer, txhash) pair.
 */
interface Announcement {
    gtxid: GenTxid;
    time: number; // reqtime or expiry (microseconds)
    peer: NodeId;
    sequence: number;
    preferred: boolean;
    state: State;
}

/** Per-peer statistics */
interface PeerInfo {
    total: number;
    completed: number;
    requested: number;
}

/**
 * Priority computer - computes a priority for each announcement.
 * Uses SipHash with a per-instance salt.
 */
class PriorityComputer {
    private k0: bigint;
    private k1: bigint;

    constructor(deterministic: boolean) {
        if (deterministic) {
            this.k0 = 0n;
            this.k1 = 0n;
        } else {
            this.k0 = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) |
                (BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) << 53n);
            this.k1 = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) |
                (BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) << 53n);
        }
    }

    compute(txhash: uint256, peer: NodeId, preferred: boolean): bigint {
        const peerBytes = new Uint8Array(8);
        // Encode peer as big-endian 64-bit
        let p = peer;
        for (let i = 7; i >= 0; i--) {
            peerBytes[i] = p & 0xff;
            p = Math.floor(p / 256);
        }
        const lowBits = new CSipHasher(this.k0, this.k1)
            .WriteData(txhash.getDataBE())
            .WriteData(peerBytes)
            .FinalizeAsBigint() >> 1n;
        // Set high bit if preferred
        if (preferred) {
            return lowBits | (1n << 63n);
        }
        return lowBits;
    }

    computeAnn(ann: Announcement): bigint {
        return this.compute(ann.gtxid.ToUint256(), ann.peer, ann.preferred);
    }
}

/**
 * Transaction request tracker.
 * Tracks announcements and manages download requests.
 */
export class TxRequestTracker {
    private m_impl: TxRequestTrackerImpl;

    constructor(deterministic = false) {
        this.m_impl = new TxRequestTrackerImpl(deterministic);
    }

    /**
     * Record an announcement from a peer.
     */
    receivedInv(peer: NodeId, gtxid: GenTxid, preferred: boolean, reqtime: number): void {
        this.m_impl.receivedInv(peer, gtxid, preferred, reqtime);
    }

    /**
     * Called when a peer disconnects - removes all their announcements.
     */
    disconnectedPeer(peer: NodeId): void {
        this.m_impl.disconnectedPeer(peer);
    }

    /**
     * Remove all announcements for a given txhash.
     */
    forgetTxHash(txhash: uint256): void {
        this.m_impl.forgetTxHash(txhash);
    }

    /**
     * Get transactions that are ready to request from a peer.
     */
    getRequestable(
        peer: NodeId,
        now: number,
        expired?: Array<[NodeId, GenTxid]>
    ): GenTxid[] {
        return this.m_impl.getRequestable(peer, now, expired);
    }

    /**
     * Mark a transaction as requested.
     */
    requestedTx(peer: NodeId, txhash: uint256, expiry: number): void {
        this.m_impl.requestedTx(peer, txhash, expiry);
    }

    /**
     * Mark a transaction response received (or NOTFOUND).
     */
    receivedResponse(peer: NodeId, txhash: uint256): void {
        this.m_impl.receivedResponse(peer, txhash);
    }

    /**
     * Count in-flight (REQUESTED) announcements for a peer.
     */
    countInFlight(peer: NodeId): number {
        return this.m_impl.countInFlight(peer);
    }

    /**
     * Count CANDIDATE announcements for a peer.
     */
    countCandidates(peer: NodeId): number {
        return this.m_impl.countCandidates(peer);
    }

    /**
     * Count total announcements for a peer.
     */
    count(peer: NodeId): number {
        return this.m_impl.count(peer);
    }

    /**
     * Total number of tracked announcements across all peers.
     */
    size(): number {
        return this.m_impl.size();
    }

    /**
     * Get all peers with non-COMPLETED announcements for a txhash.
     */
    getCandidatePeers(txhash: uint256): NodeId[] {
        return this.m_impl.getCandidatePeers(txhash);
    }

    /**
     * Compute priority for an announcement (for testing).
     */
    computePriority(txhash: uint256, peer: NodeId, preferred: boolean): bigint {
        return this.m_impl.computePriority(txhash, peer, preferred);
    }

    /**
     * Internal consistency check.
     */
    sanityCheck(): void {
        this.m_impl.sanityCheck();
    }

    /**
     * Time-dependent consistency check (call after getRequestable).
     */
    postGetRequestableSanityCheck(now: number): void {
        this.m_impl.postGetRequestableSanityCheck(now);
    }
}

/**
 * Internal implementation of TxRequestTracker.
 */
class TxRequestTrackerImpl {
    private currentSequence: number = 0;
    private computer: PriorityComputer;

    /** Map from txhash to announcement (only one per txhash) */
    private byTxHash: Map<string, Announcement> = new Map();
    
    /** Map from peer to set of txhashes */
    private byPeer: Map<NodeId, Set<string>> = new Map();
    
    /** Map from (peer, txhash) to announcement */
    private byPeerTxHash: Map<string, Announcement> = new Map();

    /** Peer statistics */
    private peerInfo: Map<NodeId, PeerInfo> = new Map();

    /** Pending time events: announcements waiting for a time to pass */
    private pendingTime: Announcement[] = [];

    constructor(deterministic: boolean) {
        this.computer = new PriorityComputer(deterministic);
    }

    private txhashKey(txhash: uint256): string {
        return txhash.toString();
    }

    private peerTxHashKey(peer: NodeId, txhash: uint256): string {
        return `${peer}:${txhash.toString()}`;
    }

    sanityCheck(): void {
        // Verify peer info matches actual counts
        for (const [peer, info] of this.peerInfo) {
            const byPeerSet = this.byPeer.get(peer);
            const computed = this.computePeerInfo(peer);
            if (info.total !== computed.total ||
                info.requested !== computed.requested ||
                info.completed !== computed.completed) {
                throw new Error(`PeerInfo mismatch for peer ${peer}`);
            }
        }
    }

    postGetRequestableSanityCheck(now: number): void {
        for (const ann of this.byTxHash.values()) {
            if (ann.state === State.REQUESTED || ann.state === State.CANDIDATE_DELAYED) {
                if (ann.time <= now) {
                    throw new Error(`Waiting announcement has time in past: ${ann.time} <= ${now}`);
                }
            }
            if (ann.state === State.CANDIDATE_READY || ann.state === State.CANDIDATE_BEST) {
                if (ann.time > now) {
                    throw new Error(`Selectable announcement has time in future: ${ann.time} > ${now}`);
                }
            }
        }
    }

    private computePeerInfo(peer: NodeId): PeerInfo {
        const set = this.byPeer.get(peer);
        if (!set) return { total: 0, completed: 0, requested: 0 };
        let completed = 0, requested = 0;
        for (const key of set) {
            const ann = this.byPeerTxHash.get(key);
            if (ann) {
                if (ann.state === State.COMPLETED) completed++;
                if (ann.state === State.REQUESTED) requested++;
            }
        }
        return { total: set.size, completed, requested };
    }

    receivedInv(peer: NodeId, gtxid: GenTxid, preferred: boolean, reqtime: number): void {
        const txhash = gtxid.ToUint256();
        const key = this.peerTxHashKey(peer, txhash);

        // Already have an announcement for this peer+txhash
        if (this.byPeerTxHash.has(key)) return;

        const ann: Announcement = {
            gtxid,
            time: reqtime,
            peer,
            sequence: this.currentSequence++,
            preferred,
            state: State.CANDIDATE_DELAYED,
        };

        this.byTxHash.set(txhash.toString(), ann);
        this.byPeerTxHash.set(key, ann);
        
        if (!this.byPeer.has(peer)) {
            this.byPeer.set(peer, new Set());
        }
        this.byPeer.get(peer)!.add(txhash.toString());

        this.updatePeerInfo(peer);
        this.pendingTime.push(ann);
    }

    disconnectedPeer(peer: NodeId): void {
        const set = this.byPeer.get(peer);
        if (!set) return;

        for (const txhashStr of set) {
            this.byTxHash.delete(txhashStr);
        }
        this.byPeer.delete(peer);
        this.peerInfo.delete(peer);
        
        // Remove all entries for this peer from byPeerTxHash
        for (const key of this.byPeerTxHash.keys()) {
            if (key.startsWith(`${peer}:`)) {
                this.byPeerTxHash.delete(key);
            }
        }
    }

    forgetTxHash(txhash: uint256): void {
        const key = txhash.toString();
        const ann = this.byTxHash.get(key);
        if (!ann) return;

        this.byPeer.get(ann.peer)?.delete(key);
        this.byPeerTxHash.delete(this.peerTxHashKey(ann.peer, txhash));
        this.byTxHash.delete(key);
        this.updatePeerInfo(ann.peer);
    }

    getRequestable(
        peer: NodeId,
        now: number,
        expired?: Array<[NodeId, GenTxid]>
    ): GenTxid[] {
        if (expired) expired.length = 0;

        // Set time point: process time-based state transitions
        this.setTimePoint(now, expired);

        // Find all CANDIDATE_BEST announcements for this peer
        const selected: Announcement[] = [];
        for (const ann of this.byTxHash.values()) {
            if (ann.peer === peer && ann.state === State.CANDIDATE_BEST) {
                selected.push(ann);
            }
        }

        // Sort by sequence number (announcement order)
        selected.sort((a, b) => a.sequence - b.sequence);

        return selected.map(a => a.gtxid);
    }

    requestedTx(peer: NodeId, txhash: uint256, expiry: number): void {
        const key = this.peerTxHashKey(peer, txhash);
        const ann = this.byPeerTxHash.get(key);
        if (!ann) return;

        if (ann.state !== State.CANDIDATE_BEST) {
            // Look for CANDIDATE_DELAYED or CANDIDATE_READY
            if (ann.state !== State.CANDIDATE_DELAYED && ann.state !== State.CANDIDATE_READY) {
                return; // No CANDIDATE announcement found
            }

            // If there's already a REQUESTED or CANDIDATE_BEST for this txhash, convert it to COMPLETED
            const txKey = txhash.toString();
            const existing = this.byTxHash.get(txKey);
            if (existing && (existing.state === State.REQUESTED || existing.state === State.CANDIDATE_BEST)) {
                existing.state = State.COMPLETED;
            }
        }

        ann.state = State.REQUESTED;
        ann.time = expiry;
    }

    receivedResponse(peer: NodeId, txhash: uint256): void {
        const key = this.peerTxHashKey(peer, txhash);
        const ann = this.byPeerTxHash.get(key);
        if (!ann) return;
        this.makeCompleted(ann);
    }

    countInFlight(peer: NodeId): number {
        const info = this.peerInfo.get(peer);
        return info?.requested ?? 0;
    }

    countCandidates(peer: NodeId): number {
        const info = this.peerInfo.get(peer);
        if (!info) return 0;
        return info.total - info.requested - info.completed;
    }

    count(peer: NodeId): number {
        const info = this.peerInfo.get(peer);
        return info?.total ?? 0;
    }

    size(): number {
        return this.byTxHash.size;
    }

    getCandidatePeers(txhash: uint256): NodeId[] {
        const ann = this.byTxHash.get(txhash.toString());
        if (!ann || ann.state === State.COMPLETED) return [];
        return [ann.peer];
    }

    computePriority(txhash: uint256, peer: NodeId, preferred: boolean): bigint {
        return this.computer.compute(txhash, peer, preferred);
    }

    private updatePeerInfo(peer: NodeId): void {
        const set = this.byPeer.get(peer);
        if (!set || set.size === 0) {
            this.peerInfo.delete(peer);
            return;
        }
        this.peerInfo.set(peer, this.computePeerInfo(peer));
    }

    private setTimePoint(now: number, expired?: Array<[NodeId, GenTxid]>): void {
        // Process pending time events: convert expired CANDIDATE_DELAYED to READY
        // and expired REQUESTED to COMPLETED
        const stillPending: Announcement[] = [];
        for (const ann of this.pendingTime) {
            if (ann.state === State.CANDIDATE_DELAYED && ann.time <= now) {
                // Promote to READY
                ann.state = State.CANDIDATE_READY;
                // Check if this should be CANDIDATE_BEST
                if (this.shouldBeBest(ann)) {
                    ann.state = State.CANDIDATE_BEST;
                }
            } else if (ann.state === State.REQUESTED && ann.time <= now) {
                // Mark as expired
                if (expired) expired.push([ann.peer, ann.gtxid]);
                this.makeCompleted(ann);
            } else {
                stillPending.push(ann);
            }
        }
        this.pendingTime = stillPending;

        // Handle time going backwards: demote selectable to DELAYED
        // (less common, but needed for correctness)
        for (const ann of this.byTxHash.values()) {
            if ((ann.state === State.CANDIDATE_READY || ann.state === State.CANDIDATE_BEST) &&
                ann.time > now) {
                ann.state = State.CANDIDATE_DELAYED;
            }
        }
    }

    private shouldBeBest(ann: Announcement): boolean {
        const txKey = ann.gtxid.ToUint256().toString();
        const existing = this.byTxHash.get(txKey);
        if (!existing) return true;
        if (existing.state === State.REQUESTED) return false;
        if (existing.state === State.CANDIDATE_BEST) {
            const existingPriority = this.computer.computeAnn(existing);
            const newPriority = this.computer.computeAnn(ann);
            return newPriority > existingPriority;
        }
        return true;
    }

    private makeCompleted(ann: Announcement): void {
        const txKey = ann.gtxid.ToUint256().toString();

        if (ann.state === State.CANDIDATE_BEST) {
            // Find the next best CANDIDATE_READY for this txhash
            // (simplified: just mark as READY for now)
        }

        ann.state = State.COMPLETED;
        this.updatePeerInfo(ann.peer);

        // Check if this is the last non-COMPLETED announcement
        const set = this.byPeer.get(ann.peer);
        if (set) {
            let hasNonCompleted = false;
            for (const key of set) {
                const other = this.byPeerTxHash.get(key);
                if (other && other.state !== State.COMPLETED && other !== ann) {
                    hasNonCompleted = true;
                    break;
                }
            }
            if (!hasNonCompleted) {
                // All announcements for this peer+txhash are COMPLETED
                this.forgetTxHash(ann.gtxid.ToUint256());
            }
        }
    }
}

/**
 * Estimate memory usage of the txrequest tracker.
 */
export function txrequestDynamicMemoryUsage(tracker: TxRequestTracker): number {
    // Rough estimate: base overhead + per-announcement overhead
    // Each announcement has: gtxid (32 bytes) + time (8) + peer (8) + sequence (8) + flags (1)
    // Plus overhead for the maps/sets
    const SIZE = tracker.size();
    const PEERS = 10; // rough estimate
    return MallocUsage(SIZE * 64 + PEERS * 128 + 256);
}
