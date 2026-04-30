// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Bitcoin P2P Networking Types
 * TypeScript port of Bitcoin Core's src/net.h
 * 
 * Key network constants and node types for the P2P protocol layer.
 * Note: Full socket/thread implementation is platform-specific and not ported.
 */

// Network configuration constants
export const TIMEOUT_INTERVAL = 20; // minutes; disconnect after ping timeout
export const FEELER_INTERVAL = 2; // minutes; feeler connection interval
export const EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL = 5; // minutes
export const MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1000 * 1000; // 4 MB max message
export const MAX_SUBVERSION_LENGTH = 256; // max user agent length
export const MAX_OUTBOUND_FULL_RELAY_CONNECTIONS = 8;
export const MAX_ADDNODE_CONNECTIONS = 8;
export const MAX_BLOCK_RELAY_ONLY_CONNECTIONS = 2;
export const MAX_FEELER_CONNECTIONS = 1;
export const MAX_PRIVATE_BROADCAST_CONNECTIONS = 64;
export const DEFAULT_LISTEN = true;
export const DEFAULT_MAX_PEER_CONNECTIONS = 125;
export const DEFAULT_MAX_UPLOAD_TARGET = "0M"; // 0 = unlimited
export const DEFAULT_BLOCKSONLY = false;
export const DEFAULT_PEER_CONNECT_TIMEOUT = 60; // seconds
export const DEFAULT_PRIVATE_BROADCAST = false;
export const DEFAULT_FORCEDNSSEED = false;
export const DEFAULT_DNSSEED = true;
export const DEFAULT_FIXEDSEEDS = true;
export const DEFAULT_MAXRECEIVEBUFFER = 5 * 1000;
export const DEFAULT_MAXSENDBUFFER = 1 * 1000;
export const ASMAP_HEALTH_CHECK_INTERVAL_HOURS = 24;

/** Whether transaction reconciliation protocol is enabled by default. */
export const DEFAULT_TXRECONCILIATION_ENABLE = false;

/** Default number of non-mempool transactions to keep for block reconstruction. */
export const DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN = 100;

/** Default for -peerbloomfilters. */
export const DEFAULT_PEERBLOOMFILTERS = false;

/** Default for -peerblockfilters. */
export const DEFAULT_PEERBLOCKFILTERS = false;

/** Maximum outstanding CMPCTBLOCK requests for the same block. */
export const MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3;

/** Maximum headers returned in one getheaders response. */
export const MAX_HEADERS_RESULTS = 2000;

/**
 * Connection type enum — categorizes node connections by purpose.
 * Used in connection managers and connection-limiting logic.
 */
export enum ConnectionType {
    /** Full-relay outbound connection for transaction and block relay. */
    OUTBOUND_FULL_RELAY = 0,
    /** Block-relay only connection (no transaction relay). */
    BLOCK_RELAY,
    /** Addnode (manually added) connection. */
    ADDNODE,
    /** Inbound connection. */
    INBOUND,
    /** Feeler connection (short-lived, for address discovery). */
    FEELER,
    /** Private broadcast connection. */
    PRIVATE,
    /** Short-lived block-relay connection. */
    BLOCK_RELAY_ONLY,
}

/**
 * Node state statistics for a connected peer.
 */
export interface CNodeStateStats {
    nSyncHeight: number;
    nCommonHeight: number;
    mPingWait: number; // milliseconds
    vHeightInFlight: number[];
    mRelayTxs: boolean;
    mInvToSend: number;
    mLastInvSeq: bigint;
    mFeeFilterReceived: bigint; // satoshis per kvB
}

/**
 * Network peer statistics — information about a connected node.
 * This is the interface for P2P networking layer metadata.
 */
export interface Peer {
    /** Unique peer identifier. */
    id: number;
    /** Connected socket address. */
    addr: string;
    /** Whether this is an inbound connection. */
    inbound: boolean;
    /** Connection type. */
    connType: ConnectionType;
    /** Peer starting height (best block known). */
    startingHeight: number;
    /** Last block we sent to this peer. */
    lastBlockInv: number;
    /** Last getheaders request we received. */
    lastGetHeaders诉求: number;
    /** Ping latency in milliseconds. */
    pingTime: number;
    /** Address of this peer as seen by us. */
    addrLocal: string;
    /** Services advertised by this peer. */
    nServices: ServiceFlags;
    /** Relay transactions to this peer. */
    mRelaysTxs: boolean;
    /** Supports BIP152 compact blocks. */
    supportsCompactBlocks: boolean;
    /** Supports BIP157/BIP158 compact filters. */
    supportsCompactFilters: boolean;
    /** Supports BIP324 P2P v2 encryption. */
    supportsP2Pv2: boolean;
}

import { ServiceFlags } from "../protocol";
import { CAddress } from "../protocol";

export type { ServiceFlags, CAddress };
