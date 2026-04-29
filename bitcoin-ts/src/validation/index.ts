// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Block and Transaction Validation
 * TypeScript port of Bitcoin Core's src/validation.h
 * 
 * Port of the core validation types: block indexing, mempool acceptance,
 * chainstate management, and block connection/disconnection.
 * 
 * Re-exports from consensus/validation.ts:
 *   TxValidationResult, BlockValidationResult, ValidationState,
 *   TxValidationState, BlockValidationState
 */

// Re-export consensus validation types (already ported)
export {
    MINIMUM_WITNESS_COMMITMENT,
    NO_WITNESS_COMMITMENT,
    TxValidationResult,
    BlockValidationResult,
    ValidationMode,
    ValidationState,
    TxValidationState,
    BlockValidationState,
    MakeTxValidationState,
    MakeBlockValidationState,
    GetWitnessCommitmentIndex,
    MinimalCBlock,
} from "../consensus/validation";

import {
    TxValidationResult,
    BlockValidationResult,
    ValidationState,
    TxValidationState,
    BlockValidationState,
} from "../consensus/validation";

// Block validation constants

/** Minimum blocks to retain (for pruning). */
export const MIN_BLOCKS_TO_KEEP = 288;

/** Default number of blocks to check (with full validation). */
export const DEFAULT_CHECKBLOCKS = 6;

/** Default checklevel (0-4, 3 = default, 4 = exhaustive). */
export const DEFAULT_CHECKLEVEL = 3;

/** Minimum disk space for block files (550 MiB). */
export const MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 * 1024 * 1024;

/** Maximum script check threads. */
export const MAX_SCRIPTCHECK_THREADS = 15;

/**
 * Current sync state passed to tip-change callbacks.
 */
export enum SynchronizationState {
    /** Currently doing initial block chain replay. */
    INIT_REINDEX = 0,
    /** Downloading headers and blocks from peers. */
    INIT_DOWNLOAD,
    /** Initial sync complete; regular operation. */
    POST_INIT,
}

/**
 * VerifyDB result codes.
 */
export enum VerifyDBResult {
    SUCCESS = 0,
    CORRUPTED_BLOCK_DB = 1,
    INTERRUPTED = 2,
    SKIPPED_L3_CHECKS = 3,
    SKIPPED_MISSING_BLOCKS = 4,
}

/**
 * Result of disconnecting a block.
 */
export enum DisconnectResult {
    /** All good. */
    DISCONNECT_OK = 0,
    /** Rolled back but UTXO set was inconsistent. */
    DISCONNECT_UNCLEAN = 1,
    /** Something went wrong. */
    DISCONNECT_FAILED = 2,
}

/**
 * Block index entry — represents a block in the block tree.
 * This is the core data structure for chain navigation.
 */
export interface CBlockIndex {
    /** Pointer to the parent block (null for genesis). */
    pprev: CBlockIndex | null;
    /** Pointer to the prev block's predecessor (merges chain of equal work). */
    pskip: CBlockIndex | null;
    /** Block hash (256-bit, as Uint8Array). */
    GetHash(): Uint8Array;
    hash: Uint8Array;
    /** Height of this block in the chain (0 = genesis). */
    nHeight: number;
    /** Chainwork (total accumulated proof of work). */
    nChainWork: Uint8Array;
    /** Timestamp of this block. */
    nTime: number;
    /** Block version. */
    nVersion: number;
    /** Merkle root of this block's transactions. */
    hashMerkleRoot: Uint8Array;
    /** Witness commitment root (BIP141). */
    hashWitnessMerkleRoot: Uint8Array;
    /** Block bits (target threshold). */
    nBits: number;
    /** Nonce (extra randomness for PoW). */
    nNonce: number;
    /** Whether this block's data is stored on disk. */
    nStatus: BlockStatus;
    /** Number of transactions in this block. */
    nTx: number;
    /** Disk size in bytes (if available). */
    nDiskSize: number;
    /** Sequence number for ordering in leveldb. */
    nSequenceId: number;
    /** Cached values. */
    nTimeMax: number;
    /** Median time of the last 11 blocks (for locktime). */
    GetMedianTimePast(): number;
    /** Next block in the chain with most work. */
    GetNextBlock(): CBlockIndex | null;
    /** Check if this block is an ancestor of another. */
    IsAncestorOf(other: CBlockIndex): boolean;
    /** Get ancestor at a given height. */
    GetAncestor(height: number): CBlockIndex;
    /** Calculate work in this chain up to this block. */
    sumForChainWork(): Uint8Array;
    /** Check if this block is on a valid chain. */
    IsValid(): boolean;
    /** Check if this block has all required data. */
    HaveTxsDownloaded(): boolean;
    /** Get block status flags. */
    GetBlockStatus(): BlockStatus;
    /** Check if this block is the genesis. */
    IsGenesis(): boolean;
}

/** Block status flags (stored in nStatus). */
export enum BlockStatus {
    /** Unset. */
    BLOCK_UNSET = 0,
    /** Have this block data on disk (pruned). */
    BLOCK_HAVE_DATA = 1 << 0,
    /** Have undo data on disk. */
    BLOCK_HAVE_UNDO = 1 << 1,
    /** Have all block data including witnesses. */
    BLOCK_HAVE_WITNESS = 1 << 2,
    /** Have complete block data (data + undo + witness). */
    BLOCK_COMPLETE = BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO | BLOCK_HAVE_WITNESS,
    /** Stored in the block index database. */
    BLOCK_VALID_MASK = 0x07,
    /** Passed CheckBlock(). */
    BLOCK_VALID_HEADER = 1 << 3,
    /** Passed CheckBlock() and context checks. */
    BLOCK_VALID_TREE = 1 << 4,
    /** Passed all context validation rules. */
    BLOCK_VALID_CHAIN = 1 << 5,
    /** Passed ConnectBlock() / header connect. */
    BLOCK_VALID_SCRIPTS = 1 << 6,
    /** Set when the block is invalid. */
    BLOCK_FAILED_MASK = 0x07 << 8,
    /** Invalid block (do not connect). */
    BLOCK_FAILED_VALID = 1 << 9,
    /** Invalid block due to failed parent. */
    BLOCK_FAILED_CHILD = 1 << 10,
    /** Block is on a conflicting/parallel chain. */
    BLOCK_FAILED_ALL = BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,
    /** Block is in the process of being added. */
    BLOCK_OPT_WITNESS = 1 << 11,
    /** Block is part of the background chain (snapshot chainstate). */
    BLOCK_FROM_SNAPSHOT = 1 << 12,
}

/**
 * Create a default CBlockIndex.
 */
export function newCBlockIndex(): CBlockIndex {
    return {
        pprev: null,
        pskip: null,
        hash: new Uint8Array(32),
        nHeight: 0,
        nChainWork: new Uint8Array(32),
        nTime: 0,
        nVersion: 0,
        hashMerkleRoot: new Uint8Array(32),
        hashWitnessMerkleRoot: new Uint8Array(32),
        nBits: 0,
        nNonce: 0,
        nStatus: BlockStatus.BLOCK_UNSET,
        nTx: 0,
        nDiskSize: 0,
        nSequenceId: 0,
        nTimeMax: 0,
        GetHash: () => new Uint8Array(32),
        GetMedianTimePast: function(): number { return 0; },
        GetNextBlock: function(): CBlockIndex | null { return null; },
        IsAncestorOf: function(_other: CBlockIndex): boolean { return false; },
        GetAncestor: function(_height: number): CBlockIndex { return this; },
        sumForChainWork: function(): Uint8Array { return new Uint8Array(32); },
        IsValid: function(): boolean { return false; },
        HaveTxsDownloaded: function(): boolean { return false; },
        GetBlockStatus: function(): BlockStatus { return BlockStatus.BLOCK_UNSET; },
        IsGenesis: function(): boolean { return this.nHeight === 0; },
    };
}

/**
 * Check if a block index has the given status flag.
 */
export function CBlockIndex_HasFlag(index: CBlockIndex, flag: BlockStatus): boolean {
    return (index.nStatus & flag) !== 0;
}

/**
 * Check if a block index failed (is in the failed block list).
 */
export function CBlockIndex_IsInvalid(index: CBlockIndex): boolean {
    return (index.nStatus & BlockStatus.BLOCK_FAILED_MASK) !== 0;
}

/**
 * Get the chainwork of the block just before this one.
 */
export function CBlockIndex_pprevChainWork(index: CBlockIndex): Uint8Array {
    if (index.pprev) return index.pprev.nChainWork;
    // Genesis: return 0
    return new Uint8Array(32);
}

/**
 * PrecomputedTransactionData — caches data needed for script verification.
 * 
 * Computed once per transaction, then reused for all inputs.
 * This avoids repeated hashing of the transaction for each input.
 */
export interface PrecomputedTransactionData {
    /** Hash of this transaction (without witness data). */
    hash: Uint8Array;
    /** Whether this transaction has witness data. */
    hasWitness: boolean;
    /** Sigops count for this transaction (for fee estimation). */
    sigopsCount: number;
    /** Updated whenever prevout values are spent. */
    m_spent_outputs_rev: Uint8Array[];
    /** Whether the previous outputs have been updated. */
    m_spends_seen: boolean;
}

/**
 * LockPoints — sequence lock time tracking.
 * Used for BIP68 sequence lock verification.
 */
export interface LockPoints {
    /** Height of the block at which the lock can be satisfied. */
    height: number;
    /** Time at which the lock can be satisfied. */
    time: number;
    /** Block that must be in the chain for this lock to be valid. */
    minHeight: number;
    /** Connection point through which this was added. */
    fromBlock: CBlockIndex;
}

/**
 * Re-export CTxMemPoolEntryRef from txmempool.
 */
export type { CTxMemPoolEntryRef } from "../txmempool";

/**
 * MempoolAcceptResult — result of trying to add a transaction to the mempool.
 */
export interface MempoolAcceptResult {
    mResultType: MempoolAcceptResultType;
    mState: TxValidationState;
    mReplacedTransactions: Uint8Array[];
    mVsize: bigint | null;
    mBaseFees: bigint | null;
    mEffectiveFeerate: bigint | null;
    mWtxidsFeeCalculations: Uint8Array[];
    mOtherWtxid: Uint8Array | null;
}

/**
 * Result type for MempoolAcceptResult.
 */
export enum MempoolAcceptResultType {
    /** Valid, fully validated. */
    VALID = 0,
    /** Invalid (rejected). */
    INVALID = 1,
    /** Valid, transaction was already in mempool. */
    MEMPOOL_ENTRY = 2,
    /** Valid but same-txid-different-witness already in mempool. */
    DIFFERENT_WITNESS = 3,
}

/**
 * PackageMempoolAcceptResult — result of validating a package of transactions.
 */
export interface PackageMempoolAcceptResult {
    mState: TxValidationState;
    mTxResults: Map<string, MempoolAcceptResult>;
}

/**
 * Package — a collection of transactions submitted together for validation.
 */
export interface Package {
    /** Vector of transaction objects. */
    transactions: CTransaction[];
    /** Whether this is a package of transactions from a block. */
    is诗人: boolean;
}

import { CTransaction } from "../primitives";
