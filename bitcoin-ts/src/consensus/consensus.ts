// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Basic consensus constants.
 * This is a TypeScript port of Bitcoin Core's consensus/consensus.h
 */

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
export const MAX_BLOCK_SERIALIZED_SIZE = 4_000_000;

/** The maximum allowed weight for a block, see BIP 141 (network rule) */
export const MAX_BLOCK_WEIGHT = 4_000_000;

/** The maximum allowed number of signature check operations in a block (network rule) */
export const MAX_BLOCK_SIGOPS_COST = 80_000;

/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
export const COINBASE_MATURITY = 100;

export const WITNESS_SCALE_FACTOR = 4;

/** Minimum transaction weight for a transaction with all inputs present */
export const MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60;

/** Minimum transaction weight for a serializable transaction */
export const MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10;

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
export const LOCKTIME_VERIFY_SEQUENCE = 1 << 0;

/**
 * Maximum number of seconds that the timestamp of the first
 * block of a difficulty adjustment period is allowed to
 * be earlier than the last block of the previous period (BIP94).
 */
export const MAX_TIMEWARP = 600;
