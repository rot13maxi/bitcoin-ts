// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Consensus validation types and utilities.
 * This is a TypeScript port of Bitcoin Core's consensus/validation.h
 */

import { WITNESS_SCALE_FACTOR } from "./consensus";
import { CTransaction, isCoinBase, hasWitness, computeTotalSize } from "../primitives";

/** Minimum size of a witness commitment structure. Defined in BIP 141. **/
export const MINIMUM_WITNESS_COMMITMENT = 38;

/** Index marker for when no witness commitment is present in a coinbase transaction. */
export const NO_WITNESS_COMMITMENT = -1;

/**
 * A "reason" why a transaction was invalid, suitable for determining whether the
 * provider of the transaction should be banned/ignored/disconnected/etc.
 */
export enum TxValidationResult {
  TX_RESULT_UNSET = 0, //!< initial value. Tx has not yet been rejected
  TX_CONSENSUS, //!< invalid by consensus rules
  TX_INPUTS_NOT_STANDARD, //!< inputs (covered by txid) failed policy rules
  TX_NOT_STANDARD, //!< otherwise didn't meet our local policy rules
  TX_MISSING_INPUTS, //!< transaction was missing some of its inputs
  TX_PREMATURE_SPEND, //!< transaction spends a coinbase too early, or violates locktime/sequence locks
  TX_WITNESS_MUTATED, //!< witness may have been malleated
  TX_WITNESS_STRIPPED, //!< Transaction is missing a witness
  TX_CONFLICT, //!< Tx already in mempool or conflicts with a tx in the chain
  TX_MEMPOOL_POLICY, //!< violated mempool's fee/size/descendant/RBF/etc limits
  TX_NO_MEMPOOL, //!< this node does not have a mempool so can't validate the transaction
  TX_RECONSIDERABLE, //!< fails some policy, but might be acceptable if submitted in a different package
  TX_UNKNOWN, //!< transaction was not validated because package failed
}

/**
 * A "reason" why a block was invalid, suitable for determining whether the
 * provider of the block should be banned/ignored/disconnected/etc.
 */
export enum BlockValidationResult {
  BLOCK_RESULT_UNSET = 0, //!< initial value. Block has not yet been rejected
  BLOCK_CONSENSUS, //!< invalid by consensus rules (excluding any below reasons)
  BLOCK_CACHED_INVALID, //!< this block was cached as being invalid and we didn't store the reason why
  BLOCK_INVALID_HEADER, //!< invalid proof of work or time too old
  BLOCK_MUTATED, //!< the block's data didn't match the data committed to by the PoW
  BLOCK_MISSING_PREV, //!< We don't have the previous block the checked one is built on
  BLOCK_INVALID_PREV, //!< A block this one builds on is invalid
  BLOCK_TIME_FUTURE, //!< block timestamp was > 2 hours in the future (or our clock is bad)
  BLOCK_HEADER_LOW_WORK, //!< the block header may be on a too-little-work chain
}

/**
 * Validation state - captures the result of block/transaction validation.
 */
export enum ValidationMode {
  M_VALID, //!< everything ok
  M_INVALID, //!< network rule violation
  M_ERROR, //!< run-time error
}

export class ValidationState<
  T extends TxValidationResult | BlockValidationResult,
> {
  private mode: ValidationMode = ValidationMode.M_VALID;
  private result: T | null = null;
  private reject_reason: string = "";
  private debug_message: string = "";

  invalid(
    result: T,
    reject_reason: string = "",
    debug_message: string = "",
  ): boolean {
    this.result = result;
    this.reject_reason = reject_reason;
    this.debug_message = debug_message;
    if (this.mode !== ValidationMode.M_ERROR) {
      this.mode = ValidationMode.M_INVALID;
    }
    return false;
  }

  error(reject_reason: string): boolean {
    if (this.mode === ValidationMode.M_VALID) {
      this.reject_reason = reject_reason;
    }
    this.mode = ValidationMode.M_ERROR;
    return false;
  }

  isValid(): boolean {
    return this.mode === ValidationMode.M_VALID;
  }
  isInvalid(): boolean {
    return this.mode === ValidationMode.M_INVALID;
  }
  isError(): boolean {
    return this.mode === ValidationMode.M_ERROR;
  }
  getResult(): T | null {
    return this.result;
  }
  getRejectReason(): string {
    return this.reject_reason;
  }
  getDebugMessage(): string {
    return this.debug_message;
  }

  toString(): string {
    if (this.isValid()) {
      return "Valid";
    }
    if (this.debug_message) {
      return `${this.reject_reason}, ${this.debug_message}`;
    }
    return this.reject_reason;
  }
}

export type TxValidationState = ValidationState<TxValidationResult>;
export type BlockValidationState = ValidationState<BlockValidationResult>;

export function MakeTxValidationState(
  result: TxValidationResult,
  reject_reason: string = "",
  debug_message: string = "",
): TxValidationState {
  const state = new ValidationState<TxValidationResult>();
  state.invalid(result, reject_reason, debug_message);
  return state;
}

export function MakeBlockValidationState(
  result: BlockValidationResult,
  reject_reason: string = "",
  debug_message: string = "",
): BlockValidationState {
  const state = new ValidationState<BlockValidationResult>();
  state.invalid(result, reject_reason, debug_message);
  return state;
}

/**
 * Compute the weight of a transaction using the formula:
 * weight = (stripped_size * 4) + witness_size
 * which is equivalent to:
 * weight = (stripped_size * 3) + total_size
 */
export function GetTransactionWeight(tx: CTransaction): number {
  const stripped_size = 0; // TODO: compute from tx.ToDiskBlock()
  const total_size = computeTotalSize(tx);
  // Simple approximation: use a heuristic based on hasWitness
  const stripped = hasWitness(tx) ? total_size - 200 : total_size;
  return stripped * (WITNESS_SCALE_FACTOR - 1) + total_size;
}

/**
 * Minimal block header interface for GetWitnessCommitmentIndex.
 */
export interface MinimalCBlock {
  vtx: CTransaction[];
}

/**
 * Compute the weight of a block's coinbase transaction witness commitment.
 * Returns the vout index if found, or NO_WITNESS_COMMITMENT (-1) if not.
 */
export function GetWitnessCommitmentIndex(block: MinimalCBlock): number {
  let commitpos = NO_WITNESS_COMMITMENT;
  if (block.vtx.length === 0) return commitpos;

  const coinbase = block.vtx[0];
  if (isCoinBase(coinbase)) {
    for (let o = 0; o < coinbase.vout.length; o++) {
      const vout = coinbase.vout[o];
      const scriptPubKey = vout.scriptPubKey;
      if (
        scriptPubKey.length >= MINIMUM_WITNESS_COMMITMENT &&
        scriptPubKey[0] === 0x6a
      ) {
        // OP_RETURN
        // Check for the standard witness commitment prefix
        // BIP 141: 0x6a 0x24 0xaa21a9ed
        if (
          scriptPubKey.length >= 38 &&
          scriptPubKey[1] === 0x24 &&
          scriptPubKey[2] === 0xaa &&
          scriptPubKey[3] === 0x21 &&
          scriptPubKey[4] === 0xa9 &&
          scriptPubKey[5] === 0xed
        ) {
          commitpos = o;
        }
      }
    }
  }
  return commitpos;
}
