// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Transaction consensus verification functions.
 * This is a TypeScript port of Bitcoin Core's consensus/tx_verify.h and tx_verify.cpp
 */

import { CTransaction, COutPoint, isCoinBase, getValueOut } from "../primitives";
import {
  TxValidationState,
  TxValidationResult,
  NO_WITNESS_COMMITMENT,
} from "./validation";
import { COINBASE_MATURITY, WITNESS_SCALE_FACTOR } from "./consensus";
import {
  SEQUENCE_FINAL,
  SEQUENCE_LOCKTIME_DISABLE_FLAG,
  SEQUENCE_LOCKTIME_TYPE_FLAG,
  SEQUENCE_LOCKTIME_MASK,
  SEQUENCE_LOCKTIME_GRANULARITY,
} from "../primitives";
import { script_verify_flags } from "../script/verify_flags";

/**
 * Minimal block index interface for consensus functions.
 * Full interface requires chain state (not part of consensus layer).
 */
export interface MinimalBlockIndex {
  readonly nHeight: number;
  readonly pprev: MinimalBlockIndex | null;
  getMedianTimePast(): number;
  getAncestor(height: number): MinimalBlockIndex | null;
}

/**
 * Minimal coin interface for transaction input access.
 */
export interface MinimalCoin {
  readonly nHeight: number;
  readonly out: { readonly nValue: bigint; readonly scriptPubKey: Uint8Array };
  isSpent(): boolean;
  isCoinBase(): boolean;
}

/**
 * Minimal UTXO view interface.
 */
export interface MinimalCoinsView {
  haveCoin(outpoint: COutPoint): boolean;
  accessCoin(outpoint: COutPoint): MinimalCoin;
}

export type CAmount = bigint;

/** Default network coin value */
export const COIN = 100000000n;
export const MAX_MONEY = 21000000n * COIN;

export function MoneyRange(value: bigint): boolean {
  return value >= 0n && value <= MAX_MONEY;
}

/**
 * Count ECDSA signature operations the old-fashioned (pre-0.6) way.
 * @return number of sigops this transaction's outputs will produce when spent.
 */
export function GetLegacySigOpCount(tx: CTransaction): number {
  // Note: this requires script interpreter access which hasn't been fully ported.
  // This is a stub that returns 0 for non-coinbase transactions.
  // Full implementation requires script interpreter.
  let nSigOps = 0;
  for (const txin of tx.vin) {
    // Stub: actual implementation requires scriptSig.GetSigOpCount(false)
    // which needs the full script interpreter. For now, return 0.
    // TODO: implement when script interpreter is available
  }
  for (const txout of tx.vout) {
    // Stub: actual implementation requires scriptPubKey.GetSigOpCount(false)
  }
  return nSigOps;
}

/**
 * Count ECDSA signature operations in pay-to-script-hash inputs.
 * @param tx - Transaction
 * @param inputs - UTXO view (required for accessing prevout scripts)
 * @return maximum number of sigops required to validate this transaction's inputs
 */
export function GetP2SHSigOpCount(
  tx: CTransaction,
  inputs: MinimalCoinsView,
): number {
  if (isCoinBase(tx)) return 0;

  let nSigOps = 0;
  for (let i = 0; i < tx.vin.length; i++) {
    const coin = inputs.accessCoin(tx.vin[i].prevout);
    if (!coin.isSpent()) {
      const prevout = coin.out;
      // Check if P2SH - stub: requires IsPayToScriptHash()
      // TODO: implement when script interpreter is available
    }
  }
  return nSigOps;
}

/**
 * Compute total signature operation cost of a transaction.
 */
export function GetTransactionSigOpCost(
  tx: CTransaction,
  inputs: MinimalCoinsView,
  flags: script_verify_flags,
): number {
  let nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

  if (isCoinBase(tx)) {
    return nSigOps;
  }

  if ((BigInt(flags) & BigInt(0x00000100)) !== 0n) {
    // SCRIPT_VERIFY_P2SH
    nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
  }

  for (let i = 0; i < tx.vin.length; i++) {
    const coin = inputs.accessCoin(tx.vin[i].prevout);
    if (!coin.isSpent()) {
      // Stub: CountWitnessSigOps requires script interpreter
      // nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, tx.vin[i].scriptWitness, flags);
    }
  }
  return nSigOps;
}

/**
 * Get the transaction weight for a given input, accounting for witness data.
 * weight = stripped_size * 3 + total_size + witness
 */
export function GetTransactionInputWeight(
  txin: CTransaction["vin"][0],
): number {
  // This is a stub; full implementation requires serialization size computation
  // including scriptWitness.stack serialization.
  const stripped_size = 32 + 4; // prevout + sequence
  const witness_size = 0; // stub: would need to compute from scriptWitness.stack serialization
  return (
    stripped_size * (WITNESS_SCALE_FACTOR - 1) + stripped_size + witness_size
  );
}

/**
 * Check if transaction is final and can be included in a block with the
 * specified height and time. Consensus critical.
 */
export function IsFinalTx(
  tx: CTransaction,
  nBlockHeight: number,
  nBlockTime: number,
): boolean {
  if (tx.nLockTime === 0) {
    return true;
  }

  const lockTimeThreshold = 500000000; // LOCKTIME_THRESHOLD

  // Check if locktime is satisfied by height or time
  if (
    (tx.nLockTime as number) <
    (tx.nLockTime < lockTimeThreshold ? nBlockHeight : nBlockTime)
  ) {
    return true;
  }

  // If all inputs have SEQUENCE_FINAL, the locktime is ignored
  for (const txin of tx.vin) {
    if (txin.nSequence !== SEQUENCE_FINAL) {
      return false;
    }
  }
  return true;
}

/**
 * Calculates the block height and previous block's median time past at
 * which the transaction will be considered final in the context of BIP 68.
 * For each input that is not sequence locked, the corresponding entries in
 * prevHeights are set to 0 as they do not affect the calculation.
 */
export function CalculateSequenceLocks(
  tx: CTransaction,
  flags: number,
  prevHeights: number[],
  block: MinimalBlockIndex,
): { first: number; second: number } {
  // prevHeights should match tx.vin.length
  let nMinHeight = -1;
  let nMinTime = -1;

  const fEnforceBIP68 = tx.version >= 2 && (flags & 1) !== 0; // LOCKTIME_VERIFY_SEQUENCE

  if (!fEnforceBIP68) {
    return { first: nMinHeight, second: nMinTime };
  }

  for (let txinIndex = 0; txinIndex < tx.vin.length; txinIndex++) {
    const txin = tx.vin[txinIndex];
    const txinSequence = txin.nSequence as number;

    // Sequence numbers with the most significant bit set are not treated as relative lock-times
    if ((txinSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) !== 0) {
      prevHeights[txinIndex] = 0;
      continue;
    }

    const nCoinHeight = prevHeights[txinIndex];

    if ((txinSequence & SEQUENCE_LOCKTIME_TYPE_FLAG) !== 0) {
      // Time-based relative lock-time
      const ancestor = block.getAncestor(Math.max(nCoinHeight - 1, 0));
      const nCoinTime = ancestor?.getMedianTimePast() ?? 0;

      const sequenceValue =
        (txinSequence & SEQUENCE_LOCKTIME_MASK) <<
        SEQUENCE_LOCKTIME_GRANULARITY;
      nMinTime = Math.max(nMinTime, nCoinTime + sequenceValue - 1);
    } else {
      // Height-based relative lock-time
      nMinHeight = Math.max(
        nMinHeight,
        nCoinHeight + (txinSequence & SEQUENCE_LOCKTIME_MASK) - 1,
      );
    }
  }

  return { first: nMinHeight, second: nMinTime };
}

/**
 * Check if sequence locks are satisfied for a given block.
 */
export function EvaluateSequenceLocks(
  block: MinimalBlockIndex,
  lockPair: { first: number; second: number },
): boolean {
  const nBlockTime = block.pprev?.getMedianTimePast() ?? 0;
  return !(lockPair.first >= block.nHeight || lockPair.second >= nBlockTime);
}

/**
 * Check if transaction is final per BIP 68 sequence numbers and can be included in a block.
 * Consensus critical.
 */
export function SequenceLocks(
  tx: CTransaction,
  flags: number,
  prevHeights: number[],
  block: MinimalBlockIndex,
): boolean {
  return EvaluateSequenceLocks(
    block,
    CalculateSequenceLocks(tx, flags, prevHeights, block),
  );
}

/**
 * Check whether all inputs of this transaction are valid (no double spends and amounts).
 * This does not modify the UTXO set. This does not check scripts and sigs.
 * @param tx - Transaction to check
 * @param state - Validation state (out parameter)
 * @param inputs - UTXO view
 * @param nSpendHeight - Current block height
 * @returns Tuple of [success, txfee]
 */
export function CheckTxInputs(
  tx: CTransaction,
  state: TxValidationState,
  inputs: MinimalCoinsView,
  nSpendHeight: number,
): [boolean, CAmount] {
  // Are the actual inputs available?
  for (const txin of tx.vin) {
    if (!inputs.haveCoin(txin.prevout)) {
      state.invalid(
        TxValidationResult.TX_MISSING_INPUTS,
        "bad-txns-inputs-missingorspent",
        `inputs missing/spent`,
      );
      return [false, 0n];
    }
  }

  let nValueIn = 0n;
  for (let i = 0; i < tx.vin.length; i++) {
    const prevout = tx.vin[i].prevout;
    const coin = inputs.accessCoin(prevout);

    // If prev is coinbase, check that it's matured
    if (coin.isCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
      state.invalid(
        TxValidationResult.TX_PREMATURE_SPEND,
        "bad-txns-premature-spend-of-coinbase",
        `tried to spend coinbase at depth ${nSpendHeight - coin.nHeight}`,
      );
      return [false, 0n];
    }

    // Check for negative or overflow input values
    nValueIn += coin.out.nValue;
    if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
      state.invalid(
        TxValidationResult.TX_CONSENSUS,
        "bad-txns-inputvalues-outofrange",
      );
      return [false, 0n];
    }
  }

  // GetValueOut() is guaranteed valid by the calling code
  const valueOut = getValueOut(tx);
  if (nValueIn < valueOut) {
    state.invalid(
      TxValidationResult.TX_CONSENSUS,
      "bad-txns-in-belowout",
      `value in (${nValueIn}) < value out (${valueOut})`,
    );
    return [false, 0n];
  }

  // Tally transaction fees
  const txfee = nValueIn - valueOut;
  if (!MoneyRange(txfee)) {
    state.invalid(TxValidationResult.TX_CONSENSUS, "bad-txns-fee-outofrange");
    return [false, 0n];
  }

  return [true, txfee];
}
