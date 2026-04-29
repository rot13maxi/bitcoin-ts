// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Proof-of-work consensus logic.
 * This is a TypeScript port of Bitcoin Core's pow.h and pow.cpp
 */

import { uint256 } from "./uint256";
import { arith_uint256, uintToArith256 } from "./arith_uint256";
import { Params, DifficultyAdjustmentInterval } from "./consensus/params";

/**
 * What block version to use for new blocks (pre versionbits)
 */
export const VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4;

/**
 * Convert nBits compact representation to a target arith_uint256.
 * @param nBits - compact representation of the target
 * @param powLimit - PoW limit (consensus parameter)
 * @returns the target or null if the nBits value is invalid
 */
export function DeriveTarget(
  nBits: number,
  powLimit: uint256,
): arith_uint256 | null {
  const bnTarget = new arith_uint256();
  bnTarget.setCompact(nBits);

  const limit = uintToArith256(powLimit);

  // Check range: target must be positive and not exceed powLimit
  if (bnTarget.bits() === 0) return null;
  if (bnTarget.compareTo(limit) > 0) return null;

  return bnTarget;
}

/**
 * Check whether a block hash satisfies the proof-of-work requirement specified by nBits.
 * @param hash - block hash
 * @param nBits - compact target
 * @param params - consensus parameters
 */
export function CheckProofOfWork(
  hash: uint256,
  nBits: number,
  params: Params,
): boolean {
  return CheckProofOfWorkImpl(hash, nBits, params);
}

/**
 * Internal proof-of-work check.
 */
export function CheckProofOfWorkImpl(
  hash: uint256,
  nBits: number,
  params: Params,
): boolean {
  const bnTarget = DeriveTarget(nBits, params.powLimit);
  if (!bnTarget) return false;

  const hashArith = uintToArith256(hash);
  return hashArith.compareTo(bnTarget) <= 0;
}

/**
 * Compute the next work required (nBits) given the last block and consensus parameters.
 * @param pindexLast - Previous block index (must not be null)
 * @param blockTime - Current block's timestamp
 * @param params - Consensus parameters
 */
export function GetNextWorkRequired(
  pindexLast: { nHeight: number; nBits: number; getBlockTime: () => number },
  blockTime: number,
  params: Params,
): number {
  const nProofOfWorkLimit = uintToArith256(params.powLimit).getCompact();

  // Only change once per difficulty adjustment interval
  if ((pindexLast.nHeight + 1) % DifficultyAdjustmentInterval(params) !== 0) {
    if (params.fPowAllowMinDifficultyBlocks) {
      if (
        blockTime >
        pindexLast.getBlockTime() + params.nPowTargetSpacing * 2
      ) {
        return nProofOfWorkLimit;
      }
    }
    return pindexLast.nBits;
  }

  const nFirstBlockTime = pindexLast.getBlockTime();
  return CalculateNextWorkRequired(pindexLast, nFirstBlockTime, params);
}

/**
 * Calculate the next work required using median past time algorithm.
 * @param pindexLast - Previous block index
 * @param nFirstBlockTime - Timestamp of the first block in the adjustment period
 * @param params - Consensus parameters
 */
export function CalculateNextWorkRequired(
  pindexLast: { nBits: number; getBlockTime: () => number },
  nFirstBlockTime: number,
  params: Params,
): number {
  if (params.fPowNoRetargeting) {
    return pindexLast.nBits;
  }

  // Limit adjustment step
  let nActualTimespan = pindexLast.getBlockTime() - nFirstBlockTime;
  if (nActualTimespan < params.nPowTargetTimespan / 4) {
    nActualTimespan = Math.floor(params.nPowTargetTimespan / 4);
  }
  if (nActualTimespan > params.nPowTargetTimespan * 4) {
    nActualTimespan = params.nPowTargetTimespan * 4;
  }

  // Retarget
  const bnPowLimit = uintToArith256(params.powLimit);
  let bnNew = new arith_uint256();
  bnNew.setCompact(pindexLast.nBits);

  // Apply retargeting: new_target = old_target * actual_timespan / target_timespan
  bnNew = bnNew.multiply32(Math.floor(nActualTimespan)) as arith_uint256;
  bnNew = bnNew.divide(
    new arith_uint256(params.nPowTargetTimespan),
  ) as arith_uint256;

  if (bnNew.compareTo(bnPowLimit) > 0) {
    return bnPowLimit.getCompact();
  }

  return bnNew.getCompact();
}

/**
 * Return false if the proof-of-work requirement specified by new_nbits at a
 * given height is not possible, given the proof-of-work on the prior block as
 * specified by old_nbits.
 *
 * This function only checks that the new value is within a factor of 4 of the
 * old value for blocks at the difficulty adjustment interval, and otherwise
 * requires the values to be the same.
 *
 * Always returns true on networks where min difficulty blocks are allowed.
 */
export function PermittedDifficultyTransition(
  params: Params,
  height: number,
  old_nbits: number,
  new_nbits: number,
): boolean {
  if (params.fPowAllowMinDifficultyBlocks) return true;

  if (height % DifficultyAdjustmentInterval(params) === 0) {
    const smallest_timespan = params.nPowTargetTimespan / 4;
    const largest_timespan = params.nPowTargetTimespan * 4;

    const pow_limit = uintToArith256(params.powLimit);

    // Calculate the largest difficulty value possible:
    let largest_target = new arith_uint256();
    largest_target.setCompact(old_nbits);
    largest_target = largest_target.multiply32(
      Math.floor(largest_timespan),
    ) as arith_uint256;
    largest_target = largest_target.divide(
      new arith_uint256(params.nPowTargetTimespan),
    ) as arith_uint256;

    // Round the largest target
    const max_rounded = new arith_uint256();
    max_rounded.setCompact(largest_target.getCompact());

    // Calculate the smallest difficulty value possible:
    let smallest_target = new arith_uint256();
    smallest_target.setCompact(old_nbits);
    smallest_target = smallest_target.multiply32(
      Math.floor(smallest_timespan),
    ) as arith_uint256;
    smallest_target = smallest_target.divide(
      new arith_uint256(params.nPowTargetTimespan),
    ) as arith_uint256;

    // Round the smallest target
    const min_rounded = new arith_uint256();
    min_rounded.setCompact(smallest_target.getCompact());

    const observed_target = new arith_uint256();
    observed_target.setCompact(new_nbits);

    if (max_rounded.compareTo(observed_target) < 0) return false;
    if (min_rounded.compareTo(observed_target) > 0) return false;
  } else if (old_nbits !== new_nbits) {
    return false;
  }
  return true;
}
