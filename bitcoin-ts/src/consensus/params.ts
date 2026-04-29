// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Consensus parameters.
 * This is a TypeScript port of Bitcoin Core's consensus/params.h
 */

import { uint256 } from "../uint256";
import { script_verify_flags } from "../script/verify_flags";

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 * Consensus changes for which the new rules are enforced from genesis are not listed here.
 */
export enum BuriedDeployment {
  // buried deployments get negative values to avoid overlap with DeploymentPos
  DEPLOYMENT_HEIGHTINCB = -(2 ** 15),
  DEPLOYMENT_CLTV,
  DEPLOYMENT_DERSIG,
  DEPLOYMENT_CSV,
  // SCRIPT_VERIFY_WITNESS is enforced from genesis, but the check for downloading
  // missing witness data is not. BIP 147 also relies on hardcoded activation height.
  DEPLOYMENT_SEGWIT,
}

export function ValidDeployment(dep: BuriedDeployment): boolean {
  return dep <= BuriedDeployment.DEPLOYMENT_SEGWIT;
}

export enum DeploymentPos {
  DEPLOYMENT_TESTDUMMY,
  // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.ts
  // Removing an entry may require bumping MinBIP9WarningHeight.
  MAX_VERSION_BITS_DEPLOYMENTS,
}

export function ValidDeploymentPos(dep: DeploymentPos): boolean {
  return dep < DeploymentPos.MAX_VERSION_BITS_DEPLOYMENTS;
}

/**
 * Struct for each individual consensus rule change using BIP9.
 */
export interface BIP9Deployment {
  /** Bit position to select the particular bit in nVersion. */
  bit: number;
  /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
  nStartTime: number;
  /** Timeout/expiry MedianTime for the deployment attempt. */
  nTimeout: number;
  /** If lock in occurs, delay activation until at least this block
   *  height.  Note that activation will only occur on a retarget
   *  boundary.
   */
  min_activation_height: number;
  /** Period of blocks to check signalling in (usually retarget period) */
  period: number;
  /**
   * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
   * which is also used for BIP9 deployments.
   * Examples: 1916 for 95%, 1512 for testchains.
   */
  threshold: number;
}

export namespace BIP9Deployment {
  /** Constant for nTimeout very far in the future. */
  export const NO_TIMEOUT = Number.MAX_SAFE_INTEGER;

  /** Special value for nStartTime indicating that the deployment is always active.
   *  This is useful for testing. */
  export const ALWAYS_ACTIVE = -1;

  /** Special value for nStartTime indicating that the deployment is never active. */
  export const NEVER_ACTIVE = -2;
}

/**
 * Parameters that influence chain consensus.
 */
export interface Params {
  hashGenesisBlock: uint256;
  nSubsidyHalvingInterval: number;
  /**
   * Hashes of blocks that
   * - are known to be consensus valid, and
   * - buried in the chain, and
   * - fail if the default script verify flags are applied.
   */
  scriptFlagExceptions: Map<uint256, script_verify_flags>;
  /** Block height and hash at which BIP34 becomes active */
  BIP34Height: number;
  BIP34Hash: uint256;
  /** Block height at which BIP65 becomes active */
  BIP65Height: number;
  /** Block height at which BIP66 becomes active */
  BIP66Height: number;
  /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
  CSVHeight: number;
  /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active. */
  SegwitHeight: number;
  /** Don't warn about unknown BIP 9 activations below this height. */
  MinBIP9WarningHeight: number;
  vDeployments: BIP9Deployment[];
  /** Proof of work parameters */
  powLimit: uint256;
  fPowAllowMinDifficultyBlocks: boolean;
  /**
   * Enforce BIP94 timewarp attack mitigation. On testnet4 this also enforces
   * the block storm mitigation.
   */
  enforce_BIP94: boolean;
  fPowNoRetargeting: boolean;
  nPowTargetSpacing: number;
  nPowTargetTimespan: number;
  /** The best chain should have at least this much work */
  nMinimumChainWork: uint256;
  /** By default assume that the signatures in ancestors of this block are valid */
  defaultAssumeValid: uint256;

  /**
   * If true, witness commitments contain a payload equal to a Bitcoin Script solution
   * to the signet challenge. See BIP325.
   */
  signet_blocks: boolean;
  signet_challenge: Uint8Array;
}

export function DifficultyAdjustmentInterval(params: Params): number {
  return Math.floor(params.nPowTargetTimespan / params.nPowTargetSpacing);
}

export function DeploymentHeight(
  params: Params,
  dep: BuriedDeployment,
): number {
  switch (dep) {
    case BuriedDeployment.DEPLOYMENT_HEIGHTINCB:
      return params.BIP34Height;
    case BuriedDeployment.DEPLOYMENT_CLTV:
      return params.BIP65Height;
    case BuriedDeployment.DEPLOYMENT_DERSIG:
      return params.BIP66Height;
    case BuriedDeployment.DEPLOYMENT_CSV:
      return params.CSVHeight;
    case BuriedDeployment.DEPLOYMENT_SEGWIT:
      return params.SegwitHeight;
  }
}
