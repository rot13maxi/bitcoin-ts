// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Deployment status checks.
 * This is a TypeScript port of Bitcoin Core's deploymentstatus.h
 */

import {
  Params,
  DeploymentHeight,
  BuriedDeployment,
  DeploymentPos,
} from "./params";
import { ValidDeploymentPos, ValidDeployment } from "./params";

/**
 * Minimal block index interface for deployment status checks.
 */
export interface DeploymentBlockIndex {
  readonly nHeight: number;
  readonly pprev: DeploymentBlockIndex | null;
}

/**
 * Version bits deployment state.
 */
export enum ThresholdState {
  DEFINED = 0,
  STARTED = 1,
  LOCKED_IN = 2,
  ACTIVE = 3,
  FAILED = 4,
}

/**
 * Get a human-readable name for a threshold state.
 */
export function StateName(state: ThresholdState): string {
  switch (state) {
    case ThresholdState.DEFINED:
      return "defined";
    case ThresholdState.STARTED:
      return "started";
    case ThresholdState.LOCKED_IN:
      return "locked_in";
    case ThresholdState.ACTIVE:
      return "active";
    case ThresholdState.FAILED:
      return "failed";
  }
  return "invalid";
}

/**
 * Statistics about BIP9 signalling in the current period.
 */
export interface BIP9Stats {
  /** Length of blocks of the BIP9 signalling period */
  period: number;
  /** Number of blocks with the version bit set required to activate */
  threshold: number;
  /** Number of blocks elapsed since the beginning of the current period */
  elapsed: number;
  /** Number of blocks with the version bit set */
  count: number;
  /** Whether activation is still possible in this period */
  possible: boolean;
}

/**
 * Detailed status of an enabled BIP9 deployment.
 */
export interface BIP9Info {
  /** Height at which current state started */
  since: number;
  /** String representing the current state */
  current_state: string;
  /** String representing the next block's state */
  next_state: string;
  /** Signalling statistics (if applicable) */
  stats: BIP9Stats | null;
  /** Which blocks signalled (if applicable) */
  signalling_blocks: boolean[];
  /** Height at which the deployment is active, if known */
  active_since: number | null;
}

/**
 * Determine if a buried deployment is active for the next block.
 */
export function DeploymentActiveAfter(
  pindexPrev: DeploymentBlockIndex | null,
  params: Params,
  dep: BuriedDeployment,
): boolean {
  if (!ValidDeployment(dep)) {
    throw new Error("Invalid buried deployment");
  }
  return (
    (pindexPrev === null ? 0 : pindexPrev.nHeight + 1) >=
    DeploymentHeight(params, dep)
  );
}

/**
 * Determine if a buried deployment is active for a given block.
 */
export function DeploymentActiveAt(
  index: DeploymentBlockIndex,
  params: Params,
  dep: BuriedDeployment,
): boolean {
  if (!ValidDeployment(dep)) {
    throw new Error("Invalid buried deployment");
  }
  return index.nHeight >= DeploymentHeight(params, dep);
}

/**
 * Determine if a deployment is enabled (can ever be active).
 */
export function DeploymentEnabled(
  params: Params,
  dep: BuriedDeployment,
): boolean {
  if (!ValidDeployment(dep)) {
    throw new Error("Invalid buried deployment");
  }
  return DeploymentHeight(params, dep) !== Number.MAX_SAFE_INTEGER;
}
