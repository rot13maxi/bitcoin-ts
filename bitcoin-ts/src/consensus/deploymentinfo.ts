// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Softfork deployment information.
 * This is a TypeScript port of Bitcoin Core's deploymentinfo.h and deploymentinfo.cpp
 */

import {
  BuriedDeployment,
  DeploymentPos,
  ValidDeployment,
  ValidDeploymentPos,
} from "./params";

/**
 * Deployment metadata for versionbits deployments.
 */
export interface VBDeploymentInfo {
  /** Deployment name */
  name: string;
  /** Whether GBT clients can safely ignore this rule in simplified usage */
  gbt_optional_rule: boolean;
}

/**
 * Version bits deployment information array.
 * Indexed by DeploymentPos enum value.
 */
export const VersionBitsDeploymentInfo: VBDeploymentInfo[] = [
  {
    name: "testdummy",
    gbt_optional_rule: true,
  },
];

/**
 * Return the name of a buried deployment.
 */
export function DeploymentName(dep: BuriedDeployment): string {
  if (!ValidDeployment(dep)) {
    throw new Error("Invalid buried deployment");
  }
  switch (dep) {
    case BuriedDeployment.DEPLOYMENT_HEIGHTINCB:
      return "bip34";
    case BuriedDeployment.DEPLOYMENT_CLTV:
      return "bip65";
    case BuriedDeployment.DEPLOYMENT_DERSIG:
      return "bip66";
    case BuriedDeployment.DEPLOYMENT_CSV:
      return "csv";
    case BuriedDeployment.DEPLOYMENT_SEGWIT:
      return "segwit";
  }
}

/**
 * Get the deployment position from a deployment name string.
 * Returns null if no deployment with that name exists.
 */
export function GetDeploymentPos(name: string): DeploymentPos | null {
  for (let i = 0; i < VersionBitsDeploymentInfo.length; i++) {
    if (VersionBitsDeploymentInfo[i].name === name) {
      return i as DeploymentPos;
    }
  }
  return null;
}

/**
 * Get a buried deployment from a deployment name string.
 * Returns null if no buried deployment with that name exists.
 */
export function GetBuriedDeployment(name: string): BuriedDeployment | null {
  if (name === "segwit") return BuriedDeployment.DEPLOYMENT_SEGWIT;
  if (name === "bip34") return BuriedDeployment.DEPLOYMENT_HEIGHTINCB;
  if (name === "dersig") return BuriedDeployment.DEPLOYMENT_DERSIG;
  if (name === "cltv") return BuriedDeployment.DEPLOYMENT_CLTV;
  if (name === "csv") return BuriedDeployment.DEPLOYMENT_CSV;
  return null;
}
