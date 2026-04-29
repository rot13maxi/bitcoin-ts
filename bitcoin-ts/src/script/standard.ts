/**
 * Bitcoin Core Standard Scripts
 * Ported from src/script/standard.h/cpp
 * 
 * @module script/standard
 */

import { CScript, Opcode } from './script';

/**
 * Standard script types
 */
export enum ScriptType {
  UNKNOWN = 'unknown',
  PUBKEY = 'pubkey',
  PUBKEYHASH = 'pkh',
  SCRIPTHASH = 'sh',
  MULTISIG = 'multisig',
  NULL_DATA = 'nulldata',
  WITNESS_V0_KEYHASH = 'wpkh',
  WITNESS_V0_SCRIPTHASH = 'wsh',
  WITNESS_UNKNOWN = 'witness_unknown',
  MULTISIG_PUBKEY = 'multisig_pubkey',
  TAPROOT = 'taproot',
  TAPSCRIPT = 'tapscript',
}

/**
 * Get the type of standard script
 */
export function GetScriptType(script: CScript): ScriptType {
  const data = script.buffer();

  // P2PK
  if (data.length >= 33 && data.length <= 65 && data[data.length - 1] === Opcode.OP_CHECKSIG) {
    return ScriptType.PUBKEY;
  }

  // P2PKH
  if (data.length === 25 && data[0] === Opcode.OP_DUP && 
      data[1] === Opcode.OP_HASH160 && data[2] === 20 &&
      data[23] === Opcode.OP_EQUALVERIFY && data[24] === Opcode.OP_CHECKSIG) {
    return ScriptType.PUBKEYHASH;
  }

  // P2SH
  if (data.length === 23 && data[0] === Opcode.OP_HASH160 && 
      data[1] === 20 && data[22] === Opcode.OP_EQUAL) {
    return ScriptType.SCRIPTHASH;
  }

  // P2WPKH
  if (data.length === 22 && data[0] === Opcode.OP_0 && data[1] === 20) {
    return ScriptType.WITNESS_V0_KEYHASH;
  }

  // P2WSH
  if (data.length === 34 && data[0] === Opcode.OP_0 && data[1] === 32) {
    return ScriptType.WITNESS_V0_SCRIPTHASH;
  }

  // OP_RETURN
  if (data.length > 0 && data[0] === Opcode.OP_RETURN) {
    return ScriptType.NULL_DATA;
  }

  // Taproot (version 1 with 32-byte program)
  if (data.length === 34 && data[0] === Opcode.OP_1 && data[1] === 32) {
    return ScriptType.TAPROOT;
  }

  // Tapscript (version 1 with 32-byte program for witness)
  if (data.length === 34 && data[0] === Opcode.OP_1 && data[1] === 32) {
    return ScriptType.TAPSCRIPT;
  }

  return ScriptType.UNKNOWN;
}

/**
 * Solver result for script analysis
 */
export interface ScriptSolution {
  script_type: ScriptType;
  script_pubkey: CScript;
  redeem_script: CScript | null;
  witness_script: CScript | null;
  final_script_witness: Uint8Array[];
}

/**
 * Extract script solutions
 */
export function Solver(script: CScript): ScriptSolution[] {
  const data = script.buffer();
  const scriptType = GetScriptType(script);

  switch (scriptType) {
    case ScriptType.PUBKEYHASH:
      return [{
        script_type: scriptType,
        script_pubkey: script,
        redeem_script: null,
        witness_script: null,
        final_script_witness: [],
      }];

    case ScriptType.SCRIPTHASH:
      return [{
        script_type: scriptType,
        script_pubkey: script,
        redeem_script: null,
        witness_script: null,
        final_script_witness: [],
      }];

    case ScriptType.WITNESS_V0_KEYHASH:
      return [{
        script_type: scriptType,
        script_pubkey: script,
        redeem_script: null,
        witness_script: null,
        final_script_witness: [],
      }];

    case ScriptType.WITNESS_V0_SCRIPTHASH:
      return [{
        script_type: scriptType,
        script_pubkey: script,
        redeem_script: null,
        witness_script: null,
        final_script_witness: [],
      }];

    default:
      return [{
        script_type: ScriptType.UNKNOWN,
        script_pubkey: script,
        redeem_script: null,
        witness_script: null,
        final_script_witness: [],
      }];
  }
}

/**
 * Check if a script is standard
 */
export function IsStandard(script: CScript): boolean {
  const data = script.buffer();

  // Must be push-only
  for (let i = 0; i < data.length; i++) {
    if (data[i] > Opcode.OP_16) {
      return false;
    }
  }

  const scriptType = GetScriptType(script);

  // Reject non-standard types
  return scriptType !== ScriptType.UNKNOWN;
}

/**
 * Get the size of a script element
 */
export function GetSizeOfCompactSize(n: number): number {
  if (n < 253) {
    return 1;
  }
  if (n < 0x10000) {
    return 3;
  }
  if (n < 0x100000000) {
    return 5;
  }
  return 9;
}

/**
 * Create a standard P2PKH script from a pubkey hash
 */
export function CreateP2PKHScript(pubkeyHash: Uint8Array): CScript {
  if (pubkeyHash.length !== 20) {
    throw new Error('P2PKH script requires 20-byte pubkey hash');
  }

  const script = new CScript();
  script.data = new Uint8Array(25);
  script.data[0] = Opcode.OP_DUP;
  script.data[1] = Opcode.OP_HASH160;
  script.data[2] = 20;
  script.data.set(pubkeyHash, 3);
  script.data[23] = Opcode.OP_EQUALVERIFY;
  script.data[24] = Opcode.OP_CHECKSIG;

  return script;
}

/**
 * Create a standard P2SH script from a script hash
 */
export function CreateP2SHScript(scriptHash: Uint8Array): CScript {
  if (scriptHash.length !== 20) {
    throw new Error('P2SH script requires 20-byte script hash');
  }

  const script = new CScript();
  script.data = new Uint8Array(23);
  script.data[0] = Opcode.OP_HASH160;
  script.data[1] = 20;
  script.data.set(scriptHash, 2);
  script.data[22] = Opcode.OP_EQUAL;

  return script;
}

/**
 * Create a standard P2WPKH script from a pubkey hash
 */
export function CreateP2WPKHScript(pubkeyHash: Uint8Array): CScript {
  if (pubkeyHash.length !== 20) {
    throw new Error('P2WPKH script requires 20-byte pubkey hash');
  }

  const script = new CScript();
  script.data = new Uint8Array(26);
  script.data[0] = Opcode.OP_0;
  script.data[1] = 20;
  script.data.set(pubkeyHash, 2);

  return script;
}

/**
 * Create a standard P2WSH script from a witness script hash
 */
export function CreateP2WSHScript(witnessScriptHash: Uint8Array): CScript {
  if (witnessScriptHash.length !== 32) {
    throw new Error('P2WSH script requires 32-byte witness script hash');
  }

  const script = new CScript();
  script.data = new Uint8Array(34);
  script.data[0] = Opcode.OP_0;
  script.data[1] = 32;
  script.data.set(witnessScriptHash, 2);

  return script;
}

/**
 * Create a standard P2TR (Taproot) script from an x-only pubkey
 */
export function CreateP2TRScript(internalKey: Uint8Array): CScript {
  if (internalKey.length !== 32) {
    throw new Error('P2TR script requires 32-byte x-only pubkey');
  }

  const script = new CScript();
  script.data = new Uint8Array(34);
  script.data[0] = Opcode.OP_1;
  script.data[1] = 32;
  script.data.set(internalKey, 2);

  return script;
}

/**
 * Create a multisig script
 */
export function CreateMultisigScript(
  threshold: number,
  pubkeys: Uint8Array[]
): CScript {
  if (threshold < 1 || threshold > pubkeys.length) {
    throw new Error('Invalid multisig threshold');
  }

  if (pubkeys.length > 16) {
    throw new Error('Too many pubkeys for multisig');
  }

  // Calculate script length
  // OP_M <threshold> <pubkey1> <pubkey2> ... <pubkeyN> OP_N OP_CHECKMULTISIG
  const scriptData = new Uint8Array(3 + pubkeys.length * 34 + 2);
  let pos = 0;

  scriptData[pos++] = Opcode.OP_1 - 1 + threshold;
  for (const pubkey of pubkeys) {
    scriptData[pos++] = pubkey.length;
    scriptData.set(pubkey, pos);
    pos += pubkey.length;
  }
  scriptData[pos++] = Opcode.OP_1 - 1 + pubkeys.length;
  scriptData[pos++] = Opcode.OP_CHECKMULTISIG;

  return new CScript(scriptData);
}
