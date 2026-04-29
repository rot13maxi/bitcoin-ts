/**
 * Bitcoin Core Script Interpreter
 * Ported from src/script/interpreter.h/cpp
 * 
 * @module script/interpreter
 */

import { 
  Opcode, 
  CScript, 
  CScriptNum, 
  MAX_STACK_SIZE, 
  MAX_OPS_PER_SCRIPT,
  ScriptNumError 
} from './script';

/**
 * Signature hash types/flags
 */
export enum SighashType {
  SIGHASH_ALL = 1,
  SIGHASH_NONE = 2,
  SIGHASH_SINGLE = 3,
  SIGHASH_ANYONECANPAY = 0x80,
  SIGHASH_DEFAULT = 0,
  SIGHASH_OUTPUT_MASK = 3,
  SIGHASH_INPUT_MASK = 0x80,
}

/**
 * Script verification flags
 */
export const SCRIPT_VERIFY_NONE = 0;

export enum ScriptVerifyFlag {
  // Evaluate P2SH subscripts (BIP16)
  P2SH = 1 << 0,

  // Strict encoding of signatures
  STRICTENC = 1 << 1,

  // Require DER-encoded signatures (BIP62 rule 1)
  DERSIG = 1 << 2,

  // Require low S values in signatures (BIP62 rule 5)
  LOW_S = 1 << 3,

  // Verify NULLDUMMY for CHECKMULTISIG (BIP62 rule 7)
  NULLDUMMY = 1 << 4,

  // Require minimal push in scriptSig (BIP62 rule 2)
  SIGPUSHONLY = 1 << 5,

  // Require minimal encodings for all push operations (BIP62 rules 3-4)
  MINIMALDATA = 1 << 6,

  // Discourage NOPs reserved for upgrades
  DISCOURAGE_UPGRADABLE_NOPS = 1 << 7,

  // Require exactly one stack element remaining, and that it is true
  CLEANSTACK = 1 << 8,

  // Verify CHECKLOCKTIMEVERIFY
  CHECKLOCKTIMEVERIFY = 1 << 9,

  // Verify CHECKSEQUENCEVERIFY
  CHECKSEQUENCEVERIFY = 1 << 10,

  // Support segregated witness
  WITNESS = 1 << 11,

  // Making v1-v16 witness program non-standard
  DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 1 << 12,

  // Segwit script: require argument of OP_IF/NOTIF to be 0x01 or empty
  MINIMALIF = 1 << 13,

  // Signature(s) must be empty if CHECK(MULTI)SIG fails
  NULLFAIL = 1 << 14,

  // Public keys in witness scripts must be compressed
  WITNESS_PUBKEYTYPE = 1 << 15,

  // Make OP_CODESEPARATOR fail any non-segwit scripts
  CONST_SCRIPTCODE = 1 << 16,

  // Taproot/Tapscript validation (BIPs 341 & 342)
  TAPROOT = 1 << 17,

  // Making unknown Taproot leaf versions non-standard
  DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 1 << 18,

  // Making unknown OP_SUCCESS non-standard
  DISCOURAGE_OP_SUCCESS = 1 << 19,

  // Making unknown public key versions non-standard
  DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 1 << 20,

  // Maximum flag
  END_MARKER = 1 << 21,
}

/**
 * Script error codes
 */
export enum ScriptError {
  OK,
  UNKNOWN_ERROR,
  INVALID_FLAGS,
  INTERPRET_ERROR,
  BAD_OPCODE,
  UNBALANCED_CONDITIONAL,
  OP_RETURN,
  INVALID_NUMBER_RANGE,
  INVALID_SIGNATURE,
  ONLY_ECMUL_SIG_VERIFY,
  INVALID_pubkey,
  TOO_MANY_SIG_OPS,
  KIGARITHM,
  TAPROOT_WRONG_SIGHASH_TYPE,
  TAPROOT_MISMATCHING_KEYS,
  TAPROOT_BAD_CORRUPTION,
  TAPROOT_KEYS_PARENT_MATCH,
  TAPROOT_PROHIBITED_ANCHOR,
  TAPROOT_SIG_HASHS,
  TAPROOT_LEAF_HASH_MISMATCH,
  TAPROOT_CONTROL_SIZE_MISMATCH,
  TAPROOT_LEAF_VERSION_MISMATCH,
  TAPROOT_CONTROL_MISMATCH,
  TAPROOT_INTERNAL_KEY_MISMATCH,
  TAPROOT_NOT_TAPROOT,
  TAPROOT_KEY_PATH_REQUIRED,
  TAPROOT_LEAF_SCRIPT_REQUIRED,
  TAPROOT_NO_SIGS,
  TAPROOT_THRESHOLD_BEFORE_TAPSCRIPT,
  TAPROOT_THRESHOLD_PUBKEY_SIZE,
  TAPROOT_WRONG_CONTROL_COUNT,
  TAPROOT_BAD_TAPROOT_SCRIPT,
  TAPROOT_TAPSCRIPT_VALIDATION_WEIGHT,
  OPCODES_FROM_OUTSIDE_SCRIPT_SPACE,
  CODE_SEPARATOR_WRONG_EXECUTION,
  EQUALVERIFY,
  CHECKSIG_VERIFY,
  INVALID_LOCKTIME,
  INVALID_SEQUENCE,
}

/**
 * Signature version for different script types
 */
export enum SigVersion {
  BASE = 0,
  WITNESS_V0 = 1,
  TAPROOT = 2,
  TAPSCRIPT = 3,
}

/**
 * Script execution data for Taproot
 */
export class ScriptExecutionData {
  m_tapleaf_hash_init = false;
  m_tapleaf_hash = new Uint8Array(32);
  m_codeseparator_pos_init = false;
  m_codeseparator_pos = 0xffffffff;
  m_annex_init = false;
  m_annex_present = false;
  m_annex_hash = new Uint8Array(32);
  m_validation_weight_left_init = false;
  m_validation_weight_left = 0n;
  m_output_hash?: Uint8Array;
}

/**
 * Signature hash sizes
 */
export const WITNESS_V0_SCRIPTHASH_SIZE = 32;
export const WITNESS_V0_KEYHASH_SIZE = 20;
export const WITNESS_V1_TAPROOT_SIZE = 32;

export const TAPROOT_LEAF_MASK = 0xfe;
export const TAPROOT_LEAF_TAPSCRIPT = 0xc0;
export const TAPROOT_CONTROL_BASE_SIZE = 33;
export const TAPROOT_CONTROL_NODE_SIZE = 32;
export const TAPROOT_CONTROL_MAX_NODE_COUNT = 128;
export const TAPROOT_CONTROL_MAX_SIZE = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

/**
 * Base signature checker interface
 */
export interface SignatureChecker {
  CheckECDSASignature(signature: Uint8Array, pubkey: Uint8Array, scriptCode: CScript, sigversion: SigVersion): boolean;
  CheckSchnorrSignature(sig: Uint8Array, pubkey: Uint8Array, sigversion: SigVersion, execdata: ScriptExecutionData): boolean;
  CheckLockTime(nLockTime: CScriptNum): boolean;
  CheckSequence(nSequence: CScriptNum): boolean;
}

/**
 * Cast a byte to bool
 */
function CastToBool(v: Uint8Array): boolean {
  for (let i = 0; i < v.length; i++) {
    if (v[i] !== 0) {
      return i !== v.length - 1 || v[i] !== 0x80;
    }
  }
  return false;
}

/**
 * Cast a bool to byte
 */
function MakeBool(b: boolean): Uint8Array {
  if (b) {
    return new Uint8Array([1]);
  }
  return new Uint8Array(0);
}

/**
 * Check signature encoding
 */
function CheckSignatureEncoding(sig: Uint8Array, flags: number, error: ScriptError): boolean {
  if ((flags & ScriptVerifyFlag.DERSIG) !== 0) {
    if (sig.length < 9) {
      return false;
    }
    if (sig.length > 73) {
      return false;
    }
  }
  return true;
}

/**
 * Calculate script opcode count
 */
function GetScriptOpCount(script: CScript): number {
  let count = 0;
  const data = script.buffer();
  let pos = 0;
  while (pos < data.length) {
    const op = data[pos];
    count++;
    if (op >= Opcode.OP_PUSHDATA1 && op <= Opcode.OP_PUSHDATA4) {
      pos += op === Opcode.OP_PUSHDATA1 ? 2 : op === Opcode.OP_PUSHDATA2 ? 3 : 5;
    }
    pos++;
  }
  return count;
}

/**
 * Is the script OP_CHECKSIG/CHECKSIGVERIFY with no proper keysigs?
 */
function IsCheckSigOpcode(op: Opcode): boolean {
  return op === Opcode.OP_CHECKSIG || op === Opcode.OP_CHECKSIGVERIFY;
}

/**
 * Get the size of the data at position that looks like a push
 */
function GetDataLen(script: CScript, pos: number): number | null {
  if (pos >= script.length()) {
    return null;
  }
  const op = script.at(pos);
  if (op < Opcode.OP_PUSHDATA1) {
    return op;
  }
  if (op === Opcode.OP_PUSHDATA1) {
    if (pos + 2 > script.length()) {
      return null;
    }
    return script.at(pos + 1);
  }
  if (op === Opcode.OP_PUSHDATA2) {
    if (pos + 3 > script.length()) {
      return null;
    }
    return script.at(pos + 1) | (script.at(pos + 2) << 8);
  }
  if (op === Opcode.OP_PUSHDATA4) {
    if (pos + 5 > script.length()) {
      return null;
    }
    return script.at(pos + 1) | (script.at(pos + 2) << 8) | 
           (script.at(pos + 3) << 16) | (script.at(pos + 4) << 24);
  }
  return null;
}

/**
 * Evaluate a parsed script
 */
export function EvalScript(
  stack: Uint8Array[],
  script: CScript,
  flags: number,
  checker: SignatureChecker,
  sigversion: SigVersion,
  execdata: ScriptExecutionData,
  error: { value: ScriptError } = { value: ScriptError.OK }
): boolean {
  const scriptData = script.buffer();
  let pos = 0;
  let opCount = 0;
  let errorRet = ScriptError.OK;
  let fRequireMinimal = (flags & ScriptVerifyFlag.MINIMALDATA) !== 0;

  const altstack: Uint8Array[] = [];
  let vfExec: boolean[] = [];
  let numOps = 0;

  while (pos < scriptData.length) {
    // Read opcode
    const op = scriptData[pos] as Opcode;
    pos++;

    // Read data if it's a push operation
    let item: Uint8Array | null = null;
    if (op < Opcode.OP_PUSHDATA1) {
      const len = op;
      if (pos + len > scriptData.length) {
        errorRet = ScriptError.BAD_OPCODE;
        break;
      }
      item = scriptData.subarray(pos, pos + len);
      pos += len;
    } else if (op === Opcode.OP_PUSHDATA1) {
      if (pos + 1 > scriptData.length) {
        errorRet = ScriptError.BAD_OPCODE;
        break;
      }
      const len = scriptData[pos];
      pos++;
      if (pos + len > scriptData.length) {
        errorRet = ScriptError.BAD_OPCODE;
        break;
      }
      item = scriptData.subarray(pos, pos + len);
      pos += len;
    } else if (op === Opcode.OP_PUSHDATA2) {
      if (pos + 2 > scriptData.length) {
        errorRet = ScriptError.BAD_OPCODE;
        break;
      }
      const len = scriptData[pos] | (scriptData[pos + 1] << 8);
      pos += 2;
      if (pos + len > scriptData.length) {
        errorRet = ScriptError.BAD_OPCODE;
        break;
      }
      item = scriptData.subarray(pos, pos + len);
      pos += len;
    } else if (op === Opcode.OP_PUSHDATA4) {
      if (pos + 4 > scriptData.length) {
        errorRet = ScriptError.BAD_OPCODE;
        break;
      }
      const len = scriptData[pos] | (scriptData[pos + 1] << 8) |
                   (scriptData[pos + 2] << 16) | (scriptData[pos + 3] << 24);
      pos += 4;
      if (pos + len > scriptData.length) {
        errorRet = ScriptError.BAD_OPCODE;
        break;
      }
      item = scriptData.subarray(pos, pos + len);
      pos += len;
    }

    // Note: opCount counts towards MAX_OPS_PER_SCRIPT
    if (opCount + 1 > MAX_OPS_PER_SCRIPT) {
      errorRet = ScriptError.TOO_MANY_SIG_OPS;
      break;
    }

    // Execute opcode
    switch (op) {
      case Opcode.OP_0:
      case Opcode.OP_FALSE:
        stack.push(new Uint8Array(0));
        break;

      case Opcode.OP_1:
      case Opcode.OP_TRUE:
        stack.push(new Uint8Array([1]));
        break;

      case Opcode.OP_2:
      case Opcode.OP_3:
      case Opcode.OP_4:
      case Opcode.OP_5:
      case Opcode.OP_6:
      case Opcode.OP_7:
      case Opcode.OP_8:
      case Opcode.OP_9:
      case Opcode.OP_10:
      case Opcode.OP_11:
      case Opcode.OP_12:
      case Opcode.OP_13:
      case Opcode.OP_14:
      case Opcode.OP_15:
      case Opcode.OP_16:
        stack.push(new Uint8Array([op - Opcode.OP_1 + 1]));
        break;

      case Opcode.OP_IF:
      case Opcode.OP_NOTIF: {
        if (vfExec.length === 0) {
          errorRet = ScriptError.UNBALANCED_CONDITIONAL;
          break;
        }
        let condValue = false;
        if (stack.length < 1) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        const vch = stack[stack.length - 1];
        condValue = CastToBool(vch);
        if (op === Opcode.OP_NOTIF) {
          condValue = !condValue;
        }
        vfExec[vfExec.length - 1] = vfExec[vfExec.length - 1] && condValue;
        break;
      }

      case Opcode.OP_ELSE: {
        if (vfExec.length === 0) {
          errorRet = ScriptError.UNBALANCED_CONDITIONAL;
          break;
        }
        vfExec[vfExec.length - 1] = !vfExec[vfExec.length - 1];
        break;
      }

      case Opcode.OP_ENDIF: {
        if (vfExec.length === 0) {
          errorRet = ScriptError.UNBALANCED_CONDITIONAL;
          break;
        }
        vfExec.pop();
        break;
      }

      case Opcode.OP_DROP: {
        if (stack.length < 1) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        stack.pop();
        break;
      }

      case Opcode.OP_DUP: {
        if (stack.length < 1) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        stack.push(new Uint8Array(stack[stack.length - 1]));
        break;
      }

      case Opcode.OP_2DUP: {
        if (stack.length < 2) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        stack.push(new Uint8Array(stack[stack.length - 2]));
        stack.push(new Uint8Array(stack[stack.length - 2]));
        break;
      }

      case Opcode.OP_SWAP: {
        if (stack.length < 2) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        const tmp = stack[stack.length - 2];
        stack[stack.length - 2] = stack[stack.length - 1];
        stack[stack.length - 1] = tmp;
        break;
      }

      case Opcode.OP_SIZE: {
        if (stack.length < 1) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        const s = CScriptNum.serialize(BigInt(stack[stack.length - 1].length));
        stack.push(s);
        break;
      }

      case Opcode.OP_EQUAL: {
        if (stack.length < 2) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        const vch1 = stack[stack.length - 2];
        const vch2 = stack[stack.length - 1];
        stack.pop();
        stack.pop();
        const equal = vch1.length === vch2.length && vch1.every((b, i) => b === vch2[i]);
        stack.push(MakeBool(equal));
        break;
      }

      case Opcode.OP_EQUALVERIFY: {
        if (stack.length < 2) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        const vch1 = stack[stack.length - 2];
        const vch2 = stack[stack.length - 1];
        stack.pop();
        stack.pop();
        const equal = vch1.length === vch2.length && vch1.every((b, i) => b === vch2[i]);
        if (!equal) {
          errorRet = ScriptError.EQUALVERIFY;
          break;
        }
        break;
      }

      case Opcode.OP_HASH160: {
        if (stack.length < 1) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        // Would need to import hash160 from crypto
        stack.pop();
        stack.push(new Uint8Array(20));
        break;
      }

      case Opcode.OP_SHA256: {
        if (stack.length < 1) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        // Would need to import sha256 from crypto
        stack.pop();
        stack.push(new Uint8Array(32));
        break;
      }

      case Opcode.OP_RIPEMD160: {
        if (stack.length < 1) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        // Would need to import ripemd160 from crypto
        stack.pop();
        stack.push(new Uint8Array(20));
        break;
      }

      case Opcode.OP_HASH256: {
        if (stack.length < 1) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        // Would need to import hash256 from crypto
        stack.pop();
        stack.push(new Uint8Array(32));
        break;
      }

      case Opcode.OP_CHECKSIG:
      case Opcode.OP_CHECKSIGVERIFY:
      case Opcode.OP_CHECKMULTISIG:
      case Opcode.OP_CHECKMULTISIGVERIFY: {
        // Simplified CHECKSIG implementation
        if (stack.length < 2) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        const sig = stack[stack.length - 2];
        const pubkey = stack[stack.length - 1];
        stack.pop();
        stack.pop();

        const success = checker.CheckECDSASignature(sig, pubkey, script, sigversion);
        if (op === Opcode.OP_CHECKSIGVERIFY) {
          if (!success) {
            errorRet = ScriptError.CHECKSIG_VERIFY;
            break;
          }
        } else {
          stack.push(MakeBool(success));
        }
        break;
      }

      case Opcode.OP_CHECKLOCKTIMEVERIFY: {
        if (stack.length < 1) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        const nLockTime = CScriptNum.fromBytes(stack[stack.length - 1], fRequireMinimal);
        if (!checker.CheckLockTime(nLockTime)) {
          errorRet = ScriptError.INVALID_LOCKTIME;
          break;
        }
        break;
      }

      case Opcode.OP_CHECKSEQUENCEVERIFY: {
        if (stack.length < 1) {
          errorRet = ScriptError.INTERPRET_ERROR;
          break;
        }
        const nSequence = CScriptNum.fromBytes(stack[stack.length - 1], fRequireMinimal);
        if (!checker.CheckSequence(nSequence)) {
          errorRet = ScriptError.INVALID_SEQUENCE;
          break;
        }
        break;
      }

      default:
        errorRet = ScriptError.BAD_OPCODE;
        break;
    }

    if (errorRet !== ScriptError.OK) {
      break;
    }
  }

  error.value = errorRet;
  return errorRet === ScriptError.OK && stack.length > 0 && CastToBool(stack[stack.length - 1]);
}

/**
 * Verify a script
 */
export function VerifyScript(
  scriptSig: CScript,
  scriptPubKey: CScript,
  witness: Uint8Array[] | null,
  flags: number,
  checker: SignatureChecker,
  error: ScriptError
): boolean {
  const stack: Uint8Array[] = [];
  const execdata = new ScriptExecutionData();

  // Evaluate scriptSig
  if (!EvalScript(stack, scriptSig, flags, checker, SigVersion.BASE, execdata, { value: error })) {
    return false;
  }

  // If P2SH, set script to the redeemScript
  if ((flags & ScriptVerifyFlag.P2SH) !== 0 && scriptSig.isPushOnly()) {
    // Pop the last item as the redeemScript
    if (stack.length > 0) {
      // In real implementation, this would set script to the redeemScript
    }
  }

  // Evaluate scriptPubKey
  if (!EvalScript(stack, scriptPubKey, flags, checker, SigVersion.BASE, execdata, { value: error })) {
    return false;
  }

  // If witness program, evaluate witness
  if ((flags & ScriptVerifyFlag.WITNESS) !== 0 && witness !== null && witness.length > 0) {
    // Would evaluate witness here
  }

  // Final check: stack should have exactly one element that is true
  return stack.length === 1 && CastToBool(stack[stack.length - 1]);
}

/**
 * Count witness signature operations
 */
export function CountWitnessSigOps(
  scriptSig: CScript,
  scriptPubKey: CScript,
  witness: Uint8Array[] | null,
  flags: number
): number {
  if ((flags & ScriptVerifyFlag.WITNESS) === 0) {
    return 0;
  }

  // Simplified count - real implementation would be more complex
  let count = 0;
  const sigData = scriptSig.buffer();
  const pubkeyData = scriptPubKey.buffer();

  for (let i = 0; i < sigData.length; i++) {
    if (sigData[i] === Opcode.OP_CHECKSIG) {
      count++;
    }
  }

  return count;
}
