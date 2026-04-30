/**
 * Bitcoin Core Script Module
 * 
 * @module script
 */

// Script constants and opcodes
export {
  // Constants
  MAX_SCRIPT_ELEMENT_SIZE,
  MAX_OPS_PER_SCRIPT,
  MAX_PUBKEYS_PER_MULTISIG,
  MAX_PUBKEYS_PER_MULTI_A,
  MAX_SCRIPT_SIZE,
  MAX_STACK_SIZE,
  LOCKTIME_THRESHOLD,
  LOCKTIME_MAX,
  ANNEX_TAG,
  VALIDATION_WEIGHT_PER_SIGOP_PASSED,
  VALIDATION_WEIGHT_OFFSET,
  MAX_OPCODE,
  
  // Opcode enum
  Opcode,
  
  // Functions
  GetOpName,
  GetOpForIndex,
} from './script';

export {
  // ScriptNum class
  CScriptNum,
  ScriptNumError,
  
  // CScript class
  CScript,
} from './script';

// Script interpreter
export {
  // Sighash types
  SighashType,
  
  // Verification flags
  ScriptVerifyFlag,
  SCRIPT_VERIFY_NONE,
  
  // Script errors
  ScriptError,
  
  // Signature versions
  SigVersion,
  
  // Execution data
  ScriptExecutionData,
  
  // Constants
  WITNESS_V0_SCRIPTHASH_SIZE,
  WITNESS_V0_KEYHASH_SIZE,
  WITNESS_V1_TAPROOT_SIZE,
  TAPROOT_LEAF_MASK,
  TAPROOT_LEAF_TAPSCRIPT,
  TAPROOT_CONTROL_BASE_SIZE,
  TAPROOT_CONTROL_NODE_SIZE,
  TAPROOT_CONTROL_MAX_NODE_COUNT,
  TAPROOT_CONTROL_MAX_SIZE,
  
  // Functions
  EvalScript,
  VerifyScript,
  CountWitnessSigOps,
} from './interpreter';

export type { SignatureChecker } from './interpreter';

// Signing
export type {
  SignOptions,
  BaseSignatureCreator,
  BaseSignatureChecker,
  SigningProvider,
  KeyPair,
  KeyOriginInfo,
  SignatureData,
  TaprootSpendData,
  TaprootBuilder,
} from './sign';

export {
  DataFromTransaction,
  UpdateInput,
  IsSegWitOutput,
  ProduceSignature,
  SignTransaction,
  MutableTransactionSignatureCreator,
  TransactionSignatureChecker,
} from './sign';

// Standard scripts
export {
  ScriptType,
  GetScriptType,
  Solver,
  IsStandard,
  CreateP2PKHScript,
  CreateP2SHScript,
  CreateP2WPKHScript,
  CreateP2WSHScript,
  CreateP2TRScript,
  CreateMultisigScript,
} from './standard';

export type { ScriptSolution } from './standard';
