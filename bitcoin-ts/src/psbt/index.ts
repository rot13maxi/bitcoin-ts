/**
 * Bitcoin Core PSBT (Partially Signed Bitcoin Transaction) Module
 * Ported from src/psbt.h/cpp
 * 
 * BIP 174: Partially Signed Bitcoin Transaction Format
 * 
 * @module psbt
 */

// PSBT constants
export {
    PSBT_MAGIC_BYTES,
    PSBT_SEPARATOR,
    MAX_FILE_SIZE_PSBT,
    PSBT_HIGHEST_VERSION,
    
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_GLOBAL_XPUB,
    PSBT_GLOBAL_VERSION,
    PSBT_GLOBAL_PROPRIETARY,
    
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_WITNESS_UTXO,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_SIGHASH,
    PSBT_IN_REDEEMSCRIPT,
    PSBT_IN_WITNESSSCRIPT,
    PSBT_IN_BIP32_DERIVATION,
    PSBT_IN_SCRIPTSIG,
    PSBT_IN_SCRIPTWITNESS,
    PSBT_IN_RIPEMD160,
    PSBT_IN_SHA256,
    PSBT_IN_HASH160,
    PSBT_IN_HASH256,
    PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_TAP_SCRIPT_SIG,
    PSBT_IN_TAP_LEAF_SCRIPT,
    PSBT_IN_TAP_BIP32_DERIVATION,
    PSBT_IN_TAP_INTERNAL_KEY,
    PSBT_IN_TAP_MERKLE_ROOT,
    PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
    PSBT_IN_MUSIG2_PUB_NONCE,
    PSBT_IN_MUSIG2_PARTIAL_SIG,
    PSBT_IN_PROPRIETARY,
    
    PSBT_OUT_REDEEMSCRIPT,
    PSBT_OUT_WITNESSSCRIPT,
    PSBT_OUT_BIP32_DERIVATION,
    PSBT_OUT_TAP_INTERNAL_KEY,
    PSBT_OUT_TAP_TREE,
    PSBT_OUT_TAP_BIP32_DERIVATION,
    PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS,
    PSBT_OUT_PROPRIETARY,
} from './types';

// PSBT types (excluding duplicates from primitives)
export type {
    CExtPubKey,
    PSBTProprietary,
    SigPair,
    TapScriptSigKey,
    TapScript,
    TaprootBIP32Path,
    MuSig2ParticipantPubkeys,
    TaprootTreeEntry,
    PSBTInput,
    PSBTOutput,
    CTxOutWitness,
    CMutableTransaction,
    PartiallySignedTransaction,
} from './types';

export {
    PSBTError,
    PSBTRole,
    psbtErrorString,
    psbtRoleName,
    createPSBTInput,
    createPSBTOutput,
    psbtInputIsNull,
    psbtOutputIsNull,
    psbtIsNull,
    psbtGetVersion,
    createPSBT,
    psbtInputSigned,
    psbtInputFillSignatureData,
    psbtInputMerge,
    psbtOutputMerge,
    countPSBTUnsignedInputs,
    psbtGetInputUTXO,
} from './types';

// PSBT serialization
export {
    serializeToVector,
    serializeKeyOrigin,
    deserializeKeyOrigin,
    serializeHDKeypath,
    serializePSBTInput,
    serializePSBTOutput,
    serializePSBT,
    checkPSBTMagic,
    decodeBase64PSBT,
    decodeRawPSBT,
    encodeBase64PSBT,
} from './serialize';
