/**
 * Bitcoin Core PSBT (Partially Signed Bitcoin Transaction) Types
 * Ported from src/psbt.h
 * 
 * @module psbt/types
 * 
 * BIP 174: Partially Signed Bitcoin Transaction Format
 */

import { CScript } from '../script/script';
import { KeyOriginInfo, SignatureData } from '../script/sign';

// Import transaction types from primitives
import { COutPoint, CTxIn, CTxOut, CTransaction, Txid, Wtxid } from '../primitives';

// Re-export transaction types for convenience (type-only to avoid TS2308 duplicate export)
export type { COutPoint, CTxIn, CTxOut, CTransaction, Txid, Wtxid };

// PSBT magic bytes: "psbt" + 0xff
export const PSBT_MAGIC_BYTES = new Uint8Array([0x70, 0x73, 0x62, 0x74, 0xff]);

// PSBT separator byte
export const PSBT_SEPARATOR = 0x00;

// Global types
export const PSBT_GLOBAL_UNSIGNED_TX = 0x00;
export const PSBT_GLOBAL_XPUB = 0x01;
export const PSBT_GLOBAL_VERSION = 0xfb;
export const PSBT_GLOBAL_PROPRIETARY = 0xfc;

// Input types
export const PSBT_IN_NON_WITNESS_UTXO = 0x00;
export const PSBT_IN_WITNESS_UTXO = 0x01;
export const PSBT_IN_PARTIAL_SIG = 0x02;
export const PSBT_IN_SIGHASH = 0x03;
export const PSBT_IN_REDEEMSCRIPT = 0x04;
export const PSBT_IN_WITNESSSCRIPT = 0x05;
export const PSBT_IN_BIP32_DERIVATION = 0x06;
export const PSBT_IN_SCRIPTSIG = 0x07;
export const PSBT_IN_SCRIPTWITNESS = 0x08;
export const PSBT_IN_RIPEMD160 = 0x0a;
export const PSBT_IN_SHA256 = 0x0b;
export const PSBT_IN_HASH160 = 0x0c;
export const PSBT_IN_HASH256 = 0x0d;
export const PSBT_IN_TAP_KEY_SIG = 0x13;
export const PSBT_IN_TAP_SCRIPT_SIG = 0x14;
export const PSBT_IN_TAP_LEAF_SCRIPT = 0x15;
export const PSBT_IN_TAP_BIP32_DERIVATION = 0x16;
export const PSBT_IN_TAP_INTERNAL_KEY = 0x17;
export const PSBT_IN_TAP_MERKLE_ROOT = 0x18;
export const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1a;
export const PSBT_IN_MUSIG2_PUB_NONCE = 0x1b;
export const PSBT_IN_MUSIG2_PARTIAL_SIG = 0x1c;
export const PSBT_IN_PROPRIETARY = 0xfc;

// Output types
export const PSBT_OUT_REDEEMSCRIPT = 0x00;
export const PSBT_OUT_WITNESSSCRIPT = 0x01;
export const PSBT_OUT_BIP32_DERIVATION = 0x02;
export const PSBT_OUT_TAP_INTERNAL_KEY = 0x05;
export const PSBT_OUT_TAP_TREE = 0x06;
export const PSBT_OUT_TAP_BIP32_DERIVATION = 0x07;
export const PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = 0x08;
export const PSBT_OUT_PROPRIETARY = 0xfc;

// Maximum PSBT file size (100 MB) - prevents reading indefinitely
export const MAX_FILE_SIZE_PSBT = 100000000;

// PSBT version number
export const PSBT_HIGHEST_VERSION = 0;

/**
 * Extended public key for HD wallet support
 */
export interface CExtPubKey {
    /** Public key */
    pubkey: Uint8Array;
    /** Chain code */
    chain_code: Uint8Array;
    /** Key fingerprint */
    fingerprint: Uint8Array;
    /** Child key derivation path */
    derivation_path: number[];
}

/**
 * PSBT proprietary type
 */
export interface PSBTProprietary {
    subtype: bigint;
    identifier: Uint8Array;
    key: Uint8Array;
    value: Uint8Array;
}

/**
 * Signature pair (pubkey, signature)
 */
export interface SigPair {
    pubkey: Uint8Array;
    signature: Uint8Array;
}

/**
 * Taproot script sig key
 */
export type TapScriptSigKey = [Uint8Array, Uint8Array]; // [xonly_pubkey, leaf_hash]

/**
 * Taproot script
 */
export type TapScript = [Uint8Array, number]; // [script, leaf_version]

/**
 * Taproot BIP32 path entry
 */
export interface TaprootBIP32Path {
    leaf_hashes: Set<Uint8Array>;
    origin: KeyOriginInfo;
}

/**
 * MuSig2 participant pubkeys entry
 */
export interface MuSig2ParticipantPubkeys {
    agg_pubkey: Uint8Array;
    participants: Uint8Array[];
}

/**
 * Taproot tree entry: [depth, leaf_version, script]
 */
export type TaprootTreeEntry = [number, number, Uint8Array];

/**
 * PSBTInput - Per-input information for a PSBT
 */
export interface PSBTInput {
    /** Previous non-witness transaction output */
    non_witness_utxo: CTransaction | null;
    /** Previous witness transaction output (for SegWit) */
    witness_utxo: CTxOut | null;
    /** Redeem script for P2SH inputs */
    redeem_script: CScript;
    /** Witness script for P2WSH/P2TR inputs */
    witness_script: CScript;
    /** Finalized scriptSig */
    final_script_sig: CScript;
    /** Finalized scriptWitness */
    final_script_witness: CTxOutWitness;
    /** BIP32 key derivation paths */
    hd_keypaths: Map<string, KeyOriginInfo>; // key_id -> key_origin
    /** Partial signatures */
    partial_sigs: Map<string, SigPair>; // key_id -> [pubkey, sig]
    /** RIPEMD160 preimages for hash locks */
    ripemd160_preimages: Map<string, Uint8Array>; // hash -> preimage
    /** SHA256 preimages for hash locks */
    sha256_preimages: Map<string, Uint8Array>; // hash -> preimage
    /** Hash160 preimages for hash locks */
    hash160_preimages: Map<string, Uint8Array>; // hash -> preimage
    /** Hash256 preimages for hash locks */
    hash256_preimages: Map<string, Uint8Array>; // hash -> preimage
    /** Taproot key path signature (schnorr signature) */
    tap_key_sig: Uint8Array;
    /** Taproot script path signatures */
    tap_script_sigs: Map<string, Uint8Array>; // [xonly_pubkey, leaf_hash] -> sig
    /** Taproot leaf scripts with control blocks */
    tap_scripts: Map<string, Set<Uint8Array>>; // [script, leaf_ver] -> Set<control_block>
    /** Taproot BIP32 keypaths */
    tap_bip32_paths: Map<string, TaprootBIP32Path>; // xonly_pubkey -> {leaf_hashes, origin}
    /** Taproot internal key */
    tap_internal_key: Uint8Array;
    /** Taproot merkle root */
    tap_merkle_root: Uint8Array;
    /** MuSig2 participants */
    musig2_participants: Map<string, Uint8Array[]>; // agg_pubkey -> [participant_pubkeys]
    /** MuSig2 pubnonces */
    musig2_pubnonces: Map<string, Map<string, Uint8Array>>; // [agg_pubkey, leaf_hash] -> Map<part_pubkey, nonce>
    /** MuSig2 partial signatures */
    musig2_partial_sigs: Map<string, Map<string, Uint8Array>>; // [agg_pubkey, leaf_hash] -> Map<part_pubkey, partial_sig>
    /** Unknown proprietary key-value pairs */
    unknown: Map<string, Uint8Array>;
    /** Proprietary key-value pairs */
    proprietary: Set<PSBTProprietary>;
    /** Sighash type for this input */
    sighash_type: number | null;
}

/**
 * PSBTOutput - Per-output information for a PSBT
 */
export interface PSBTOutput {
    /** Redeem script */
    redeem_script: CScript;
    /** Witness script */
    witness_script: CScript;
    /** BIP32 key derivation paths */
    hd_keypaths: Map<string, KeyOriginInfo>; // key_id -> key_origin
    /** Taproot internal key */
    tap_internal_key: Uint8Array;
    /** Taproot tree structure */
    tap_tree: TaprootTreeEntry[];
    /** Taproot BIP32 keypaths */
    tap_bip32_paths: Map<string, TaprootBIP32Path>; // xonly_pubkey -> {leaf_hashes, origin}
    /** MuSig2 participants */
    musig2_participants: Map<string, Uint8Array[]>; // agg_pubkey -> [participant_pubkeys]
    /** Unknown proprietary key-value pairs */
    unknown: Map<string, Uint8Array>;
    /** Proprietary key-value pairs */
    proprietary: Set<PSBTProprietary>;
}

/**
 * Transaction output witness
 */
export interface CTxOutWitness {
    stack: Uint8Array[];
}

/**
 * Mutable transaction (can be modified) - extends CTransaction with mutability
 */
export interface CMutableTransaction {
    version: number;
    vin: CTxIn[];
    vout: CTxOut[];
    nLockTime: number;
}

/**
 * Partially Signed Bitcoin Transaction
 */
export interface PartiallySignedTransaction {
    /** The underlying transaction */
    tx: CMutableTransaction | null;
    /** Extended public keys with key origins (key is keypath, value is set of xpubs) */
    m_xpubs: Map<string, Set<CExtPubKey>>;
    /** Per-input data */
    inputs: PSBTInput[];
    /** Per-output data */
    outputs: PSBTOutput[];
    /** Unknown key-value pairs */
    unknown: Map<string, Uint8Array>;
    /** PSBT version */
    m_version: number | null;
    /** Proprietary key-value pairs */
    proprietary: Set<PSBTProprietary>;
}

/**
 * PSBTError types
 */
export enum PSBTError {
    UNKNOWN = 0,
    MISSING_INPUT,
    MISSING_OUTPUT,
    MISSING_SIGHASH,
    INVALID_SIGHASH,
    NOT_ENOUGH_WEIGHT,
    PSBT_MISMATCH,
    INVALID_TXFEE,
    BROADCAST_FAILED,
    FINAL_INPUT_ALREADY_SET,
    PSBT_UNSUPPORTED,
}

/**
 * PSBT error string conversion
 */
export function psbtErrorString(error: PSBTError): string {
    switch (error) {
        case PSBTError.UNKNOWN: return "Unknown error";
        case PSBTError.MISSING_INPUT: return "Missing input";
        case PSBTError.MISSING_OUTPUT: return "Missing output";
        case PSBTError.MISSING_SIGHASH: return "Missing sighash";
        case PSBTError.INVALID_SIGHASH: return "Invalid sighash";
        case PSBTError.NOT_ENOUGH_WEIGHT: return "Not enough weight";
        case PSBTError.PSBT_MISMATCH: return "PSBT mismatch";
        case PSBTError.INVALID_TXFEE: return "Invalid transaction fee";
        case PSBTError.BROADCAST_FAILED: return "Broadcast failed";
        case PSBTError.FINAL_INPUT_ALREADY_SET: return "Final input already set";
        case PSBTError.PSBT_UNSUPPORTED: return "PSBT unsupported";
        default: return "Unknown error";
    }
}

/**
 * PSBT roles for signing workflow
 */
export enum PSBTRole {
    CREATOR,
    UPDATER,
    SIGNER,
    FINALIZER,
    EXTRACTOR,
}

/**
 * Get human-readable name for PSBT role
 */
export function psbtRoleName(role: PSBTRole): string {
    switch (role) {
        case PSBTRole.CREATOR: return "Creator";
        case PSBTRole.UPDATER: return "Updater";
        case PSBTRole.SIGNER: return "Signer";
        case PSBTRole.FINALIZER: return "Finalizer";
        case PSBTRole.EXTRACTOR: return "Extractor";
        default: return "Unknown";
    }
}

/**
 * Create a new empty PSBTInput
 */
export function createPSBTInput(): PSBTInput {
    return {
        non_witness_utxo: null,
        witness_utxo: null,
        redeem_script: new CScript(),
        witness_script: new CScript(),
        final_script_sig: new CScript(),
        final_script_witness: { stack: [] },
        hd_keypaths: new Map(),
        partial_sigs: new Map(),
        ripemd160_preimages: new Map(),
        sha256_preimages: new Map(),
        hash160_preimages: new Map(),
        hash256_preimages: new Map(),
        tap_key_sig: new Uint8Array(0),
        tap_script_sigs: new Map(),
        tap_scripts: new Map(),
        tap_bip32_paths: new Map(),
        tap_internal_key: new Uint8Array(0),
        tap_merkle_root: new Uint8Array(0),
        musig2_participants: new Map(),
        musig2_pubnonces: new Map(),
        musig2_partial_sigs: new Map(),
        unknown: new Map(),
        proprietary: new Set(),
        sighash_type: null,
    };
}

/**
 * Create a new empty PSBTOutput
 */
export function createPSBTOutput(): PSBTOutput {
    return {
        redeem_script: new CScript(),
        witness_script: new CScript(),
        hd_keypaths: new Map(),
        tap_internal_key: new Uint8Array(0),
        tap_tree: [],
        tap_bip32_paths: new Map(),
        musig2_participants: new Map(),
        unknown: new Map(),
        proprietary: new Set(),
    };
}

/**
 * Check if PSBTInput is empty/null
 */
export function psbtInputIsNull(input: PSBTInput): boolean {
    return (
        input.non_witness_utxo === null &&
        input.witness_utxo === null &&
        input.redeem_script.length() === 0 &&
        input.witness_script.length() === 0 &&
        input.final_script_sig.length() === 0 &&
        input.final_script_witness.stack.length === 0 &&
        input.hd_keypaths.size === 0 &&
        input.partial_sigs.size === 0 &&
        input.ripemd160_preimages.size === 0 &&
        input.sha256_preimages.size === 0 &&
        input.hash160_preimages.size === 0 &&
        input.hash256_preimages.size === 0 &&
        input.tap_key_sig.length === 0 &&
        input.tap_script_sigs.size === 0 &&
        input.tap_scripts.size === 0 &&
        input.tap_bip32_paths.size === 0 &&
        input.tap_internal_key.length === 0 &&
        input.tap_merkle_root.length === 0 &&
        input.musig2_participants.size === 0 &&
        input.musig2_pubnonces.size === 0 &&
        input.musig2_partial_sigs.size === 0 &&
        input.unknown.size === 0 &&
        input.proprietary.size === 0 &&
        input.sighash_type === null
    );
}

/**
 * Check if PSBTOutput is empty/null
 */
export function psbtOutputIsNull(output: PSBTOutput): boolean {
    return (
        output.redeem_script.length() === 0 &&
        output.witness_script.length() === 0 &&
        output.hd_keypaths.size === 0 &&
        output.tap_internal_key.length === 0 &&
        output.tap_tree.length === 0 &&
        output.tap_bip32_paths.size === 0 &&
        output.musig2_participants.size === 0 &&
        output.unknown.size === 0 &&
        output.proprietary.size === 0
    );
}

/**
 * Check if PSBT is null (has no transaction)
 */
export function psbtIsNull(psbt: PartiallySignedTransaction): boolean {
    return psbt.tx === null;
}

/**
 * Get PSBT version
 */
export function psbtGetVersion(psbt: PartiallySignedTransaction): number {
    return psbt.m_version ?? 0;
}

/**
 * Create a PSBT from a transaction
 */
export function createPSBT(tx: CMutableTransaction): PartiallySignedTransaction {
    const psbt: PartiallySignedTransaction = {
        tx: tx,
        m_xpubs: new Map(),
        inputs: [],
        outputs: [],
        unknown: new Map(),
        m_version: null,
        proprietary: new Set(),
    };
    
    // Initialize inputs
    for (let i = 0; i < tx.vin.length; i++) {
        psbt.inputs.push(createPSBTInput());
    }
    
    // Initialize outputs
    for (let i = 0; i < tx.vout.length; i++) {
        psbt.outputs.push(createPSBTOutput());
    }
    
    return psbt;
}

/**
 * Check if PSBTInput has any signatures (finalized)
 */
export function psbtInputSigned(input: PSBTInput): boolean {
    return (
        input.final_script_sig.length() > 0 ||
        input.final_script_witness.stack.length > 0
    );
}

/**
 * Fill signature data from PSBTInput
 */
export function psbtInputFillSignatureData(input: PSBTInput, sigdata: SignatureData): void {
    // Transfer partial signatures
    for (const [keyId, pair] of input.partial_sigs) {
        sigdata.signatures.set(keyId, { pubkey: pair.pubkey, sig: pair.signature });
    }
    
    // Transfer taproot key path signature
    if (input.tap_key_sig.length > 0) {
        sigdata.taproot_key_path_sig = input.tap_key_sig;
    }
    
    // Transfer taproot script signatures
    for (const [key, sig] of input.tap_script_sigs) {
        sigdata.taproot_script_sigs.set(key, sig);
    }
    
    // Transfer redeem/witness scripts
    if (input.redeem_script.length() > 0) {
        sigdata.redeem_script = input.redeem_script;
    }
    if (input.witness_script.length() > 0) {
        sigdata.witness_script = input.witness_script;
    }
    
    // Transfer script witness
    if (input.final_script_witness.stack.length > 0) {
        sigdata.scriptWitness = input.final_script_witness.stack;
        sigdata.witness = true;
    }
    
    // Set complete if fully signed
    if (input.final_script_sig.length() > 0 || input.final_script_witness.stack.length > 0) {
        sigdata.complete = true;
    }
}

/**
 * Merge PSBTInput into another PSBTInput
 */
export function psbtInputMerge(dest: PSBTInput, source: PSBTInput): void {
    // Merge non_witness_utxo
    if (dest.non_witness_utxo === null && source.non_witness_utxo !== null) {
        dest.non_witness_utxo = source.non_witness_utxo;
    }
    
    // Merge witness_utxo
    if (dest.witness_utxo === null && source.witness_utxo !== null) {
        dest.witness_utxo = source.witness_utxo;
    }
    
    // Merge partial signatures
    for (const [keyId, pair] of source.partial_sigs) {
        if (!dest.partial_sigs.has(keyId)) {
            dest.partial_sigs.set(keyId, pair);
        }
    }
    
    // Merge sighash type
    if (dest.sighash_type === null && source.sighash_type !== null) {
        dest.sighash_type = source.sighash_type;
    }
    
    // Merge redeem script
    if (dest.redeem_script.length() === 0 && source.redeem_script.length() > 0) {
        dest.redeem_script = source.redeem_script;
    }
    
    // Merge witness script
    if (dest.witness_script.length() === 0 && source.witness_script.length() > 0) {
        dest.witness_script = source.witness_script;
    }
    
    // Merge HD keypaths
    for (const [keyId, origin] of source.hd_keypaths) {
        if (!dest.hd_keypaths.has(keyId)) {
            dest.hd_keypaths.set(keyId, origin);
        }
    }
    
    // Merge preimages
    for (const [hash, preimage] of source.ripemd160_preimages) {
        if (!dest.ripemd160_preimages.has(hash)) {
            dest.ripemd160_preimages.set(hash, preimage);
        }
    }
    for (const [hash, preimage] of source.sha256_preimages) {
        if (!dest.sha256_preimages.has(hash)) {
            dest.sha256_preimages.set(hash, preimage);
        }
    }
    for (const [hash, preimage] of source.hash160_preimages) {
        if (!dest.hash160_preimages.has(hash)) {
            dest.hash160_preimages.set(hash, preimage);
        }
    }
    for (const [hash, preimage] of source.hash256_preimages) {
        if (!dest.hash256_preimages.has(hash)) {
            dest.hash256_preimages.set(hash, preimage);
        }
    }
    
    // Merge taproot fields
    if (dest.tap_key_sig.length === 0 && source.tap_key_sig.length > 0) {
        dest.tap_key_sig = source.tap_key_sig;
    }
    
    for (const [key, sig] of source.tap_script_sigs) {
        if (!dest.tap_script_sigs.has(key)) {
            dest.tap_script_sigs.set(key, sig);
        }
    }
    
    for (const [key, blocks] of source.tap_scripts) {
        if (!dest.tap_scripts.has(key)) {
            dest.tap_scripts.set(key, new Set(blocks));
        }
    }
    
    for (const [key, path] of source.tap_bip32_paths) {
        if (!dest.tap_bip32_paths.has(key)) {
            dest.tap_bip32_paths.set(key, path);
        }
    }
    
    if (dest.tap_internal_key.length === 0 && source.tap_internal_key.length > 0) {
        dest.tap_internal_key = source.tap_internal_key;
    }
    
    if (dest.tap_merkle_root.length === 0 && source.tap_merkle_root.length > 0) {
        dest.tap_merkle_root = source.tap_merkle_root;
    }
    
    // Merge MuSig2 fields
    for (const [key, participants] of source.musig2_participants) {
        if (!dest.musig2_participants.has(key)) {
            dest.musig2_participants.set(key, participants);
        }
    }
    
    for (const [key, nonces] of source.musig2_pubnonces) {
        if (!dest.musig2_pubnonces.has(key)) {
            dest.musig2_pubnonces.set(key, new Map(nonces));
        }
    }
    
    for (const [key, sigs] of source.musig2_partial_sigs) {
        if (!dest.musig2_partial_sigs.has(key)) {
            dest.musig2_partial_sigs.set(key, new Map(sigs));
        }
    }
    
    // Merge unknown
    for (const [key, value] of source.unknown) {
        if (!dest.unknown.has(key)) {
            dest.unknown.set(key, value);
        }
    }
}

/**
 * Merge PSBTOutput into another PSBTOutput
 */
export function psbtOutputMerge(dest: PSBTOutput, source: PSBTOutput): void {
    // Merge redeem script
    if (dest.redeem_script.length() === 0 && source.redeem_script.length() > 0) {
        dest.redeem_script = source.redeem_script;
    }
    
    // Merge witness script
    if (dest.witness_script.length() === 0 && source.witness_script.length() > 0) {
        dest.witness_script = source.witness_script;
    }
    
    // Merge HD keypaths
    for (const [keyId, origin] of source.hd_keypaths) {
        if (!dest.hd_keypaths.has(keyId)) {
            dest.hd_keypaths.set(keyId, origin);
        }
    }
    
    // Merge taproot fields
    if (dest.tap_internal_key.length === 0 && source.tap_internal_key.length > 0) {
        dest.tap_internal_key = source.tap_internal_key;
    }
    
    if (dest.tap_tree.length === 0 && source.tap_tree.length > 0) {
        dest.tap_tree = source.tap_tree;
    }
    
    for (const [key, path] of source.tap_bip32_paths) {
        if (!dest.tap_bip32_paths.has(key)) {
            dest.tap_bip32_paths.set(key, path);
        }
    }
    
    // Merge MuSig2 participants
    for (const [key, participants] of source.musig2_participants) {
        if (!dest.musig2_participants.has(key)) {
            dest.musig2_participants.set(key, participants);
        }
    }
    
    // Merge unknown
    for (const [key, value] of source.unknown) {
        if (!dest.unknown.has(key)) {
            dest.unknown.set(key, value);
        }
    }
}

/**
 * Count unsigned inputs in a PSBT
 */
export function countPSBTUnsignedInputs(psbt: PartiallySignedTransaction): number {
    let count = 0;
    for (const input of psbt.inputs) {
        if (!psbtInputSigned(input)) {
            count++;
        }
    }
    return count;
}

/**
 * Get UTXO for a given input index
 */
export function psbtGetInputUTXO(psbt: PartiallySignedTransaction, input_index: number): CTxOut | null {
    if (!psbt.tx || input_index >= psbt.inputs.length) {
        return null;
    }
    
    const input = psbt.inputs[input_index];
    
    // Check witness_utxo first (preferred)
    if (input.witness_utxo !== null) {
        return input.witness_utxo;
    }
    
    // Fall back to non_witness_utxo
    if (input.non_witness_utxo !== null) {
        const tx = input.non_witness_utxo;
        const prevout = psbt.tx.vin[input_index].prevout;
        if (prevout.n < tx.vout.length) {
            return tx.vout[prevout.n];
        }
    }
    
    return null;
}
