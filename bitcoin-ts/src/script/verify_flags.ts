// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Script Verification Flags
 * 
 * This module defines flags that control script verification.
 * These flags are used by the script interpreter to determine
 * which script validation rules to enforce.
 */

export const SCRIPT_VERIFY_NONE = 0;

export enum ScriptVerifyFlag {
    /** Evaluate P2SH subscripts (BIP16) */
    P2SH = 1 << 0,
    
    /** Strict encoding of signatures */
    STRICTENC = 1 << 1,
    
    /** Require DER-encoded signatures (BIP62 rule 1) */
    DERSIG = 1 << 2,
    
    /** Require low S values in signatures (BIP62 rule 5) */
    LOW_S = 1 << 3,
    
    /** Verify NULLDUMMY for CHECKMULTISIG (BIP62 rule 7) */
    NULLDUMMY = 1 << 4,
    
    /** Require minimal push in scriptSig (BIP62 rule 2) */
    SIGPUSHONLY = 1 << 5,
    
    /** Require minimal encodings for all push operations (BIP62 rules 3-4) */
    MINIMALDATA = 1 << 6,
    
    /** Discourage NOPs reserved for upgrades */
    DISCOURAGE_UPGRADABLE_NOPS = 1 << 7,
    
    /** Require exactly one stack element remaining, and that it is true */
    CLEANSTACK = 1 << 8,
    
    /** Verify CHECKLOCKTIMEVERIFY */
    CHECKLOCKTIMEVERIFY = 1 << 9,
    
    /** Verify CHECKSEQUENCEVERIFY */
    CHECKSEQUENCEVERIFY = 1 << 10,
    
    /** Segwit script (BIP141) */
    WITNESS = 1 << 11,
    
    /** Taproot (BIP341, BIP342) */
    TAPROOT = 1 << 12,
}

export const script_verify_flags = {
    NONE: SCRIPT_VERIFY_NONE,
    P2SH: ScriptVerifyFlag.P2SH,
    STRICTENC: ScriptVerifyFlag.STRICTENC,
    DERSIG: ScriptVerifyFlag.DERSIG,
    LOW_S: ScriptVerifyFlag.LOW_S,
    NULLDUMMY: ScriptVerifyFlag.NULLDUMMY,
    SIGPUSHONLY: ScriptVerifyFlag.SIGPUSHONLY,
    MINIMALDATA: ScriptVerifyFlag.MINIMALDATA,
    DISCOURAGE_UPGRADABLE_NOPS: ScriptVerifyFlag.DISCOURAGE_UPGRADABLE_NOPS,
    CLEANSTACK: ScriptVerifyFlag.CLEANSTACK,
    CHECKLOCKTIMEVERIFY: ScriptVerifyFlag.CHECKLOCKTIMEVERIFY,
    CHECKSEQUENCEVERIFY: ScriptVerifyFlag.CHECKSEQUENCEVERIFY,
    WITNESS: ScriptVerifyFlag.WITNESS,
    TAPROOT: ScriptVerifyFlag.TAPROOT,
};

export type ScriptVerifyFlags = number;
export type script_verify_flags = number;
