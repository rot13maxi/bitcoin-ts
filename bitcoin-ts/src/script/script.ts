/**
 * Bitcoin Core Script - Script opcodes, CScript, and CScriptNum
 * Ported from src/script/script.h/cpp
 * 
 * @module script/script
 */

// Maximum number of bytes pushable to the stack
export const MAX_SCRIPT_ELEMENT_SIZE = 520;

// Maximum number of non-push operations per script
export const MAX_OPS_PER_SCRIPT = 201;

// Maximum number of public keys per multisig
export const MAX_PUBKEYS_PER_MULTISIG = 20;

// Maximum number of keys in OP_CHECKSIGADD-based scripts (BIP342)
export const MAX_PUBKEYS_PER_MULTI_A = 999;

// Maximum script length in bytes
export const MAX_SCRIPT_SIZE = 10000;

// Maximum number of values on script interpreter stack
export const MAX_STACK_SIZE = 1000;

// Threshold for nLockTime: below this value it is interpreted as block number,
// otherwise as UNIX timestamp
export const LOCKTIME_THRESHOLD = 500000000;

// Maximum nLockTime
export const LOCKTIME_MAX = 0xffffffff;

// Tag for input annex
export const ANNEX_TAG = 0x50;

// Validation weight per passing signature (Tapscript only, BIP 342)
export const VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50;

// Weight budget added to witness size (Tapscript only, BIP 342)
export const VALIDATION_WEIGHT_OFFSET = 50;

/**
 * Script opcodes
 */
export enum Opcode {
  // push value
  OP_0 = 0x00,
  OP_FALSE = 0x00,
  OP_PUSHDATA1 = 0x4c,
  OP_PUSHDATA2 = 0x4d,
  OP_PUSHDATA4 = 0x4e,
  OP_1NEGATE = 0x4f,
  OP_RESERVED = 0x50,
  OP_1 = 0x51,
  OP_TRUE = 0x51,
  OP_2 = 0x52,
  OP_3 = 0x53,
  OP_4 = 0x54,
  OP_5 = 0x55,
  OP_6 = 0x56,
  OP_7 = 0x57,
  OP_8 = 0x58,
  OP_9 = 0x59,
  OP_10 = 0x5a,
  OP_11 = 0x5b,
  OP_12 = 0x5c,
  OP_13 = 0x5d,
  OP_14 = 0x5e,
  OP_15 = 0x5f,
  OP_16 = 0x60,

  // control
  OP_NOP = 0x61,
  OP_VER = 0x62,
  OP_IF = 0x63,
  OP_NOTIF = 0x64,
  OP_VERIF = 0x65,
  OP_VERNOTIF = 0x66,
  OP_ELSE = 0x67,
  OP_ENDIF = 0x68,
  OP_VERIFY = 0x69,
  OP_RETURN = 0x6a,

  // stack ops
  OP_TOALTSTACK = 0x6b,
  OP_FROMALTSTACK = 0x6c,
  OP_2DROP = 0x6d,
  OP_2DUP = 0x6e,
  OP_3DUP = 0x6f,
  OP_2OVER = 0x70,
  OP_2ROT = 0x71,
  OP_2SWAP = 0x72,
  OP_IFDUP = 0x73,
  OP_DEPTH = 0x74,
  OP_DROP = 0x75,
  OP_DUP = 0x76,
  OP_NIP = 0x77,
  OP_OVER = 0x78,
  OP_PICK = 0x79,
  OP_ROLL = 0x7a,
  OP_ROT = 0x7b,
  OP_SWAP = 0x7c,
  OP_TUCK = 0x7d,

  // splice ops
  OP_CAT = 0x7e,
  OP_SUBSTR = 0x7f,
  OP_LEFT = 0x80,
  OP_RIGHT = 0x81,
  OP_SIZE = 0x82,

  // bit logic
  OP_INVERT = 0x83,
  OP_AND = 0x84,
  OP_OR = 0x85,
  OP_XOR = 0x86,
  OP_EQUAL = 0x87,
  OP_EQUALVERIFY = 0x88,
  OP_RESERVED1 = 0x89,
  OP_RESERVED2 = 0x8a,

  // numeric
  OP_1ADD = 0x8b,
  OP_1SUB = 0x8c,
  OP_2MUL = 0x8d,
  OP_2DIV = 0x8e,
  OP_NEGATE = 0x8f,
  OP_ABS = 0x90,
  OP_NOT = 0x91,
  OP_0NOTEQUAL = 0x92,

  OP_ADD = 0x93,
  OP_SUB = 0x94,
  OP_MUL = 0x95,
  OP_DIV = 0x96,
  OP_MOD = 0x97,
  OP_LSHIFT = 0x98,
  OP_RSHIFT = 0x99,

  OP_BOOLAND = 0x9a,
  OP_NUMEQUAL = 0x9c,
  OP_NUMEQUALVERIFY = 0x9d,
  OP_NUMNOTEQUAL = 0x9e,
  OP_LESSTHAN = 0x9f,
  OP_GREATERTHAN = 0xa0,
  OP_LESSTHANOREQUAL = 0xa1,
  OP_GREATERTHANOREQUAL = 0xa2,
  OP_MIN = 0xa3,
  OP_MAX = 0xa4,

  OP_WITHIN = 0xa5,

  // crypto
  OP_RIPEMD160 = 0xa6,
  OP_SHA1 = 0xa7,
  OP_SHA256 = 0xa8,
  OP_HASH160 = 0xa9,
  OP_HASH256 = 0xaa,
  OP_CODESEPARATOR = 0xab,
  OP_CHECKSIG = 0xac,
  OP_CHECKSIGVERIFY = 0xad,
  OP_CHECKMULTISIG = 0xae,
  OP_CHECKMULTISIGVERIFY = 0xaf,

  // expansion
  OP_NOP1 = 0xb0,
  OP_CHECKLOCKTIMEVERIFY = 0xb1,
  OP_NOP2 = 0xb1,
  OP_CHECKSEQUENCEVERIFY = 0xb2,
  OP_NOP3 = 0xb2,
  OP_NOP4 = 0xb3,
  OP_NOP5 = 0xb4,
  OP_NOP6 = 0xb5,
  OP_NOP7 = 0xb6,
  OP_NOP8 = 0xb7,
  OP_NOP9 = 0xb8,
  OP_NOP10 = 0xb9,

  // Taproot (BIP 342)
  OP_CHECKSIGADD = 0xba,

  OP_INVALIDOPCODE = 0xff,
}

// Maximum value that an opcode can be
export const MAX_OPCODE = Opcode.OP_NOP10;

/**
 * Get the name of an opcode
 */
export function GetOpName(opcode: Opcode): string {
  switch (opcode) {
    case Opcode.OP_0: return "OP_0";
    case Opcode.OP_PUSHDATA1: return "OP_PUSHDATA1";
    case Opcode.OP_PUSHDATA2: return "OP_PUSHDATA2";
    case Opcode.OP_PUSHDATA4: return "OP_PUSHDATA4";
    case Opcode.OP_1NEGATE: return "OP_1NEGATE";
    case Opcode.OP_RESERVED: return "OP_RESERVED";
    case Opcode.OP_1: return "OP_1";
    case Opcode.OP_2: return "OP_2";
    case Opcode.OP_3: return "OP_3";
    case Opcode.OP_4: return "OP_4";
    case Opcode.OP_5: return "OP_5";
    case Opcode.OP_6: return "OP_6";
    case Opcode.OP_7: return "OP_7";
    case Opcode.OP_8: return "OP_8";
    case Opcode.OP_9: return "OP_9";
    case Opcode.OP_10: return "OP_10";
    case Opcode.OP_11: return "OP_11";
    case Opcode.OP_12: return "OP_12";
    case Opcode.OP_13: return "OP_13";
    case Opcode.OP_14: return "OP_14";
    case Opcode.OP_15: return "OP_15";
    case Opcode.OP_16: return "OP_16";
    case Opcode.OP_NOP: return "OP_NOP";
    case Opcode.OP_VER: return "OP_VER";
    case Opcode.OP_IF: return "OP_IF";
    case Opcode.OP_NOTIF: return "OP_NOTIF";
    case Opcode.OP_VERIF: return "OP_VERIF";
    case Opcode.OP_VERNOTIF: return "OP_VERNOTIF";
    case Opcode.OP_ELSE: return "OP_ELSE";
    case Opcode.OP_ENDIF: return "OP_ENDIF";
    case Opcode.OP_VERIFY: return "OP_VERIFY";
    case Opcode.OP_RETURN: return "OP_RETURN";
    case Opcode.OP_TOALTSTACK: return "OP_TOALTSTACK";
    case Opcode.OP_FROMALTSTACK: return "OP_FROMALTSTACK";
    case Opcode.OP_2DROP: return "OP_2DROP";
    case Opcode.OP_2DUP: return "OP_2DUP";
    case Opcode.OP_3DUP: return "OP_3DUP";
    case Opcode.OP_2OVER: return "OP_2OVER";
    case Opcode.OP_2ROT: return "OP_2ROT";
    case Opcode.OP_2SWAP: return "OP_2SWAP";
    case Opcode.OP_IFDUP: return "OP_IFDUP";
    case Opcode.OP_DEPTH: return "OP_DEPTH";
    case Opcode.OP_DROP: return "OP_DROP";
    case Opcode.OP_DUP: return "OP_DUP";
    case Opcode.OP_NIP: return "OP_NIP";
    case Opcode.OP_OVER: return "OP_OVER";
    case Opcode.OP_PICK: return "OP_PICK";
    case Opcode.OP_ROLL: return "OP_ROLL";
    case Opcode.OP_ROT: return "OP_ROT";
    case Opcode.OP_SWAP: return "OP_SWAP";
    case Opcode.OP_TUCK: return "OP_TUCK";
    case Opcode.OP_CAT: return "OP_CAT";
    case Opcode.OP_SUBSTR: return "OP_SUBSTR";
    case Opcode.OP_LEFT: return "OP_LEFT";
    case Opcode.OP_RIGHT: return "OP_RIGHT";
    case Opcode.OP_SIZE: return "OP_SIZE";
    case Opcode.OP_INVERT: return "OP_INVERT";
    case Opcode.OP_AND: return "OP_AND";
    case Opcode.OP_OR: return "OP_OR";
    case Opcode.OP_XOR: return "OP_XOR";
    case Opcode.OP_EQUAL: return "OP_EQUAL";
    case Opcode.OP_EQUALVERIFY: return "OP_EQUALVERIFY";
    case Opcode.OP_RESERVED1: return "OP_RESERVED1";
    case Opcode.OP_RESERVED2: return "OP_RESERVED2";
    case Opcode.OP_1ADD: return "OP_1ADD";
    case Opcode.OP_1SUB: return "OP_1SUB";
    case Opcode.OP_2MUL: return "OP_2MUL";
    case Opcode.OP_2DIV: return "OP_2DIV";
    case Opcode.OP_NEGATE: return "OP_NEGATE";
    case Opcode.OP_ABS: return "OP_ABS";
    case Opcode.OP_NOT: return "OP_NOT";
    case Opcode.OP_0NOTEQUAL: return "OP_0NOTEQUAL";
    case Opcode.OP_ADD: return "OP_ADD";
    case Opcode.OP_SUB: return "OP_SUB";
    case Opcode.OP_MUL: return "OP_MUL";
    case Opcode.OP_DIV: return "OP_DIV";
    case Opcode.OP_MOD: return "OP_MOD";
    case Opcode.OP_LSHIFT: return "OP_LSHIFT";
    case Opcode.OP_RSHIFT: return "OP_RSHIFT";
    case Opcode.OP_BOOLAND: return "OP_BOOLAND";
    case Opcode.OP_NUMEQUAL: return "OP_NUMEQUAL";
    case Opcode.OP_NUMEQUALVERIFY: return "OP_NUMEQUALVERIFY";
    case Opcode.OP_NUMNOTEQUAL: return "OP_NUMNOTEQUAL";
    case Opcode.OP_LESSTHAN: return "OP_LESSTHAN";
    case Opcode.OP_GREATERTHAN: return "OP_GREATERTHAN";
    case Opcode.OP_LESSTHANOREQUAL: return "OP_LESSTHANOREQUAL";
    case Opcode.OP_GREATERTHANOREQUAL: return "OP_GREATERTHANOREQUAL";
    case Opcode.OP_MIN: return "OP_MIN";
    case Opcode.OP_MAX: return "OP_MAX";
    case Opcode.OP_WITHIN: return "OP_WITHIN";
    case Opcode.OP_RIPEMD160: return "OP_RIPEMD160";
    case Opcode.OP_SHA1: return "OP_SHA1";
    case Opcode.OP_SHA256: return "OP_SHA256";
    case Opcode.OP_HASH160: return "OP_HASH160";
    case Opcode.OP_HASH256: return "OP_HASH256";
    case Opcode.OP_CODESEPARATOR: return "OP_CODESEPARATOR";
    case Opcode.OP_CHECKSIG: return "OP_CHECKSIG";
    case Opcode.OP_CHECKSIGVERIFY: return "OP_CHECKSIGVERIFY";
    case Opcode.OP_CHECKMULTISIG: return "OP_CHECKMULTISIG";
    case Opcode.OP_CHECKMULTISIGVERIFY: return "OP_CHECKMULTISIGVERIFY";
    case Opcode.OP_NOP1: return "OP_NOP1";
    case Opcode.OP_CHECKLOCKTIMEVERIFY: return "OP_CHECKLOCKTIMEVERIFY";
    case Opcode.OP_CHECKSEQUENCEVERIFY: return "OP_CHECKSEQUENCEVERIFY";
    case Opcode.OP_NOP4: return "OP_NOP4";
    case Opcode.OP_NOP5: return "OP_NOP5";
    case Opcode.OP_NOP6: return "OP_NOP6";
    case Opcode.OP_NOP7: return "OP_NOP7";
    case Opcode.OP_NOP8: return "OP_NOP8";
    case Opcode.OP_NOP9: return "OP_NOP9";
    case Opcode.OP_NOP10: return "OP_NOP10";
    case Opcode.OP_CHECKSIGADD: return "OP_CHECKSIGADD";
    default: return `OP_UNKNOWN (0x${opcode.toString(16).padStart(2, '0')})`;
  }
}

/**
 * Error class for script number errors
 */
export class ScriptNumError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScriptNumError';
  }
}

/**
 * CScriptNum - Script numeric type with Bitcoin-specific semantics
 * 
 * Numeric opcodes (OP_1ADD, etc) are restricted to operating on 4-byte integers.
 * The semantics are subtle: operands must be in the range [-2^31+1...2^31-1],
 * but results may overflow (and are valid as long as they are not used in a
 * subsequent numeric operation).
 */
export class CScriptNum {
  private value: bigint;
  static readonly nDefaultMaxNumSize = 4;

  constructor(value: number | bigint) {
    this.value = BigInt(value);
  }

  /**
   * Create from byte vector with optional minimal encoding requirement
   */
  static fromBytes(vch: Uint8Array, requireMinimal: boolean = false, nMaxNumSize: number = CScriptNum.nDefaultMaxNumSize): CScriptNum {
    if (vch.length > nMaxNumSize) {
      throw new ScriptNumError('script number overflow');
    }

    if (requireMinimal && vch.length > 0) {
      // Check minimal encoding
      if ((vch[vch.length - 1] & 0x7f) === 0) {
        // Check that there are not extra leading zeros
        if (vch.length <= 1 || (vch[vch.length - 2] & 0x80) === 0) {
          throw new ScriptNumError('non-minimally encoded script number');
        }
      }
    }

    return CScriptNum.fromVector(vch);
  }

  /**
   * Create from byte vector
   */
  static fromVector(vch: Uint8Array): CScriptNum {
    if (vch.length === 0) {
      return new CScriptNum(0);
    }

    let result = 0n;
    let isNegative = false;

    if (vch[vch.length - 1] & 0x80) {
      isNegative = true;
      // Clear sign bit
      const cleanVch = new Uint8Array(vch);
      cleanVch[vch.length - 1] &= 0x7f;
      for (let i = 0; i < cleanVch.length; i++) {
        result = (result << 8n) | BigInt(cleanVch[i]);
      }
      result = -result;
    } else {
      for (let i = 0; i < vch.length; i++) {
        result = (result << 8n) | BigInt(vch[i]);
      }
    }

    return new CScriptNum(result);
  }

  /**
   * Get as 32-bit integer (clamped to int range)
   */
  getint(): number {
    if (this.value > BigInt(Number.MAX_SAFE_INTEGER)) {
      return Number.MAX_SAFE_INTEGER;
    }
    if (this.value < BigInt(Number.MIN_SAFE_INTEGER)) {
      return Number.MIN_SAFE_INTEGER;
    }
    return Number(this.value);
  }

  /**
   * Get as 64-bit integer
   */
  getInt64(): bigint {
    return this.value;
  }

  /**
   * Convert to byte vector
   */
  getvch(): Uint8Array {
    return CScriptNum.serialize(this.value);
  }

  /**
   * Serialize a value to byte vector
   */
  static serialize(value: bigint): Uint8Array {
    if (value === 0n) {
      return new Uint8Array(0);
    }

    const neg = value < 0n;
    let absValue = value < 0n ? -value - 1n : value;

    const result: number[] = [];
    while (absValue > 0n) {
      result.push(Number(absValue & 0xffn));
      absValue >>= 8n;
    }

    // If high bit is set, add a leading zero for sign
    if (result[result.length - 1] & 0x80) {
      result.push(neg ? 0x80 : 0x00);
    } else if (neg) {
      result[result.length - 1] |= 0x80;
    }

    return new Uint8Array(result);
  }

  // Comparison operators
  eq(rhs: number | CScriptNum): boolean {
    const rhsVal = typeof rhs === 'number' ? BigInt(rhs) : rhs.value;
    return this.value === rhsVal;
  }

  compare(rhs: number | CScriptNum): number {
    const rhsVal = typeof rhs === 'number' ? BigInt(rhs) : rhs.value;
    if (this.value < rhsVal) return -1;
    if (this.value > rhsVal) return 1;
    return 0;
  }

  // Arithmetic operators
  add(rhs: number | CScriptNum): CScriptNum {
    const rhsVal = typeof rhs === 'number' ? BigInt(rhs) : rhs.value;
    return new CScriptNum(this.value + rhsVal);
  }

  sub(rhs: number | CScriptNum): CScriptNum {
    const rhsVal = typeof rhs === 'number' ? BigInt(rhs) : rhs.value;
    return new CScriptNum(this.value - rhsVal);
  }

  neg(): CScriptNum {
    return new CScriptNum(-this.value);
  }

  bitand(rhs: number | CScriptNum): CScriptNum {
    const rhsVal = typeof rhs === 'number' ? BigInt(rhs) : rhs.value;
    return new CScriptNum(this.value & rhsVal);
  }
}

/**
 * CScript - Bitcoin script
 */
export class CScript {
  data: Uint8Array;

  constructor(data: Uint8Array = new Uint8Array(0)) {
    this.data = data;
  }

  /**
   * Create an empty script
   */
  static empty(): CScript {
    return new CScript();
  }

  /**
   * Get the underlying data
   */
  buffer(): Uint8Array {
    return this.data;
  }

  /**
   * Get script length
   */
  length(): number {
    return this.data.length;
  }

  /**
   * Get iterator to beginning
   */
  begin(): number {
    return 0;
  }

  /**
   * Get iterator to end
   */
  end(): number {
    return this.data.length;
  }

  /**
   * Get element at position
   */
  at(pos: number): number {
    return this.data[pos];
  }

  /**
   * Clear the script
   */
  clear(): void {
    this.data = new Uint8Array(0);
  }

  /**
   * Reserve capacity
   */
  reserve(size: number): void {
    const newData = new Uint8Array(size);
    newData.set(this.data);
    this.data = newData;
  }

  /**
   * Get script as Vector
   */
  toVector(): Uint8Array {
    return new Uint8Array(this.data);
  }

  /**
   * Get script as Span
   */
  toSpan(): Uint8Array {
    return this.data;
  }

  /**
   * Find and delete an opcode sequence
   */
  static FindAndDelete(script: CScript, opcode: Uint8Array): CScript {
    let result = new Uint8Array(script.data);
    // Simple implementation - find and remove
    let found = true;
    while (found) {
      found = false;
      for (let i = 0; i <= result.length - opcode.length; i++) {
        let match = true;
        for (let j = 0; j < opcode.length; j++) {
          if (result[i + j] !== opcode[j]) {
            match = false;
            break;
          }
        }
        if (match) {
          // Remove the match
          const newResult = new Uint8Array(result.length - opcode.length);
          newResult.set(result.subarray(0, i));
          newResult.set(result.subarray(i + opcode.length));
          result = newResult;
          found = true;
          break;
        }
      }
    }
    return new CScript(result);
  }

  /**
   * Insert data at position
   */
  insert(pos: number, item: Uint8Array): void {
    const newData = new Uint8Array(this.data.length + item.length);
    newData.set(this.data.subarray(0, pos));
    newData.set(item, pos);
    newData.set(this.data.subarray(pos), pos + item.length);
    this.data = newData;
  }

  /**
   * Erase data at position
   */
  erase(pos: number, size: number): void {
    const newData = new Uint8Array(this.data.length - size);
    newData.set(this.data.subarray(0, pos));
    newData.set(this.data.subarray(pos + size));
    this.data = newData;
  }

  /**
   * Get the opcodes in the script
   */
  getOpcodes(): Opcode[] {
    const opcodes: Opcode[] = [];
    let pos = 0;
    while (pos < this.data.length) {
      opcodes.push(this.data[pos] as Opcode);
      pos++;
    }
    return opcodes;
  }

  /**
   * Check if script is push-only
   */
  isPushOnly(): boolean {
    for (let i = 0; i < this.data.length; i++) {
      if (this.data[i] > Opcode.OP_16) {
        return false;
      }
    }
    return true;
  }

  /**
   * Check if script is minimal push
   */
  isMinimalPush(pos: number, op: number): boolean {
    if (op === 0) {
      return true;
    }
    if (op >= Opcode.OP_1 && op <= Opcode.OP_16) {
      return true;
    }
    if (this.data[pos + 1] === op) {
      return true;
    }
    if (op < Opcode.OP_PUSHDATA1) {
      return pos + 1 + op < this.data.length;
    }
    if (op === Opcode.OP_PUSHDATA1) {
      return pos + 2 < this.data.length;
    }
    if (op === Opcode.OP_PUSHDATA2) {
      return pos + 3 < this.data.length;
    }
    return true;
  }

  /**
   * Convert script to human-readable string
   */
  toString(): string {
    const parts: string[] = [];
    let pos = 0;
    while (pos < this.data.length) {
      const op = this.data[pos];
      if (op >= Opcode.OP_1 && op <= Opcode.OP_16) {
        parts.push((op - Opcode.OP_1 + 1).toString());
        pos++;
      } else if (op >= 0x01 && op <= 0x4b) {
        // Direct push
        const len = op;
        parts.push(`0x${Buffer.from(this.data.subarray(pos + 1, pos + 1 + len)).toString('hex')}`);
        pos += 1 + len;
      } else {
        parts.push(GetOpName(op as Opcode));
        pos++;
      }
    }
    return parts.join(' ');
  }

  /**
   * Create P2PK script
   */
  static createP2PKScript(pubkey: Uint8Array): CScript {
    const script = new CScript();
    script.data = new Uint8Array(pubkey.length + 2);
    script.data.set(pubkey, 1);
    script.data[0] = pubkey.length;
    script.data[pubkey.length + 1] = Opcode.OP_CHECKSIG;
    return script;
  }

  /**
   * Create P2PKH script
   */
  static createP2PKHScript(pubkeyHash: Uint8Array): CScript {
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
   * Create P2WPKH script
   */
  static createP2WPKHScript(pubkeyHash: Uint8Array): CScript {
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
   * Create P2WSH script
   */
  static createP2WSHScript(witnessScript: Uint8Array): CScript {
    const script = new CScript();
    script.data = new Uint8Array(34);
    script.data[0] = Opcode.OP_0;
    script.data[1] = 32;
    // Note: In real implementation, this would be SHA256 of witnessScript
    // For now, we'll just create the structure
    return script;
  }

  /**
   * Create P2SH script
   */
  static createP2SHScript(scriptHash: Uint8Array): CScript {
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
}

/**
 * Helper to convert any integer to a minimal push opcode
 */
export function GetOpForIndex(index: number): Opcode {
  if (index === 0) {
    return Opcode.OP_0;
  }
  if (index >= 1 && index <= 16) {
    return Opcode.OP_1 - 1 + index as Opcode;
  }
  throw new Error('Invalid index');
}
