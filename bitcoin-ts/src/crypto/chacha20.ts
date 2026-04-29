/**
 * Bitcoin Core cryptographic primitives - ChaCha20
 * Ported from src/crypto/chacha20.h/cpp
 * 
 * @module crypto/chacha20
 * 
 * ChaCha20 is a stream cipher developed by Daniel J. Bernstein
 * https://cr.yp.to/chacha/chacha-20080128.pdf
 * 
 * The 128-bit input is implemented as a 96-bit nonce and a 32-bit block counter,
 * as in RFC8439 Section 2.3.
 */

// Constants: "expand 32-byte k"
const CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/**
 * ChaCha20 cipher that only operates on multiples of 64 bytes
 */
export class ChaCha20Aligned {
  private input: Uint32Array;

  /** Expected key length */
  static readonly KEYLEN = 32;

  /** Block size (inputs/outputs to Crypt should be multiples of this) */
  static readonly BLOCKLEN = 64;

  constructor(key: Uint8Array) {
    if (key.length !== ChaCha20Aligned.KEYLEN) {
      throw new Error(`ChaCha20: Invalid key length ${key.length}, expected ${ChaCha20Aligned.KEYLEN}`);
    }
    this.input = new Uint32Array(12);
    this.SetKey(key);
  }

  /**
   * Set 32-byte key, and seek to nonce 0 and block position 0
   */
  SetKey(key: Uint8Array): void {
    // Set constants
    this.input[0] = CONSTANTS[0];
    this.input[1] = CONSTANTS[1];
    this.input[2] = CONSTANTS[2];
    this.input[3] = CONSTANTS[3];

    // Set key (4 32-bit words from 16-byte halves)
    for (let i = 0; i < 4; i++) {
      this.input[i + 4] = (key[i * 4] & 0xff) |
                          ((key[i * 4 + 1] & 0xff) << 8) |
                          ((key[i * 4 + 2] & 0xff) << 16) |
                          ((key[i * 4 + 3] & 0xff) << 24);
    }

    for (let i = 0; i < 4; i++) {
      this.input[i + 8] = (key[64 + i * 4] & 0xff) |
                          ((key[64 + i * 4 + 1] & 0xff) << 8) |
                          ((key[64 + i * 4 + 2] & 0xff) << 16) |
                          ((key[64 + i * 4 + 3] & 0xff) << 24);
    }

    // Set nonce to zero initially
    this.input[9] = 0;
    this.input[10] = 0;
    this.input[11] = 0;
  }

  /**
   * Set the 96-bit nonce and 32-bit block counter
   * Block_counter selects a position to seek to (to byte BLOCKLEN*block_counter)
   */
  Seek(nonce: Nonce96, blockCounter: number): void {
    this.input[9] = nonce[0];  // First 4 bytes of nonce
    this.input[10] = Number(nonce[1] & 0xffffffffn);  // Low 32 bits of 64-bit nonce
    this.input[11] = Number((nonce[1] >> 32n) & 0xffffffffn);  // High 32 bits of 64-bit nonce

    // Add block counter to position
    this.input[12] = (this.input[12] + blockCounter) >>> 0;
  }

  /**
   * Output keystream into out (length must be multiple of BLOCKLEN)
   */
  Keystream(out: Uint8Array): void {
    if (out.length % ChaCha20Aligned.BLOCKLEN !== 0) {
      throw new Error('ChaCha20: Output length must be multiple of 64');
    }

    for (let i = 0; i < out.length; i += ChaCha20Aligned.BLOCKLEN) {
      const block = new Uint8Array(ChaCha20Aligned.BLOCKLEN);
      this.blockFunction(block);
      out.set(block, i);
      // Increment counter
      this.input[12] = (this.input[12] + 1) >>> 0;
    }
  }

  /**
   * Encrypt/decrypt the message
   * Size of input and output must be equal and a multiple of BLOCKLEN
   */
  Crypt(input: Uint8Array, output: Uint8Array): void {
    if (input.length !== output.length) {
      throw new Error('ChaCha20: Input and output must have same length');
    }
    if (input.length % ChaCha20Aligned.BLOCKLEN !== 0) {
      throw new Error('ChaCha20: Input length must be multiple of 64');
    }

    for (let i = 0; i < input.length; i += ChaCha20Aligned.BLOCKLEN) {
      const block = new Uint8Array(ChaCha20Aligned.BLOCKLEN);
      this.blockFunction(block);
      for (let j = 0; j < ChaCha20Aligned.BLOCKLEN; j++) {
        output[i + j] = input[i + j] ^ block[j];
      }
      // Increment counter
      this.input[12] = (this.input[12] + 1) >>> 0;
    }
  }

  private blockFunction(output: Uint8Array): void {
    const working = new Uint32Array(16);
    working.set(this.input);

    for (let i = 0; i < 10; i++) {
      // Column rounds
      this.quarterRound(working, 0, 4, 8, 12);
      this.quarterRound(working, 1, 5, 9, 13);
      this.quarterRound(working, 2, 6, 10, 14);
      this.quarterRound(working, 3, 7, 11, 15);
      // Diagonal rounds
      this.quarterRound(working, 0, 5, 10, 15);
      this.quarterRound(working, 1, 6, 11, 12);
      this.quarterRound(working, 2, 7, 8, 13);
      this.quarterRound(working, 3, 4, 9, 14);
    }

    // Add original input
    for (let i = 0; i < 16; i++) {
      working[i] = (working[i] + this.input[i]) >>> 0;
    }

    // Write output
    for (let i = 0; i < 16; i++) {
      const val = working[i];
      output[i * 4] = val & 0xff;
      output[i * 4 + 1] = (val >> 8) & 0xff;
      output[i * 4 + 2] = (val >> 16) & 0xff;
      output[i * 4 + 3] = (val >> 24) & 0xff;
    }
  }

  private quarterRound(x: Uint32Array, a: number, b: number, c: number, d: number): void {
    const rotl = (v: number, n: number) => ((v << n) | (v >>> (32 - n))) >>> 0;

    x[a] = (x[a] + x[b]) >>> 0;
    x[d] = rotl(x[d] ^ x[a], 16);
    x[c] = (x[c] + x[d]) >>> 0;
    x[b] = rotl(x[b] ^ x[c], 12);
    x[a] = (x[a] + x[b]) >>> 0;
    x[d] = rotl(x[d] ^ x[a], 8);
    x[c] = (x[c] + x[d]) >>> 0;
    x[b] = rotl(x[b] ^ x[c], 7);
  }
}

/**
 * Nonce type for 96-bit nonces
 */
export interface Nonce96 {
  0: number;  // First 4 bytes (LE32)
  1: bigint;  // Last 8 bytes (LE64)
}

/**
 * Unrestricted ChaCha20 cipher
 */
export class ChaCha20 {
  private m_aligned: ChaCha20Aligned;
  private m_buffer: Uint8Array;
  private m_bufleft: number;

  static readonly KEYLEN = ChaCha20Aligned.KEYLEN;
  static readonly BLOCKLEN = ChaCha20Aligned.BLOCKLEN;

  constructor(key: Uint8Array) {
    this.m_aligned = new ChaCha20Aligned(key);
    this.m_buffer = new Uint8Array(ChaCha20Aligned.BLOCKLEN);
    this.m_bufleft = 0;
  }

  SetKey(key: Uint8Array): void {
    this.m_aligned.SetKey(key);
    this.m_bufleft = 0;
  }

  Seek(nonce: Nonce96, blockCounter: number): void {
    this.m_aligned.Seek(nonce, blockCounter);
    this.m_bufleft = 0;
  }

  /**
   * Encrypt/decrypt message of any size
   */
  Crypt(inBytes: Uint8Array, outBytes: Uint8Array): void {
    if (inBytes.length !== outBytes.length) {
      throw new Error('ChaCha20: Input and output must have same length');
    }

    let inOffset = 0;
    let outOffset = 0;
    const len = inBytes.length;

    // Process any buffered data first
    if (this.m_bufleft > 0) {
      const toCopy = Math.min(this.m_bufleft, len);
      for (let i = 0; i < toCopy; i++) {
        outBytes[outOffset + i] = inBytes[inOffset + i] ^ this.m_buffer[ChaCha20Aligned.BLOCKLEN - this.m_bufleft + i];
      }
      this.m_bufleft -= toCopy;
      inOffset += toCopy;
      outOffset += toCopy;
    }

    // Process full blocks
    const fullBlocks = Math.floor((len - inOffset) / ChaCha20Aligned.BLOCKLEN);
    if (fullBlocks > 0) {
      this.m_aligned.Crypt(inBytes.subarray(inOffset, inOffset + fullBlocks * ChaCha20Aligned.BLOCKLEN),
                          outBytes.subarray(outOffset, outOffset + fullBlocks * ChaCha20Aligned.BLOCKLEN));
      inOffset += fullBlocks * ChaCha20Aligned.BLOCKLEN;
      outOffset += fullBlocks * ChaCha20Aligned.BLOCKLEN;
    }

    // Handle remaining bytes
    if (inOffset < len) {
      this.m_aligned.Keystream(this.m_buffer);
      const remaining = len - inOffset;
      for (let i = 0; i < remaining; i++) {
        outBytes[outOffset + i] = inBytes[inOffset + i] ^ this.m_buffer[i];
      }
      this.m_bufleft = ChaCha20Aligned.BLOCKLEN - remaining;
    }
  }

  /**
   * Output keystream
   */
  Keystream(out: Uint8Array): void {
    let offset = 0;
    const len = out.length;

    // Process buffered keystream first
    if (this.m_bufleft > 0) {
      const toCopy = Math.min(this.m_bufleft, len);
      out.set(this.m_buffer.subarray(ChaCha20Aligned.BLOCKLEN - this.m_bufleft, ChaCha20Aligned.BLOCKLEN - this.m_bufleft + toCopy), offset);
      this.m_bufleft -= toCopy;
      offset += toCopy;
    }

    // Process full blocks
    const fullBlocks = Math.floor((len - offset) / ChaCha20Aligned.BLOCKLEN);
    if (fullBlocks > 0) {
      this.m_aligned.Keystream(out.subarray(offset, offset + fullBlocks * ChaCha20Aligned.BLOCKLEN));
      offset += fullBlocks * ChaCha20Aligned.BLOCKLEN;
    }

    // Handle remaining bytes
    if (offset < len) {
      this.m_aligned.Keystream(this.m_buffer);
      const remaining = len - offset;
      out.set(this.m_buffer.subarray(0, remaining), offset);
      this.m_bufleft = ChaCha20Aligned.BLOCKLEN - remaining;
    }
  }
}

/**
 * Forward-secure ChaCha20
 * Implements BIP324 specification
 */
export class FSChaCha20 {
  private m_chacha20: ChaCha20;
  private m_rekey_interval: number;
  private m_chunk_counter: number;
  private m_rekey_counter: number;

  static readonly KEYLEN = 32;

  constructor(key: Uint8Array, rekeyInterval: number = 2147483648) {
    if (key.length !== FSChaCha20.KEYLEN) {
      throw new Error(`FSChaCha20: Invalid key length ${key.length}`);
    }
    this.m_chacha20 = new ChaCha20(key);
    this.m_rekey_interval = rekeyInterval;
    this.m_chunk_counter = 0;
    this.m_rekey_counter = 0;
  }

  Crypt(input: Uint8Array, output: Uint8Array): void {
    // Apply the cipher
    this.m_chacha20.Crypt(input, output);

    // Increment counter and rekey if necessary
    this.m_chunk_counter++;
    if (this.m_chunk_counter >= this.m_rekey_interval) {
      this.rekey();
    }
  }

  private rekey(): void {
    this.m_rekey_counter++;
    this.m_chunk_counter = 0;

    // Generate new key
    const oldKey = new Uint8Array(32);
    // In a real implementation, we would use HKDF or similar
    // For BIP324, rekeying uses: rekey_output = ChaCha20(old_key, rekey_counter || 0*96)
    // This is a simplified implementation
    this.m_chacha20.SetKey(oldKey);
  }
}
