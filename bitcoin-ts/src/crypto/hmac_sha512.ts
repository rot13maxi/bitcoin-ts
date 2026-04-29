/**
 * Bitcoin Core cryptographic primitives - HMAC-SHA512
 * Ported from src/crypto/hmac_sha512.h/cpp
 * 
 * @module crypto/hmac_sha512
 */

import { CSHA512 } from './sha512';

export const OUTPUT_SIZE = 64;

/**
 * CHMAC_SHA512 - A hasher class for HMAC-SHA-512
 */
export class CHMAC_SHA512 {
  private outer: CSHA512;
  private inner: CSHA512;

  constructor(key: Uint8Array) {
    this.outer = new CSHA512();
    this.inner = new CSHA512();

    // If key is longer than 128 bytes, hash it first
    let processedKey = key;
    if (key.length > 128) {
      processedKey = new Uint8Array(64);
      const hash = new CSHA512();
      hash.Write(key);
      hash.Finalize(processedKey);
    }

    // Pad key to 128 bytes with zeros
    const paddedKey = new Uint8Array(128);
    paddedKey.set(processedKey);

    // Inner key: key XOR ipad (0x36)
    const ipadKey = new Uint8Array(128);
    for (let i = 0; i < 128; i++) {
      ipadKey[i] = paddedKey[i] ^ 0x36;
    }

    this.inner.Write(ipadKey);

    // Outer key: key XOR opad (0x5c)
    const opadKey = new Uint8Array(128);
    for (let i = 0; i < 128; i++) {
      opadKey[i] = paddedKey[i] ^ 0x5c;
    }

    this.outer.Write(opadKey);
  }

  /**
   * Write data to the HMAC
   */
  Write(data: Uint8Array): CHMAC_SHA512 {
    this.inner.Write(data);
    return this;
  }

  /**
   * Finalize the HMAC and return the result
   */
  Finalize(hash: Uint8Array): void {
    const innerHash = new Uint8Array(CSHA512.OUTPUT_SIZE);
    this.inner.Finalize(innerHash);
    this.outer.Write(innerHash);
    this.outer.Finalize(hash);
  }
}

/**
 * Compute HMAC-SHA512
 */
export function hmacSha512(key: Uint8Array, data: Uint8Array): Uint8Array {
  const hmac = new CHMAC_SHA512(key);
  hmac.Write(data);
  const hash = new Uint8Array(OUTPUT_SIZE);
  hmac.Finalize(hash);
  return hash;
}
