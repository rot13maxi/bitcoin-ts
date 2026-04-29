/**
 * Bitcoin Core cryptographic primitives - HMAC-SHA256
 * Ported from src/crypto/hmac_sha256.h/cpp
 * 
 * @module crypto/hmac_sha256
 */

import { CSHA256 } from './sha256';

export const OUTPUT_SIZE = 32;

/**
 * CHMAC_SHA256 - A hasher class for HMAC-SHA-256
 */
export class CHMAC_SHA256 {
  private outer: CSHA256;
  private inner: CSHA256;

  constructor(key: Uint8Array) {
    this.outer = new CSHA256();
    this.inner = new CSHA256();

    // If key is longer than 64 bytes, hash it first
    let processedKey = key;
    if (key.length > 64) {
      processedKey = new Uint8Array(32);
      const hash = new CSHA256();
      hash.Write(key);
      hash.Finalize(processedKey);
    }

    // Pad key to 64 bytes with zeros
    const paddedKey = new Uint8Array(64);
    paddedKey.set(processedKey);

    // Inner key: key XOR ipad (0x36)
    const ipadKey = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      ipadKey[i] = paddedKey[i] ^ 0x36;
    }

    this.inner.Write(ipadKey);

    // Outer key: key XOR opad (0x5c)
    const opadKey = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      opadKey[i] = paddedKey[i] ^ 0x5c;
    }

    this.outer.Write(opadKey);
  }

  /**
   * Write data to the HMAC
   */
  Write(data: Uint8Array): CHMAC_SHA256 {
    this.inner.Write(data);
    return this;
  }

  /**
   * Finalize the HMAC and return the result
   */
  Finalize(hash: Uint8Array): void {
    const innerHash = new Uint8Array(CSHA256.OUTPUT_SIZE);
    this.inner.Finalize(innerHash);
    this.outer.Write(innerHash);
    this.outer.Finalize(hash);
  }
}

/**
 * Compute HMAC-SHA256
 */
export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  const hmac = new CHMAC_SHA256(key);
  hmac.Write(data);
  const hash = new Uint8Array(OUTPUT_SIZE);
  hmac.Finalize(hash);
  return hash;
}
