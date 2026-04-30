// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Base58 and Base58Check encoding/decoding.
 * This is a TypeScript port of Bitcoin Core's base58.h/cpp
 */

import { sha256d } from "../crypto";

/**
 * Base58 alphabet (Bitcoin variant)
 */
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Decode a single base58 character
 */
function base58Decode(c: string): number {
  return BASE58_ALPHABET.indexOf(c);
}

/**
 * Encode a base58 value (0-57)
 */
function base58Encode(v: number): string {
  return BASE58_ALPHABET[v];
}

/**
 * Encode a byte span as base58-encoded string (no checksum)
 */
export function EncodeBase58(input: Uint8Array | readonly number[]): string {
  const data = new Uint8Array(input);

  // Count leading zeros
  let leadingZeros = 0;
  for (let i = 0; i < data.length; i++) {
    if (data[i] !== 0) break;
    leadingZeros++;
  }

  // Allocate output buffer (worst case: 138/100 ratio for full bytes)
  const output: number[] = [];

  // Convert to bigint for division
  let num = BigInt(
    "0x" +
      Array.from(data)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(""),
  );
  const base = BigInt(58);

  while (num > 0n) {
    const div = num / base;
    const rem = num % base;
    output.push(Number(rem));
    num = div;
  }

  // Handle remaining bytes
  for (let i = 0; i < leadingZeros; i++) {
    output.push(0);
  }

  // Convert to string
  return output
    .map((v) => base58Encode(v))
    .join("")
    .split("")
    .reverse()
    .join("");
}

/**
 * Decode a base58 string to byte vector
 */
export function DecodeBase58(
  str: string,
  maxRetLen: number = 0,
): Uint8Array | null {
  if (str.length === 0) return new Uint8Array(0);

  let leadingOnes = 0;
  for (let i = 0; i < str.length; i++) {
    if (str[i] !== "1") break;
    leadingOnes++;
  }

  const result: number[] = [];
  let num = 0n;
  const base = BigInt(58);

  for (let i = leadingOnes; i < str.length; i++) {
    const c = str[i];
    const digit = base58Decode(c);
    if (digit === -1) return null;

    num = num * base + BigInt(digit);
  }

  // Convert to bytes
  const hexStr = num.toString(16);
  const paddedHex =
    leadingOnes * 2 + (hexStr.length % 2 === 0 ? 0 : 1) + hexStr.length;

  // Build result with leading zeros
  for (let i = 0; i < leadingOnes; i++) {
    if (result.length >= maxRetLen && maxRetLen > 0) break;
    result.push(0);
  }

  const bytes: string[] = [];
  for (let i = 0; i < hexStr.length; i++) {
    bytes.push(hexStr[i]);
  }

  // Parse hex pairs
  let pos = 0;
  while (pos < bytes.length) {
    if (result.length >= maxRetLen && maxRetLen > 0) break;
    const pair = bytes.slice(pos, pos + 2).join("");
    if (pair.length === 1) {
      result.push(parseInt("0" + pair, 16));
    } else if (pair.length === 2) {
      result.push(parseInt(pair, 16));
    }
    pos += 2;
  }

  return new Uint8Array(result);
}

/**
 * Encode a byte span as Base58Check string (with 4-byte checksum)
 */
export function EncodeBase58Check(
  input: Uint8Array | readonly number[],
): string {
  const data = new Uint8Array(input);
  const checksum = sha256d(data).slice(0, 4);
  const combined = new Uint8Array(data.length + 4);
  combined.set(data);
  combined.set(checksum, data.length);
  return EncodeBase58(combined);
}

/**
 * Decode a Base58Check string
 */
export function DecodeBase58Check(
  str: string,
  maxRetLen: number = 0,
): Uint8Array | null {
  const decoded = DecodeBase58(
    str,
    (maxRetLen > 0 ? maxRetLen + 4 : 0) as number,
  );
  if (!decoded) return null;

  if (decoded.length < 4) return null;
  if (maxRetLen > 0 && decoded.length - 4 > maxRetLen) {
    return decoded.slice(0, maxRetLen);
  }

  const data = decoded.slice(0, decoded.length - 4);
  const expectedChecksum = decoded.slice(decoded.length - 4);
  const actualChecksum = sha256d(data).slice(0, 4);

  // Compare checksums
  for (let i = 0; i < 4; i++) {
    if (expectedChecksum[i] !== actualChecksum[i]) return null;
  }

  return data;
}

/**
 * Decode a Base58Check string to a specific type
 */
export interface DecodedBase58Check {
  version: number;
  payload: Uint8Array;
}

/**
 * Decode Base58Check with version byte
 */
export function decodeBase58Check(str: string): DecodedBase58Check | null {
  const decoded = DecodeBase58Check(str);
  if (!decoded || decoded.length === 0) return null;

  return {
    version: decoded[0],
    payload: decoded.slice(1),
  };
}

/**
 * Encode with version byte
 */
export function encodeBase58Check(
  version: number,
  payload: Uint8Array | readonly number[],
): string {
  const data = new Uint8Array(1 + payload.length);
  data[0] = version;
  data.set(payload, 1);
  return EncodeBase58Check(data);
}

// Common Bitcoin address prefixes
export const PUBKEY_ADDRESS_PREFIX_MAIN = 0x00; // P2PKH
export const SCRIPT_ADDRESS_PREFIX_MAIN = 0x05; // P2SH
export const PUBKEY_ADDRESS_PREFIX_TEST = 0x6f; // P2PKH testnet
export const SCRIPT_ADDRESS_PREFIX_TEST = 0xc4; // P2SH testnet
