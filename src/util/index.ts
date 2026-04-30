// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Utility functions.
 */

export function strjoin<T>(items: T[], separator: string): string {
  return items.join(separator);
}

export function ToString<T>(value: T): string {
  return String(value);
}

export function tf_format(pattern: string, ...args: unknown[]): string {
  let result = pattern;
  for (let i = 0; i < args.length; i++) {
    const placeholder = `{${i}}`;
    const value = args[i];

    if (value === undefined) {
      result = result.replace(placeholder, "undefined");
    } else if (value === null) {
      result = result.replace(placeholder, "null");
    } else if (typeof value === "object") {
      result = result.replace(placeholder, JSON.stringify(value));
    } else {
      result = result.replace(placeholder, String(value));
    }
  }
  return result;
}

const HEX_CHARS = "0123456789abcdef";

export function isHex(ch: string): boolean {
  return /^[0-9a-fA-F]*$/.test(ch);
}

export function isHexNumber(ch: string): boolean {
  return /^[0-9a-fA-F]+$/.test(ch);
}

export function HexDigit(c: string): number {
  const digit = parseInt(c, 16);
  return isNaN(digit) ? 0 : digit;
}

export function HexStr(
  data: Uint8Array | readonly number[],
  fReverseBytes?: boolean,
): string {
  let result = "";
  const bytes = Array.from(data);
  if (fReverseBytes) {
    bytes.reverse();
  }
  for (const byte of bytes) {
    result += HEX_CHARS[(byte >> 4) & 0xf];
    result += HEX_CHARS[byte & 0xf];
  }
  return result;
}

export function ParseHex(str: string): number[] {
  str = str.replace(/^0x/i, "");
  if (!isHex(str)) {
    return [];
  }
  if (str.length % 2 !== 0) {
    str = "0" + str;
  }
  const result: number[] = [];
  for (let i = 0; i < str.length; i += 2) {
    result.push(parseInt(str.substr(i, 2), 16));
  }
  return result;
}

export function constevalHexDigit(c: string): number {
  const d = parseInt(c, 16);
  if (isNaN(d)) {
    return 0;
  }
  return d;
}

export function RemovePrefixView(input: string, prefix: string): string {
  if (input.startsWith(prefix)) {
    return input.slice(prefix.length);
  }
  return input;
}

export function ParseUInt8(s: string): number | null {
  const n = parseInt(s, 16);
  if (isNaN(n) || n < 0 || n > 255) {
    return null;
  }
  return n;
}

export function ParseUInt16LE(s: string): number | null {
  const bytes = ParseHex(s);
  if (bytes.length !== 2) return null;
  return bytes[0] | (bytes[1] << 8);
}

export function ParseUInt16BE(s: string): number | null {
  const bytes = ParseHex(s);
  if (bytes.length !== 2) return null;
  return (bytes[0] << 8) | bytes[1];
}

export function ParseUInt32LE(s: string): number | null {
  const bytes = ParseHex(s);
  if (bytes.length !== 4) return null;
  return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
}

export function ParseUInt32BE(s: string): number | null {
  const bytes = ParseHex(s);
  if (bytes.length !== 4) return null;
  return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

export function ParseUInt64LE(s: string): bigint | null {
  const bytes = ParseHex(s);
  if (bytes.length !== 8) return null;
  let result = 0n;
  for (let i = 7; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

export function countLeadingZeros(
  data: Uint8Array | readonly number[],
): number {
  let count = 0;
  for (const byte of data) {
    if (byte === 0) {
      count += 8;
    } else {
      for (let i = 7; i >= 0; i--) {
        if ((byte & (1 << i)) === 0) {
          count++;
        } else {
          return count;
        }
      }
    }
  }
  return count;
}

export function copySpan(
  dest: Uint8Array,
  destOffset: number,
  src: Uint8Array | readonly number[],
): void {
  for (let i = 0; i < src.length; i++) {
    dest[destOffset + i] = src[i];
  }
}

export function max(...args: number[]): number {
  return Math.max(...args);
}

export function min(...args: number[]): number {
  return Math.min(...args);
}

export function clamp(value: number, minVal: number, maxVal: number): number {
  return Math.min(Math.max(value, minVal), maxVal);
}

export function ceilDiv(a: number, b: number): number {
  return Math.floor((a + b - 1) / b);
}

export function coalesce<T>(value: T | null | undefined, defaultValue: T): T {
  return value ?? defaultValue;
}

export function spanToString(span: Uint8Array | readonly number[]): string {
  const decoder = new TextDecoder();
  return decoder.decode(new Uint8Array(span as Uint8Array));
}

export function insert<T>(
  vec: T[],
  item: T,
  comp: (a: T, b: T) => number,
): void {
  const pos = vec.findIndex((v) => comp(v, item) >= 0);
  if (pos === -1) {
    vec.push(item);
  } else {
    vec.splice(pos, 0, item);
  }
}

export function contains<T>(
  vec: readonly T[],
  item: T,
  comp: (a: T, b: T) => number,
): boolean {
  return vec.some((v) => comp(v, item) === 0);
}
