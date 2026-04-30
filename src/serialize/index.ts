// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Serialization framework for Bitcoin Core data structures.
 * This is a TypeScript port of Bitcoin Core's serialize.h.
 */

/**
 * Serializable interface - objects that can be serialized
 */
export interface Serializable {
  serialize(stream: Stream): void;
  unserialize(stream: Stream): void;
}

/**
 * Stream interface for serialization
 */
export interface Stream {
  write(data: Uint8Array | readonly number[]): void;
  read(size: number): Uint8Array;
  writeCompactSize(size: number): void;
  readCompactSize(): number;
  writeVector<T>(items: T[], serializer: (item: T) => Uint8Array): void;
  readVector<T>(deserializer: (data: Uint8Array) => T): T[];
  getParams<T>(): T;
}

/**
 * Base stream implementation using Uint8Array
 */
export class Uint8ArrayStream implements Stream {
  private buffer: number[];
  private offset: number;
  private params: Record<string, unknown>;

  constructor(params: Record<string, unknown> = {}) {
    this.buffer = [];
    this.offset = 0;
    this.params = params;
  }

  write(data: Uint8Array | readonly number[]): void {
    for (let i = 0; i < data.length; i++) {
      this.buffer.push(data[i]);
    }
  }

  read(size: number): Uint8Array {
    const result = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      result[i] = this.buffer[this.offset++] ?? 0;
    }
    return result;
  }

  writeCompactSize(size: number): void {
    if (size < 253) {
      this.write(new Uint8Array([size]));
    } else if (size < 0x10000) {
      this.write(new Uint8Array([253, size & 0xff, (size >> 8) & 0xff]));
    } else if (size < 0x100000000) {
      this.write(
        new Uint8Array([
          254,
          size & 0xff,
          (size >> 8) & 0xff,
          (size >> 16) & 0xff,
          (size >> 24) & 0xff,
        ]),
      );
    } else {
      const hi = Math.floor(size / 0x100000000);
      const lo = size % 0x100000000;
      this.write(
        new Uint8Array([
          255,
          lo & 0xff,
          (lo >> 8) & 0xff,
          (lo >> 16) & 0xff,
          (lo >> 24) & 0xff,
          hi & 0xff,
          (hi >> 8) & 0xff,
          (hi >> 16) & 0xff,
          (hi >> 24) & 0xff,
        ]),
      );
    }
  }

  readCompactSize(): number {
    const prefix = this.read(1)[0];

    if (prefix < 253) {
      return prefix;
    } else if (prefix === 253) {
      const data = this.read(2);
      return data[0] | (data[1] << 8);
    } else if (prefix === 254) {
      const data = this.read(4);
      return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
    } else {
      const data = this.read(8);
      return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
    }
  }

  writeVector<T>(items: T[], serializer: (item: T) => Uint8Array): void {
    this.writeCompactSize(items.length);
    for (const item of items) {
      this.write(serializer(item));
    }
  }

  readVector<T>(deserializer: (data: Uint8Array) => T): T[] {
    const count = this.readCompactSize();
    const result: T[] = [];
    for (let i = 0; i < count; i++) {
      // For variable-length items, we'd need more context
      // This is a simplified version
      result.push(deserializer(new Uint8Array(0)));
    }
    return result;
  }

  getParams<T>(): T {
    return this.params as T;
  }

  getBuffer(): Uint8Array {
    return new Uint8Array(this.buffer);
  }

  getOffset(): number {
    return this.offset;
  }

  setOffset(offset: number): void {
    this.offset = offset;
  }
}

/**
 * Serialize a uint8 array
 */
export function serializeUint8Array(
  stream: Stream,
  data: Uint8Array | readonly number[],
): void {
  stream.write(data);
}

/**
 * Unserialize a uint8 array
 */
export function unserializeUint8Array(
  stream: Stream,
  size: number,
): Uint8Array {
  return stream.read(size);
}

/**
 * Serialize a number (8-bit)
 */
export function serializeUInt8(stream: Stream, value: number): void {
  stream.write(new Uint8Array([value & 0xff]));
}

/**
 * Unserialize a number (8-bit)
 */
export function unserializeUInt8(stream: Stream): number {
  return stream.read(1)[0];
}

/**
 * Serialize a number (16-bit little-endian)
 */
export function serializeUInt16LE(stream: Stream, value: number): void {
  stream.write(new Uint8Array([value & 0xff, (value >> 8) & 0xff]));
}

/**
 * Unserialize a number (16-bit little-endian)
 */
export function unserializeUInt16LE(stream: Stream): number {
  const data = stream.read(2);
  return data[0] | (data[1] << 8);
}

/**
 * Serialize a number (16-bit big-endian)
 */
export function serializeUInt16BE(stream: Stream, value: number): void {
  stream.write(new Uint8Array([(value >> 8) & 0xff, value & 0xff]));
}

/**
 * Unserialize a number (16-bit big-endian)
 */
export function unserializeUInt16BE(stream: Stream): number {
  const data = stream.read(2);
  return (data[0] << 8) | data[1];
}

/**
 * Serialize a number (32-bit little-endian)
 */
export function serializeUInt32LE(stream: Stream, value: number): void {
  stream.write(
    new Uint8Array([
      value & 0xff,
      (value >> 8) & 0xff,
      (value >> 16) & 0xff,
      (value >> 24) & 0xff,
    ]),
  );
}

/**
 * Unserialize a number (32-bit little-endian)
 */
export function unserializeUInt32LE(stream: Stream): number {
  const data = stream.read(4);
  return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

/**
 * Serialize a number (32-bit big-endian)
 */
export function serializeUInt32BE(stream: Stream, value: number): void {
  stream.write(
    new Uint8Array([
      (value >> 24) & 0xff,
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff,
    ]),
  );
}

/**
 * Unserialize a number (32-bit big-endian)
 */
export function unserializeUInt32BE(stream: Stream): number {
  const data = stream.read(4);
  return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
}

/**
 * Serialize a bigint (64-bit little-endian)
 */
export function serializeUInt64LE(stream: Stream, value: bigint): void {
  const data = new Uint8Array(8);
  let remaining = value;
  for (let i = 0; i < 8; i++) {
    data[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  stream.write(data);
}

/**
 * Unserialize a bigint (64-bit little-endian)
 */
export function unserializeUInt64LE(stream: Stream): bigint {
  const data = stream.read(8);
  let result = 0n;
  for (let i = 7; i >= 0; i--) {
    result = (result << 8n) | BigInt(data[i]);
  }
  return result;
}

/**
 * Serialize a number (64-bit little-endian as bigint for precision)
 */
export function serializeInt64LE(stream: Stream, value: bigint): void {
  serializeUInt64LE(stream, value);
}

/**
 * Unserialize a signed 64-bit integer (little-endian)
 */
export function unserializeInt64LE(stream: Stream): bigint {
  return unserializeUInt64LE(stream);
}

/**
 * Serialize a boolean
 */
export function serializeBool(stream: Stream, value: boolean): void {
  stream.write(new Uint8Array([value ? 1 : 0]));
}

/**
 * Unserialize a boolean
 */
export function unserializeBool(stream: Stream): boolean {
  return stream.read(1)[0] !== 0;
}

/**
 * Serialize a string (as length-prefixed bytes)
 */
export function serializeString(stream: Stream, value: string): void {
  const encoder = new TextEncoder();
  const data = encoder.encode(value);
  stream.writeCompactSize(data.length);
  stream.write(data);
}

/**
 * Unserialize a string
 */
export function unserializeString(stream: Stream): string {
  const length = stream.readCompactSize();
  const data = stream.read(length);
  const decoder = new TextDecoder();
  return decoder.decode(data);
}

/**
 * SERIALIZE methods helper - creates serialize/unserialize pair
 */
export function defineSerializeMethods<T extends Serializable>(
  _name: string,
  _obj: T,
  ...fields: Array<keyof T>
): {
  serialize: (stream: Stream) => void;
  unserialize: (stream: Stream) => void;
} {
  return {
    serialize: (stream: Stream) => {
      for (const field of fields) {
        const value = _obj[field] as Serializable;
        if (value && typeof value.serialize === "function") {
          value.serialize(stream);
        }
      }
    },
    unserialize: (stream: Stream) => {
      for (const field of fields) {
        const value = _obj[field] as Serializable;
        if (value && typeof value.unserialize === "function") {
          value.unserialize(stream);
        }
      }
    },
  };
}

/**
 * Macros for defining serialize methods in classes
 */
export function SERIALIZE_METHODS<T extends Serializable>(
  this: T,
  obj: T,
  fields: (keyof T)[],
): {
  serialize: (stream: Stream) => void;
  unserialize: (stream: Stream) => void;
} {
  return defineSerializeMethods("", obj, ...fields);
}
