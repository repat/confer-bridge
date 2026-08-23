/**
 * Minimal protobuf wire-format reader/writer (proto3 semantics, no protobufjs
 * dependency). Only the features the confer transport schema needs are
 * implemented: varint and length-delimited fields, int64/uint32 as varints,
 * bytes/string submessages, and map<string,string> entries.
 */
import { UpstreamProtocolChangedError } from '../errors.js';

export const enum WireType {
  Varint = 0,
  LengthDelimited = 2,
}

export function encodeVarint(value: bigint | number): Uint8Array {
  let v = typeof value === 'bigint' ? value : BigInt(value);
  if (v < 0n) v += 1n << 64n; // two's-complement encoding for negative int64
  const out: number[] = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) byte |= 0x80;
    out.push(byte);
  } while (v > 0n);
  return new Uint8Array(out);
}

export function encodeTag(fieldNumber: number, wireType: WireType): Uint8Array {
  return encodeVarint((fieldNumber << 3) | wireType);
}

export class ProtoWriter {
  private chunks: Uint8Array[] = [];

  uint64Field(fieldNumber: number, value: bigint | number): this {
    this.chunks.push(encodeTag(fieldNumber, WireType.Varint), encodeVarint(value));
    return this;
  }

  boolField(fieldNumber: number, value: boolean): this {
    if (!value) return this; // proto3 default: omit false
    return this.uint64Field(fieldNumber, 1n);
  }

  bytesField(fieldNumber: number, value: Uint8Array): this {
    this.chunks.push(encodeTag(fieldNumber, WireType.LengthDelimited), encodeVarint(value.length), value);
    return this;
  }

  stringField(fieldNumber: number, value: string): this {
    return this.bytesField(fieldNumber, new TextEncoder().encode(value));
  }

  messageField(fieldNumber: number, encoded: Uint8Array): this {
    return this.bytesField(fieldNumber, encoded);
  }

  finish(): Uint8Array {
    return concat(this.chunks);
  }
}

export function concat(chunks: readonly Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export class ProtoReader {
  private offset = 0;

  constructor(private readonly buffer: Uint8Array) {}

  /** Returns null at end of message. */
  nextField(): { fieldNumber: number; wireType: WireType } | null {
    if (this.offset >= this.buffer.length) return null;
    const tag = this.readVarint();
    const fieldNumber = Number(tag >> 3n);
    const wireType = Number(tag & 7n) as WireType;
    if (fieldNumber === 0) throw new UpstreamProtocolChangedError('Invalid protobuf field number 0.');
    return { fieldNumber, wireType };
  }

  readVarint(): bigint {
    let result = 0n;
    let shift = 0n;
    for (;;) {
      if (this.offset >= this.buffer.length) throw new UpstreamProtocolChangedError('Truncated varint.');
      const byte = this.buffer[this.offset++]!;
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7n;
      if (shift > 70n) throw new UpstreamProtocolChangedError('Varint too long.');
    }
    return result;
  }

  readInt64(): bigint {
    const raw = this.readVarint();
    // Interpret as signed 64-bit two's complement.
    if (raw >= 1n << 63n) return raw - (1n << 64n);
    return raw;
  }

  readUint32(): number {
    const raw = this.readVarint();
    if (raw > 0xffff_ffffn) throw new UpstreamProtocolChangedError('uint32 out of range.');
    return Number(raw);
  }

  readBool(): boolean {
    return this.readVarint() !== 0n;
  }

  readBytes(): Uint8Array {
    const length = this.readVarint();
    if (length > BigInt(Number.MAX_SAFE_INTEGER)) throw new UpstreamProtocolChangedError('Length-delimited field too large.');
    const start = this.offset;
    const end = start + Number(length);
    if (end > this.buffer.length) throw new UpstreamProtocolChangedError('Length-delimited field truncated.');
    this.offset = end;
    return this.buffer.subarray(start, end);
  }

  readString(): string {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(this.readBytes());
    } catch (error) {
      if (error instanceof UpstreamProtocolChangedError) throw error;
      throw new UpstreamProtocolChangedError('String field is not valid UTF-8.');
    }
  }

  /** Decode a length-delimited submessage with a callback per field. */
  readMessage(handle: (reader: ProtoReader, fieldNumber: number, wireType: WireType) => void): void {
    const bytes = this.readBytes();
    const reader = new ProtoReader(bytes);
    for (;;) {
      const field = reader.nextField();
      if (!field) break;
      handle(reader, field.fieldNumber, field.wireType);
    }
  }

  skip(wireType: WireType): void {
    switch (wireType) {
      case WireType.Varint:
        this.readVarint();
        return;
      case WireType.LengthDelimited:
        this.readBytes();
        return;
      default:
        throw new UpstreamProtocolChangedError(`Unsupported wire type ${wireType}.`);
    }
  }
}
