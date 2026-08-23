/**
 * Protobuf message codecs for the confer confidential transport, matching
 * the schema embedded in browser bundle module 2029 (see
 * docs/FRONTEND_BUNDLE_ANALYSIS.md).
 *
 * Field numbers below were VERIFIED by decoding the base64 FileDescriptorProto
 * embedded in module 2029 of entry-ebca9276d77e452faa3c6dfcfa0fd7b8.js:
 *
 *   NoiseTransportFrame { chunk_id=1:int64, chunk_index=2:uint32,
 *                         total_chunks=3:uint32, payload=4:bytes }
 *   StreamChunk         { data=1:bytes, final=2:bool, seq=3:uint32 }
 *   WebsocketRequest    { id=1:int64, verb=2:string, path=3:string,
 *                         body=4:bytes, chunk=5:StreamChunk }
 *   WebsocketResponse   { id=1:int64, status=2:int32, body=3:bytes,
 *                         headers=4:map<string,string> }
 */
import {
  ProtoReader,
  ProtoWriter,
  WireType,
  concat,
} from './wire.js';
import { UpstreamProtocolChangedError } from '../errors.js';

/** Iterate the fields of a TOP-LEVEL protobuf message (no length prefix). */
function forEachField(
  bytes: Uint8Array,
  handle: (reader: ProtoReader, fieldNumber: number, wireType: number) => void,
): void {
  const reader = new ProtoReader(bytes);
  for (;;) {
    const field = reader.nextField();
    if (!field) break;
    handle(reader, field.fieldNumber, field.wireType);
  }
}

export const NOISE_TRANSPORT_FRAME = {
  chunkId: 1,
  chunkIndex: 2,
  totalChunks: 3,
  payload: 4,
} as const;

export const WEBSOCKET_REQUEST = {
  id: 1,
  verb: 2,
  path: 3,
  body: 4,
  chunk: 5,
} as const;

export const STREAM_CHUNK = {
  data: 1,
  final: 2,
  seq: 3,
} as const;

export const WEBSOCKET_RESPONSE = {
  id: 1,
  status: 2,
  body: 3,
  headers: 4,
} as const;

export interface NoiseTransportFrame {
  chunkId: bigint;
  chunkIndex: number;
  totalChunks: number;
  payload: Uint8Array;
}

export interface StreamChunk {
  data: Uint8Array;
  final: boolean;
  seq: number;
}

export interface WebsocketRequest {
  id: bigint;
  verb: string;
  path: string;
  body?: Uint8Array;
  chunk?: StreamChunk;
}

export interface WebsocketResponse {
  id: bigint;
  status: number;
  body?: Uint8Array;
  headers: Map<string, string>;
}

export function encodeNoiseTransportFrame(frame: NoiseTransportFrame): Uint8Array {
  const w = new ProtoWriter();
  w.uint64Field(NOISE_TRANSPORT_FRAME.chunkId, frame.chunkId);
  w.uint64Field(NOISE_TRANSPORT_FRAME.chunkIndex, frame.chunkIndex);
  w.uint64Field(NOISE_TRANSPORT_FRAME.totalChunks, frame.totalChunks);
  w.bytesField(NOISE_TRANSPORT_FRAME.payload, frame.payload);
  return w.finish();
}

export function decodeNoiseTransportFrame(bytes: Uint8Array): NoiseTransportFrame {
  let chunkId = 0n;
  let chunkIndex = 0;
  let totalChunks = 0;
  let payload: Uint8Array = new Uint8Array(0);
  const r = new ProtoReader(bytes);
  for (;;) {
    const field = r.nextField();
    if (!field) break;
    if (field.wireType !== WireType.Varint && field.wireType !== WireType.LengthDelimited) {
      throw new UpstreamProtocolChangedError('Unexpected wire type in NoiseTransportFrame.');
    }
    switch (field.fieldNumber) {
      case NOISE_TRANSPORT_FRAME.chunkId:
        chunkId = r.readInt64();
        break;
      case NOISE_TRANSPORT_FRAME.chunkIndex:
        chunkIndex = r.readUint32();
        break;
      case NOISE_TRANSPORT_FRAME.totalChunks:
        totalChunks = r.readUint32();
        break;
      case NOISE_TRANSPORT_FRAME.payload:
        payload = r.readBytes();
        break;
      default:
        r.skip(field.wireType);
    }
  }
  return { chunkId, chunkIndex, totalChunks, payload };
}

function encodeStreamChunk(chunk: StreamChunk): Uint8Array {
  const w = new ProtoWriter();
  w.bytesField(STREAM_CHUNK.data, chunk.data);
  w.boolField(STREAM_CHUNK.final, chunk.final);
  w.uint64Field(STREAM_CHUNK.seq, chunk.seq);
  return w.finish();
}

function decodeStreamChunk(bytes: Uint8Array): StreamChunk {
  let data: Uint8Array = new Uint8Array(0);
  let final = false;
  let seq = 0;
  forEachField(bytes, (r, fieldNumber, wireType) => {
    switch (fieldNumber) {
      case STREAM_CHUNK.data:
        data = r.readBytes();
        break;
      case STREAM_CHUNK.final:
        final = r.readBool();
        break;
      case STREAM_CHUNK.seq:
        seq = r.readUint32();
        break;
      default:
        r.skip(wireType);
    }
  });
  return { data, final, seq };
}

export function encodeWebsocketRequest(request: WebsocketRequest): Uint8Array {
  const w = new ProtoWriter();
  w.uint64Field(WEBSOCKET_REQUEST.id, request.id);
  w.stringField(WEBSOCKET_REQUEST.verb, request.verb);
  w.stringField(WEBSOCKET_REQUEST.path, request.path);
  if (request.body) w.bytesField(WEBSOCKET_REQUEST.body, request.body);
  if (request.chunk) w.messageField(WEBSOCKET_REQUEST.chunk, encodeStreamChunk(request.chunk));
  return w.finish();
}

export function decodeWebsocketRequest(bytes: Uint8Array): WebsocketRequest {
  let id = 0n;
  let verb = '';
  let path = '';
  let body: Uint8Array | undefined;
  let chunk: StreamChunk | undefined;
  forEachField(bytes, (r, fieldNumber, wireType) => {
    switch (fieldNumber) {
      case WEBSOCKET_REQUEST.id:
        id = r.readInt64();
        break;
      case WEBSOCKET_REQUEST.verb:
        verb = r.readString();
        break;
      case WEBSOCKET_REQUEST.path:
        path = r.readString();
        break;
      case WEBSOCKET_REQUEST.body:
        body = r.readBytes();
        break;
      case WEBSOCKET_REQUEST.chunk:
        chunk = decodeStreamChunk(r.readBytes());
        break;
      default:
        r.skip(wireType);
    }
  });
  const result: WebsocketRequest = { id, verb, path };
  if (body) result.body = body;
  if (chunk) result.chunk = chunk;
  return result;
}

export function encodeWebsocketResponse(response: WebsocketResponse): Uint8Array {
  const w = new ProtoWriter();
  w.uint64Field(WEBSOCKET_RESPONSE.id, response.id);
  w.uint64Field(WEBSOCKET_RESPONSE.status, response.status);
  if (response.body) w.bytesField(WEBSOCKET_RESPONSE.body, response.body);
  for (const [key, value] of response.headers) {
    const entry = new ProtoWriter()
      .stringField(1, key)
      .stringField(2, value)
      .finish();
    w.messageField(WEBSOCKET_RESPONSE.headers, entry);
  }
  return w.finish();
}

export function decodeWebsocketResponse(bytes: Uint8Array): WebsocketResponse {
  let id = 0n;
  let status = 0;
  let body: Uint8Array | undefined;
  const headers = new Map<string, string>();
  forEachField(bytes, (r, fieldNumber, wireType) => {
    switch (fieldNumber) {
      case WEBSOCKET_RESPONSE.id:
        id = r.readInt64();
        break;
      case WEBSOCKET_RESPONSE.status:
        status = Number(r.readInt64() & 0xffff_ffffn) | 0;
        break;
      case WEBSOCKET_RESPONSE.body:
        body = r.readBytes();
        break;
      case WEBSOCKET_RESPONSE.headers:
        r.readMessage((entry, entryField, entryWireType) => {
          if (entryField === 1) headers.set(entry.readString(), '');
          else if (entryField === 2) {
            const lastKey = [...headers.keys()].pop();
            if (!lastKey) throw new UpstreamProtocolChangedError('Map value before key.');
            headers.set(lastKey, entry.readString());
          } else entry.skip(entryWireType);
        });
        break;
      default:
        r.skip(wireType);
    }
  });
  const result: WebsocketResponse = { id, status, headers };
  if (body) result.body = body;
  return result;
}

/** Re-encode a decoded frame's payload pieces back into one buffer. */
export function concatPayloads(chunks: readonly Uint8Array[]): Uint8Array {
  return concat(chunks);
}
