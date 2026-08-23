/**
 * Protobuf codec round trips for the four transport messages, including
 * varint edge cases (negative int64 ids, large payloads) and map headers.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  decodeNoiseTransportFrame,
  decodeWebsocketRequest,
  decodeWebsocketResponse,
  encodeNoiseTransportFrame,
  encodeWebsocketRequest,
  encodeWebsocketResponse,
} from '../src/confer/proto/messages.js';
import { encodeVarint, ProtoReader, WireType } from '../src/confer/proto/wire.js';

test('varint encodes boundary values', () => {
  assert.deepEqual([...encodeVarint(0)], [0]);
  assert.deepEqual([...encodeVarint(127)], [0x7f]);
  assert.deepEqual([...encodeVarint(128)], [0x80, 0x01]);
  assert.equal(encodeVarint(-1n).length, 10); // negative int64 -> 10-byte varint
});

test('reader rejects truncated varints', () => {
  const reader = new ProtoReader(new Uint8Array([0x80]));
  assert.throws(() => reader.readVarint());
});

test('NoiseTransportFrame round trip', () => {
  const frame = {
    chunkId: -5n,
    chunkIndex: 3,
    totalChunks: 7,
    payload: new Uint8Array([1, 2, 3, 4, 5]),
  };
  const decoded = decodeNoiseTransportFrame(encodeNoiseTransportFrame(frame));
  assert.deepEqual(decoded, frame);
});

test('WebsocketRequest round trip with and without optional fields', () => {
  const chunk = { data: new Uint8Array([9, 9]), final: true, seq: 2 };
  const full = { id: 42n, verb: 'POST', path: '/v1/vllm/chat/completions', body: new Uint8Array([7]), chunk };
  assert.deepEqual(decodeWebsocketRequest(encodeWebsocketRequest(full)), full);

  const minimal = { id: 1n, verb: 'GET', path: '/ping' };
  assert.deepEqual(decodeWebsocketRequest(encodeWebsocketRequest(minimal)), minimal);
});

test('WebsocketResponse round trip with headers map', () => {
  const response = {
    id: -12345678901234n,
    status: 200,
    body: new TextEncoder().encode('{"ok":true}'),
    headers: new Map([['content-type', 'application/json'], ['x-trace', 'abc']]),
  };
  const decoded = decodeWebsocketResponse(encodeWebsocketResponse(response));
  assert.equal(decoded.id, response.id);
  assert.equal(decoded.status, response.status);
  assert.deepEqual(decoded.body, response.body);
  assert.deepEqual(new Map(decoded.headers), response.headers);
});

test('unknown fields are skipped without error', () => {
  // Hand-assemble a frame with an extra unknown field (number 99, varint).
  const base = encodeNoiseTransportFrame({ chunkId: 1n, chunkIndex: 0, totalChunks: 1, payload: new Uint8Array([1]) });
  const extra = new Uint8Array([...base, ...encodeTagRaw(99, WireType.Varint), 0x2a]);
  const decoded = decodeNoiseTransportFrame(extra);
  assert.equal(decoded.chunkIndex, 0);
  assert.deepEqual([...decoded.payload], [1]);
});

function encodeTagRaw(fieldNumber: number, wireType: number): number[] {
  return [...encodeVarint((fieldNumber << 3) | wireType)];
}
