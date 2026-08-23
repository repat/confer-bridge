/**
 * Framer tests: chunking at the 65,489-byte cap, reassembly (including
 * out-of-order delivery), duplicate/gap detection, and multi-stream isolation.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomBytes } from 'node:crypto';
import { chunkPayload, encodeFrames, FrameReassembler, FRAME_PAYLOAD_CAP } from '../src/confer/framer.js';
import { decodeNoiseTransportFrame } from '../src/confer/proto/messages.js';
import { TransportFrameError, UpstreamProtocolChangedError } from '../src/confer/errors.js';

test('small payloads produce a single frame', () => {
  const frames = chunkPayload(1n, new Uint8Array([1, 2, 3]));
  assert.equal(frames.length, 1);
  assert.equal(frames[0]!.totalChunks, 1);
});

test('empty payloads still produce one frame', () => {
  const frames = chunkPayload(1n, new Uint8Array(0));
  assert.equal(frames.length, 1);
});

test('large payloads are split at the documented cap', () => {
  const payload = new Uint8Array(FRAME_PAYLOAD_CAP * 2 + 100);
  const frames = chunkPayload(7n, payload);
  assert.equal(frames.length, 3);
  assert.ok(frames.every((f) => f.payload.length <= FRAME_PAYLOAD_CAP));
  assert.ok(frames.every((f) => f.chunkId === 7n));
  assert.deepEqual(
    frames.map((f) => f.chunkIndex),
    [0, 1, 2],
  );
});

test('reassembly round trips a large payload', () => {
  const payload = new Uint8Array(randomBytes(FRAME_PAYLOAD_CAP * 2 + 5));
  const reassembler = new FrameReassembler();
  let result: Uint8Array | null = null;
  for (const encoded of encodeFrames(chunkPayload(9n, payload))) {
    result = reassembler.push(decodeNoiseTransportFrame(encoded));
  }
  assert.ok(result);
  assert.equal(Buffer.from(result).equals(Buffer.from(payload)), true);
  assert.equal(reassembler.pendingStreams, 0);
});

test('out-of-order chunks reassemble correctly', () => {
  const payload = new Uint8Array(FRAME_PAYLOAD_CAP + 10); // two chunks
  const frames = chunkPayload(3n, payload);
  assert.equal(frames.length, 2);
  const reassembler = new FrameReassembler();
  let result: Uint8Array | null = reassembler.push(frames[1]!);
  assert.equal(result, null); // not complete until index 0 arrives
  result = reassembler.push(frames[0]!);
  assert.ok(result);
  assert.equal(Buffer.from(result).equals(Buffer.from(payload)), true);
});

test('duplicate chunks are rejected', () => {
  const frames = chunkPayload(1n, new Uint8Array(FRAME_PAYLOAD_CAP + 1)); // two chunks
  const reassembler = new FrameReassembler();
  reassembler.push(frames[0]!);
  assert.throws(() => reassembler.push(frames[0]!), TransportFrameError);
});

test('conflicting total_chunks for one id is rejected', () => {
  const reassembler = new FrameReassembler();
  reassembler.push({ chunkId: 1n, chunkIndex: 0, totalChunks: 2, payload: new Uint8Array([1]) });
  assert.throws(
    () => reassembler.push({ chunkId: 1n, chunkIndex: 1, totalChunks: 3, payload: new Uint8Array([2]) }),
    UpstreamProtocolChangedError,
  );
});

test('chunk_index beyond total_chunks is rejected', () => {
  const reassembler = new FrameReassembler();
  assert.throws(
    () => reassembler.push({ chunkId: 1n, chunkIndex: 5, totalChunks: 2, payload: new Uint8Array([1]) }),
    UpstreamProtocolChangedError,
  );
});
