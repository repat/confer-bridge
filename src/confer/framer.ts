/**
 * Chunked framing of protobuf payloads inside the Noise transport.
 *
 * Evidence basis: docs/FRONTEND_BUNDLE_ANALYSIS.md (module 1971). A logical
 * payload is serialized protobuf, wrapped in one or more NoiseTransportFrame
 * messages, then encrypted with Noise. The frame payload cap is 65,489 bytes
 * (65,519 - 30). Responses are reassembled by chunk_id and chunk_index before
 * protobuf decoding.
 */
import {
  decodeNoiseTransportFrame,
  encodeNoiseTransportFrame,
  type NoiseTransportFrame,
} from './proto/messages.js';
import { concat } from './proto/wire.js';
import { TransportFrameError, UpstreamProtocolChangedError } from './errors.js';

export const FRAME_PAYLOAD_CAP = 65_489;

export interface EncodedChunk extends NoiseTransportFrame {}

export function chunkPayload(chunkId: bigint, payload: Uint8Array): EncodedChunk[] {
  if (payload.length === 0) {
    return [{ chunkId, chunkIndex: 0, totalChunks: 1, payload }];
  }
  const totalChunks = Math.ceil(payload.length / FRAME_PAYLOAD_CAP);
  if (totalChunks > 0xffff_ffff) throw new UpstreamProtocolChangedError('Payload requires too many chunks.');
  const frames: EncodedChunk[] = [];
  for (let index = 0; index < totalChunks; index++) {
    frames.push({
      chunkId,
      chunkIndex: index,
      totalChunks,
      payload: payload.subarray(index * FRAME_PAYLOAD_CAP, (index + 1) * FRAME_PAYLOAD_CAP),
    });
  }
  return frames;
}

export function encodeFrames(frames: readonly EncodedChunk[]): Uint8Array[] {
  return frames.map(encodeNoiseTransportFrame);
}

/** Reassembles framed payloads keyed by chunk_id, tolerating out-of-order arrival. */
export class FrameReassembler {
  private readonly streams = new Map<
    bigint,
    { total: number; received: Map<number, Uint8Array> }
  >();

  /** Feed one decoded frame; returns the complete payload when finished. */
  push(frame: NoiseTransportFrame): Uint8Array | null {
    if (frame.totalChunks === 0 || frame.totalChunks > 0xffff_ffff) {
      throw new UpstreamProtocolChangedError('Invalid total_chunks in frame.');
    }
    if (frame.chunkIndex >= frame.totalChunks) {
      throw new UpstreamProtocolChangedError('chunk_index exceeds total_chunks.');
    }
    let stream = this.streams.get(frame.chunkId);
    if (!stream) {
      stream = { total: frame.totalChunks, received: new Map() };
      this.streams.set(frame.chunkId, stream);
    }
    if (stream.total !== frame.totalChunks) {
      throw new UpstreamProtocolChangedError('Conflicting total_chunks for a chunk_id.');
    }
    if (stream.received.has(frame.chunkIndex)) {
      throw new TransportFrameError(`Duplicate chunk_index ${frame.chunkIndex} for chunk_id ${frame.chunkId}.`);
    }
    stream.received.set(frame.chunkIndex, frame.payload);
    if (stream.received.size === stream.total) {
      this.streams.delete(frame.chunkId);
      const parts: Uint8Array[] = [];
      for (let i = 0; i < stream.total; i++) parts.push(stream.received.get(i)!);
      return concat(parts);
    }
    return null;
  }

  /** Number of incomplete streams currently buffered. */
  get pendingStreams(): number {
    return this.streams.size;
  }
}
