/**
 * ConferClient lifecycle tests against the in-memory Noise loopback server:
 * concurrent connect() sharing one attempt, lazy reconnection after close()
 * (regression: stale clients crashed with a TypeError on a null transport
 * instead of re-establishing), and reconnectable transport errors.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bytesToHex } from '@noble/hashes/utils.js';
import type { WebSocketLike } from '../src/confer/noise-websocket-client.js';
import { NoiseXXResponder } from '../src/confer/noise/handshake.js';
import { generateKeypair } from '../src/confer/noise/symmetric-state.js';
import { TdxAttestationValidator } from '../src/confer/noise/attestation.js';
import { ConferClient, type ModelSessionTokenProvider } from '../src/confer/client.js';
import {
  decodeNoiseTransportFrame,
  encodeNoiseTransportFrame,
  encodeWebsocketResponse,
  decodeWebsocketRequest,
} from '../src/confer/proto/messages.js';
import { ConnectionClosedError, TransportFrameError } from '../src/confer/errors.js';
import { createAttestationFixture, type AttestationFixture } from './helpers/attestation-fixtures.js';

let fixture: AttestationFixture;
let validator: TdxAttestationValidator;

test.before(async () => {
  fixture = await createAttestationFixture();
  validator = new TdxAttestationValidator({
    jwks: fixture.jwks,
    sigstoreVerifierFactory: fixture.verifierFactory,
  });
});

/** In-memory WebSocket mirroring the loopback fakes used elsewhere. */
class FakeSocket implements WebSocketLike {
  private messageListeners: Array<(data: Uint8Array) => void> = [];
  private openListeners: Array<() => void> = [];
  private closeListeners: Array<(code: number, reason: string) => void> = [];
  private inbox: Uint8Array[] = [];
  sent: Uint8Array[] = [];
  onSend?: (data: Uint8Array) => void;
  /** Fire the open event automatically once a listener attaches. */
  autoOpen = false;

  send(data: Uint8Array): void {
    const copy = new Uint8Array(data);
    this.sent.push(copy);
    this.onSend?.(copy);
  }

  close(): void {}
  onOpen(listener: () => void): void {
    this.openListeners.push(listener);
    if (this.autoOpen) setTimeout(() => this.emitOpen(), 0);
  }
  onMessage(listener: (data: Uint8Array) => void): void {
    this.messageListeners.push(listener);
    for (const data of this.inbox.splice(0)) listener(data);
  }
  onClose(listener: (code: number, reason: string) => void): void { this.closeListeners.push(listener); }
  onError(): void {}

  emitClose(code = 1000, reason = ''): void { this.closeListeners.forEach((l) => l(code, reason)); }

  emitOpen(): void { this.openListeners.forEach((l) => l()); }
  emitMessage(data: Uint8Array): void {
    if (this.messageListeners.length === 0) {
      this.inbox.push(new Uint8Array(data));
      return;
    }
    this.messageListeners.forEach((l) => l(data));
  }
}

interface Loopback {
  sockets: FakeSocket[];
  /** Fail (silently drop) all traffic from the Nth socket onwards. */
  deadFrom: number;
}

/**
 * Serves one attested handshake per socket plus transport-mode requests.
 * Streaming requests get a terminal `completion` event; anything else gets
 * the canned JSON answer.
 */
function makeLoopback(streamBody = '{"type":"completion"}'): {
  loopback: Loopback;
  socketFactory: (url: string) => WebSocketLike;
} {
  const loopback: Loopback = { sockets: [], deadFrom: Number.MAX_SAFE_INTEGER };

  const serve = async (socket: FakeSocket, index: number): Promise<void> => {
    const staticKeypair = generateKeypair();
    const responder = new NoiseXXResponder(staticKeypair);
    let step: 0 | 1 | 2 = 0;
    let session: ReturnType<NoiseXXResponder['split']> | null = null;

    // Buffer peer traffic until the attestation envelope is ready, so a fast
    // open/message-one race cannot lose the handshake.
    const buffered: Uint8Array[] = [];
    socket.onSend = (data) => buffered.push(data);

    const attestationPayload = await fixture.buildEnvelope({
      remoteStaticKeyHex: bytesToHex(staticKeypair.publicKey),
    });

    const handle = (data: Uint8Array): void => {
      if (index >= loopback.deadFrom) return; // simulate a dead peer
      if (step === 0) {
        responder.readMessageOne(data);
        step = 1;
        socket.emitMessage(responder.writeMessageTwo(attestationPayload));
        return;
      }
      if (step === 1) {
        responder.readMessageThree(data);
        session = responder.split();
        step = 2;
        return;
      }
      if (!session) throw new Error('no session');
      const plaintext = session.readMessage(data);
      const frame = decodeNoiseTransportFrame(plaintext);
      const request = decodeWebsocketRequest(frame.payload);
      const body = request.path === '/v1/vllm/chat/completions'
        ? new TextEncoder().encode(streamBody)
        : new TextEncoder().encode('{"ok":true}');
      socket.emitMessage(session.writeMessage(
        encodeNoiseTransportFrame({
          chunkId: 1n,
          chunkIndex: 0,
          totalChunks: 1,
          payload: encodeWebsocketResponse({ id: request.id, status: 200, body, headers: new Map() }),
        }),
      ));
    };

    socket.onSend = (data) => handle(data);
    for (const data of buffered.splice(0)) handle(data);
  };

  return {
    loopback,
    socketFactory: (_url: string): WebSocketLike => {
      const socket = new FakeSocket();
      socket.autoOpen = true;
      const index = loopback.sockets.push(socket) - 1;
      void serve(socket, index);
      return socket;
    },
  };
}

function tokenProvider(counter: { count: number }): ModelSessionTokenProvider {
  return {
    async getToken(): Promise<string> {
      counter.count++;
      return 'test-model-session-token';
    },
  };
}

test('concurrent connects share one token fetch and one connection', async () => {
  const { socketFactory } = makeLoopback();
  const counter = { count: 0 };
  const client = new ConferClient({ tokenProvider: tokenProvider(counter), validator, socketFactory });

  const connectPromise = client.connect();
  // A second caller racing the first must join the in-flight attempt.
  await Promise.all([connectPromise, client.connect()]);

  assert.equal(counter.count, 1);
  assert.equal(client.isConnected, true);
  client.close();
  assert.equal(client.isConnected, false);
});

test('requests after close() lazily reconnect instead of crashing on a null transport', async () => {
  // Regression: the facade reconnect path reused a closed ConferClient whose
  // noiseClient was null, surfacing as:
  //   Cannot read properties of null (reading 'requestStreaming')
  const { socketFactory } = makeLoopback('{"type":"completion"}');
  const counter = { count: 0 };
  const client = new ConferClient({ tokenProvider: tokenProvider(counter), validator, socketFactory });

  await client.connect();
  assert.equal(counter.count, 1);
  client.close();

  // Stale handle: a stream request must transparently re-establish.
  await client.chatCompletionStream([{ role: 'user', content: 'hi' }], () => undefined);
  assert.equal(client.isConnected, true);
  assert.equal(counter.count, 2); // fresh token, fresh session
  client.close();
});

test('a dead peer surfaces ConnectionClosedError, which stays reconnectable', async () => {
  const { loopback, socketFactory } = makeLoopback();
  const counter = { count: 0 };
  const client = new ConferClient({ tokenProvider: tokenProvider(counter), validator, socketFactory });

  await client.connect();
  loopback.deadFrom = 1; // first socket goes dark; a reconnect would use socket #2
  loopback.sockets[0]!.emitClose(1011, 'peer vanished');

  // Either flavor is fine: both names are in the facade's reconnectable set.
  await assert.rejects(
    client.chatCompletion([{ role: 'user', content: 'hi' }], {}),
    (error: unknown) => error instanceof ConnectionClosedError || error instanceof TransportFrameError,
  );
  client.close();
});
