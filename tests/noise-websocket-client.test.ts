/**
 * Loopback integration tests for NoiseWebsocketClient: a fake in-memory
 * WebSocket server completes the responder side of the handshake and serves a
 * real attestation envelope (Intel-style JWT + manifest + sigstore bundle,
 * produced by the shared fixtures). Verifies that attestation validation
 * gates message three and that rejections close the socket.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bytesToHex } from '@noble/hashes/utils.js';
import { NoiseWebsocketClient, type WebSocketLike } from '../src/confer/noise-websocket-client.js';
import { NoiseXXResponder } from '../src/confer/noise/handshake.js';
import { generateKeypair } from '../src/confer/noise/symmetric-state.js';
import { TdxAttestationValidator } from '../src/confer/noise/attestation.js';
import {
  decodeNoiseTransportFrame,
  encodeNoiseTransportFrame,
  encodeWebsocketResponse,
  decodeWebsocketRequest,
} from '../src/confer/proto/messages.js';
import { AttestationRejectedError, ConnectionClosedError, HandshakeFailedError, RequestTimeoutError } from '../src/confer/errors.js';
import { createAttestationFixture, type AttestationFixture } from './helpers/attestation-fixtures.js';

interface FixtureState {
  fixture: AttestationFixture;
  validator: TdxAttestationValidator;
}

let state: FixtureState;

test.before(async () => {
  const fixture = await createAttestationFixture();
  state = {
    fixture,
    validator: new TdxAttestationValidator({
      jwks: fixture.jwks,
      sigstoreVerifierFactory: fixture.verifierFactory,
    }),
  };
});

class FakeSocket implements WebSocketLike {
  private messageListeners: Array<(data: Uint8Array) => void> = [];
  private closeListeners: Array<(code: number, reason: string) => void> = [];
  private errorListeners: Array<(error: Error) => void> = [];
  private openListeners: Array<() => void> = [];
  /** Messages delivered before any listener attached (synchronous servers). */
  private inbox: Uint8Array[] = [];
  sent: Uint8Array[] = [];
  closed = false;
  onSend?: (data: Uint8Array) => void;

  send(data: Uint8Array): void {
    const copy = new Uint8Array(data);
    this.sent.push(copy);
    this.onSend?.(copy);
  }

  close(): void {
    this.closed = true;
  }

  onOpen(listener: () => void): void { this.openListeners.push(listener); }

  onMessage(listener: (data: Uint8Array) => void): void {
    this.messageListeners.push(listener);
    const buffered = this.inbox.splice(0);
    for (const data of buffered) listener(data);
  }

  onClose(listener: (code: number, reason: string) => void): void { this.closeListeners.push(listener); }
  onError(listener: (error: Error) => void): void { this.errorListeners.push(listener); }

  emitOpen(): void { this.openListeners.forEach((l) => l()); }
  emitMessage(data: Uint8Array): void {
    if (this.messageListeners.length === 0) {
      this.inbox.push(new Uint8Array(data));
      return;
    }
    this.messageListeners.forEach((l) => l(data));
  }
  emitClose(code = 1000, reason = ''): void { this.closeListeners.forEach((l) => l(code, reason)); }
}

interface FakeServerOptions {
  /** Serve an envelope bound to a foreign key (forces rejection). */
  bindForeign?: boolean;
  platform?: string;
}

/** In-memory responder speaking XX handshake plus one-shot request handling. */
async function makeFakeServer(options: FakeServerOptions = {}) {
  const staticKeypair = generateKeypair();
  const responder = new NoiseXXResponder(staticKeypair);
  let step: 0 | 1 | 2 | 3 = 0;
  let session: ReturnType<NoiseXXResponder['split']> | null = null;

  const bindingKey = options.bindForeign ? generateKeypair().publicKey : staticKeypair.publicKey;
  const attestationPayload = await state.fixture.buildEnvelope({
    remoteStaticKeyHex: bytesToHex(bindingKey),
    platform: options.platform,
  });

  return {
    staticPublicKey: staticKeypair.publicKey,
    sawMessageThree: () => step >= 3,
    receivedMessageOne: () => step >= 1,
    handle(data: Uint8Array, reply: (data: Uint8Array) => void): void {
      if (step === 0) {
        responder.readMessageOne(data);
        step = 1;
        reply(responder.writeMessageTwo(attestationPayload));
        return;
      }
      if (step === 1) {
        responder.readMessageThree(data);
        step = 2;
        // Transport is live only once msg3 is processed AND split() below;
        // mirror intoTransportMode by marking complete.
        session = responder.split();
        step = 3;
        return;
      }
      if (!session) throw new Error('no session');
      const plaintext = session.readMessage(data);
      const frame = decodeNoiseTransportFrame(plaintext);
      const request = decodeWebsocketRequest(frame.payload);
      assert.equal(request.path.startsWith('/'), true);
      const responseBytes = encodeWebsocketResponse({
        id: request.id,
        status: 200,
        body: new TextEncoder().encode('{"answer":"confer-protocol-test"}'),
        headers: new Map([['content-type', 'application/json']]),
      });
      reply(session.writeMessage(
        encodeNoiseTransportFrame({ chunkId: 1n, chunkIndex: 0, totalChunks: 1, payload: responseBytes }),
      ));
    },
  };
}

function wireClient(
  socket: FakeSocket,
  server: Awaited<ReturnType<typeof makeFakeServer>>,
  onHandshakeTrace?: (event: import('../src/confer/noise-websocket-client.js').HandshakeTraceEvent) => void,
): NoiseWebsocketClient {
  const client = new NoiseWebsocketClient({
    token: 'test-model-session-token',
    url: 'wss://loopback.test/websocket',
    validator: state.validator,
    socketFactory: () => socket,
    ...(onHandshakeTrace ? { onHandshakeTrace } : {}),
  });
  socket.onSend = (data) => server.handle(data, (reply) => socket.emitMessage(reply));
  return client;
}

test('client completes attested handshake and round-trips a request', async () => {
  const socket = new FakeSocket();
  const server = await makeFakeServer();
  const client = wireClient(socket, server);

  const connectPromise = client.connect().then(() =>
    client.request('POST', '/v1/vllm/chat/completions', new TextEncoder().encode('{"prompt":"ping"}')),
  );
  socket.emitOpen();

  const response = await connectPromise;
  assert.equal(server.sawMessageThree(), true);
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, new TextEncoder().encode('{"answer":"confer-protocol-test"}'));
  client.close();
});

test('handshake trace events fire in order with spec-sized messages', async () => {
  const socket = new FakeSocket();
  const server = await makeFakeServer();
  const events: import('../src/confer/noise-websocket-client.js').HandshakeTraceEvent[] = [];
  const client = wireClient(socket, server, (event) => events.push(event));

  const connectPromise = client.connect();
  socket.emitOpen();
  await connectPromise;

  assert.deepEqual(events.map((e) => e.step), [
    'message-one-sent',
    'message-two-received',
    'attestation-validated',
    'message-three-sent',
    'established',
  ]);
  // XX sizes with empty payloads per module 1970 evidence.
  const first = events[0]!;
  const second = events[1]!;
  assert.ok(first.step === 'message-one-sent' && first.length === 32);
  assert.ok(second.step === 'message-two-received' && second.length >= 80); // re + encrypted static + payload
  client.close();
});

test('extra records during the handshake phase are traced', async () => {
  const socket = new FakeSocket();
  const server = await makeFakeServer();
  const events: import('../src/confer/noise-websocket-client.js').HandshakeTraceEvent[] = [];
  const client = wireClient(socket, server, (event) => events.push(event));

  // After serving message two, the fake server sends an additional record
  // before the handshake completes — e.g. a server preamble or a fragment.
  let servedMessageTwo = false;
  socket.onSend = (data) => {
    server.handle(data, (reply) => {
      socket.emitMessage(reply);
      if (!servedMessageTwo) {
        servedMessageTwo = true;
        socket.emitMessage(new TextEncoder().encode('unexpected-preamble-record'));
      }
    });
  };
  const connectPromise = client.connect().then(() =>
    client.request('POST', '/v1/vllm/chat/completions'),
  );
  socket.emitOpen();

  await connectPromise;
  const extra = events.filter((e) => e.step === 'handshake-extra-record');
  assert.equal(extra.length, 1);
  assert.ok(extra[0]!.step === 'handshake-extra-record' && extra[0]!.length === 26);
  client.close();
});

test('AEAD failure trace carries a printable-text preview when the peer replies with text', async () => {
  const socket = new FakeSocket();
  const server = await makeFakeServer({ bindForeign: true });
  const events: import('../src/confer/noise-websocket-client.js').HandshakeTraceEvent[] = [];

  const client = new NoiseWebsocketClient({
    token: 'test-model-session-token',
    url: 'wss://loopback.test/websocket',
    validator: state.validator,
    socketFactory: () => socket,
    onHandshakeTrace: (event) => events.push(event),
  });
  // Serve a plain-text rejection instead of message two, like the production
  // server does for an invalid token. It must be >=64 bytes to reach the
  // keyed static-key decrypt (anything shorter is rejected as truncated).
  const fakeError = JSON.stringify({
    error: 'invalid or expired token',
    detail: 'x'.repeat(48),
  });
  socket.onSend = (data) => {
    if (!server.receivedMessageOne()) {
      // Consume message one but replace its reply with a plain-text error.
      server.handle(data, () => undefined);
      socket.emitMessage(new TextEncoder().encode(fakeError));
    }
  };
  const connectPromise = client.connect();
  socket.emitOpen();

  await assert.rejects(connectPromise, HandshakeFailedError);
  const failure = events.find((e) => e.step === 'message-two-aead-failed');
  assert.ok(failure && failure.step === 'message-two-aead-failed');
  assert.equal(failure.utf8Preview, fakeError);
  assert.equal(server.sawMessageThree(), false);
});

test('attestation gate runs before message three is sent', async () => {
  const socket = new FakeSocket();
  // Envelope binds a foreign key -> validation fails before msg3 leaves.
  const server = await makeFakeServer({ bindForeign: true });
  const client = wireClient(socket, server);

  const connectPromise = client.connect();
  socket.emitOpen();
  await assert.rejects(connectPromise, AttestationRejectedError);
  assert.equal(server.sawMessageThree(), false);
  assert.equal(socket.sent.length, 1); // only message one was sent
  assert.equal(socket.closed, true);
});

test('client rejects SEV-SNP attestations end to end', async () => {
  const socket = new FakeSocket();
  const server = await makeFakeServer({ platform: 'SEV-SNP' });
  const client = wireClient(socket, server);

  const connectPromise = client.connect();
  socket.emitOpen();
  await assert.rejects(connectPromise, AttestationRejectedError);
  assert.equal(server.sawMessageThree(), false);
});

test('pending requests reject with the server close reason when the socket closes', async () => {
  const socket = new FakeSocket();
  const server = await makeFakeServer();
  const client = wireClient(socket, server);

  const connectPromise = client.connect();
  socket.emitOpen();
  await connectPromise;

  // Swallow transport sends so the request cannot be answered, then close.
  socket.onSend = () => undefined;
  const requestPromise = client.request('POST', '/v1/vllm/chat/completions');
  socket.emitClose(1011, 'upstream vllm failed');
  await assert.rejects(requestPromise, ConnectionClosedError);
  client.close();
});

test('requests that never receive a response time out', async () => {
  const socket = new FakeSocket();
  const server = await makeFakeServer();
  const client = new NoiseWebsocketClient({
    token: 'test-model-session-token',
    url: 'wss://loopback.test/websocket',
    validator: state.validator,
    socketFactory: () => socket,
    requestTimeoutMs: 50,
  });
  // Serve the handshake normally, then swallow transport replies.
  socket.onSend = (data) => {
    if (!server.sawMessageThree()) {
      server.handle(data, (reply) => socket.emitMessage(reply));
    }
  };

  const connectPromise = client.connect();
  socket.emitOpen();
  await connectPromise;

  // Hold the event loop open so the unref'd response timer can fire.
  const keepAlive = setTimeout(() => undefined, 250);
  await assert.rejects(
    client.request('GET', '/ping'),
    (error: unknown) => error instanceof RequestTimeoutError && error.timeoutMs === 50,
  );
  clearTimeout(keepAlive);
  client.close();
});

test('missing token is rejected before any connection attempt', () => {
  assert.throws(
    () =>
      new NoiseWebsocketClient({
        token: '',
        validator: state.validator,
      }),
  );
});
