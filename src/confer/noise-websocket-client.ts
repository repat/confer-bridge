/**
 * Authenticated, attested WebSocket transport for confer.to inference.
 *
 * Evidence basis: docs/FRONTEND_BUNDLE_ANALYSIS.md (modules 1958, 1959).
 * Flow:
 *   1. connect to wss://inference.confer.to/websocket?token=<model-session token>
 *   2. Noise_XX_25519_AESGCM_SHA256 handshake as initiator
 *   3. parse the first decrypted handshake payload (message two's payload) as
 *      attestation JSON and validate it against the Noise remote static key
 *      BEFORE sending the final handshake message or entering transport mode
 *   4. exchange protobuf-framed application messages over encrypted records
 *
 * The attestation gate has no bypass. A completed Noise handshake alone is
 * not a trusted connection.
 */
import { randomBytes } from 'node:crypto';
import WebSocket from 'ws';
import { NoiseTransportSession, NoiseXXInitiator } from './noise/handshake.js';
import { generateKeypair } from './noise/symmetric-state.js';
import type { AttestationValidator } from './noise/attestation.js';
import {
  decodeNoiseTransportFrame,
  decodeWebsocketResponse,
  encodeNoiseTransportFrame,
  encodeWebsocketRequest,
  type NoiseTransportFrame,
  type WebsocketRequest,
  type WebsocketResponse,
} from './proto/messages.js';
import { chunkPayload, FrameReassembler } from './framer.js';
import {
  AttestationRejectedError,
  ConnectionClosedError,
  HandshakeFailedError,
  PaymentRequiredError,
  RequestTimeoutError,
  SessionTokenError,
  TransportFrameError,
  UpstreamProtocolChangedError,
  UpstreamRequestError,
} from './errors.js';

export const OBSERVED_INFERENCE_WEBSOCKET_URL = 'wss://inference.confer.to/websocket';

export type { WebsocketRequest, WebsocketResponse } from './proto/messages.js';

export interface WebSocketLike {
  send(data: Uint8Array): void;
  close(): void;
  onOpen(listener: () => void): void;
  onMessage(listener: (data: Uint8Array) => void): void;
  onClose(listener: (code: number, reason: string) => void): void;
  onError(listener: (error: Error) => void): void;
}

export interface NoiseWebsocketClientOptions {
  /** Model-session token obtained through an authorized flow. */
  token: string;
  /** Base URL override; defaults to the observed production endpoint. */
  url?: string;
  validator: AttestationValidator;
  /** Injectable socket factory for loopback tests. */
  socketFactory?: (url: string) => WebSocketLike;
  /** Optional per-request timeout override (ms); defaults to 120 s. */
  requestTimeoutMs?: number;
  /**
   * Optional local-only diagnostic hook. Events carry structural facts
   * (step names and byte lengths); never key material or payload bytes.
   */
  onHandshakeTrace?: (event: HandshakeTraceEvent) => void;
}

export type HandshakeTraceEvent =
  | { step: 'message-one-sent'; length: number }
  | { step: 'message-two-received'; length: number }
  | { step: 'handshake-extra-record'; length: number }
  | {
      step: 'message-two-aead-failed';
      length: number;
      /**
       * Set only when the received bytes decode as printable ASCII — a strong
       * signal that the peer answered with a plain-text error (e.g. token
       * rejection) instead of a Noise message.
       */
      utf8Preview?: string;
    }
  | { step: 'attestation-validated' }
  | { step: 'attestation-rejected'; reason: string }
  | { step: 'message-three-sent'; length: number }
  | { step: 'established' };

/** True when every byte decodes as printable ASCII (0x20–0x7E or whitespace). */
function printableAsciiPreview(data: Uint8Array, max = 200): string | undefined {
  for (const byte of data.subarray(0, max)) {
    const printable = (byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d;
    if (!printable) return undefined;
  }
  const text = new TextDecoder().decode(data.subarray(0, max));
  return text.length > 0 ? text : undefined;
}

const HANDSHAKE_TIMEOUT_MS = 15_000;

interface PendingRequest {
  reject: (error: Error) => void;
  /** Resolves with the first response (non-streaming usage). */
  resolveFirst?: (response: WebsocketResponse) => void;
  /** Receives every response; returns true when the stream is complete. */
  onEvent?: (response: WebsocketResponse) => boolean;
  onDone?: () => void;
}

/** Default per-request timeout: model inference can legitimately take a while. */
const DEFAULT_REQUEST_TIMEOUT_MS = 120_000;

export class NoiseWebsocketClient {
  private readonly url: string;
  private readonly validator: AttestationValidator;
  private readonly socketFactory: (url: string) => WebSocketLike;
  private session: NoiseTransportSession | null = null;
  private nextRequestId = 1n;
  private nextChunkId = 1n;
  private keepaliveTimer: ReturnType<typeof setInterval> | null = null;
  private currentSocket: WebSocketLike | null = null;
  private closed = false;
  /** True from connect() until the transport split; used for record tracing. */
  private handshakePhase = false;

  private trace(event: HandshakeTraceEvent): void {
    this.options.onHandshakeTrace?.(event);
  }

  /**
   * Wraps resolve/reject so exactly one settlement happens and the response
   * timeout is cancelled on any settlement (response, close, or error).
   */
  private withSettlement<T>(
    resolve: (value: T) => void,
    reject: (error: Error) => void,
  ): { resolve: (value: T) => void; reject: (error: Error) => void } {
    const timeoutMs = this.options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      reject(new RequestTimeoutError(timeoutMs));
    }, timeoutMs);
    // Never hold the event loop open just for a response timeout.
    timer.unref?.();
    return {
      resolve: (value) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve(value);
      },
      reject: (error) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        reject(error);
      },
    };
  }

  constructor(private readonly options: NoiseWebsocketClientOptions) {
    if (!options.token || options.token.length === 0) throw new SessionTokenError('Missing model-session token.');
    this.url = `${options.url ?? OBSERVED_INFERENCE_WEBSOCKET_URL}?token=${encodeURIComponent(options.token)}`;
    this.validator = options.validator;
    this.socketFactory = options.socketFactory ?? defaultSocketFactory;
  }

  /** Connects, runs the attested handshake, and enters transport mode. */
  async connect(): Promise<void> {
    const socket = this.currentSocket = this.socketFactory(this.url);
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new HandshakeFailedError('WebSocket connection timed out.')), HANDSHAKE_TIMEOUT_MS);
      socket.onOpen(() => {
        clearTimeout(timeout);
        resolve();
      });
      socket.onError((error) => {
        clearTimeout(timeout);
        reject(new HandshakeFailedError(`WebSocket connection failed: ${error.message}`));
      });
    });

    socket.onClose((code, reason) => this.handleClose(code, reason));
    this.handshakePhase = true;
    socket.onMessage((data) => {
      const waiter = this.incomingWaiters.shift();
      if (waiter) {
        waiter(data);
        return;
      }
      if (this.handshakePhase && !this.session) {
        // A record arrived while still handshaking but no one was waiting:
        // evidence of fragmentation or an unexpected server preamble.
        this.trace({ step: 'handshake-extra-record', length: data.length });
      }
      this.handleMessage(data);
    });

    // --- Noise XX handshake, initiator role ---
    const handshake = new NoiseXXInitiator(generateKeypair());

    // Arm the receiver BEFORE sending so a synchronous peer reply is not lost.
    const messageTwoPromise = this.waitForIncoming();
    const messageOne = handshake.writeMessageOne();
    socket.send(messageOne);
    this.trace({ step: 'message-one-sent', length: messageOne.length });

    const messageTwo = await messageTwoPromise;
    this.trace({ step: 'message-two-received', length: messageTwo.length });

    let attestationPayload: Uint8Array;
    try {
      attestationPayload = handshake.readMessageTwo(messageTwo);
    } catch (error) {
      if (error instanceof HandshakeFailedError) {
        // AEAD failure on the keyed static-key decrypt usually means the peer
        // sent something other than Noise message two (e.g. a plain-text
        // token error). Surface a safe preview to confirm.
        const utf8Preview = printableAsciiPreview(messageTwo);
        const event: HandshakeTraceEvent = { step: 'message-two-aead-failed', length: messageTwo.length };
        if (utf8Preview !== undefined) event.utf8Preview = utf8Preview;
        this.trace(event);
      }
      throw error;
    }

    // Gate: validate TDX attestation against the remote static key BEFORE the
    // final handshake message leaves this process.
    try {
      await this.validator.validateFromPayload(attestationPayload, handshake.getRemoteStaticKey());
      this.trace({ step: 'attestation-validated' });
    } catch (error) {
      if (error instanceof AttestationRejectedError || error instanceof UpstreamProtocolChangedError) {
        this.trace({ step: 'attestation-rejected', reason: error.message });
      }
      socket.close();
      if (error instanceof AttestationRejectedError || error instanceof UpstreamProtocolChangedError) throw error;
      throw new AttestationRejectedError(`Attestation validation failed: ${(error as Error).message}`);
    }

    const messageThree = handshake.writeMessageThree();
    socket.send(messageThree);
    this.trace({ step: 'message-three-sent', length: messageThree.length });
    this.session = handshake.split();
    this.handshakePhase = false;
    this.trace({ step: 'established' });

    this.keepaliveTimer = setInterval(() => {
      void this.request('GET', '/ping').catch(() => undefined);
    }, 20_000);
    this.keepaliveTimer.unref?.();
  }

  /**
   * Sends one logical request (chunked and encrypted) and resolves with the
   * first matching response.
   */
  async request(verb: string, path: string, body?: Uint8Array): Promise<WebsocketResponse> {
    return new Promise<WebsocketResponse>((resolve, reject) => {
      const settled = this.withSettlement(resolve, reject);
      void this.sendWithHandler(verb, path, body, { resolveFirst: settled.resolve, reject: settled.reject });
    });
  }

  /**
   * Sends a streaming request. `onEvent` receives every response with the
   * request's id (module 1958 semantics: each transport response carries one
   * JSON stream event); it returns true when the stream is complete and the
   * pending entry should be removed.
   */
  async requestStreaming(
    verb: string,
    path: string,
    body: Uint8Array | undefined,
    onEvent: (response: WebsocketResponse) => boolean,
  ): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const settled = this.withSettlement(resolve, reject);
      void this.sendWithHandler(verb, path, body, { reject: settled.reject, onEvent, onDone: settled.resolve });
    });
  }

  private async sendWithHandler(
    verb: string,
    path: string,
    body: Uint8Array | undefined,
    handler: PendingRequest,
  ): Promise<void> {
    if (!this.session || !this.currentSocket) throw new UpstreamProtocolChangedError('request called before connect().');
    if (this.closed) throw new TransportFrameError('Connection is closed.');
    const id = this.nextRequestId++;
    const request: WebsocketRequest = { id, verb, path };
    if (body !== undefined) request.body = body;
    const encoded = encodeWebsocketRequest(request);
    const frames = chunkPayload(this.nextChunkId++, encoded);
    this.pending.set(id, handler);
    try {
      for (const frame of frames) {
        this.currentSocket!.send(this.session!.writeMessage(encodeNoiseTransportFrame(frame)));
      }
    } catch (error) {
      this.pending.delete(id);
      throw error;
    }
  }

  close(): void {
    this.closed = true;
    if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
    for (const [id] of this.pending) this.pending.delete(id);
    this.currentSocket?.close();
  }

  /** Resolvers waiting for the next inbound record, armed before sends. */
  private readonly incomingWaiters: Array<(data: Uint8Array) => void> = [];
  private readonly reassembler = new FrameReassembler();
  private readonly pending = new Map<bigint, PendingRequest>();

  private waitForIncoming(): Promise<Uint8Array> {
    return new Promise<Uint8Array>((resolve, reject) => {
      const timeout = setTimeout(() => {
        const index = this.incomingWaiters.indexOf(resolve);
        if (index !== -1) this.incomingWaiters.splice(index, 1);
        reject(new HandshakeFailedError('Handshake message timed out.'));
      }, HANDSHAKE_TIMEOUT_MS);
      this.incomingWaiters.push((data) => {
        clearTimeout(timeout);
        resolve(data);
      });
    });
  }

  private handleMessage(data: Uint8Array): void {
    if (!this.session) return;
    let plaintext: Uint8Array;
    try {
      plaintext = this.session.readMessage(data);
    } catch {
      this.handleClose(1002);
      return;
    }
    // Mirror module 1959: every record carries one NoiseTransportFrame; the
    // assembler reassembles multi-frame payloads before protobuf decoding.
    const frame = decodeNoiseTransportFrame(plaintext);
    let payload: Uint8Array | null;
    try {
      payload = this.reassembler.push(frame);
    } catch (error) {
      this.handleClose(1002);
      throw error;
    }
    if (payload === null) return; // awaiting more chunks
    const response = decodeWebsocketResponse(payload);
    const handler = this.pending.get(response.id);
    if (!handler) return;

    // Module 1958 semantics: 402 is terminal for the connection; other >=400
    // statuses reject the request but keep the session.
    if (response.status === 402) {
      this.pending.delete(response.id);
      handler.reject(new PaymentRequiredError('Payment required.'));
      this.close();
      return;
    }
    if (response.status >= 400) {
      this.pending.delete(response.id);
      handler.reject(new UpstreamRequestError(response.status, response.body));
      return;
    }

    if (handler.onEvent) {
      let done = false;
      try {
        done = handler.onEvent(response);
      } catch (error) {
        this.pending.delete(response.id);
        handler.reject(error as Error);
        return;
      }
      if (done) {
        this.pending.delete(response.id);
        handler.onDone?.();
      }
    } else if (handler.resolveFirst) {
      this.pending.delete(response.id);
      handler.resolveFirst(response);
    }
  }

  private handleClose(code: number, reason = ''): void {
    const wasEstablished = this.session !== null;
    this.closed = true;
    if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
    // Fail every in-flight request; otherwise a server-side close leaves the
    // caller hanging forever. The close reason is diagnostic gold.
    for (const [id, handler] of [...this.pending]) {
      this.pending.delete(id);
      handler.reject(new ConnectionClosedError(code, reason));
    }
    void wasEstablished;
  }
}

function defaultSocketFactory(url: string): WebSocketLike {
  const ws = new WebSocket(url);
  const openListeners: Array<() => void> = [];
  ws.on('open', () => openListeners.forEach((listener) => listener()));
  return {
    send: (data) => ws.send(data),
    close: () => ws.close(),
    onOpen: (listener) => openListeners.push(listener),
    onMessage: (listener) =>
      ws.on('message', (data) => listener(new Uint8Array(data as Buffer))),
    onClose: (listener) => ws.on('close', (code, reason) => listener(code, reason.toString())),
    onError: (listener) => ws.on('error', listener),
  };
}
