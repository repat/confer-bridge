/**
 * The only permitted boundary for browser-derived cryptography and the
 * confidential transport. The captured browser bundle confirms two separate
 * layers: at-rest AES-GCM records and an attested Noise WebSocket session.
 *
 * See docs/FRONTEND_BUNDLE_ANALYSIS.md and docs/UPSTREAM_MODULE_MAP.md. Do not
 * disable TDX attestation validation in order to get a live connection.
 *
 * The facade is stateless: chat/message persistence (at-rest encryption)
 * is deliberately not implemented. Only the confidential transport path is
 * wired here.
 */
import { NoiseWebsocketClient, type NoiseWebsocketClientOptions, type WebsocketResponse } from './noise-websocket-client.js';
import { NotSupportedError } from './errors.js';

export interface ConferCryptoAdapter {
  initialize(): Promise<void>;
  encryptChat(plaintext: Uint8Array): Promise<{ ciphertext: string; encryptedKey: string }>;
  encryptMessage(plaintext: Uint8Array): Promise<{ ciphertext: string }>;
  decryptResponse(envelope: unknown): Promise<Uint8Array>;
}

export interface AttestedTransportOptions {
  websocket: Omit<NoiseWebsocketClientOptions, 'token'>;
  /** Provider for a fresh model-session token; never reuse browser tokens. */
  tokenProvider: () => Promise<string>;
}

/**
 * Transport-backed adapter. `decryptResponse` unwraps a completed
 * WebsocketResponse envelope into its plaintext body bytes.
 */
export class ConferAttestedCryptoAdapter implements ConferCryptoAdapter {
  private client: NoiseWebsocketClient | null = null;

  constructor(private readonly options: AttestedTransportOptions) {}

  async initialize(): Promise<void> {
    const token = await this.options.tokenProvider();
    this.client = new NoiseWebsocketClient({ ...this.options.websocket, token });
    await this.client.connect();
  }

  /**
   * Sends a request through the attested transport and returns the verified
   * plaintext response body.
   */
  async decryptResponse(envelope: { verb: string; path: string; body?: Uint8Array }): Promise<Uint8Array> {
    if (!this.client) throw new NotSupportedError('Adapter not initialized.');
    const response: WebsocketResponse = await this.client.request(envelope.verb, envelope.path, envelope.body);
    return response.body ?? new Uint8Array(0);
  }

  async encryptChat(_: Uint8Array): Promise<{ ciphertext: string; encryptedKey: string }> {
    throw new NotSupportedError(
      'Encrypted chat persistence is not implemented; this facade is stateless by design.',
    );
  }

  async encryptMessage(_: Uint8Array): Promise<{ ciphertext: string }> {
    throw new NotSupportedError(
      'Encrypted message persistence is not implemented; this facade is stateless by design.',
    );
  }

  close(): void {
    this.client?.close();
    this.client = null;
  }
}

export { UnimplementedConferCryptoAdapter } from './unimplemented-adapter.js';
