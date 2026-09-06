/**
 * Authenticated upstream client for confer.to confidential inference.
 *
 * Authenticated upstream client: owns token handling and transport
 * lifecycle; crypto stays behind the Noise client. Request and stream-event
 * shapes mirror browser module 1958 (SecureModelClient):
 *
 *   POST /v1/vllm/chat/completions with body
 *   { messages, model, temperature, topP, topK, minP, presencePenalty,
 *     repetitionPenalty, stream, thinking, json }
 *
 *   Non-streaming: one response whose body is UTF-8 JSON text.
 *   Streaming:     one response per JSON event; types 'token', 'thinking',
 *                  'tool_call', 'tool_response', 'client_tool_call',
 *                  'completion' (terminal).
 */
import {
  NoiseWebsocketClient,
  OBSERVED_INFERENCE_WEBSOCKET_URL,
  type HandshakeTraceEvent,
  type NoiseWebsocketClientOptions,
  type WebSocketLike,
} from './noise-websocket-client.js';
import type { AttestationValidator } from './noise/attestation.js';
import {
  NotSupportedError,
  SessionTokenError,
  UpstreamProtocolChangedError,
  UpstreamRequestError,
} from './errors.js';

/** Observed default model in the captured browser bundle (module 1958). */
export const OBSERVED_CHAT_MODEL = 'Qwen/Qwen3-235B-A22B-Instruct-2507-tput';

export const CHAT_COMPLETIONS_PATH = '/v1/vllm/chat/completions';

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'developer' | 'tool_call' | 'tool_response';
  content: string;
}

/** Client-executable tool declared to the upstream (ChatRequest.clientTools). */
export interface ClientTool {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

export interface ChatCompletionOptions {
  model?: string;
  temperature?: number;
  topP?: number;
  topK?: number;
  minP?: number;
  presencePenalty?: number;
  repetitionPenalty?: number;
  thinking?: boolean;
  /** Ask the upstream to emit JSON. Browser parity default: true. */
  json?: boolean;
  /**
   * Client-executable tools. The upstream streams `client_tool_call` events
   * for model-initiated calls and pauses with a pending completion; the
   * caller resumes by including tool_call/tool_response messages.
   */
  clientTools?: readonly ClientTool[];
}

export type StreamEvent =
  | { type: 'content'; content: string; model: string }
  | { type: 'thinking'; content: string }
  | { type: 'tool_call'; toolCallId?: unknown; toolName?: unknown; toolArguments?: unknown }
  | { type: 'tool_response'; toolCallId?: unknown; toolName?: unknown; content?: unknown }
  | { type: 'client_tool_call'; toolCallId?: unknown; toolName?: unknown; toolArguments?: unknown }
  | { type: 'completion'; pendingToolCalls?: unknown; contextTokens?: unknown; maxContextTokens?: unknown };

/** Supplies a fresh model-session token through an authorized flow. */
export interface ModelSessionTokenProvider {
  getToken(): Promise<string>;
}

/** Observed REST API base (module 1935, `API_BASE_URL`). */
export const OBSERVED_API_BASE_URL = 'https://api.confer.to';
const OBSERVED_MODEL_TOKEN_PATH = '/v1/tokens/model';

/**
 * Exchanges a REST access token for the short-lived model-session token via
 * `GET /v1/tokens/model`, mirroring module 1282's getConfidentialModelAuthToken.
 *
 * The access token comes from your own authorized session (see
 * docs/MODEL_SESSION_TOKEN.md). It is sent only to the configured base URL
 * and never logged.
 */
export class RestModelSessionTokenProvider implements ModelSessionTokenProvider {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly accessToken: string, options: { baseUrl?: string; fetchImpl?: typeof fetch } = {}) {
    if (!accessToken || accessToken.length === 0) {
      throw new SessionTokenError('Missing REST access token.');
    }
    this.baseUrl = (options.baseUrl ?? OBSERVED_API_BASE_URL).replace(/\/+$/, '');
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async getToken(): Promise<string> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${OBSERVED_MODEL_TOKEN_PATH}`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${this.accessToken}` },
      });
    } catch (error) {
      throw new SessionTokenError(`Model-token request failed: ${(error as Error).message}`);
    }
    if (response.status === 401 || response.status === 403) {
      throw new SessionTokenError(`Access token rejected by ${OBSERVED_MODEL_TOKEN_PATH} (${response.status}).`);
    }
    if (!response.ok) {
      throw new UpstreamRequestError(response.status);
    }
    let parsed: { token?: unknown };
    try {
      parsed = (await response.json()) as { token?: unknown };
    } catch {
      throw new UpstreamProtocolChangedError('Model-token response is not valid JSON.');
    }
    const token = parsed['token'];
    if (typeof token !== 'string' || token.length === 0) {
      throw new UpstreamProtocolChangedError('Model-token response has no token field.');
    }
    return token;
  }
}

/** Environment-backed provider for local, authorized use. */
export class EnvModelSessionTokenProvider implements ModelSessionTokenProvider {
  async getToken(): Promise<string> {
    const token = process.env['CONFER_MODEL_SESSION_TOKEN'];
    if (!token || token.length === 0) {
      throw new NotSupportedError(
        'CONFER_MODEL_SESSION_TOKEN is not set. Obtain a model-session token through an authorized flow first; see docs/MODEL_SESSION_TOKEN.md.',
      );
    }
    return token;
  }
}

export interface ConferClientOptions {
  /** Provides the model-session token appended to the WebSocket URL. */
  tokenProvider: ModelSessionTokenProvider;
  validator: AttestationValidator;
  /** Defaults to the observed production inference endpoint. */
  websocketUrl?: string;
  /** Test hook: injectable socket factory (see NoiseWebsocketClient). */
  socketFactory?: (url: string) => WebSocketLike;
  /** Keepalive interval override; browser uses 20s. */
  keepaliveMs?: number;
  /** Optional local-only handshake diagnostics; see NoiseWebsocketClient. */
  onHandshakeTrace?: (event: HandshakeTraceEvent) => void;
}

interface RawStreamEvent {
  type?: unknown;
  content?: unknown;
  tool_call_id?: unknown;
  tool_name?: unknown;
  tool_arguments?: unknown;
  full_content?: unknown;
  image_refs?: unknown;
  pending_tool_calls?: unknown;
  context_tokens?: unknown;
  max_context_tokens?: unknown;
}

export class ConferClient {
  private readonly options: ConferClientOptions;
  private noiseClient: NoiseWebsocketClient | null = null;
  private connecting: Promise<void> | null = null;

  constructor(options: ConferClientOptions) {
    this.options = options;
  }

  get isConnected(): boolean {
    return this.noiseClient !== null;
  }

  /**
   * Fetches a fresh token through the authorized provider and opens the
   * attested transport. Tokens can expire and are tied to the session;
   * never reuse tokens copied out of a browser. Concurrent callers share
   * one in-flight connection attempt.
   */
  async connect(): Promise<void> {
    if (this.noiseClient) return;
    if (this.connecting) return this.connecting;
    this.connecting = (async () => {
      try {
        const token = await this.options.tokenProvider.getToken();
        const clientOptions: NoiseWebsocketClientOptions = {
          token,
          url: this.options.websocketUrl ?? OBSERVED_INFERENCE_WEBSOCKET_URL,
          validator: this.options.validator,
        };
        if (this.options.socketFactory) clientOptions.socketFactory = this.options.socketFactory;
        if (this.options.onHandshakeTrace) clientOptions.onHandshakeTrace = this.options.onHandshakeTrace;
        const client = new NoiseWebsocketClient(clientOptions);
        await client.connect();
        this.noiseClient = client;
      } finally {
        this.connecting = null;
      }
    })();
    return this.connecting;
  }

  /** The live transport, (re)connecting lazily after a close. */
  private async requireClient(): Promise<NoiseWebsocketClient> {
    await this.connect();
    if (!this.noiseClient) {
      throw new UpstreamProtocolChangedError('request called before connect().');
    }
    return this.noiseClient;
  }

  /** Non-streaming chat completion; resolves with the raw UTF-8 response text. */
  async chatCompletion(messages: readonly ChatMessage[], options: ChatCompletionOptions = {}): Promise<string> {
    const client = await this.requireClient();
    const body = this.chatRequestBody(messages, options, false);
    const response = await client.request('POST', CHAT_COMPLETIONS_PATH, body);
    return new TextDecoder().decode(response.body ?? new Uint8Array(0));
  }

  /**
   * Streaming chat completion. Events are delivered in order; the promise
   * resolves when the upstream sends its terminal `completion` event.
   */
  async chatCompletionStream(
    messages: readonly ChatMessage[],
    onEvent: (event: StreamEvent) => void,
    options: ChatCompletionOptions = {},
  ): Promise<void> {
    const body = this.chatRequestBody(messages, options, true);
    const model = options.model ?? OBSERVED_CHAT_MODEL;
    const client = await this.requireClient();
    await client.requestStreaming('POST', CHAT_COMPLETIONS_PATH, body, (response) => {
      const text = new TextDecoder().decode(response.body ?? new Uint8Array(0));
      let parsed: RawStreamEvent;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new UpstreamProtocolChangedError('Stream event is not valid JSON.');
      }
      switch (parsed.type) {
        case 'token':
          onEvent({ type: 'content', content: String(parsed.content ?? ''), model });
          return false;
        case 'thinking':
          onEvent({ type: 'thinking', content: String(parsed.content ?? '') });
          return false;
        case 'tool_call':
          onEvent({
            type: 'tool_call',
            toolCallId: parsed.tool_call_id,
            toolName: parsed.tool_name,
            toolArguments: parsed.tool_arguments,
          });
          return false;
        case 'tool_response':
          onEvent({
            type: 'tool_response',
            toolCallId: parsed.tool_call_id,
            toolName: parsed.tool_name,
            content: parsed.content,
          });
          return false;
        case 'client_tool_call':
          onEvent({
            type: 'client_tool_call',
            toolCallId: parsed.tool_call_id,
            toolName: parsed.tool_name,
            toolArguments: parsed.tool_arguments,
          });
          return false;
        case 'completion':
          onEvent({
            type: 'completion',
            pendingToolCalls: parsed.pending_tool_calls,
            contextTokens: parsed.context_tokens,
            maxContextTokens: parsed.max_context_tokens,
          });
          return true; // terminal event per module 1958 handleStreamToken
        default:
          throw new UpstreamProtocolChangedError(`Unknown stream event type: ${String(parsed.type)}.`);
      }
    });
  }

  close(): void {
    this.noiseClient?.close();
    this.noiseClient = null;
  }

  /** Body layout copied from module 1958 chatCompletion / chatCompletionStream. */
  private chatRequestBody(
    messages: readonly ChatMessage[],
    options: ChatCompletionOptions,
    stream: boolean,
  ): Uint8Array {
    const payload: Record<string, unknown> = {
      messages,
      model: options.model ?? OBSERVED_CHAT_MODEL,
      temperature: options.temperature ?? 0.6,
      topP: options.topP ?? 0.95,
      topK: options.topK ?? 20,
      minP: options.minP ?? 0,
      presencePenalty: options.presencePenalty ?? 0,
      repetitionPenalty: options.repetitionPenalty ?? 1,
      stream,
      thinking: options.thinking ?? true,
      json: options.json ?? true,
    };
    if (options.clientTools && options.clientTools.length > 0) {
      payload['clientTools'] = options.clientTools;
    }
    return new TextEncoder().encode(JSON.stringify(payload));
  }
}
