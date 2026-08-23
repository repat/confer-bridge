/**
 * OpenAI-compatible HTTP facade over the attested confer.to transport.
 *
 * Exposes GET /v1/models and POST /v1/chat/completions with strict parameter
 * validation. Only OpenAI features that map faithfully onto the upstream are
 * supported; everything else is rejected with an explicit error rather than
 * ignored.
 *
 * Zero-dependency: built on node:http.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import {
  ConferClient,
  OBSERVED_CHAT_MODEL,
  type ChatMessage,
  type StreamEvent,
} from '../confer/client.js';
import { PaymentRequiredError } from '../confer/errors.js';

export const FACADE_MODEL = OBSERVED_CHAT_MODEL;

/** Fields accepted on POST /v1/chat/completions; anything else is rejected. */
const SUPPORTED_REQUEST_FIELDS = new Set([
  'model',
  'messages',
  'stream',
  'temperature',
  'top_p',
  'presence_penalty',
  'frequency_penalty',
  'max_tokens',
]);

export class UnsupportedParameterError extends Error {
  constructor(public readonly field: string) {
    super(`Unsupported parameter: "${field}" is not supported by this facade.`);
    this.name = 'UnsupportedParameterError';
  }
}

export interface FacadeClient {
  chatCompletion(
    messages: readonly ChatMessage[],
    options?: Record<string, unknown>,
  ): Promise<string>;
  chatCompletionStream(
    messages: readonly ChatMessage[],
    onEvent: (event: StreamEvent) => void,
    options?: Record<string, unknown>,
  ): Promise<void>;
  close(): void;
}

export interface FacadeServerOptions {
  /** Lazily invoked once; the same connected client is reused across requests. */
  getClient: () => Promise<FacadeClient>;
  /** Required bearer key for facade callers. */
  apiKey: string;
  /**
   * When true, upstream thinking deltas are exposed as reasoning_content
   * chunks. Default false: reasoning never leaks into normal content.
   */
  exposeThinking?: boolean | undefined;
}

interface ParsedChatRequest {
  messages: ChatMessage[];
  stream: boolean;
  options: Record<string, unknown>;
}

function readBody(req: IncomingMessage, limitBytes = 1_048_576): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > limitBytes) {
        reject(new Error('Request body too large.'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(text);
}

function validateMessages(raw: unknown): ChatMessage[] {
  if (!Array.isArray(raw) || raw.length === 0 || !raw.every((m) => typeof m === 'object' && m !== null)) {
    throw new UnsupportedParameterError('messages must be a non-empty array of message objects');
  }
  return raw.map((m) => {
    const record = m as Record<string, unknown>;
    const role = record['role'];
    const content = record['content'];
    if (typeof role !== 'string' || !['user', 'assistant', 'system', 'developer'].includes(role)) {
      throw new UnsupportedParameterError(`messages[].role "${String(role)}" is not supported`);
    }
    if (typeof content !== 'string') {
      throw new UnsupportedParameterError('messages[].content must be a string');
    }
    return { role, content } as ChatMessage;
  });
}

function parseChatCompletionBody(bodyText: string): ParsedChatRequest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    throw new UnsupportedParameterError('request body is not valid JSON');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new UnsupportedParameterError('request body must be a JSON object');
  }
  const record = parsed as Record<string, unknown>;

  for (const field of Object.keys(record)) {
    if (!SUPPORTED_REQUEST_FIELDS.has(field)) {
      throw new UnsupportedParameterError(field);
    }
  }
  if (typeof record['model'] !== 'undefined' && record['model'] !== FACADE_MODEL) {
    throw new UnsupportedParameterError(`model "${String(record['model'])}" is not available`);
  }

  const messages = validateMessages(record['messages']);
  const numeric = (value: unknown, field: string): number | undefined => {
    if (typeof value === 'undefined') return undefined;
    if (typeof value !== 'number') throw new UnsupportedParameterError(`${field} must be a number`);
    return value;
  };

  const options: Record<string, unknown> = {};
  const temperature = numeric(record['temperature'], 'temperature');
  if (temperature !== undefined) options['temperature'] = temperature;
  const topP = numeric(record['top_p'], 'top_p');
  if (topP !== undefined) options['topP'] = topP;
  const presencePenalty = numeric(record['presence_penalty'], 'presence_penalty');
  if (presencePenalty !== undefined) options['presencePenalty'] = presencePenalty;
  const frequencyPenalty = numeric(record['frequency_penalty'], 'frequency_penalty');
  if (frequencyPenalty !== undefined) options['frequencyPenalty'] = frequencyPenalty;
  const maxTokens = numeric(record['max_tokens'], 'max_tokens');
  if (maxTokens !== undefined) options['maxTokens'] = Math.trunc(maxTokens);

  const json = false;

  return {
    messages,
    stream: record['stream'] === true,
    options: { ...options, json },
  };
}

function completionId(): string {
  return `chatcmpl-${randomBytes(12).toString('hex')}`;
}

export function createFacadeServer(options: FacadeServerOptions): Server {
  let cachedClient: FacadeClient | null = null;
  let connecting: Promise<FacadeClient> | null = null;

  async function getClient(): Promise<FacadeClient> {
    if (cachedClient) return cachedClient;
    if (!connecting) {
      connecting = options
        .getClient()
        .then((client) => {
          cachedClient = client;
          connecting = null;
          return client;
        })
        .catch((error) => {
          connecting = null;
          throw error;
        });
    }
    return connecting;
  }

  /** Invalidate the cached client after transport-level failures. */
  function dropClient(): void {
    cachedClient?.close();
    cachedClient = null;
  }

  async function withReconnect<T>(run: (client: FacadeClient) => Promise<T>): Promise<T> {
    let client = await getClient();
    try {
      return await run(client);
    } catch (error) {
      const name = (error as Error).name;
      if (name === 'ConnectionClosedError' || name === 'TransportFrameError') {
        // Transport died mid-request: reconnect once with fresh credentials.
        dropClient();
        client = await getClient();
        return run(client);
      }
      throw error;
    }
  }

  const server = createServer((req, res) => {
    void handle(req, res).catch((error) => {
      if (!res.headersSent) sendJson(res, 500, { error: { message: 'Internal facade error' } });
      else res.end();
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = (req.url ?? '').split('?')[0];

    // Unauthenticated liveness probe for systemd / uptime monitors.
    if (req.method === 'GET' && url === '/healthz') {
      sendJson(res, 200, {
        status: 'ok',
        upstream: cachedClient !== null,
      });
      return;
    }

    // Facade authentication.
    const auth = req.headers['authorization'] ?? '';
    if (auth !== `Bearer ${options.apiKey}`) {
      sendJson(res, 401, {
        error: { message: 'Missing or invalid API key', type: 'invalid_request_error' },
      });
      return;
    }

    if (req.method === 'GET' && url === '/v1/models') {
      sendJson(res, 200, {
        object: 'list',
        data: [
          {
            id: FACADE_MODEL,
            object: 'model',
            created: 0,
            owned_by: 'confer.to',
          },
        ],
      });
      return;
    }

    if (req.method === 'POST' && url === '/v1/chat/completions') {
      await handleChatCompletions(req, res);
      return;
    }

    sendJson(res, 404, {
      error: { message: `No route for ${req.method} ${url}`, type: 'invalid_request_error' },
    });
  }

  async function handleChatCompletions(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let parsed: ParsedChatRequest;
    try {
      parsed = parseChatCompletionBody(await readBody(req));
    } catch (error) {
      if (error instanceof UnsupportedParameterError) {
        sendJson(res, 400, {
          error: { message: error.message, type: 'invalid_request_error', code: 'unsupported_parameter' },
        });
      } else {
        sendJson(res, 400, {
          error: { message: (error as Error).message, type: 'invalid_request_error' },
        });
      }
      return;
    }

    try {
      if (parsed.stream) {
        await streamCompletion(parsed, res);
      } else {
        await plainCompletion(parsed, res);
      }
    } catch (error) {
      if (res.headersSent) {
        // Mid-stream failure: emit an error event and close cleanly.
        res.write(`data: ${JSON.stringify({ error: { message: (error as Error).message } })}\n\n`);
        res.write('data: [DONE]\n\n');
        res.end();
        return;
      }
      if (error instanceof PaymentRequiredError) {
        sendJson(res, 402, {
          error: { message: 'Upstream account cannot use the model', type: 'upstream_error' },
        });
        return;
      }
      sendJson(res, 502, {
        error: { message: `Upstream request failed: ${(error as Error).message}`, type: 'upstream_error' },
      });
    }
  }

  async function plainCompletion(parsed: ParsedChatRequest, res: ServerResponse): Promise<void> {
    const text = await withReconnect((client) =>
      client.chatCompletion(parsed.messages, parsed.options),
    );
    sendJson(res, 200, {
      id: completionId(),
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: String(parsed.options['model'] ?? FACADE_MODEL),
      choices: [
        {
          index: 0,
          message: { role: 'assistant', content: text },
          finish_reason: 'stop',
        },
      ],
      usage: null,
    });
  }

  async function streamCompletion(parsed: ParsedChatRequest, res: ServerResponse): Promise<void> {
    const id = completionId();
    const created = Math.floor(Date.now() / 1000);
    const model = String(parsed.options['model'] ?? FACADE_MODEL);

    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
    });

    let first = true;
    const writeChunk = (delta: Record<string, unknown>, finishReason: string | null): void => {
      const rolePart = first ? { role: 'assistant' } : {};
      first = false;
      const chunk = {
        id,
        object: 'chat.completion.chunk',
        created,
        model,
        choices: [
          {
            index: 0,
            delta: { ...rolePart, ...delta },
            finish_reason: finishReason,
          },
        ],
      };
      res.write(`data: ${JSON.stringify(chunk)}\n\n`);
    };

    const onEvent = (event: StreamEvent): void => {
      switch (event.type) {
        case 'content':
          writeChunk({ content: event.content }, null);
          break;
        case 'thinking':
          if (options.exposeThinking) writeChunk({ reasoning_content: event.content }, null);
          break;
        case 'completion':
          writeChunk({}, 'stop');
          break;
        default:
          // tool_call / tool_response / client_tool_call are not exposed yet.
          break;
      }
    };

    await withReconnect((client) =>
      client.chatCompletionStream(parsed.messages, onEvent, parsed.options),
    );
    res.write('data: [DONE]\n\n');
    res.end();
  }

  // Attach close hook so tests and embedders can release the upstream client.
  server.on('close', () => dropClient());

  return server;
}
