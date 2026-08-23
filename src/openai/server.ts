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
  type ClientTool,
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
  'tools',
  'tool_choice',
]);

/**
 * Fields OpenAI clients may send that we accept but deliberately ignore —
 * no faithful upstream mapping exists, yet rejecting them breaks common
 * SDKs (e.g. nanobot sends stream_options on every streaming request).
 */
const IGNORED_REQUEST_FIELDS = new Set([
  'stream_options', // toggles usage-in-stream; we never emit usage chunks
  'user', // OpenAI end-user identifier; meaningless here
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

interface OpenAIToolCall {
  id: string;
  functionName: string;
  arguments: string;
}

/**
 * Transform OpenAI chat messages into upstream ChatMessages.
 *
 * Mappings (verified against confer-proxy's OpenAIWebsocketHandler):
 * - assistant messages carrying tool_calls become one upstream `tool_call`
 *   message per call, whose content is the JSON-encoded ToolCallContent
 *   ({toolCallId, toolName, toolArguments}).
 * - OpenAI role:"tool" result messages become a `tool_response` message with
 *   JSON-encoded ToolResponseContent ({toolCallId, toolName, content}); the
 *   tool name is recovered from the earlier assistant tool_calls.
 */
function transformMessages(raw: unknown): ChatMessage[] {
  if (!Array.isArray(raw) || raw.length === 0 || !raw.every((m) => typeof m === 'object' && m !== null)) {
    throw new UnsupportedParameterError('messages must be a non-empty array of message objects');
  }

  const out: ChatMessage[] = [];
  // tool_call_id -> function name, for resolving role:"tool" messages.
  const toolNamesById = new Map<string, string>();

  for (const m of raw) {
    const record = m as Record<string, unknown>;
    const role = record['role'];

    switch (role) {
      case 'system':
      case 'developer':
      case 'user': {
        const content = record['content'];
        if (typeof content !== 'string') {
          throw new UnsupportedParameterError(`messages[].role "${role}" requires string content`);
        }
        out.push({ role, content });
        break;
      }
      case 'assistant': {
        const content = record['content'];
        if (typeof content === 'string' && content.length > 0) {
          out.push({ role: 'assistant', content });
        }
        const rawToolCalls = record['tool_calls'];
        if (rawToolCalls === undefined && typeof content !== 'string') {
          throw new UnsupportedParameterError('assistant message requires content or tool_calls');
        }
        if (!Array.isArray(rawToolCalls)) {
          if (rawToolCalls !== undefined) {
            throw new UnsupportedParameterError('tool_calls must be an array');
          }
          break;
        }
        for (const tc of rawToolCalls) {
          const tcRecord = (tc ?? {}) as Record<string, unknown>;
          const fn = (tcRecord['function'] ?? {}) as Record<string, unknown>;
          const id = tcRecord['id'];
          const fname = fn['name'];
          if (typeof id !== 'string' || typeof fname !== 'string') {
            throw new UnsupportedParameterError('tool_calls[].id and .function.name are required');
          }
          let args = fn['arguments'];
          if (args === undefined || args === null) args = '{}';
          if (typeof args !== 'string') args = JSON.stringify(args);
          toolNamesById.set(id, fname);
          out.push({
            role: 'tool_call',
            content: JSON.stringify({ toolCallId: id, toolName: fname, toolArguments: args }),
          });
        }
        break;
      }
      case 'tool': {
        const toolCallId = record['tool_call_id'];
        const content = record['content'];
        if (typeof toolCallId !== 'string' || toolCallId.length === 0) {
          throw new UnsupportedParameterError('messages[].tool_call_id is required for tool results');
        }
        if (typeof content !== 'string') {
          throw new UnsupportedParameterError('messages[].content must be a string for tool results');
        }
        const toolName = toolNamesById.get(toolCallId);
        if (!toolName) {
          throw new UnsupportedParameterError(
            `tool result references unknown tool_call_id "${toolCallId}" (no preceding assistant tool_calls entry)`,
          );
        }
        out.push({
          role: 'tool_response',
          content: JSON.stringify({ toolCallId, toolName, content }),
        });
        break;
      }
      default:
        throw new UnsupportedParameterError(`messages[].role "${String(role)}" is not supported`);
    }
  }

  return out;
}

/** Parse OpenAI `tools` into upstream clientTools; only function tools are supported. */
function parseTools(raw: unknown): ClientTool[] | undefined {
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw)) throw new UnsupportedParameterError('tools must be an array');
  const tools: ClientTool[] = [];
  for (const t of raw) {
    const record = (t ?? {}) as Record<string, unknown>;
    if (record['type'] !== 'function') {
      throw new UnsupportedParameterError(
        `tools[].type "${String(record['type'])}" is not supported (only "function")`,
      );
    }
    const fn = (record['function'] ?? {}) as Record<string, unknown>;
    const name = fn['name'];
    if (typeof name !== 'string' || name.trim().length === 0 || name.length > 64) {
      throw new UnsupportedParameterError('tools[].function.name must be a non-empty string (max 64 chars)');
    }
    const description = typeof fn['description'] === 'string' ? fn['description'] : '';
    const parameters =
      typeof fn['parameters'] === 'object' && fn['parameters'] !== null
        ? (fn['parameters'] as Record<string, unknown>)
        : {};
    tools.push({ name, description, parameters });
  }
  return tools;
}

/** Apply OpenAI tool_choice semantics to the declared clientTools list. */
function applyToolChoice(
  rawChoice: unknown,
  tools: ClientTool[] | undefined,
): ClientTool[] | undefined {
  if (rawChoice === undefined) return tools;
  if (rawChoice === 'none') return undefined;
  if (rawChoice === 'auto') return tools;
  if (typeof rawChoice === 'object' && rawChoice !== null) {
    const record = rawChoice as Record<string, unknown>;
    if (record['type'] === 'function' && typeof record['function'] === 'object' && record['function'] !== null) {
      const wanted = (record['function'] as Record<string, unknown>)['name'];
      const filtered = (tools ?? []).filter((t) => t.name === wanted);
      if (filtered.length === 0) {
        throw new UnsupportedParameterError(`tool_choice references unknown tool "${String(wanted)}"`);
      }
      return filtered;
    }
  }
  throw new UnsupportedParameterError(`tool_choice value ${JSON.stringify(rawChoice)} is not supported`);
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
    if (SUPPORTED_REQUEST_FIELDS.has(field)) continue;
    if (IGNORED_REQUEST_FIELDS.has(field)) continue; // accepted, no upstream effect
    throw new UnsupportedParameterError(field);
  }
  if (typeof record['model'] !== 'undefined' && record['model'] !== FACADE_MODEL) {
    throw new UnsupportedParameterError(`model "${String(record['model'])}" is not available`);
  }

  const messages = transformMessages(record['messages']);
  const clientTools = applyToolChoice(record['tool_choice'], parseTools(record['tools']));
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
  if (clientTools !== undefined) options['clientTools'] = clientTools;

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

  interface OpenAIToolCall {
    id: string;
    type: 'function';
    function: { name: string; arguments: string };
  }

  async function plainCompletion(parsed: ParsedChatRequest, res: ServerResponse): Promise<void> {
    let content = '';
    const toolCalls: OpenAIToolCall[] = [];

    // Internally always stream so client tool calls can be captured; the
    // upstream pauses with a pending completion when the caller must act.
    await withReconnect((client) =>
      client.chatCompletionStream(parsed.messages, (event) => {
        switch (event.type) {
          case 'content':
            content += event.content;
            break;
          case 'thinking':
            // Reasoning is not exposed to non-streaming callers.
            break;
          case 'client_tool_call':
            toolCalls.push({
              id: String(event.toolCallId),
              type: 'function',
              function: {
                name: String(event.toolName),
                arguments: String(event.toolArguments ?? '{}'),
              },
            });
            break;
          default:
            break;
        }
      }, parsed.options),
    );

    const finishReason = toolCalls.length > 0 ? 'tool_calls' : 'stop';
    const message: Record<string, unknown> = { role: 'assistant', content };
    if (toolCalls.length > 0) message['tool_calls'] = toolCalls;

    sendJson(res, 200, {
      id: completionId(),
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: String(parsed.options['model'] ?? FACADE_MODEL),
      choices: [
        {
          index: 0,
          message,
          finish_reason: finishReason,
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
    let toolCallIndex = 0;
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
        case 'client_tool_call': {
          // Model wants a CLIENT-executable tool. Emitted as one complete
          // tool_calls delta; the OpenAI client executes and resumes.
          writeChunk(
            {
              tool_calls: [
                {
                  index: toolCallIndex++,
                  id: String(event.toolCallId),
                  type: 'function',
                  function: {
                    name: String(event.toolName),
                    arguments: String(event.toolArguments ?? '{}'),
                  },
                },
              ],
            },
            null,
          );
          break;
        }
        case 'completion':
          writeChunk({}, event.pendingToolCalls ? 'tool_calls' : 'stop');
          break;
        default:
          // Server-side tool events (web_search etc.) are executed by the
          // upstream itself; their results surface as normal content.
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
