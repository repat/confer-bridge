/**
 * Facade tests: parameter validation, OpenAI response shapes, SSE streaming
 * (including the thinking flag), auth, and reconnect behavior. All against a
 * mocked FacadeClient — no network.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer, type Server } from 'node:http';
import {
  createFacadeServer,
  FACADE_MODEL,
  type FacadeClient,
} from '../src/openai/server.js';
import type { StreamEvent } from '../src/confer/client.js';

interface RecordedCall {
  messages: Array<{ role: string; content: string }>;
  options: Record<string, unknown>;
}

class MockClient implements FacadeClient {
  calls: RecordedCall[] = [];
  streamCalls = 0;
  plainAnswer = 'confer-protocol-test';
  events: StreamEvent[] = [];
  failNextWith: Error | null = null;
  closed = 0;

  async chatCompletion(messages: readonly { role: string; content: string }[], options?: Record<string, unknown>) {
    if (this.failNextWith) {
      const err = this.failNextWith;
      this.failNextWith = null;
      throw err;
    }
    this.calls.push({ messages: [...messages], options: options ?? {} });
    return this.plainAnswer;
  }

  async chatCompletionStream(
    messages: readonly { role: string; content: string }[],
    onEvent: (event: StreamEvent) => void,
    _options?: Record<string, unknown>,
  ) {
    if (this.failNextWith) {
      const err = this.failNextWith;
      this.failNextWith = null;
      throw err;
    }
    this.streamCalls++;
    this.calls.push({ messages: [...messages], options: _options ?? {} });
    if (this.events.length === 0) {
      // Default behaviour: answer with the canned plain response.
      onEvent({ type: 'content', content: this.plainAnswer, model: 'test' });
      onEvent({ type: 'completion' });
      return;
    }
    for (const event of this.events) onEvent(event);
  }

  close(): void {
    this.closed++;
  }
}

function startFacade(client: FacadeClient, extra: Partial<{ exposeThinking: boolean; apiKey: string }> = {}): Promise<{
  server: Server;
  url: string;
}> {
  return new Promise((resolve) => {
    const server = createFacadeServer({
      getClient: async () => client,
      apiKey: extra.apiKey ?? 'test-key',
      ...(extra.exposeThinking !== undefined ? { exposeThinking: extra.exposeThinking } : {}),
    });
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      resolve({ server, url: `http://127.0.0.1:${address.port}` });
    });
  });
}

async function postJson(url: string, path: string, body: string, headers: Record<string, string> = {}): Promise<{ status: number; json: any; text: string }> {
  const response = await fetch(`${url}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer test-key', ...headers },
    body,
  });
  const text = await response.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    // non-JSON (SSE)
  }
  return { status: response.status, json, text };
}

test('GET /v1/models lists the observed model', async () => {
  const { server, url } = await startFacade(new MockClient());
  try {
    const response = await fetch(`${url}/v1/models`, { headers: { authorization: 'Bearer test-key' } });
    const body = (await response.json()) as any;
    assert.equal(response.status, 200);
    assert.equal(body.object, 'list');
    assert.equal(body.data[0].id, FACADE_MODEL);
  } finally {
    server.close();
  }
});

test('GET /healthz reports liveness and upstream state without auth', async () => {
  const client = new MockClient();
  const { server, url } = await startFacade(client);
  try {
    const before = (await (await fetch(`${url}/healthz`)).json()) as { status: string; upstream: boolean };
    assert.equal(before.status, 'ok');
    assert.equal(before.upstream, false); // nothing connected yet

    await postJson(url, '/v1/chat/completions', JSON.stringify({ messages: [{ role: 'user', content: 'x' }] }));
    const after = (await (await fetch(`${url}/healthz`)).json()) as { status: string; upstream: boolean };
    assert.equal(after.upstream, true);
  } finally {
    server.close();
  }
});

test('missing or wrong API key is rejected with 401', async () => {
  const { server, url } = await startFacade(new MockClient());
  try {
    const noKey = await fetch(`${url}/v1/models`);
    assert.equal(noKey.status, 401);
    const badKey = await postJson(url, '/v1/chat/completions', '{}', { authorization: 'Bearer wrong' });
    assert.equal(badKey.status, 401);
  } finally {
    server.close();
  }
});

test('non-streaming completion returns an OpenAI chat.completion object', async () => {
  const client = new MockClient();
  const { server, url } = await startFacade(client);
  try {
    const { status, json } = await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({ model: FACADE_MODEL, messages: [{ role: 'user', content: 'hi' }] }),
    );
    assert.equal(status, 200);
    assert.match(json.id as string, /^chatcmpl-/);
    assert.equal(json.object, 'chat.completion');
    assert.equal(json.choices[0].message.role, 'assistant');
    assert.equal(json.choices[0].message.content, 'confer-protocol-test');
    assert.equal(json.choices[0].finish_reason, 'stop');

    // Mapped request shape for the upstream.
    assert.equal(client.calls.length, 1);
    assert.deepEqual(client.calls[0]!.messages, [{ role: 'user', content: 'hi' }]);
    assert.equal(client.calls[0]!.options['json'], false);
  } finally {
    server.close();
  }
});

test('unsupported parameters are rejected with explicit 400s', async () => {
  const { server, url } = await startFacade(new MockClient());
  try {
    for (const field of ['tools', 'tool_choice', 'n', 'logprobs', 'response_format', 'seed']) {
      const { status, json } = await postJson(
        url,
        '/v1/chat/completions',
        JSON.stringify({ messages: [{ role: 'user', content: 'x' }], [field]: 'whatever' }),
      );
      assert.equal(status, 400, `expected 400 for ${field}`);
      assert.equal(json.error.code, 'unsupported_parameter');
      assert.match(json.error.message as string, new RegExp(field));
    }
  } finally {
    server.close();
  }
});

test('benign client fields (stream_options, user) are accepted and not leaked upstream', async () => {
  const client = new MockClient();
  const { server, url } = await startFacade(client);
  try {
    const { status, json } = await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({
        messages: [{ role: 'user', content: 'x' }],
        stream_options: { include_usage: true },
        user: 'end-user-42',
      }),
    );
    assert.equal(status, 200);
    assert.equal(json.choices[0].message.content, 'confer-protocol-test');

    // The ignored fields must not appear in the upstream request options.
    assert.equal(client.calls.length, 1);
    assert.ok(!('streamOptions' in client.calls[0]!.options));
    assert.ok(!('user' in client.calls[0]!.options));
  } finally {
    server.close();
  }
});

test('tools are mapped to clientTools and tool_choice filters them', async () => {
  const client = new MockClient();
  const { server, url } = await startFacade(client);
  try {
    await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({
        messages: [{ role: 'user', content: 'x' }],
        tools: [
          {
            type: 'function',
            function: { name: 'get_weather', description: 'weather lookup', parameters: { type: 'object' } },
          },
          {
            type: 'function',
            function: { name: 'get_time', description: 'clock', parameters: {} },
          },
        ],
        tool_choice: { type: 'function', function: { name: 'get_time' } },
      }),
    );
    assert.equal(client.calls.length, 1);
    const tools = client.calls[0]!.options['clientTools'] as Array<{ name: string; description: string }>;
    assert.deepEqual(tools.map((t) => t.name), ['get_time']);
    assert.equal(tools[0]!.description, 'clock');
  } finally {
    server.close();
  }
});

test('tool_choice none omits clientTools entirely', async () => {
  const client = new MockClient();
  const { server, url } = await startFacade(client);
  try {
    await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({
        messages: [{ role: 'user', content: 'x' }],
        tools: [{ type: 'function', function: { name: 'f', description: '', parameters: {} } }],
        tool_choice: 'none',
      }),
    );
    assert.equal(client.calls[0]!.options['clientTools'], undefined);
  } finally {
    server.close();
  }
});

test('non-function tool types are rejected', async () => {
  const { server, url } = await startFacade(new MockClient());
  try {
    const { status, json } = await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({
        messages: [{ role: 'user', content: 'x' }],
        tools: [{ type: 'code_interpreter' }],
      }),
    );
    assert.equal(status, 400);
    assert.match(json.error.message as string, /code_interpreter/);
  } finally {
    server.close();
  }
});

test('resume flow: assistant.tool_calls and role:tool map to upstream tool_call/tool_response', async () => {
  const client = new MockClient();
  const { server, url } = await startFacade(client);
  try {
    await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({
        messages: [
          { role: 'user', content: 'what time is it?' },
          {
            role: 'assistant',
            content: null,
            tool_calls: [
              {
                id: 'call_abc',
                type: 'function',
                function: { name: 'get_time', arguments: '{"tz":"UTC"}' },
              },
            ],
          },
          { role: 'tool', tool_call_id: 'call_abc', content: '12:00' },
        ],
      }),
    );

    assert.equal(client.calls.length, 1);
    assert.deepEqual(
      client.calls[0]!.messages.slice(1),
      [
        {
          role: 'tool_call',
          content: JSON.stringify({
            toolCallId: 'call_abc',
            toolName: 'get_time',
            toolArguments: '{"tz":"UTC"}',
          }),
        },
        {
          role: 'tool_response',
          content: JSON.stringify({
            toolCallId: 'call_abc',
            toolName: 'get_time',
            content: '12:00',
          }),
        },
      ],
    );
  } finally {
    server.close();
  }
});

test('tool result referencing an unknown tool_call_id is rejected', async () => {
  const { server, url } = await startFacade(new MockClient());
  try {
    const { status } = await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({
        messages: [
          { role: 'user', content: 'x' },
          { role: 'tool', tool_call_id: 'missing', content: 'y' },
        ],
      }),
    );
    assert.equal(status, 400);
  } finally {
    server.close();
  }
});

test('non-streaming response carries tool_calls with finish_reason tool_calls', async () => {
  const client = new MockClient();
  client.events = [
    { type: 'client_tool_call', toolCallId: 'call_xyz', toolName: 'get_weather', toolArguments: '{"city":"Oslo"}' },
    { type: 'completion', pendingToolCalls: true },
  ];
  const { server, url } = await startFacade(client);
  try {
    // The facade always streams internally; with no client_tool_call handling
    // by the caller this surfaces as message.tool_calls in the JSON response.
    const { status, json } = await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({ messages: [{ role: 'user', content: 'weather?' }] }),
    );
    assert.equal(status, 200);
    assert.equal(json.choices[0].finish_reason, 'tool_calls');
    assert.equal(json.choices[0].message.tool_calls[0].id, 'call_xyz');
    assert.equal(json.choices[0].message.tool_calls[0].function.name, 'get_weather');
    assert.equal(json.choices[0].message.tool_calls[0].function.arguments, '{"city":"Oslo"}');
  } finally {
    server.close();
  }
});

test('SSE streaming surfaces client_tool_call as tool_calls delta with finish_reason tool_calls', async () => {
  const client = new MockClient();
  client.events = [
    { type: 'content', content: 'checking…', model: 'test' },
    {
      type: 'client_tool_call',
      toolCallId: 'call_42',
      toolName: 'get_weather',
      toolArguments: '{"city":"Oslo"}',
    },
    { type: 'completion', pendingToolCalls: true },
  ];
  const { server, url } = await startFacade(client);
  try {
    const { text } = await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({ messages: [{ role: 'user', content: 'weather?' }], stream: true }),
    );
    const dataLines = text.split('\n').filter((l) => l.startsWith('data: ') && l !== 'data: [DONE]');
    const chunks = dataLines.map((l) => JSON.parse(l.slice(6)));
    const toolChunk = chunks.find((c) => c.choices[0].delta.tool_calls !== undefined);
    assert.ok(toolChunk, 'expected a tool_calls delta chunk');
    const delta = toolChunk.choices[0].delta.tool_calls[0];
    assert.equal(delta.id, 'call_42');
    assert.equal(delta.type, 'function');
    assert.equal(delta.function.name, 'get_weather');
    assert.equal(delta.function.arguments, '{"city":"Oslo"}');
    assert.equal(chunks[chunks.length - 1].choices[0].finish_reason, 'tool_calls');
  } finally {
    server.close();
  }
});
test('unknown model ids are rejected', async () => {
  const { server, url } = await startFacade(new MockClient());
  try {
    const { status, json } = await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({ model: 'gpt-4o', messages: [{ role: 'user', content: 'x' }] }),
    );
    assert.equal(status, 400);
    assert.equal(json.error.code, 'unsupported_parameter');
  } finally {
    server.close();
  }
});

test('SSE streaming maps token/thinking/completion events correctly', async () => {
  const client = new MockClient();
  client.events = [
    { type: 'content', content: 'Hel', model: 'test' },
    { type: 'thinking', content: 'pondering' },
    { type: 'content', content: 'lo', model: 'test' },
    { type: 'completion', contextTokens: 42 },
  ];
  const { server, url } = await startFacade(client, { exposeThinking: false });
  try {
    const { status, text } = await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({ messages: [{ role: 'user', content: 'hi' }], stream: true }),
    );
    assert.equal(status, 200);

    const dataLines = text.split('\n').filter((l) => l.startsWith('data: '));
    const chunks = dataLines.slice(0, -1).map((l) => JSON.parse(l.slice(6)));
    assert.equal(dataLines[dataLines.length - 1], 'data: [DONE]');

    // First chunk carries the assistant role.
    assert.deepEqual(chunks[0].choices[0].delta, { role: 'assistant', content: 'Hel' });
    // Thinking suppressed by default.
    const reasoning = chunks.filter((c) => c.choices[0].delta.reasoning_content !== undefined);
    assert.equal(reasoning.length, 0);
    // Content deltas in order.
    assert.equal(chunks[1].choices[0].delta.content, 'lo');
    // Terminal chunk sets finish_reason then DONE.
    assert.equal(chunks[chunks.length - 1].choices[0].finish_reason, 'stop');
    assert.ok(chunks.every((c) => c.object === 'chat.completion.chunk'));
  } finally {
    server.close();
  }
});

test('thinking deltas are exposed as reasoning_content when enabled', async () => {
  const client = new MockClient();
  client.events = [
    { type: 'thinking', content: 'hmm' },
    { type: 'content', content: 'answer', model: 'test' },
    { type: 'completion' },
  ];
  const { server, url } = await startFacade(client, { exposeThinking: true });
  try {
    const { text } = await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({ messages: [{ role: 'user', content: 'hi' }], stream: true }),
    );
    assert.match(text, /reasoning_content/);
    assert.match(text, /"hmm"/);
  } finally {
    server.close();
  }
});

test('transport failures are reported as 502 upstream errors', async () => {
  const alwaysFail: FacadeClient = {
    async chatCompletion() {
      const error = new Error('Connection closed by peer (code 1011): Handshake failed.');
      error.name = 'ConnectionClosedError';
      throw error;
    },
    async chatCompletionStream() {
      const error = new Error('Connection closed by peer (code 1011)');
      error.name = 'ConnectionClosedError';
      throw error;
    },
    close(): void {},
  };

  const { server, url } = await startFacade(alwaysFail);
  try {
    const { status, json } = await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({ messages: [{ role: 'user', content: 'x' }] }),
    );
    assert.equal(status, 502);
    assert.equal(json.error.type, 'upstream_error');
  } finally {
    server.close();
  }
});

test('connection drops trigger a single transparent reconnect', async () => {
  const client = new MockClient();
  class Fail extends Error {
    constructor() {
      super('Connection closed by peer (code 1011)');
      this.name = 'ConnectionClosedError';
    }
  }
  client.failNextWith = new Fail(); // fails once, reconnect succeeds
  const { server, url } = await startFacade(client);
  try {
    const { status, json } = await postJson(
      url,
      '/v1/chat/completions',
      JSON.stringify({ messages: [{ role: 'user', content: 'x' }] }),
    );
    assert.equal(status, 200);
    assert.equal(json.choices[0].message.content, 'confer-protocol-test');
  } finally {
    server.close();
  }
});
