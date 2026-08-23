/**
 * RestModelSessionTokenProvider tests against a loopback HTTP server:
 * request shape (path + Bearer header), token extraction, and error mapping.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer, type Server } from 'node:http';
import {
  EnvModelSessionTokenProvider,
  RestModelSessionTokenProvider,
} from '../src/confer/client.js';
import {
  NotSupportedError,
  SessionTokenError,
  UpstreamProtocolChangedError,
  UpstreamRequestError,
} from '../src/confer/errors.js';

function startServer(handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void): Promise<{ server: Server; url: string }> {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      resolve({ server, url: `http://127.0.0.1:${address.port}` });
    });
  });
}

test('provider requests /v1/tokens/model with the Bearer access token', async () => {
  let seenPath = '';
  let seenAuth = '';
  const { server, url } = await startServer((req, res) => {
    seenPath = req.url ?? '';
    seenAuth = req.headers['authorization'] ?? '';
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ token: 'model-session-token-123' }));
  });
  try {
    const provider = new RestModelSessionTokenProvider('access-token-abc', { baseUrl: url });
    const token = await provider.getToken();
    assert.equal(token, 'model-session-token-123');
    assert.equal(seenPath, '/v1/tokens/model');
    assert.equal(seenAuth, 'Bearer access-token-abc');
  } finally {
    server.close();
  }
});

test('401 maps to SessionTokenError without leaking the response body', async () => {
  const { server, url } = await startServer((_req, res) => {
    res.statusCode = 401;
    res.end('unauthorized');
  });
  try {
    const provider = new RestModelSessionTokenProvider('bad-token', { baseUrl: url });
    await assert.rejects(provider.getToken(), SessionTokenError);
  } finally {
    server.close();
  }
});

test('500 maps to UpstreamRequestError with the status code', async () => {
  const { server, url } = await startServer((_req, res) => {
    res.statusCode = 500;
    res.end('boom');
  });
  try {
    const provider = new RestModelSessionTokenProvider('t', { baseUrl: url });
    await assert.rejects(
      provider.getToken(),
      (error: unknown) => error instanceof UpstreamRequestError && error.status === 500,
    );
  } finally {
    server.close();
  }
});

test('malformed JSON body fails closed as a protocol change', async () => {
  const { server, url } = await startServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end('not-json{');
  });
  try {
    const provider = new RestModelSessionTokenProvider('t', { baseUrl: url });
    await assert.rejects(provider.getToken(), UpstreamProtocolChangedError);
  } finally {
    server.close();
  }
});

test('response without a token field fails closed as a protocol change', async () => {
  const { server, url } = await startServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ something: 'else' }));
  });
  try {
    const provider = new RestModelSessionTokenProvider('t', { baseUrl: url });
    await assert.rejects(provider.getToken(), UpstreamProtocolChangedError);
  } finally {
    server.close();
  }
});

test('empty access token is rejected at construction', () => {
  assert.throws(() => new RestModelSessionTokenProvider(''), SessionTokenError);
});

test('connection failures map to SessionTokenError', async () => {
  // Port 1 is reserved and refuses connections.
  const provider = new RestModelSessionTokenProvider('t', { baseUrl: 'http://127.0.0.1:1' });
  await assert.rejects(provider.getToken(), SessionTokenError);
});

test('EnvModelSessionTokenProvider requires the env var', async () => {
  const previous = process.env['CONFER_MODEL_SESSION_TOKEN'];
  delete process.env['CONFER_MODEL_SESSION_TOKEN'];
  try {
    await assert.rejects(
      new EnvModelSessionTokenProvider().getToken(),
      NotSupportedError,
    );
  } finally {
    if (previous !== undefined) process.env['CONFER_MODEL_SESSION_TOKEN'] = previous;
  }
});
