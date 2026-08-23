/**
 * Runnable OpenAI-compatible facade server.
 *
 * Usage (see docs/MODEL_SESSION_TOKEN.md for token setup):
 *   CONFER_ACCESS_TOKEN=... FACADE_API_KEY=my-key npx tsx src/openai/main.ts
 *
 * Then point any OpenAI client at http://127.0.0.1:<port>/v1 with the same
 * bearer key. Environment variables are read from process.env; load a .env
 * file yourself or export them in the shell.
 */
import { createFacadeServer } from './server.js';
import {
  ConferClient,
  EnvModelSessionTokenProvider,
  RestModelSessionTokenProvider,
} from '../confer/client.js';
import { TdxAttestationValidator } from '../confer/noise/attestation.js';

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.length === 0) {
    console.error(`Missing required environment variable ${name}.`);
    process.exit(1);
  }
  return value;
}

function buildConferClient(): ConferClient {
  const accessToken = process.env['CONFER_ACCESS_TOKEN'];
  const tokenProvider = accessToken
    ? new RestModelSessionTokenProvider(accessToken)
    : new EnvModelSessionTokenProvider();
  return new ConferClient({
    tokenProvider,
    validator: new TdxAttestationValidator(),
  });
}

const apiKey = requireEnv('FACADE_API_KEY');
requireEnv('CONFER_ACCESS_TOKEN'); // supported path for tokens today

let confer: ConferClient | null = null;

const server = createFacadeServer({
  apiKey,
  exposeThinking: process.env['FACADE_EXPOSE_THINKING'] === '1',
  getClient: async () => {
    if (!confer) {
      confer = buildConferClient();
      await confer.connect();
    }
    return confer;
  },
});

const port = Number(process.env['FACADE_PORT'] ?? 8080);
server.listen(port, '127.0.0.1', () => {
  console.log(`OpenAI-compatible facade listening on http://127.0.0.1:${port}/v1`);
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    confer?.close();
    server.close(() => process.exit(0));
  });
}
