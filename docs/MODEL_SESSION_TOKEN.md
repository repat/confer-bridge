# Obtaining `CONFER_MODEL_SESSION_TOKEN`

This guide explains how to get a model-session token for `examples/chat-once.ts`
and `ConferClient` **from your own authorized confer.to session**.

Evidence basis: browser bundle modules 1282 (`getConfidentialModelAuthToken`),
1935 (`API_BASE_URL`), and the generated REST client (`GET /v1/tokens/model`,
Bearer auth, `credentials: 'omit'`). See
[the upstream module map](UPSTREAM_MODULE_MAP.md).

## How the token chain works

```text
sign in (OAuth Google/Apple)
  └─ confer.to issues a REST access token
       stored in the browser's localStorage under the key 'auth_token'
       └─ GET https://api.confer.to/v1/tokens/model
            Authorization: Bearer <access token>
            └─ { "token": "<model-session token>" }
                 └─ wss://inference.confer.to/websocket?token=<model-session token>
```

The access token is longer-lived (a `/v1/tokens/refresh_token` endpoint exists);
the model-session token is short-lived and session-bound.

## Step A — copy your REST access token

1. Sign in at `https://confer.to` in your desktop browser.
2. Open Developer Tools → **Application** → **Local Storage** → `https://confer.to`.
3. Find the key `auth_token` and copy its value. This is your **REST access token**.

## Step B — get the model-session token

### Option 1 (recommended): let the code do it

Use `RestModelSessionTokenProvider`, which performs the exchange for you:

```ts
import { ConferClient, RestModelSessionTokenProvider } from "../src/confer/client.js";
import { TdxAttestationValidator } from "../src/confer/noise/attestation.js";

const client = new ConferClient({
  tokenProvider: new RestModelSessionTokenProvider(process.env.CONFER_ACCESS_TOKEN!),
  validator: new TdxAttestationValidator(),
});
```

You only need to keep the access token in your environment:

```sh
export CONFER_ACCESS_TOKEN=<paste value from step A>
```

(Add it to `.env` — gitignored — rather than your shell history.)

### Option 2: manual exchange with curl

```sh
curl -s https://api.confer.to/v1/tokens/model \
  -H "Authorization: Bearer <access-token-from-step-A>"
# → {"token":"..."}   ← this value is CONFER_MODEL_SESSION_TOKEN
```

### Option 3: devtools Network tab

1. With confer.to open, reload and filter the Network tab by `tokens/model`.
2. Open that request's response; copy the `token` field.

## Step C — run the harmless live test

```sh
export CONFER_MODEL_SESSION_TOKEN=<value from step B>
npx tsx examples/chat-once.ts
```

## Hygiene and lifecycle

- Both tokens authorize *your* account. Never use anyone else's, never share,
  commit, or log yours. The example script never prints them.
- Tokens are short-lived. If you get `SessionTokenError`, repeat steps A–B.
- Use one request per test; respect confer.to's terms and service limits.
- If anything fails at the protocol level, stop and capture evidence —
  compare against the extracted browser modules in docs/. Do not bypass the attestation gate.
