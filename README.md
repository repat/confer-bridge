# confer-bridge

> ⚠️ This project was almost entirely written / reverse engineered by AI. I'm not in any way affiliated with [ConferLabs/confer.to](https://github.com/ConferLabs) or [Moxie](https://github.com/moxie0). It's was done purely out of interest and so that I can connect my OpenClaw instance to confer. You should treat this as alpha software as best, as there has been no independent security audit and I take no responsibility for any security problems that may arise. As stated in the [LICENSE](https://github.com/repat/confer-bridge/blob/main/LICENSE), it simply comes "as is". This also goes for any documentation, which might be only partially correct and up to date.

A personal OpenAI-compatible API gateway backed by [confer.to](https://confer.to)'s
attested confidential-computing inference transport. Requests arrive as ordinary
OpenAI chat-completion calls and are forwarded through an end-to-end encrypted
Noise session to a remote TEE (Intel TDX) whose identity is verified via Intel
Trust Authority attestation, RTMR measurements, and sigstore manifest
verification before any prompt leaves the machine.

The protocol implementation was reconstructed from the official web client's
publicly delivered bundles; the evidence documents live in [`docs/`](docs/).

## How it works

```text
OpenAI client ──HTTP/SSE──▶ facade (src/openai)
                               │ maps chat.completion ⇄ upstream events
                               ▼
                    attested Noise WebSocket (src/confer)
                               │ Noise_XX_25519_AESGCM_SHA256 + protobuf frames
                               ▼
                    wss://inference.confer.to (Intel TDX)
```

Key properties:

- The server must present a valid Intel Trust Authority attestation bound to
  its session key **before** any prompt is sent — validation fails closed.
- Prompts are never stored locally; the facade is stateless.

## Start here

1. Read [the evidence-based HAR findings](docs/HAR_FINDINGS.md) and [the frontend bundle analysis](docs/FRONTEND_BUNDLE_ANALYSIS.md).
2. Use [the upstream module map](docs/UPSTREAM_MODULE_MAP.md) to extract focused source modules into your local, gitignored `captures/` directory.
3. Run the local analyzer against a copy of a HAR. It emits a sanitized Markdown inventory and never writes request/response values:

   ```sh
   npm run analyze:har -- /absolute/path/to/confer.to.har
   ```

4. The confidential-transport stack is implemented behind `ConferCryptoAdapter` in `src/confer/crypto-adapter.ts` — see [Usage](#usage) below.

## Usage

```sh
npm install        # jose, @freedomofpress/sigstore-browser, @noble/*, ws
npm test           # 35 tests: Noise vectors, attestation chain, protobuf, framer, loopback transport
npm run typecheck
```

### Non-streaming chat

```ts
import { ConferClient, EnvModelSessionTokenProvider } from "./src/confer/client.js";
import { TdxAttestationValidator } from "./src/confer/noise/attestation.js";

const client = new ConferClient({
  tokenProvider: new EnvModelSessionTokenProvider(), // reads CONFER_MODEL_SESSION_TOKEN
  validator: new TdxAttestationValidator(),          // pinned Intel JWKS + sigstore trust root
});

await client.connect(); // token fetch → Noise_XX handshake → TDX attestation gate → transport
const answer = await client.chatCompletion([{ role: "user", content: "Hello" }]);
console.log(answer);
client.close();
```

### Streaming chat

```ts
await client.chatCompletionStream([{ role: "user", content: "Hello" }], (event) => {
  switch (event.type) {
    case "content":    process.stdout.write(event.content); break; // assistant delta
    case "thinking":   /* reasoning delta; keep out of user-facing text */ break;
    case "completion": console.log("\n[done]", event.contextTokens); break;
  }
});
```

The `ConferCryptoAdapter` boundary in `src/confer/crypto-adapter.ts` stays the single protocol-aware layer that the future OpenAI compatibility server (`src/openai/`) will call.

## Talking to the real confer.to servers

The client targets `wss://inference.confer.to/websocket?token=…` exactly as the captured browser does. Before you try it, understand what is and isn't proven.

**What you need**

1. Your own authorized confer.to account and session.
2. A model-session token. In the browser this comes from `GET /v1/tokens/model` after sign-in (module 1282, `getConfidentialModelAuthToken`). **Detailed step-by-step instructions: [docs/MODEL_SESSION_TOKEN.md](docs/MODEL_SESSION_TOKEN.md)** — either export a token manually, or use `RestModelSessionTokenProvider` with your REST access token to fetch one automatically:

   ```ts
   import { ConferClient, RestModelSessionTokenProvider } from "./src/confer/client.js";
   const client = new ConferClient({
     tokenProvider: new RestModelSessionTokenProvider(process.env.CONFER_ACCESS_TOKEN!),
     validator: new TdxAttestationValidator(),
   });
   ```
3. Put it in the environment (never in files git can see):

   ```sh
   export CONFER_MODEL_SESSION_TOKEN=...   # short-lived; treat like a password
   npx tsx examples/chat-once.ts
   ```

**What is verified vs not**

| Layer | Status |
| --- | --- |
| Protobuf field layout | Verified byte-for-byte against bundle module 2029 |
| Chunk framing (65,489-byte cap) | Verified against module 1971 |
| Attestation chain (Intel JWT, report-data binding, RTMR/sigstore) | Ported from modules 2036–2039/2106; tested locally with generated keys |
| Noise_XX_25519_AESGCM_SHA256 handshake | Implemented per the Noise spec and self-tested via loopback; **byte-level interop with the production server is NOT yet proven** |

Expect a first live attempt to possibly fail with `HANDSHAKE_FAILED` or `UpstreamProtocolChangedError`. That is the intended fail-closed behavior — do not work around it; capture evidence instead and compare against the extracted browser modules.

**Rules of engagement**

- Send only the harmless test prompt (`Return exactly: confer-protocol-test`); never private conversations.
- Tokens are short-lived and session-bound: never reuse another person's token, never commit or log yours.
- Respect confer.to's terms and service limits; one request per test run.
- Never disable or bypass the TDX attestation gate to make a connection succeed.

**Troubleshooting**

| Error | Likely cause | Correct response |
| --- | --- | --- |
| `NotSupportedError` (token) | Neither `CONFER_MODEL_SESSION_TOKEN` nor `CONFER_ACCESS_TOKEN` provided | Follow [docs/MODEL_SESSION_TOKEN.md](docs/MODEL_SESSION_TOKEN.md) |
| `HandshakeFailedError`: "AEAD authentication failed" during connect | The peer likely answered with a non-Noise message (e.g. plain-text token rejection) instead of handshake message two, or a genuine byte-level divergence exists. Verified evidence (modules 1963–1970) confirms our primitives match the browser exactly, so suspect the token first. | Re-run with `CONFER_DEBUG_HANDSHAKE=1`. If the trace shows a printable-text preview, refresh your token and retry; otherwise capture lengths and compare against module 1970 evidence |
| `HandshakeFailedError` (other) | Connection/token issues at other handshake steps | Check the message with `CONFER_DEBUG_HANDSHAKE=1`; see [docs/MODEL_SESSION_TOKEN.md](docs/MODEL_SESSION_TOKEN.md) |
| `AttestationRejectedError` / `UpstreamProtocolChangedError` | Server attestation shape changed, or pinned trust root stale | Re-capture bundle; re-run `scripts/generate-trust-root.mjs`; re-verify |
| `PaymentRequiredError` | Account tier cannot use the model | Stop; billing question, not a code bug |

## Running the OpenAI-compatible facade

`src/openai/main.ts` exposes a standard OpenAI-compatible API over the attested transport:

```sh
# .env (gitignored) — see docs/MODEL_SESSION_TOKEN.md for token setup
CONFER_ACCESS_TOKEN=<auth_token value>
FACADE_API_KEY=<any secret you invent for your own clients>

npx tsx src/openai/main.ts
# OpenAI-compatible facade listening on http://127.0.0.1:8080/v1
```

Then point any OpenAI client at it:

```sh
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $FACADE_API_KEY" \
  -H "content-type: application/json" \
  -d '{"model":"Qwen/Qwen3-235B-A22B-Instruct-2507-tput",
       "messages":[{"role":"user","content":"Hello"}]}'
```

Supported today:

- `GET /v1/models` — the single upstream model
- `POST /v1/chat/completions` — `model`, `messages`, `stream`, `temperature`,
  `top_p`, `presence_penalty`, `frequency_penalty`, `max_tokens`
- Streaming via SSE (`stream: true`) with standard `chat.completion.chunk`
  frames and `[DONE]` termination; upstream thinking deltas appear as
  `reasoning_content` only when `FACADE_EXPOSE_THINKING=1`

Anything that cannot be mapped faithfully onto the upstream (tools,
`response_format`, `n > 1`, unknown models, …) is rejected with an explicit
400 rather than silently ignored.

## Deploying on a Raspberry Pi

The facade is pure JavaScript (no native modules) and comfortably fits a Pi 4:
~15 MB of runtime dependencies plus ~60 MB of RSS. The TypeScript toolchain is
dev-only and never ships to the Pi.

**1. On your dev machine — build the deployment tarball**

```sh
npm run pack:pi        # -> confer-bridge-pi.tar.gz (dist + package files + deploy/)
scp confer-bridge-pi.tar.gz pi@<pi-address>:
```

**2. On the Pi — install**

```sh
# Node.js >= 20 (e.g. via nodesource, or: sudo apt install nodejs npm)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install -y nodejs

sudo mkdir -p /opt/confer-bridge
sudo tar -xzf ~/confer-bridge-pi.tar.gz -C /opt/confer-bridge
cd /opt/confer-bridge && sudo npm ci --omit=dev   # ~15 MB, dev tooling excluded

# Secrets (never in git; keep chmod 600)
sudo cp deploy/confer-bridge.env.example /etc/confer-bridge.env
sudo chmod 600 /etc/confer-bridge.env && sudoedit /etc/confer-bridge.env

# Service user + unit
sudo useradd -r -s /usr/sbin/nologin confer-bridge || true
sudo chown -R confer-bridge:confer-bridge /opt/confer-bridge
sudo cp deploy/confer-bridge.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now confer-bridge

curl http://127.0.0.1:8080/healthz    # {"status":"ok","upstream":false}
```

**3. Update an existing install**: `npm run pack:pi`, re-scp, re-extract over
`/opt/confer-bridge`, then `sudo systemctl restart confer-bridge`.

Notes:

- Liveness monitoring: unauthenticated `GET /healthz` returns
  `{"status":"ok","upstream":true|false}` (`upstream` = an attested transport
  is currently connected). Watch it with systemd or any uptime monitor.
- Logs go to journald (`journalctl -u confer-bridge`); nothing is written to
  disk by default, so microSD wear is negligible.
- If you prefer building on the Pi itself, clone the repo there, run
  `npm ci` (includes dev deps), `npm run build`, then follow from step 2's
  env-file onward.

## Safety and hygiene

- Do not commit HAR files, cookies, authorization headers, session tokens, private keys, prompts, or decrypted responses.
- Use only scripts delivered to and traffic generated by your authorized browser session; respect confer.to's terms and service limits.
- The existing HAR is intentionally not copied into this repository because it may contain personal data or session material.

## Layout

```text
docs/                        Evidence, next capture steps, and implementation order
docs/MODEL_SESSION_TOKEN.md  Step-by-step guide to obtaining live tokens
examples/chat-once.ts        One-shot harmless live test (opt-in, needs a token)
scripts/analyze-har.mjs      Dependency-free, sanitized HAR inventory generator
scripts/generate-trust-root.mjs  Regenerates pinned trust anchors from extracted modules
src/confer/client.ts         ConferClient: token provider + chat/stream API
src/confer/crypto-adapter.ts Protocol boundary for the future OpenAI layer
src/confer/noise/            Noise XX handshake, attestation gate, pinned trust root
src/confer/proto/            Protobuf wire codecs (verified against module 2029)
src/confer/framer.ts         Chunk framing/reassembly at the documented cap
src/openai/                  Deliberately empty boundary for the future compatibility layer
tests/                       Crypto vectors, attestation chain, framer, loopback transport
```
