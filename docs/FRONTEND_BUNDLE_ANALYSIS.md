# Frontend bundle analysis

## Evidence set

The following locally saved, browser-delivered bundles were inspected on 2026-08-22. They are not copied into this repository; use the gitignored extraction workflow in [the module map](UPSTREAM_MODULE_MAP.md).

| File | Size | Role |
| --- | ---: | --- |
| `__expo-metro-runtime-46ac14f77b8d07852b02d57eb3e5b645.js` | 3.7 KB | Expo Metro runtime |
| `__common-1094f9ac97534a4abb53152af24d8ca6.js` | 1.6 MB | Common vendor code |
| `entry-ebca9276d77e452faa3c6dfcfa0fd7b8.js` | 8.5 MB | Application code, protocol implementation, and generated API client |

The findings below are code-backed observations from `entry-…js`; they are not inferred from ciphertext lengths.

## Architecture discovered

```text
authorized browser session
  ├─ API client → GET /v1/tokens/model → model-session token
  ├─ wss://inference.confer.to/websocket?token=…
  │    └─ Noise_XX_25519_AESGCM_SHA256 handshake
  │         └─ verify TDX attestation binds to Noise remote static key
  │              └─ encrypted protobuf-framed request/response transport
  └─ API client → encrypted chat/message persistence at api.confer.to
       └─ AES-256-GCM storage encryption unlocked from passkey/recovery key
```

The OpenAI-compatible facade belongs above the secure-model client. This facade does **not** store chat history.

## Encrypted chat and message storage

Modules `1280`, `1282`, and `1283` establish the persisted-record format.

- A master AES-256-GCM key generates an extractable, random AES-256-GCM chat key per chat/folder/profile/memory record.
- The raw chat key is encrypted under the master key and sent as `encryptedKey`.
- JSON plaintext is AES-GCM encrypted with the chat key and sent as `ciphertext`.
- Each encryption generates a random 12-byte IV.
- The stored byte layout is `IV (12 bytes) || WebCrypto AES-GCM result`; Web Crypto’s AES-GCM result includes the authentication tag.
- The byte layout is encoded with standard padded Base64 via `btoa`; it is not Base64URL.
- A persisted message removes `fullContent` and `inferenceImageRefs` before JSON encryption and keeps `createdAt` outside the ciphertext.

This exactly explains the HAR’s `ciphertext` and `encryptedKey` fields. No additional authenticated data was passed to the observed Web Crypto calls.

## Master-key unlocking

Modules `3823`, `3838`, and `3839` show that the passkey’s WebAuthn PRF output is not necessarily the long-lived master secret. The flow uses the fixed UTF-8 PRF salt `LUNIRA_KEY_1`:

1. Request a WebAuthn assertion with the PRF extension, passing that salt.
2. Import the PRF result as a non-extractable AES-256-GCM key.
3. Decrypt the account’s `encryptedMasterKey` with that PRF-derived key.
4. Import the resulting raw master secret as the AES-256-GCM master key.

The bundle also supports recovery credentials (`SECRET_KEY`) which wrap the same master secret. A Node server cannot invoke a browser passkey authenticator directly. For a personal server-side project, decide explicitly whether to use an approved recovery-key-based unlock flow or keep the key material in a local secure store after an authorized setup step. Never log or commit raw master keys, recovery keys, PRF output, or encrypted master-key blobs.

## Confidential inference transport

Modules `1958`, `1959`, `1971`, and `2029` establish the TEE path.

- Endpoint: `wss://inference.confer.to/websocket`.
- Before connection, the model-session token returned by the API client is appended as `?token=…`.
- Handshake protocol: `Noise_XX_25519_AESGCM_SHA256`, with the browser as initiator.
- The first decrypted handshake payload is parsed as attestation JSON. The browser obtains the Noise remote static key from the handshake and validates TDX attestation against that key **before** sending the final handshake message or entering transport mode.
- Validation accepts a `TDX` platform in the observed code and rejects the observed `SEV-SNP` branch. It also checks configured expected TDX measurements; preserve the full validator when porting.
- After handshake completion, all application frames are Noise-encrypted binary WebSocket messages.

Do not remove or weaken attestation validation. A connection that merely completes a Noise handshake is not equivalent to the browser’s trusted-TEE connection.

## Application wire format inside Noise

Module `2029` embeds a protobuf schema. The logical messages are:

| Message | Fields |
| --- | --- |
| `NoiseTransportFrame` | `chunk_id:int64`, `chunk_index:uint32`, `total_chunks:uint32`, `payload:bytes` |
| `WebsocketRequest` | `id:int64`, `verb:string`, `path:string`, `body:bytes`, optional `chunk:StreamChunk` |
| `StreamChunk` | `data:bytes`, `final:bool`, `seq:uint32` |
| `WebsocketResponse` | `id:int64`, `status:int32`, `body:bytes`, `headers: map<string,string>` |

The payload is serialized protobuf, wrapped in one or more `NoiseTransportFrame` messages, then encrypted with Noise. The frame payload cap is 65,489 bytes (`65,519 - 30`). Responses are reassembled by `chunk_id` and `chunk_index` before protobuf decoding.

## Model calls and streaming

Module `1958` sends the following paths through the encrypted transport:

| Path | Purpose |
| --- | --- |
| `POST /v1/vllm/chat/completions` | Chat completion, both regular and streamed |
| `POST /v1/embeddings` | Embeddings |
| `POST /v1/fetch/html` | Secure HTML fetch |
| `POST /v2/document/extract` | Document extraction |
| `GET /ping` | Keepalive every 20 seconds |

The observed chat client assigns `Qwen/Qwen3-235B-A22B-Instruct-2507-tput` as the model and sends JSON request bodies. It maps streamed JSON events as follows:

| Upstream event type | Meaning for facade |
| --- | --- |
| `token` | Assistant content delta |
| `thinking` | Reasoning/thinking delta; do not expose as normal content unless intentionally supported |
| `tool_call`, `tool_response`, `client_tool_call` | Tool protocol events; defer until basic chat works |
| `completion` | End event with context-token metadata |

## Implementation implications

1. Keep the facade stateless: accept OpenAI `messages`, pass them to the secure-model transport, and return a response. Do not recreate encrypted chat persistence yet.
2. Port the complete Noise and attestation stack, including protobuf framing, before testing against the live TEE.
3. Build a dedicated, authorized token provider. Do not reuse a copied browser token; tokens can expire and may be tied to the browser session.
4. Add OpenAI non-streaming output only after the attested round trip succeeds. Add SSE after correctly handling `token` and `completion` events.

## Still to verify live

- The model-session-token endpoint’s token lifetime and refresh behavior.
- The complete attestation validator dependency chain and all trust-root/material provenance.
- Whether the chosen Node Noise implementation’s byte-level behavior matches the extracted browser stack.
- Which user-facing OpenAI parameters confer.to accepts or ignores.
- Error/reconnect behavior under token expiration and session interruption.
