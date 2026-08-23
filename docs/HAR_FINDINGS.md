# Findings from `confer.to.har`

## Scope and confidence

This document describes only evidence in the HAR captured on 2026-08-22. It contains 62 entries, all with JSON (or empty) response bodies, produced by Chrome WebInspector HAR 1.2. No JavaScript, WebAssembly, HTML, WebSocket frames, EventSource frames, or TEE inference exchange was captured.

The HAR alone could not establish encryption, attestation, inference, or streaming details. Those gaps are now addressed by the separately captured frontend bundles in [the bundle analysis](FRONTEND_BUNDLE_ANALYSIS.md); the evidence in this file remains limited to the HAR.

## Observed hosts

| Host | Role supported by the HAR |
| --- | --- |
| `confer.to` | Version polling (`/version.json`) |
| `api.confer.to` | User, billing, chat, memory, telemetry, and model-token APIs |

## Observed application endpoints

| Method | Route | Request fields observed | Response fields observed | Interpretation |
| --- | --- | --- | --- | --- |
| `GET` | `/v1/users/whoami` | — | `credentials`, `email`, `featureFlags`, `id`, `passkeyCredentialId`, `profileSettings`, `subscription`, `usage` | Signed-in user state |
| `GET` | `/v1/tokens/model` | — | `token` | A model-related token exists; its purpose and cryptographic role are unknown |
| `GET` | `/v1/chats` | — | `folders`, `items` | Chat index |
| `PUT` | `/v1/chats` | `ciphertext`, `encryptedKey` | `ciphertext`, `createdAt`, `encryptedKey`, `id`, `lastMessageAt` | Create encrypted chat record |
| `PATCH` | `/v1/chats/{chatId}` | `ciphertext` | `ciphertext`, `createdAt`, `encryptedKey`, `id`, `lastMessageAt` | Update encrypted chat metadata |
| `DELETE` | `/v1/chats/{chatId}` | — | empty | Delete chat |
| `GET` | `/v1/chats/{chatId}/messages` | — | `messages` | Fetch encrypted messages; a `since` query was also observed |
| `PUT` | `/v1/chats/{chatId}/messages` | `ciphertext` | `ciphertext`, `createdAt`, `messageId` | Persist encrypted message |
| `GET` | `/v1/memories` | — | `memories` | Memory collection |
| `GET` | `/v1/billing/plans` | — | array | Billing metadata |
| `GET` | `/v1/billing/subscription` | — | `provider`, `status`, `tier` | Subscription metadata |
| `POST` | `/v1/status/update` | `distinctId`, `event`, `properties` (and once `userId`) | `status` | Product telemetry; not part of the adapter |
| `GET` | `https://confer.to/version.json` | — | `buildTime` | Frontend-version signal |

## Encrypted record observations

The request fields named `ciphertext` and `encryptedKey` are strings matching standard Base64 character patterns (not Base64URL in the captured entries). The HAR shows these lengths:

| Operation | `ciphertext` character lengths | `encryptedKey` character length |
| --- | --- | --- |
| Create chat | 164 | 80 |
| Patch chat | 172 | not sent |
| Store message | 88, 216, 264, 1,992, 9,520 | not sent |

Bundle module `1283` now confirms that these are standard-Base64 encodings of `12-byte IV || AES-GCM ciphertext-with-tag`. See [the bundle analysis](FRONTEND_BUNDLE_ANALYSIS.md#encrypted-chat-and-message-storage).

## Transport observations

- The recorded API calls use ordinary HTTPS JSON requests.
- The HAR did not show an `Authorization` request-header name on the representative application calls. That is not proof that authentication is cookie-free or token-free: HAR/browser export settings can omit sensitive header values or cookies.
- No request in this HAR is identifiable as an inference call. The observed `messages` calls appear to persist encrypted content after a chat action, not to invoke a model.

## What this gives the implementation

It provides a storage API map and clear encrypted-data boundary:

```text
plaintext chat/message object
  → browser-derived crypto adapter (missing evidence)
  → Base64 ciphertext (+ encrypted chat key on chat creation)
  → api.confer.to chat/message persistence routes
```

It does not itself provide the model/TEE request path; bundle modules `1958`, `1959`, and `2029` provide that path. The HAR and bundles should be kept as distinct sources of evidence.
