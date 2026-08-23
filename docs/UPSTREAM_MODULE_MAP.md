# Upstream module map

The main application bundle is Metro-formatted. Its modules have stable numeric IDs only for this exact bundle hash; treat them as a versioned reference, not a permanent API.

Run this from the repository after saving the bundle locally:

```sh
npm run extract:metro -- /absolute/path/to/entry-ebca9276d77e452faa3c6dfcfa0fd7b8.js captures/metro-modules
```

The command writes raw modules to a gitignored directory. Do not commit the extracted code or a HAR with session data.

| Module ID | Extracted filename | Why it matters |
| ---: | --- | --- |
| 1280 | `master-cipher` | Generates chat keys and wraps/unwraps them with AES-GCM |
| 1282 | `encrypting-api-client` | Applies storage crypto around the generated REST API client |
| 1283 | `chat-cipher` | Exact Base64 + IV-prefixed AES-GCM record format |
| 1935 | `auth-constants` | Runtime configuration and public sigstore identity constants (`SIGSTORE_EMAIL`, `SIGSTORE_ISSUER`, `STAGING_SIGSTORE=false`) plus expected RTMR pairs. |
| 1957 | `secure-model-provider` | Constructs/owns the secure model client |
| 1958 | `secure-model-client` | Encrypted model paths, request shapes, stream-event mapping |
| 1959 | `noise-websocket-client` | Noise handshake, token query parameter, attestation gate, transport encryption |
| 1971 | `noise-transport-framer` | Protobuf chunk framing/reassembly (MAX_CHUNK_PAYLOAD = 65519 − 30 = 65489) |
| 2029 | `noise-transport-proto` | Embedded protobuf descriptors (field numbers verified 2026-08-22) |
| 2036 | `attestation-validator` | Attestation payload dispatch: `{platform, attestation, manifest, manifestBundle}`; SEV-SNP hard-rejected |
| 2037 | `tdx-attestation-validator` | Full chain: Intel Trust Authority JWT → tdx_report_data key binding → TDX claims (MRTD allowlist, SEAM SVN ≥ 1) → manifest RTMR/hash checks → sigstore verification |
| 2038 | `sigstore-root-production` | Sigstore production trusted root (public) |
| 2039 | `sigstore-root-staging` | Sigstore staging trusted root (unused; staging compiled out) |
| 2106 | `intel-trust-authority-jwks` | Intel Trust Authority token-signing JWKS (public) |
| 2107 | `sigstore-roots` | Re-export barrel for @freedomofpress/sigstore-browser |
| 3823 | `passkey-prf` | WebAuthn PRF key creation/unlock |
| 3838 | `passkey-master-key` | PRF salt and encrypted-master-key flow |
| 3839 | `recovery-key-master-key` | Recovery-key unlocking flow |

Some mapped source references are indirect (for example `SecureModelClientProvider` is module 1957 and the client itself is module 1958). Keep the source modules together when porting.
