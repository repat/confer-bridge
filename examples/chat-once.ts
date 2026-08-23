/**
 * One-shot live test against the real confer.to inference endpoint.
 *
 * Token options (first match wins):
 *   CONFER_ACCESS_TOKEN          REST access token ('auth_token' in the
 *                                browser's localStorage); the script fetches
 *                                a fresh model-session token automatically.
 *   CONFER_MODEL_SESSION_TOKEN   A model-session token exported directly.
 *
 * Optional diagnostics:
 *   CONFER_DEBUG_HANDSHAKE=1     Print handshake trace events (step names and
 *                                byte lengths only; never key material).
 *
 * Sends the harmless prompt "Return exactly: confer-protocol-test" once
 * through the attested transport and prints the response. Never logs or
 * stores tokens. See docs/MODEL_SESSION_TOKEN.md for token instructions and
 * README.md ("Talking to the real confer.to servers") for failure modes.
 */
import {
  ConferClient,
  EnvModelSessionTokenProvider,
  RestModelSessionTokenProvider,
  type ModelSessionTokenProvider,
} from "../src/confer/client.js";
import { TdxAttestationValidator } from "../src/confer/noise/attestation.js";
import type { HandshakeTraceEvent } from "../src/confer/noise-websocket-client.js";
import {
  AttestationRejectedError,
  ConnectionClosedError,
  HandshakeFailedError,
  PaymentRequiredError,
  RequestTimeoutError,
  SessionTokenError,
  UpstreamProtocolChangedError,
} from "../src/confer/errors.js";

function env(name: string): string | undefined {
  const value = process.env[name];
  return value && value.length > 0 ? value : undefined;
}

function selectTokenProvider(): ModelSessionTokenProvider | null {
  const accessToken = env('CONFER_ACCESS_TOKEN');
  if (accessToken) return new RestModelSessionTokenProvider(accessToken);
  const modelSessionToken = env('CONFER_MODEL_SESSION_TOKEN');
  if (modelSessionToken) return new EnvModelSessionTokenProvider();
  return null;
}

function printTrace(event: HandshakeTraceEvent): void {
  switch (event.step) {
    case 'message-two-aead-failed':
      console.error(`[trace] message two AEAD failed (received ${event.length} bytes)`);
      if (event.utf8Preview !== undefined) {
        console.error(`[trace] peer replied with printable text, not Noise:`);
        console.error(`[trace] ${JSON.stringify(event.utf8Preview)}`);
        console.error('[trace] This usually means the token was rejected server-side.');
      } else {
        console.error('[trace] Received binary data failed to authenticate.');
        console.error('[trace] Expected >=80 bytes for a valid XX message two; check lengths against module 1959/1970 evidence.');
      }
      break;
    case 'attestation-rejected':
      console.error(`[trace] attestation rejected: ${event.reason}`);
      break;
    case 'handshake-extra-record':
      console.error(`[trace] EXTRA handshake record received (${event.length} bytes)`);
      console.error('[trace] The peer sent more than one record during the handshake;');
      console.error('[trace] this suggests fragmentation or an unexpected preamble.');
      break;
    case 'established':
      console.error('[trace] transport established');
      break;
    default:
      console.error(`[trace] ${event.step}${'length' in event ? ` (${event.length} bytes)` : ''}`);
  }
}

async function main(): Promise<void> {
  const debug = process.env['CONFER_DEBUG_HANDSHAKE'] === '1';

  const provider = selectTokenProvider();
  if (!provider) {
    console.error('No token configured. Set CONFER_ACCESS_TOKEN or CONFER_MODEL_SESSION_TOKEN.');
    console.error('Step-by-step instructions: docs/MODEL_SESSION_TOKEN.md');
    process.exitCode = 1;
    return;
  }

  let client: ConferClient | null = null;
  try {
    client = new ConferClient({
      tokenProvider: provider,
      validator: new TdxAttestationValidator(),
      ...(debug ? { onHandshakeTrace: printTrace } : {}),
    });

    await client.connect();
    console.log("Connected: Noise handshake complete, TDX attestation verified.");

    const answer = await client.chatCompletion([
      { role: "user", content: "Return exactly: confer-protocol-test" },
    ]);
    console.log("Response:", answer);
  } catch (error) {
    if (error instanceof AttestationRejectedError) {
      console.error("Live test failed: the server's attestation was rejected.");
      console.error("Do NOT bypass this check; capture the payload and verify the trust root instead.");
    } else if (error instanceof UpstreamProtocolChangedError) {
      console.error("Live test failed: upstream protocol assumptions no longer hold.");
      console.error("Re-capture the frontend bundle and re-run scripts/generate-trust-root.mjs / module checks.");
    } else if (error instanceof PaymentRequiredError) {
      console.error("Live test failed: the account cannot use the model (402).");
    } else if (error instanceof SessionTokenError) {
      console.error("Live test failed: token missing, expired, or rejected.");
      console.error("Obtain fresh tokens from your authorized session; see docs/MODEL_SESSION_TOKEN.md.");
    } else if (error instanceof ConnectionClosedError) {
      console.error(`Live test failed: the server closed the connection. ${error.message}`);
      if (error.closeCode === 1002) {
        console.error("Code 1002 usually means a protocol-level rejection; compare with module evidence.");
      }
    } else if (error instanceof RequestTimeoutError) {
      console.error(`Live test failed: no response within ${error.timeoutMs} ms.`);
    } else if (error instanceof HandshakeFailedError) {
      console.error("Live test failed at the Noise handshake.");
      console.error("Run once with CONFER_DEBUG_HANDSHAKE=1 to see which step diverged.");
    } else {
      console.error(`Live test failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    process.exitCode = 1;
  } finally {
    client?.close();
  }
}

void main();
