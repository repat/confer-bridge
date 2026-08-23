/**
 * Stable internal error taxonomy. Callers should branch on these classes, not
 * on upstream exception text. Never include secrets, tokens, or decrypted
 * payloads in error messages.
 */

export class ConferError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Parsing, framing, or crypto assumptions no longer match the upstream. */
export class UpstreamProtocolChangedError extends ConferError {}

/** The peer failed Noise-level authentication or sent malformed frames. */
export class HandshakeFailedError extends ConferError {}

/** The WebSocket connection closed while requests were in flight. */
export class ConnectionClosedError extends ConferError {
  readonly closeCode: number;

  constructor(closeCode: number, reason: string) {
    super(`Connection closed by peer (code ${closeCode})${reason ? `: ${reason}` : ''}.`);
    this.closeCode = closeCode;
  }
}

/** A request timed out without receiving a response from the upstream. */
export class RequestTimeoutError extends ConferError {
  readonly timeoutMs: number;

  constructor(timeoutMs: number) {
    super(`No response within ${timeoutMs} ms.`);
    this.timeoutMs = timeoutMs;
  }
}

/** Remote attestation was missing, malformed, untrusted, or mismatched. */
export class AttestationRejectedError extends ConferError {}

/** A transport-mode record failed AEAD authentication or exceeded limits. */
export class TransportFrameError extends ConferError {}

/** The Noise nonce counter reached its maximum; the session must be re-established. */
export class TransportNonceExhaustedError extends ConferError {}

/** The model-session token is missing, expired, or rejected by the server. */
export class SessionTokenError extends ConferError {}

/** The upstream returned an HTTP-style error status on the transport. */
export class UpstreamRequestError extends ConferError {
  readonly status: number;

  constructor(status: number, body?: Uint8Array) {
    const text = body ? new TextDecoder().decode(body) : '';
    super(`API Error ${status}: ${text || 'Unknown error'}`);
    this.status = status;
  }
}

/** The account cannot use the model (upstream status 402); connection closes. */
export class PaymentRequiredError extends ConferError {}

/** Feature deliberately not implemented. */
export class NotSupportedError extends ConferError {}
