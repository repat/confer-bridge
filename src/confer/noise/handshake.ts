/**
 * Noise_XX_25519_AESGCM_SHA256 handshake, browser-equivalent initiator role
 * and a responder role used only for local loopback testing.
 *
 * Message sizes on the wire with EMPTY payloads, per the Noise spec and
 * browser module 1970 (payloads always pass through the cipher state; a
 * keyless EncryptAndHash still mixes the payload into h, and a keyed one
 * appends a 16-byte AEAD tag):
 *   message 1: 32 bytes  (cleartext ephemeral)
 *   message 2: 80 bytes + encrypted payload + tag
 *   message 3: 64 bytes  (encrypted static + sealed empty payload)
 *
 * The caller MUST validate the attestation payload returned by
 * `readMessageTwo` against the remote static key before calling
 * `writeMessageThree`. See docs/FRONTEND_BUNDLE_ANALYSIS.md.
 */
import { concatBytes } from '@noble/hashes/utils.js';
import {
  DHLEN,
  dh,
  generateKeypair,
  MAX_MESSAGE_LEN,
  SymmetricState,
  TAGLEN,
  type KeyPair,
} from './symmetric-state.js';
import {
  HandshakeFailedError,
  TransportFrameError,
  UpstreamProtocolChangedError,
} from '../errors.js';

function readWithLength(buffer: Uint8Array, offset: number, length: number): { data: Uint8Array; next: number } {
  if (buffer.length < offset + length) {
    throw new UpstreamProtocolChangedError('Handshake message shorter than the XX pattern requires.');
  }
  return { data: buffer.subarray(offset, offset + length), next: offset + length };
}

const EMPTY = new Uint8Array(0);

export class NoiseXXInitiator {
  private readonly ss = new SymmetricState();
  private readonly e: KeyPair;
  private remoteStatic: Uint8Array | null = null;
  private remoteEphemeral: Uint8Array | null = null;
  private step = 0;

  constructor(
    private readonly staticKeypair: KeyPair,
    private readonly prologue: Uint8Array = EMPTY,
  ) {
    this.e = generateKeypair();
  }

  getRemoteStaticKey(): Uint8Array {
    if (!this.remoteStatic) throw new HandshakeFailedError('Remote static key not yet known.');
    return this.remoteStatic;
  }

  writeMessageOne(payload: Uint8Array = EMPTY): Uint8Array {
    if (this.step !== 0) throw new UpstreamProtocolChangedError('writeMessageOne called out of order.');
    this.ss.mixHash(this.prologue);
    // e token: no key is set yet, so encryptAndHash returns the ephemeral
    // unchanged — but it still mixes it into h (spec + module 1970).
    const parts: Uint8Array[] = [this.ss.encryptAndHash(this.e.publicKey)];
    // The payload goes through encryptAndHash too. Keyless EncryptAndHash of
    // an empty payload still performs MixHash(""), which changes h; skipping
    // this caused AEAD failures against the production server.
    parts.push(this.ss.encryptAndHash(payload));
    this.step = 1;
    return concatBytes(...parts);
  }

  readMessageTwo(wire: Uint8Array): Uint8Array {
    if (this.step !== 1) throw new UpstreamProtocolChangedError('readMessageTwo called out of order.');
    if (wire.length < DHLEN + DHLEN + TAGLEN) {
      throw new UpstreamProtocolChangedError('Handshake message truncated.');
    }

    const re = readWithLength(wire, 0, DHLEN).data;
    const rePlaintext = this.ss.decryptAndHash(re);
    if (rePlaintext.length !== DHLEN) throw new UpstreamProtocolChangedError('Responder ephemeral key has wrong length.');
    // Saved for the se operation in writeMessageThree: XX mixes
    // DH(initiator static, responder EPHEMERAL), not the responder static.
    this.remoteEphemeral = new Uint8Array(rePlaintext);

    this.ss.mixKey(dh(this.e.privateKey, rePlaintext));

    const rsCiphertext = readWithLength(wire, DHLEN, DHLEN + TAGLEN).data;
    const rs = this.ss.decryptAndHash(rsCiphertext);
    if (rs.length !== DHLEN) throw new UpstreamProtocolChangedError('Responder static key has wrong length.');
    this.remoteStatic = new Uint8Array(rs);

    this.ss.mixKey(dh(this.e.privateKey, rs));

    // The message-two payload is encrypted under the post-es key.
    const payloadOffset = DHLEN + DHLEN + TAGLEN;
    const payload = this.ss.decryptAndHash(readWithLength(wire, payloadOffset, wire.length - payloadOffset).data);
    this.step = 2;
    return payload;
  }

  writeMessageThree(payload: Uint8Array = EMPTY): Uint8Array {
    if (this.step !== 2) throw new UpstreamProtocolChangedError('writeMessageThree called out of order.');
    const enc = this.ss.encryptAndHash(this.staticKeypair.publicKey);
    // se token: DH(initiator static, responder EPHEMERAL) per the XX pattern.
    this.ss.mixKey(dh(this.staticKeypair.privateKey, this.remoteEphemeral!));
    // The message-three payload is encrypted under the post-se key.
    const message = concatBytes(enc, this.ss.encryptAndHash(payload));
    this.step = 3;
    return message;
  }

  split(): NoiseTransportSession {
    if (this.step !== 3) throw new UpstreamProtocolChangedError('split called before the handshake completed.');
    const { send, receive } = this.ss.split(true);
    return new NoiseTransportSession(send, receive, this.ss.getHandshakeHash());
  }
}

export class NoiseXXResponder {
  private readonly ss = new SymmetricState();
  private readonly e: KeyPair;
  private remoteEphemeral: Uint8Array | null = null;
  private step = 0;

  constructor(
    private readonly staticKeypair: KeyPair,
    private readonly prologue: Uint8Array = EMPTY,
  ) {
    this.e = generateKeypair();
  }

  readMessageOne(wire: Uint8Array): Uint8Array {
    if (this.step !== 0) throw new UpstreamProtocolChangedError('readMessageOne called out of order.');
    this.ss.mixHash(this.prologue);
    if (wire.length < DHLEN) throw new UpstreamProtocolChangedError('Handshake message truncated.');
    const ie = readWithLength(wire, 0, DHLEN).data;
    const iePlaintext = this.ss.decryptAndHash(ie);
    if (iePlaintext.length !== DHLEN) throw new UpstreamProtocolChangedError('Initiator ephemeral key has wrong length.');
    this.remoteEphemeral = new Uint8Array(iePlaintext);
    // Keyless decryptAndHash of the payload still mixes it into h.
    const payload = this.ss.decryptAndHash(readWithLength(wire, DHLEN, wire.length - DHLEN).data);
    this.step = 1;
    return payload;
  }

  writeMessageTwo(payload: Uint8Array = EMPTY): Uint8Array {
    if (this.step !== 1) throw new UpstreamProtocolChangedError('writeMessageTwo called out of order.');
    const parts: Uint8Array[] = [];
    // e token: keyless encryptAndHash passes the ephemeral through unchanged
    // while mixing it into h.
    parts.push(this.ss.encryptAndHash(this.e.publicKey));
    this.ss.mixKey(dh(this.e.privateKey, this.remoteEphemeral!));
    const encS = this.ss.encryptAndHash(this.staticKeypair.publicKey);
    parts.push(encS);
    this.ss.mixKey(dh(this.staticKeypair.privateKey, this.remoteEphemeral!));
    // The message-two payload is encrypted under the post-es key.
    parts.push(this.ss.encryptAndHash(payload));
    this.step = 2;
    return concatBytes(...parts);
  }

  readMessageThree(wire: Uint8Array): Uint8Array {
    if (this.step !== 2) throw new UpstreamProtocolChangedError('readMessageThree called out of order.');
    if (wire.length < DHLEN + TAGLEN) {
      throw new UpstreamProtocolChangedError('Handshake message truncated.');
    }
    const body = readWithLength(wire, 0, DHLEN + TAGLEN).data;
    const is = this.ss.decryptAndHash(body);
    if (is.length !== DHLEN) throw new UpstreamProtocolChangedError('Initiator static key has wrong length.');
    // se token: DH(responder EPHEMERAL, initiator static) per the XX pattern.
    this.ss.mixKey(dh(this.e.privateKey, is));
    // The message-three payload is encrypted under the post-se key.
    const payloadOffset = DHLEN + TAGLEN;
    const payload = this.ss.decryptAndHash(readWithLength(wire, payloadOffset, wire.length - payloadOffset).data);
    this.step = 3;
    return payload;
  }

  split(): NoiseTransportSession {
    if (this.step !== 3) throw new UpstreamProtocolChangedError('split called before the handshake completed.');
    const { send, receive } = this.ss.split(false);
    return new NoiseTransportSession(send, receive, this.ss.getHandshakeHash());
  }
}

/**
 * Post-handshake transport. The first CipherState encrypts initiator→responder
 * messages; the second handles the reverse direction.
 */
export class NoiseTransportSession {
  constructor(
    private readonly sendState: SymmetricState['cipherstate'],
    private readonly receiveState: SymmetricState['cipherstate'],
    private readonly handshakeHash: Uint8Array,
  ) {}

  getHandshakeHash(): Uint8Array {
    return new Uint8Array(this.handshakeHash);
  }

  writeMessage(plaintext: Uint8Array): Uint8Array {
    if (plaintext.length > MAX_TRANSPORT_PLAINTEXT_LEN) {
      throw new UpstreamProtocolChangedError(`Transport plaintext exceeds ${MAX_TRANSPORT_PLAINTEXT_LEN} bytes.`);
    }
    return this.sendState.encryptWithAd(EMPTY, plaintext);
  }

  readMessage(ciphertext: Uint8Array): Uint8Array {
    if (ciphertext.length > MAX_MESSAGE_LEN_WIRE) {
      throw new UpstreamProtocolChangedError(`Transport record exceeds ${MAX_MESSAGE_LEN_WIRE} bytes.`);
    }
    try {
      return this.receiveState.decryptWithAd(EMPTY, ciphertext);
    } catch {
      throw new TransportFrameError('Transport record failed AEAD authentication.');
    }
  }
}

export const MAX_TRANSPORT_PLAINTEXT_LEN = MAX_MESSAGE_LEN - TAGLEN;
export const MAX_MESSAGE_LEN_WIRE = MAX_MESSAGE_LEN;
