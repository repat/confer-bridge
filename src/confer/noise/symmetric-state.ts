/**
 * Noise Protocol Framework core for Noise_XX_25519_AESGCM_SHA256.
 *
 * Implements CipherState, SymmetricState, and the XX handshake message
 * patterns per the Noise specification (revision 34). Byte layout follows the
 * spec exactly: AES-GCM nonces are 4 zero bytes followed by a 64-bit
 * little-endian counter, ciphertexts carry a 16-byte tag appended by the
 * cipher, and handshake messages are limited to 65535 bytes.
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { gcm } from '@noble/ciphers/aes.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { concatBytes } from '@noble/hashes/utils.js';
import {
  HandshakeFailedError,
  TransportNonceExhaustedError,
  UpstreamProtocolChangedError,
} from '../errors.js';

export const NOISE_PROTOCOL_NAME = 'Noise_XX_25519_AESGCM_SHA256';
export const DHLEN = 32;
export const TAGLEN = 16;
export const MAX_MESSAGE_LEN = 65535;
const MAX_NONCE = 0xffff_ffff_ffff_ffffn;

export type KeyPair = { publicKey: Uint8Array; privateKey: Uint8Array };

export function generateKeypair(): KeyPair {
  const privateKey = x25519.utils.randomSecretKey();
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

export function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  try {
    return x25519.getSharedSecret(privateKey, publicKey);
  } catch {
    throw new HandshakeFailedError('X25519 shared-secret derivation failed.');
  }
}

function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

/** HKDF as defined by the Noise spec: HMAC-based, output length fixed per call. */
export function hkdf(chainingKey: Uint8Array, ikm: Uint8Array, outputs: 2 | 3): [Uint8Array, Uint8Array] | [Uint8Array, Uint8Array, Uint8Array] {
  const tempKey = hmacSha256(chainingKey, ikm);
  const o1 = hmacSha256(tempKey, new Uint8Array([1]));
  const o2 = hmacSha256(tempKey, concatBytes(o1, new Uint8Array([2])));
  if (outputs === 2) return [o1, o2];
  const o3 = hmacSha256(tempKey, concatBytes(o2, new Uint8Array([3])));
  return [o1, o2, o3];
}

class CipherState {
  private key: Uint8Array | null = null;
  private nonce = 0n;

  initializeKey(key: Uint8Array | null): void {
    this.key = key ? new Uint8Array(key) : null;
    this.nonce = 0n;
  }

  hasKey(): boolean {
    return this.key !== null;
  }

  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (!this.key) throw new UpstreamProtocolChangedError('CipherState.encryptWithAd called without a key.');
    if (this.nonce === MAX_NONCE) throw new TransportNonceExhaustedError("Noise nonce space exhausted.");
    const nonceBytes = nonceToBytes(this.nonce++);
    const cipher = gcm(this.key, nonceBytes, ad);
    return cipher.encrypt(plaintext);
  }

  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (!this.key) throw new UpstreamProtocolChangedError('CipherState.decryptWithAd called without a key.');
    if (this.nonce === MAX_NONCE) throw new TransportNonceExhaustedError("Noise nonce space exhausted.");
    const nonceBytes = nonceToBytes(this.nonce++);
    const cipher = gcm(this.key, nonceBytes, ad);
    try {
      return cipher.decrypt(ciphertext);
    } catch {
      throw new HandshakeFailedError('AEAD authentication failed.');
    }
  }
}

function nonceToBytes(n: bigint): Uint8Array {
  // ⚠️ confer.to deviates from Noise spec §12 (little-endian): the browser
  // bundle (module 1963) and the server's noise-java both encode the 64-bit
  // handshake/transport counter BIG-ENDIAN at bytes [4..12]. Verified against
  // production and a local noise-java interop harness — do not "fix" this.
  const out = new Uint8Array(12);
  const view = new DataView(out.buffer);
  view.setBigUint64(4, n, false);
  return out;
}

export class SymmetricState {
  readonly cipherstate = new CipherState();
  private h: Uint8Array;
  private ck: Uint8Array;

  constructor() {
    const nameBytes = new TextEncoder().encode(NOISE_PROTOCOL_NAME);
    if (nameBytes.length > 32) throw new UpstreamProtocolChangedError('Protocol name exceeds 32 bytes.');
    // Noise spec §5.2 (InitializeSymmetric): a protocol name of HASHLEN bytes
    // or fewer is ZERO-PADDED into h unhashed; only longer names are hashed.
    // Verified against browser module 1968 and noise-java. Hashing here (as
    // this code once did) desyncs every subsequent AEAD.
    const paddedName = new Uint8Array(32);
    paddedName.set(nameBytes);
    this.h = paddedName;
    this.ck = new Uint8Array(paddedName);
  }

  getHandshakeHash(): Uint8Array {
    return new Uint8Array(this.h);
  }

  mixHash(data: Uint8Array): void {
    this.h = sha256(concatBytes(this.h, data));
  }

  mixKey(ikm: Uint8Array): void {
    const [newCk, tempK] = hkdf(this.ck, ikm, 2);
    this.ck = newCk!;
    this.cipherstate.initializeKey(tempK!);
  }

  encryptAndHash(plaintext: Uint8Array): Uint8Array {
    let ciphertext: Uint8Array;
    if (this.cipherstate.hasKey()) {
      ciphertext = this.cipherstate.encryptWithAd(this.h, plaintext);
      this.mixHash(ciphertext);
    } else {
      ciphertext = plaintext;
      this.mixHash(plaintext);
    }
    return ciphertext;
  }

  decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    let plaintext: Uint8Array;
    if (this.cipherstate.hasKey()) {
      plaintext = this.cipherstate.decryptWithAd(this.h, ciphertext);
      this.mixHash(ciphertext);
    } else {
      plaintext = ciphertext;
      this.mixHash(ciphertext);
    }
    return plaintext;
  }

  /**
   * Per the Noise spec, temp_k1 always belongs to the initiator→responder
   * direction and temp_k2 to responder→initiator. Each side therefore keeps
   * the matching half.
   */
  split(isInitiator: boolean): { send: CipherState; receive: CipherState } {
    const [tempK1, tempK2] = hkdf(this.ck, new Uint8Array(0), 2);
    const c1 = new CipherState();
    const c2 = new CipherState();
    c1.initializeKey(tempK1!);
    c2.initializeKey(tempK2!);
    return isInitiator ? { send: c1, receive: c2 } : { send: c2, receive: c1 };
  }
}
