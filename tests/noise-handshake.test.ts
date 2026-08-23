/**
 * Known-answer tests pinning the Noise primitives (HMAC-SHA256 from RFC 4231,
 * HKDF-SHA256 from RFC 5869) and the XX handshake byte layout.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createCipheriv, createDecipheriv, createHmac, createHash } from 'node:crypto';
import { hexToBytes } from '@noble/hashes/utils.js';
import { hkdf, generateKeypair, SymmetricState, TAGLEN } from '../src/confer/noise/symmetric-state.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { NoiseXXInitiator, NoiseXXResponder, MAX_TRANSPORT_PLAINTEXT_LEN } from '../src/confer/noise/handshake.js';

test('HKDF-SHA256 matches the Noise spec (RFC 5869 without info)', () => {
  const ikm = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  const salt = hexToBytes('000102030405060708090a0b0c');
  const [okm1, okm2] = hkdf(salt, ikm, 2) as [Uint8Array, Uint8Array];
  // PRK per RFC 5869 §A.1.
  const prk = createHmac('sha256', Buffer.from(salt)).update(Buffer.from(ikm)).digest();
  assert.equal(prk.toString('hex'), '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
  // Noise HKDF-Expand uses no info field; verify both outputs independently.
  const t1 = createHmac('sha256', prk).update(Buffer.from([1])).digest();
  const t2 = createHmac('sha256', prk).update(Buffer.concat([t1, Buffer.from([2])])).digest();
  assert.equal(Buffer.from(okm1).toString('hex'), t1.toString('hex'));
  assert.equal(Buffer.from(okm2).toString('hex'), t2.toString('hex'));
});

test('SymmetricState initializes h to the zero-padded, UNHASHED protocol name', () => {
  // Noise spec §5.2; verified against browser module 1968 and noise-java.
  // Regression guard: hashing the padded name here caused live AEAD failures.
  const ss = new SymmetricState();
  const expected = Buffer.concat([
    Buffer.from('Noise_XX_25519_AESGCM_SHA256', 'utf8'),
    Buffer.alloc(32 - 'Noise_XX_25519_AESGCM_SHA256'.length, 0),
  ]);
  assert.equal(Buffer.from(ss.getHandshakeHash()).toString('hex'), expected.toString('hex'));
});

test('XX handshake produces spec-sized messages and a working transport', () => {
  const clientStatic = generateKeypair();
  const serverStatic = generateKeypair();

  const initiator = new NoiseXXInitiator(clientStatic);
  const responder = new NoiseXXResponder(serverStatic);

  const m1 = initiator.writeMessageOne();
  assert.equal(m1.length, 32); // cleartext ephemeral per Noise spec (no tag while keyless)

  responder.readMessageOne(m1);
  const attestationPayload = new TextEncoder().encode('{"platform":"TDX"}');
  const m2 = responder.writeMessageTwo(attestationPayload);
  // 32-byte e + 48-byte encrypted static + AEAD-sealed payload.
  assert.equal(m2.length, 80 + attestationPayload.length + TAGLEN);

  const receivedPayload = initiator.readMessageTwo(m2);
  assert.deepEqual(new TextDecoder().decode(receivedPayload), '{"platform":"TDX"}');
  assert.deepEqual(initiator.getRemoteStaticKey(), serverStatic.publicKey);

  const m3 = initiator.writeMessageThree();
  // 48-byte encrypted static + AEAD tag for the (empty) sealed payload.
  assert.equal(m3.length, 48 + TAGLEN);
  const responderPayload = responder.readMessageThree(m3);
  assert.equal(responderPayload.length, 0);

  const clientSession = initiator.split();
  const serverSession = responder.split();

  const plaintext = new TextEncoder().encode('hello confidential transport');
  const record = clientSession.writeMessage(plaintext);
  assert.equal(record.length, plaintext.length + 16); // AEAD tag overhead
  assert.deepEqual(serverSession.readMessage(record), plaintext);

  const reply = serverSession.writeMessage(plaintext);
  assert.deepEqual(clientSession.readMessage(reply), plaintext);

  // Tampered records must fail closed.
  const tampered = new Uint8Array(record);
  tampered[0]! ^= 0xff;
  assert.throws(() => clientSession.readMessage(tampered));
});

test('transport rejects oversized plaintext and ciphertext', () => {
  const clientStatic = generateKeypair();
  const serverStatic = generateKeypair();
  const initiator = new NoiseXXInitiator(clientStatic);
  const responder = new NoiseXXResponder(serverStatic);
  responder.readMessageOne(initiator.writeMessageOne());
  initiator.readMessageTwo(responder.writeMessageTwo());
  responder.readMessageThree(initiator.writeMessageThree());
  const clientSession = initiator.split();
  const serverSession = responder.split();

  assert.throws(() => clientSession.writeMessage(new Uint8Array(MAX_TRANSPORT_PLAINTEXT_LEN + 1)));
  const record = clientSession.writeMessage(new Uint8Array(MAX_TRANSPORT_PLAINTEXT_LEN));
  assert.throws(() => serverSession.readMessage(new Uint8Array(record.length + 1)));
});

test('handshake fails closed on corrupted message two', () => {
  const clientStatic = generateKeypair();
  const serverStatic = generateKeypair();
  const initiator = new NoiseXXInitiator(clientStatic);
  const responder = new NoiseXXResponder(serverStatic);
  const m1 = initiator.writeMessageOne();
  responder.readMessageOne(m1);
  const m2 = responder.writeMessageTwo();
  m2[5]! ^= 0x01;
  assert.throws(() => initiator.readMessageTwo(m2));
});

/**
 * Independent, spec-faithful XX initiator built directly on node:crypto and
 * noble primitives — deliberately sharing no code with our handshake classes.
 * If our responder picks the wrong DH input anywhere (as it once did for se),
 * the derived transport keys diverge and this test fails.
 */
test('responder interoperates with an independent Noise-spec implementation', () => {
  const sha256Buf = (data: Buffer) => Buffer.from(createHash('sha256').update(data).digest());
  const mixHash = (h: Buffer, data: Uint8Array) => sha256Buf(Buffer.concat([h, Buffer.from(data)]));
  const noiseHkdf = (ck: Buffer, ikm: Uint8Array): [Buffer, Buffer] => {
    const prk = createHmac('sha256', ck).update(Buffer.from(ikm)).digest();
    const t1 = createHmac('sha256', prk).update(Buffer.from([1])).digest();
    const t2 = createHmac('sha256', prk).update(Buffer.concat([t1, Buffer.from([2])])).digest();
    return [Buffer.from(t1), Buffer.from(t2)];
  };
  const nonce = (n: bigint) => {
    const out = Buffer.alloc(12);
    // confer.to deviates from spec §12: nonce is BIG-endian (module 1963 +
    // noise-java AESGCMOnCtrCipherState.setup both encode it this way).
    out.writeBigUInt64BE(n, 4);
    return out;
  };
  const seal = (key: Buffer, ad: Uint8Array, plaintext: Uint8Array, counter: bigint) => {
    const cipher = createCipheriv('aes-256-gcm', key, nonce(counter), { authTagLength: 16 });
    cipher.setAAD(ad);
    return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  };
  const unseal = (key: Buffer, ad: Uint8Array, data: Uint8Array, counter: bigint): Buffer => {
    const decipher = createDecipheriv('aes-256-gcm', key, nonce(counter), { authTagLength: 16 });
    decipher.setAAD(ad);
    decipher.setAuthTag(data.subarray(data.length - 16));
    return Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]);
  };

  // --- independent initiator, following Noise spec §5 in order ---
  const name = Buffer.from('Noise_XX_25519_AESGCM_SHA256');
  let h = Buffer.concat([name, Buffer.alloc(32 - name.length)]);
  let ck: Buffer = Buffer.from(h);

  const eInitiator = x25519.keygen(); // {scalar, publicKey}
  const sInitiator = x25519.keygen();

  // message one: -> e (+ empty payload through EncryptAndHash, keyless)
  // InitializeSymmetric mixes the (empty) prologue first.
  h = mixHash(h, Buffer.alloc(0));
  h = mixHash(h, Buffer.from(eInitiator.publicKey));
  h = mixHash(h, Buffer.alloc(0));
  const messageOne = Buffer.from(eInitiator.publicKey);

  // message two from OUR responder
  const serverStatic = generateKeypair();
  const responder = new NoiseXXResponder(serverStatic);
  responder.readMessageOne(messageOne);
  const m2 = responder.writeMessageTwo(new TextEncoder().encode('{"platform":"TDX"}'));

  let k: Buffer;
  // e token of message two: MixHash(re) happens before the ee decryption.
  h = mixHash(h, m2.subarray(0, 32));
  [ck, k] = noiseHkdf(ck, Buffer.from(x25519.getSharedSecret(eInitiator.secretKey, m2.subarray(0, 32))));

  const rsCiphertext = m2.subarray(32, 80);
  const rsPub = unseal(k, h, rsCiphertext, 0n);
  h = mixHash(h, rsCiphertext);

  [ck, k] = noiseHkdf(ck, Buffer.from(x25519.getSharedSecret(eInitiator.secretKey, rsPub)));
  const payload = unseal(k, h, m2.subarray(80), 0n);
  assert.equal(payload.toString(), '{"platform":"TDX"}');
  // The payload CIPHERTEXT was mixed into h by the sender; mirror it.
  h = mixHash(h, m2.subarray(80));

  // message three: -> s, se (+ sealed empty payload).
  // Nonce note: the handshake CipherState counts keyed operations
  // sequentially and only resets on MixKey. Initiator history: dec rs (0),
  // dec payload (0 after the es MixKey reset), so sealing the static uses
  // nonce 1; the post-se key starts fresh at 0 for the payload.
  const encStatic = seal(k, h, Buffer.from(sInitiator.publicKey), 1n);
  h = mixHash(h, encStatic);
  // THE critical operation under test: se uses the responder EPHEMERAL.
  [ck, k] = noiseHkdf(ck, Buffer.from(x25519.getSharedSecret(sInitiator.secretKey, m2.subarray(0, 32))));
  const sealedEmpty = seal(k, h, Buffer.alloc(0), 0n);
  responder.readMessageThree(Buffer.concat([encStatic, sealedEmpty]));

  // Transport: encrypt a record with our independently derived k1; the
  // responder session must decrypt it — proving identical split keys.
  const serverSession = responder.split();
  const [k1] = noiseHkdf(ck, Buffer.alloc(0)); // temp_k1: initiator -> responder
  const framePlaintext = new TextEncoder().encode('independent-transport-check');
  const record = seal(k1, Buffer.alloc(0), framePlaintext, 0n);
  assert.deepEqual(serverSession.readMessage(record), framePlaintext);
});
