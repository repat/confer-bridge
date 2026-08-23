/**
 * Attestation gate tests against the real envelope schema (modules 2036 +
 * 2037): platform dispatch, Intel JWT verification, report-data key binding,
 * TDX claims, RTMR/manifest-hash checks, and the sigstore step.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bytesToHex } from '@noble/hashes/utils.js';
import { TdxAttestationValidator, ACCEPTED_PLATFORM } from '../src/confer/noise/attestation.js';
import { generateKeypair } from '../src/confer/noise/symmetric-state.js';
import { AttestationRejectedError, UpstreamProtocolChangedError } from '../src/confer/errors.js';
import {
  createAttestationFixture,
  TEST_RTVR1,
  type AttestationFixture,
  type EnvelopeOverrides,
} from './helpers/attestation-fixtures.js';

interface Context {
  fixture: AttestationFixture;
  validator: TdxAttestationValidator;
}

test.before(async () => {
  const fixture = await createAttestationFixture();
  context = {
    fixture,
    validator: new TdxAttestationValidator({
      jwks: fixture.jwks,
      sigstoreVerifierFactory: fixture.verifierFactory,
    }),
  };
});

let context: Context;

function remoteKey(): Uint8Array {
  return generateKeypair().publicKey;
}

async function validEnvelope(key = remoteKey(), overrides: EnvelopeOverrides = {}) {
  const payload = await context.fixture.buildEnvelope({ remoteStaticKeyHex: bytesToHex(key), ...overrides });
  return { key, payload };
}

test('valid full-chain envelope passes', async () => {
  const { key, payload } = await validEnvelope();
  await context.validator.validateFromPayload(payload, key);
});

test('SEV-SNP attestation is rejected outright', async () => {
  const { key, payload } = await validEnvelope(undefined, { platform: 'SEV-SNP' });
  await assert.rejects(context.validator.validateFromPayload(payload, key), AttestationRejectedError);
});

test('unknown platform is rejected', async () => {
  const { key, payload } = await validEnvelope(undefined, { platform: 'SGX' });
  await assert.rejects(context.validator.validateFromPayload(payload, key), AttestationRejectedError);
});

test('JWT signed by an untrusted key is rejected', async () => {
  // A second fixture has its own signing key not present in the first JWKS.
  const otherFixture = await createAttestationFixture();
  const key = remoteKey();
  const foreignPayload = await otherFixture.buildEnvelope({ remoteStaticKeyHex: bytesToHex(key) });
  await assert.rejects(context.validator.validateFromPayload(foreignPayload, key), AttestationRejectedError);
});

test('report-data mismatch is rejected (constant-time binding)', async () => {
  const envelopeKey = remoteKey();
  const validatorKey = remoteKey();
  const payload = await context.fixture.buildEnvelope({ remoteStaticKeyHex: bytesToHex(envelopeKey) });
  await assert.rejects(
    context.validator.validateFromPayload(payload, validatorKey),
    AttestationRejectedError,
  );
});

test('missing report data fails closed as a protocol change', async () => {
  const { key, payload } = await validEnvelope(undefined, { omitReportData: true });
  await assert.rejects(context.validator.validateFromPayload(payload, key), UpstreamProtocolChangedError);
});

test('debuggable TDX environment is rejected', async () => {
  const { key, payload } = await validEnvelope(undefined, { debuggable: true });
  await assert.rejects(context.validator.validateFromPayload(payload, key), AttestationRejectedError);
});

test('SEAM SVN below 1 is rejected', async () => {
  const { key, payload } = await validEnvelope(undefined, { seamsvn: 0 });
  await assert.rejects(context.validator.validateFromPayload(payload, key), AttestationRejectedError);
});

test('RTMR mismatch between manifest and attestation is rejected', async () => {
  // JWT reports one runtime measurement; the signed manifest pins another.
  const { key, payload } = await validEnvelope(undefined, {
    rtmr1: 'f'.repeat(96),
    manifestRtmr1: TEST_RTVR1,
  });
  await assert.rejects(context.validator.validateFromPayload(payload, key), AttestationRejectedError);
});

test('corrupt manifest digest is rejected', async () => {
  const { key, payload } = await validEnvelope(undefined, { corruptDigest: true });
  await assert.rejects(context.validator.validateFromPayload(payload, key), AttestationRejectedError);
});

test('sigstore failure is rejected', async () => {
  const { key, payload } = await validEnvelope(undefined, { sigstoreFails: true });
  await assert.rejects(context.validator.validateFromPayload(payload, key), AttestationRejectedError);
});

test('non-JSON payloads fail closed as a protocol change', async () => {
  const key = remoteKey();
  await assert.rejects(
    context.validator.validateFromPayload(new Uint8Array([1, 2, 3]), key),
    UpstreamProtocolChangedError,
  );
});

test('envelope with missing fields fails closed as a protocol change', async () => {
  const key = remoteKey();
  await assert.rejects(
    context.validator.validateFromPayload(new TextEncoder().encode(JSON.stringify({ platform: ACCEPTED_PLATFORM })), key),
    UpstreamProtocolChangedError,
  );
});
