/**
 * Test fixtures for the real attestation envelope: signs Intel-style JWTs
 * with a locally generated RSA-PSS (PS384) key, builds matching manifests
 * and sigstore-bundle digests, and provides a stub sigstore verifier.
 */
import { createHash } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import type { SigstoreVerifierLike } from '../../src/confer/noise/attestation.js';

export const TEST_MRTD = '3c939d8afae2ed7cd153f962e5df0636f899f5f4bd8f790d77eb003d8f1e3a956e283e4e5fc1980ccd4bf00a3bb104ce';
export const TEST_RTVR1 = '225da8c5c388cbe4f3f3b47df36b5a83e615186cd8993bac632a9704dc2974aff3518af391c9d1d481f59796483255e9';
export const TEST_RTVR2 = 'd4e08948700235c2fc9bce1ed5907e8bae49bdc4f3533319365d348533facb66e85472633dc3436becfb00fa09a8eb54';

export interface AttestationFixture {
  /** JWKS containing exactly the test verification key. */
  jwks: { keys: JWK[] };
  verifierFactory: () => SigstoreVerifierLike;
  buildEnvelope: (options: EnvelopeOptions) => Promise<Uint8Array>;
}
interface EnvelopeOptions {
  /** Hex Noise remote static key to bind into tdx_report_data. */
  remoteStaticKeyHex: string;
  platform?: string | undefined;
  rtmr1?: string | undefined;
  rtmr2?: string | undefined;
  debuggable?: boolean | undefined;
  seamsvn?: number | undefined;
  omitReportData?: boolean | undefined;
  /** Corrupt the bundle digest to test manifest-hash rejection. */
  corruptDigest?: boolean | undefined;
  /** Make the stub sigstore verifier fail. */
  sigstoreFails?: boolean | undefined;
  /**
   * Override only the signed manifest's expected RTMR values (JWT claims
   * keep rtmr1/rtmr2); use to simulate manifest-vs-attestation mismatch.
   */
  manifestRtmr1?: string | undefined;
  manifestRtmr2?: string | undefined;
}

export type EnvelopeOverrides = Omit<EnvelopeOptions, 'remoteStaticKeyHex'>;

export async function createAttestationFixture(): Promise<AttestationFixture> {
  const { publicKey, privateKey } = await generateKeyPair('PS384', { modulusLength: 2048 });
  const publicJwk = (await exportJWK(publicKey)) as JWK;
  publicJwk.alg = 'PS384';
  publicJwk.kid = 'test-attestation-key';
  const jwks = { keys: [publicJwk] };

  let sigstoreResult = true;
  const verifierFactory = (): SigstoreVerifierLike => ({
    loadSigstoreRoot: async () => undefined,
    verifyArtifact: async () => sigstoreResult,
  });

  const signToken = async (claims: Record<string, unknown>): Promise<string> =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: 'PS384', kid: 'test-attestation-key', typ: 'JWT' })
      .setIssuer('https://portal.trustauthority.intel.com')
      .setIssuedAt()
      .setExpirationTime('10 min')
      .sign(privateKey);

  function manifestAndBundle(options: EnvelopeOptions): { manifest: string; manifestBundle: string } {
    const manifest = JSON.stringify({
      tdxMeasurements: {
        rtmr1: options.manifestRtmr1 ?? options.rtmr1 ?? TEST_RTVR1,
        rtmr2: options.manifestRtmr2 ?? options.rtmr2 ?? TEST_RTVR2,
      },
    });
    const digest = createHash('sha256').update(new TextEncoder().encode(manifest)).digest();
    if (options.corruptDigest) digest[0]! ^= 0x01;
    const manifestBundle = JSON.stringify({
      messageSignature: { messageDigest: { digest: digest.toString('base64') } },
    });
    return { manifest, manifestBundle };
  }

  async function buildEnvelope(options: EnvelopeOptions): Promise<Uint8Array> {
    // Remember the intended sigstore outcome for this envelope.
    sigstoreResult = !options.sigstoreFails;

    // Report data carries the 32-byte key plus padding, mirroring the
    // browser's >= 32 byte check with a first-32-bytes comparison.
    const claims: Record<string, unknown> = {
      tdx_report_data: options.omitReportData ? undefined : `${options.remoteStaticKeyHex}deadbeef`,
      tdx_is_debuggable: options.debuggable ?? false,
      tdx_mrtd: TEST_MRTD,
      tdx_mrseam: 'aa'.repeat(48),
      tdx_seamsvn: options.seamsvn ?? 2,
      tdx_rtmr1: options.rtmr1 ?? TEST_RTVR1,
      tdx_rtmr2: options.rtmr2 ?? TEST_RTVR2,
    };

    const attestation = await signToken(claims);
    const { manifest, manifestBundle } = manifestAndBundle(options);

    return new TextEncoder().encode(
      JSON.stringify({
        platform: options.platform ?? 'TDX',
        attestation,
        manifest,
        manifestBundle,
      }),
    );
  }

  return { jwks, verifierFactory, buildEnvelope };
}
