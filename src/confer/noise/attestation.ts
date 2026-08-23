/**
 * TDX attestation gate for the confidential inference transport.
 *
 * Faithful port of browser bundle modules 2036 (AttestationValidator) and
 * 2037 (TdxAttestationValidator), extracted from
 * entry-ebca9276d77e452faa3c6dfcfa0fd7b8.js. The chain, in the browser's
 * order:
 *
 *   1. Parse the decrypted handshake payload as an attestation envelope
 *      `{ platform, attestation, manifest, manifestBundle }`.
 *   2. Dispatch on `platform`: `TDX` continues; `SEV-SNP` is rejected
 *      outright; anything else is unsupported.
 *   3. Verify `attestation` as a JWT against the pinned Intel Trust
 *      Authority JWKS (issuer portal.trustauthority.intel.com,
 *      clockTolerance 1 min).
 *   4. Bind the attested key: JWT claim `tdx_report_data` (hex), first 32
 *      bytes constant-time-equal to the Noise remote static key.
 *   5. TDX claims: not debuggable; `tdx_mrtd` in the pinned firmware
 *      allowlist; non-empty `tdx_mrseam`; `tdx_seamsvn >= 1`.
 *   6. Manifest checks: `manifest.tdxMeasurements.rtmr1/rtmr2` equal the
 *      JWT's `tdx_rtmr1/tdx_rtmr2`; SHA-256(manifest) equals the sigstore
 *      bundle's message digest.
 *   7. Sigstore verification of the bundle against the pinned production
 *      trusted root with the pinned signer identity.
 *
 * Every failure throws. There is deliberately no bypass option.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { createLocalJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { SigstoreVerifier } from '@freedomofpress/sigstore-browser';
import {
  AttestationRejectedError,
  UpstreamProtocolChangedError,
} from '../errors.js';
import {
  EXPECTED_MRTD_ALLOWLIST,
  INTEL_TRUST_AUTHORITY_JWKS,
  PRODUCTION_TRUSTED_ROOT,
  SIGSTORE_EMAIL,
  SIGSTORE_ISSUER,
} from './trust-root.js';

export const ACCEPTED_PLATFORM = 'TDX';
const REJECTED_PLATFORM = 'SEV-SNP';
const INTEL_TRUST_AUTHORITY_ISSUER = 'https://portal.trustauthority.intel.com';

/** What the transport needs from a validator (module 1959 calls exactly this). */
export interface AttestationValidator {
  validateFromPayload(payload: Uint8Array, remoteStaticKey: Uint8Array): Promise<void>;
}

/** Top-level envelope carried as the first decrypted handshake payload. */
export interface AttestationEnvelope {
  platform: string;
  attestation: string;
  manifest: string;
  manifestBundle: string;
}

interface IntelJwtPayload extends JWTPayload {
  tdx_report_data?: unknown;
  tdx_is_debuggable?: unknown;
  tdx_mrtd?: unknown;
  tdx_mrseam?: unknown;
  tdx_seamsvn?: unknown;
  tdx_rtmr1?: unknown;
  tdx_rtmr2?: unknown;
}

interface ManifestMeasurements {
  tdxMeasurements?: { rtmr1?: unknown; rtmr2?: unknown };
}

interface SigstoreMessageDigest {
  messageSignature?: { messageDigest?: { digest?: unknown } };
}

/** Minimal structural type of the parts of SigstoreVerifier we exercise. */
export interface SigstoreVerifierLike {
  loadSigstoreRoot(root: unknown): Promise<void>;
  verifyArtifact(identity: string, issuer: string, bundle: object, data: Uint8Array): Promise<boolean>;
}

export interface TdxAttestationOptions {
  /** Test override for the pinned Intel Trust Authority JWKS. */
  jwks?: unknown;
  /** Test override for the pinned production trusted root. */
  trustedRoot?: unknown;
  /** Test overrides for the pinned sigstore identity. */
  sigstoreEmail?: string;
  sigstoreIssuer?: string;
  /** Test override for the sigstore verifier implementation. */
  sigstoreVerifierFactory?: () => SigstoreVerifierLike;
}

function constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function hexToBytesLoose(value: string): Uint8Array {
  return Buffer.from(value.toLowerCase(), 'hex');
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new UpstreamProtocolChangedError(`Attestation field ${field} missing or not a string.`);
  }
  return value;
}

function parseEnvelope(payload: Uint8Array): AttestationEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload));
  } catch {
    throw new UpstreamProtocolChangedError('Attestation payload is not valid UTF-8 JSON.');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new UpstreamProtocolChangedError('Attestation payload is not a JSON object.');
  }
  const record = parsed as Record<string, unknown>;
  // Module 2036 requires all four fields before dispatching on platform.
  return {
    platform: requireString(record['platform'], 'platform'),
    attestation: requireString(record['attestation'], 'attestation'),
    manifest: requireString(record['manifest'], 'manifest'),
    manifestBundle: requireString(record['manifestBundle'], 'manifestBundle'),
  };
}

export class TdxAttestationValidator implements AttestationValidator {
  private readonly jwks: unknown;
  private readonly trustedRoot: unknown;
  private readonly sigstoreEmail: string;
  private readonly sigstoreIssuer: string;
  private readonly verifierFactory: () => SigstoreVerifierLike;

  constructor(options: TdxAttestationOptions = {}) {
    this.jwks = options.jwks ?? INTEL_TRUST_AUTHORITY_JWKS;
    this.trustedRoot = options.trustedRoot ?? PRODUCTION_TRUSTED_ROOT;
    this.sigstoreEmail = options.sigstoreEmail ?? SIGSTORE_EMAIL;
    this.sigstoreIssuer = options.sigstoreIssuer ?? SIGSTORE_ISSUER;
    this.verifierFactory =
      options.sigstoreVerifierFactory ??
      (() => new SigstoreVerifier() as unknown as SigstoreVerifierLike);
  }

  /**
   * Validate a full handshake-payload envelope against the Noise remote
   * static key. Throws AttestationRejectedError or
   * UpstreamProtocolChangedError; never resolves on doubt.
   */
  async validateFromPayload(payload: Uint8Array, remoteStaticKey: Uint8Array): Promise<void> {
    const envelope = parseEnvelope(payload);

    // Module 2036 platform dispatch.
    if (envelope.platform === REJECTED_PLATFORM) {
      throw new AttestationRejectedError(`Untrusted attestation platform: ${envelope.platform}.`);
    }
    if (envelope.platform !== ACCEPTED_PLATFORM) {
      throw new AttestationRejectedError(`Unsupported attestation platform: ${envelope.platform}.`);
    }

    await this.validateAttestation(envelope.attestation, remoteStaticKey, envelope.manifest, envelope.manifestBundle);
  }

  /** Module 2037 validateAttestation. */
  async validateAttestation(
    jwt: string,
    remoteStaticKey: Uint8Array,
    manifest: string,
    manifestBundle: string,
  ): Promise<void> {
    let jwtPayload: IntelJwtPayload;
    try {
      const result = await jwtVerify(jwt, createLocalJWKSet(this.jwks as Parameters<typeof createLocalJWKSet>[0]), {
        issuer: INTEL_TRUST_AUTHORITY_ISSUER,
        clockTolerance: '1 min',
      });
      jwtPayload = result.payload as IntelJwtPayload;
    } catch (error) {
      throw new AttestationRejectedError(
        `Intel Trust Authority token verification failed: ${(error as Error).message}`,
      );
    }

    this.validatePublicKey(jwtPayload, remoteStaticKey);
    this.validateTdxClaims(jwtPayload);
    await this.validateManifest(manifest, manifestBundle, jwtPayload);
  }

  /** Module 2037 validatePublicKey: report data binds the server public key. */
  validatePublicKey(jwtPayload: IntelJwtPayload, remoteStaticKey: Uint8Array): void {
    const reportData = jwtPayload['tdx_report_data'];
    if (typeof reportData !== 'string' || reportData.length === 0) {
      throw new UpstreamProtocolChangedError('JWT has no tdx_report_data claim.');
    }
    const bytes = hexToBytesLoose(reportData);
    if (bytes.length < 32) {
      throw new UpstreamProtocolChangedError('tdx_report_data too short to contain a public key.');
    }
    const attested = bytes.subarray(0, 32);
    if (!constantTimeEquals(attested, remoteStaticKey)) {
      throw new AttestationRejectedError('Server public key does not match TDX attestation.');
    }
  }

  /** Module 2037 validateTdxClaims + validateMrtd. */
  validateTdxClaims(jwtPayload: IntelJwtPayload): void {
    if (jwtPayload['tdx_is_debuggable'] === true) {
      throw new AttestationRejectedError('Debug mode enabled in TDX environment.');
    }
    const mrtd = jwtPayload['tdx_mrtd'];
    if (typeof mrtd !== 'string' || mrtd.length === 0) {
      throw new UpstreamProtocolChangedError('Invalid or missing MRTD measurement.');
    }
    const normalized = mrtd.toLowerCase();
    if (!EXPECTED_MRTD_ALLOWLIST.some((allowed) => allowed.toLowerCase() === normalized)) {
      throw new AttestationRejectedError('MRTD not in allowed list (unknown firmware).');
    }
    const mrseam = jwtPayload['tdx_mrseam'];
    if (typeof mrseam !== 'string' || mrseam.length === 0) {
      throw new UpstreamProtocolChangedError('Invalid or missing MRSEAM measurement.');
    }
    const seamsvn = jwtPayload['tdx_seamsvn'];
    if (typeof seamsvn !== 'number' || !(seamsvn >= 1)) {
      throw new AttestationRejectedError('TDX SEAM SVN too low.');
    }
  }

  /** Module 2037 validateManifest + validateRtmrMeasurements + hash + sigstore. */
  async validateManifest(manifest: string, manifestBundle: string, jwtPayload: IntelJwtPayload): Promise<void> {
    const manifestBytes = new TextEncoder().encode(manifest);
    let bundle: SigstoreMessageDigest & Record<string, unknown>;
    let manifestObj: ManifestMeasurements & Record<string, unknown>;
    try {
      bundle = JSON.parse(manifestBundle);
      manifestObj = JSON.parse(manifest);
    } catch {
      throw new UpstreamProtocolChangedError('Manifest or manifest bundle is not valid JSON.');
    }

    this.validateRtmrMeasurements(manifestObj, jwtPayload);
    this.validateManifestHash(manifestBytes, bundle);

    const verifier = this.verifierFactory();
    await verifier.loadSigstoreRoot(this.trustedRoot);
    const verified = await verifier.verifyArtifact(this.sigstoreEmail, this.sigstoreIssuer, bundle, manifestBytes);
    if (!verified) {
      throw new AttestationRejectedError('Sigstore artifact verification failed.');
    }
  }

  /**
   * Module 2037 validateRtmrMeasurements: the signed manifest's expected
   * RTMR values must equal the attestation-reported runtime measurements.
   */
  validateRtmrMeasurements(manifestObj: ManifestMeasurements, jwtPayload: IntelJwtPayload): void {
    const expectedRtmr1 = manifestObj['tdxMeasurements']?.['rtmr1'];
    const expectedRtmr2 = manifestObj['tdxMeasurements']?.['rtmr2'];
    const actualRtmr1 = jwtPayload['tdx_rtmr1'];
    const actualRtmr2 = jwtPayload['tdx_rtmr2'];
    for (const [name, value] of [['rtmr1', actualRtmr1], ['rtmr2', actualRtmr2]] as const) {
      if (typeof value !== 'string') {
        throw new UpstreamProtocolChangedError(`Attestation is missing tdx_${name}.`);
      }
    }
    for (const [name, value] of [['rtmr1', expectedRtmr1], ['rtmr2', expectedRtmr2]] as const) {
      if (typeof value !== 'string') {
        throw new UpstreamProtocolChangedError(`Manifest is missing tdxMeasurements.${name}.`);
      }
    }
    const rtmr1Ok = constantTimeEquals(hexToBytesLoose(expectedRtmr1 as string), hexToBytesLoose(actualRtmr1 as string));
    const rtmr2Ok = constantTimeEquals(hexToBytesLoose(expectedRtmr2 as string), hexToBytesLoose(actualRtmr2 as string));
    if (!rtmr1Ok) throw new AttestationRejectedError('RTMR1 mismatch between manifest and attestation.');
    if (!rtmr2Ok) throw new AttestationRejectedError('RTMR2 mismatch between manifest and attestation.');
  }

  /** Module 2037 validateManifestHash: bundle digest == SHA-256(manifest bytes). */
  validateManifestHash(manifestBytes: Uint8Array, bundle: SigstoreMessageDigest): void {
    const digestB64 = bundle['messageSignature']?.['messageDigest']?.['digest'];
    if (typeof digestB64 !== 'string') {
      throw new UpstreamProtocolChangedError('No digest found in Sigstore bundle.');
    }
    const expected = Buffer.from(digestB64, 'base64');
    const computed = Buffer.from(createHash('sha256').update(manifestBytes).digest());
    if (!constantTimeEquals(new Uint8Array(expected), new Uint8Array(computed))) {
      throw new AttestationRejectedError('Manifest hash mismatch.');
    }
  }
}
