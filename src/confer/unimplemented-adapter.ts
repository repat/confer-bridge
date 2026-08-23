/**
 * Placeholder adapter that always refuses. Prefer ConferAttestedCryptoAdapter.
 */
import type { ConferCryptoAdapter } from './crypto-adapter.js';
import { NotSupportedError } from './errors.js';

export class UnimplementedConferCryptoAdapter implements ConferCryptoAdapter {
  private unsupported(): never {
    throw new NotSupportedError('Confer crypto is not available in this adapter; use ConferAttestedCryptoAdapter.');
  }

  async initialize(): Promise<void> { this.unsupported(); }
  async encryptChat(_: Uint8Array): Promise<{ ciphertext: string; encryptedKey: string }> { return this.unsupported(); }
  async encryptMessage(_: Uint8Array): Promise<{ ciphertext: string }> { return this.unsupported(); }
  async decryptResponse(_: unknown): Promise<Uint8Array> { return this.unsupported(); }
}
