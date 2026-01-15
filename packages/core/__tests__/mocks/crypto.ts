/**
 * Mock Crypto Provider
 */

import type { CryptoProvider } from '../../src/providers/crypto.js';

/**
 * Create a mock crypto provider
 */
export function createMockCrypto(): CryptoProvider {
  let counter = 0;

  return {
    async randomBytes(length: number): Promise<Uint8Array> {
      // Generate deterministic but unique bytes for testing
      const bytes = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        bytes[i] = (counter + i) % 256;
      }
      counter++;
      return bytes;
    },

    async sha256(data: string): Promise<Uint8Array> {
      // Simple deterministic hash for testing (NOT cryptographically secure)
      // This ensures different inputs produce different outputs
      const encoder = new TextEncoder();
      const bytes = encoder.encode(data);
      const hash = new Uint8Array(32);

      // Simple but effective mixing function
      // Use xorshift-like operations to spread bits
      let h = 0x811c9dc5; // FNV offset basis
      for (let i = 0; i < bytes.length; i++) {
        h ^= bytes[i];
        h = (h * 0x01000193) >>> 0; // FNV prime
      }

      // Fill hash array with mixed values
      for (let i = 0; i < 32; i++) {
        h ^= (h << 13) >>> 0;
        h ^= (h >>> 17) >>> 0;
        h ^= (h << 5) >>> 0;
        hash[i] = h & 0xff;
      }

      return hash;
    },

    async generateCodeVerifier(): Promise<string> {
      const bytes = await this.randomBytes(32);
      return base64urlEncode(bytes);
    },

    async generateCodeChallenge(verifier: string): Promise<string> {
      const hash = await this.sha256(verifier);
      return base64urlEncode(hash);
    },
  };
}

/**
 * Simple base64url encode for mocks
 */
function base64urlEncode(bytes: Uint8Array): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let result = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = bytes[i + 1] ?? 0;
    const c = bytes[i + 2] ?? 0;

    result += chars[a >> 2];
    result += chars[((a & 3) << 4) | (b >> 4)];
    if (i + 1 < bytes.length) {
      result += chars[((b & 15) << 2) | (c >> 6)];
    }
    if (i + 2 < bytes.length) {
      result += chars[c & 63];
    }
  }
  return result;
}
