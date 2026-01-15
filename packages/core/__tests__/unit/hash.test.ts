/**
 * Hash Utilities Tests
 *
 * Tests for ds_hash calculation (OIDC Native SSO 1.0)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { calculateDsHash } from '../../src/utils/hash.js';
import { createMockCrypto } from '../mocks/crypto.js';

describe('calculateDsHash', () => {
  let crypto: ReturnType<typeof createMockCrypto>;

  beforeEach(() => {
    crypto = createMockCrypto();
  });

  describe('Basic Calculation', () => {
    it('should calculate ds_hash from device_secret', async () => {
      const deviceSecret = 'test-device-secret';
      const dsHash = await calculateDsHash(deviceSecret, crypto);

      // Result should be base64url encoded
      expect(dsHash).toMatch(/^[A-Za-z0-9_-]+$/);

      // SHA-256 produces 32 bytes, left half is 16 bytes
      // 16 bytes base64url encoded = 22 characters (without padding)
      expect(dsHash.length).toBe(22);
    });

    it('should produce consistent hash for same secret', async () => {
      const deviceSecret = 'consistent-secret';
      const hash1 = await calculateDsHash(deviceSecret, crypto);
      const hash2 = await calculateDsHash(deviceSecret, crypto);

      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different secrets', async () => {
      const hash1 = await calculateDsHash('secret-1', crypto);
      const hash2 = await calculateDsHash('secret-2', crypto);

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string', async () => {
      const dsHash = await calculateDsHash('', crypto);

      // Should still produce valid base64url
      expect(dsHash).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(dsHash.length).toBe(22);
    });

    it('should handle single character', async () => {
      const dsHash = await calculateDsHash('a', crypto);

      expect(dsHash).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(dsHash.length).toBe(22);
    });

    it('should handle unicode device_secret', async () => {
      const deviceSecret = 'デバイスシークレット-🔐';
      const dsHash = await calculateDsHash(deviceSecret, crypto);

      expect(dsHash).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(dsHash.length).toBe(22);
    });

    it('should handle very long device_secret', async () => {
      const deviceSecret = 'a'.repeat(10000);
      const dsHash = await calculateDsHash(deviceSecret, crypto);

      expect(dsHash).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(dsHash.length).toBe(22);
    });

    it('should handle device_secret with special characters', async () => {
      const deviceSecret = '!@#$%^&*()_+-=[]{}|;\':",.<>?/`~';
      const dsHash = await calculateDsHash(deviceSecret, crypto);

      expect(dsHash).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(dsHash.length).toBe(22);
    });

    it('should handle device_secret with whitespace', async () => {
      const deviceSecret = '  secret with spaces  ';
      const dsHash = await calculateDsHash(deviceSecret, crypto);

      expect(dsHash).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(dsHash.length).toBe(22);
    });

    it('should handle device_secret with newlines', async () => {
      const deviceSecret = 'line1\nline2\r\nline3';
      const dsHash = await calculateDsHash(deviceSecret, crypto);

      expect(dsHash).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(dsHash.length).toBe(22);
    });
  });

  describe('Algorithm Verification', () => {
    it('should use left half of SHA-256 hash', async () => {
      // The implementation should:
      // 1. SHA-256(device_secret) -> 32 bytes
      // 2. Take left half -> 16 bytes
      // 3. BASE64URL encode -> 22 characters

      const deviceSecret = 'test-secret';
      const dsHash = await calculateDsHash(deviceSecret, crypto);

      // 16 bytes = 128 bits
      // BASE64URL: 128 bits / 6 bits per char = 21.33, rounded up = 22 chars
      expect(dsHash.length).toBe(22);
    });

    it('should produce url-safe output without padding', async () => {
      const dsHash = await calculateDsHash('any-secret', crypto);

      // Should not contain standard base64 characters that are not URL-safe
      expect(dsHash).not.toContain('+');
      expect(dsHash).not.toContain('/');
      expect(dsHash).not.toContain('=');
    });
  });

  describe('Determinism', () => {
    it('should be deterministic across multiple calls', async () => {
      const secrets = ['secret1', 'secret2', 'secret3'];
      const hashes1 = await Promise.all(secrets.map((s) => calculateDsHash(s, crypto)));
      const hashes2 = await Promise.all(secrets.map((s) => calculateDsHash(s, crypto)));

      expect(hashes1).toEqual(hashes2);
    });

    it('should produce unique hash for each unique input', async () => {
      const secrets = ['a', 'b', 'c', 'd', 'e'];
      const hashes = await Promise.all(secrets.map((s) => calculateDsHash(s, crypto)));

      const uniqueHashes = new Set(hashes);
      expect(uniqueHashes.size).toBe(secrets.length);
    });
  });
});
