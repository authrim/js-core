/**
 * Storage Keys Tests
 *
 * Tests for acceptance criteria:
 * #6: Storage keys don't contain URL strings
 * #7: Client initialization hashes issuer/clientId once
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createAuthrimClient, AuthrimClient } from '../../src/client/index.js';
import { STORAGE_KEYS } from '../../src/auth/state.js';
import { createMockCrypto } from '../mocks/crypto.js';
import { createMockStorage } from '../mocks/storage.js';
import { createMockHttp, createMockDiscoveryDocument } from '../mocks/http.js';

describe('Storage Keys', () => {
  describe('Hash Format - Acceptance Criteria #6', () => {
    it('should not contain URL characters in storage keys', async () => {
      const crypto = createMockCrypto();
      const storage = createMockStorage();
      const http = createMockHttp();

      const issuer = 'https://auth.example.com';

      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockDiscoveryDocument(issuer),
      }));

      const client = await createAuthrimClient({
        issuer,
        clientId: 'client-id-123',
        http,
        crypto,
        storage,
      });

      // Build authorization URL to trigger state storage
      await client.buildAuthorizationUrl({
        redirectUri: 'https://app.example.com/callback',
      });

      // Check all storage keys
      const keys = storage.getAllKeys();
      expect(keys.length).toBeGreaterThan(0);

      for (const key of keys) {
        // Keys should not contain URL components
        expect(key).not.toContain('://');
        expect(key).not.toContain('https');
        expect(key).not.toContain('http');
        expect(key).not.toContain('.com');
        expect(key).not.toContain('/path');

        // Keys should follow the expected format
        expect(key).toMatch(/^authrim:[^:]+:[^:]+:/);
      }
    });

    it('should generate stable hash for same issuer', async () => {
      const crypto = createMockCrypto();

      // Hash the same issuer twice
      const hash1 = await hashForKey(crypto, 'https://auth.example.com');
      const hash2 = await hashForKey(crypto, 'https://auth.example.com');

      expect(hash1).toBe(hash2);
      expect(hash1.length).toBe(16);
    });

    it('should generate different hashes for different issuers', async () => {
      const crypto = createMockCrypto();

      const hash1 = await hashForKey(crypto, 'https://auth1.example.com');
      const hash2 = await hashForKey(crypto, 'https://auth2.example.com');

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('Client Initialization - Acceptance Criteria #7', () => {
    it('should only hash issuer and clientId once during initialization', async () => {
      const crypto = createMockCrypto();
      const storage = createMockStorage();
      const http = createMockHttp();

      // Spy on sha256
      const sha256Spy = vi.spyOn(crypto, 'sha256');

      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockDiscoveryDocument('https://auth.example.com'),
      }));

      // Create client
      await createAuthrimClient({
        issuer: 'https://auth.example.com',
        clientId: 'test-client',
        http,
        crypto,
        storage,
      });

      // sha256 should be called exactly twice (issuer + clientId)
      expect(sha256Spy).toHaveBeenCalledTimes(2);

      // Calls should be for issuer and clientId
      const calls = sha256Spy.mock.calls.map((c) => c[0]);
      expect(calls).toContain('https://auth.example.com');
      expect(calls).toContain('test-client');
    });

    it('should reuse hashes for subsequent operations', async () => {
      const crypto = createMockCrypto();
      const storage = createMockStorage();
      const http = createMockHttp();

      const sha256Spy = vi.spyOn(crypto, 'sha256');

      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockDiscoveryDocument('https://auth.example.com'),
      }));

      const client = await createAuthrimClient({
        issuer: 'https://auth.example.com',
        clientId: 'test-client',
        http,
        crypto,
        storage,
      });

      const initialCallCount = sha256Spy.mock.calls.length;

      // Perform multiple operations
      await client.buildAuthorizationUrl({
        redirectUri: 'https://app.example.com/callback',
      });
      await client.buildAuthorizationUrl({
        redirectUri: 'https://app.example.com/callback',
      });

      // sha256 should not be called again for issuer/clientId hashing
      // (only for PKCE code challenge generation which is different)
      const additionalCalls = sha256Spy.mock.calls
        .slice(initialCallCount)
        .filter((c) => c[0] === 'https://auth.example.com' || c[0] === 'test-client');

      expect(additionalCalls.length).toBe(0);
    });
  });
});

/**
 * Helper function to hash for key (same as in client)
 */
async function hashForKey(
  crypto: { sha256: (data: string) => Promise<Uint8Array> },
  value: string,
  length = 16
): Promise<string> {
  const hash = await crypto.sha256(value);
  return base64urlEncode(hash).slice(0, length);
}

/**
 * Simple base64url encode
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
