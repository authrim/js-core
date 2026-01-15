/**
 * Refresh Token Rotation Tests
 *
 * Tests for acceptance criteria:
 * #2: Concurrent getAccessToken calls result in max 1 refresh
 * #2b: refreshPromise is always cleared (success or failure)
 */

import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { TokenManager } from '../../src/token/manager.js';
import { createMockStorage } from '../mocks/storage.js';
import {
  createMockHttp,
  createMockDiscoveryDocument,
  createMockTokenResponse,
} from '../mocks/http.js';
import type { TokenSet } from '../../src/types/token.js';

describe('Refresh Token Rotation', () => {
  const issuer = 'https://auth.example.com';
  const clientId = 'test-client';
  const issuerHash = 'issuer-hash';
  const clientIdHash = 'client-hash';

  let storage: ReturnType<typeof createMockStorage>;
  let http: ReturnType<typeof createMockHttp>;
  let tokenManager: TokenManager;

  beforeEach(() => {
    storage = createMockStorage();
    http = createMockHttp();
    tokenManager = new TokenManager({
      http,
      storage,
      clientId,
      issuerHash,
      clientIdHash,
      refreshSkewSeconds: 30,
    });

    // Set discovery
    tokenManager.setDiscovery(createMockDiscoveryDocument(issuer));
  });

  /**
   * Helper to create expired tokens
   */
  async function saveExpiredTokens(): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const expiredTokens: TokenSet = {
      accessToken: 'expired-access-token',
      refreshToken: 'valid-refresh-token',
      tokenType: 'Bearer',
      expiresAt: now - 100, // Expired 100 seconds ago
    };
    await tokenManager.saveTokens(expiredTokens);
  }

  describe('Concurrent Request Coalescing - Acceptance Criteria #2', () => {
    it('should only call refresh once with 10 concurrent requests', async () => {
      await saveExpiredTokens();

      // Track number of refresh calls
      let refreshCallCount = 0;

      http.setHandler(async () => {
        refreshCallCount++;
        // Simulate network delay
        await new Promise((resolve) => setTimeout(resolve, 50));
        return {
          ok: true,
          status: 200,
          data: createMockTokenResponse(),
        };
      });

      // Launch 10 concurrent getAccessToken calls
      const results = await Promise.all(
        Array(10)
          .fill(null)
          .map(() => tokenManager.getAccessToken())
      );

      // All should return the same new token
      const newToken = results[0];
      expect(results.every((t) => t === newToken)).toBe(true);

      // Refresh should have been called only once
      expect(refreshCallCount).toBe(1);
    });

    it('should allow subsequent refresh after first completes', async () => {
      let refreshCallCount = 0;

      http.setHandler(async () => {
        refreshCallCount++;
        const now = Math.floor(Date.now() / 1000);
        return {
          ok: true,
          status: 200,
          data: {
            access_token: `token-${refreshCallCount}`,
            refresh_token: 'new-refresh-token',
            expires_in: 1, // Very short expiry
            token_type: 'Bearer',
          },
        };
      });

      // First refresh
      await saveExpiredTokens();
      await tokenManager.getAccessToken();
      expect(refreshCallCount).toBe(1);

      // Wait for token to expire
      await new Promise((resolve) => setTimeout(resolve, 1100));

      // Second refresh
      await tokenManager.getAccessToken();
      expect(refreshCallCount).toBe(2);
    });
  });

  describe('Promise Cleanup - Acceptance Criteria #2b', () => {
    it('should clear refreshPromise after successful refresh', async () => {
      await saveExpiredTokens();

      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenResponse(),
      }));

      // First call
      await tokenManager.getAccessToken();

      // Save expired tokens again
      await saveExpiredTokens();

      // Second call should trigger new refresh (not reuse old promise)
      let secondRefreshCalled = false;
      http.setHandler(() => {
        secondRefreshCalled = true;
        return {
          ok: true,
          status: 200,
          data: createMockTokenResponse(),
        };
      });

      await tokenManager.getAccessToken();
      expect(secondRefreshCalled).toBe(true);
    });

    it('should clear refreshPromise after failed refresh', async () => {
      await saveExpiredTokens();

      // First refresh fails with server error (not retryable)
      http.setHandler(() => ({
        ok: false,
        status: 400,
        data: { error: 'invalid_grant' },
      }));

      // First call should fail
      await expect(tokenManager.getAccessToken()).rejects.toMatchObject({ code: 'refresh_error' });

      // Save expired tokens again (refresh token might still be valid)
      await saveExpiredTokens();

      // Second refresh should be attempted (promise was cleared)
      let secondRefreshAttempted = false;
      http.setHandler(() => {
        secondRefreshAttempted = true;
        return {
          ok: true,
          status: 200,
          data: createMockTokenResponse(),
        };
      });

      await tokenManager.getAccessToken();
      expect(secondRefreshAttempted).toBe(true);
    });

    it('should retry once on network error', async () => {
      await saveExpiredTokens();

      let attemptCount = 0;
      http.setHandler(() => {
        attemptCount++;
        if (attemptCount === 1) {
          // Simulate network error on first attempt
          throw new Error('Network error');
        }
        return {
          ok: true,
          status: 200,
          data: createMockTokenResponse(),
        };
      });

      // Should succeed after retry
      const token = await tokenManager.getAccessToken();
      expect(token).toBe('mock-access-token');
      expect(attemptCount).toBe(2); // Original + 1 retry
    });

    it('should not retry on non-network errors', async () => {
      await saveExpiredTokens();

      let attemptCount = 0;
      http.setHandler(() => {
        attemptCount++;
        return {
          ok: false,
          status: 401,
          data: { error: 'invalid_grant', error_description: 'Refresh token expired' },
        };
      });

      // Should fail without retry
      await expect(tokenManager.getAccessToken()).rejects.toThrow();
      expect(attemptCount).toBe(1); // No retry
    });
  });

  describe('Token Refresh Timing', () => {
    it('should refresh when within skew period', async () => {
      const now = Math.floor(Date.now() / 1000);
      const tokens: TokenSet = {
        accessToken: 'soon-expiring-token',
        refreshToken: 'valid-refresh-token',
        tokenType: 'Bearer',
        expiresAt: now + 20, // Expires in 20 seconds (within 30s skew)
      };
      await tokenManager.saveTokens(tokens);

      let refreshCalled = false;
      http.setHandler(() => {
        refreshCalled = true;
        return {
          ok: true,
          status: 200,
          data: createMockTokenResponse(),
        };
      });

      await tokenManager.getAccessToken();
      expect(refreshCalled).toBe(true);
    });

    it('should not refresh when outside skew period', async () => {
      const now = Math.floor(Date.now() / 1000);
      const tokens: TokenSet = {
        accessToken: 'valid-token',
        refreshToken: 'valid-refresh-token',
        tokenType: 'Bearer',
        expiresAt: now + 60, // Expires in 60 seconds (outside 30s skew)
      };
      await tokenManager.saveTokens(tokens);

      let refreshCalled = false;
      http.setHandler(() => {
        refreshCalled = true;
        return {
          ok: true,
          status: 200,
          data: createMockTokenResponse(),
        };
      });

      const token = await tokenManager.getAccessToken();
      expect(refreshCalled).toBe(false);
      expect(token).toBe('valid-token');
    });
  });
});
