/**
 * Token Refresh Integration Tests
 *
 * Tests for token refresh with token rotation and revocation.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TokenManager } from '../../src/token/manager.js';
import { EventEmitter } from '../../src/events/emitter.js';
import { createMockOIDCServer } from './helpers/mock-server.js';
import { createMockStorage } from '../mocks/storage.js';

describe('Token Refresh Integration', () => {
  const issuer = 'https://auth.example.com';
  const clientId = 'test-client';
  const issuerHash = 'issuer-hash';
  const clientIdHash = 'client-hash';

  let server: ReturnType<typeof createMockOIDCServer>;
  let storage: ReturnType<typeof createMockStorage>;
  let eventEmitter: EventEmitter;
  let tokenManager: TokenManager;

  beforeEach(() => {
    server = createMockOIDCServer({
      issuer,
      clientId,
      tokenExpiresIn: 3600,
    });
    storage = createMockStorage();
    eventEmitter = new EventEmitter();
    tokenManager = new TokenManager({
      http: server.http,
      storage,
      clientId,
      issuerHash,
      clientIdHash,
      eventEmitter,
      refreshSkewSeconds: 30,
    });
    tokenManager.setDiscovery(server.discovery);
  });

  describe('Basic Token Refresh', () => {
    it('should refresh tokens using refresh_token grant', async () => {
      const { accessToken, refreshToken } = server.issueToken();

      // Store initial tokens (expired)
      const expiredAt = Math.floor(Date.now() / 1000) - 100; // Already expired
      await tokenManager.saveTokens({
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresAt: expiredAt,
      });

      // Get access token should trigger refresh
      const newAccessToken = await tokenManager.getAccessToken();

      // Should have new access token
      expect(newAccessToken).not.toBe(accessToken);
      expect(newAccessToken).toContain('access-token-');

      // Verify refresh request was made
      const refreshRequest = server.state.requests.find(
        (r) => r.url === server.discovery.token_endpoint && r.body?.includes('refresh_token')
      );
      expect(refreshRequest).toBeDefined();
    });

    it('should emit token:refreshed event on successful refresh', async () => {
      const refreshedHandler = vi.fn();
      eventEmitter.on('token:refreshed', refreshedHandler);

      const { accessToken, refreshToken } = server.issueToken();

      // Store expired tokens
      await tokenManager.saveTokens({
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresAt: Math.floor(Date.now() / 1000) - 100,
      });

      await tokenManager.getAccessToken();

      expect(refreshedHandler).toHaveBeenCalledOnce();
      expect(refreshedHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          tokens: expect.objectContaining({
            accessToken: expect.any(String),
          }),
        })
      );
    });

    it('should fail refresh with revoked refresh token', async () => {
      const { accessToken, refreshToken } = server.issueToken();

      // Revoke the refresh token
      server.revokeToken(refreshToken);

      // Store expired tokens
      await tokenManager.saveTokens({
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresAt: Math.floor(Date.now() / 1000) - 100,
      });

      // Should fail to refresh
      await expect(tokenManager.getAccessToken()).rejects.toMatchObject({
        code: 'refresh_error',
      });
    });
  });

  describe('Token Refresh Skew', () => {
    it('should refresh token before actual expiry based on skew', async () => {
      const { accessToken, refreshToken } = server.issueToken();

      // Token expires in 20 seconds, but skew is 30 seconds
      // So it should trigger refresh
      const expiresAt = Math.floor(Date.now() / 1000) + 20;
      await tokenManager.saveTokens({
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresAt,
      });

      const newAccessToken = await tokenManager.getAccessToken();

      // Should have refreshed (got new token)
      expect(newAccessToken).not.toBe(accessToken);
    });

    it('should not refresh token if within safe period', async () => {
      const { accessToken, refreshToken } = server.issueToken();

      // Token expires in 60 seconds, skew is 30 seconds
      // So it should NOT trigger refresh
      const expiresAt = Math.floor(Date.now() / 1000) + 60;
      await tokenManager.saveTokens({
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresAt,
      });

      const returnedToken = await tokenManager.getAccessToken();

      // Should return existing token
      expect(returnedToken).toBe(accessToken);
    });
  });

  describe('Concurrent Refresh Coalescing', () => {
    it('should coalesce concurrent refresh requests', async () => {
      const { accessToken, refreshToken } = server.issueToken();

      // Store expired tokens
      await tokenManager.saveTokens({
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresAt: Math.floor(Date.now() / 1000) - 100,
      });

      // Make 3 concurrent requests
      const [token1, token2, token3] = await Promise.all([
        tokenManager.getAccessToken(),
        tokenManager.getAccessToken(),
        tokenManager.getAccessToken(),
      ]);

      // All should get the same new token
      expect(token1).toBe(token2);
      expect(token2).toBe(token3);

      // Only one refresh request should have been made
      const refreshRequests = server.state.requests.filter(
        (r) => r.url === server.discovery.token_endpoint && r.body?.includes('refresh_token')
      );
      expect(refreshRequests).toHaveLength(1);
    });
  });

  describe('Token Rotation', () => {
    it('should use new refresh token from response (rotation)', async () => {
      const { accessToken, refreshToken: initialRefreshToken } = server.issueToken();

      // Store expired tokens
      await tokenManager.saveTokens({
        accessToken,
        refreshToken: initialRefreshToken,
        tokenType: 'Bearer',
        expiresAt: Math.floor(Date.now() / 1000) - 100,
      });

      // Trigger refresh
      await tokenManager.getAccessToken();

      // Get stored tokens
      const storedTokens = await tokenManager.getTokens();

      // Refresh token should be different (rotated)
      expect(storedTokens?.refreshToken).not.toBe(initialRefreshToken);
      expect(storedTokens?.refreshToken).toContain('refresh-token-');
    });
  });

  describe('isAuthenticated', () => {
    it('should return true when tokens exist and are not expired', async () => {
      const { accessToken, refreshToken } = server.issueToken();

      await tokenManager.saveTokens({
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      });

      expect(await tokenManager.isAuthenticated()).toBe(true);
    });

    it('should return true when access token expired but refresh token exists', async () => {
      const { accessToken, refreshToken } = server.issueToken();

      await tokenManager.saveTokens({
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresAt: Math.floor(Date.now() / 1000) - 100, // Expired
      });

      expect(await tokenManager.isAuthenticated()).toBe(true);
    });

    it('should return false when no tokens exist', async () => {
      expect(await tokenManager.isAuthenticated()).toBe(false);
    });
  });
});
