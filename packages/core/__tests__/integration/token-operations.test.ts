/**
 * Token Operations Integration Tests
 *
 * Tests for Token Introspection (RFC 7662) and Token Revocation (RFC 7009)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { TokenIntrospector } from '../../src/token/introspection.js';
import { TokenRevoker } from '../../src/token/revocation.js';
import { createMockOIDCServer } from './helpers/mock-server.js';

describe('Token Operations Integration', () => {
  const issuer = 'https://auth.example.com';
  const clientId = 'test-client';

  let server: ReturnType<typeof createMockOIDCServer>;
  let introspector: TokenIntrospector;
  let revoker: TokenRevoker;

  beforeEach(() => {
    server = createMockOIDCServer({ issuer, clientId });
    introspector = new TokenIntrospector({ http: server.http, clientId });
    revoker = new TokenRevoker({ http: server.http, clientId });
  });

  describe('Token Introspection (RFC 7662)', () => {
    it('should introspect a valid access token', async () => {
      const { accessToken } = server.issueToken({ sub: 'user-456', scope: 'openid profile email' });

      const result = await introspector.introspect(server.discovery, { token: accessToken });

      expect(result.active).toBe(true);
      expect(result.sub).toBe('user-456');
      expect(result.scope).toBe('openid profile email');
      expect(result.client_id).toBe(clientId);
      expect(result.iss).toBe(issuer);
    });

    it('should return active=false for invalid token', async () => {
      const result = await introspector.introspect(server.discovery, { token: 'invalid-token' });

      expect(result.active).toBe(false);
    });

    it('should return active=false for revoked token', async () => {
      const { accessToken } = server.issueToken();
      server.revokeToken(accessToken);

      const result = await introspector.introspect(server.discovery, { token: accessToken });

      expect(result.active).toBe(false);
    });

    it('should support token_type_hint parameter', async () => {
      const { refreshToken } = server.issueToken();

      const result = await introspector.introspect(server.discovery, {
        token: refreshToken,
        tokenTypeHint: 'refresh_token',
      });

      expect(result.active).toBe(true);

      // Verify request was made with token_type_hint
      const lastRequest = server.state.requests[server.state.requests.length - 1];
      const params = new URLSearchParams(lastRequest.body);
      expect(params.get('token_type_hint')).toBe('refresh_token');
    });

    it('should use isActive convenience method', async () => {
      const { accessToken } = server.issueToken();

      const isActive = await introspector.isActive(server.discovery, accessToken);

      expect(isActive).toBe(true);
    });

    it('should throw when introspection endpoint is not available', async () => {
      const discoveryWithoutIntrospection = {
        ...server.discovery,
        introspection_endpoint: undefined,
      };

      await expect(
        introspector.introspect(discoveryWithoutIntrospection, { token: 'any-token' })
      ).rejects.toMatchObject({
        code: 'no_introspection_endpoint',
      });
    });
  });

  describe('Token Revocation (RFC 7009)', () => {
    it('should revoke an access token', async () => {
      const { accessToken } = server.issueToken();

      // Verify token is active before revocation
      expect(server.state.activeTokens.has(accessToken)).toBe(true);

      await revoker.revoke(server.discovery, { token: accessToken });

      // Token should be revoked
      expect(server.state.activeTokens.has(accessToken)).toBe(false);
      expect(server.state.revokedTokens.has(accessToken)).toBe(true);
    });

    it('should revoke a refresh token', async () => {
      const { refreshToken } = server.issueToken();

      await revoker.revoke(server.discovery, {
        token: refreshToken,
        tokenTypeHint: 'refresh_token',
      });

      expect(server.state.revokedTokens.has(refreshToken)).toBe(true);

      // Verify request was made with token_type_hint
      const lastRequest = server.state.requests[server.state.requests.length - 1];
      const params = new URLSearchParams(lastRequest.body);
      expect(params.get('token_type_hint')).toBe('refresh_token');
    });

    it('should succeed even if token was already invalid (RFC 7009)', async () => {
      // Per RFC 7009, revocation should return 200 OK even if token is invalid
      await expect(
        revoker.revoke(server.discovery, { token: 'already-invalid-token' })
      ).resolves.toBeUndefined();
    });

    it('should succeed even if token was already revoked (RFC 7009)', async () => {
      const { accessToken } = server.issueToken();
      server.revokeToken(accessToken);

      // Should not throw
      await expect(
        revoker.revoke(server.discovery, { token: accessToken })
      ).resolves.toBeUndefined();
    });

    it('should throw when revocation endpoint is not available', async () => {
      const discoveryWithoutRevocation = {
        ...server.discovery,
        revocation_endpoint: undefined,
      };

      await expect(
        revoker.revoke(discoveryWithoutRevocation, { token: 'any-token' })
      ).rejects.toMatchObject({
        code: 'no_revocation_endpoint',
      });
    });
  });

  describe('Introspection + Revocation Integration', () => {
    it('should show token as inactive after revocation', async () => {
      const { accessToken } = server.issueToken();

      // Token should be active initially
      const beforeRevocation = await introspector.introspect(server.discovery, {
        token: accessToken,
      });
      expect(beforeRevocation.active).toBe(true);

      // Revoke the token
      await revoker.revoke(server.discovery, { token: accessToken });

      // Token should be inactive after revocation
      const afterRevocation = await introspector.introspect(server.discovery, {
        token: accessToken,
      });
      expect(afterRevocation.active).toBe(false);
    });

    it('should revoke both access and refresh tokens', async () => {
      const { accessToken, refreshToken } = server.issueToken();

      // Revoke both tokens
      await revoker.revoke(server.discovery, {
        token: accessToken,
        tokenTypeHint: 'access_token',
      });
      await revoker.revoke(server.discovery, {
        token: refreshToken,
        tokenTypeHint: 'refresh_token',
      });

      // Both should be inactive
      const accessResult = await introspector.introspect(server.discovery, { token: accessToken });
      const refreshResult = await introspector.introspect(server.discovery, { token: refreshToken });

      expect(accessResult.active).toBe(false);
      expect(refreshResult.active).toBe(false);
    });
  });
});
