/**
 * Full Authentication Flow Integration Tests
 *
 * End-to-end tests for the complete authentication flow.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AuthrimError, getErrorMeta } from '../../src/types/errors.js';
import { SilentAuthHandler } from '../../src/auth/silent-auth.js';
import { LogoutHandler } from '../../src/session/logout.js';
import { TokenManager } from '../../src/token/manager.js';
import { TokenIntrospector } from '../../src/token/introspection.js';
import { TokenRevoker } from '../../src/token/revocation.js';
import { EventEmitter } from '../../src/events/emitter.js';
import { createMockOIDCServer } from './helpers/mock-server.js';
import { createMockStorage } from '../mocks/storage.js';
import { STORAGE_KEYS } from '../../src/auth/state.js';

describe('Full Authentication Flow Integration', () => {
  const issuer = 'https://auth.example.com';
  const clientId = 'test-client';
  const issuerHash = 'issuer-hash';
  const clientIdHash = 'client-hash';

  let server: ReturnType<typeof createMockOIDCServer>;
  let storage: ReturnType<typeof createMockStorage>;
  let eventEmitter: EventEmitter;
  let tokenManager: TokenManager;
  let logoutHandler: LogoutHandler;
  let introspector: TokenIntrospector;
  let revoker: TokenRevoker;

  beforeEach(() => {
    server = createMockOIDCServer({ issuer, clientId });
    storage = createMockStorage();
    eventEmitter = new EventEmitter();

    tokenManager = new TokenManager({
      http: server.http,
      storage,
      clientId,
      issuerHash,
      clientIdHash,
      eventEmitter,
    });
    tokenManager.setDiscovery(server.discovery);

    logoutHandler = new LogoutHandler({
      storage,
      http: server.http,
      clientId,
      issuerHash,
      clientIdHash,
      eventEmitter,
    });

    introspector = new TokenIntrospector({ http: server.http, clientId });
    revoker = new TokenRevoker({ http: server.http, clientId });
  });

  describe('Error Meta', () => {
    it('should provide recovery metadata for errors', () => {
      const error = new AuthrimError('network_error', 'Network failed');

      expect(error.meta).toEqual({
        transient: true,
        retryable: true,
        retryAfterMs: 2000,
        maxRetries: 3,
        userAction: 'check_network',
        severity: 'error',
      });
    });

    it('should provide metadata for all error codes', () => {
      const errorCodes = [
        'invalid_request',
        'unauthorized_client',
        'access_denied',
        'server_error',
        'network_error',
        'timeout_error',
        'no_tokens',
        'token_expired',
        'login_required',
        'introspection_error',
        'revocation_error',
      ] as const;

      for (const code of errorCodes) {
        const meta = getErrorMeta(code);
        expect(meta).toBeDefined();
        expect(meta.userAction).toBeDefined();
        expect(meta.severity).toBeDefined();
      }
    });

    it('should identify retryable errors via isRetryable()', () => {
      const networkError = new AuthrimError('network_error', 'Network failed');
      const accessDenied = new AuthrimError('access_denied', 'Access denied');

      expect(networkError.isRetryable()).toBe(true);
      expect(accessDenied.isRetryable()).toBe(false);
    });
  });

  describe('Complete Authentication Lifecycle', () => {
    it('should handle full login -> use -> logout flow', async () => {
      // 1. Simulate successful authentication
      const { accessToken, refreshToken, idToken } = server.issueToken();
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      await tokenManager.saveTokens({
        accessToken,
        refreshToken,
        idToken,
        tokenType: 'Bearer',
        expiresAt,
      });

      // 2. Verify authenticated
      expect(await tokenManager.isAuthenticated()).toBe(true);

      // 3. Get access token
      const token = await tokenManager.getAccessToken();
      expect(token).toBe(accessToken);

      // 4. Introspect token (verify it's valid)
      const introspectionResult = await introspector.introspect(server.discovery, {
        token: accessToken,
      });
      expect(introspectionResult.active).toBe(true);

      // 5. Logout with token revocation
      const logoutResult = await logoutHandler.logout(server.discovery, {
        revokeTokens: true,
      });

      expect(logoutResult.localOnly).toBe(false);
      expect(logoutResult.logoutUrl).toContain('/logout');
      expect(logoutResult.revocation?.attempted).toBe(true);
      expect(logoutResult.revocation?.accessTokenRevoked).toBe(true);

      // 6. Verify tokens are cleared locally
      expect(await tokenManager.isAuthenticated()).toBe(false);

      // 7. Verify tokens are revoked on server
      const afterLogout = await introspector.introspect(server.discovery, {
        token: accessToken,
      });
      expect(afterLogout.active).toBe(false);
    });

    it('should handle logout without token revocation', async () => {
      const { accessToken, refreshToken, idToken } = server.issueToken();

      await tokenManager.saveTokens({
        accessToken,
        refreshToken,
        idToken,
        tokenType: 'Bearer',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      });

      const logoutResult = await logoutHandler.logout(server.discovery, {
        revokeTokens: false, // Don't revoke
      });

      expect(logoutResult.revocation).toBeUndefined();

      // Token should still be active on server (not revoked)
      const introspectionResult = await introspector.introspect(server.discovery, {
        token: accessToken,
      });
      expect(introspectionResult.active).toBe(true);
    });
  });

  describe('Silent Authentication', () => {
    it('should build silent auth URL with prompt=none', () => {
      const silentAuthHandler = new SilentAuthHandler(clientId);

      const authState = {
        state: 'test-state',
        nonce: 'test-nonce',
        redirectUri: 'https://app.example.com/callback',
        codeVerifier: 'test-verifier',
        createdAt: Date.now(),
        expiresAt: Date.now() + 600000,
      };

      const pkce = {
        codeVerifier: 'test-verifier',
        codeChallenge: 'test-challenge',
        codeChallengeMethod: 'S256' as const,
      };

      const result = silentAuthHandler.buildSilentAuthUrl(server.discovery, authState, pkce, {
        redirectUri: 'https://app.example.com/silent-callback',
        scope: 'openid',
      });

      expect(result.url).toContain('prompt=none');
      expect(result.url).toContain('response_type=code');
      expect(result.url).toContain('client_id=' + clientId);
    });

    it('should parse successful silent auth response', () => {
      const silentAuthHandler = new SilentAuthHandler(clientId);

      const responseUrl = 'https://app.example.com/silent-callback?code=abc123&state=test-state';
      const result = silentAuthHandler.parseSilentAuthResponse(responseUrl);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.code).toBe('abc123');
        expect(result.state).toBe('test-state');
      }
    });

    it('should parse login_required error response', () => {
      const silentAuthHandler = new SilentAuthHandler(clientId);

      const responseUrl =
        'https://app.example.com/silent-callback?error=login_required&error_description=No%20active%20session';
      const result = silentAuthHandler.parseSilentAuthResponse(responseUrl);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.code).toBe('login_required');
        expect(silentAuthHandler.isInteractiveLoginRequired(result.error)).toBe(true);
      }
    });

    it('should identify interactive login required errors', () => {
      const silentAuthHandler = new SilentAuthHandler(clientId);

      const interactiveErrors = [
        new AuthrimError('login_required', 'Login required'),
        new AuthrimError('interaction_required', 'Interaction required'),
        new AuthrimError('consent_required', 'Consent required'),
        new AuthrimError('account_selection_required', 'Account selection required'),
      ];

      for (const error of interactiveErrors) {
        expect(silentAuthHandler.isInteractiveLoginRequired(error)).toBe(true);
      }

      const nonInteractiveError = new AuthrimError('network_error', 'Network error');
      expect(silentAuthHandler.isInteractiveLoginRequired(nonInteractiveError)).toBe(false);
    });
  });

  describe('Token Lifecycle Events', () => {
    it('should emit events throughout the token lifecycle', async () => {
      const refreshedHandler = vi.fn();
      const sessionEndedHandler = vi.fn();

      eventEmitter.on('token:refreshed', refreshedHandler);
      eventEmitter.on('session:ended', sessionEndedHandler);

      // Issue and store tokens
      const { accessToken, refreshToken, idToken } = server.issueToken();

      // Store expired tokens to trigger refresh
      await tokenManager.saveTokens({
        accessToken,
        refreshToken,
        idToken,
        tokenType: 'Bearer',
        expiresAt: Math.floor(Date.now() / 1000) - 100, // Expired
      });

      // Trigger refresh
      await tokenManager.getAccessToken();
      expect(refreshedHandler).toHaveBeenCalledOnce();

      // Logout
      await logoutHandler.logout(server.discovery);
      expect(sessionEndedHandler).toHaveBeenCalledWith({ reason: 'logout' });
    });
  });
});
