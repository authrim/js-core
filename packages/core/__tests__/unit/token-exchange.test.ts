/**
 * Token Exchange Tests (RFC 8693)
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TokenManager } from '../../src/token/manager.js';
import { EventEmitter } from '../../src/events/emitter.js';
import { TOKEN_TYPE_URIS } from '../../src/types/token.js';
import { createMockHttp, createMockDiscoveryDocument } from '../mocks/http.js';
import { createMockStorage } from '../mocks/storage.js';

/**
 * Create a mock token exchange response
 */
function createMockTokenExchangeResponse(
  overrides: Partial<{
    access_token: string;
    refresh_token: string;
    id_token: string;
    expires_in: number;
    token_type: string;
    scope: string;
    issued_token_type: string;
  }> = {}
) {
  return {
    access_token: overrides.access_token ?? 'exchanged-access-token',
    refresh_token: overrides.refresh_token,
    id_token: overrides.id_token,
    expires_in: overrides.expires_in ?? 3600,
    token_type: overrides.token_type ?? 'Bearer',
    scope: overrides.scope ?? 'openid profile',
    issued_token_type: overrides.issued_token_type ?? TOKEN_TYPE_URIS.access_token,
  };
}

describe('Token Exchange (RFC 8693)', () => {
  const issuer = 'https://auth.example.com';
  const clientId = 'test-client';
  const issuerHash = 'issuer-hash';
  const clientIdHash = 'client-hash';

  let http: ReturnType<typeof createMockHttp>;
  let storage: ReturnType<typeof createMockStorage>;
  let eventEmitter: EventEmitter;
  let tokenManager: TokenManager;

  beforeEach(() => {
    http = createMockHttp();
    storage = createMockStorage();
    eventEmitter = new EventEmitter();
    tokenManager = new TokenManager({
      http,
      storage,
      clientId,
      issuerHash,
      clientIdHash,
      eventEmitter,
    });
    tokenManager.setDiscovery(createMockDiscoveryDocument(issuer));
  });

  describe('Basic Token Exchange', () => {
    it('should exchange token with subject_token only', async () => {
      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenExchangeResponse(),
      }));

      const result = await tokenManager.exchangeToken({
        subjectToken: 'original-access-token',
      });

      expect(result.tokens.accessToken).toBe('exchanged-access-token');
      expect(result.issuedTokenType).toBe(TOKEN_TYPE_URIS.access_token);

      // Verify request
      expect(http.calls).toHaveLength(1);
      const requestBody = new URLSearchParams(http.calls[0].options?.body as string);
      expect(requestBody.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
      expect(requestBody.get('client_id')).toBe(clientId);
      expect(requestBody.get('subject_token')).toBe('original-access-token');
      expect(requestBody.get('subject_token_type')).toBe(TOKEN_TYPE_URIS.access_token);
    });

    it('should exchange token with audience and scope', async () => {
      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenExchangeResponse({
          scope: 'read write',
        }),
      }));

      const result = await tokenManager.exchangeToken({
        subjectToken: 'original-access-token',
        audience: 'https://api.example.com',
        scope: 'read write',
      });

      expect(result.tokens.scope).toBe('read write');

      // Verify request
      const requestBody = new URLSearchParams(http.calls[0].options?.body as string);
      expect(requestBody.get('audience')).toBe('https://api.example.com');
      expect(requestBody.get('scope')).toBe('read write');
    });

    it('should exchange token with requested_token_type', async () => {
      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenExchangeResponse({
          issued_token_type: TOKEN_TYPE_URIS.refresh_token,
          refresh_token: 'new-refresh-token',
        }),
      }));

      const result = await tokenManager.exchangeToken({
        subjectToken: 'original-access-token',
        requestedTokenType: 'refresh_token',
      });

      expect(result.issuedTokenType).toBe(TOKEN_TYPE_URIS.refresh_token);

      // Verify request
      const requestBody = new URLSearchParams(http.calls[0].options?.body as string);
      expect(requestBody.get('requested_token_type')).toBe(TOKEN_TYPE_URIS.refresh_token);
    });
  });

  describe('Delegation (Actor Token)', () => {
    it('should exchange token with actor_token for delegation', async () => {
      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenExchangeResponse(),
      }));

      await tokenManager.exchangeToken({
        subjectToken: 'user-access-token',
        actorToken: 'service-access-token',
        actorTokenType: 'access_token',
        audience: 'https://backend-api.example.com',
      });

      // Verify request
      const requestBody = new URLSearchParams(http.calls[0].options?.body as string);
      expect(requestBody.get('subject_token')).toBe('user-access-token');
      expect(requestBody.get('actor_token')).toBe('service-access-token');
      expect(requestBody.get('actor_token_type')).toBe(TOKEN_TYPE_URIS.access_token);
    });
  });

  describe('Token Type Mapping', () => {
    it('should map access_token to URI', async () => {
      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenExchangeResponse(),
      }));

      await tokenManager.exchangeToken({
        subjectToken: 'token',
        subjectTokenType: 'access_token',
      });

      const requestBody = new URLSearchParams(http.calls[0].options?.body as string);
      expect(requestBody.get('subject_token_type')).toBe(
        'urn:ietf:params:oauth:token-type:access_token'
      );
    });

    it('should map refresh_token to URI', async () => {
      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenExchangeResponse(),
      }));

      await tokenManager.exchangeToken({
        subjectToken: 'token',
        subjectTokenType: 'refresh_token',
      });

      const requestBody = new URLSearchParams(http.calls[0].options?.body as string);
      expect(requestBody.get('subject_token_type')).toBe(
        'urn:ietf:params:oauth:token-type:refresh_token'
      );
    });

    it('should map id_token to URI', async () => {
      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenExchangeResponse(),
      }));

      await tokenManager.exchangeToken({
        subjectToken: 'token',
        subjectTokenType: 'id_token',
      });

      const requestBody = new URLSearchParams(http.calls[0].options?.body as string);
      expect(requestBody.get('subject_token_type')).toBe(
        'urn:ietf:params:oauth:token-type:id_token'
      );
    });
  });

  describe('Error Handling', () => {
    it('should throw on network error', async () => {
      http.setHandler(() => {
        throw new Error('Network error');
      });

      await expect(tokenManager.exchangeToken({ subjectToken: 'token' })).rejects.toMatchObject({
        code: 'network_error',
      });
    });

    it('should throw on token endpoint error', async () => {
      http.setHandler(() => ({
        ok: false,
        status: 400,
        data: {
          error: 'invalid_grant',
          error_description: 'The provided token is invalid',
        },
      }));

      await expect(
        tokenManager.exchangeToken({ subjectToken: 'invalid-token' })
      ).rejects.toMatchObject({
        code: 'token_exchange_error',
      });
    });

    it('should throw when discovery not set', async () => {
      const managerWithoutDiscovery = new TokenManager({
        http,
        storage,
        clientId,
        issuerHash,
        clientIdHash,
      });

      await expect(
        managerWithoutDiscovery.exchangeToken({ subjectToken: 'token' })
      ).rejects.toMatchObject({
        code: 'no_discovery',
      });
    });
  });

  describe('Events', () => {
    it('should emit token:exchanged event on success', async () => {
      const exchangedHandler = vi.fn();
      eventEmitter.on('token:exchanged', exchangedHandler);

      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenExchangeResponse(),
      }));

      await tokenManager.exchangeToken({ subjectToken: 'token' });

      expect(exchangedHandler).toHaveBeenCalledOnce();
      expect(exchangedHandler).toHaveBeenCalledWith({
        tokens: expect.objectContaining({
          accessToken: 'exchanged-access-token',
        }),
        issuedTokenType: TOKEN_TYPE_URIS.access_token,
      });
    });

    it('should emit token:error event on failure', async () => {
      const errorHandler = vi.fn();
      eventEmitter.on('token:error', errorHandler);

      http.setHandler(() => ({
        ok: false,
        status: 400,
        data: { error: 'invalid_grant' },
      }));

      await expect(tokenManager.exchangeToken({ subjectToken: 'token' })).rejects.toThrow();

      expect(errorHandler).toHaveBeenCalledOnce();
      expect(errorHandler).toHaveBeenCalledWith({
        error: expect.objectContaining({
          code: 'token_exchange_error',
        }),
      });
    });
  });

  describe('Token Response Parsing', () => {
    it('should calculate expiresAt from expires_in', async () => {
      const now = Math.floor(Date.now() / 1000);

      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenExchangeResponse({
          expires_in: 7200, // 2 hours
        }),
      }));

      const result = await tokenManager.exchangeToken({ subjectToken: 'token' });

      // expiresAt should be approximately now + 7200
      expect(result.tokens.expiresAt).toBeGreaterThanOrEqual(now + 7200);
      expect(result.tokens.expiresAt).toBeLessThan(now + 7200 + 5); // Allow 5 second margin
    });

    it('should default to 1 hour if expires_in not provided', async () => {
      const now = Math.floor(Date.now() / 1000);

      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: {
          access_token: 'token',
          token_type: 'Bearer',
          issued_token_type: TOKEN_TYPE_URIS.access_token,
          // No expires_in
        },
      }));

      const result = await tokenManager.exchangeToken({ subjectToken: 'token' });

      // Should default to 1 hour (3600 seconds)
      expect(result.tokens.expiresAt).toBeGreaterThanOrEqual(now + 3600);
      expect(result.tokens.expiresAt).toBeLessThan(now + 3600 + 5);
    });
  });
});
