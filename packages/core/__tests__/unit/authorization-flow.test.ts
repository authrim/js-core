/**
 * Authorization Flow Tests
 *
 * Tests for acceptance criteria:
 * #1: State is always deleted (success or failure)
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { StateManager, STORAGE_KEYS } from '../../src/auth/state.js';
import { AuthorizationCodeFlow } from '../../src/auth/authorization-code.js';
import { createMockCrypto } from '../mocks/crypto.js';
import { createMockStorage } from '../mocks/storage.js';
import {
  createMockHttp,
  createMockDiscoveryDocument,
  createMockTokenResponse,
  createMockIdToken,
} from '../mocks/http.js';

describe('Authorization Flow', () => {
  const issuer = 'https://auth.example.com';
  const clientId = 'test-client';
  const issuerHash = 'issuer-hash';
  const clientIdHash = 'client-hash';
  const redirectUri = 'https://app.example.com/callback';

  let crypto: ReturnType<typeof createMockCrypto>;
  let storage: ReturnType<typeof createMockStorage>;
  let http: ReturnType<typeof createMockHttp>;
  let stateManager: StateManager;
  let authCodeFlow: AuthorizationCodeFlow;

  beforeEach(() => {
    crypto = createMockCrypto();
    storage = createMockStorage();
    http = createMockHttp();
    stateManager = new StateManager(crypto, storage, issuerHash, clientIdHash);
    authCodeFlow = new AuthorizationCodeFlow(http, clientId);
  });

  describe('State Management - Acceptance Criteria #1', () => {
    it('should delete state after successful validation', async () => {
      // Generate state
      const authState = await stateManager.generateAuthState({
        redirectUri,
        codeVerifier: 'test-verifier',
        scope: 'openid profile',
        ttlSeconds: 600,
      });

      const stateKey = STORAGE_KEYS.authState(issuerHash, clientIdHash, authState.state);

      // Verify state is stored
      expect(await storage.get(stateKey)).not.toBeNull();

      // Validate and consume
      const result = await stateManager.validateAndConsumeState(authState.state);
      expect(result.state).toBe(authState.state);

      // State should be deleted after successful validation
      expect(await storage.get(stateKey)).toBeNull();
    });

    it('should delete state after invalid_state error', async () => {
      const invalidState = 'non-existent-state';
      const stateKey = STORAGE_KEYS.authState(issuerHash, clientIdHash, invalidState);

      // Try to validate non-existent state
      await expect(stateManager.validateAndConsumeState(invalidState)).rejects.toMatchObject({
        code: 'invalid_state',
      });

      // Storage should not have this key (no leftover)
      expect(await storage.get(stateKey)).toBeNull();
    });

    it('should delete state after expired_state error', async () => {
      // Generate state with very short TTL
      const authState = await stateManager.generateAuthState({
        redirectUri,
        codeVerifier: 'test-verifier',
        scope: 'openid profile',
        ttlSeconds: 0, // Expires immediately
      });

      const stateKey = STORAGE_KEYS.authState(issuerHash, clientIdHash, authState.state);

      // Wait a bit for expiration
      await new Promise((resolve) => setTimeout(resolve, 10));

      // Verify state is stored
      expect(await storage.get(stateKey)).not.toBeNull();

      // Try to validate expired state
      await expect(stateManager.validateAndConsumeState(authState.state)).rejects.toMatchObject({
        code: 'expired_state',
      });

      // State should be deleted even after expiration error
      expect(await storage.get(stateKey)).toBeNull();
    });
  });

  describe('Callback Parsing', () => {
    it('should parse code and state from callback URL', () => {
      const result = authCodeFlow.parseCallback(
        'https://app.example.com/callback?code=auth-code&state=test-state'
      );

      expect(result.code).toBe('auth-code');
      expect(result.state).toBe('test-state');
    });

    it('should throw on OAuth error in callback', () => {
      try {
        authCodeFlow.parseCallback('?error=access_denied&error_description=User%20cancelled');
        expect.fail('Should have thrown');
      } catch (e: unknown) {
        expect((e as { code: string }).code).toBe('oauth_error');
      }
    });

    it('should throw on missing code', () => {
      try {
        authCodeFlow.parseCallback('?state=test-state');
        expect.fail('Should have thrown');
      } catch (e: unknown) {
        expect((e as { code: string }).code).toBe('missing_code');
      }
    });

    it('should throw on missing state', () => {
      try {
        authCodeFlow.parseCallback('?code=auth-code');
        expect.fail('Should have thrown');
      } catch (e: unknown) {
        expect((e as { code: string }).code).toBe('missing_state');
      }
    });
  });

  describe('Nonce Validation', () => {
    it('should reject on nonce mismatch in id_token', async () => {
      const discovery = createMockDiscoveryDocument(issuer);
      const expectedNonce = 'expected-nonce';
      const wrongNonce = 'wrong-nonce';

      // Create ID token with wrong nonce
      const idToken = createMockIdToken({ nonce: wrongNonce });

      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenResponse({ id_token: idToken }),
      }));

      await expect(
        authCodeFlow.exchangeCode(discovery, {
          code: 'auth-code',
          state: 'test-state',
          redirectUri,
          codeVerifier: 'test-verifier',
          nonce: expectedNonce,
          scope: 'openid profile',
        })
      ).rejects.toMatchObject({ code: 'nonce_mismatch' });
    });

    it('should accept valid nonce in id_token', async () => {
      const discovery = createMockDiscoveryDocument(issuer);
      const nonce = 'valid-nonce';

      // Create ID token with correct nonce
      const idToken = createMockIdToken({ nonce });

      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenResponse({ id_token: idToken }),
      }));

      const tokens = await authCodeFlow.exchangeCode(discovery, {
        code: 'auth-code',
        state: 'test-state',
        redirectUri,
        codeVerifier: 'test-verifier',
        nonce,
        scope: 'openid profile',
      });

      expect(tokens.accessToken).toBe('mock-access-token');
    });
  });

  describe('DPoP token request binding', () => {
    it('sends resource and audience on authorization code token requests', async () => {
      const discovery = createMockDiscoveryDocument(issuer);
      const nonce = 'valid-nonce';
      const idToken = createMockIdToken({ nonce });

      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenResponse({ id_token: idToken }),
      }));

      await authCodeFlow.exchangeCode(discovery, {
        code: 'auth-code',
        state: 'test-state',
        redirectUri,
        codeVerifier: 'test-verifier',
        nonce,
        scope: 'openid profile',
        resource: ['https://api.example.com/orders', 'https://api.example.com/profile'],
        audience: 'https://api.example.com',
      });

      const requestBody = new URLSearchParams(http.calls[0]?.options?.body as string);
      expect(requestBody.getAll('resource')).toEqual([
        'https://api.example.com/orders',
        'https://api.example.com/profile',
      ]);
      expect(requestBody.get('audience')).toBe('https://api.example.com');
    });

    it('attaches DPoP proof to authorization code token requests', async () => {
      const discovery = createMockDiscoveryDocument(issuer);
      const nonce = 'valid-nonce';
      const idToken = createMockIdToken({ nonce });

      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockTokenResponse({ id_token: idToken, token_type: 'DPoP' }),
      }));

      const tokens = await authCodeFlow.exchangeCode(discovery, {
        code: 'auth-code',
        state: 'test-state',
        redirectUri,
        codeVerifier: 'test-verifier',
        nonce,
        scope: 'openid profile',
        dpopProof: 'proof.jwt',
      });

      expect(http.calls[0]?.options?.headers).toMatchObject({ DPoP: 'proof.jwt' });
      expect(tokens.tokenType).toBe('DPoP');
    });

    it('retries a token request once when the server returns a DPoP nonce challenge', async () => {
      const discovery = createMockDiscoveryDocument(issuer);
      const nonce = 'valid-nonce';
      const idToken = createMockIdToken({ nonce });
      const proofFactory = vi.fn(async (serverNonce: string) => `proof-with-${serverNonce}`);
      let tokenCalls = 0;

      http.setHandler(() => {
        tokenCalls += 1;
        if (tokenCalls === 1) {
          return {
            ok: false,
            status: 400,
            headers: { 'DPoP-Nonce': 'server-nonce-1' },
            data: {
              error: 'use_dpop_nonce',
              error_description: 'DPoP nonce required',
            },
          };
        }

        return {
          ok: true,
          status: 200,
          data: createMockTokenResponse({ id_token: idToken, token_type: 'DPoP' }),
        };
      });

      const tokens = await authCodeFlow.exchangeCode(discovery, {
        code: 'auth-code',
        state: 'test-state',
        redirectUri,
        codeVerifier: 'test-verifier',
        nonce,
        scope: 'openid profile',
        dpopProof: 'initial-proof.jwt',
        dpopProofFactory: proofFactory,
      });

      expect(tokens.tokenType).toBe('DPoP');
      expect(proofFactory).toHaveBeenCalledWith('server-nonce-1');
      expect(http.calls).toHaveLength(2);
      expect(http.calls[0]?.options?.headers).toMatchObject({ DPoP: 'initial-proof.jwt' });
      expect(http.calls[1]?.options?.headers).toMatchObject({ DPoP: 'proof-with-server-nonce-1' });
    });

    it('does not loop when a DPoP nonce retry also fails', async () => {
      const discovery = createMockDiscoveryDocument(issuer);
      const proofFactory = vi.fn(async (serverNonce: string) => `proof-with-${serverNonce}`);

      http.setHandler(() => ({
        ok: false,
        status: 400,
        headers: { 'dpop-nonce': 'server-nonce-1' },
        data: {
          error: 'use_dpop_nonce',
          error_description: 'DPoP nonce required',
        },
      }));

      await expect(
        authCodeFlow.exchangeCode(discovery, {
          code: 'auth-code',
          state: 'test-state',
          redirectUri,
          codeVerifier: 'test-verifier',
          nonce: 'valid-nonce',
          scope: 'openid profile',
          dpopProof: 'initial-proof.jwt',
          dpopProofFactory: proofFactory,
        })
      ).rejects.toMatchObject({ code: 'token_error' });

      expect(proofFactory).toHaveBeenCalledTimes(1);
      expect(http.calls).toHaveLength(2);
    });

    it('fails without retry when use_dpop_nonce omits the DPoP-Nonce header', async () => {
      const discovery = createMockDiscoveryDocument(issuer);
      const proofFactory = vi.fn(async (serverNonce: string) => `proof-with-${serverNonce}`);

      http.setHandler(() => ({
        ok: false,
        status: 400,
        data: {
          error: 'use_dpop_nonce',
          error_description: 'DPoP nonce required',
        },
      }));

      await expect(
        authCodeFlow.exchangeCode(discovery, {
          code: 'auth-code',
          state: 'test-state',
          redirectUri,
          codeVerifier: 'test-verifier',
          nonce: 'valid-nonce',
          scope: 'openid profile',
          dpopProof: 'initial-proof.jwt',
          dpopProofFactory: proofFactory,
        })
      ).rejects.toMatchObject({ code: 'token_error' });

      expect(proofFactory).not.toHaveBeenCalled();
      expect(http.calls).toHaveLength(1);
    });

    it('exposes refresh token expiry metadata from token responses', async () => {
      const discovery = createMockDiscoveryDocument(issuer);
      const nonce = 'valid-nonce';
      const idToken = createMockIdToken({ nonce });

      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: {
          ...createMockTokenResponse({ id_token: idToken }),
          refresh_token_expires_in: 604800,
          refresh_token_expires_at: '2026-06-01T00:00:00.000Z',
          refresh_token_expires_at_unix: 1780272000,
        },
      }));

      const tokens = await authCodeFlow.exchangeCode(discovery, {
        code: 'auth-code',
        state: 'test-state',
        redirectUri,
        codeVerifier: 'test-verifier',
        nonce,
        scope: 'openid profile',
      });

      expect(tokens.refreshTokenExpiresIn).toBe(604800);
      expect(tokens.refreshTokenExpiresAtIso).toBe('2026-06-01T00:00:00.000Z');
      expect(tokens.refreshTokenExpiresAt).toBe(1780272000);
    });
  });

  describe('Security Parameter Protection', () => {
    it('should not allow extraParams to override security parameters', async () => {
      const discovery = createMockDiscoveryDocument(issuer);

      // Generate auth state
      const authState = await stateManager.generateAuthState({
        redirectUri,
        codeVerifier: 'test-verifier',
        scope: 'openid profile',
      });

      const pkce = {
        codeVerifier: 'test-verifier',
        codeChallenge: 'test-challenge',
        codeChallengeMethod: 'S256' as const,
      };

      // Try to override security parameters via extraParams
      const result = authCodeFlow.buildAuthorizationUrl(discovery, authState, pkce, {
        redirectUri,
        resource: ['https://api.example.com/orders', 'https://api.example.com/profile'],
        audience: 'https://api.example.com',
        extraParams: {
          state: 'attacker-state',
          nonce: 'attacker-nonce',
          code_challenge: 'attacker-challenge',
          code_challenge_method: 'plain',
          response_type: 'token',
          client_id: 'attacker-client',
          redirect_uri: 'https://attacker.com/callback',
          scope: 'admin',
          resource: 'https://attacker.example.com',
          audience: 'https://attacker.example.com',
        },
      });

      // Security parameters should NOT be overwritten
      const url = new URL(result.url);
      expect(url.searchParams.get('state')).toBe(authState.state);
      expect(url.searchParams.get('nonce')).toBe(authState.nonce);
      expect(url.searchParams.get('code_challenge')).toBe('test-challenge');
      expect(url.searchParams.get('code_challenge_method')).toBe('S256');
      expect(url.searchParams.get('response_type')).toBe('code');
      expect(url.searchParams.get('client_id')).toBe(clientId);
      expect(url.searchParams.get('redirect_uri')).toBe(redirectUri);
      expect(url.searchParams.get('scope')).toBe('openid profile');
      expect(url.searchParams.getAll('resource')).toEqual([
        'https://api.example.com/orders',
        'https://api.example.com/profile',
      ]);
      expect(url.searchParams.get('audience')).toBe('https://api.example.com');
    });

    it('should allow non-security extraParams', async () => {
      const discovery = createMockDiscoveryDocument(issuer);

      const authState = await stateManager.generateAuthState({
        redirectUri,
        codeVerifier: 'test-verifier',
        scope: 'openid profile',
      });

      const pkce = {
        codeVerifier: 'test-verifier',
        codeChallenge: 'test-challenge',
        codeChallengeMethod: 'S256' as const,
      };

      const result = authCodeFlow.buildAuthorizationUrl(discovery, authState, pkce, {
        redirectUri,
        extraParams: {
          ui_locales: 'ja',
          custom_param: 'custom_value',
        },
      });

      const url = new URL(result.url);
      expect(url.searchParams.get('ui_locales')).toBe('ja');
      expect(url.searchParams.get('custom_param')).toBe('custom_value');
    });
  });
});
