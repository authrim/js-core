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
      });

      expect(tokens.accessToken).toBe('mock-access-token');
    });
  });

  describe('Security Parameter Protection', () => {
    it('should not allow extraParams to override security parameters', async () => {
      const discovery = createMockDiscoveryDocument(issuer);

      // Generate auth state
      const authState = await stateManager.generateAuthState({
        redirectUri,
        codeVerifier: 'test-verifier',
      });

      const pkce = {
        codeVerifier: 'test-verifier',
        codeChallenge: 'test-challenge',
        codeChallengeMethod: 'S256' as const,
      };

      // Try to override security parameters via extraParams
      const result = authCodeFlow.buildAuthorizationUrl(discovery, authState, pkce, {
        redirectUri,
        extraParams: {
          state: 'attacker-state',
          nonce: 'attacker-nonce',
          code_challenge: 'attacker-challenge',
          code_challenge_method: 'plain',
          response_type: 'token',
          client_id: 'attacker-client',
          redirect_uri: 'https://attacker.com/callback',
          scope: 'admin',
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
    });

    it('should allow non-security extraParams', async () => {
      const discovery = createMockDiscoveryDocument(issuer);

      const authState = await stateManager.generateAuthState({
        redirectUri,
        codeVerifier: 'test-verifier',
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
