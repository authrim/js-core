/**
 * Logout Tests
 *
 * Tests for acceptance criteria:
 * #4: Logout succeeds and clears tokens even without end_session_endpoint
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { LogoutHandler } from '../../src/session/logout.js';
import { STORAGE_KEYS } from '../../src/auth/state.js';
import { createMockStorage } from '../mocks/storage.js';
import { createMockDiscoveryDocument } from '../mocks/http.js';
import { EventEmitter } from '../../src/events/emitter.js';

describe('Logout Handler', () => {
  const issuer = 'https://auth.example.com';
  const clientId = 'test-client';
  const issuerHash = 'issuer-hash';
  const clientIdHash = 'client-hash';

  let storage: ReturnType<typeof createMockStorage>;
  let eventEmitter: EventEmitter;
  let logoutHandler: LogoutHandler;

  beforeEach(async () => {
    storage = createMockStorage();
    eventEmitter = new EventEmitter();
    logoutHandler = new LogoutHandler({
      storage,
      clientId,
      issuerHash,
      clientIdHash,
      eventEmitter,
    });

    // Store some tokens
    const tokenKey = STORAGE_KEYS.tokens(issuerHash, clientIdHash);
    const idTokenKey = STORAGE_KEYS.idToken(issuerHash, clientIdHash);
    await storage.set(tokenKey, JSON.stringify({ accessToken: 'test-token' }));
    await storage.set(idTokenKey, 'test-id-token');
  });

  describe('Token Cleanup - Acceptance Criteria #4', () => {
    it('should clear tokens when end_session_endpoint is not available', async () => {
      const discoveryWithoutEndSession = {
        ...createMockDiscoveryDocument(issuer),
        end_session_endpoint: undefined,
      };

      const result = await logoutHandler.logout(discoveryWithoutEndSession);

      expect(result.localOnly).toBe(true);
      expect(result.logoutUrl).toBeUndefined();

      // Tokens should be cleared
      const tokenKey = STORAGE_KEYS.tokens(issuerHash, clientIdHash);
      const idTokenKey = STORAGE_KEYS.idToken(issuerHash, clientIdHash);
      expect(await storage.get(tokenKey)).toBeNull();
      expect(await storage.get(idTokenKey)).toBeNull();
    });

    it('should clear tokens when discovery is null', async () => {
      const result = await logoutHandler.logout(null);

      expect(result.localOnly).toBe(true);

      // Tokens should be cleared
      const tokenKey = STORAGE_KEYS.tokens(issuerHash, clientIdHash);
      expect(await storage.get(tokenKey)).toBeNull();
    });

    it('should clear tokens even when building logout URL', async () => {
      const discovery = createMockDiscoveryDocument(issuer);

      const result = await logoutHandler.logout(discovery, {
        postLogoutRedirectUri: 'https://app.example.com',
      });

      expect(result.localOnly).toBe(false);
      expect(result.logoutUrl).toContain('/logout');

      // Tokens should still be cleared
      const tokenKey = STORAGE_KEYS.tokens(issuerHash, clientIdHash);
      expect(await storage.get(tokenKey)).toBeNull();
    });
  });

  describe('Logout URL Building', () => {
    it('should build logout URL with all parameters', async () => {
      const discovery = createMockDiscoveryDocument(issuer);

      const result = await logoutHandler.logout(discovery, {
        postLogoutRedirectUri: 'https://app.example.com',
        idTokenHint: 'custom-id-token',
        state: 'logout-state',
      });

      expect(result.logoutUrl).toContain('post_logout_redirect_uri=https%3A%2F%2Fapp.example.com');
      expect(result.logoutUrl).toContain('id_token_hint=custom-id-token');
      expect(result.logoutUrl).toContain('state=logout-state');
      expect(result.logoutUrl).toContain('client_id=test-client');
    });

    it('should use stored id_token when not provided', async () => {
      const discovery = createMockDiscoveryDocument(issuer);

      const result = await logoutHandler.logout(discovery);

      // Should use stored ID token
      expect(result.logoutUrl).toContain('id_token_hint=test-id-token');
    });

    it('should respect endpoint override to disable logout', async () => {
      const handlerWithDisabledLogout = new LogoutHandler({
        storage,
        clientId,
        issuerHash,
        clientIdHash,
        endpoints: {
          endSession: null, // Explicitly disabled
        },
      });

      const discovery = createMockDiscoveryDocument(issuer);
      const result = await handlerWithDisabledLogout.logout(discovery);

      expect(result.localOnly).toBe(true);
      expect(result.logoutUrl).toBeUndefined();
    });

    it('should use custom endpoint override', async () => {
      const customEndpoint = 'https://custom.auth.com/logout';
      const handlerWithOverride = new LogoutHandler({
        storage,
        clientId,
        issuerHash,
        clientIdHash,
        endpoints: {
          endSession: customEndpoint,
        },
      });

      const discovery = createMockDiscoveryDocument(issuer);
      const result = await handlerWithOverride.logout(discovery);

      expect(result.logoutUrl).toContain(customEndpoint);
    });
  });

  describe('Event Emission', () => {
    it('should emit session:ended event', async () => {
      let eventReceived = false;
      let eventReason: string | undefined;

      eventEmitter.on('session:ended', (event) => {
        eventReceived = true;
        eventReason = event.reason;
      });

      await logoutHandler.logout(null);

      expect(eventReceived).toBe(true);
      expect(eventReason).toBe('logout');
    });
  });
});
