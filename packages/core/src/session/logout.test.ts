import { describe, expect, it } from 'vitest';
import { STORAGE_KEYS } from '../auth/state.js';
import type { HttpClient } from '../providers/http.js';
import type { AuthrimStorage } from '../providers/storage.js';
import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import { LogoutHandler } from './logout.js';

describe('LogoutHandler', () => {
  it('clears local tokens before calling the revocation endpoint', async () => {
    const issuerHash = 'issuer';
    const clientIdHash = 'client-hash';
    const tokenKey = STORAGE_KEYS.tokens(issuerHash, clientIdHash);
    const idTokenKey = STORAGE_KEYS.idToken(issuerHash, clientIdHash);
    const values = new Map<string, string>([
      [
        tokenKey,
        JSON.stringify({
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
          tokenType: 'Bearer',
          expiresAt: 9999999999,
        }),
      ],
      [idTokenKey, 'id-token'],
    ]);
    const storage: AuthrimStorage = {
      async get(key) {
        return values.get(key) ?? null;
      },
      async set(key, value) {
        values.set(key, value);
      },
      async remove(key) {
        values.delete(key);
      },
    };
    let revocationCalled = false;
    const http: HttpClient = {
      async fetch<T>() {
        revocationCalled = true;
        expect(values.has(tokenKey)).toBe(false);
        expect(values.has(idTokenKey)).toBe(false);
        return { ok: true, status: 200, statusText: 'OK', headers: {}, data: undefined as T };
      },
    };
    const handler = new LogoutHandler({
      storage,
      http,
      clientId: 'client-1',
      issuerHash,
      clientIdHash,
    });
    const discovery = {
      issuer: 'https://issuer.example',
      authorization_endpoint: 'https://issuer.example/oauth/authorize',
      token_endpoint: 'https://issuer.example/oauth/token',
      jwks_uri: 'https://issuer.example/jwks',
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      revocation_endpoint: 'https://issuer.example/oauth/revoke',
    } satisfies OIDCDiscoveryDocument;

    await handler.logout(discovery, { revokeTokens: true });

    expect(revocationCalled).toBe(true);
    expect(values.has(tokenKey)).toBe(false);
    expect(values.has(idTokenKey)).toBe(false);
  });
});
