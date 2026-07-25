import { describe, expect, it } from 'vitest';
import { AuthorizationCodeFlow } from './authorization-code.js';
import type { HttpClient } from '../providers/http.js';
import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import type { AuthrimError } from '../types/errors.js';

const discovery: OIDCDiscoveryDocument = {
  issuer: 'https://issuer.example',
  authorization_endpoint: 'https://issuer.example/oauth/authorize',
  token_endpoint: 'https://issuer.example/oauth/token',
  jwks_uri: 'https://issuer.example/.well-known/jwks.json',
  response_types_supported: ['code'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['RS256'],
};

function jwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none' })}.${encode(payload)}.signature`;
}

describe('AuthorizationCodeFlow ID token validation', () => {
  it('rejects ID tokens without a numeric exp claim', async () => {
    const now = Math.floor(Date.now() / 1000);
    const http: HttpClient = {
      async fetch<T>() {
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          headers: {},
          data: {
            access_token: 'access-token',
            token_type: 'Bearer',
            id_token: jwt({
              iss: discovery.issuer,
              sub: 'user-1',
              aud: 'client-1',
              iat: now,
              nonce: 'nonce-1',
            }),
          } as T,
        };
      },
    };

    const flow = new AuthorizationCodeFlow(http, 'client-1');
    await expect(
      flow.exchangeCode(discovery, {
        code: 'code',
        state: 'state',
        redirectUri: 'https://app.example/callback',
        codeVerifier: 'verifier',
        nonce: 'nonce-1',
        scope: 'openid profile',
      })
    ).rejects.toMatchObject({ code: 'invalid_id_token' } satisfies Partial<AuthrimError>);
  });

  it('rejects ID tokens with an azp for a different client', async () => {
    const now = Math.floor(Date.now() / 1000);
    const http: HttpClient = {
      async fetch<T>() {
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          headers: {},
          data: {
            access_token: 'access-token',
            token_type: 'Bearer',
            id_token: jwt({
              iss: discovery.issuer,
              sub: 'user-1',
              aud: ['client-1', 'api-1'],
              azp: 'attacker-client',
              exp: now + 300,
              iat: now,
              nonce: 'nonce-1',
            }),
          } as T,
        };
      },
    };

    const flow = new AuthorizationCodeFlow(http, 'client-1');
    await expect(
      flow.exchangeCode(discovery, {
        code: 'code',
        state: 'state',
        redirectUri: 'https://app.example/callback',
        codeVerifier: 'verifier',
        nonce: 'nonce-1',
        scope: 'openid profile',
      })
    ).rejects.toMatchObject({ code: 'invalid_audience' } satisfies Partial<AuthrimError>);
  });
});
