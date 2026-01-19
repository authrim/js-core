/**
 * Mock HTTP Client
 */

import type { HttpClient, HttpOptions, HttpResponse } from '../../src/providers/http.js';

/**
 * Mock response configuration
 */
export interface MockResponse<T = unknown> {
  ok: boolean;
  status: number;
  statusText?: string;
  data: T;
}

/**
 * Mock request handler
 */
export type MockHandler = (
  url: string,
  options?: HttpOptions
) => MockResponse | Promise<MockResponse>;

/**
 * Create a mock HTTP client
 */
export function createMockHttp(): HttpClient & {
  setHandler(handler: MockHandler): void;
  calls: Array<{ url: string; options?: HttpOptions }>;
} {
  let handler: MockHandler = () => ({
    ok: true,
    status: 200,
    data: {},
  });

  const calls: Array<{ url: string; options?: HttpOptions }> = [];

  return {
    calls,

    setHandler(h: MockHandler): void {
      handler = h;
    },

    async fetch<T>(url: string, options?: HttpOptions): Promise<HttpResponse<T>> {
      calls.push({ url, options });
      const response = await handler(url, options);
      return {
        ok: response.ok,
        status: response.status,
        statusText: response.statusText ?? (response.ok ? 'OK' : 'Error'),
        data: response.data as T,
      };
    },
  };
}

/**
 * Create a mock OIDC discovery document
 */
export function createMockDiscoveryDocument(issuer: string) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    revocation_endpoint: `${issuer}/revoke`,
    introspection_endpoint: `${issuer}/introspect`,
    end_session_endpoint: `${issuer}/logout`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
  };
}

/**
 * Create a mock token response
 */
export function createMockTokenResponse(
  overrides: Partial<{
    access_token: string;
    refresh_token: string;
    id_token: string;
    expires_in: number;
    token_type: string;
    scope: string;
  }> = {}
) {
  return {
    access_token: overrides.access_token ?? 'mock-access-token',
    refresh_token: overrides.refresh_token ?? 'mock-refresh-token',
    id_token: overrides.id_token ?? createMockIdToken(),
    expires_in: overrides.expires_in ?? 3600,
    token_type: overrides.token_type ?? 'Bearer',
    scope: overrides.scope ?? 'openid profile',
  };
}

/**
 * Create a mock ID token (JWT format, not cryptographically valid)
 */
export function createMockIdToken(claims: Record<string, unknown> = {}): string {
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: 'https://auth.example.com',
    sub: 'user-123',
    aud: 'test-client',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    nonce: 'test-nonce',
    ...claims,
  };

  const encode = (obj: unknown) => {
    const json = JSON.stringify(obj);
    return Buffer.from(json).toString('base64url');
  };

  return `${encode(header)}.${encode(payload)}.fake-signature`;
}
