/**
 * Mock OIDC Server
 *
 * Simulates an OIDC authorization server for integration testing.
 * Handles discovery, token, introspection, and revocation endpoints.
 */

import type { HttpClient, HttpOptions, HttpResponse } from '../../../src/providers/http.js';
import type { OIDCDiscoveryDocument } from '../../../src/types/oidc.js';
import type { IntrospectionResponse } from '../../../src/token/introspection.js';

/**
 * Mock server configuration
 */
export interface MockServerConfig {
  /** Issuer URL */
  issuer: string;
  /** Client ID */
  clientId: string;
  /** Whether tokens are valid by default */
  tokensValid?: boolean;
  /** Token expiration time in seconds */
  tokenExpiresIn?: number;
}

/**
 * Mock server state
 */
export interface MockServerState {
  /** Active tokens */
  activeTokens: Set<string>;
  /** Revoked tokens */
  revokedTokens: Set<string>;
  /** Token metadata */
  tokenMetadata: Map<string, { exp: number; sub: string; scope: string }>;
  /** Request log */
  requests: Array<{ url: string; method: string; body?: string }>;
}

/**
 * Create a mock OIDC server
 */
export function createMockOIDCServer(config: MockServerConfig): {
  http: HttpClient;
  discovery: OIDCDiscoveryDocument;
  state: MockServerState;
  issueToken: (options?: { sub?: string; scope?: string }) => {
    accessToken: string;
    refreshToken: string;
    idToken: string;
  };
  revokeToken: (token: string) => void;
  setTokensValid: (valid: boolean) => void;
} {
  const state: MockServerState = {
    activeTokens: new Set(),
    revokedTokens: new Set(),
    tokenMetadata: new Map(),
    requests: [],
  };

  let tokensValid = config.tokensValid ?? true;
  let tokenCounter = 0;

  const discovery: OIDCDiscoveryDocument = {
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/authorize`,
    token_endpoint: `${config.issuer}/token`,
    userinfo_endpoint: `${config.issuer}/userinfo`,
    revocation_endpoint: `${config.issuer}/revoke`,
    introspection_endpoint: `${config.issuer}/introspect`,
    end_session_endpoint: `${config.issuer}/logout`,
    jwks_uri: `${config.issuer}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
  };

  /**
   * Issue new tokens
   */
  function issueToken(options?: { sub?: string; scope?: string }) {
    tokenCounter++;
    const accessToken = `access-token-${tokenCounter}-${Date.now()}`;
    const refreshToken = `refresh-token-${tokenCounter}-${Date.now()}`;
    const idToken = createMockIdToken({
      iss: config.issuer,
      sub: options?.sub ?? 'user-123',
      aud: config.clientId,
      nonce: 'test-nonce',
    });

    const exp = Math.floor(Date.now() / 1000) + (config.tokenExpiresIn ?? 3600);
    const metadata = {
      exp,
      sub: options?.sub ?? 'user-123',
      scope: options?.scope ?? 'openid profile',
    };

    state.activeTokens.add(accessToken);
    state.activeTokens.add(refreshToken);
    state.tokenMetadata.set(accessToken, metadata);
    state.tokenMetadata.set(refreshToken, metadata);

    return { accessToken, refreshToken, idToken };
  }

  /**
   * Revoke a token
   */
  function revokeToken(token: string) {
    state.activeTokens.delete(token);
    state.revokedTokens.add(token);
  }

  /**
   * Set whether tokens are valid
   */
  function setTokensValid(valid: boolean) {
    tokensValid = valid;
  }

  /**
   * Handle HTTP requests
   */
  async function handleRequest<T>(url: string, options?: HttpOptions): Promise<HttpResponse<T>> {
    const method = options?.method ?? 'GET';
    const body = options?.body?.toString();

    state.requests.push({ url, method, body });

    // Parse request body
    const params = body ? new URLSearchParams(body) : new URLSearchParams();

    // Discovery endpoint
    if (url.endsWith('/.well-known/openid-configuration')) {
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: discovery as T,
      };
    }

    // Token endpoint
    if (url === discovery.token_endpoint) {
      const grantType = params.get('grant_type');

      if (grantType === 'authorization_code') {
        const tokens = issueToken();
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          headers: {},
          data: {
            access_token: tokens.accessToken,
            refresh_token: tokens.refreshToken,
            id_token: tokens.idToken,
            token_type: 'Bearer',
            expires_in: config.tokenExpiresIn ?? 3600,
            scope: 'openid profile',
          } as T,
        };
      }

      if (grantType === 'refresh_token') {
        const refreshToken = params.get('refresh_token');

        if (!refreshToken || !state.activeTokens.has(refreshToken)) {
          return {
            ok: false,
            status: 400,
            statusText: 'Bad Request',
            headers: {},
            data: {
              error: 'invalid_grant',
              error_description: 'Invalid refresh token',
            } as T,
          };
        }

        const tokens = issueToken();
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          headers: {},
          data: {
            access_token: tokens.accessToken,
            refresh_token: tokens.refreshToken,
            token_type: 'Bearer',
            expires_in: config.tokenExpiresIn ?? 3600,
            scope: 'openid profile',
          } as T,
        };
      }

      return {
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        headers: {},
        data: {
          error: 'unsupported_grant_type',
        } as T,
      };
    }

    // Introspection endpoint
    if (url === discovery.introspection_endpoint) {
      const token = params.get('token');

      if (!token) {
        return {
          ok: false,
          status: 400,
          statusText: 'Bad Request',
          headers: {},
          data: {
            error: 'invalid_request',
            error_description: 'Token parameter required',
          } as T,
        };
      }

      if (!tokensValid || !state.activeTokens.has(token) || state.revokedTokens.has(token)) {
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          headers: {},
          data: { active: false } as T,
        };
      }

      const metadata = state.tokenMetadata.get(token);
      const response: IntrospectionResponse = {
        active: true,
        client_id: config.clientId,
        token_type: 'Bearer',
        exp: metadata?.exp,
        sub: metadata?.sub,
        scope: metadata?.scope,
        iss: config.issuer,
      };

      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: response as T,
      };
    }

    // Revocation endpoint
    if (url === discovery.revocation_endpoint) {
      const token = params.get('token');

      if (!token) {
        return {
          ok: false,
          status: 400,
          statusText: 'Bad Request',
          headers: {},
          data: {
            error: 'invalid_request',
            error_description: 'Token parameter required',
          } as T,
        };
      }

      // RFC 7009: Always return 200 OK, even if token was already invalid
      revokeToken(token);

      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: undefined as T,
      };
    }

    // UserInfo endpoint
    if (url === discovery.userinfo_endpoint) {
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          sub: 'user-123',
          name: 'Test User',
          email: 'test@example.com',
        } as T,
      };
    }

    // Unknown endpoint
    return {
      ok: false,
      status: 404,
      statusText: 'Not Found',
      headers: {},
      data: { error: 'not_found' } as T,
    };
  }

  const http: HttpClient = {
    fetch: handleRequest,
  };

  return {
    http,
    discovery,
    state,
    issueToken,
    revokeToken,
    setTokensValid,
  };
}

/**
 * Create a mock ID token (JWT format, not cryptographically valid)
 */
function createMockIdToken(claims: {
  iss: string;
  sub: string;
  aud: string;
  nonce?: string;
}): string {
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    ...claims,
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
  };

  const encode = (obj: unknown) => {
    const json = JSON.stringify(obj);
    return Buffer.from(json).toString('base64url');
  };

  return `${encode(header)}.${encode(payload)}.fake-signature`;
}
