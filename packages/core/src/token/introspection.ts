/**
 * Token Introspection (RFC 7662)
 *
 * Implements OAuth 2.0 Token Introspection to validate tokens server-side.
 * https://datatracker.ietf.org/doc/html/rfc7662
 */

import type { HttpClient, OAuthErrorResponse } from '../providers/http.js';
import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import { AuthrimError } from '../types/errors.js';

/**
 * Token type hint for introspection
 */
export type IntrospectionTokenTypeHint = 'access_token' | 'refresh_token';

/**
 * Token introspection response (RFC 7662)
 */
export interface IntrospectionResponse {
  /** Whether the token is active */
  active: boolean;
  /** Space-separated list of scopes (if active) */
  scope?: string;
  /** Client identifier (if active) */
  client_id?: string;
  /** Human-readable username (if active) */
  username?: string;
  /** Token type (e.g., "Bearer") */
  token_type?: string;
  /** Expiration time (Unix timestamp) */
  exp?: number;
  /** Issued at time (Unix timestamp) */
  iat?: number;
  /** Not before time (Unix timestamp) */
  nbf?: number;
  /** Subject identifier */
  sub?: string;
  /** Audience (single string or array) */
  aud?: string | string[];
  /** Issuer identifier */
  iss?: string;
  /** JWT ID */
  jti?: string;
  /** Additional claims */
  [key: string]: unknown;
}

/**
 * Token introspection options
 */
export interface IntrospectTokenOptions {
  /** Token to introspect */
  token: string;
  /** Hint about the token type (optional, helps server optimize lookup) */
  tokenTypeHint?: IntrospectionTokenTypeHint;
}

/**
 * Token introspector options
 */
export interface TokenIntrospectorOptions {
  /** HTTP client */
  http: HttpClient;
  /** Client ID */
  clientId: string;
}

/**
 * Token Introspector
 *
 * Handles token introspection requests to the authorization server.
 */
export class TokenIntrospector {
  private readonly http: HttpClient;
  private readonly clientId: string;

  constructor(options: TokenIntrospectorOptions) {
    this.http = options.http;
    this.clientId = options.clientId;
  }

  /**
   * Introspect a token
   *
   * Per RFC 7662, the introspection endpoint returns:
   * - { active: true, ... } for valid tokens with additional metadata
   * - { active: false } for invalid, expired, or revoked tokens
   *
   * @param discovery - OIDC discovery document
   * @param options - Introspection options
   * @returns Introspection response
   * @throws AuthrimError if introspection endpoint is not available or request fails
   */
  async introspect(
    discovery: OIDCDiscoveryDocument,
    options: IntrospectTokenOptions
  ): Promise<IntrospectionResponse> {
    const endpoint = discovery.introspection_endpoint;

    if (!endpoint) {
      throw new AuthrimError(
        'no_introspection_endpoint',
        'Authorization server does not support token introspection'
      );
    }

    return this.introspectWithEndpoint(endpoint, options);
  }

  /**
   * Introspect a token directly using the endpoint URL
   *
   * Use this when you have the endpoint URL but not the full discovery document.
   *
   * @param endpoint - Introspection endpoint URL
   * @param options - Introspection options
   * @returns Introspection response
   * @throws AuthrimError if request fails
   */
  async introspectWithEndpoint(
    endpoint: string,
    options: IntrospectTokenOptions
  ): Promise<IntrospectionResponse> {
    // Build introspection request
    const body = new URLSearchParams({
      client_id: this.clientId,
      token: options.token,
    });

    if (options.tokenTypeHint) {
      body.set('token_type_hint', options.tokenTypeHint);
    }

    let response;
    try {
      response = await this.http.fetch<IntrospectionResponse | OAuthErrorResponse>(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
      });
    } catch (error) {
      throw new AuthrimError('network_error', 'Token introspection request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (!response.ok) {
      const errorData = response.data as OAuthErrorResponse | undefined;
      throw new AuthrimError('introspection_error', 'Token introspection failed', {
        details: {
          status: response.status,
          error: errorData?.error,
          error_description: errorData?.error_description,
        },
      });
    }

    return response.data as IntrospectionResponse;
  }

  /**
   * Check if a token is active
   *
   * Convenience method that returns only the active status.
   *
   * @param discovery - OIDC discovery document
   * @param token - Token to check
   * @returns True if token is active
   */
  async isActive(discovery: OIDCDiscoveryDocument, token: string): Promise<boolean> {
    const result = await this.introspect(discovery, { token });
    return result.active;
  }
}
