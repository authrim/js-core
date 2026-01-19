/**
 * Token Revocation (RFC 7009)
 *
 * Implements OAuth 2.0 Token Revocation to explicitly invalidate tokens.
 * https://datatracker.ietf.org/doc/html/rfc7009
 */

import type { HttpClient, OAuthErrorResponse } from '../providers/http.js';
import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import { AuthrimError } from '../types/errors.js';

/**
 * Token type hint for revocation
 */
export type TokenTypeHint = 'access_token' | 'refresh_token';

/**
 * Token revocation options
 */
export interface RevokeTokenOptions {
  /** Token to revoke */
  token: string;
  /** Hint about the token type (optional, helps server optimize lookup) */
  tokenTypeHint?: TokenTypeHint;
}

/**
 * Token revoker options
 */
export interface TokenRevokerOptions {
  /** HTTP client */
  http: HttpClient;
  /** Client ID */
  clientId: string;
}

/**
 * Token Revoker
 *
 * Handles token revocation requests to the authorization server.
 */
export class TokenRevoker {
  private readonly http: HttpClient;
  private readonly clientId: string;

  constructor(options: TokenRevokerOptions) {
    this.http = options.http;
    this.clientId = options.clientId;
  }

  /**
   * Revoke a token
   *
   * Per RFC 7009, the revocation endpoint:
   * - Returns 200 OK on success (even if token was already invalid)
   * - Returns 400 for invalid requests
   * - Returns 503 if temporarily unavailable
   *
   * @param discovery - OIDC discovery document
   * @param options - Revocation options
   * @throws AuthrimError if revocation endpoint is not available or request fails
   */
  async revoke(discovery: OIDCDiscoveryDocument, options: RevokeTokenOptions): Promise<void> {
    const endpoint = discovery.revocation_endpoint;

    if (!endpoint) {
      throw new AuthrimError(
        'no_revocation_endpoint',
        'Authorization server does not support token revocation'
      );
    }

    // Build revocation request
    const body = new URLSearchParams({
      client_id: this.clientId,
      token: options.token,
    });

    if (options.tokenTypeHint) {
      body.set('token_type_hint', options.tokenTypeHint);
    }

    let response;
    try {
      response = await this.http.fetch<OAuthErrorResponse | void>(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
      });
    } catch (error) {
      throw new AuthrimError('network_error', 'Token revocation request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    // RFC 7009: 200 OK means success (even if token was already invalid)
    if (response.ok) {
      return;
    }

    // Handle error response
    const errorData = response.data as OAuthErrorResponse | undefined;
    throw new AuthrimError('revocation_error', 'Token revocation failed', {
      details: {
        status: response.status,
        error: errorData?.error,
        error_description: errorData?.error_description,
      },
    });
  }

  /**
   * Revoke a token directly using the endpoint URL
   *
   * Use this when you have the endpoint URL but not the full discovery document.
   *
   * @param endpoint - Revocation endpoint URL
   * @param options - Revocation options
   * @throws AuthrimError if request fails
   */
  async revokeWithEndpoint(endpoint: string, options: RevokeTokenOptions): Promise<void> {
    // Build revocation request
    const body = new URLSearchParams({
      client_id: this.clientId,
      token: options.token,
    });

    if (options.tokenTypeHint) {
      body.set('token_type_hint', options.tokenTypeHint);
    }

    let response;
    try {
      response = await this.http.fetch<OAuthErrorResponse | void>(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
      });
    } catch (error) {
      throw new AuthrimError('network_error', 'Token revocation request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (response.ok) {
      return;
    }

    const errorData = response.data as OAuthErrorResponse | undefined;
    throw new AuthrimError('revocation_error', 'Token revocation failed', {
      details: {
        status: response.status,
        error: errorData?.error,
        error_description: errorData?.error_description,
      },
    });
  }
}
