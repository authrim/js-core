/**
 * Client Credentials Flow
 * RFC 6749 §4.4
 *
 * The client credentials grant is used for machine-to-machine (M2M) authentication
 * where no user is involved. The client authenticates directly with the authorization
 * server using its own credentials.
 *
 * IMPORTANT: This flow should only be used in secure environments (server-side)
 * where client credentials can be kept confidential.
 */

import type { HttpClient } from '../providers/http.js';
import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import type { TokenSet, TokenResponse } from '../types/token.js';
import type { ClientCredentials } from '../types/client-auth.js';
import { buildClientAuthentication } from './client-auth.js';
import { AuthrimError } from '../types/errors.js';

/**
 * Options for ClientCredentialsClient constructor
 */
export interface ClientCredentialsClientOptions {
  /** HTTP client */
  http: HttpClient;
  /** Client ID */
  clientId: string;
  /** Client credentials */
  credentials: ClientCredentials;
}

/**
 * Options for getting a token
 */
export interface ClientCredentialsTokenOptions {
  /** Scopes to request */
  scope?: string;
  /** Target audience (resource server identifier) */
  audience?: string;
  /** Additional parameters */
  extraParams?: Record<string, string>;
}

/**
 * Client Credentials Flow Client
 *
 * Handles machine-to-machine authentication using the client credentials grant.
 */
export class ClientCredentialsClient {
  private readonly http: HttpClient;
  private readonly clientId: string;
  private readonly credentials: ClientCredentials;

  constructor(options: ClientCredentialsClientOptions) {
    this.http = options.http;
    this.clientId = options.clientId;
    this.credentials = options.credentials;
  }

  /**
   * Get an access token using client credentials
   *
   * @param discovery - OIDC discovery document
   * @param options - Token request options
   * @returns Token set
   * @throws AuthrimError with code 'client_credentials_error' if token request fails
   */
  async getToken(
    discovery: OIDCDiscoveryDocument,
    options?: ClientCredentialsTokenOptions
  ): Promise<TokenSet> {
    const tokenEndpoint = discovery.token_endpoint;

    // Build client authentication
    const { headers: authHeaders, bodyParams: authBodyParams } =
      await buildClientAuthentication(this.credentials, this.clientId, tokenEndpoint);

    // Build request body
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      ...authBodyParams,
    });

    // Add optional parameters
    if (options?.scope) {
      body.set('scope', options.scope);
    }
    if (options?.audience) {
      body.set('audience', options.audience);
    }

    // Add extra parameters (with protection for core params)
    if (options?.extraParams) {
      const protectedParams = new Set([
        'grant_type',
        'client_id',
        'client_secret',
        'client_assertion',
        'client_assertion_type',
        'scope',
        'audience',
      ]);

      for (const [key, value] of Object.entries(options.extraParams)) {
        if (protectedParams.has(key.toLowerCase())) {
          continue;
        }
        body.set(key, value);
      }
    }

    // Build headers
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...authHeaders,
    };

    // Make token request
    let response;
    try {
      response = await this.http.fetch<TokenResponse>(tokenEndpoint, {
        method: 'POST',
        headers,
        body: body.toString(),
      });
    } catch (error) {
      throw new AuthrimError('network_error', 'Client credentials token request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (!response.ok) {
      const errorData = response.data as unknown as Record<string, unknown>;
      throw new AuthrimError('client_credentials_error', 'Client credentials token request failed', {
        details: {
          status: response.status,
          error: errorData?.error,
          error_description: errorData?.error_description,
        },
      });
    }

    const tokenResponse = response.data;

    // Calculate expiresAt (epoch seconds)
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = tokenResponse.expires_in ? now + tokenResponse.expires_in : now + 3600;

    // Build token set
    // Note: Client credentials flow typically doesn't return refresh_token or id_token
    const tokenSet: TokenSet = {
      accessToken: tokenResponse.access_token,
      tokenType: (tokenResponse.token_type as 'Bearer') ?? 'Bearer',
      expiresAt,
      refreshToken: tokenResponse.refresh_token,
      scope: tokenResponse.scope,
    };

    return tokenSet;
  }
}
