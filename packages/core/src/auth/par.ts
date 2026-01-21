/**
 * PAR (Pushed Authorization Request) Client
 * RFC 9126: OAuth 2.0 Pushed Authorization Requests
 *
 * PAR allows the client to push the authorization request payload
 * to the authorization server via a direct POST request, receiving
 * a request_uri to use in the authorization URL.
 *
 * Benefits:
 * - Integrity protection of authorization request
 * - Confidentiality of authorization request parameters
 * - Support for large request parameters
 * - Required for FAPI 2.0 compliance
 */

import type { HttpClient } from '../providers/http.js';
import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import type { PARRequest, PARResponse, PARResult, PARClientOptions } from '../types/par.js';
import { AuthrimError } from '../types/errors.js';

/**
 * PAR Client
 *
 * Handles Pushed Authorization Requests per RFC 9126.
 */
export class PARClient {
  constructor(
    private readonly http: HttpClient,
    private readonly clientId: string,
    private readonly options?: PARClientOptions
  ) {}

  /**
   * Push authorization request to the server
   *
   * @param discovery - OIDC discovery document
   * @param request - PAR request parameters
   * @returns PAR result with request_uri and expiration
   * @throws AuthrimError with code 'no_par_endpoint' if PAR endpoint not available
   * @throws AuthrimError with code 'par_error' if PAR request fails
   */
  async pushAuthorizationRequest(
    discovery: OIDCDiscoveryDocument,
    request: PARRequest
  ): Promise<PARResult> {
    const parEndpoint = discovery.pushed_authorization_request_endpoint;

    if (!parEndpoint) {
      throw new AuthrimError(
        'no_par_endpoint',
        'PAR endpoint not available in discovery document'
      );
    }

    // Build PAR request body
    const body = new URLSearchParams();

    // Required parameters
    body.set('client_id', this.clientId);
    body.set('response_type', request.responseType ?? 'code');
    body.set('redirect_uri', request.redirectUri);
    body.set('state', request.state);
    body.set('nonce', request.nonce);
    body.set('code_challenge', request.codeChallenge);
    body.set('code_challenge_method', request.codeChallengeMethod);

    // Scopes
    body.set('scope', request.scope ?? 'openid profile');

    // Optional parameters
    if (request.prompt) {
      body.set('prompt', request.prompt);
    }
    if (request.loginHint) {
      body.set('login_hint', request.loginHint);
    }
    if (request.acrValues) {
      body.set('acr_values', request.acrValues);
    }

    // Extra custom parameters (with security parameter protection)
    if (request.extraParams) {
      const protectedParams = new Set([
        'client_id',
        'response_type',
        'redirect_uri',
        'state',
        'nonce',
        'code_challenge',
        'code_challenge_method',
        'scope',
      ]);

      for (const [key, value] of Object.entries(request.extraParams)) {
        if (protectedParams.has(key.toLowerCase())) {
          continue; // Silently ignore protected params
        }
        body.set(key, value);
      }
    }

    // Build headers
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...this.options?.headers,
    };

    // Make PAR request
    let response;
    try {
      response = await this.http.fetch<PARResponse>(parEndpoint, {
        method: 'POST',
        headers,
        body: body.toString(),
      });
    } catch (error) {
      throw new AuthrimError('network_error', 'PAR request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (!response.ok) {
      const errorData = response.data as unknown as Record<string, unknown>;
      throw new AuthrimError('par_error', 'PAR request failed', {
        details: {
          status: response.status,
          error: errorData?.error,
          error_description: errorData?.error_description,
        },
      });
    }

    const parResponse = response.data;

    // Validate response
    if (!parResponse.request_uri) {
      throw new AuthrimError('par_error', 'PAR response missing request_uri');
    }
    if (typeof parResponse.expires_in !== 'number') {
      throw new AuthrimError('par_error', 'PAR response missing or invalid expires_in');
    }

    // Calculate absolute expiration
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + parResponse.expires_in;

    return {
      requestUri: parResponse.request_uri,
      expiresAt,
    };
  }

  /**
   * Build authorization URL using request_uri from PAR
   *
   * @param discovery - OIDC discovery document
   * @param requestUri - Request URI from PAR response
   * @returns Authorization URL
   */
  buildAuthorizationUrlWithPar(
    discovery: OIDCDiscoveryDocument,
    requestUri: string
  ): string {
    const params = new URLSearchParams();
    params.set('client_id', this.clientId);
    params.set('request_uri', requestUri);

    return `${discovery.authorization_endpoint}?${params.toString()}`;
  }
}
