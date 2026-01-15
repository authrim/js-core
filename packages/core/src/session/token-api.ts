/**
 * Token API Client
 *
 * Provides session verification against the authorization server.
 * Uses the UserInfo endpoint or custom session check endpoint.
 */

import type { HttpClient } from '../providers/http.js';
import type { OIDCDiscoveryDocument, UserInfo } from '../types/oidc.js';
import { AuthrimError } from '../types/errors.js';

/**
 * Session check result
 */
export interface SessionCheckResult {
  /** Whether session is valid */
  valid: boolean;
  /** User info if session is valid */
  user?: UserInfo;
  /** Error if session is invalid */
  error?: AuthrimError;
}

/**
 * Token API client options
 */
export interface TokenApiClientOptions {
  /** HTTP client */
  http: HttpClient;
}

/**
 * Token API Client
 *
 * Verifies session status with the authorization server.
 */
export class TokenApiClient {
  private readonly http: HttpClient;

  constructor(options: TokenApiClientOptions) {
    this.http = options.http;
  }

  /**
   * Check session validity by calling UserInfo endpoint
   *
   * @param discovery - OIDC discovery document
   * @param accessToken - Access token to verify
   * @returns Session check result
   */
  async checkSession(
    discovery: OIDCDiscoveryDocument,
    accessToken: string
  ): Promise<SessionCheckResult> {
    const userinfoEndpoint = discovery.userinfo_endpoint;

    if (!userinfoEndpoint) {
      return {
        valid: false,
        error: new AuthrimError('no_userinfo_endpoint', 'UserInfo endpoint not available'),
      };
    }

    try {
      const response = await this.http.fetch<UserInfo>(userinfoEndpoint, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (!response.ok) {
        // 401 means token is invalid/expired
        if (response.status === 401) {
          return {
            valid: false,
            error: new AuthrimError('session_expired', 'Session has expired'),
          };
        }

        return {
          valid: false,
          error: new AuthrimError('session_check_failed', 'Session check failed', {
            details: { status: response.status },
          }),
        };
      }

      return {
        valid: true,
        user: response.data,
      };
    } catch (error) {
      return {
        valid: false,
        error: new AuthrimError('network_error', 'Failed to check session', {
          cause: error instanceof Error ? error : undefined,
        }),
      };
    }
  }

  /**
   * Get user info from the authorization server
   *
   * @param discovery - OIDC discovery document
   * @param accessToken - Access token
   * @returns User info
   * @throws AuthrimError if request fails
   */
  async getUserInfo(discovery: OIDCDiscoveryDocument, accessToken: string): Promise<UserInfo> {
    const userinfoEndpoint = discovery.userinfo_endpoint;

    if (!userinfoEndpoint) {
      throw new AuthrimError('no_userinfo_endpoint', 'UserInfo endpoint not available');
    }

    let response;
    try {
      response = await this.http.fetch<UserInfo>(userinfoEndpoint, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
    } catch (error) {
      throw new AuthrimError('network_error', 'Failed to fetch user info', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (!response.ok) {
      throw new AuthrimError('userinfo_error', 'Failed to get user info', {
        details: { status: response.status },
      });
    }

    return response.data;
  }
}
