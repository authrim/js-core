/**
 * Session Manager
 *
 * Coordinates session-related operations including checking
 * session status and retrieving user information.
 */

import type { OIDCDiscoveryDocument, UserInfo } from '../types/oidc.js';
import type { TokenManager } from '../token/manager.js';
import { TokenApiClient, type SessionCheckResult } from './token-api.js';
export type { SessionCheckResult };
import { AuthrimError } from '../types/errors.js';

/**
 * Session manager options
 */
export interface SessionManagerOptions {
  /** Token manager */
  tokenManager: TokenManager;
  /** Token API client */
  tokenApiClient: TokenApiClient;
}

/**
 * Session Manager
 */
export class SessionManager {
  private readonly tokenManager: TokenManager;
  private readonly tokenApiClient: TokenApiClient;

  /** Discovery document */
  private discovery: OIDCDiscoveryDocument | null = null;

  constructor(options: SessionManagerOptions) {
    this.tokenManager = options.tokenManager;
    this.tokenApiClient = options.tokenApiClient;
  }

  /**
   * Set discovery document
   */
  setDiscovery(discovery: OIDCDiscoveryDocument): void {
    this.discovery = discovery;
  }

  /**
   * Check if user is authenticated locally
   *
   * This checks if valid tokens exist in storage.
   * Does not verify with the authorization server.
   *
   * @returns True if tokens exist
   */
  async isAuthenticated(): Promise<boolean> {
    return this.tokenManager.isAuthenticated();
  }

  /**
   * Check session validity with authorization server
   *
   * Calls the UserInfo endpoint to verify the session is still valid.
   *
   * @returns Session check result
   */
  async checkSession(): Promise<SessionCheckResult> {
    if (!this.discovery) {
      return {
        valid: false,
        error: new AuthrimError('no_discovery', 'Discovery document not available'),
      };
    }

    try {
      const accessToken = await this.tokenManager.getAccessToken();
      return this.tokenApiClient.checkSession(this.discovery, accessToken);
    } catch (error) {
      if (error instanceof AuthrimError) {
        return { valid: false, error };
      }
      return {
        valid: false,
        error: new AuthrimError('session_check_failed', 'Failed to check session', {
          cause: error instanceof Error ? error : undefined,
        }),
      };
    }
  }

  /**
   * Get user information
   *
   * Fetches user info from the UserInfo endpoint.
   *
   * @returns User info
   * @throws AuthrimError if not authenticated or request fails
   */
  async getUser(): Promise<UserInfo> {
    if (!this.discovery) {
      throw new AuthrimError('no_discovery', 'Discovery document not available');
    }

    const accessToken = await this.tokenManager.getAccessToken();
    return this.tokenApiClient.getUserInfo(this.discovery, accessToken);
  }
}
