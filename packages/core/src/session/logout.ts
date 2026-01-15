/**
 * Logout Handler
 *
 * Implements RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0)
 * https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 */

import type { AuthrimStorage } from '../providers/storage.js';
import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import type { EventEmitter } from '../events/emitter.js';
import type { EndpointOverrides } from '../client/config.js';
import { STORAGE_KEYS } from '../auth/state.js';

/**
 * Logout options
 */
export interface LogoutOptions {
  /** URI to redirect to after logout */
  postLogoutRedirectUri?: string;
  /** ID token hint (optional, uses stored ID token if not provided) */
  idTokenHint?: string;
  /** State parameter for post-logout redirect */
  state?: string;
}

/**
 * Logout result
 */
export interface LogoutResult {
  /** Logout URL to redirect to (if IdP supports end_session_endpoint) */
  logoutUrl?: string;
  /** True if only local logout was performed (IdP doesn't support RP-Initiated Logout) */
  localOnly: boolean;
}

/**
 * Logout handler options
 */
export interface LogoutHandlerOptions {
  /** Storage provider */
  storage: AuthrimStorage;
  /** Client ID */
  clientId: string;
  /** Issuer hash for storage keys */
  issuerHash: string;
  /** Client ID hash for storage keys */
  clientIdHash: string;
  /** Event emitter */
  eventEmitter?: EventEmitter;
  /** Endpoint overrides */
  endpoints?: EndpointOverrides;
}

/**
 * Logout Handler
 */
export class LogoutHandler {
  private readonly storage: AuthrimStorage;
  private readonly clientId: string;
  private readonly issuerHash: string;
  private readonly clientIdHash: string;
  private readonly eventEmitter?: EventEmitter;
  private readonly endpoints?: EndpointOverrides;

  constructor(options: LogoutHandlerOptions) {
    this.storage = options.storage;
    this.clientId = options.clientId;
    this.issuerHash = options.issuerHash;
    this.clientIdHash = options.clientIdHash;
    this.eventEmitter = options.eventEmitter;
    this.endpoints = options.endpoints;
  }

  /**
   * Perform logout
   *
   * 1. Clears local tokens (always)
   * 2. Emits session:ended event
   * 3. Builds logout URL if IdP supports end_session_endpoint
   *
   * @param discovery - OIDC discovery document
   * @param options - Logout options
   * @returns Logout result
   */
  async logout(
    discovery: OIDCDiscoveryDocument | null,
    options?: LogoutOptions
  ): Promise<LogoutResult> {
    // Get stored ID token BEFORE clearing tokens (for logout URL)
    const storedIdToken = await this.getStoredIdToken();

    // Clear local tokens
    await this.clearTokens();

    // Emit session ended event
    this.eventEmitter?.emit('session:ended', { reason: 'logout' });

    // Determine end_session_endpoint
    // Priority: config override > discovery > null
    let endSessionEndpoint: string | null | undefined;

    if (this.endpoints?.endSession !== undefined) {
      // Explicit override (can be null to disable)
      endSessionEndpoint = this.endpoints.endSession;
    } else if (discovery) {
      endSessionEndpoint = discovery.end_session_endpoint;
    }

    // If no end_session_endpoint, return local-only logout
    if (!endSessionEndpoint) {
      return { localOnly: true };
    }

    // Build logout URL (use stored token if not provided in options)
    const idToken = options?.idTokenHint ?? storedIdToken;

    const params = new URLSearchParams({
      client_id: this.clientId,
    });

    if (idToken) {
      params.set('id_token_hint', idToken);
    }
    if (options?.postLogoutRedirectUri) {
      params.set('post_logout_redirect_uri', options.postLogoutRedirectUri);
    }
    if (options?.state) {
      params.set('state', options.state);
    }

    return {
      logoutUrl: `${endSessionEndpoint}?${params.toString()}`,
      localOnly: false,
    };
  }

  /**
   * Clear all tokens from storage
   */
  private async clearTokens(): Promise<void> {
    const tokenKey = STORAGE_KEYS.tokens(this.issuerHash, this.clientIdHash);
    const idTokenKey = STORAGE_KEYS.idToken(this.issuerHash, this.clientIdHash);

    await this.storage.remove(tokenKey);
    await this.storage.remove(idTokenKey);
  }

  /**
   * Get stored ID token
   */
  private async getStoredIdToken(): Promise<string | null> {
    const idTokenKey = STORAGE_KEYS.idToken(this.issuerHash, this.clientIdHash);
    return this.storage.get(idTokenKey);
  }
}
