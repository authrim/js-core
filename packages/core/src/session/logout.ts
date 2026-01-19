/**
 * Logout Handler
 *
 * Implements RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0)
 * https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 */

import type { AuthrimStorage } from '../providers/storage.js';
import type { HttpClient } from '../providers/http.js';
import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import type { TokenSet } from '../types/token.js';
import type { EventEmitter } from '../events/emitter.js';
import type { EndpointOverrides } from '../client/config.js';
import { STORAGE_KEYS } from '../auth/state.js';
import { TokenRevoker } from '../token/revocation.js';

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
  /** Whether to revoke tokens before logout (requires revocation_endpoint) */
  revokeTokens?: boolean;
}

/**
 * Logout result
 */
export interface LogoutResult {
  /** Logout URL to redirect to (if IdP supports end_session_endpoint) */
  logoutUrl?: string;
  /** True if only local logout was performed (IdP doesn't support RP-Initiated Logout) */
  localOnly: boolean;
  /** Token revocation result (if revokeTokens was true) */
  revocation?: {
    /** Whether revocation was attempted */
    attempted: boolean;
    /** Whether access token revocation succeeded */
    accessTokenRevoked?: boolean;
    /** Whether refresh token revocation succeeded */
    refreshTokenRevoked?: boolean;
    /** Error if revocation failed (logout still proceeds) */
    error?: Error;
  };
}

/**
 * Logout handler options
 */
export interface LogoutHandlerOptions {
  /** Storage provider */
  storage: AuthrimStorage;
  /** HTTP client (for token revocation) */
  http: HttpClient;
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
  private readonly tokenRevoker: TokenRevoker;

  constructor(options: LogoutHandlerOptions) {
    this.storage = options.storage;
    this.clientId = options.clientId;
    this.issuerHash = options.issuerHash;
    this.clientIdHash = options.clientIdHash;
    this.eventEmitter = options.eventEmitter;
    this.endpoints = options.endpoints;
    this.tokenRevoker = new TokenRevoker({
      http: options.http,
      clientId: options.clientId,
    });
  }

  /**
   * Perform logout
   *
   * 1. Optionally revokes tokens at the authorization server (if revokeTokens=true)
   * 2. Clears local tokens (always)
   * 3. Emits session:ended event
   * 4. Builds logout URL if IdP supports end_session_endpoint
   *
   * @param discovery - OIDC discovery document
   * @param options - Logout options
   * @returns Logout result
   */
  async logout(
    discovery: OIDCDiscoveryDocument | null,
    options?: LogoutOptions
  ): Promise<LogoutResult> {
    // Get stored tokens BEFORE clearing (for revocation and logout URL)
    const storedIdToken = await this.getStoredIdToken();
    const storedTokens = await this.getStoredTokens();

    // Revoke tokens if requested
    let revocationResult: LogoutResult['revocation'];
    if (options?.revokeTokens && discovery?.revocation_endpoint && storedTokens) {
      revocationResult = await this.revokeTokens(discovery, storedTokens);
    }

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
      return { localOnly: true, revocation: revocationResult };
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
      revocation: revocationResult,
    };
  }

  /**
   * Revoke tokens at the authorization server
   *
   * Best-effort: if revocation fails, logout still proceeds
   *
   * @param discovery - OIDC discovery document
   * @param tokens - Tokens to revoke
   * @returns Revocation result
   */
  private async revokeTokens(
    discovery: OIDCDiscoveryDocument,
    tokens: TokenSet
  ): Promise<NonNullable<LogoutResult['revocation']>> {
    const result: NonNullable<LogoutResult['revocation']> = {
      attempted: true,
    };

    try {
      // Revoke refresh token first (if present) - this often invalidates access token too
      if (tokens.refreshToken) {
        await this.tokenRevoker.revoke(discovery, {
          token: tokens.refreshToken,
          tokenTypeHint: 'refresh_token',
        });
        result.refreshTokenRevoked = true;
      }

      // Revoke access token
      await this.tokenRevoker.revoke(discovery, {
        token: tokens.accessToken,
        tokenTypeHint: 'access_token',
      });
      result.accessTokenRevoked = true;
    } catch (error) {
      result.error = error instanceof Error ? error : new Error(String(error));
    }

    return result;
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

  /**
   * Get stored tokens
   */
  private async getStoredTokens(): Promise<TokenSet | null> {
    const tokenKey = STORAGE_KEYS.tokens(this.issuerHash, this.clientIdHash);
    const stored = await this.storage.get(tokenKey);
    if (!stored) {
      return null;
    }
    try {
      return JSON.parse(stored) as TokenSet;
    } catch {
      return null;
    }
  }
}
