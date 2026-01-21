/**
 * Token Manager
 *
 * Manages token storage, retrieval, and automatic refresh.
 * Implements in-flight request coalescing for concurrent refresh requests.
 */

import type { HttpClient } from '../providers/http.js';
import type { AuthrimStorage } from '../providers/storage.js';
import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import type {
  TokenSet,
  TokenResponse,
  TokenExchangeRequest,
  TokenExchangeResponse,
  TokenExchangeResult,
} from '../types/token.js';
import { TOKEN_TYPE_URIS } from '../types/token.js';
import type { EventEmitter } from '../events/emitter.js';
import { AuthrimError, isRetryableError, emitClassifiedError } from '../types/errors.js';
import { STORAGE_KEYS } from '../auth/state.js';

/**
 * Token manager options
 */
export interface TokenManagerOptions {
  /** HTTP client */
  http: HttpClient;
  /** Storage provider */
  storage: AuthrimStorage;
  /** Client ID */
  clientId: string;
  /** Issuer hash for storage keys */
  issuerHash: string;
  /** Client ID hash for storage keys */
  clientIdHash: string;
  /** Refresh skew in seconds (default: 30) */
  refreshSkewSeconds?: number;
  /** Event emitter for token events */
  eventEmitter?: EventEmitter;
  /** Token expiring warning threshold in seconds (default: 300 = 5 minutes) */
  expiringThresholdSeconds?: number;
  /** Jitter for expiring event in milliseconds (default: 30000 = ±30 seconds) */
  expiringJitterMs?: number;
}

/**
 * Token Manager
 *
 * Handles token storage, retrieval, and automatic refresh with
 * concurrent request coalescing.
 */
export class TokenManager {
  private readonly http: HttpClient;
  private readonly storage: AuthrimStorage;
  private readonly clientId: string;
  private readonly issuerHash: string;
  private readonly clientIdHash: string;
  private readonly refreshSkewSeconds: number;
  private readonly eventEmitter?: EventEmitter;
  private readonly expiringThresholdMs: number;
  private readonly expiringJitterMs: number;

  /** In-flight refresh promise for request coalescing */
  private refreshPromise: Promise<TokenSet> | null = null;

  /** Discovery document (set externally) */
  private discovery: OIDCDiscoveryDocument | null = null;

  /** Timer for token expiring event */
  private expiringTimeout: ReturnType<typeof setTimeout> | null = null;

  /** Whether this tab is the leader for refresh scheduling */
  private isLeaderTab = true;

  /** Current operation ID for event tracking */
  private currentOperationId: string | null = null;

  /** Default refresh skew: 30 seconds */
  private static readonly DEFAULT_REFRESH_SKEW_SECONDS = 30;

  /** Default expiring threshold: 5 minutes */
  private static readonly DEFAULT_EXPIRING_THRESHOLD_SECONDS = 300;

  /** Default expiring jitter: ±30 seconds */
  private static readonly DEFAULT_EXPIRING_JITTER_MS = 30000;

  constructor(options: TokenManagerOptions) {
    this.http = options.http;
    this.storage = options.storage;
    this.clientId = options.clientId;
    this.issuerHash = options.issuerHash;
    this.clientIdHash = options.clientIdHash;
    this.refreshSkewSeconds =
      options.refreshSkewSeconds ?? TokenManager.DEFAULT_REFRESH_SKEW_SECONDS;
    this.eventEmitter = options.eventEmitter;
    this.expiringThresholdMs =
      (options.expiringThresholdSeconds ?? TokenManager.DEFAULT_EXPIRING_THRESHOLD_SECONDS) * 1000;
    this.expiringJitterMs = options.expiringJitterMs ?? TokenManager.DEFAULT_EXPIRING_JITTER_MS;
  }

  /**
   * Set discovery document
   */
  setDiscovery(discovery: OIDCDiscoveryDocument): void {
    this.discovery = discovery;
  }

  /**
   * Get storage key for tokens
   */
  private get tokenKey(): string {
    return STORAGE_KEYS.tokens(this.issuerHash, this.clientIdHash);
  }

  /**
   * Get storage key for ID token
   */
  private get idTokenKey(): string {
    return STORAGE_KEYS.idToken(this.issuerHash, this.clientIdHash);
  }

  /**
   * Get current tokens from storage
   *
   * @returns Token set or null if not found
   */
  async getTokens(): Promise<TokenSet | null> {
    const stored = await this.storage.get(this.tokenKey);
    if (!stored) {
      return null;
    }

    try {
      return JSON.parse(stored) as TokenSet;
    } catch {
      // Corrupted data - clear and return null
      await this.clearTokens();
      return null;
    }
  }

  /**
   * Save tokens to storage
   *
   * @param tokens - Token set to save
   */
  async saveTokens(tokens: TokenSet): Promise<void> {
    await this.storage.set(this.tokenKey, JSON.stringify(tokens));

    // Also save ID token separately for logout
    if (tokens.idToken) {
      await this.storage.set(this.idTokenKey, tokens.idToken);
    }

    // Schedule expiring event
    this.scheduleExpiringEvent(tokens.expiresAt);
  }

  /**
   * Schedule token:expiring event with jitter
   *
   * @param expiresAt - Token expiration timestamp (epoch seconds)
   */
  private scheduleExpiringEvent(expiresAt: number): void {
    // Clear existing timeout
    if (this.expiringTimeout) {
      clearTimeout(this.expiringTimeout);
      this.expiringTimeout = null;
    }

    // Only schedule if we're the leader tab
    if (!this.isLeaderTab) {
      return;
    }

    const expiresAtMs = expiresAt * 1000;
    const warningTime = expiresAtMs - this.expiringThresholdMs;

    // Add jitter: random value between -jitter and +jitter
    const jitter = Math.random() * this.expiringJitterMs * 2 - this.expiringJitterMs;
    const delay = warningTime - Date.now() + jitter;

    // Only schedule if the warning time is in the future
    if (delay > 0) {
      this.expiringTimeout = setTimeout(() => {
        const now = Date.now();
        const expiresIn = Math.max(0, Math.floor((expiresAtMs - now) / 1000));

        this.eventEmitter?.emit('token:expiring', {
          expiresAt,
          expiresIn,
          timestamp: now,
          source: 'core',
        });
      }, delay);
    }
  }

  /**
   * Set leader tab status
   *
   * When not the leader, expiring event scheduling is disabled
   * to prevent multiple tabs from triggering simultaneous refreshes.
   *
   * @param isLeader - Whether this tab is the leader
   */
  setLeaderTab(isLeader: boolean): void {
    this.isLeaderTab = isLeader;

    if (!isLeader && this.expiringTimeout) {
      clearTimeout(this.expiringTimeout);
      this.expiringTimeout = null;
    }
  }

  /**
   * Set current operation ID for event tracking
   */
  setOperationId(operationId: string | null): void {
    this.currentOperationId = operationId;
  }

  /**
   * Get current operation ID
   */
  getOperationId(): string | null {
    return this.currentOperationId;
  }

  /**
   * Clear all tokens from storage
   */
  async clearTokens(): Promise<void> {
    await this.storage.remove(this.tokenKey);
    await this.storage.remove(this.idTokenKey);
  }

  /**
   * Get access token, refreshing if necessary
   *
   * This method coalesces concurrent refresh requests - if multiple
   * calls are made while a refresh is in-flight, they all share the
   * same refresh operation.
   *
   * @returns Access token
   * @throws AuthrimError if no tokens available or refresh fails
   */
  async getAccessToken(): Promise<string> {
    const tokens = await this.getTokens();

    if (!tokens) {
      throw new AuthrimError('no_tokens', 'No tokens available. Please authenticate first.');
    }

    // Check if token needs refresh (with skew)
    if (this.shouldRefresh(tokens)) {
      if (!tokens.refreshToken) {
        throw new AuthrimError(
          'token_expired',
          'Access token expired and no refresh token available'
        );
      }
      return this.refreshWithLock(tokens.refreshToken);
    }

    return tokens.accessToken;
  }

  /**
   * Get ID token
   *
   * @returns ID token or null
   */
  async getIdToken(): Promise<string | null> {
    const tokens = await this.getTokens();
    return tokens?.idToken ?? null;
  }

  /**
   * Check if token needs refresh
   *
   * @param tokens - Token set to check
   * @returns True if token should be refreshed
   */
  private shouldRefresh(tokens: TokenSet): boolean {
    const now = Math.floor(Date.now() / 1000);
    return tokens.expiresAt - this.refreshSkewSeconds <= now;
  }

  /**
   * Refresh token with in-flight request coalescing
   *
   * If a refresh is already in progress, wait for it instead of
   * starting a new one.
   *
   * @param refreshToken - Refresh token to use
   * @param reason - Reason for refresh
   * @returns Access token from new token set
   */
  private async refreshWithLock(
    refreshToken: string,
    reason: 'expiring' | 'manual' | 'on_demand' | 'background' = 'on_demand'
  ): Promise<string> {
    // If refresh is already in-flight, wait for it
    if (this.refreshPromise) {
      const tokens = await this.refreshPromise;
      return tokens.accessToken;
    }

    // Start new refresh operation
    this.refreshPromise = this.doRefreshWithRetry(refreshToken, reason);

    try {
      const tokens = await this.refreshPromise;
      return tokens.accessToken;
    } finally {
      // ALWAYS clear promise (success or failure)
      this.refreshPromise = null;
    }
  }

  /**
   * Manually refresh tokens
   *
   * @returns New token set
   * @throws AuthrimError if refresh fails
   */
  async refresh(): Promise<TokenSet> {
    const tokens = await this.getTokens();
    if (!tokens?.refreshToken) {
      throw new AuthrimError('no_tokens', 'No refresh token available');
    }

    // Start new refresh with manual reason
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = this.doRefreshWithRetry(tokens.refreshToken, 'manual');

    try {
      return await this.refreshPromise;
    } finally {
      this.refreshPromise = null;
    }
  }

  /**
   * Perform refresh with retry for network errors
   *
   * @param refreshToken - Refresh token to use
   * @param reason - Reason for refresh
   * @param attempt - Current retry attempt (0-indexed)
   * @returns New token set
   */
  private async doRefreshWithRetry(
    refreshToken: string,
    reason: 'expiring' | 'manual' | 'on_demand' | 'background' = 'on_demand',
    attempt = 0
  ): Promise<TokenSet> {
    const maxRetries = 1;
    const timestamp = Date.now();

    // Emit refreshing event on first attempt
    if (attempt === 0) {
      this.eventEmitter?.emit('token:refreshing', {
        reason,
        timestamp,
        source: 'core',
        operationId: this.currentOperationId ?? undefined,
      });
    }

    try {
      return await this.doRefresh(refreshToken);
    } catch (error) {
      const authrimError = error instanceof AuthrimError
        ? error
        : new AuthrimError('refresh_error', 'Token refresh failed', {
            cause: error instanceof Error ? error : undefined,
          });

      const willRetry = attempt < maxRetries && isRetryableError(authrimError);

      // Emit refresh failed event
      this.eventEmitter?.emit('token:refresh:failed', {
        error: authrimError,
        willRetry,
        attempt,
        timestamp: Date.now(),
        source: 'core',
        operationId: this.currentOperationId ?? undefined,
      });

      // Retry once for retryable errors
      if (willRetry) {
        return this.doRefreshWithRetry(refreshToken, reason, attempt + 1);
      }

      // Emit auth:required if refresh failed and not retryable
      if (!isRetryableError(authrimError)) {
        this.eventEmitter?.emit('auth:required', {
          reason: 'refresh_failed',
          timestamp: Date.now(),
          source: 'core',
          operationId: this.currentOperationId ?? undefined,
        });
      }

      throw error;
    }
  }

  /**
   * Perform the actual token refresh
   *
   * @param refreshToken - Refresh token to use
   * @returns New token set
   */
  private async doRefresh(refreshToken: string): Promise<TokenSet> {
    if (!this.discovery) {
      throw new AuthrimError('no_discovery', 'Discovery document not set');
    }

    const tokenEndpoint = this.discovery.token_endpoint;

    // Build refresh request
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.clientId,
      refresh_token: refreshToken,
    });

    let response;
    try {
      response = await this.http.fetch<TokenResponse>(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
      });
    } catch (error) {
      const authrimError = new AuthrimError('network_error', 'Token refresh request failed', {
        cause: error instanceof Error ? error : undefined,
      });
      this.eventEmitter?.emit('token:error', {
        error: authrimError,
        context: 'refresh',
        timestamp: Date.now(),
        source: 'core',
      });
      // Also emit classified error events (error:recoverable or error:fatal)
      if (this.eventEmitter) {
        emitClassifiedError(this.eventEmitter, authrimError, { context: 'refresh' });
      }
      throw authrimError;
    }

    if (!response.ok) {
      const errorData = response.data as unknown as Record<string, unknown>;
      const authrimError = new AuthrimError('refresh_error', 'Token refresh failed', {
        details: {
          status: response.status,
          error: errorData?.error,
          error_description: errorData?.error_description,
        },
      });
      this.eventEmitter?.emit('token:error', {
        error: authrimError,
        context: 'refresh',
        timestamp: Date.now(),
        source: 'core',
      });
      // Also emit classified error events (error:recoverable or error:fatal)
      if (this.eventEmitter) {
        emitClassifiedError(this.eventEmitter, authrimError, { context: 'refresh' });
      }
      throw authrimError;
    }

    const tokenResponse = response.data;

    // Calculate expiresAt
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = tokenResponse.expires_in ? now + tokenResponse.expires_in : now + 3600;

    // Build new token set (preserve old refresh token if new one not provided)
    const newTokens: TokenSet = {
      accessToken: tokenResponse.access_token,
      tokenType: (tokenResponse.token_type as 'Bearer') ?? 'Bearer',
      expiresAt,
      refreshToken: tokenResponse.refresh_token ?? refreshToken,
      idToken: tokenResponse.id_token,
      scope: tokenResponse.scope,
    };

    // Save new tokens
    await this.saveTokens(newTokens);

    // Emit event with new format (no token values for security)
    this.eventEmitter?.emit('token:refreshed', {
      hasAccessToken: !!newTokens.accessToken,
      hasRefreshToken: !!newTokens.refreshToken,
      hasIdToken: !!newTokens.idToken,
      expiresAt: newTokens.expiresAt,
      timestamp: Date.now(),
      source: 'core',
      operationId: this.currentOperationId ?? undefined,
    });

    return newTokens;
  }

  /**
   * Check if user is authenticated
   *
   * @returns True if valid tokens exist
   */
  async isAuthenticated(): Promise<boolean> {
    const tokens = await this.getTokens();
    if (!tokens) {
      return false;
    }

    // Check if access token is expired (without skew)
    const now = Math.floor(Date.now() / 1000);
    if (tokens.expiresAt <= now) {
      // Token expired - check if we have refresh token
      return !!tokens.refreshToken;
    }

    return true;
  }

  /**
   * Exchange a token using RFC 8693 Token Exchange
   *
   * This allows exchanging tokens for different audiences or scopes,
   * delegation scenarios, and cross-service token acquisition.
   *
   * @param request - Token exchange request parameters
   * @returns Token exchange result with new tokens and issued token type
   * @throws AuthrimError if exchange fails
   */
  async exchangeToken(request: TokenExchangeRequest): Promise<TokenExchangeResult> {
    if (!this.discovery) {
      throw new AuthrimError('no_discovery', 'Discovery document not set');
    }

    const tokenEndpoint = this.discovery.token_endpoint;

    // Map short token type names to URIs
    const subjectTokenType = this.mapTokenTypeToUri(request.subjectTokenType ?? 'access_token');

    // Build token exchange request
    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: this.clientId,
      subject_token: request.subjectToken,
      subject_token_type: subjectTokenType,
    });

    // Optional parameters
    if (request.audience) {
      body.set('audience', request.audience);
    }
    if (request.scope) {
      body.set('scope', request.scope);
    }
    if (request.requestedTokenType) {
      body.set('requested_token_type', this.mapTokenTypeToUri(request.requestedTokenType));
    }
    if (request.actorToken) {
      body.set('actor_token', request.actorToken);
      if (request.actorTokenType) {
        body.set('actor_token_type', this.mapTokenTypeToUri(request.actorTokenType));
      }
    }

    let response;
    try {
      response = await this.http.fetch<TokenExchangeResponse>(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
      });
    } catch (error) {
      const authrimError = new AuthrimError('network_error', 'Token exchange request failed', {
        cause: error instanceof Error ? error : undefined,
      });
      this.eventEmitter?.emit('token:error', {
        error: authrimError,
        context: 'exchange',
        timestamp: Date.now(),
        source: 'core',
      });
      // Also emit classified error events (error:recoverable or error:fatal)
      if (this.eventEmitter) {
        emitClassifiedError(this.eventEmitter, authrimError, { context: 'exchange' });
      }
      throw authrimError;
    }

    if (!response.ok) {
      const errorData = response.data as unknown as Record<string, unknown>;
      const authrimError = new AuthrimError('token_exchange_error', 'Token exchange failed', {
        details: {
          status: response.status,
          error: errorData?.error,
          error_description: errorData?.error_description,
        },
      });
      this.eventEmitter?.emit('token:error', {
        error: authrimError,
        context: 'exchange',
        timestamp: Date.now(),
        source: 'core',
      });
      // Also emit classified error events (error:recoverable or error:fatal)
      if (this.eventEmitter) {
        emitClassifiedError(this.eventEmitter, authrimError, { context: 'exchange' });
      }
      throw authrimError;
    }

    const tokenResponse = response.data;

    // Calculate expiresAt
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = tokenResponse.expires_in ? now + tokenResponse.expires_in : now + 3600;

    const tokens: TokenSet = {
      accessToken: tokenResponse.access_token,
      tokenType: (tokenResponse.token_type as 'Bearer') ?? 'Bearer',
      expiresAt,
      refreshToken: tokenResponse.refresh_token,
      idToken: tokenResponse.id_token,
      scope: tokenResponse.scope,
    };

    const result: TokenExchangeResult = {
      tokens,
      issuedTokenType: tokenResponse.issued_token_type,
    };

    // Emit event with new format (no token values for security)
    this.eventEmitter?.emit('token:exchanged', {
      hasAccessToken: !!tokens.accessToken,
      hasRefreshToken: !!tokens.refreshToken,
      issuedTokenType: tokenResponse.issued_token_type,
      timestamp: Date.now(),
      source: 'core',
      operationId: this.currentOperationId ?? undefined,
    });

    return result;
  }

  /**
   * Map short token type to URI (RFC 8693)
   */
  private mapTokenTypeToUri(type: 'access_token' | 'refresh_token' | 'id_token'): string {
    return TOKEN_TYPE_URIS[type];
  }

  /**
   * Clean up resources
   */
  destroy(): void {
    if (this.expiringTimeout) {
      clearTimeout(this.expiringTimeout);
      this.expiringTimeout = null;
    }
  }
}
