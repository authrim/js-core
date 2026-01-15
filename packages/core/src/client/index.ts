/**
 * Authrim Client
 *
 * Main entry point for the Authrim SDK.
 */

import type { AuthrimClientConfig, ResolvedConfig } from './config.js';
import type { OIDCDiscoveryDocument, UserInfo } from '../types/oidc.js';
import type { TokenSet, TokenExchangeRequest, TokenExchangeResult } from '../types/token.js';
import type { AuthrimEventName, AuthrimEventHandler } from '../events/types.js';
import { resolveConfig } from './config.js';
import { DiscoveryClient, normalizeIssuer } from './discovery.js';
import { EventEmitter } from '../events/emitter.js';
import { PKCEHelper } from '../auth/pkce.js';
import { StateManager } from '../auth/state.js';
import {
  AuthorizationCodeFlow,
  type BuildAuthorizationUrlOptions,
  type AuthorizationUrlResult,
} from '../auth/authorization-code.js';
import { TokenManager } from '../token/manager.js';
import { LogoutHandler, type LogoutOptions, type LogoutResult } from '../session/logout.js';
import { TokenApiClient } from '../session/token-api.js';
import { SessionManager } from '../session/manager.js';
import { base64urlEncode } from '../utils/base64url.js';
import { AuthrimError } from '../types/errors.js';

/**
 * Hash a value for use in storage keys
 *
 * @param crypto - Crypto provider
 * @param value - Value to hash
 * @param length - Hash length (default: 16 = 96 bits)
 * @returns Base64url-encoded hash
 */
async function hashForKey(
  crypto: AuthrimClientConfig['crypto'],
  value: string,
  length = 16
): Promise<string> {
  const hash = await crypto.sha256(value);
  return base64urlEncode(hash).slice(0, length);
}

/**
 * Authrim Client
 */
export class AuthrimClient {
  /** Resolved configuration */
  private readonly config: ResolvedConfig;

  /** Event emitter */
  private readonly events: EventEmitter;

  /** Discovery client */
  private readonly discoveryClient: DiscoveryClient;

  /** PKCE helper */
  private readonly pkce: PKCEHelper;

  /** State manager (initialized in initialize()) */
  private stateManager!: StateManager;

  /** Authorization code flow helper */
  private readonly authCodeFlow: AuthorizationCodeFlow;

  /** Token manager (initialized in initialize()) */
  private tokenManager!: TokenManager;

  /** Logout handler (initialized in initialize()) */
  private logoutHandler!: LogoutHandler;

  /** Session manager (initialized in initialize()) */
  private sessionManager!: SessionManager;

  /** Issuer hash for storage keys */
  private issuerHash!: string;

  /** Client ID hash for storage keys */
  private clientIdHash!: string;

  /** Normalized issuer URL */
  private readonly normalizedIssuer: string;

  /** Whether the client has been initialized */
  private initialized = false;

  /**
   * Create a new Authrim client
   *
   * @internal Use createAuthrimClient() instead
   */
  constructor(config: AuthrimClientConfig) {
    this.config = resolveConfig(config);
    this.normalizedIssuer = normalizeIssuer(config.issuer);

    // Initialize components that don't need hashes
    this.events = new EventEmitter();

    this.discoveryClient = new DiscoveryClient({
      http: this.config.http,
      cacheTtlMs: this.config.discoveryCacheTtlMs,
    });

    this.pkce = new PKCEHelper(this.config.crypto);

    this.authCodeFlow = new AuthorizationCodeFlow(this.config.http, this.config.clientId);
  }

  /**
   * Initialize the client
   *
   * @internal Called by createAuthrimClient()
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    // Calculate hashes for storage keys
    const hashLength = this.config.hashOptions.hashLength;
    this.issuerHash = await hashForKey(this.config.crypto, this.normalizedIssuer, hashLength);
    this.clientIdHash = await hashForKey(this.config.crypto, this.config.clientId, hashLength);

    // Initialize state manager
    this.stateManager = new StateManager(
      this.config.crypto,
      this.config.storage,
      this.issuerHash,
      this.clientIdHash
    );

    // Initialize token manager
    this.tokenManager = new TokenManager({
      http: this.config.http,
      storage: this.config.storage,
      clientId: this.config.clientId,
      issuerHash: this.issuerHash,
      clientIdHash: this.clientIdHash,
      refreshSkewSeconds: this.config.refreshSkewSeconds,
      eventEmitter: this.events,
    });

    // Initialize logout handler
    this.logoutHandler = new LogoutHandler({
      storage: this.config.storage,
      clientId: this.config.clientId,
      issuerHash: this.issuerHash,
      clientIdHash: this.clientIdHash,
      eventEmitter: this.events,
      endpoints: this.config.endpoints,
    });

    // Initialize token API client
    const tokenApiClient = new TokenApiClient({
      http: this.config.http,
    });

    // Initialize session manager
    this.sessionManager = new SessionManager({
      tokenManager: this.tokenManager,
      tokenApiClient,
    });

    // Clean up expired states (best-effort)
    await this.stateManager.cleanupExpiredStates();

    this.initialized = true;
  }

  /**
   * Ensure client is initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new AuthrimError(
        'not_initialized',
        'Client not initialized. Use createAuthrimClient().'
      );
    }
  }

  /**
   * Get OIDC discovery document
   *
   * @returns Discovery document
   */
  async discover(): Promise<OIDCDiscoveryDocument> {
    const discovery = await this.discoveryClient.discover(this.normalizedIssuer);

    // Update dependent components
    this.tokenManager.setDiscovery(discovery);
    this.sessionManager.setDiscovery(discovery);

    return discovery;
  }

  // ============================================================
  // Authorization Code Flow
  // ============================================================

  /**
   * Build authorization URL
   *
   * Generates the URL to redirect the user to for authentication.
   * Stores state, nonce, and code_verifier in storage.
   *
   * @param options - Authorization options
   * @returns Authorization URL result
   */
  async buildAuthorizationUrl(
    options: BuildAuthorizationUrlOptions
  ): Promise<AuthorizationUrlResult> {
    this.ensureInitialized();

    const discovery = await this.discover();

    // Generate PKCE pair
    const pkcePair = await this.pkce.generatePKCE();

    // Generate auth state
    const authState = await this.stateManager.generateAuthState({
      redirectUri: options.redirectUri,
      codeVerifier: pkcePair.codeVerifier,
      ttlSeconds: this.config.stateTtlSeconds,
    });

    // Build URL
    const result = this.authCodeFlow.buildAuthorizationUrl(discovery, authState, pkcePair, options);

    // Emit event
    this.events.emit('auth:redirecting', { url: result.url });

    return result;
  }

  /**
   * Handle authorization callback
   *
   * Processes the callback URL, validates state/nonce, and exchanges
   * the authorization code for tokens.
   *
   * @param callbackUrl - Callback URL or query string
   * @returns Token set
   */
  async handleCallback(callbackUrl: string): Promise<TokenSet> {
    this.ensureInitialized();

    // Parse callback
    const { code, state } = this.authCodeFlow.parseCallback(callbackUrl);

    // Emit event
    this.events.emit('auth:callback', { code, state });

    // Validate and consume state (always deletes)
    const authState = await this.stateManager.validateAndConsumeState(state);

    // Get discovery
    const discovery = await this.discover();

    // Exchange code for tokens
    const tokens = await this.authCodeFlow.exchangeCode(discovery, {
      code,
      state,
      redirectUri: authState.redirectUri,
      codeVerifier: authState.codeVerifier,
      nonce: authState.nonce,
    });

    // Save tokens
    await this.tokenManager.saveTokens(tokens);

    return tokens;
  }

  // ============================================================
  // Token API
  // ============================================================

  /**
   * Token API accessor
   */
  get token() {
    this.ensureInitialized();
    return {
      /**
       * Get access token (refreshes if needed)
       */
      getAccessToken: () => this.tokenManager.getAccessToken(),

      /**
       * Get current tokens
       */
      getTokens: () => this.tokenManager.getTokens(),

      /**
       * Get ID token
       */
      getIdToken: () => this.tokenManager.getIdToken(),

      /**
       * Check if authenticated
       */
      isAuthenticated: () => this.tokenManager.isAuthenticated(),

      /**
       * Exchange token (RFC 8693)
       *
       * Exchanges a token for a new token with different audience, scope,
       * or delegation. Useful for:
       * - Cross-service token acquisition
       * - Delegation (actor token)
       * - Scope reduction
       *
       * @param request - Token exchange request parameters
       * @returns Token exchange result
       */
      exchange: async (request: TokenExchangeRequest): Promise<TokenExchangeResult> => {
        // Ensure discovery is loaded
        await this.discover();
        return this.tokenManager.exchangeToken(request);
      },
    };
  }

  // ============================================================
  // Session API
  // ============================================================

  /**
   * Session API accessor
   */
  get session() {
    this.ensureInitialized();
    return {
      /**
       * Check if authenticated locally
       */
      isAuthenticated: () => this.sessionManager.isAuthenticated(),

      /**
       * Check session with authorization server
       */
      check: () => this.sessionManager.checkSession(),
    };
  }

  /**
   * Check if user is authenticated
   *
   * @returns True if tokens exist
   */
  async isAuthenticated(): Promise<boolean> {
    this.ensureInitialized();
    return this.tokenManager.isAuthenticated();
  }

  /**
   * Get user information
   *
   * @returns User info
   */
  async getUser(): Promise<UserInfo> {
    this.ensureInitialized();
    return this.sessionManager.getUser();
  }

  // ============================================================
  // Logout
  // ============================================================

  /**
   * Log out the user
   *
   * Clears local tokens and optionally redirects to IdP for logout.
   *
   * @param options - Logout options
   * @returns Logout result
   */
  async logout(options?: LogoutOptions): Promise<LogoutResult> {
    this.ensureInitialized();

    let discovery: OIDCDiscoveryDocument | null = null;
    try {
      discovery = await this.discover();
    } catch {
      // Discovery failure is OK for logout - we can still do local logout
    }

    return this.logoutHandler.logout(discovery, options);
  }

  // ============================================================
  // Events
  // ============================================================

  /**
   * Subscribe to an event
   *
   * @param event - Event name
   * @param handler - Event handler
   * @returns Unsubscribe function
   */
  on<T extends AuthrimEventName>(event: T, handler: AuthrimEventHandler<T>): () => void {
    return this.events.on(event, handler);
  }

  /**
   * Subscribe to an event (one-time)
   *
   * @param event - Event name
   * @param handler - Event handler
   * @returns Unsubscribe function
   */
  once<T extends AuthrimEventName>(event: T, handler: AuthrimEventHandler<T>): () => void {
    return this.events.once(event, handler);
  }

  /**
   * Unsubscribe from an event
   *
   * @param event - Event name
   * @param handler - Event handler
   */
  off<T extends AuthrimEventName>(event: T, handler: AuthrimEventHandler<T>): void {
    this.events.off(event, handler);
  }
}

/**
 * Create an Authrim client
 *
 * This is the main entry point for creating a client.
 * The client is fully initialized when returned.
 *
 * @param config - Client configuration
 * @returns Initialized Authrim client
 */
export async function createAuthrimClient(config: AuthrimClientConfig): Promise<AuthrimClient> {
  const client = new AuthrimClient(config);
  await client.initialize();
  return client;
}
