/**
 * Authrim Client
 *
 * Main entry point for the Authrim SDK.
 */

import type { AuthrimClientConfig, ResolvedConfig } from './config.js';
import type { OIDCDiscoveryDocument, UserInfo } from '../types/oidc.js';
import type { TokenSet, TokenExchangeRequest, TokenExchangeResult } from '../types/token.js';
import type { AuthrimEventName, AuthrimEventHandler } from '../events/types.js';
import type { DeviceFlowState, DeviceFlowPollResult, DeviceFlowStartOptions } from '../types/device-flow.js';
import type { PARResult } from '../types/par.js';
import type { DPoPCryptoProvider } from '../types/dpop.js';
import type { CryptoProvider } from '../providers/crypto.js';
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
import { PARClient } from '../auth/par.js';
import { DeviceFlowClient } from '../auth/device-flow.js';
import { DPoPManager } from '../security/dpop.js';
import { TokenManager } from '../token/manager.js';
import {
  TokenIntrospector,
  type IntrospectionResponse,
  type IntrospectTokenOptions,
} from '../token/introspection.js';
import { TokenRevoker, type RevokeTokenOptions } from '../token/revocation.js';
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

  /** PAR client */
  private readonly parClient: PARClient;

  /** Device Flow client */
  private readonly deviceFlowClient: DeviceFlowClient;

  /** DPoP manager (lazily initialized) */
  private dpopManager: DPoPManager | null = null;

  /** Token manager (initialized in initialize()) */
  private tokenManager!: TokenManager;

  /** Logout handler (initialized in initialize()) */
  private logoutHandler!: LogoutHandler;

  /** Session manager (initialized in initialize()) */
  private sessionManager!: SessionManager;

  /** Token introspector */
  private tokenIntrospector!: TokenIntrospector;

  /** Token revoker */
  private tokenRevoker!: TokenRevoker;

  /** Issuer hash for storage keys */
  private issuerHash!: string;

  /** Client ID hash for storage keys */
  private clientIdHash!: string;

  /** Normalized issuer URL */
  private readonly normalizedIssuer: string;

  /** Whether the client has been initialized */
  private initialized = false;

  /**
   * Get the event emitter for subscribing to SDK events
   */
  get eventEmitter(): EventEmitter {
    return this.events;
  }

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

    this.parClient = new PARClient(this.config.http, this.config.clientId);

    this.deviceFlowClient = new DeviceFlowClient(this.config.http, this.config.clientId);
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
      http: this.config.http,
      clientId: this.config.clientId,
      issuerHash: this.issuerHash,
      clientIdHash: this.clientIdHash,
      eventEmitter: this.events,
      endpoints: this.config.endpoints,
    });

    // Initialize token introspector
    this.tokenIntrospector = new TokenIntrospector({
      http: this.config.http,
      clientId: this.config.clientId,
    });

    // Initialize token revoker
    this.tokenRevoker = new TokenRevoker({
      http: this.config.http,
      clientId: this.config.clientId,
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

    // Determine scope (default: 'openid profile')
    const scope = options.scope ?? 'openid profile';

    // Generate auth state (including scope for validation during callback)
    const authState = await this.stateManager.generateAuthState({
      redirectUri: options.redirectUri,
      codeVerifier: pkcePair.codeVerifier,
      scope,
      ttlSeconds: this.config.stateTtlSeconds,
    });

    // Build URL
    const result = this.authCodeFlow.buildAuthorizationUrl(discovery, authState, pkcePair, options);

    // Emit event with operationId for tracking
    this.events.emit('auth:redirecting', {
      url: result.url,
      timestamp: Date.now(),
      source: 'core',
      operationId: authState.operationId,
    });

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

    // Validate and consume state (always deletes) - do this first to get operationId
    const authState = await this.stateManager.validateAndConsumeState(state);
    const operationId = authState.operationId;

    // Emit callback received event with operationId
    this.events.emit('auth:callback', {
      code,
      state,
      timestamp: Date.now(),
      source: 'core',
      operationId,
    });

    // Emit callback processing event
    this.events.emit('auth:callback:processing', {
      state,
      timestamp: Date.now(),
      source: 'core',
      operationId,
    });

    try {
      // Get discovery
      const discovery = await this.discover();

      // Exchange code for tokens
      const tokens = await this.authCodeFlow.exchangeCode(discovery, {
        code,
        state,
        redirectUri: authState.redirectUri,
        codeVerifier: authState.codeVerifier,
        nonce: authState.nonce,
        scope: authState.scope,
      });

      // Save tokens
      await this.tokenManager.saveTokens(tokens);

      // Emit callback complete event
      this.events.emit('auth:callback:complete', {
        success: true,
        timestamp: Date.now(),
        source: 'core',
        operationId,
      });

      return tokens;
    } catch (error) {
      // Emit callback complete event with failure
      this.events.emit('auth:callback:complete', {
        success: false,
        timestamp: Date.now(),
        source: 'core',
        operationId,
      });
      throw error;
    }
  }

  // ============================================================
  // PAR API (Pushed Authorization Request - RFC 9126)
  // ============================================================

  /**
   * PAR API accessor
   *
   * Provides access to Pushed Authorization Request functionality.
   * PAR allows pushing authorization request parameters to a dedicated endpoint,
   * receiving a request_uri to use in the authorization URL.
   */
  get par() {
    return {
      /**
       * Push authorization request and get request_uri
       *
       * @param options - Authorization options
       * @returns PAR result with request_uri and expiration
       */
      push: async (options: BuildAuthorizationUrlOptions): Promise<PARResult> => {
        this.ensureInitialized();
        const discovery = await this.discover();

        // Generate PKCE and state
        const pkcePair = await this.pkce.generatePKCE();
        const scope = options.scope ?? 'openid profile';
        const authState = await this.stateManager.generateAuthState({
          redirectUri: options.redirectUri,
          codeVerifier: pkcePair.codeVerifier,
          scope,
          ttlSeconds: this.config.stateTtlSeconds,
        });

        // Push to PAR endpoint
        return this.parClient.pushAuthorizationRequest(discovery, {
          redirectUri: options.redirectUri,
          scope,
          state: authState.state,
          nonce: authState.nonce,
          codeChallenge: pkcePair.codeChallenge,
          codeChallengeMethod: 'S256',
          prompt: options.prompt,
          loginHint: options.loginHint,
          acrValues: options.acrValues,
          extraParams: options.extraParams,
        });
      },

      /**
       * Build authorization URL using request_uri from PAR
       *
       * @param requestUri - Request URI from PAR response
       * @returns Authorization URL
       */
      buildAuthorizationUrl: async (requestUri: string): Promise<string> => {
        const discovery = await this.discover();
        return this.parClient.buildAuthorizationUrlWithPar(discovery, requestUri);
      },

      /**
       * Check if PAR is available
       *
       * @returns True if PAR endpoint is available
       */
      isAvailable: async (): Promise<boolean> => {
        const discovery = await this.discover();
        return !!discovery.pushed_authorization_request_endpoint;
      },

      /**
       * Check if PAR is required by the server
       *
       * @returns True if server requires PAR
       */
      isRequired: async (): Promise<boolean> => {
        const discovery = await this.discover();
        return discovery.require_pushed_authorization_requests === true;
      },
    };
  }

  // ============================================================
  // Device Flow API (RFC 8628)
  // ============================================================

  /**
   * Device Flow API accessor
   *
   * Provides access to Device Authorization Grant functionality.
   * Used for devices with limited input capabilities (TVs, CLIs, IoT).
   */
  get deviceFlow() {
    return {
      /**
       * Start device authorization
       *
       * @param options - Start options (scope, etc.)
       * @returns Device flow state with codes and URIs
       */
      start: async (options?: DeviceFlowStartOptions): Promise<DeviceFlowState> => {
        this.ensureInitialized();
        const discovery = await this.discover();
        return this.deviceFlowClient.startDeviceAuthorization(discovery, options);
      },

      /**
       * Poll once for token
       *
       * @param state - Device flow state
       * @returns Poll result
       */
      pollOnce: async (state: DeviceFlowState): Promise<DeviceFlowPollResult> => {
        const discovery = await this.discover();
        return this.deviceFlowClient.pollOnce(discovery, state);
      },

      /**
       * Poll until complete or expired
       *
       * @param state - Device flow state
       * @param options - Polling options (signal for abort)
       * @returns Token set on success
       */
      pollUntilComplete: async (
        state: DeviceFlowState,
        options?: { signal?: AbortSignal }
      ): Promise<TokenSet> => {
        const discovery = await this.discover();
        const tokens = await this.deviceFlowClient.pollUntilComplete(discovery, state, options);

        // Save tokens
        await this.tokenManager.saveTokens(tokens);

        return tokens;
      },

      /**
       * Check if Device Flow is available
       *
       * @returns True if device authorization endpoint is available
       */
      isAvailable: async (): Promise<boolean> => {
        const discovery = await this.discover();
        return !!discovery.device_authorization_endpoint;
      },
    };
  }

  // ============================================================
  // DPoP API (RFC 9449)
  // ============================================================

  /**
   * DPoP API accessor
   *
   * Provides access to DPoP (Demonstrating Proof of Possession) functionality.
   * DPoP binds access tokens to a cryptographic key held by the client,
   * preventing token theft and replay attacks.
   *
   * NOTE: The CryptoProvider must implement DPoPCryptoProvider interface
   * for DPoP to be available.
   *
   * @returns DPoP API accessor, or undefined if not supported
   */
  get dpop() {
    // Check if crypto provider supports DPoP
    const cryptoWithDPoP = this.config.crypto as DPoPCryptoProvider;
    if (!cryptoWithDPoP.generateDPoPKeyPair) {
      return undefined;
    }

    // Lazily initialize DPoP manager
    if (!this.dpopManager) {
      // Cast to the combined type that DPoPManager expects
      this.dpopManager = new DPoPManager(
        this.config.crypto as CryptoProvider & DPoPCryptoProvider
      );
    }

    const manager = this.dpopManager;

    return {
      /**
       * Initialize DPoP (generates or retrieves key pair)
       */
      initialize: () => manager.initialize(),

      /**
       * Check if DPoP is initialized
       */
      isInitialized: () => manager.isInitialized(),

      /**
       * Generate a DPoP proof for a request
       *
       * @param method - HTTP method (GET, POST, etc.)
       * @param uri - Full request URI
       * @param options - Additional options (access token hash, nonce)
       * @returns Signed DPoP proof JWT
       */
      generateProof: (
        method: string,
        uri: string,
        options?: { accessTokenHash?: string; nonce?: string }
      ) => manager.generateProof(method, uri, options),

      /**
       * Handle DPoP-Nonce response from server
       *
       * @param nonce - Server-provided nonce
       */
      handleNonceResponse: (nonce: string) => manager.handleNonceResponse(nonce),

      /**
       * Calculate access token hash for ath claim
       *
       * @param accessToken - Access token to hash
       * @returns Base64url-encoded SHA-256 hash
       */
      calculateAccessTokenHash: (accessToken: string) =>
        manager.calculateAccessTokenHash(accessToken),

      /**
       * Get the public key JWK
       */
      getPublicKeyJwk: () => manager.getPublicKeyJwk(),

      /**
       * Get the JWK thumbprint
       */
      getThumbprint: () => manager.getThumbprint(),

      /**
       * Clear DPoP key pair (call on logout)
       */
      clear: () => manager.clear(),

      /**
       * Check if DPoP is supported by the server
       *
       * @returns True if server advertises DPoP support
       */
      isServerSupported: async (): Promise<boolean> => {
        const discovery = await this.discover();
        return Array.isArray(discovery.dpop_signing_alg_values_supported) &&
          discovery.dpop_signing_alg_values_supported.length > 0;
      },
    };
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

      /**
       * Introspect a token (RFC 7662)
       *
       * Validates a token server-side and returns its metadata.
       * Useful for resource servers to validate access tokens.
       *
       * @param options - Introspection options (token and optional type hint)
       * @returns Introspection response with token metadata
       * @throws AuthrimError if introspection endpoint not available or request fails
       */
      introspect: async (options: IntrospectTokenOptions): Promise<IntrospectionResponse> => {
        const discovery = await this.discover();
        return this.tokenIntrospector.introspect(discovery, options);
      },

      /**
       * Revoke a token (RFC 7009)
       *
       * Explicitly invalidates a token at the authorization server.
       * Use this when you want to ensure a token can no longer be used.
       *
       * @param options - Revocation options (token and optional type hint)
       * @throws AuthrimError if revocation endpoint not available or request fails
       */
      revoke: async (options: RevokeTokenOptions): Promise<void> => {
        const discovery = await this.discover();
        return this.tokenRevoker.revoke(discovery, options);
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
