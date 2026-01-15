/**
 * Authorization Code Flow
 *
 * Implements OAuth 2.0 Authorization Code Flow with PKCE.
 * Uses 2-step pattern: buildAuthorizationUrl() + handleCallback()
 */

import type { HttpClient } from '../providers/http.js';
import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import type { TokenSet, TokenResponse } from '../types/token.js';
import type { AuthState } from './state.js';
import type { PKCEPair } from './pkce.js';
import { AuthrimError } from '../types/errors.js';
import { getIdTokenNonce } from '../utils/jwt.js';

/**
 * Options for building authorization URL
 */
export interface BuildAuthorizationUrlOptions {
  /** Redirect URI (required) */
  redirectUri: string;
  /** Scopes to request (default: 'openid profile') */
  scope?: string;
  /** Prompt behavior */
  prompt?: 'none' | 'login' | 'consent' | 'select_account';
  /** Hint about the login identifier */
  loginHint?: string;
  /** Requested Authentication Context Class Reference values */
  acrValues?: string;
  /** Additional custom parameters */
  extraParams?: Record<string, string>;
  /**
   * Expose state/nonce in result (for SSR/external storage)
   *
   * Default: false (security: state/nonce stay internal)
   * Set to true only when you need to store state externally
   * (e.g., cookie, server-side session)
   */
  exposeState?: boolean;
}

/**
 * Result of buildAuthorizationUrl
 */
export interface AuthorizationUrlResult {
  /** Authorization URL to redirect to */
  url: string;
  /** State parameter (only if exposeState: true) */
  state?: string;
  /** Nonce parameter (only if exposeState: true) */
  nonce?: string;
}

/**
 * Internal authorization context (stored by StateManager)
 */
export interface AuthorizationContext {
  /** Auth state object */
  authState: AuthState;
  /** PKCE pair */
  pkce: PKCEPair;
}

/**
 * Options for exchanging authorization code
 */
export interface ExchangeCodeOptions {
  /** Authorization code */
  code: string;
  /** State parameter (for validation) */
  state: string;
  /** Redirect URI used in authorization request */
  redirectUri: string;
  /** Code verifier for PKCE */
  codeVerifier: string;
  /** Nonce to validate in ID token */
  nonce: string;
}

/**
 * Authorization Code Flow helper
 */
export class AuthorizationCodeFlow {
  constructor(
    private readonly http: HttpClient,
    private readonly clientId: string
  ) {}

  /**
   * Build authorization URL
   *
   * @param discovery - OIDC discovery document
   * @param authState - Auth state from StateManager
   * @param pkce - PKCE pair
   * @param options - Authorization options
   * @returns Authorization URL result
   */
  buildAuthorizationUrl(
    discovery: OIDCDiscoveryDocument,
    authState: AuthState,
    pkce: PKCEPair,
    options: BuildAuthorizationUrlOptions
  ): AuthorizationUrlResult {
    const endpoint = discovery.authorization_endpoint;
    const params = new URLSearchParams();

    // Required parameters
    params.set('client_id', this.clientId);
    params.set('response_type', 'code');
    params.set('redirect_uri', options.redirectUri);
    params.set('state', authState.state);
    params.set('nonce', authState.nonce);

    // PKCE parameters
    params.set('code_challenge', pkce.codeChallenge);
    params.set('code_challenge_method', pkce.codeChallengeMethod);

    // Scopes
    const scope = options.scope ?? 'openid profile';
    params.set('scope', scope);

    // Optional parameters
    if (options.prompt) {
      params.set('prompt', options.prompt);
    }
    if (options.loginHint) {
      params.set('login_hint', options.loginHint);
    }
    if (options.acrValues) {
      params.set('acr_values', options.acrValues);
    }

    // Extra custom parameters (with security parameter protection)
    if (options.extraParams) {
      // Security parameters that MUST NOT be overwritten
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

      for (const [key, value] of Object.entries(options.extraParams)) {
        if (protectedParams.has(key.toLowerCase())) {
          // Silently ignore attempts to override security parameters
          // This prevents CSRF, PKCE bypass, and other attacks
          continue;
        }
        params.set(key, value);
      }
    }

    const url = `${endpoint}?${params.toString()}`;

    // Build result
    const result: AuthorizationUrlResult = { url };

    if (options.exposeState) {
      result.state = authState.state;
      result.nonce = authState.nonce;
    }

    return result;
  }

  /**
   * Parse callback URL and extract code/state
   *
   * @param callbackUrl - Callback URL or query string
   * @returns Parsed code and state
   * @throws AuthrimError if code or state is missing, or if error is present
   */
  parseCallback(callbackUrl: string): { code: string; state: string } {
    let searchParams: URLSearchParams;

    // Support both full URL and query string
    if (callbackUrl.includes('?')) {
      const url = callbackUrl.startsWith('http')
        ? new URL(callbackUrl)
        : new URL(callbackUrl, 'https://dummy.local');
      searchParams = url.searchParams;
    } else {
      searchParams = new URLSearchParams(callbackUrl);
    }

    // Check for OAuth error response
    const error = searchParams.get('error');
    if (error) {
      const errorDescription = searchParams.get('error_description') ?? 'Authorization failed';
      throw new AuthrimError('oauth_error', errorDescription, {
        details: {
          error,
          error_description: errorDescription,
          error_uri: searchParams.get('error_uri'),
        },
      });
    }

    // Extract code and state
    const code = searchParams.get('code');
    const state = searchParams.get('state');

    if (!code) {
      throw new AuthrimError('missing_code', 'Authorization code not found in callback');
    }
    if (!state) {
      throw new AuthrimError('missing_state', 'State parameter not found in callback');
    }

    return { code, state };
  }

  /**
   * Exchange authorization code for tokens
   *
   * @param discovery - OIDC discovery document
   * @param options - Exchange options
   * @returns Token set
   * @throws AuthrimError if exchange fails or nonce validation fails
   */
  async exchangeCode(
    discovery: OIDCDiscoveryDocument,
    options: ExchangeCodeOptions
  ): Promise<TokenSet> {
    const tokenEndpoint = discovery.token_endpoint;

    // Build token request body
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.clientId,
      code: options.code,
      redirect_uri: options.redirectUri,
      code_verifier: options.codeVerifier,
    });

    // Make token request
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
      throw new AuthrimError('network_error', 'Token request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (!response.ok) {
      const errorData = response.data as unknown as Record<string, unknown>;
      throw new AuthrimError('token_error', 'Token exchange failed', {
        details: {
          status: response.status,
          error: errorData?.error,
          error_description: errorData?.error_description,
        },
      });
    }

    const tokenResponse = response.data;

    // Validate nonce in ID token
    if (tokenResponse.id_token) {
      const idTokenNonce = getIdTokenNonce(tokenResponse.id_token);
      if (idTokenNonce !== options.nonce) {
        // Do not include nonce values in error details (security sensitive)
        throw new AuthrimError('nonce_mismatch', 'ID token nonce does not match expected value');
      }
    }

    // Calculate expiresAt (epoch seconds)
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = tokenResponse.expires_in ? now + tokenResponse.expires_in : now + 3600; // Default to 1 hour if not provided

    // Build token set
    const tokenSet: TokenSet = {
      accessToken: tokenResponse.access_token,
      tokenType: (tokenResponse.token_type as 'Bearer') ?? 'Bearer',
      expiresAt,
      refreshToken: tokenResponse.refresh_token,
      idToken: tokenResponse.id_token,
      scope: tokenResponse.scope,
    };

    return tokenSet;
  }
}
