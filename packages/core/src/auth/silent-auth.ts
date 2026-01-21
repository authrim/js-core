/**
 * Silent Authentication (prompt=none)
 *
 * Foundation for silent authentication using OIDC prompt=none.
 * This module provides the core logic for building silent auth requests
 * and parsing responses. The actual iframe/hidden frame implementation
 * is platform-specific and should be implemented in @authrim/web or similar.
 *
 * Silent authentication allows checking if a user has an active session
 * with the authorization server without user interaction.
 */

import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import type { TokenSet } from '../types/token.js';
import type { AuthState } from './state.js';
import type { PKCEPair } from './pkce.js';
import { AuthrimError } from '../types/errors.js';

/**
 * Silent authentication options
 */
export interface SilentAuthOptions {
  /** Redirect URI for silent auth response (often an iframe callback page) */
  redirectUri: string;
  /** Scopes to request (default: 'openid') */
  scope?: string;
  /**
   * Response type (default: 'code')
   *
   * Use 'none' for session check without token issuance
   * (OAuth 2.0 Multiple Response Types 1.0 §5)
   */
  responseType?: 'code' | 'none';
  /** Hint about the login identifier */
  loginHint?: string;
  /** ID token hint (helps IdP identify the user) */
  idTokenHint?: string;
  /** Additional custom parameters */
  extraParams?: Record<string, string>;
  /**
   * Expose state/nonce in result (for SSR/external storage)
   *
   * Default: false (security: state/nonce stay internal)
   */
  exposeState?: boolean;
}

/**
 * Result of building silent auth URL
 */
export interface SilentAuthUrlResult {
  /** Authorization URL with prompt=none */
  url: string;
  /** State parameter (only if exposeState: true) */
  state?: string;
  /** Nonce parameter (only if exposeState: true) */
  nonce?: string;
}

/**
 * Silent authentication result
 */
export interface SilentAuthResult {
  /** Whether silent auth succeeded */
  success: boolean;
  /** Tokens if successful */
  tokens?: TokenSet;
  /** Error if failed (e.g., login_required) */
  error?: AuthrimError;
}

/**
 * Silent auth error codes that indicate interactive login is needed
 */
const INTERACTIVE_LOGIN_REQUIRED_ERRORS = new Set([
  'login_required',
  'interaction_required',
  'consent_required',
  'account_selection_required',
]);

/**
 * Silent Authentication Handler
 *
 * Provides core logic for silent authentication. Platform-specific
 * implementations (iframe, hidden frame, etc.) should use this class.
 */
export class SilentAuthHandler {
  constructor(private readonly clientId: string) {}

  /**
   * Build silent authentication URL
   *
   * Creates an authorization URL with prompt=none for silent authentication.
   *
   * @param discovery - OIDC discovery document
   * @param authState - Auth state from StateManager
   * @param pkce - PKCE pair
   * @param options - Silent auth options
   * @returns Silent auth URL result
   */
  buildSilentAuthUrl(
    discovery: OIDCDiscoveryDocument,
    authState: AuthState,
    pkce: PKCEPair,
    options: SilentAuthOptions
  ): SilentAuthUrlResult {
    const endpoint = discovery.authorization_endpoint;
    const params = new URLSearchParams();

    // Required parameters
    params.set('client_id', this.clientId);
    params.set('response_type', options.responseType ?? 'code');
    params.set('redirect_uri', options.redirectUri);
    params.set('state', authState.state);
    params.set('nonce', authState.nonce);

    // Silent auth specific - MUST be prompt=none
    params.set('prompt', 'none');

    // PKCE parameters
    params.set('code_challenge', pkce.codeChallenge);
    params.set('code_challenge_method', pkce.codeChallengeMethod);

    // Scopes (default to openid only for silent auth)
    const scope = options.scope ?? 'openid';
    params.set('scope', scope);

    // Optional parameters
    if (options.loginHint) {
      params.set('login_hint', options.loginHint);
    }
    if (options.idTokenHint) {
      params.set('id_token_hint', options.idTokenHint);
    }

    // Extra custom parameters (with security parameter protection)
    if (options.extraParams) {
      const protectedParams = new Set([
        'client_id',
        'response_type',
        'redirect_uri',
        'state',
        'nonce',
        'code_challenge',
        'code_challenge_method',
        'scope',
        'prompt', // Protect prompt=none
      ]);

      for (const [key, value] of Object.entries(options.extraParams)) {
        if (protectedParams.has(key.toLowerCase())) {
          continue;
        }
        params.set(key, value);
      }
    }

    const url = `${endpoint}?${params.toString()}`;

    const result: SilentAuthUrlResult = { url };

    if (options.exposeState) {
      result.state = authState.state;
      result.nonce = authState.nonce;
    }

    return result;
  }

  /**
   * Parse silent authentication response URL
   *
   * Parses the callback URL from silent authentication and returns
   * either the authorization code (for token exchange) or an error.
   *
   * @param responseUrl - Response URL from silent auth (iframe callback)
   * @returns Parsed result with code/state or error
   */
  parseSilentAuthResponse(responseUrl: string): {
    success: true;
    code: string;
    state: string;
  } | {
    success: false;
    error: AuthrimError;
  } {
    let searchParams: URLSearchParams;

    // Support both full URL and query string
    if (responseUrl.includes('?')) {
      const url = responseUrl.startsWith('http')
        ? new URL(responseUrl)
        : new URL(responseUrl, 'https://dummy.local');
      searchParams = url.searchParams;
    } else {
      searchParams = new URLSearchParams(responseUrl);
    }

    // Check for OAuth error response
    const error = searchParams.get('error');
    if (error) {
      const errorDescription = searchParams.get('error_description');
      const errorCode = this.mapSilentAuthError(error);

      return {
        success: false,
        error: new AuthrimError(errorCode, errorDescription ?? this.getDefaultErrorMessage(error), {
          details: {
            error,
            error_description: errorDescription,
            error_uri: searchParams.get('error_uri'),
          },
        }),
      };
    }

    // Extract code and state
    const code = searchParams.get('code');
    const state = searchParams.get('state');

    if (!code) {
      return {
        success: false,
        error: new AuthrimError('missing_code', 'Authorization code not found in silent auth response'),
      };
    }
    if (!state) {
      return {
        success: false,
        error: new AuthrimError('missing_state', 'State parameter not found in silent auth response'),
      };
    }

    return { success: true, code, state };
  }

  /**
   * Check if an error indicates interactive login is required
   *
   * @param error - Error to check
   * @returns True if interactive login is needed
   */
  isInteractiveLoginRequired(error: AuthrimError): boolean {
    return INTERACTIVE_LOGIN_REQUIRED_ERRORS.has(error.code);
  }

  /**
   * Map OAuth error to AuthrimErrorCode
   */
  private mapSilentAuthError(
    error: string
  ): 'login_required' | 'interaction_required' | 'consent_required' | 'account_selection_required' | 'oauth_error' {
    if (INTERACTIVE_LOGIN_REQUIRED_ERRORS.has(error)) {
      return error as 'login_required' | 'interaction_required' | 'consent_required' | 'account_selection_required';
    }
    return 'oauth_error';
  }

  /**
   * Get default error message for silent auth errors
   */
  private getDefaultErrorMessage(error: string): string {
    switch (error) {
      case 'login_required':
        return 'User must log in - no active session found';
      case 'interaction_required':
        return 'User interaction required';
      case 'consent_required':
        return 'User consent required';
      case 'account_selection_required':
        return 'User must select an account';
      default:
        return 'Silent authentication failed';
    }
  }
}
