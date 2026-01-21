/**
 * PAR (Pushed Authorization Request) Types
 * RFC 9126: OAuth 2.0 Pushed Authorization Requests
 */

/**
 * PAR request parameters
 */
export interface PARRequest {
  /** Redirect URI (required) */
  redirectUri: string;
  /** Scopes to request (default: 'openid profile') */
  scope?: string;
  /**
   * Response type (default: 'code')
   *
   * Use 'none' for session check without token issuance
   * (OAuth 2.0 Multiple Response Types 1.0 §5)
   */
  responseType?: 'code' | 'none';
  /** State parameter for CSRF protection */
  state: string;
  /** Nonce for replay attack prevention */
  nonce: string;
  /** PKCE code challenge */
  codeChallenge: string;
  /** PKCE code challenge method (always S256) */
  codeChallengeMethod: 'S256';
  /** Prompt behavior */
  prompt?: 'none' | 'login' | 'consent' | 'select_account';
  /** Hint about the login identifier */
  loginHint?: string;
  /** Requested Authentication Context Class Reference values */
  acrValues?: string;
  /** Additional custom parameters */
  extraParams?: Record<string, string>;
}

/**
 * PAR response from the server (RFC 9126 §2.2)
 */
export interface PARResponse {
  /** The request URI to use in authorization request */
  request_uri: string;
  /** Lifetime of the request URI in seconds */
  expires_in: number;
}

/**
 * PAR result returned by PARClient
 */
export interface PARResult {
  /** The request URI to use in authorization request */
  requestUri: string;
  /** Absolute expiration time (epoch seconds) */
  expiresAt: number;
}

/**
 * Options for PAR client
 */
export interface PARClientOptions {
  /** Additional headers to include in PAR request */
  headers?: Record<string, string>;
}
