/**
 * Token Types
 */

/**
 * Token set returned from token endpoint
 *
 * Note: expiresAt is epoch seconds (not milliseconds)
 */
export interface TokenSet {
  /** Access token */
  accessToken: string;
  /** Refresh token (if provided) */
  refreshToken?: string;
  /** ID token (if openid scope was requested) */
  idToken?: string;
  /** Token type (always 'Bearer' for OAuth 2.0) */
  tokenType: 'Bearer';
  /**
   * Token expiration time as epoch seconds
   *
   * Calculated from expires_in at token exchange time:
   * expiresAt = Math.floor(Date.now() / 1000) + expires_in
   */
  expiresAt: number;
  /** Scope granted (may differ from requested scope) */
  scope?: string;
}

/**
 * Token endpoint response (raw)
 */
export interface TokenEndpointResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

/**
 * Alias for TokenEndpointResponse
 */
export type TokenResponse = TokenEndpointResponse;

/**
 * Token exchange request (RFC 8693)
 */
export interface TokenExchangeRequest {
  /** The subject token to exchange */
  subjectToken: string;
  /** Subject token type (default: access_token) */
  subjectTokenType?: 'access_token' | 'refresh_token' | 'id_token';
  /** Target audience for the new token */
  audience?: string;
  /** Requested scope for the new token */
  scope?: string;
  /** Requested token type (default: access_token) */
  requestedTokenType?: 'access_token' | 'refresh_token' | 'id_token';
  /** Actor token (for delegation) */
  actorToken?: string;
  /** Actor token type */
  actorTokenType?: 'access_token' | 'id_token';
}

/**
 * Token exchange response (RFC 8693)
 *
 * Extends standard token response with issued_token_type
 */
export interface TokenExchangeResponse extends TokenEndpointResponse {
  /** URI of the issued token type */
  issued_token_type: string;
}

/**
 * Token type URIs (RFC 8693)
 */
export const TOKEN_TYPE_URIS = {
  access_token: 'urn:ietf:params:oauth:token-type:access_token',
  refresh_token: 'urn:ietf:params:oauth:token-type:refresh_token',
  id_token: 'urn:ietf:params:oauth:token-type:id_token',
} as const;

/**
 * Token type URI type
 */
export type TokenTypeUri = (typeof TOKEN_TYPE_URIS)[keyof typeof TOKEN_TYPE_URIS];

/**
 * Token exchange result
 */
export interface TokenExchangeResult {
  /** Token set from exchange */
  tokens: TokenSet;
  /** Issued token type URI */
  issuedTokenType: TokenTypeUri | string;
}
