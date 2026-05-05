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
  /** Token type */
  tokenType: 'Bearer' | 'DPoP';
  /**
   * Token expiration time as epoch seconds
   *
   * Calculated from expires_in at token exchange time:
   * expiresAt = Math.floor(Date.now() / 1000) + expires_in
   */
  expiresAt: number;
  /** Scope granted (may differ from requested scope) */
  scope?: string;
  /** Refresh token expiration time as epoch seconds, when provided by the server */
  refreshTokenExpiresAt?: number;
  /** Refresh token lifetime in seconds, when provided by the server */
  refreshTokenExpiresIn?: number;
  /** Refresh token expiration timestamp string, when provided by the server */
  refreshTokenExpiresAtIso?: string;
}

/**
 * Token endpoint response (raw)
 */
export interface TokenEndpointResponse {
  access_token: string;
  token_type: 'Bearer' | 'DPoP' | string;
  expires_in?: number;
  refresh_token?: string;
  refresh_token_expires_in?: number;
  refresh_token_expires_at?: string;
  refresh_token_expires_at_unix?: number;
  id_token?: string;
  scope?: string;
  installation_id?: string;
  client_id?: string;
  app_display_name?: string;
  platform?: string;
  display_name?: string;
  fallback_display_name?: string;
  last_seen_at?: string;
  last_seen_at_unix?: number;
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
  subjectTokenType?: 'access_token' | 'refresh_token' | 'id_token' | 'device_secret';
  /** Resource indicator for the new token */
  resource?: string | string[];
  /** Target audience for the new token */
  audience?: string;
  /** Requested scope for the new token */
  scope?: string;
  /** Requested token type (default: access_token) */
  requestedTokenType?: 'access_token' | 'refresh_token' | 'id_token';
  /** Actor token (for delegation) */
  actorToken?: string;
  /** Actor token type */
  actorTokenType?: 'access_token' | 'id_token' | 'device_secret';
  /** Product-specific channel for Phase 1 profile requests */
  channel?: 'browser' | 'native' | 'server';
  /** DPoP proof JWT to attach to the token exchange request */
  dpopProof?: string;
}

/**
 * Native SSO token exchange request.
 *
 * Uses the Phase 1 Native SSO profile:
 * subject_token=id_token, actor_token=device_secret, channel=native, DPoP required.
 */
export interface NativeSSOTokenExchangeRequest {
  /** Subject ID Token issued with ds_hash */
  idToken: string;
  /** Raw Native SSO device_secret */
  deviceSecret: string;
  /** DPoP proof JWT for the token endpoint request */
  dpopProof: string;
  /** Optional requested scope */
  scope?: string;
  /** Optional resource indicator */
  resource?: string | string[];
  /** Optional target audience */
  audience?: string;
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
  device_secret: 'urn:openid:params:token-type:device-secret',
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
  /** Native SSO installation metadata, when returned by the server */
  nativeSSO?: {
    installationId?: string;
    clientId?: string;
    appDisplayName?: string;
    platform?: string;
    displayName?: string;
    fallbackDisplayName?: string;
    lastSeenAt?: string;
    lastSeenAtUnix?: number;
  };
}
