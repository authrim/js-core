/**
 * JAR (JWT Secured Authorization Request) Types
 * RFC 9101: The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)
 *
 * JAR allows authorization request parameters to be encoded in a
 * signed JWT, providing integrity protection and non-repudiation.
 */

/**
 * JAR request object claims
 */
export interface JARRequestObjectClaims {
  /** Issuer (client_id) */
  iss: string;
  /** Audience (authorization server issuer) */
  aud: string;
  /** Response type */
  response_type: string;
  /** Client ID */
  client_id: string;
  /** Redirect URI */
  redirect_uri: string;
  /** Scope */
  scope: string;
  /** State */
  state: string;
  /** Nonce */
  nonce: string;
  /** PKCE code challenge */
  code_challenge: string;
  /** PKCE code challenge method */
  code_challenge_method: string;
  /** Issued at time (epoch seconds) */
  iat: number;
  /** Expiration time (epoch seconds) */
  exp: number;
  /** JWT ID (optional but recommended) */
  jti?: string;
  /** Not before time (optional) */
  nbf?: number;
  // Optional OIDC parameters
  /** Prompt */
  prompt?: string;
  /** Login hint */
  login_hint?: string;
  /** ACR values */
  acr_values?: string;
  // Additional claims
  [key: string]: unknown;
}

/**
 * JAR Builder configuration
 */
export interface JARBuilderConfig {
  /**
   * Function to sign JWT
   *
   * @param header - JWT header object
   * @param claims - JWT claims object
   * @returns Signed JWT string
   */
  signJwt: (header: object, claims: object) => Promise<string>;
  /** Key ID to include in JWT header */
  keyId?: string;
  /** Lifetime of the request object in seconds (default: 300) */
  lifetime?: number;
  /** Algorithm for signing (e.g., 'RS256', 'ES256') */
  algorithm?: string;
}

/**
 * Options for building a request object
 */
export interface JARRequestOptions {
  /** Client ID */
  clientId: string;
  /** Authorization server issuer */
  issuer: string;
  /** Response type (default: 'code') */
  responseType?: string;
  /** Redirect URI */
  redirectUri: string;
  /** Scope */
  scope: string;
  /** State */
  state: string;
  /** Nonce */
  nonce: string;
  /** PKCE code challenge */
  codeChallenge: string;
  /** PKCE code challenge method */
  codeChallengeMethod: string;
  /** Prompt */
  prompt?: string;
  /** Login hint */
  loginHint?: string;
  /** ACR values */
  acrValues?: string;
  /** Additional claims */
  extraClaims?: Record<string, unknown>;
}
