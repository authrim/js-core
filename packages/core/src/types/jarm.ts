/**
 * JARM (JWT Secured Authorization Response Mode) Types
 * Financial-grade API (FAPI) / OpenID Connect
 *
 * JARM provides a way for authorization servers to return authorization
 * response parameters in a signed (and optionally encrypted) JWT.
 * This provides integrity protection and authenticity verification.
 */

/**
 * JARM response JWT claims
 */
export interface JARMResponseClaims {
  /** Issuer (authorization server) */
  iss: string;
  /** Audience (client_id) */
  aud: string;
  /** Expiration time (epoch seconds) */
  exp: number;
  /** Issued at time (optional) */
  iat?: number;
  // Authorization response parameters
  /** Authorization code */
  code?: string;
  /** State parameter */
  state?: string;
  /** Error code */
  error?: string;
  /** Error description */
  error_description?: string;
  /** Error URI */
  error_uri?: string;
  // Additional claims
  [key: string]: unknown;
}

/**
 * JARM validation options
 */
export interface JARMValidationOptions {
  /** Expected state value */
  expectedState: string;
  /** Client ID (audience) */
  clientId: string;
  /** Clock skew tolerance in seconds (default: 60) */
  clockSkewSeconds?: number;
}

/**
 * JARM validation result
 */
export interface JARMValidationResult {
  /** Authorization code (if present) */
  code: string;
  /** State parameter */
  state: string;
}

/**
 * JARM Validator configuration
 */
export interface JARMValidatorConfig {
  /**
   * Function to verify JWT signature
   *
   * Should verify the signature using the authorization server's public keys
   * (typically from JWKS endpoint) and return the decoded claims.
   *
   * @param jwt - The JWT string to verify
   * @param issuer - Expected issuer
   * @returns Decoded and verified claims
   * @throws Error if signature verification fails
   */
  verifyJwt: (jwt: string, issuer: string) => Promise<JARMResponseClaims>;
}
