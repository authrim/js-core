/**
 * Client Authentication Types
 * RFC 6749 §2.3, RFC 7521, RFC 7523
 */

/**
 * Client authentication methods
 */
export type ClientAuthMethod =
  | 'client_secret_basic'
  | 'client_secret_post'
  | 'private_key_jwt'
  | 'none';

/**
 * Client secret credentials (Basic or POST)
 */
export interface ClientSecretCredentials {
  /** Authentication method */
  method: 'client_secret_basic' | 'client_secret_post';
  /** Client secret */
  clientSecret: string;
}

/**
 * Private key JWT credentials (RFC 7523)
 */
export interface PrivateKeyJwtCredentials {
  /** Authentication method */
  method: 'private_key_jwt';
  /**
   * Function to sign JWT assertions
   *
   * @param claims - JWT claims to sign
   * @returns Signed JWT string
   */
  signJwt: (claims: Record<string, unknown>) => Promise<string>;
  /** Key ID to include in JWT header */
  keyId?: string;
}

/**
 * No client authentication (public client)
 *
 * SECURITY: method='none' requires explicit opt-in via dangerouslyAllowInsecure
 * to ensure developers consciously choose to use public client authentication.
 */
export interface NoClientCredentials {
  /** Authentication method */
  method: 'none';
  /**
   * Required flag to acknowledge insecure client authentication
   *
   * Setting this to true acknowledges that:
   * - The client cannot be authenticated securely
   * - This should only be used for public clients (browser apps, native apps)
   * - Tokens may be exposed to the user
   */
  dangerouslyAllowInsecure: true;
}

/**
 * Union type for all client credentials
 */
export type ClientCredentials =
  | ClientSecretCredentials
  | PrivateKeyJwtCredentials
  | NoClientCredentials;

/**
 * JWT assertion claims for client authentication
 */
export interface ClientAssertionClaims extends Record<string, unknown> {
  /** Issuer (client_id) */
  iss: string;
  /** Subject (client_id) */
  sub: string;
  /** Audience (token endpoint URL) */
  aud: string;
  /** JWT ID (unique identifier) */
  jti: string;
  /** Expiration time (epoch seconds) */
  exp: number;
  /** Issued at time (epoch seconds) */
  iat: number;
}
