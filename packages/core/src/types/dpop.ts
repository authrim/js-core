/**
 * DPoP (Demonstrating Proof of Possession) Types
 * RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)
 *
 * DPoP provides a mechanism for sender-constraining access tokens
 * to a particular client by binding tokens to a cryptographic key.
 */

/**
 * JSON Web Key (JWK) format
 *
 * Subset of the Web Crypto API JWK interface.
 * Defined here for platform-agnostic support.
 */
export interface JWK {
  /** Key type (e.g., 'EC', 'RSA') */
  kty?: string;
  /** Key ID */
  kid?: string;
  /** Algorithm */
  alg?: string;
  /** Public key use */
  use?: string;
  /** Key operations */
  key_ops?: string[];
  /** Extractable flag */
  ext?: boolean;
  // EC key parameters
  /** Curve name */
  crv?: string;
  /** X coordinate (base64url) */
  x?: string;
  /** Y coordinate (base64url) */
  y?: string;
  /** Private key value (base64url) - should not be exported */
  d?: string;
  // RSA key parameters
  /** Modulus (base64url) */
  n?: string;
  /** Public exponent (base64url) */
  e?: string;
  // Additional properties
  [key: string]: unknown;
}

/**
 * DPoP key pair interface
 *
 * Represents an asymmetric key pair used for DPoP proofs.
 */
export interface DPoPKeyPair {
  /** Algorithm identifier (e.g., 'ES256', 'RS256') */
  algorithm: string;
  /** JWK thumbprint of the public key (base64url encoded) */
  thumbprint: string;
  /** Public key in JWK format */
  publicKeyJwk: JWK;
  /**
   * Sign data with the private key
   *
   * @param data - Data to sign
   * @returns Signature
   */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/**
 * DPoP proof JWT header
 */
export interface DPoPProofHeader {
  /** Type (always 'dpop+jwt') */
  typ: 'dpop+jwt';
  /** Algorithm */
  alg: string;
  /** Public key in JWK format */
  jwk: JWK;
}

/**
 * DPoP proof JWT claims
 */
export interface DPoPProofClaims {
  /** Unique identifier for the proof */
  jti: string;
  /** HTTP method of the request */
  htm: string;
  /** HTTP URI of the request (without query and fragment) */
  htu: string;
  /** Issued at time (epoch seconds) */
  iat: number;
  /** Access token hash (when binding to access token) */
  ath?: string;
  /** Server-provided nonce (when server requires it) */
  nonce?: string;
}

/**
 * Options for generating a DPoP proof
 */
export interface DPoPProofOptions {
  /** Hash of the access token (base64url(SHA-256(access_token))) */
  accessTokenHash?: string;
  /** Server-provided nonce */
  nonce?: string;
}

/**
 * DPoP Manager configuration
 */
export interface DPoPManagerConfig {
  /** Preferred algorithm (default: 'ES256') */
  algorithm?: string;
}

/**
 * Extended CryptoProvider interface with DPoP support
 *
 * This extends the base CryptoProvider with optional DPoP methods.
 * Implementations that support DPoP should implement these methods.
 */
export interface DPoPCryptoProvider {
  /**
   * Generate a new DPoP key pair
   *
   * @param algorithm - Preferred algorithm (default: 'ES256')
   * @returns Generated key pair
   */
  generateDPoPKeyPair?(algorithm?: string): Promise<DPoPKeyPair>;

  /**
   * Get the current DPoP key pair
   *
   * Returns null if no key pair has been generated.
   *
   * @returns Current key pair or null
   */
  getDPoPKeyPair?(): Promise<DPoPKeyPair | null>;

  /**
   * Clear the DPoP key pair
   *
   * Should be called on logout to clean up key material.
   */
  clearDPoPKeyPair?(): Promise<void>;
}
