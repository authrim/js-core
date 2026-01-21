/**
 * DPoP Manager
 * RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)
 *
 * DPoP provides sender-constrained access tokens by binding them
 * to a cryptographic key held by the client. This prevents token theft
 * and replay attacks.
 *
 * NOTE: DPoP proofs are required for:
 * - Token requests (authorization code exchange, refresh)
 * - PAR requests
 * - UserInfo requests
 * - Any protected resource request
 *
 * Future consideration: HttpClient-level middleware for automatic DPoP proof attachment.
 */

import type {
  DPoPKeyPair,
  DPoPProofHeader,
  DPoPProofClaims,
  DPoPProofOptions,
  DPoPManagerConfig,
  DPoPCryptoProvider,
  JWK,
} from '../types/dpop.js';
import type { CryptoProvider } from '../providers/crypto.js';
import { AuthrimError } from '../types/errors.js';
import { base64urlEncode, stringToBase64url } from '../utils/base64url.js';

/**
 * DPoP Manager
 *
 * Manages DPoP key pairs and generates DPoP proofs for requests.
 */
export class DPoPManager {
  private readonly crypto: CryptoProvider & DPoPCryptoProvider;
  private readonly config: DPoPManagerConfig;
  private keyPair: DPoPKeyPair | null = null;
  private serverNonce: string | null = null;

  constructor(
    crypto: CryptoProvider & DPoPCryptoProvider,
    config?: DPoPManagerConfig
  ) {
    this.crypto = crypto;
    this.config = config ?? {};
  }

  /**
   * Initialize the DPoP manager
   *
   * Generates or retrieves a DPoP key pair.
   *
   * @throws AuthrimError with code 'dpop_key_generation_error' if key generation fails
   */
  async initialize(): Promise<void> {
    // Check if crypto provider supports DPoP
    if (!this.crypto.generateDPoPKeyPair) {
      throw new AuthrimError(
        'dpop_key_generation_error',
        'CryptoProvider does not support DPoP key generation'
      );
    }

    // Try to get existing key pair
    if (this.crypto.getDPoPKeyPair) {
      const existing = await this.crypto.getDPoPKeyPair();
      if (existing) {
        this.keyPair = existing;
        return;
      }
    }

    // Generate new key pair
    try {
      this.keyPair = await this.crypto.generateDPoPKeyPair(
        this.config.algorithm ?? 'ES256'
      );
    } catch (error) {
      throw new AuthrimError(
        'dpop_key_generation_error',
        'Failed to generate DPoP key pair',
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Check if DPoP is initialized
   */
  isInitialized(): boolean {
    return this.keyPair !== null;
  }

  /**
   * Generate a DPoP proof
   *
   * Creates a signed JWT proof for the specified HTTP method and URI.
   *
   * @param method - HTTP method (GET, POST, etc.)
   * @param uri - Full request URI (https://example.com/path)
   * @param options - Additional options (access token hash, nonce)
   * @returns Signed DPoP proof JWT
   * @throws AuthrimError with code 'dpop_proof_generation_error' if proof generation fails
   */
  async generateProof(
    method: string,
    uri: string,
    options?: DPoPProofOptions
  ): Promise<string> {
    if (!this.keyPair) {
      throw new AuthrimError(
        'dpop_proof_generation_error',
        'DPoP manager not initialized. Call initialize() first.'
      );
    }

    // Parse URI to get htu (without query and fragment)
    const url = new URL(uri);
    const htu = `${url.protocol}//${url.host}${url.pathname}`;

    // Build JWT header
    const header: DPoPProofHeader = {
      typ: 'dpop+jwt',
      alg: this.keyPair.algorithm,
      jwk: this.keyPair.publicKeyJwk,
    };

    // Build JWT claims
    const now = Math.floor(Date.now() / 1000);
    const claims: DPoPProofClaims = {
      jti: this.generateJti(),
      htm: method.toUpperCase(),
      htu,
      iat: now,
    };

    // Add optional claims
    if (options?.accessTokenHash) {
      claims.ath = options.accessTokenHash;
    }
    if (options?.nonce ?? this.serverNonce) {
      claims.nonce = options?.nonce ?? this.serverNonce ?? undefined;
    }

    // Encode and sign
    try {
      const headerB64 = stringToBase64url(JSON.stringify(header));
      const claimsB64 = stringToBase64url(JSON.stringify(claims));
      const signingInput = `${headerB64}.${claimsB64}`;

      const signature = await this.keyPair.sign(
        new TextEncoder().encode(signingInput)
      );
      const signatureB64 = base64urlEncode(signature);

      return `${signingInput}.${signatureB64}`;
    } catch (error) {
      throw new AuthrimError(
        'dpop_proof_generation_error',
        'Failed to generate DPoP proof',
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Handle a DPoP-Nonce response from the server
   *
   * When the server returns a use_dpop_nonce error or includes
   * a DPoP-Nonce header, this method stores the nonce for future proofs.
   *
   * @param nonce - Server-provided nonce value
   */
  handleNonceResponse(nonce: string): void {
    this.serverNonce = nonce;
  }

  /**
   * Get the current server nonce
   */
  getServerNonce(): string | null {
    return this.serverNonce;
  }

  /**
   * Clear the server nonce
   */
  clearServerNonce(): void {
    this.serverNonce = null;
  }

  /**
   * Get the public key JWK
   *
   * @returns Public key in JWK format, or null if not initialized
   */
  getPublicKeyJwk(): JWK | null {
    return this.keyPair?.publicKeyJwk ?? null;
  }

  /**
   * Get the JWK thumbprint
   *
   * @returns Base64url-encoded thumbprint, or null if not initialized
   */
  getThumbprint(): string | null {
    return this.keyPair?.thumbprint ?? null;
  }

  /**
   * Calculate access token hash for ath claim
   *
   * @param accessToken - Access token to hash
   * @returns Base64url-encoded SHA-256 hash
   */
  async calculateAccessTokenHash(accessToken: string): Promise<string> {
    const hash = await this.crypto.sha256(accessToken);
    return base64urlEncode(hash);
  }

  /**
   * Clear the DPoP key pair
   *
   * Should be called on logout to clean up key material.
   */
  async clear(): Promise<void> {
    if (this.crypto.clearDPoPKeyPair) {
      await this.crypto.clearDPoPKeyPair();
    }
    this.keyPair = null;
    this.serverNonce = null;
  }

  /**
   * Generate a unique JWT ID (jti)
   */
  private generateJti(): string {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
      return crypto.randomUUID();
    }
    return `${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
  }
}
