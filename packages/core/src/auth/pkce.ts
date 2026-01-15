/**
 * PKCE (Proof Key for Code Exchange) Helper
 *
 * Implements RFC 7636 for Authorization Code Flow security.
 * https://tools.ietf.org/html/rfc7636
 */

import type { CryptoProvider } from '../providers/crypto.js';

/**
 * PKCE challenge method
 */
export type CodeChallengeMethod = 'S256' | 'plain';

/**
 * PKCE pair (verifier and challenge)
 */
export interface PKCEPair {
  /** Code verifier (high-entropy random string) */
  codeVerifier: string;
  /** Code challenge (derived from verifier) */
  codeChallenge: string;
  /** Challenge method used */
  codeChallengeMethod: CodeChallengeMethod;
}

/**
 * PKCE Helper class
 */
export class PKCEHelper {
  constructor(private readonly crypto: CryptoProvider) {}

  /**
   * Generate a PKCE pair (verifier + challenge)
   *
   * Uses S256 method (SHA-256 hash, base64url-encoded).
   *
   * @returns PKCE pair
   */
  async generatePKCE(): Promise<PKCEPair> {
    const codeVerifier = await this.crypto.generateCodeVerifier();
    const codeChallenge = await this.crypto.generateCodeChallenge(codeVerifier);

    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256',
    };
  }

  /**
   * Generate only the code verifier
   *
   * @returns Code verifier string
   */
  async generateCodeVerifier(): Promise<string> {
    return this.crypto.generateCodeVerifier();
  }

  /**
   * Generate a code challenge from a verifier
   *
   * @param verifier - Code verifier
   * @returns Code challenge (base64url-encoded SHA-256 hash)
   */
  async generateCodeChallenge(verifier: string): Promise<string> {
    return this.crypto.generateCodeChallenge(verifier);
  }
}
