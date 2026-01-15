/**
 * Crypto Provider Interface
 *
 * Platform-agnostic cryptographic operations abstraction.
 * Implementations must be injected - @authrim/core does not use crypto.subtle directly.
 */

/**
 * Crypto Provider interface
 *
 * Implementations should:
 * - Use cryptographically secure random number generation
 * - Implement SHA-256 using platform-native crypto APIs
 * - Generate PKCE code verifiers and challenges per RFC 7636
 */
export interface CryptoProvider {
  /**
   * Generate cryptographically secure random bytes
   *
   * @param length - Number of bytes to generate
   * @returns Promise resolving to random bytes
   */
  randomBytes(length: number): Promise<Uint8Array>;

  /**
   * Compute SHA-256 hash of a string
   *
   * @param data - String to hash (UTF-8 encoded)
   * @returns Promise resolving to hash bytes
   */
  sha256(data: string): Promise<Uint8Array>;

  /**
   * Generate a PKCE code verifier (RFC 7636)
   *
   * Requirements:
   * - 43-128 characters
   * - URL-safe characters only: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
   * - Recommended: 43 characters of base64url-encoded random bytes
   *
   * @returns Promise resolving to code verifier string
   */
  generateCodeVerifier(): Promise<string>;

  /**
   * Generate a PKCE code challenge from a code verifier (RFC 7636)
   *
   * Computes: BASE64URL(SHA256(code_verifier))
   *
   * @param verifier - Code verifier string
   * @returns Promise resolving to code challenge string
   */
  generateCodeChallenge(verifier: string): Promise<string>;
}
