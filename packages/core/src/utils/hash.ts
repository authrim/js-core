/**
 * Hash Utilities
 *
 * Provides hash calculation utilities for OIDC specifications.
 */

import type { CryptoProvider } from '../providers/crypto.js';
import { base64urlEncode } from './base64url.js';

/**
 * Calculate ds_hash for Native SSO device_secret verification
 *
 * Algorithm: BASE64URL(left half of SHA-256(device_secret))
 * Reference: OIDC Native SSO 1.0 specification
 *
 * This is the same algorithm used for at_hash and c_hash in OIDC Core,
 * applied to the device_secret value.
 *
 * @param deviceSecret - The device_secret value to hash
 * @param crypto - Platform-specific crypto provider
 * @returns ds_hash value (BASE64URL encoded)
 *
 * @example
 * ```typescript
 * const dsHash = await calculateDsHash(deviceSecret, cryptoProvider);
 * // Compare with id_token.ds_hash claim
 * if (idToken.ds_hash === dsHash) {
 *   // device_secret is valid
 * }
 * ```
 */
export async function calculateDsHash(
  deviceSecret: string,
  crypto: CryptoProvider
): Promise<string> {
  // 1. Compute SHA-256 hash (32 bytes)
  const hash = await crypto.sha256(deviceSecret);

  // 2. Take the left half (16 bytes for SHA-256)
  const leftHalf = hash.slice(0, hash.length / 2);

  // 3. BASE64URL encode
  return base64urlEncode(leftHalf);
}
