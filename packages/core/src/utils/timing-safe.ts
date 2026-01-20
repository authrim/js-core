/**
 * Timing-Safe Comparison Utilities
 *
 * Provides constant-time string comparison to prevent timing attacks.
 * Used for comparing security-sensitive values like nonces and states.
 */

/**
 * Compare two strings in constant time
 *
 * This function always takes the same amount of time regardless of
 * where the strings differ, preventing timing attacks.
 *
 * @param a - First string
 * @param b - Second string
 * @returns true if strings are equal, false otherwise
 */
export function timingSafeEqual(a: string, b: string): boolean {
  // Encode strings to bytes for comparison
  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);

  // Use byte array lengths for comparison
  const aLen = aBytes.length;
  const bLen = bBytes.length;

  // Use the longer length to ensure we compare all bytes
  const maxLen = Math.max(aLen, bLen);

  // XOR accumulator - will be non-zero if any bytes differ
  let result = aLen ^ bLen; // Start with length comparison

  // Compare all bytes, using 0 for out-of-bounds access
  for (let i = 0; i < maxLen; i++) {
    const aByte = i < aLen ? aBytes[i] : 0;
    const bByte = i < bLen ? bBytes[i] : 0;
    result |= aByte ^ bByte;
  }

  return result === 0;
}
