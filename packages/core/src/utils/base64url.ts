/**
 * Base64URL Encoding/Decoding Utilities
 *
 * Implements RFC 4648 Section 5 (Base64 URL and Filename Safe Alphabet)
 */

/**
 * Encode a Uint8Array to base64url string
 *
 * @param data - Bytes to encode
 * @returns Base64URL encoded string (no padding)
 */
export function base64urlEncode(data: Uint8Array): string {
  // Convert to base64
  let base64 = '';

  // Use platform-agnostic conversion
  const len = data.length;
  for (let i = 0; i < len; i += 3) {
    const byte1 = data[i];
    const byte2 = i + 1 < len ? data[i + 1] : 0;
    const byte3 = i + 2 < len ? data[i + 2] : 0;

    const triplet = (byte1 << 16) | (byte2 << 8) | byte3;

    base64 += BASE64_CHARS[(triplet >> 18) & 0x3f];
    base64 += BASE64_CHARS[(triplet >> 12) & 0x3f];
    base64 += i + 1 < len ? BASE64_CHARS[(triplet >> 6) & 0x3f] : '';
    base64 += i + 2 < len ? BASE64_CHARS[triplet & 0x3f] : '';
  }

  // Convert to base64url (replace + with -, / with _)
  // Remove padding (=)
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode a base64url string to Uint8Array
 *
 * @param str - Base64URL encoded string
 * @returns Decoded bytes
 * @throws Error if the input contains invalid characters
 */
export function base64urlDecode(str: string): Uint8Array {
  // Validate input contains only valid base64url characters
  // Valid: A-Z, a-z, 0-9, -, _
  if (!/^[A-Za-z0-9_-]*$/.test(str)) {
    throw new Error('Invalid base64url string: contains invalid characters');
  }

  // Convert base64url to base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if needed
  while (base64.length % 4) {
    base64 += '=';
  }

  // Decode base64
  const len = base64.length;
  const paddingLen = base64.endsWith('==') ? 2 : base64.endsWith('=') ? 1 : 0;
  const outputLen = (len * 3) / 4 - paddingLen;
  const output = new Uint8Array(outputLen);

  let outputIndex = 0;
  for (let i = 0; i < len; i += 4) {
    const byte1 = BASE64_LOOKUP[base64.charCodeAt(i)];
    const byte2 = BASE64_LOOKUP[base64.charCodeAt(i + 1)];
    const byte3 = BASE64_LOOKUP[base64.charCodeAt(i + 2)];
    const byte4 = BASE64_LOOKUP[base64.charCodeAt(i + 3)];

    const triplet = (byte1 << 18) | (byte2 << 12) | (byte3 << 6) | byte4;

    if (outputIndex < outputLen) output[outputIndex++] = (triplet >> 16) & 0xff;
    if (outputIndex < outputLen) output[outputIndex++] = (triplet >> 8) & 0xff;
    if (outputIndex < outputLen) output[outputIndex++] = triplet & 0xff;
  }

  return output;
}

/**
 * Encode a string to base64url
 *
 * @param str - String to encode (UTF-8)
 * @returns Base64URL encoded string
 */
export function stringToBase64url(str: string): string {
  const encoder = new TextEncoder();
  return base64urlEncode(encoder.encode(str));
}

/**
 * Decode a base64url string to string
 *
 * @param base64url - Base64URL encoded string
 * @returns Decoded string (UTF-8)
 */
export function base64urlToString(base64url: string): string {
  const decoder = new TextDecoder();
  return decoder.decode(base64urlDecode(base64url));
}

// Base64 character set
const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

// Lookup table for decoding
const BASE64_LOOKUP = new Uint8Array(256);
for (let i = 0; i < BASE64_CHARS.length; i++) {
  BASE64_LOOKUP[BASE64_CHARS.charCodeAt(i)] = i;
}
