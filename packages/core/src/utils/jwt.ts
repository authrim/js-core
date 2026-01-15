/**
 * JWT Utilities
 *
 * Note: This module only provides decoding (parsing) functionality.
 * JWT signature verification MUST be performed by the server.
 * Never trust decoded JWT claims without server-side verification.
 */

import { base64urlToString } from './base64url.js';
import type { IdTokenClaims } from '../types/oidc.js';

/**
 * JWT Header
 */
export interface JwtHeader {
  alg: string;
  typ?: string;
  kid?: string;
  [key: string]: unknown;
}

/**
 * Decoded JWT structure
 */
export interface DecodedJwt<T = Record<string, unknown>> {
  header: JwtHeader;
  payload: T;
  signature: string;
}

/**
 * Decode a JWT without verifying the signature
 *
 * WARNING: This function does NOT verify the JWT signature.
 * Use this only for reading claims after the token has been
 * validated by the authorization server.
 *
 * @param jwt - JWT string to decode
 * @returns Decoded JWT parts
 * @throws Error if the JWT format is invalid
 */
export function decodeJwt<T = Record<string, unknown>>(jwt: string): DecodedJwt<T> {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format: expected 3 parts');
  }

  const [headerB64, payloadB64, signature] = parts;

  try {
    const header = JSON.parse(base64urlToString(headerB64)) as JwtHeader;
    const payload = JSON.parse(base64urlToString(payloadB64)) as T;

    return {
      header,
      payload,
      signature,
    };
  } catch {
    throw new Error('Invalid JWT format: failed to decode');
  }
}

/**
 * Decode an ID token and extract claims
 *
 * WARNING: This function does NOT verify the ID token.
 * The token MUST be verified by the authorization server before use.
 *
 * @param idToken - ID token string
 * @returns ID token claims
 */
export function decodeIdToken(idToken: string): IdTokenClaims {
  const decoded = decodeJwt<IdTokenClaims>(idToken);
  return decoded.payload;
}

/**
 * Check if a JWT is expired
 *
 * @param jwt - Decoded JWT payload with exp claim
 * @param skewSeconds - Clock skew tolerance in seconds (default: 0)
 * @returns true if expired
 */
export function isJwtExpired(payload: { exp?: number }, skewSeconds: number = 0): boolean {
  if (payload.exp === undefined) {
    return false; // No expiration
  }

  const now = Math.floor(Date.now() / 1000);
  return payload.exp + skewSeconds < now;
}

/**
 * Get the nonce claim from an ID token
 *
 * @param idToken - ID token string
 * @returns nonce value or undefined
 */
export function getIdTokenNonce(idToken: string): string | undefined {
  try {
    const claims = decodeIdToken(idToken);
    return claims.nonce;
  } catch {
    return undefined;
  }
}
