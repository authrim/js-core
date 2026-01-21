/**
 * Client Authentication Utilities
 * RFC 6749 §2.3, RFC 7521, RFC 7523
 *
 * Provides utilities for building client authentication headers and body parameters
 * for various authentication methods.
 */

import type { ClientCredentials, ClientAssertionClaims } from '../types/client-auth.js';
import { AuthrimError } from '../types/errors.js';

/**
 * Client authentication result
 */
export interface ClientAuthResult {
  /** Headers to include in the request */
  headers: Record<string, string>;
  /** Body parameters to include in the request */
  bodyParams: Record<string, string>;
}

/**
 * Build client authentication headers and body parameters
 *
 * @param credentials - Client credentials configuration
 * @param clientId - Client ID
 * @param tokenEndpoint - Token endpoint URL (used as audience for private_key_jwt)
 * @returns Headers and body parameters for authentication
 * @throws AuthrimError with code 'insecure_client_auth' if method='none' without dangerouslyAllowInsecure
 * @throws AuthrimError with code 'invalid_client_authentication' for invalid credentials
 */
export async function buildClientAuthentication(
  credentials: ClientCredentials,
  clientId: string,
  tokenEndpoint: string
): Promise<ClientAuthResult> {
  const headers: Record<string, string> = {};
  const bodyParams: Record<string, string> = {};

  switch (credentials.method) {
    case 'client_secret_basic': {
      // RFC 6749 §2.3.1 - HTTP Basic Authentication
      const encodedCredentials = btoa(`${clientId}:${credentials.clientSecret}`);
      headers['Authorization'] = `Basic ${encodedCredentials}`;
      break;
    }

    case 'client_secret_post': {
      // RFC 6749 §2.3.1 - Client credentials in request body
      bodyParams['client_id'] = clientId;
      bodyParams['client_secret'] = credentials.clientSecret;
      break;
    }

    case 'private_key_jwt': {
      // RFC 7521, RFC 7523 - JWT Client Authentication
      const now = Math.floor(Date.now() / 1000);

      const claims: ClientAssertionClaims = {
        iss: clientId,
        sub: clientId,
        aud: tokenEndpoint,
        jti: generateJti(),
        exp: now + 300, // 5 minutes expiry
        iat: now,
      };

      let assertion: string;
      try {
        assertion = await credentials.signJwt(claims);
      } catch (error) {
        throw new AuthrimError(
          'invalid_client_authentication',
          'Failed to sign client assertion JWT',
          { cause: error instanceof Error ? error : undefined }
        );
      }

      bodyParams['client_id'] = clientId;
      bodyParams['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
      bodyParams['client_assertion'] = assertion;
      break;
    }

    case 'none': {
      // Public client - only client_id in body
      // SECURITY: Require explicit opt-in for insecure auth
      if (!('dangerouslyAllowInsecure' in credentials) || credentials.dangerouslyAllowInsecure !== true) {
        throw new AuthrimError(
          'insecure_client_auth',
          'Client authentication method "none" requires dangerouslyAllowInsecure: true'
        );
      }
      bodyParams['client_id'] = clientId;
      break;
    }

    default: {
      // Exhaustive check
      const _exhaustive: never = credentials;
      throw new AuthrimError(
        'invalid_client_authentication',
        `Unknown client authentication method: ${(_exhaustive as ClientCredentials).method}`
      );
    }
  }

  return { headers, bodyParams };
}

/**
 * Generate a unique JWT ID (jti)
 *
 * Uses crypto.randomUUID if available, falls back to timestamp + random.
 */
function generateJti(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  // Fallback for environments without crypto.randomUUID
  return `${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
}
