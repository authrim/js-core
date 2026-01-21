/**
 * JARM Validator
 * JWT Secured Authorization Response Mode (JARM)
 *
 * JARM allows authorization servers to return authorization response
 * parameters in a signed JWT, providing:
 * - Response integrity protection
 * - Response authenticity verification
 * - Confidentiality (when encrypted)
 *
 * The response JWT is returned in the 'response' parameter of the
 * authorization callback.
 */

import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import type {
  JARMResponseClaims,
  JARMValidationOptions,
  JARMValidationResult,
  JARMValidatorConfig,
} from '../types/jarm.js';
import { AuthrimError } from '../types/errors.js';
import { timingSafeEqual } from '../utils/timing-safe.js';

/**
 * JARM Validator
 *
 * Validates JWT-secured authorization responses.
 */
export class JARMValidator {
  private readonly config: JARMValidatorConfig;

  constructor(config: JARMValidatorConfig) {
    this.config = config;
  }

  /**
   * Validate a JARM response
   *
   * @param discovery - OIDC discovery document
   * @param response - The JWT response string from the 'response' parameter
   * @param options - Validation options
   * @returns Validated authorization code and state
   * @throws AuthrimError with code 'jarm_validation_error' if validation fails
   * @throws AuthrimError with code 'jarm_signature_invalid' if signature verification fails
   */
  async validateResponse(
    discovery: OIDCDiscoveryDocument,
    response: string,
    options: JARMValidationOptions
  ): Promise<JARMValidationResult> {
    const clockSkew = options.clockSkewSeconds ?? 60;

    // Verify JWT signature and get claims
    let claims: JARMResponseClaims;
    try {
      claims = await this.config.verifyJwt(response, discovery.issuer);
    } catch (error) {
      throw new AuthrimError(
        'jarm_signature_invalid',
        'Failed to verify JARM response signature',
        { cause: error instanceof Error ? error : undefined }
      );
    }

    // Validate issuer
    if (claims.iss !== discovery.issuer) {
      throw new AuthrimError(
        'jarm_validation_error',
        'JARM response issuer does not match discovery issuer',
        {
          details: {
            expected: discovery.issuer,
            actual: claims.iss,
          },
        }
      );
    }

    // Validate audience (must be client_id or array containing client_id)
    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audience.includes(options.clientId)) {
      throw new AuthrimError(
        'jarm_validation_error',
        'JARM response audience does not match client_id',
        {
          details: {
            expected: options.clientId,
            actual: claims.aud,
          },
        }
      );
    }

    // Validate expiration
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp && claims.exp + clockSkew < now) {
      throw new AuthrimError(
        'jarm_validation_error',
        'JARM response has expired'
      );
    }

    // Validate iat if present (not in the future)
    if (claims.iat && claims.iat - clockSkew > now) {
      throw new AuthrimError(
        'jarm_validation_error',
        'JARM response iat is in the future'
      );
    }

    // Check for OAuth error in response
    if (claims.error) {
      throw new AuthrimError('oauth_error', claims.error_description ?? claims.error, {
        details: {
          error: claims.error,
          error_description: claims.error_description,
          error_uri: claims.error_uri,
        },
      });
    }

    // Validate state (constant-time comparison)
    if (!claims.state) {
      throw new AuthrimError(
        'jarm_validation_error',
        'JARM response is missing state claim'
      );
    }
    if (!timingSafeEqual(claims.state, options.expectedState)) {
      throw new AuthrimError(
        'jarm_validation_error',
        'JARM response state does not match expected state'
      );
    }

    // Validate code is present
    if (!claims.code) {
      throw new AuthrimError(
        'jarm_validation_error',
        'JARM response is missing authorization code'
      );
    }

    return {
      code: claims.code,
      state: claims.state,
    };
  }

  /**
   * Parse a JARM response from callback URL
   *
   * Extracts the 'response' parameter from the callback URL.
   *
   * @param callbackUrl - Full callback URL or query string
   * @returns The response JWT, or null if not present
   */
  static extractResponseFromCallback(callbackUrl: string): string | null {
    let searchParams: URLSearchParams;

    if (callbackUrl.includes('?')) {
      const url = callbackUrl.startsWith('http')
        ? new URL(callbackUrl)
        : new URL(callbackUrl, 'https://dummy.local');
      searchParams = url.searchParams;
    } else {
      searchParams = new URLSearchParams(callbackUrl);
    }

    return searchParams.get('response');
  }
}
