/**
 * JAR Builder
 * RFC 9101: JWT-Secured Authorization Request (JAR)
 *
 * JAR provides a way to send authorization request parameters
 * in a signed (and optionally encrypted) JWT, ensuring:
 * - Integrity protection of parameters
 * - Non-repudiation
 * - Confidentiality (when encrypted)
 *
 * The signed JWT is sent as the 'request' parameter in the authorization URL,
 * or can be passed by reference using the 'request_uri' parameter (with PAR).
 */

import type {
  JARBuilderConfig,
  JARRequestOptions,
  JARRequestObjectClaims,
} from '../types/jar.js';
import { AuthrimError } from '../types/errors.js';

/**
 * JAR Builder
 *
 * Builds signed JWT request objects for authorization requests.
 */
export class JARBuilder {
  private readonly config: JARBuilderConfig;

  constructor(config: JARBuilderConfig) {
    this.config = config;
  }

  /**
   * Build a signed request object
   *
   * @param options - Request options
   * @returns Signed JWT request object
   * @throws AuthrimError with code 'jar_signing_error' if signing fails
   */
  async buildRequestObject(options: JARRequestOptions): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const lifetime = this.config.lifetime ?? 300; // 5 minutes default

    // Build JWT header
    const header: Record<string, unknown> = {
      alg: this.config.algorithm ?? 'RS256',
      typ: 'oauth-authz-req+jwt',
    };

    if (this.config.keyId) {
      header['kid'] = this.config.keyId;
    }

    // Build JWT claims (request object)
    const claims: JARRequestObjectClaims = {
      iss: options.clientId,
      aud: options.issuer,
      response_type: options.responseType ?? 'code',
      client_id: options.clientId,
      redirect_uri: options.redirectUri,
      scope: options.scope,
      state: options.state,
      nonce: options.nonce,
      code_challenge: options.codeChallenge,
      code_challenge_method: options.codeChallengeMethod,
      iat: now,
      exp: now + lifetime,
      jti: this.generateJti(),
    };

    // Add optional OIDC parameters
    if (options.prompt) {
      claims.prompt = options.prompt;
    }
    if (options.loginHint) {
      claims.login_hint = options.loginHint;
    }
    if (options.acrValues) {
      claims.acr_values = options.acrValues;
    }

    // Add extra claims (with protection for core claims)
    if (options.extraClaims) {
      const protectedClaims = new Set([
        'iss',
        'aud',
        'response_type',
        'client_id',
        'redirect_uri',
        'scope',
        'state',
        'nonce',
        'code_challenge',
        'code_challenge_method',
        'iat',
        'exp',
        'jti',
        'nbf',
      ]);

      for (const [key, value] of Object.entries(options.extraClaims)) {
        if (!protectedClaims.has(key)) {
          claims[key] = value;
        }
      }
    }

    // Sign the JWT
    try {
      return await this.config.signJwt(header, claims);
    } catch (error) {
      throw new AuthrimError(
        'jar_signing_error',
        'Failed to sign JAR request object',
        { cause: error instanceof Error ? error : undefined }
      );
    }
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

/**
 * Check if JAR is required by the authorization server
 *
 * @param discovery - OIDC discovery document
 * @returns True if require_signed_request_object is true
 */
export function isJarRequired(discovery: { require_signed_request_object?: boolean }): boolean {
  return discovery.require_signed_request_object === true;
}
