import { decodeJwt } from '../utils/jwt.js';
import { AuthrimError } from '../types/errors.js';
import type { LogoutTokenClaims } from '../types/session-management.js';

const BACK_CHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

export interface BackChannelLogoutValidationOptions {
  issuer: string;
  clientId: string;
  maxAgeSeconds?: number;
  now?: number;
}

export type BackChannelLogoutTokenVerifier = (
  logoutToken: string,
  options: Pick<BackChannelLogoutValidationOptions, 'issuer' | 'clientId'>
) => Promise<LogoutTokenClaims & Record<string, unknown>>;

export interface BackChannelLogoutValidatorConfig {
  /**
   * Verifies the logout token signature and returns the verified claims.
   *
   * Implementations should use the issuer's JWKS and reject unsupported
   * algorithms before returning claims.
   */
  verifyJwt: BackChannelLogoutTokenVerifier;
}

export interface BackChannelLogoutValidationResult {
  claims: LogoutTokenClaims;
}

export class BackChannelLogoutValidator {
  constructor(private readonly config: BackChannelLogoutValidatorConfig) {
    if (!config?.verifyJwt) {
      throw new AuthrimError(
        'configuration_error',
        'BackChannelLogoutValidator requires a logout token signature verifier'
      );
    }
  }

  async validate(
    logoutToken: string,
    options: BackChannelLogoutValidationOptions
  ): Promise<BackChannelLogoutValidationResult> {
    let claims: LogoutTokenClaims & Record<string, unknown>;
    try {
      const decoded = decodeJwt<LogoutTokenClaims & Record<string, unknown>>(logoutToken);
      if (!decoded.header.alg || decoded.header.alg.toLowerCase() === 'none') {
        throw new AuthrimError('invalid_token', 'Logout token uses an unsupported algorithm');
      }
      if (!decoded.signature) {
        throw new AuthrimError('invalid_token', 'Logout token signature is required');
      }
      claims = await this.config.verifyJwt(logoutToken, {
        issuer: options.issuer,
        clientId: options.clientId,
      });
    } catch (error) {
      if (error instanceof AuthrimError) {
        throw error;
      }
      throw new AuthrimError('invalid_token', 'Failed to verify logout token', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    return this.validateClaims(claims, options);
  }

  /**
   * Validate claims that have already passed logout token signature verification.
   */

  validateClaims(
    claims: LogoutTokenClaims & Record<string, unknown>,
    options: BackChannelLogoutValidationOptions
  ): BackChannelLogoutValidationResult {
    if (claims.iss !== options.issuer) {
      throw new AuthrimError(
        'invalid_issuer',
        'Logout token issuer does not match expected issuer'
      );
    }

    const audList = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audList.includes(options.clientId)) {
      throw new AuthrimError(
        'invalid_audience',
        'Logout token audience does not contain client_id'
      );
    }

    if (typeof claims.iat !== 'number' || !Number.isFinite(claims.iat)) {
      throw new AuthrimError('invalid_token', 'Logout token iat claim is required');
    }
    const now = options.now ?? Math.floor(Date.now() / 1000);
    const maxAgeSeconds = options.maxAgeSeconds ?? 120;
    if (claims.iat > now + 60 || now - claims.iat > maxAgeSeconds) {
      throw new AuthrimError('invalid_token', 'Logout token iat is outside the allowed window');
    }

    if (!claims.jti) {
      throw new AuthrimError('invalid_token', 'Logout token jti claim is required');
    }
    if (
      !claims.events ||
      !Object.prototype.hasOwnProperty.call(claims.events, BACK_CHANNEL_LOGOUT_EVENT)
    ) {
      throw new AuthrimError('invalid_token', 'Logout token back-channel logout event is required');
    }
    if (claims.nonce !== undefined) {
      throw new AuthrimError('invalid_token', 'Logout token must not contain nonce');
    }
    if (!claims.sub && !claims.sid) {
      throw new AuthrimError('invalid_token', 'Logout token requires sub or sid');
    }

    return { claims };
  }
}
