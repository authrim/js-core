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

export interface BackChannelLogoutValidationResult {
  claims: LogoutTokenClaims;
}

export class BackChannelLogoutValidator {
  validate(
    logoutToken: string,
    options: BackChannelLogoutValidationOptions
  ): BackChannelLogoutValidationResult {
    let claims: LogoutTokenClaims & Record<string, unknown>;
    try {
      claims = decodeJwt<LogoutTokenClaims & Record<string, unknown>>(logoutToken).payload;
    } catch (error) {
      throw new AuthrimError('invalid_token', 'Failed to decode logout token', {
        cause: error instanceof Error ? error : undefined,
      });
    }

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
