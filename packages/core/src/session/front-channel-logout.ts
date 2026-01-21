/**
 * Front-Channel Logout URL Builder
 *
 * Implements OpenID Connect Front-Channel Logout 1.0
 * https://openid.net/specs/openid-connect-frontchannel-1_0.html
 *
 * Front-channel logout allows the OP to notify RPs of logout events
 * via browser redirects (iframes loaded by the OP's logout page).
 */

import type { FrontChannelLogoutParams, FrontChannelLogoutUrlOptions } from '../types/session-management.js';
import { timingSafeEqual } from '../utils/timing-safe.js';

/**
 * Result of building a front-channel logout URL
 */
export interface FrontChannelLogoutUrlResult {
  /** Complete logout URL with query parameters */
  url: string;
  /** Parameters included in the URL */
  params: FrontChannelLogoutParams;
}

/**
 * Parameters for building a front-channel logout URL
 */
export interface FrontChannelLogoutBuildParams {
  /** Issuer identifier to include (optional) */
  iss?: string;
  /** Session ID to include (optional) */
  sid?: string;
}

/**
 * Validation options for front-channel logout requests
 */
export interface FrontChannelLogoutValidationOptions {
  /** Expected issuer (for validation) */
  issuer?: string;
  /** Expected session ID (for validation) */
  sessionId?: string;
  /** Require issuer parameter */
  requireIss?: boolean;
  /** Require session ID parameter */
  requireSid?: boolean;
}

/**
 * Result of front-channel logout request validation
 */
export interface FrontChannelLogoutValidationResult {
  /** Whether the request is valid */
  valid: boolean;
  /** Parsed parameters (if valid) */
  params?: FrontChannelLogoutParams;
  /** Error message (if invalid) */
  error?: string;
}

/**
 * Front-Channel Logout URL Builder
 *
 * Builds and validates front-channel logout URLs per OIDC Front-Channel Logout 1.0.
 *
 * Usage (OP side - building logout URL to load in iframe):
 * ```typescript
 * const builder = new FrontChannelLogoutUrlBuilder();
 * const result = builder.build(
 *   { logoutUri: 'https://rp.example.com/logout', includeIssuer: true, includeSessionId: true },
 *   { iss: 'https://op.example.com', sid: 'session-123' }
 * );
 * // result.url -> load in iframe
 * ```
 *
 * Usage (RP side - validating incoming logout request):
 * ```typescript
 * const result = builder.validateRequest(window.location.href, {
 *   issuer: 'https://op.example.com',
 *   requireIss: true
 * });
 * if (result.valid) {
 *   // Perform local logout
 * }
 * ```
 */
export class FrontChannelLogoutUrlBuilder {
  /**
   * Build a front-channel logout URL
   *
   * @param options - URL configuration options
   * @param params - Parameters to include in the URL
   * @returns Built URL and included parameters
   */
  build(
    options: FrontChannelLogoutUrlOptions,
    params: FrontChannelLogoutBuildParams
  ): FrontChannelLogoutUrlResult {
    const url = new URL(options.logoutUri);
    const resultParams: FrontChannelLogoutParams = {};

    if (options.includeIssuer && params.iss) {
      url.searchParams.set('iss', params.iss);
      resultParams.iss = params.iss;
    }

    if (options.includeSessionId && params.sid) {
      url.searchParams.set('sid', params.sid);
      resultParams.sid = params.sid;
    }

    return {
      url: url.toString(),
      params: resultParams,
    };
  }

  /**
   * Parse parameters from a front-channel logout URL
   *
   * @param url - URL or URL string to parse
   * @returns Parsed parameters
   */
  parseParams(url: string | URL): FrontChannelLogoutParams {
    const urlObj = typeof url === 'string' ? new URL(url) : url;
    const params: FrontChannelLogoutParams = {};

    const iss = urlObj.searchParams.get('iss');
    if (iss) {
      params.iss = iss;
    }

    const sid = urlObj.searchParams.get('sid');
    if (sid) {
      params.sid = sid;
    }

    return params;
  }

  /**
   * Validate a front-channel logout request
   *
   * Uses constant-time comparison for security-sensitive values to prevent timing attacks.
   *
   * @param url - URL to validate
   * @param expected - Expected values and requirements
   * @returns Validation result
   */
  validateRequest(
    url: string | URL,
    expected: FrontChannelLogoutValidationOptions = {}
  ): FrontChannelLogoutValidationResult {
    let params: FrontChannelLogoutParams;

    try {
      params = this.parseParams(url);
    } catch {
      return {
        valid: false,
        error: 'Invalid URL format',
      };
    }

    // Check required parameters
    if (expected.requireIss && !params.iss) {
      return {
        valid: false,
        error: 'Missing required iss parameter',
      };
    }

    if (expected.requireSid && !params.sid) {
      return {
        valid: false,
        error: 'Missing required sid parameter',
      };
    }

    // Validate issuer if provided and expected
    // Use constant-time comparison to prevent timing attacks
    if (expected.issuer && params.iss && !timingSafeEqual(params.iss, expected.issuer)) {
      return {
        valid: false,
        error: 'Issuer validation failed',
      };
    }

    // Validate session ID if provided and expected
    // Use constant-time comparison to prevent timing attacks
    if (expected.sessionId && params.sid && !timingSafeEqual(params.sid, expected.sessionId)) {
      return {
        valid: false,
        error: 'Session ID validation failed',
      };
    }

    return {
      valid: true,
      params,
    };
  }
}
