/**
 * Session State Calculator
 *
 * Implements OIDC Session Management 1.0 specification
 * https://openid.net/specs/openid-connect-session-1_0.html
 *
 * session_state = hash(client_id + " " + origin + " " + browser_state + salt) + "." + salt
 */

import type { CryptoProvider } from '../providers/crypto.js';
import { base64urlEncode } from '../utils/base64url.js';
import { timingSafeEqual } from '../utils/timing-safe.js';

/**
 * Parameters for calculating session_state
 */
export interface SessionStateParams {
  /** OAuth client_id */
  clientId: string;
  /** RP origin (e.g., "https://example.com") */
  origin: string;
  /**
   * OP-managed browser state (opaque value)
   *
   * Per OIDC Session Management 1.0 spec, this is called "browser_state" but is actually
   * an opaque value managed by the OP to identify the session at the OP.
   * It is NOT a value managed by the RP's browser.
   */
  opBrowserState: string;
  /** Optional salt (generated if not provided) */
  salt?: string;
}

/**
 * Result of session_state calculation
 */
export interface SessionStateResult {
  /** Full session_state value (hash.salt) */
  sessionState: string;
  /** Hash portion of session_state */
  hash: string;
  /** Salt used in calculation */
  salt: string;
}

/**
 * Options for SessionStateCalculator
 */
export interface SessionStateCalculatorOptions {
  /** Crypto provider for hashing */
  crypto: CryptoProvider;
}

/**
 * Session State Calculator
 *
 * Calculates and validates session_state values per OIDC Session Management 1.0.
 *
 * Usage (OP side - calculating session_state to include in auth response):
 * ```typescript
 * const calculator = new SessionStateCalculator({ crypto });
 * const result = await calculator.calculate({
 *   clientId: 'my-client',
 *   origin: 'https://rp.example.com',
 *   opBrowserState: 'op-session-id-xyz'
 * });
 * // result.sessionState -> include in auth response
 * ```
 *
 * Usage (RP check_session_iframe - validating session state):
 * ```typescript
 * const isValid = await calculator.validate(sessionState, {
 *   clientId: 'my-client',
 *   origin: 'https://rp.example.com',
 *   opBrowserState: 'op-session-id-xyz'
 * });
 * ```
 */
export class SessionStateCalculator {
  private readonly crypto: CryptoProvider;

  constructor(options: SessionStateCalculatorOptions) {
    this.crypto = options.crypto;
  }

  /**
   * Calculate session_state
   *
   * Per OIDC Session Management 1.0:
   * session_state = hash(client_id + " " + origin + " " + browser_state + salt) + "." + salt
   *
   * @param params - Parameters for calculation
   * @returns Session state result
   */
  async calculate(params: SessionStateParams): Promise<SessionStateResult> {
    // Generate salt if not provided (16 random bytes, base64url encoded)
    let salt = params.salt;
    if (!salt) {
      const saltBytes = await this.crypto.randomBytes(16);
      salt = base64urlEncode(saltBytes);
    }

    // Build the string to hash
    // Note: The spec uses space as delimiter
    const hashInput =
      params.clientId + ' ' + params.origin + ' ' + params.opBrowserState + salt;

    // Compute SHA-256 hash
    const hashBytes = await this.crypto.sha256(hashInput);
    const hash = base64urlEncode(hashBytes);

    // session_state = hash + "." + salt
    const sessionState = hash + '.' + salt;

    return {
      sessionState,
      hash,
      salt,
    };
  }

  /**
   * Validate session_state
   *
   * Uses constant-time comparison to prevent timing attacks.
   *
   * @param sessionState - session_state value to validate
   * @param params - Parameters that should match (without salt, extracted from sessionState)
   * @returns true if valid
   */
  async validate(
    sessionState: string,
    params: Omit<SessionStateParams, 'salt'>
  ): Promise<boolean> {
    const parsed = this.parse(sessionState);
    if (!parsed) {
      return false;
    }

    // Recalculate with the extracted salt
    const calculated = await this.calculate({
      ...params,
      salt: parsed.salt,
    });

    // Use constant-time comparison to prevent timing attacks
    return timingSafeEqual(calculated.sessionState, sessionState);
  }

  /**
   * Parse session_state into hash and salt components
   *
   * @param sessionState - session_state value to parse
   * @returns Parsed components or null if invalid format
   */
  parse(sessionState: string): { hash: string; salt: string } | null {
    // Maximum lengths to prevent DoS via oversized input
    // SHA-256 base64url is ~43 chars, salt is typically ~22 chars
    const MAX_SESSION_STATE_LENGTH = 512;
    const MAX_HASH_LENGTH = 256;
    const MAX_SALT_LENGTH = 128;

    if (!sessionState || typeof sessionState !== 'string') {
      return null;
    }

    // Length validation to prevent DoS
    if (sessionState.length > MAX_SESSION_STATE_LENGTH) {
      return null;
    }

    const dotIndex = sessionState.lastIndexOf('.');
    if (dotIndex === -1 || dotIndex === 0 || dotIndex === sessionState.length - 1) {
      return null;
    }

    const hash = sessionState.substring(0, dotIndex);
    const salt = sessionState.substring(dotIndex + 1);

    // Basic validation - both parts should be non-empty and look like base64url
    if (!hash || !salt) {
      return null;
    }

    // Length validation for individual components
    if (hash.length > MAX_HASH_LENGTH || salt.length > MAX_SALT_LENGTH) {
      return null;
    }

    // Base64url validation: only A-Z, a-z, 0-9, -, _ allowed
    const base64urlRegex = /^[A-Za-z0-9_-]+$/;
    if (!base64urlRegex.test(hash) || !base64urlRegex.test(salt)) {
      return null;
    }

    return { hash, salt };
  }
}
