/**
 * Device Authorization Flow Types
 * RFC 8628: OAuth 2.0 Device Authorization Grant
 *
 * Used for devices with limited input capabilities (TVs, CLI tools, IoT devices).
 */

/**
 * Device authorization response from the server (RFC 8628 §3.2)
 */
export interface DeviceAuthorizationResponse {
  /** Device verification code (for token requests) */
  device_code: string;
  /** User-facing code to enter at verification_uri */
  user_code: string;
  /** URI where the user should go to enter the code */
  verification_uri: string;
  /** Complete URI with user_code embedded (optional) */
  verification_uri_complete?: string;
  /** Lifetime of device_code and user_code in seconds */
  expires_in: number;
  /** Minimum polling interval in seconds (default: 5) */
  interval?: number;
}

/**
 * Device flow state maintained by the client
 */
export interface DeviceFlowState {
  /** Device code (used for polling) */
  deviceCode: string;
  /** User code (displayed to user) */
  userCode: string;
  /** Verification URI (user goes here) */
  verificationUri: string;
  /** Complete verification URI with code (if provided) */
  verificationUriComplete?: string;
  /** Absolute expiration time (epoch seconds) */
  expiresAt: number;
  /**
   * Polling interval in seconds (RFC 8628)
   *
   * IMPORTANT: This value is in SECONDS, not milliseconds.
   * When using with setTimeout, multiply by 1000.
   */
  interval: number;
}

/**
 * Poll result from Device Flow
 *
 * Core SDK returns "facts" only - UX events are the responsibility
 * of upper-layer SDKs (web/react/svelte).
 */
export type DeviceFlowPollResult =
  | DeviceFlowPendingResult
  | DeviceFlowCompletedResult
  | DeviceFlowSlowDownResult
  | DeviceFlowExpiredResult
  | DeviceFlowAccessDeniedResult;

/**
 * Authorization pending - user hasn't completed auth yet
 */
export interface DeviceFlowPendingResult {
  status: 'pending';
  /**
   * Seconds until next poll attempt (RFC 8628)
   *
   * IMPORTANT: This value is in SECONDS.
   * Use `retryAfter * 1000` for setTimeout in JavaScript.
   */
  retryAfter: number;
}

/**
 * Authorization completed - tokens received
 */
export interface DeviceFlowCompletedResult {
  status: 'completed';
  /** Received tokens */
  tokens: import('./token.js').TokenSet;
}

/**
 * Slow down - polling too fast
 */
export interface DeviceFlowSlowDownResult {
  status: 'slow_down';
  /**
   * New interval in seconds (server-specified)
   *
   * IMPORTANT: This value is in SECONDS.
   * The polling interval should be increased to this value.
   */
  retryAfter: number;
}

/**
 * Device code expired - user needs to start over
 */
export interface DeviceFlowExpiredResult {
  status: 'expired';
}

/**
 * Access denied - user denied the authorization request
 */
export interface DeviceFlowAccessDeniedResult {
  status: 'access_denied';
}

/**
 * Options for starting device authorization
 */
export interface DeviceFlowStartOptions {
  /** Scopes to request */
  scope?: string;
  /** Additional parameters */
  extraParams?: Record<string, string>;
}
