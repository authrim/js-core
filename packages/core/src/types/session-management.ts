/**
 * Session Management Types
 * OpenID Connect Session Management 1.0
 *
 * These types support session management via check_session_iframe
 * and related specifications.
 *
 * NOTE: Actual implementation of session management (postMessage communication,
 * iframe handling) is the responsibility of the web SDK (@authrim/web).
 * Core SDK only provides type definitions.
 */

/**
 * Session state from check_session_iframe
 */
export type SessionState = string;

/**
 * Check session iframe message
 *
 * Format: "client_id session_state"
 */
export interface CheckSessionMessage {
  /** Client ID */
  clientId: string;
  /** Session state from authentication response */
  sessionState: SessionState;
}

/**
 * Check session iframe response
 */
export type CheckSessionResponse = 'changed' | 'unchanged' | 'error';

/**
 * Session management configuration
 */
export interface SessionManagementConfig {
  /** check_session_iframe URL from discovery */
  checkSessionIframe?: string;
  /** Polling interval in milliseconds (default: 2000) */
  pollIntervalMs?: number;
  /** Whether session management is enabled */
  enabled: boolean;
}

/**
 * Session change event
 */
export interface SessionChangeEvent {
  /** Previous session state */
  previousState: SessionState | null;
  /** Current session state */
  currentState: SessionState | null;
  /** Whether the session is still valid */
  isValid: boolean;
}

/**
 * Front-Channel Logout Types
 * OpenID Connect Front-Channel Logout 1.0
 *
 * Front-channel logout allows the OP to notify RPs of logout events
 * via browser redirects.
 *
 * NOTE: Actual implementation of front-channel logout (iframe handling)
 * is the responsibility of the web SDK (@authrim/web).
 * Core SDK only provides type definitions.
 */

/**
 * Front-channel logout request parameters
 */
export interface FrontChannelLogoutParams {
  /** Issuer identifier */
  iss?: string;
  /** Session ID */
  sid?: string;
}

/**
 * Front-channel logout URL builder options
 */
export interface FrontChannelLogoutUrlOptions {
  /** Base logout URI registered with the OP */
  logoutUri: string;
  /** Whether to include issuer parameter */
  includeIssuer?: boolean;
  /** Whether to include session ID parameter */
  includeSessionId?: boolean;
}

/**
 * Back-Channel Logout Types
 * OpenID Connect Back-Channel Logout 1.0
 *
 * Back-channel logout allows the OP to notify RPs of logout events
 * via direct HTTP calls (server-to-server).
 *
 * NOTE: This is typically handled server-side, not in the browser.
 * Included here for completeness of type definitions.
 */

/**
 * Logout token claims (for back-channel logout)
 */
export interface LogoutTokenClaims {
  /** Issuer */
  iss: string;
  /** Subject */
  sub?: string;
  /** Audience */
  aud: string | string[];
  /** Issued at time */
  iat: number;
  /** JWT ID */
  jti: string;
  /** Events claim (must contain logout event) */
  events: {
    'http://schemas.openid.net/event/backchannel-logout': Record<string, never>;
  };
  /** Session ID (if back-channel logout session is supported) */
  sid?: string;
}
