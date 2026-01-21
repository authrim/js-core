/**
 * Event Types
 *
 * Unified event system for SDK observability.
 * All events follow the namespace convention: auth:*, token:*, session:*, state:*, error:*, warning:*, debug:*
 */

import type { AuthrimError, AuthrimErrorRemediation } from '../types/errors.js';
import type { TokenTypeUri } from '../types/token.js';
import type { UserInfo } from '../types/oidc.js';

// =============================================================================
// Base Event Payload
// =============================================================================

/**
 * Base event payload - all events include these fields
 */
export interface BaseEventPayload {
  /** Event timestamp (Date.now()) */
  timestamp: number;
  /** Event source */
  source: 'core' | 'web';
  /** Operation tracking ID (maintained from redirect start to callback complete) */
  operationId?: string;
}

// =============================================================================
// auth:* - Authentication Lifecycle Events
// =============================================================================

/**
 * SDK initialization complete
 */
export interface AuthInitEvent extends BaseEventPayload {
  /** Client ID */
  clientId: string;
  /** Issuer URL */
  issuer: string;
}

/**
 * Auth redirecting event data
 */
export interface AuthRedirectingEvent extends BaseEventPayload {
  /** Authorization URL */
  url: string;
}

/**
 * Auth callback received
 */
export interface AuthCallbackEvent extends BaseEventPayload {
  /** Authorization code */
  code: string;
  /** State parameter */
  state: string;
}

/**
 * Callback processing started
 */
export interface AuthCallbackProcessingEvent extends BaseEventPayload {
  /** State parameter being processed */
  state: string;
}

/**
 * Callback processing complete
 */
export interface AuthCallbackCompleteEvent extends BaseEventPayload {
  /** Whether authentication was successful */
  success: boolean;
}

/**
 * Login complete
 */
export interface AuthLoginCompleteEvent extends BaseEventPayload {
  /** Authentication method used */
  method: 'redirect' | 'popup' | 'silent' | 'passkey' | 'email_code' | 'social';
  /** User info (if available) */
  user?: UserInfo;
}

/**
 * Logout complete
 */
export interface AuthLogoutCompleteEvent extends BaseEventPayload {
  /** Logout method */
  method: 'local' | 'redirect' | 'front_channel' | 'back_channel';
}

/**
 * Re-authentication required
 */
export interface AuthRequiredEvent extends BaseEventPayload {
  /** Reason for re-authentication */
  reason: 'refresh_failed' | 'session_expired' | 'token_revoked' | 'user_action';
}

/**
 * Popup blocked by browser (Web SDK only)
 */
export interface AuthPopupBlockedEvent extends BaseEventPayload {
  /** Intended popup URL */
  url?: string;
}

/**
 * Flow fallback occurred (e.g., popup → redirect)
 */
export interface AuthFallbackEvent extends BaseEventPayload {
  /** Original flow */
  from: 'popup' | 'silent' | 'iframe';
  /** Fallback flow */
  to: 'redirect';
  /** Reason for fallback */
  reason: 'popup_blocked' | 'iframe_timeout' | 'silent_failed';
}

// =============================================================================
// token:* - Token Lifecycle Events
// =============================================================================

/**
 * Token refresh starting
 */
export interface TokenRefreshingEvent extends BaseEventPayload {
  /** Reason for refresh */
  reason: 'expiring' | 'manual' | 'on_demand' | 'background';
}

/**
 * Token refresh succeeded
 */
export interface TokenRefreshedEvent extends BaseEventPayload {
  /** Whether access token is present */
  hasAccessToken: boolean;
  /** Whether refresh token is present */
  hasRefreshToken: boolean;
  /** Whether ID token is present */
  hasIdToken: boolean;
  /** Token expiration timestamp (epoch seconds) */
  expiresAt: number;
}

/**
 * Token refresh failed
 */
export interface TokenRefreshFailedEvent extends BaseEventPayload {
  /** Error that caused the failure */
  error: AuthrimError;
  /** Whether retry is possible */
  willRetry: boolean;
  /** Retry attempt number (0 = first attempt) */
  attempt: number;
}

/**
 * Token expiring soon (warning)
 */
export interface TokenExpiringEvent extends BaseEventPayload {
  /** Token expiration timestamp (epoch seconds) */
  expiresAt: number;
  /** Remaining time in seconds */
  expiresIn: number;
}

/**
 * Token expired
 */
export interface TokenExpiredEvent extends BaseEventPayload {
  /** Token expiration timestamp (epoch seconds) */
  expiredAt: number;
  /** Whether refresh token is available */
  hasRefreshToken: boolean;
}

/**
 * Token error
 */
export interface TokenErrorEvent extends BaseEventPayload {
  /** Error details */
  error: AuthrimError;
  /** Operation context */
  context: 'refresh' | 'exchange' | 'validation' | 'storage';
}

/**
 * Token exchanged (RFC 8693)
 */
export interface TokenExchangedEvent extends BaseEventPayload {
  /** Whether new access token is present */
  hasAccessToken: boolean;
  /** Whether new refresh token is present */
  hasRefreshToken: boolean;
  /** Issued token type URI */
  issuedTokenType: TokenTypeUri | string;
}

// =============================================================================
// session:* - Session Management Events
// =============================================================================

/**
 * Session started
 */
export interface SessionStartedEvent extends BaseEventPayload {
  /** User info */
  user: UserInfo;
}

/**
 * Session ended
 */
export interface SessionEndedEvent extends BaseEventPayload {
  /** Reason for session end */
  reason: 'logout' | 'expired' | 'revoked';
}

/**
 * Session changed (general)
 */
export interface SessionChangedEvent extends BaseEventPayload {
  /** Whether user is authenticated */
  isAuthenticated: boolean;
  /** User info (if authenticated) */
  user?: UserInfo;
}

/**
 * Tab synchronization event (Web SDK only)
 */
export interface SessionSyncEvent extends BaseEventPayload {
  /** Sync action */
  action: 'login' | 'logout' | 'refresh' | 'leader_change';
  /** Source tab ID */
  sourceTabId?: string;
}

/**
 * Logout broadcast from another tab (Web SDK only)
 */
export interface SessionLogoutBroadcastEvent extends BaseEventPayload {
  /** Source tab ID */
  sourceTabId?: string;
}

// =============================================================================
// state:* - SDK State Events
// =============================================================================

/**
 * Auth state type
 */
export type AuthState =
  | 'idle'              // Initial state
  | 'initializing'      // SDK initializing
  | 'authenticated'     // User authenticated
  | 'unauthenticated'   // User not authenticated
  | 'authenticating'    // Authentication in progress
  | 'refreshing'        // Token refresh in progress
  | 'logging_out'       // Logout in progress
  | 'error';            // Error state

/**
 * Auth state snapshot
 */
export interface AuthStateSnapshot {
  /** Current state */
  state: AuthState;
  /** Previous state */
  previousState: AuthState | null;
  /** Snapshot timestamp */
  timestamp: number;
  /** Current operation ID */
  operationId: string | null;
  /** State context */
  context: {
    /** Whether user is authenticated */
    isAuthenticated: boolean;
    /** Token expiration timestamp (epoch seconds) */
    tokenExpiresAt: number | null;
    /** Last error */
    lastError: AuthrimError | null;
    /** Pending operation description */
    pendingOperation: string | null;
  };
}

/**
 * State change event
 */
export interface StateChangeEvent extends BaseEventPayload {
  /** Previous state */
  from: AuthState;
  /** New state */
  to: AuthState;
  /** Full state snapshot */
  snapshot: AuthStateSnapshot;
}

// =============================================================================
// error:* - Error Events
// =============================================================================

/**
 * Error severity for event classification
 */
export type ErrorSeverity = 'recoverable' | 'fatal';

/**
 * Error event payload (extended)
 */
export interface ErrorEventPayload extends BaseEventPayload {
  /** Error instance */
  error: AuthrimError;
  /** Error severity */
  severity: ErrorSeverity;
  /** Recommended remediation */
  remediation: AuthrimErrorRemediation;
  /** Operation context where error occurred */
  context: string;
}

/**
 * Legacy error event (backward compatibility)
 */
export interface ErrorEvent {
  error: AuthrimError;
  context: string;
}

/**
 * Recoverable error event
 */
export interface ErrorRecoverableEvent extends ErrorEventPayload {
  severity: 'recoverable';
}

/**
 * Fatal error event
 */
export interface ErrorFatalEvent extends ErrorEventPayload {
  severity: 'fatal';
}

// =============================================================================
// warning:* - Warning Events
// =============================================================================

/**
 * ITP environment detected warning (Web SDK only)
 */
export interface WarningITPEvent extends BaseEventPayload {
  /** Warning message */
  message: string;
  /** Detected browser */
  browser: 'safari' | 'webkit' | 'unknown';
  /** Recommended action */
  recommendation: 'use_redirect' | 'use_popup' | 'normal';
}

/**
 * Storage fallback warning
 *
 * Fired when:
 * - localStorage → sessionStorage fallback
 * - sessionStorage → memory fallback
 */
export interface WarningStorageFallbackEvent extends BaseEventPayload {
  /** Original storage type */
  from: 'localStorage' | 'sessionStorage';
  /** Fallback storage type */
  to: 'sessionStorage' | 'memory';
  /** Reason for fallback */
  reason: 'not_available' | 'quota_exceeded' | 'private_mode' | 'security_error';
}

/**
 * Private browsing mode detected warning (Web SDK only)
 */
export interface WarningPrivateModeEvent extends BaseEventPayload {
  /** Detected browser */
  browser: 'safari' | 'firefox' | 'chrome' | 'edge' | 'unknown';
  /** Storage limitations */
  limitations: string[];
}

// =============================================================================
// debug:* - Debug Events (debug mode only)
// =============================================================================

/**
 * Timeline event entry
 */
export interface TimelineEntry {
  /** Event type */
  type: string;
  /** Event timestamp */
  timestamp: number;
  /** Operation ID */
  operationId?: string;
  /** Redacted event data */
  data?: Record<string, unknown>;
}

/**
 * Debug timeline event
 */
export interface DebugTimelineEvent extends BaseEventPayload {
  /** Timeline entry */
  entry: TimelineEntry;
}

// =============================================================================
// All Authrim Events Map
// =============================================================================

/**
 * All Authrim events
 */
export interface AuthrimEvents {
  // auth:* - Authentication lifecycle
  'auth:init': AuthInitEvent;
  'auth:redirecting': AuthRedirectingEvent;
  'auth:callback': AuthCallbackEvent;
  'auth:callback:processing': AuthCallbackProcessingEvent;
  'auth:callback:complete': AuthCallbackCompleteEvent;
  'auth:login:complete': AuthLoginCompleteEvent;
  'auth:logout:complete': AuthLogoutCompleteEvent;
  'auth:required': AuthRequiredEvent;
  'auth:popup_blocked': AuthPopupBlockedEvent;
  'auth:fallback': AuthFallbackEvent;

  // token:* - Token lifecycle
  'token:refreshing': TokenRefreshingEvent;
  'token:refreshed': TokenRefreshedEvent;
  'token:refresh:failed': TokenRefreshFailedEvent;
  'token:expiring': TokenExpiringEvent;
  'token:expired': TokenExpiredEvent;
  'token:error': TokenErrorEvent;
  'token:exchanged': TokenExchangedEvent;

  // session:* - Session management
  'session:started': SessionStartedEvent;
  'session:ended': SessionEndedEvent;
  'session:changed': SessionChangedEvent;
  'session:sync': SessionSyncEvent;
  'session:logout:broadcast': SessionLogoutBroadcastEvent;

  // state:* - SDK state
  'state:change': StateChangeEvent;

  // error:* - Errors
  'error': ErrorEvent;
  'error:recoverable': ErrorRecoverableEvent;
  'error:fatal': ErrorFatalEvent;

  // warning:* - Warnings
  'warning:itp': WarningITPEvent;
  'warning:storage_fallback': WarningStorageFallbackEvent;
  'warning:private_mode': WarningPrivateModeEvent;

  // debug:* - Debug (debug mode only)
  'debug:timeline': DebugTimelineEvent;
}

/**
 * Event names
 */
export type AuthrimEventName = keyof AuthrimEvents;

/**
 * Event handler type
 */
export type AuthrimEventHandler<T extends AuthrimEventName> = (event: AuthrimEvents[T]) => void;

// =============================================================================
// Utility Types
// =============================================================================

/**
 * Events emitted by Core SDK
 */
export type CoreEventName =
  | 'auth:init'
  | 'auth:redirecting'
  | 'auth:callback'
  | 'auth:callback:processing'
  | 'auth:callback:complete'
  | 'auth:login:complete'
  | 'auth:logout:complete'
  | 'auth:required'
  | 'token:refreshing'
  | 'token:refreshed'
  | 'token:refresh:failed'
  | 'token:expiring'
  | 'token:expired'
  | 'token:error'
  | 'token:exchanged'
  | 'session:started'
  | 'session:ended'
  | 'session:changed'
  | 'state:change'
  | 'error'
  | 'error:recoverable'
  | 'error:fatal'
  | 'debug:timeline';

/**
 * Events emitted by Web SDK only
 */
export type WebOnlyEventName =
  | 'auth:popup_blocked'
  | 'auth:fallback'
  | 'session:sync'
  | 'session:logout:broadcast'
  | 'warning:itp'
  | 'warning:storage_fallback'
  | 'warning:private_mode';
