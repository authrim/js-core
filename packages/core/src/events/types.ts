/**
 * Event Types
 */

import type { AuthrimError } from '../types/errors.js';
import type { TokenSet } from '../types/token.js';
import type { UserInfo } from '../types/oidc.js';

/**
 * Token refresh event data
 */
export interface TokenRefreshedEvent {
  tokens: TokenSet;
}

/**
 * Token expired event data
 */
export interface TokenExpiredEvent {
  accessToken: string;
}

/**
 * Token error event data
 */
export interface TokenErrorEvent {
  error: AuthrimError;
}

/**
 * Token exchanged event data (RFC 8693)
 */
export interface TokenExchangedEvent {
  tokens: TokenSet;
  issuedTokenType: string;
}

/**
 * Session started event data
 */
export interface SessionStartedEvent {
  user: UserInfo;
}

/**
 * Session ended event data
 */
export interface SessionEndedEvent {
  reason: 'logout' | 'expired' | 'revoked';
}

/**
 * Auth redirecting event data
 */
export interface AuthRedirectingEvent {
  url: string;
}

/**
 * Auth callback event data
 */
export interface AuthCallbackEvent {
  code: string;
  state: string;
}

/**
 * Error event data
 */
export interface ErrorEvent {
  error: AuthrimError;
  context: string;
}

/**
 * All Authrim events
 */
export interface AuthrimEvents {
  'token:refreshed': TokenRefreshedEvent;
  'token:expired': TokenExpiredEvent;
  'token:error': TokenErrorEvent;
  'token:exchanged': TokenExchangedEvent;
  'session:started': SessionStartedEvent;
  'session:ended': SessionEndedEvent;
  'auth:redirecting': AuthRedirectingEvent;
  'auth:callback': AuthCallbackEvent;
  error: ErrorEvent;
}

/**
 * Event names
 */
export type AuthrimEventName = keyof AuthrimEvents;

/**
 * Event handler type
 */
export type AuthrimEventHandler<T extends AuthrimEventName> = (event: AuthrimEvents[T]) => void;
