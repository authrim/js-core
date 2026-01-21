/**
 * Events Module
 */

export { EventEmitter } from './emitter.js';
export type {
  // Base types
  BaseEventPayload,

  // auth:* events
  AuthInitEvent,
  AuthRedirectingEvent,
  AuthCallbackEvent,
  AuthCallbackProcessingEvent,
  AuthCallbackCompleteEvent,
  AuthLoginCompleteEvent,
  AuthLogoutCompleteEvent,
  AuthRequiredEvent,
  AuthPopupBlockedEvent,
  AuthFallbackEvent,

  // token:* events
  TokenRefreshingEvent,
  TokenRefreshedEvent,
  TokenRefreshFailedEvent,
  TokenExpiringEvent,
  TokenExpiredEvent,
  TokenErrorEvent,
  TokenExchangedEvent,

  // session:* events
  SessionStartedEvent,
  SessionEndedEvent,
  SessionChangedEvent,
  SessionSyncEvent,
  SessionLogoutBroadcastEvent,

  // state:* events
  AuthState,
  AuthStateSnapshot,
  StateChangeEvent,

  // error:* events
  ErrorSeverity,
  ErrorEventPayload,
  ErrorEvent,
  ErrorRecoverableEvent,
  ErrorFatalEvent,

  // warning:* events
  WarningITPEvent,
  WarningStorageFallbackEvent,
  WarningPrivateModeEvent,

  // debug:* events
  TimelineEntry,
  DebugTimelineEvent,

  // Event map and utilities
  AuthrimEvents,
  AuthrimEventName,
  AuthrimEventHandler,
  CoreEventName,
  WebOnlyEventName,
} from './types.js';
