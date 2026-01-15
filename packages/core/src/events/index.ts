/**
 * Events Module
 */

export { EventEmitter } from './emitter.js';
export type {
  AuthrimEvents,
  AuthrimEventName,
  AuthrimEventHandler,
  TokenRefreshedEvent,
  TokenExpiredEvent,
  TokenErrorEvent,
  SessionStartedEvent,
  SessionEndedEvent,
  AuthRedirectingEvent,
  AuthCallbackEvent,
  ErrorEvent,
} from './types.js';
