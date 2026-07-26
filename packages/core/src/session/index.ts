/**
 * Session Module
 */

export {
  LogoutHandler,
  type LogoutScope,
  type LogoutOptions,
  type LogoutResult,
  type LogoutHandlerOptions,
} from './logout.js';
export {
  BackChannelLogoutValidator,
  type BackChannelLogoutTokenVerifier,
  type BackChannelLogoutValidatorConfig,
  type BackChannelLogoutValidationOptions,
  type BackChannelLogoutValidationResult,
} from './back-channel-logout.js';
export {
  TokenApiClient,
  type SessionCheckResult,
  type TokenApiClientOptions,
} from './token-api.js';
export { SessionManager, type SessionManagerOptions } from './manager.js';
export {
  SessionStateCalculator,
  type SessionStateParams,
  type SessionStateResult,
  type SessionStateCalculatorOptions,
} from './session-state.js';
export {
  FrontChannelLogoutUrlBuilder,
  type FrontChannelLogoutUrlResult,
  type FrontChannelLogoutBuildParams,
  type FrontChannelLogoutValidationOptions,
  type FrontChannelLogoutValidationResult,
} from './front-channel-logout.js';
