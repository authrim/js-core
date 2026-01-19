/**
 * @authrim/core
 *
 * Platform-agnostic core library for Authrim authentication.
 */

// Main client
export { AuthrimClient, createAuthrimClient } from './client/index.js';

// Configuration
export {
  type AuthrimClientConfig,
  type ResolvedConfig,
  type EndpointOverrides,
  type HashOptions,
  resolveConfig,
} from './client/config.js';

// Discovery
export { DiscoveryClient, normalizeIssuer } from './client/discovery.js';

// Provider interfaces
export { type HttpClient, type HttpOptions, type HttpResponse } from './providers/http.js';
export { type CryptoProvider } from './providers/crypto.js';
export { type AuthrimStorage } from './providers/storage.js';

// Auth
export { PKCEHelper, type PKCEPair, type CodeChallengeMethod } from './auth/pkce.js';
export {
  StateManager,
  STORAGE_KEYS,
  type AuthState,
  type GenerateAuthStateOptions,
} from './auth/state.js';
export {
  AuthorizationCodeFlow,
  type BuildAuthorizationUrlOptions,
  type AuthorizationUrlResult,
  type AuthorizationContext,
  type ExchangeCodeOptions,
} from './auth/authorization-code.js';
export {
  SilentAuthHandler,
  type SilentAuthOptions,
  type SilentAuthUrlResult,
  type SilentAuthResult,
} from './auth/silent-auth.js';

// Token
export { TokenManager, type TokenManagerOptions } from './token/manager.js';
export {
  TokenIntrospector,
  type TokenIntrospectorOptions,
  type IntrospectionResponse,
  type IntrospectTokenOptions,
  type IntrospectionTokenTypeHint,
} from './token/introspection.js';
export {
  TokenRevoker,
  type TokenRevokerOptions,
  type RevokeTokenOptions,
  type TokenTypeHint,
} from './token/revocation.js';

// Session
export {
  LogoutHandler,
  type LogoutOptions,
  type LogoutResult,
  type LogoutHandlerOptions,
} from './session/logout.js';
export {
  TokenApiClient,
  type SessionCheckResult,
  type TokenApiClientOptions,
} from './session/token-api.js';
export { SessionManager, type SessionManagerOptions } from './session/manager.js';

// Events
export { EventEmitter } from './events/emitter.js';
export type {
  AuthrimEvents,
  AuthrimEventName,
  AuthrimEventHandler,
  TokenRefreshedEvent,
  TokenExpiredEvent,
  TokenErrorEvent,
  TokenExchangedEvent,
  SessionStartedEvent,
  SessionEndedEvent,
  AuthRedirectingEvent,
  AuthCallbackEvent,
  ErrorEvent,
} from './events/types.js';

// Types
export {
  AuthrimError,
  getErrorMeta,
  type AuthrimErrorOptions,
  type AuthrimErrorCode,
  type AuthrimErrorMeta,
  type AuthrimErrorUserAction,
  type AuthrimErrorSeverity,
} from './types/errors.js';
export type {
  OIDCDiscoveryDocument,
  UserInfo,
  StandardClaims,
  AddressClaim,
} from './types/oidc.js';
export {
  TOKEN_TYPE_URIS,
  type TokenSet,
  type TokenResponse,
  type TokenExchangeRequest,
  type TokenExchangeResponse,
  type TokenExchangeResult,
  type TokenTypeUri,
} from './types/token.js';

// Utils
export {
  base64urlEncode,
  base64urlDecode,
  stringToBase64url,
  base64urlToString,
} from './utils/base64url.js';
export {
  decodeJwt,
  decodeIdToken,
  isJwtExpired,
  getIdTokenNonce,
  type JwtHeader,
  type DecodedJwt,
} from './utils/jwt.js';
export { calculateDsHash } from './utils/hash.js';
