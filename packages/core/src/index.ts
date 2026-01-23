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
export { type HttpClient, type HttpOptions, type HttpResponse, type OAuthErrorResponse } from './providers/http.js';
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
export { PARClient } from './auth/par.js';
export type {
  PARRequest,
  PARResponse,
  PARResult,
  PARClientOptions,
} from './types/par.js';

// Client Authentication
export {
  buildClientAuthentication,
  type ClientAuthResult,
} from './auth/client-auth.js';
export {
  ClientCredentialsClient,
  type ClientCredentialsClientOptions,
  type ClientCredentialsTokenOptions,
} from './auth/client-credentials.js';
export type {
  ClientAuthMethod,
  ClientSecretCredentials,
  PrivateKeyJwtCredentials,
  NoClientCredentials,
  ClientCredentials,
  ClientAssertionClaims,
} from './types/client-auth.js';

// Device Flow
export { DeviceFlowClient } from './auth/device-flow.js';
export type {
  DeviceAuthorizationResponse,
  DeviceFlowState,
  DeviceFlowPollResult,
  DeviceFlowPendingResult,
  DeviceFlowCompletedResult,
  DeviceFlowSlowDownResult,
  DeviceFlowExpiredResult,
  DeviceFlowAccessDeniedResult,
  DeviceFlowStartOptions,
} from './types/device-flow.js';

// Security (DPoP, JAR, JARM)
export { DPoPManager } from './security/dpop.js';
export type {
  JWK,
  DPoPKeyPair,
  DPoPProofHeader,
  DPoPProofClaims,
  DPoPProofOptions,
  DPoPManagerConfig,
  DPoPCryptoProvider,
} from './types/dpop.js';
export { JARBuilder, isJarRequired } from './security/jar.js';
export type {
  JARRequestObjectClaims,
  JARBuilderConfig,
  JARRequestOptions,
} from './types/jar.js';
export { JARMValidator } from './security/jarm.js';
export type {
  JARMResponseClaims,
  JARMValidationOptions,
  JARMValidationResult,
  JARMValidatorConfig,
} from './types/jarm.js';

// Session Management Types (implementation in web SDK)
export type {
  SessionState,
  CheckSessionMessage,
  CheckSessionResponse,
  SessionManagementConfig,
  SessionChangeEvent,
  FrontChannelLogoutParams,
  FrontChannelLogoutUrlOptions,
  LogoutTokenClaims,
} from './types/session-management.js';

// Token
export { TokenManager, type TokenManagerOptions } from './token/manager.js';
export { AutoRefreshScheduler, type AutoRefreshOptions } from './token/auto-refresh.js';
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
export {
  SessionStateCalculator,
  type SessionStateParams,
  type SessionStateResult,
  type SessionStateCalculatorOptions,
} from './session/session-state.js';
export {
  FrontChannelLogoutUrlBuilder,
  type FrontChannelLogoutUrlResult,
  type FrontChannelLogoutBuildParams,
  type FrontChannelLogoutValidationOptions,
  type FrontChannelLogoutValidationResult,
} from './session/front-channel-logout.js';

// Events
export { EventEmitter } from './events/emitter.js';
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
  AuthState as AuthStateType,
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
  // Event utilities
  AuthrimEvents,
  AuthrimEventName,
  AuthrimEventHandler,
  CoreEventName,
  WebOnlyEventName,
} from './events/types.js';

// Debug
export {
  EventTimeline,
  createConsoleLogger,
  createDebugLogger,
  noopLogger,
  DebugContext,
  type DebugOptions,
  type DebugLogger,
  type DebugLogLevel,
  type RedactLevel,
} from './debug/index.js';

// Types
export {
  AuthrimError,
  getErrorMeta,
  classifyError,
  isRetryableError,
  emitClassifiedError,
  type AuthrimErrorOptions,
  type AuthrimErrorCode,
  type AuthrimErrorMeta,
  type AuthrimErrorUserAction,
  type AuthrimErrorSeverity,
  type AuthrimErrorRemediation,
  type ErrorClassification,
  type ErrorEventEmitter,
  type EmitClassifiedErrorOptions,
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
export { timingSafeEqual } from './utils/timing-safe.js';
export {
  withAbortSignal,
  createCancellableOperation,
  isCancellationError,
  raceWithCancellation,
} from './utils/cancellation.js';
export {
  withRetry,
  createRetryFunction,
  calculateBackoffDelay,
  sleep,
  parseRetryAfterHeader,
  type RetryOptions,
} from './utils/retry.js';

// Direct Auth
export type {
  // WebAuthn Types
  AuthenticatorTransportType,
  UserVerificationRequirementType,
  AuthenticatorAttachmentType,
  ResidentKeyRequirementType,
  AttestationConveyancePreferenceType,
  PublicKeyCredentialType,
  COSEAlgorithmIdentifier,
  PublicKeyCredentialParametersType,
  PublicKeyCredentialRpEntityType,
  AuthenticatorSelectionCriteriaType,
  AuthenticationExtensionsClientInputsType,
  // Common
  SocialProvider,
  MfaMethod,
  User,
  Session,
  NextAction,
  AuthResult,
  DirectAuthError,
  // Passkey
  PasskeyLoginOptions,
  PasskeySignUpOptions,
  PasskeyRegisterOptions,
  PasskeyCredential,
  // Email Code
  EmailCodeSendOptions,
  EmailCodeSendResult,
  EmailCodeVerifyOptions,
  // Social
  SocialLoginOptions,
  // Session
  DirectAuthLogoutOptions,
  // Silent Login (Cross-Domain SSO)
  TrySilentLoginOptions,
  SilentLoginResult,
  SilentLoginStateData,
  // API Request/Response
  PasskeyLoginStartRequest,
  PasskeyLoginStartResponse,
  PasskeyLoginFinishRequest,
  PasskeyLoginFinishResponse,
  PasskeySignupStartRequest,
  PasskeySignupStartResponse,
  PasskeySignupFinishRequest,
  PasskeySignupFinishResponse,
  EmailCodeSendRequest,
  EmailCodeSendResponse,
  EmailCodeVerifyRequest,
  EmailCodeVerifyResponse,
  DirectAuthTokenRequest,
  DirectAuthTokenResponse,
  // WebAuthn JSON
  PublicKeyCredentialRequestOptionsJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialDescriptorJSON,
  PublicKeyCredentialUserEntityJSON,
  AuthenticatorAssertionResponseJSON,
  AuthenticatorAttestationResponseJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  // SDK Interface
  DirectAuthClientConfig,
  PasskeyAuth,
  EmailCodeAuth,
  SocialAuth,
  SessionAuth,
  DirectAuthClient,
} from './direct-auth/index.js';
