/**
 * Type Definitions
 */

export {
  AuthrimError,
  getErrorMeta,
  isAuthrimErrorCode,
  classifyError,
  isRetryableError,
  type AuthrimErrorCode,
  type AuthrimErrorMeta,
  type AuthrimErrorSeverity,
  type AuthrimErrorUserAction,
  type AuthrimErrorRemediation,
  type ErrorClassification,
  type Phase1ErrorDetails,
  type Phase1ErrorDetailSeverity,
  type Phase1ErrorDetailUserAction,
  type StepUpActionStatus,
  type StepUpErrorDetailCode,
  type StepUpErrorResponseBody,
  type StepUpInputState,
  type StepUpPreferredMethod,
  type StepUpStatusObject,
} from './errors.js';
export type { OIDCDiscoveryDocument, IdTokenClaims, UserInfo } from './oidc.js';
export type {
  TokenSet,
  TokenEndpointResponse,
  TokenExchangeRequest,
  NativeSSOTokenExchangeRequest,
  TokenExchangeResponse,
  TokenExchangeResult,
} from './token.js';
export type {
  PARRequest,
  PARResponse,
  PARResult,
  PARClientOptions,
} from './par.js';
export type {
  ClientAuthMethod,
  ClientSecretCredentials,
  PrivateKeyJwtCredentials,
  NoClientCredentials,
  ClientCredentials,
  ClientAssertionClaims,
} from './client-auth.js';
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
} from './device-flow.js';
export {
  DEFAULT_STEP_UP_POLICY,
  type StepUpAcceptableMethods,
  type StepUpActionResponse,
  type StepUpCompleteRequest,
  type StepUpFailureBody,
  type StepUpNextAction,
  type StepUpRequirement,
  type StepUpResendResponse,
  type StepUpStartRequest,
} from './step-up.js';
export type {
  JWK,
  DPoPKeyPair,
  DPoPAlgorithm,
  DPoPProofHeader,
  DPoPProofClaims,
  DPoPProofOptions,
  DPoPManagerConfig,
  DPoPCryptoProvider,
} from './dpop.js';
export type {
  JARRequestObjectClaims,
  JARBuilderConfig,
  JARRequestOptions,
} from './jar.js';
export type {
  JARMResponseClaims,
  JARMValidationOptions,
  JARMValidationResult,
  JARMValidatorConfig,
} from './jarm.js';
export type {
  SessionState,
  CheckSessionMessage,
  CheckSessionResponse,
  SessionManagementConfig,
  SessionChangeEvent,
  FrontChannelLogoutParams,
  FrontChannelLogoutUrlOptions,
  LogoutTokenClaims,
} from './session-management.js';
