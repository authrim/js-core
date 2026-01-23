/**
 * Direct Authentication API
 *
 * BetterAuth スタイルのシンプルで直感的な認証 API
 */

// Types
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
} from './types.js';
