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
  DirectAuthChannel,
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
  DirectAuthLogoutScope,
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
  DirectAuthManagedSessionRequest,
  DirectAuthManagedSessionResponse,
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

export {
  DirectAuthBrowserSessionClient,
  type DirectAuthEmailCodeManagedSessionResult,
  type DirectAuthBrowserSessionClientOptions,
  type DirectAuthBrowserEmailCodeSendResponse,
  type DirectAuthRequestOptions,
  type DirectoryPasswordLoginInput,
  type DirectoryPasswordLoginResponse,
  type DirectoryPasswordMigrationEmailCodeSendInput,
  type DirectoryPasswordMigrationEmailCodeSendResponse,
  type DirectoryPasswordMigrationEmailCodeVerifyInput,
  type DirectoryPasswordMigrationPasskeyOptionsInput,
  type DirectoryPasswordMigrationPasskeyOptionsResponse,
  type DirectoryPasswordMigrationPasskeyVerifyInput,
  type DirectoryPasswordMigrationResponse,
  type DirectoryPasswordRecoveryResponse,
  type EmailCodeSendInput,
  type EmailCodeVerifyInput,
  type ManagedDirectAuthSessionOptions,
  type PasskeyFinishInput,
  type PasskeyLoginStartInput,
  type PasskeySignupStartInput,
  type TotpActivateSignupInput,
  type TotpCredential,
  type TotpLoginStartResponse,
  type TotpManagedSessionResponse,
  type TotpProfile,
  type TotpSignupOptionsInput,
  type TotpSignupOptionsResponse,
  type TotpStartLoginInput,
  type TotpVerifyLoginInput,
} from './browser-session.js';
