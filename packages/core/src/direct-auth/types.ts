/**
 * Direct Authentication API Types
 *
 * Simple and intuitive BetterAuth-style API type definitions
 * for calling Authrim API directly from custom login pages.
 */

// =============================================================================
// WebAuthn Types (platform-agnostic definitions)
// These mirror the Web Platform types for use in platform-agnostic code
// =============================================================================

/**
 * Authenticator transport type
 */
export type AuthenticatorTransportType = 'usb' | 'nfc' | 'ble' | 'internal' | 'hybrid';

/**
 * User verification requirement
 */
export type UserVerificationRequirementType = 'required' | 'preferred' | 'discouraged';

/**
 * Authenticator attachment
 */
export type AuthenticatorAttachmentType = 'platform' | 'cross-platform';

/**
 * Resident key requirement
 */
export type ResidentKeyRequirementType = 'required' | 'preferred' | 'discouraged';

/**
 * Attestation conveyance preference
 */
export type AttestationConveyancePreferenceType = 'none' | 'indirect' | 'direct' | 'enterprise';

/**
 * Public key credential type
 */
export type PublicKeyCredentialType = 'public-key';

/**
 * COSE algorithm identifier
 */
export type COSEAlgorithmIdentifier = -7 | -257 | -8 | -35 | -36 | -37 | -38 | -39 | number;

/**
 * Public key credential parameters
 */
export interface PublicKeyCredentialParametersType {
  type: PublicKeyCredentialType;
  alg: COSEAlgorithmIdentifier;
}

/**
 * Relying party entity
 */
export interface PublicKeyCredentialRpEntityType {
  id?: string;
  name: string;
}

/**
 * Authenticator selection criteria
 */
export interface AuthenticatorSelectionCriteriaType {
  authenticatorAttachment?: AuthenticatorAttachmentType;
  residentKey?: ResidentKeyRequirementType;
  requireResidentKey?: boolean;
  userVerification?: UserVerificationRequirementType;
}

/**
 * Authentication extensions client inputs
 */
export interface AuthenticationExtensionsClientInputsType {
  credProps?: boolean;
  appid?: string;
  [key: string]: unknown;
}

// =============================================================================
// Common Types
// =============================================================================

/**
 * Social login provider
 */
export type SocialProvider = 'google' | 'github' | 'apple' | 'microsoft' | 'facebook';

/**
 * MFA method
 */
export type MfaMethod = 'totp' | 'sms' | 'email' | 'passkey';

/**
 * User information
 */
export interface User {
  /** User ID */
  id: string;
  /** Email address */
  email?: string;
  /** Whether email is verified */
  emailVerified?: boolean;
  /** Display name */
  name?: string;
  /** Profile picture URL */
  picture?: string;
  /** Username */
  username?: string;
  /** Additional claims */
  [key: string]: unknown;
}

/**
 * Session information
 */
export interface Session {
  /** Session ID */
  id: string;
  /** User ID */
  userId: string;
  /** Session creation time (ISO 8601) */
  createdAt: string;
  /** Session expiration time (ISO 8601) */
  expiresAt: string;
  /** Last activity time (ISO 8601) */
  lastActiveAt?: string;
  /** User agent that created the session */
  userAgent?: string;
  /** IP address (for display purposes only, not for security) */
  ipAddress?: string;
}

/**
 * Next action required after authentication
 */
export type NextAction =
  | { type: 'mfa_required'; methods: MfaMethod[] }
  | { type: 'consent_required'; scopes: string[] }
  | { type: 'email_verification_required' };

/**
 * Authentication result (tokens are not returned directly for security)
 */
export interface AuthResult {
  /** Authentication success flag */
  success: boolean;
  /** Session information (on success) */
  session?: Session;
  /** User information (on success) */
  user?: User;
  /** Error information (on failure) */
  error?: DirectAuthError;
  /** Additional action required */
  nextAction?: NextAction;
}

/**
 * Direct Auth error structure (OAuth 2.0 extension)
 */
export interface DirectAuthError {
  /** OAuth 2.0 error code */
  error: string;
  /** Human-readable error description */
  error_description?: string;
  /** URI with more information about the error */
  error_uri?: string;
  /** Authrim error code (AR000001 format) */
  code: string;
  /** Error metadata */
  meta: {
    /** Whether the error can be retried */
    retryable: boolean;
    /** Whether the error is transient */
    transient?: boolean;
    /** Suggested user action */
    user_action?: 'login' | 'reauth' | 'retry' | 'contact_admin';
    /** Error severity */
    severity: 'info' | 'warn' | 'error' | 'critical';
    /** Retry after (seconds) */
    retry_after?: number;
  };
}

// =============================================================================
// Passkey Types
// =============================================================================

/**
 * Passkey login options
 */
export interface PasskeyLoginOptions {
  /** Use conditional UI (autofill) */
  conditional?: boolean;
  /** Mediation preference */
  mediation?: 'conditional' | 'optional' | 'required' | 'silent';
  /** Abort signal for cancellation */
  signal?: AbortSignal;
}

/**
 * Passkey sign-up options
 */
export interface PasskeySignUpOptions {
  /** User email */
  email: string;
  /** User display name */
  displayName?: string;
  /** Preferred authenticator type */
  authenticatorType?: 'platform' | 'cross-platform' | 'any';
  /** Resident key requirement */
  residentKey?: 'required' | 'preferred' | 'discouraged';
  /** User verification requirement */
  userVerification?: 'required' | 'preferred' | 'discouraged';
  /** Abort signal for cancellation */
  signal?: AbortSignal;
}

/**
 * Passkey register options (for adding to existing account)
 */
export interface PasskeyRegisterOptions {
  /** Passkey display name */
  displayName?: string;
  /** Preferred authenticator type */
  authenticatorType?: 'platform' | 'cross-platform' | 'any';
  /** Resident key requirement */
  residentKey?: 'required' | 'preferred' | 'discouraged';
  /** User verification requirement */
  userVerification?: 'required' | 'preferred' | 'discouraged';
  /** Abort signal for cancellation */
  signal?: AbortSignal;
}

/**
 * Passkey credential (returned after registration)
 */
export interface PasskeyCredential {
  /** Credential ID (base64url) */
  credentialId: string;
  /** Public key (COSE format, base64url) */
  publicKey: string;
  /** Authenticator type */
  authenticatorType: 'platform' | 'cross-platform';
  /** Transports (usb, nfc, ble, internal, etc.) */
  transports?: AuthenticatorTransportType[];
  /** When the credential was created */
  createdAt: string;
  /** User-friendly name */
  displayName?: string;
}

// =============================================================================
// Email Code Types
// =============================================================================

/**
 * Email code send options
 */
export interface EmailCodeSendOptions {
  /** Email locale for the message */
  locale?: string;
  /** Code length (default: 6) */
  codeLength?: 6 | 8;
}

/**
 * Email code send result
 */
export interface EmailCodeSendResult {
  /** Attempt ID for verification */
  attemptId: string;
  /** Code expiration time (seconds) */
  expiresIn: number;
  /** Masked email for display */
  maskedEmail: string;
  /** Whether this is a new user */
  isNewUser?: boolean;
}

/**
 * Email code verify options
 */
export interface EmailCodeVerifyOptions {
  /** Create account if user doesn't exist */
  createAccountIfNotExists?: boolean;
}

// =============================================================================
// Social Login Types
// =============================================================================

/**
 * Social login options
 */
export interface SocialLoginOptions {
  /** Redirect URI after authentication */
  redirectUri?: string;
  /** Additional OAuth scopes */
  scopes?: string[];
  /** Custom state parameter */
  state?: string;
  /** Login hint (e.g., email address) */
  loginHint?: string;
  /** Popup window features */
  popupFeatures?: {
    width?: number;
    height?: number;
  };
}

// =============================================================================
// Session Types
// =============================================================================

/**
 * Logout options
 */
export interface DirectAuthLogoutOptions {
  /** Revoke refresh tokens */
  revokeTokens?: boolean;
  /** Post-logout redirect URI */
  redirectUri?: string;
}

// =============================================================================
// API Request/Response Types
// =============================================================================

/**
 * Passkey login start request
 */
export interface PasskeyLoginStartRequest {
  client_id: string;
  code_challenge: string;
  code_challenge_method: 'S256';
}

/**
 * Passkey login start response
 */
export interface PasskeyLoginStartResponse {
  /** Challenge ID (5 min TTL) */
  challenge_id: string;
  /** WebAuthn options */
  options: PublicKeyCredentialRequestOptionsJSON;
}

/**
 * Passkey login finish request
 */
export interface PasskeyLoginFinishRequest {
  challenge_id: string;
  credential: AuthenticationResponseJSON;
  code_verifier: string;
}

/**
 * Passkey login finish response
 */
export interface PasskeyLoginFinishResponse {
  /** Authorization code (60s TTL, single-use) */
  auth_code: string;
}

/**
 * Passkey signup start request
 */
export interface PasskeySignupStartRequest {
  client_id: string;
  email: string;
  display_name?: string;
  code_challenge: string;
  code_challenge_method: 'S256';
  authenticator_type?: 'platform' | 'cross-platform' | 'any';
  resident_key?: 'required' | 'preferred' | 'discouraged';
  user_verification?: 'required' | 'preferred' | 'discouraged';
}

/**
 * Passkey signup start response
 */
export interface PasskeySignupStartResponse {
  /** Challenge ID (5 min TTL) */
  challenge_id: string;
  /** WebAuthn creation options */
  options: PublicKeyCredentialCreationOptionsJSON;
}

/**
 * Passkey signup finish request
 */
export interface PasskeySignupFinishRequest {
  challenge_id: string;
  credential: RegistrationResponseJSON;
  code_verifier: string;
}

/**
 * Passkey signup finish response
 */
export interface PasskeySignupFinishResponse {
  /** Authorization code (60s TTL, single-use) */
  auth_code: string;
  /** Whether the user was newly created */
  is_new_user: boolean;
}

/**
 * Email code send request
 */
export interface EmailCodeSendRequest {
  client_id: string;
  email: string;
  code_challenge: string;
  code_challenge_method: 'S256';
  locale?: string;
}

/**
 * Email code send response
 */
export interface EmailCodeSendResponse {
  /** Attempt ID (5 min TTL) */
  attempt_id: string;
  /** Code expiration (seconds) */
  expires_in: number;
  /** Masked email */
  masked_email: string;
}

/**
 * Email code verify request
 */
export interface EmailCodeVerifyRequest {
  attempt_id: string;
  code: string;
  code_verifier: string;
}

/**
 * Email code verify response
 */
export interface EmailCodeVerifyResponse {
  /** Authorization code (60s TTL, single-use) */
  auth_code: string;
  /** Whether the user was newly created */
  is_new_user: boolean;
}

/**
 * Token exchange request (Direct Auth)
 */
export interface DirectAuthTokenRequest {
  grant_type: 'authorization_code';
  code: string;
  client_id: string;
  code_verifier: string;
  /** Whether to request refresh token (for SPA opt-in) */
  request_refresh_token?: boolean;
}

/**
 * Token exchange response (OAuth 2.0 extension)
 *
 * Unified structure for Web/Mobile, differentiated by flags.
 */
export interface DirectAuthTokenResponse {
  /** Token type (always 'Bearer') */
  token_type: 'Bearer';
  /** Access token */
  access_token: string;
  /** Token expiration (seconds) */
  expires_in: number;
  /** Refresh token (Mobile, or SPA with opt-in) */
  refresh_token?: string;
  /** ID token */
  id_token?: string;
  /** Granted scopes */
  scope?: string;
  /** Whether session is established via Cookie (Web) */
  session_established: boolean;
  /** Session information */
  session?: Session;
  /** User information */
  user?: User;
}

// =============================================================================
// WebAuthn JSON Types (for JSON serialization)
// =============================================================================

/**
 * PublicKeyCredentialRequestOptions as JSON
 */
export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptorJSON[];
  userVerification?: UserVerificationRequirementType;
  extensions?: AuthenticationExtensionsClientInputsType;
}

/**
 * PublicKeyCredentialCreationOptions as JSON
 */
export interface PublicKeyCredentialCreationOptionsJSON {
  rp: PublicKeyCredentialRpEntityType;
  user: PublicKeyCredentialUserEntityJSON;
  challenge: string;
  pubKeyCredParams: PublicKeyCredentialParametersType[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
  authenticatorSelection?: AuthenticatorSelectionCriteriaType;
  attestation?: AttestationConveyancePreferenceType;
  extensions?: AuthenticationExtensionsClientInputsType;
}

/**
 * PublicKeyCredentialDescriptor as JSON
 */
export interface PublicKeyCredentialDescriptorJSON {
  type: PublicKeyCredentialType;
  id: string;
  transports?: AuthenticatorTransportType[];
}

/**
 * PublicKeyCredentialUserEntity as JSON
 */
export interface PublicKeyCredentialUserEntityJSON {
  id: string;
  name: string;
  displayName: string;
}

/**
 * AuthenticatorAssertionResponse as JSON
 */
export interface AuthenticatorAssertionResponseJSON {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string;
}

/**
 * AuthenticatorAttestationResponse as JSON (inner response part)
 */
export interface AuthenticatorAttestationResponseJSON {
  clientDataJSON: string;
  attestationObject: string;
  transports?: AuthenticatorTransportType[];
}

/**
 * Full RegistrationResponseJSON format (compatible with @simplewebauthn/server)
 *
 * This is the complete WebAuthn credential structure returned by navigator.credentials.create()
 */
export interface RegistrationResponseJSON {
  /** Credential ID (base64url) */
  id: string;
  /** Credential ID (base64url, same as id) */
  rawId: string;
  /** Attestation response */
  response: AuthenticatorAttestationResponseJSON;
  /** Always 'public-key' */
  type: 'public-key';
  /** Client extension results */
  clientExtensionResults: Record<string, unknown>;
  /** Authenticator attachment type */
  authenticatorAttachment?: 'platform' | 'cross-platform' | null;
}

/**
 * Full AuthenticationResponseJSON format (compatible with @simplewebauthn/server)
 *
 * This is the complete WebAuthn credential structure returned by navigator.credentials.get()
 */
export interface AuthenticationResponseJSON {
  /** Credential ID (base64url) */
  id: string;
  /** Credential ID (base64url, same as id) */
  rawId: string;
  /** Assertion response */
  response: AuthenticatorAssertionResponseJSON;
  /** Always 'public-key' */
  type: 'public-key';
  /** Client extension results */
  clientExtensionResults: Record<string, unknown>;
  /** Authenticator attachment type */
  authenticatorAttachment?: 'platform' | 'cross-platform' | null;
}

// =============================================================================
// SDK Interface Types
// =============================================================================

/**
 * Direct Auth client configuration
 */
export interface DirectAuthClientConfig {
  /** Authrim IdP URL */
  issuer: string;
  /** OAuth client ID */
  clientId: string;
  /** Default redirect URI */
  redirectUri?: string;
}

/**
 * Passkey authentication interface
 */
export interface PasskeyAuth {
  /** Login with Passkey */
  login(options?: PasskeyLoginOptions): Promise<AuthResult>;
  /** Sign up with Passkey (create account + register Passkey) */
  signUp(options: PasskeySignUpOptions): Promise<AuthResult>;
  /** Register a Passkey to existing account (requires authentication) */
  register(options?: PasskeyRegisterOptions): Promise<PasskeyCredential>;
  /** Check if WebAuthn is supported */
  isSupported(): boolean;
  /** Check if conditional UI (autofill) is available */
  isConditionalUIAvailable(): Promise<boolean>;
}

/**
 * Email code authentication interface
 */
export interface EmailCodeAuth {
  /** Send verification code to email */
  send(email: string, options?: EmailCodeSendOptions): Promise<EmailCodeSendResult>;
  /** Verify code and authenticate */
  verify(email: string, code: string, options?: EmailCodeVerifyOptions): Promise<AuthResult>;
}

/**
 * Social login interface
 */
export interface SocialAuth {
  /** Login with social provider (popup) */
  loginWithPopup(provider: SocialProvider, options?: SocialLoginOptions): Promise<AuthResult>;
  /** Login with social provider (redirect) */
  loginWithRedirect(provider: SocialProvider, options?: SocialLoginOptions): Promise<void>;
  /** Handle callback from social provider (redirect) */
  handleCallback(): Promise<AuthResult>;
}

/**
 * Session management interface
 */
export interface SessionAuth {
  /** Get current session */
  get(): Promise<Session | null>;
  /** Validate session */
  validate(): Promise<boolean>;
  /** Logout */
  logout(options?: DirectAuthLogoutOptions): Promise<void>;
}

/**
 * Direct Auth client interface (BetterAuth style)
 */
export interface DirectAuthClient {
  /** Passkey authentication */
  passkey: PasskeyAuth;
  /** Email code authentication */
  emailCode: EmailCodeAuth;
  /** Social login */
  social: SocialAuth;
  /** Session management */
  session: SessionAuth;
}

// =============================================================================
// Silent Login Types (Cross-Domain SSO)
// =============================================================================

/**
 * Silent Login options for cross-domain SSO
 *
 * Executes prompt=none via top-level navigation to check IdP session.
 * Works with Safari ITP and Chrome Third-Party Cookie Phaseout.
 */
export interface TrySilentLoginOptions {
  /**
   * Behavior when IdP has no session (login_required error)
   *
   * - 'return': Return to original page (show login button, etc.)
   * - 'login': Show login screen for user authentication
   *
   * Default: 'return'
   */
  onLoginRequired?: 'return' | 'login';

  /**
   * Return URL (used for both success and return scenarios)
   * Default: current URL
   */
  returnTo?: string;

  /**
   * OAuth scopes (if additional scopes are needed)
   */
  scope?: string;
}

/**
 * Silent Login result (used in callback page)
 *
 * error values follow OIDC standard error codes:
 * - 'login_required': IdP has no session
 * - 'interaction_required': User interaction needed
 * - 'consent_required': Re-consent needed
 * - 'invalid_return_to': Invalid returnTo URL (SDK-specific)
 */
export type SilentLoginResult =
  | { status: 'success' }
  | { status: 'login_required' }
  | { status: 'error'; error: string; errorDescription?: string };

/**
 * Silent Login state data (stored in state parameter)
 * @internal
 */
export interface SilentLoginStateData {
  /** Type identifier: 'sl' = silent_login */
  t: 'sl';
  /** onLoginRequired: 'l' = login, 'r' = return */
  lr: 'l' | 'r';
  /** Return URL */
  rt: string;
}
