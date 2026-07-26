import { PKCEHelper, type PKCEPair } from '../auth/pkce.js';
import type { CryptoProvider } from '../providers/crypto.js';
import type { HttpClient, HttpOptions } from '../providers/http.js';
import type { AuthrimStorage } from '../providers/storage.js';
import { assertNoBrowserTokenMaterial } from '../session/profiles.js';
import { AuthrimError, type Phase1ErrorDetails } from '../types/errors.js';
import type {
  AuthenticationResponseJSON,
  DirectAuthChannel,
  DirectAuthManagedSessionResponse,
  EmailCodeVerifyResponse,
  PasskeyLoginFinishResponse,
  PasskeyLoginStartResponse,
  PasskeySignupFinishResponse,
  PasskeySignupStartResponse,
  RegistrationResponseJSON,
} from './types.js';

export interface DirectAuthBrowserSessionClientOptions {
  /** Authrim issuer. Used as the API base URL when baseUrl is omitted. */
  issuer: string;
  /** API base URL for browser surfaces that call Authrim through a same-origin proxy. */
  baseUrl?: string;
  clientId: string;
  http: HttpClient;
  crypto: CryptoProvider;
  storage: AuthrimStorage;
  storageKeyPrefix?: string;
}

export interface DirectAuthRequestOptions {
  headers?: Record<string, string>;
  signal?: AbortSignal;
  timeout?: number;
}

export interface PasskeyLoginStartInput {
  email?: string;
  scope?: string;
  authorizationChallengeId?: string;
  humanVerificationResponse?: string;
}

export interface PasskeySignupStartInput {
  email?: string;
  displayName?: string;
  customFields?: Record<string, unknown>;
  scope?: string;
  authorizationChallengeId?: string;
  humanVerificationResponse?: string;
}

export interface PasskeyFinishInput<TCredential> {
  challengeId: string;
  credential: TCredential;
}

export interface ManagedDirectAuthSessionOptions {
  authorizationChallengeId?: string;
  deferAuthorizationContinuation?: boolean;
  providerId?: string;
}

export interface EmailCodeSendInput {
  email: string;
  displayName?: string;
  inviteToken?: string;
  customFields?: Record<string, unknown>;
  scope?: string;
  locale?: string;
  authorizationChallengeId?: string;
  deferAuthorizationContinuation?: boolean;
  humanVerificationResponse?: string;
  runtimeInteractionId?: string;
  emailVerification?: {
    token: string;
    challengeId: string;
    interactionId?: string;
  };
}

export interface EmailCodeVerifyInput {
  email: string;
  code: string;
}

export interface DirectAuthBrowserEmailCodeSendResponse {
  attempt_id?: string;
  expires_in: number;
  masked_email?: string;
  direct_auth_artifact?: string;
  is_new_user?: boolean;
  _dev_code?: string;
}

export type DirectAuthEmailCodeManagedSessionResult =
  | {
      status: 'challenge';
      response: DirectAuthBrowserEmailCodeSendResponse;
    }
  | {
      status: 'completed';
      session: DirectAuthManagedSessionResponse;
    };

export interface TotpStartLoginInput {
  identifier?: string;
  authorizationChallengeId?: string;
}

export interface TotpVerifyLoginInput {
  challengeId: string;
  code: string;
  authorizationChallengeId?: string;
  deferAuthorizationContinuation?: boolean;
}

export interface TotpSignupOptionsInput {
  email: string;
  name?: string;
  label?: string;
  customFields?: Record<string, unknown>;
  authorizationChallengeId?: string;
  humanVerificationResponse?: string;
}

export interface TotpActivateSignupInput {
  challengeId: string;
  code: string;
  deferAuthorizationContinuation?: boolean;
}

export interface TotpLoginStartResponse {
  challenge_id: string;
  expires_in: number;
}

export interface TotpCredential {
  id: string;
  label: string | null;
  algorithm: 'SHA1' | 'SHA256';
  digits: number;
  period: number;
  window: number;
  status: 'pending' | 'active' | 'disabled';
  created_at: number;
  activated_at: number | null;
  last_used_at: number | null;
}

export interface TotpProfile {
  algorithm: 'SHA1' | 'SHA256';
  digits: number;
  period: number;
  window: number;
}

export interface TotpSignupOptionsResponse {
  challenge_id: string;
  expires_in: number;
  credential: TotpCredential;
  secret: string;
  otpauth_uri: string;
  profile: TotpProfile;
}

export interface TotpManagedSessionResponse {
  ok?: boolean;
  success: boolean;
  sessionId?: string;
  redirect_url?: string;
  authorization?: {
    challenge_id?: string;
    type?: string;
  };
  session?: {
    userId: string;
    createdAt: number;
    expiresAt: number;
    authTime?: number;
    acr?: string;
    amr?: string[];
  };
  user: {
    id: string;
    email: string;
    name?: string | null;
  };
  backup_codes?: string[];
}

export interface DirectoryPasswordLoginInput {
  username: string;
  password: string;
  inviteToken?: string;
  authorizationChallengeId?: string;
  deferAuthorizationContinuation?: boolean;
  humanVerificationResponse?: string;
}

export interface DirectoryPasswordMigrationResponse {
  ok: false;
  migration: {
    required: boolean;
    action: 'prompt_passkey' | 'require_passkey';
    transaction_id?: string;
    transaction_token?: string;
    expires_at?: number;
    campaign_id: string;
    state: string;
    reason?: string;
    passkey_required_at?: number | null;
    email_code_fallback_mode?: string;
    email_code_fallback_available?: boolean;
    email_code_fallback?: {
      transaction_id: string;
      transaction_token: string;
      expires_at: number;
      masked_email: string;
    };
  };
  user?: {
    id: string;
    email: string;
    name?: string | null;
  };
}

export interface DirectoryPasswordRecoveryResponse {
  ok: false;
  recovery: {
    required: boolean;
    reason: 'directory_unavailable';
    transaction_id: string;
    transaction_token: string;
    expires_at: number;
    masked_email: string;
  };
  user?: {
    id: string;
    email: string;
    name?: string | null;
  };
}

export type DirectoryPasswordLoginResponse =
  | DirectAuthManagedSessionResponse
  | DirectoryPasswordMigrationResponse
  | DirectoryPasswordRecoveryResponse;

export interface DirectoryPasswordMigrationPasskeyOptionsInput {
  transactionId: string;
  transactionToken: string;
  displayName?: string;
}

export interface DirectoryPasswordMigrationPasskeyOptionsResponse {
  challenge_id: string;
  options: unknown;
}

export interface DirectoryPasswordMigrationPasskeyVerifyInput {
  transactionId: string;
  transactionToken: string;
  challengeId: string;
  credential: unknown;
  deviceName?: string;
}

export interface DirectoryPasswordMigrationEmailCodeSendInput {
  transactionId: string;
  transactionToken: string;
}

export interface DirectoryPasswordMigrationEmailCodeSendResponse {
  success: boolean;
  challenge_id: string;
  expires_in: number;
  masked_email: string;
}

export interface DirectoryPasswordMigrationEmailCodeVerifyInput {
  transactionId: string;
  transactionToken: string;
  challengeId: string;
  code: string;
}

interface DirectAuthState {
  codeVerifier: string;
}

interface DirectEmailCodeState extends DirectAuthState {
  attemptId: string;
}

interface DirectAuthFailureBody {
  error: string;
  error_description?: string;
  error_uri?: string;
  error_details?: Phase1ErrorDetails;
  [key: string]: unknown;
}

type DirectAuthStateKind = 'passkey-login' | 'passkey-signup' | 'email-code';

export class DirectAuthBrowserSessionClient {
  private readonly baseUrl: string;
  private readonly clientId: string;
  private readonly http: HttpClient;
  private readonly storage: AuthrimStorage;
  private readonly pkce: PKCEHelper;
  private readonly storageKeyPrefix: string;
  private readonly channel: DirectAuthChannel = 'browser';

  constructor(options: DirectAuthBrowserSessionClientOptions) {
    this.baseUrl = normalizeBaseUrl(options.baseUrl ?? options.issuer, 'baseUrl');
    this.clientId = requireNonEmpty(options.clientId, 'clientId');
    this.http = options.http;
    this.storage = options.storage;
    this.pkce = new PKCEHelper(options.crypto);
    this.storageKeyPrefix =
      options.storageKeyPrefix ?? `authrim:direct-auth:${encodeStorageKeyPart(this.clientId)}`;
  }

  async startPasskeyLogin(
    input: PasskeyLoginStartInput = {},
    options?: DirectAuthRequestOptions
  ): Promise<PasskeyLoginStartResponse> {
    const pkce = await this.pkce.generatePKCE();
    const response = await this.request<PasskeyLoginStartResponse>(
      '/api/v1/auth/direct/passkey/login/start',
      {
        method: 'POST',
        headers: jsonHeaders(options?.headers),
        body: JSON.stringify({
          client_id: this.clientId,
          code_challenge: pkce.codeChallenge,
          code_challenge_method: pkce.codeChallengeMethod,
          channel: this.channel,
          email: input.email,
          scope: input.scope,
          authorization_challenge_id: input.authorizationChallengeId,
          human_verification_response: input.humanVerificationResponse,
        }),
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
    await this.persistState('passkey-login', response.challenge_id, {
      codeVerifier: pkce.codeVerifier,
    });
    return response;
  }

  async finishPasskeyLogin(
    input: PasskeyFinishInput<AuthenticationResponseJSON | unknown>,
    options?: DirectAuthRequestOptions
  ): Promise<PasskeyLoginFinishResponse> {
    const state = await this.consumeDirectState('passkey-login', input.challengeId);
    return this.request<PasskeyLoginFinishResponse>('/api/v1/auth/direct/passkey/login/finish', {
      method: 'POST',
      headers: jsonHeaders(options?.headers),
      body: JSON.stringify({
        challenge_id: input.challengeId,
        credential: input.credential,
        code_verifier: state.codeVerifier,
        channel: this.channel,
      }),
      signal: options?.signal,
      timeout: options?.timeout,
    });
  }

  async finishPasskeyLoginWithManagedSession(
    input: PasskeyFinishInput<AuthenticationResponseJSON | unknown>,
    sessionOptions: ManagedDirectAuthSessionOptions = {},
    requestOptions?: DirectAuthRequestOptions
  ): Promise<DirectAuthManagedSessionResponse> {
    const state = await this.consumeDirectState('passkey-login', input.challengeId);
    const finish = await this.request<PasskeyLoginFinishResponse>(
      '/api/v1/auth/direct/passkey/login/finish',
      {
        method: 'POST',
        headers: jsonHeaders(requestOptions?.headers),
        body: JSON.stringify({
          challenge_id: input.challengeId,
          credential: input.credential,
          code_verifier: state.codeVerifier,
          channel: this.channel,
        }),
        signal: requestOptions?.signal,
        timeout: requestOptions?.timeout,
      }
    );
    return this.finalizeManagedSession(
      finish.direct_auth_artifact,
      state.codeVerifier,
      sessionOptions,
      requestOptions
    );
  }

  async startPasskeySignup(
    input: PasskeySignupStartInput = {},
    options?: DirectAuthRequestOptions
  ): Promise<PasskeySignupStartResponse> {
    const pkce = await this.pkce.generatePKCE();
    const response = await this.request<PasskeySignupStartResponse>(
      '/api/v1/auth/direct/passkey/signup/start',
      {
        method: 'POST',
        headers: jsonHeaders(options?.headers),
        body: JSON.stringify({
          client_id: this.clientId,
          code_challenge: pkce.codeChallenge,
          code_challenge_method: pkce.codeChallengeMethod,
          channel: this.channel,
          email: input.email,
          display_name: input.displayName,
          custom_fields: input.customFields,
          scope: input.scope,
          authorization_challenge_id: input.authorizationChallengeId,
          human_verification_response: input.humanVerificationResponse,
        }),
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
    await this.persistState('passkey-signup', response.challenge_id, {
      codeVerifier: pkce.codeVerifier,
    });
    return response;
  }

  async finishPasskeySignup(
    input: PasskeyFinishInput<RegistrationResponseJSON | unknown>,
    options?: DirectAuthRequestOptions
  ): Promise<PasskeySignupFinishResponse> {
    const state = await this.consumeDirectState('passkey-signup', input.challengeId);
    return this.request<PasskeySignupFinishResponse>('/api/v1/auth/direct/passkey/signup/finish', {
      method: 'POST',
      headers: jsonHeaders(options?.headers),
      body: JSON.stringify({
        challenge_id: input.challengeId,
        credential: input.credential,
        code_verifier: state.codeVerifier,
        channel: this.channel,
      }),
      signal: options?.signal,
      timeout: options?.timeout,
    });
  }

  async finishPasskeySignupWithManagedSession(
    input: PasskeyFinishInput<RegistrationResponseJSON | unknown>,
    sessionOptions: ManagedDirectAuthSessionOptions = {},
    requestOptions?: DirectAuthRequestOptions
  ): Promise<DirectAuthManagedSessionResponse> {
    const state = await this.consumeDirectState('passkey-signup', input.challengeId);
    const finish = await this.request<PasskeySignupFinishResponse>(
      '/api/v1/auth/direct/passkey/signup/finish',
      {
        method: 'POST',
        headers: jsonHeaders(requestOptions?.headers),
        body: JSON.stringify({
          challenge_id: input.challengeId,
          credential: input.credential,
          code_verifier: state.codeVerifier,
          channel: this.channel,
        }),
        signal: requestOptions?.signal,
        timeout: requestOptions?.timeout,
      }
    );
    return this.finalizeManagedSession(
      finish.direct_auth_artifact,
      state.codeVerifier,
      sessionOptions,
      requestOptions
    );
  }

  async sendEmailCode(
    input: EmailCodeSendInput,
    options?: DirectAuthRequestOptions
  ): Promise<DirectAuthBrowserEmailCodeSendResponse> {
    const { email, pkce, response } = await this.sendEmailCodeRequest(input, options);

    if (hasDirectAuthArtifact(response)) {
      return response;
    }
    if (!response.attempt_id) {
      throw new AuthrimError('invalid_response', 'Email code send response is missing attempt_id');
    }

    await this.persistEmailCodeState(email, {
      attemptId: response.attempt_id,
      codeVerifier: pkce.codeVerifier,
    });
    return response;
  }

  async sendEmailCodeWithManagedSession(
    input: EmailCodeSendInput,
    sessionOptions: ManagedDirectAuthSessionOptions = {},
    requestOptions?: DirectAuthRequestOptions
  ): Promise<DirectAuthEmailCodeManagedSessionResult> {
    const { email, pkce, response } = await this.sendEmailCodeRequest(input, requestOptions);

    if (hasDirectAuthArtifact(response)) {
      return {
        status: 'completed',
        session: await this.finalizeManagedSession(
          response.direct_auth_artifact,
          pkce.codeVerifier,
          {
            authorizationChallengeId:
              sessionOptions.authorizationChallengeId ?? input.authorizationChallengeId,
            deferAuthorizationContinuation:
              sessionOptions.deferAuthorizationContinuation ?? input.deferAuthorizationContinuation,
            providerId: sessionOptions.providerId,
          },
          requestOptions
        ),
      };
    }
    if (!response.attempt_id) {
      throw new AuthrimError('invalid_response', 'Email code send response is missing attempt_id');
    }

    await this.persistEmailCodeState(email, {
      attemptId: response.attempt_id,
      codeVerifier: pkce.codeVerifier,
    });
    return {
      status: 'challenge',
      response,
    };
  }

  async verifyEmailCode(
    input: EmailCodeVerifyInput,
    options?: DirectAuthRequestOptions
  ): Promise<EmailCodeVerifyResponse> {
    const state = await this.readEmailCodeState(input.email);
    const response = await this.request<EmailCodeVerifyResponse>(
      '/api/v1/auth/direct/email-code/verify',
      {
        method: 'POST',
        headers: jsonHeaders(options?.headers),
        body: JSON.stringify({
          attempt_id: state.attemptId,
          code: input.code,
          code_verifier: state.codeVerifier,
          channel: this.channel,
        }),
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
    await this.clearEmailCodeStateIfCurrent(input.email, state);
    return response;
  }

  async verifyEmailCodeWithManagedSession(
    input: EmailCodeVerifyInput,
    sessionOptions: ManagedDirectAuthSessionOptions = {},
    requestOptions?: DirectAuthRequestOptions
  ): Promise<DirectAuthManagedSessionResponse> {
    const state = await this.readEmailCodeState(input.email);
    const finish = await this.request<EmailCodeVerifyResponse>(
      '/api/v1/auth/direct/email-code/verify',
      {
        method: 'POST',
        headers: jsonHeaders(requestOptions?.headers),
        body: JSON.stringify({
          attempt_id: state.attemptId,
          code: input.code,
          code_verifier: state.codeVerifier,
          channel: this.channel,
        }),
        signal: requestOptions?.signal,
        timeout: requestOptions?.timeout,
      }
    );
    await this.clearEmailCodeStateIfCurrent(input.email, state);
    return this.finalizeManagedSession(
      finish.direct_auth_artifact,
      state.codeVerifier,
      sessionOptions,
      requestOptions
    );
  }

  async finalizeManagedSession(
    directAuthArtifact: string,
    codeVerifier: string,
    sessionOptions: ManagedDirectAuthSessionOptions = {},
    requestOptions?: DirectAuthRequestOptions
  ): Promise<DirectAuthManagedSessionResponse> {
    const session = await this.request<DirectAuthManagedSessionResponse>(
      '/api/v1/auth/direct/session',
      {
        method: 'POST',
        headers: jsonHeaders(requestOptions?.headers),
        body: JSON.stringify({
          direct_auth_artifact: requireNonEmpty(directAuthArtifact, 'directAuthArtifact'),
          client_id: this.clientId,
          code_verifier: requireNonEmpty(codeVerifier, 'codeVerifier'),
          channel: this.channel,
          provider_id: sessionOptions.providerId,
          authorization_challenge_id: sessionOptions.authorizationChallengeId,
          defer_authorization_continuation: sessionOptions.deferAuthorizationContinuation === true,
        }),
        signal: requestOptions?.signal,
        timeout: requestOptions?.timeout,
      }
    );
    assertNoBrowserTokenMaterial(session, 'direct auth managed session');
    return session;
  }

  async clearEmailCodeState(email: string): Promise<void> {
    await this.storage.remove(this.stateKey('email-code', normalizeEmail(email)));
  }

  async startTotpLogin(
    input: TotpStartLoginInput = {},
    options?: DirectAuthRequestOptions
  ): Promise<TotpLoginStartResponse> {
    return this.request<TotpLoginStartResponse>('/api/auth/totp/login/start', {
      method: 'POST',
      headers: jsonHeaders(options?.headers),
      body: JSON.stringify({
        identifier: input.identifier,
        authorization_challenge_id: input.authorizationChallengeId,
      }),
      signal: options?.signal,
      timeout: options?.timeout,
    });
  }

  async verifyTotpLogin(
    input: TotpVerifyLoginInput,
    options?: DirectAuthRequestOptions
  ): Promise<TotpManagedSessionResponse> {
    const session = await this.request<TotpManagedSessionResponse>('/api/auth/totp/login/verify', {
      method: 'POST',
      headers: jsonHeaders(options?.headers),
      body: JSON.stringify({
        challenge_id: input.challengeId,
        code: input.code,
        authorization_challenge_id: input.authorizationChallengeId,
        defer_authorization_continuation: input.deferAuthorizationContinuation === true,
      }),
      signal: options?.signal,
      timeout: options?.timeout,
    });
    assertNoBrowserTokenMaterial(session, 'TOTP login');
    return session;
  }

  async createTotpSignupOptions(
    input: TotpSignupOptionsInput,
    options?: DirectAuthRequestOptions
  ): Promise<TotpSignupOptionsResponse> {
    return this.request<TotpSignupOptionsResponse>('/api/auth/totp/signup/options', {
      method: 'POST',
      headers: jsonHeaders(options?.headers),
      body: JSON.stringify({
        email: normalizeEmail(input.email),
        name: input.name,
        label: input.label,
        custom_fields: input.customFields,
        authorization_challenge_id: input.authorizationChallengeId,
        human_verification_response: input.humanVerificationResponse,
      }),
      signal: options?.signal,
      timeout: options?.timeout,
    });
  }

  async activateTotpSignup(
    input: TotpActivateSignupInput,
    options?: DirectAuthRequestOptions
  ): Promise<TotpManagedSessionResponse> {
    const session = await this.request<TotpManagedSessionResponse>(
      '/api/auth/totp/signup/activate',
      {
        method: 'POST',
        headers: jsonHeaders(options?.headers),
        body: JSON.stringify({
          challenge_id: input.challengeId,
          code: input.code,
          defer_authorization_continuation: input.deferAuthorizationContinuation === true,
        }),
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
    assertNoBrowserTokenMaterial(session, 'TOTP signup');
    return session;
  }

  async loginWithDirectoryPassword(
    input: DirectoryPasswordLoginInput,
    options?: DirectAuthRequestOptions
  ): Promise<DirectoryPasswordLoginResponse> {
    const session = await this.request<DirectoryPasswordLoginResponse>(
      '/api/auth/directory-password/login',
      {
        method: 'POST',
        headers: jsonHeaders(options?.headers),
        body: JSON.stringify({
          username: input.username,
          password: input.password,
          invite_token: input.inviteToken,
          authorization_challenge_id: input.authorizationChallengeId,
          defer_authorization_continuation: input.deferAuthorizationContinuation === true,
          human_verification_response: input.humanVerificationResponse,
        }),
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
    assertNoBrowserTokenMaterial(session, 'directory password login');
    return session;
  }

  async createDirectoryPasswordMigrationPasskeyOptions(
    input: DirectoryPasswordMigrationPasskeyOptionsInput,
    options?: DirectAuthRequestOptions
  ): Promise<DirectoryPasswordMigrationPasskeyOptionsResponse> {
    return this.request<DirectoryPasswordMigrationPasskeyOptionsResponse>(
      '/api/auth/directory-password/migration/passkey/options',
      {
        method: 'POST',
        headers: jsonHeaders(options?.headers),
        body: JSON.stringify({
          transaction_id: input.transactionId,
          transaction_token: input.transactionToken,
          display_name: input.displayName,
        }),
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
  }

  async verifyDirectoryPasswordMigrationPasskey(
    input: DirectoryPasswordMigrationPasskeyVerifyInput,
    options?: DirectAuthRequestOptions
  ): Promise<DirectAuthManagedSessionResponse> {
    const session = await this.request<DirectAuthManagedSessionResponse>(
      '/api/auth/directory-password/migration/passkey/verify',
      {
        method: 'POST',
        headers: jsonHeaders(options?.headers),
        body: JSON.stringify({
          transaction_id: input.transactionId,
          transaction_token: input.transactionToken,
          challenge_id: input.challengeId,
          credential: input.credential,
          device_name: input.deviceName,
        }),
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
    assertNoBrowserTokenMaterial(session, 'directory password migration passkey');
    return session;
  }

  async sendDirectoryPasswordMigrationEmailCode(
    input: DirectoryPasswordMigrationEmailCodeSendInput,
    options?: DirectAuthRequestOptions
  ): Promise<DirectoryPasswordMigrationEmailCodeSendResponse> {
    return this.request<DirectoryPasswordMigrationEmailCodeSendResponse>(
      '/api/auth/directory-password/migration/email-code/send',
      {
        method: 'POST',
        headers: jsonHeaders(options?.headers),
        body: JSON.stringify({
          transaction_id: input.transactionId,
          transaction_token: input.transactionToken,
        }),
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
  }

  async verifyDirectoryPasswordMigrationEmailCode(
    input: DirectoryPasswordMigrationEmailCodeVerifyInput,
    options?: DirectAuthRequestOptions
  ): Promise<DirectAuthManagedSessionResponse> {
    const session = await this.request<DirectAuthManagedSessionResponse>(
      '/api/auth/directory-password/migration/email-code/verify',
      {
        method: 'POST',
        headers: jsonHeaders(options?.headers),
        body: JSON.stringify({
          transaction_id: input.transactionId,
          transaction_token: input.transactionToken,
          challenge_id: input.challengeId,
          code: input.code,
        }),
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
    assertNoBrowserTokenMaterial(session, 'directory password migration email code');
    return session;
  }

  private async sendEmailCodeRequest(
    input: EmailCodeSendInput,
    options?: DirectAuthRequestOptions
  ): Promise<{
    email: string;
    pkce: PKCEPair;
    response: DirectAuthBrowserEmailCodeSendResponse;
  }> {
    const email = normalizeEmail(input.email);
    const pkce = await this.pkce.generatePKCE();
    const response = await this.request<DirectAuthBrowserEmailCodeSendResponse>(
      '/api/v1/auth/direct/email-code/send',
      {
        method: 'POST',
        headers: jsonHeaders(options?.headers),
        body: JSON.stringify({
          client_id: this.clientId,
          email,
          display_name: input.displayName,
          code_challenge: pkce.codeChallenge,
          code_challenge_method: pkce.codeChallengeMethod,
          channel: this.channel,
          scope: input.scope,
          locale: input.locale,
          invite_token: input.inviteToken,
          authorization_challenge_id: input.authorizationChallengeId,
          custom_fields: input.customFields,
          human_verification_response: input.humanVerificationResponse,
          email_verification_token: input.emailVerification?.token,
          email_verification_challenge_id: input.emailVerification?.challengeId,
          runtime_interaction_id:
            input.runtimeInteractionId ?? input.emailVerification?.interactionId,
        }),
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
    return { email, pkce, response };
  }

  private async persistEmailCodeState(email: string, state: DirectEmailCodeState): Promise<void> {
    await this.storage.set(
      this.stateKey('email-code', normalizeEmail(email)),
      JSON.stringify(state)
    );
  }

  private async readEmailCodeState(email: string): Promise<DirectEmailCodeState> {
    const key = this.stateKey('email-code', normalizeEmail(email));
    const raw = await this.storage.get(key);
    const state = readEmailCodeState(raw);
    if (!state) {
      throw new AuthrimError('invalid_state', 'Email code state is missing or expired');
    }
    return state;
  }

  private async clearEmailCodeStateIfCurrent(
    email: string,
    expected: DirectEmailCodeState
  ): Promise<void> {
    const key = this.stateKey('email-code', normalizeEmail(email));
    const current = readEmailCodeState(await this.storage.get(key));
    if (
      current &&
      current.attemptId === expected.attemptId &&
      current.codeVerifier === expected.codeVerifier
    ) {
      await this.storage.remove(key);
    }
  }

  private async persistState(
    kind: DirectAuthStateKind,
    id: string,
    state: DirectAuthState
  ): Promise<void> {
    await this.storage.set(this.stateKey(kind, id), JSON.stringify(state));
  }

  private async consumeDirectState(
    kind: Exclude<DirectAuthStateKind, 'email-code'>,
    id: string
  ): Promise<DirectAuthState> {
    const key = this.stateKey(kind, id);
    const raw = await this.storage.get(key);
    await this.storage.remove(key);
    const state = readDirectState(raw);
    if (!state) {
      throw new AuthrimError('invalid_state', `${kind} state is missing or expired`);
    }
    return state;
  }

  private stateKey(kind: DirectAuthStateKind, id: string): string {
    return `${this.storageKeyPrefix}:${kind}:${encodeStorageKeyPart(id)}`;
  }

  private async request<T>(path: string, options: HttpOptions): Promise<T> {
    let response;
    try {
      response = await this.http.fetch<T | DirectAuthFailureBody>(
        `${this.baseUrl}${path}`,
        options
      );
    } catch (error) {
      throw new AuthrimError('network_error', 'Direct Auth request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (!response.ok) {
      if (isFailureBody(response.data)) {
        throw AuthrimError.fromOAuthError(response.data);
      }
      throw new AuthrimError('invalid_request', 'Direct Auth request failed', {
        details: { status: response.status },
      });
    }
    return response.data as T;
  }
}

function normalizeBaseUrl(value: string, name: string): string {
  const baseUrl = requireNonEmpty(value, name);
  const url = new URL(baseUrl);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new AuthrimError('configuration_error', `${name} must use http or https`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new AuthrimError(
      'configuration_error',
      `${name} must not include userinfo, search, or hash`
    );
  }
  return url.toString().replace(/\/+$/, '');
}

function requireNonEmpty(value: string, name: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new AuthrimError('configuration_error', `${name} is required`);
  }
  return normalized;
}

function normalizeEmail(value: string): string {
  return requireNonEmpty(value, 'email').toLowerCase();
}

function encodeStorageKeyPart(value: string): string {
  return encodeURIComponent(value);
}

function jsonHeaders(headers?: Record<string, string>): Record<string, string> {
  return {
    ...(headers ?? {}),
    'Content-Type': headers?.['Content-Type'] ?? headers?.['content-type'] ?? 'application/json',
  };
}

function readDirectState(value: string | null): DirectAuthState | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<DirectAuthState>;
    return typeof parsed.codeVerifier === 'string' && parsed.codeVerifier
      ? { codeVerifier: parsed.codeVerifier }
      : null;
  } catch {
    return null;
  }
}

function readEmailCodeState(value: string | null): DirectEmailCodeState | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<DirectEmailCodeState>;
    return typeof parsed.attemptId === 'string' &&
      parsed.attemptId &&
      typeof parsed.codeVerifier === 'string' &&
      parsed.codeVerifier
      ? { attemptId: parsed.attemptId, codeVerifier: parsed.codeVerifier }
      : null;
  } catch {
    return null;
  }
}

function hasDirectAuthArtifact(
  value: DirectAuthBrowserEmailCodeSendResponse
): value is DirectAuthBrowserEmailCodeSendResponse & { direct_auth_artifact: string } {
  return typeof (value as { direct_auth_artifact?: unknown }).direct_auth_artifact === 'string';
}

function isFailureBody(value: unknown): value is DirectAuthFailureBody {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { error?: unknown }).error === 'string'
  );
}
