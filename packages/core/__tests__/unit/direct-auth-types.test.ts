/**
 * Direct Auth Types Tests
 *
 * Tests for Direct Authentication type definitions and error codes
 */

import { describe, it, expect } from 'vitest';
import {
  AuthrimError,
  getErrorMeta,
  type AuthrimErrorCode,
  type User,
  type Session,
  type AuthResult,
  type DirectAuthError,
  type NextAction,
  type SocialProvider,
  type MfaMethod,
  type PasskeyLoginOptions,
  type PasskeySignUpOptions,
  type PasskeyRegisterOptions,
  type PasskeyCredential,
  type EmailCodeSendOptions,
  type EmailCodeSendResult,
  type EmailCodeVerifyOptions,
  type SocialLoginOptions,
  type DirectAuthLogoutOptions,
  type PasskeyLoginStartRequest,
  type PasskeyLoginStartResponse,
  type PasskeyLoginFinishRequest,
  type PasskeyLoginFinishResponse,
  type PasskeySignupStartRequest,
  type PasskeySignupStartResponse,
  type PasskeySignupFinishRequest,
  type PasskeySignupFinishResponse,
  type EmailCodeSendRequest,
  type EmailCodeSendResponse,
  type EmailCodeVerifyRequest,
  type EmailCodeVerifyResponse,
  type DirectAuthTokenRequest,
  type DirectAuthTokenResponse,
  type DirectAuthClientConfig,
  type PasskeyAuth,
  type EmailCodeAuth,
  type SocialAuth,
  type SessionAuth,
  type DirectAuthClient,
  type PublicKeyCredentialRequestOptionsJSON,
  type PublicKeyCredentialCreationOptionsJSON,
} from '../../src/index.js';

describe('Direct Auth Types', () => {
  describe('Type Exports', () => {
    it('should export User type with expected shape', () => {
      const user: User = {
        id: 'user-123',
        email: 'test@example.com',
        emailVerified: true,
        name: 'Test User',
        picture: 'https://example.com/pic.jpg',
        username: 'testuser',
      };

      expect(user.id).toBe('user-123');
      expect(user.email).toBe('test@example.com');
      expect(user.emailVerified).toBe(true);
    });

    it('should export Session type with expected shape', () => {
      const session: Session = {
        id: 'session-123',
        userId: 'user-123',
        createdAt: '2025-01-20T00:00:00Z',
        expiresAt: '2025-01-21T00:00:00Z',
        lastActiveAt: '2025-01-20T12:00:00Z',
        userAgent: 'Mozilla/5.0',
        ipAddress: '192.168.1.1',
      };

      expect(session.id).toBe('session-123');
      expect(session.userId).toBe('user-123');
    });

    it('should export AuthResult type with success case', () => {
      const result: AuthResult = {
        success: true,
        session: {
          id: 'session-123',
          userId: 'user-123',
          createdAt: '2025-01-20T00:00:00Z',
          expiresAt: '2025-01-21T00:00:00Z',
        },
        user: {
          id: 'user-123',
          email: 'test@example.com',
        },
      };

      expect(result.success).toBe(true);
      expect(result.session?.id).toBe('session-123');
      expect(result.user?.email).toBe('test@example.com');
    });

    it('should export AuthResult type with error case', () => {
      const result: AuthResult = {
        success: false,
        error: {
          error: 'invalid_request',
          error_description: 'Missing required parameter',
          code: 'AR001001',
          meta: {
            retryable: false,
            severity: 'error',
          },
        },
      };

      expect(result.success).toBe(false);
      expect(result.error?.error).toBe('invalid_request');
    });

    it('should export AuthResult with nextAction', () => {
      const resultMfa: AuthResult = {
        success: false,
        nextAction: {
          type: 'mfa_required',
          methods: ['totp', 'email'],
        },
      };

      const resultConsent: AuthResult = {
        success: false,
        nextAction: {
          type: 'consent_required',
          scopes: ['openid', 'profile'],
        },
      };

      const resultVerify: AuthResult = {
        success: false,
        nextAction: {
          type: 'email_verification_required',
        },
      };

      expect(resultMfa.nextAction?.type).toBe('mfa_required');
      expect(resultConsent.nextAction?.type).toBe('consent_required');
      expect(resultVerify.nextAction?.type).toBe('email_verification_required');
    });

    it('should export DirectAuthError type', () => {
      const error: DirectAuthError = {
        error: 'passkey_not_found',
        error_description: 'No passkey registered for this account',
        code: 'AR003001',
        meta: {
          retryable: false,
          severity: 'warn',
          user_action: 'login',
        },
      };

      expect(error.error).toBe('passkey_not_found');
      expect(error.code).toBe('AR003001');
    });

    it('should export SocialProvider type', () => {
      const providers: SocialProvider[] = ['google', 'github', 'apple', 'microsoft', 'facebook'];
      expect(providers).toHaveLength(5);
    });

    it('should export MfaMethod type', () => {
      const methods: MfaMethod[] = ['totp', 'sms', 'email', 'passkey'];
      expect(methods).toHaveLength(4);
    });
  });

  describe('Passkey Types', () => {
    it('should export PasskeyLoginOptions', () => {
      const options: PasskeyLoginOptions = {
        conditional: true,
        mediation: 'conditional',
      };
      expect(options.conditional).toBe(true);
    });

    it('should export PasskeySignUpOptions', () => {
      const options: PasskeySignUpOptions = {
        email: 'test@example.com',
        displayName: 'Test User',
        authenticatorType: 'platform',
        residentKey: 'required',
        userVerification: 'required',
      };
      expect(options.email).toBe('test@example.com');
    });

    it('should export PasskeyRegisterOptions', () => {
      const options: PasskeyRegisterOptions = {
        displayName: 'My Passkey',
        authenticatorType: 'cross-platform',
      };
      expect(options.displayName).toBe('My Passkey');
    });

    it('should export PasskeyCredential', () => {
      const credential: PasskeyCredential = {
        credentialId: 'cred-123',
        publicKey: 'base64url-encoded-key',
        authenticatorType: 'platform',
        transports: ['internal'],
        createdAt: '2025-01-20T00:00:00Z',
        displayName: 'My MacBook',
      };
      expect(credential.credentialId).toBe('cred-123');
    });
  });

  describe('Email Code Types', () => {
    it('should export EmailCodeSendOptions', () => {
      const options: EmailCodeSendOptions = {
        locale: 'ja',
        codeLength: 6,
      };
      expect(options.locale).toBe('ja');
    });

    it('should export EmailCodeSendResult', () => {
      const result: EmailCodeSendResult = {
        attemptId: 'attempt-123',
        expiresIn: 300,
        maskedEmail: 't***@example.com',
        isNewUser: false,
      };
      expect(result.attemptId).toBe('attempt-123');
      expect(result.expiresIn).toBe(300);
    });

    it('should export EmailCodeVerifyOptions', () => {
      const options: EmailCodeVerifyOptions = {
        createAccountIfNotExists: true,
      };
      expect(options.createAccountIfNotExists).toBe(true);
    });
  });

  describe('Social Login Types', () => {
    it('should export SocialLoginOptions', () => {
      const options: SocialLoginOptions = {
        redirectUri: 'https://app.example.com/callback',
        scopes: ['openid', 'profile', 'email'],
        loginHint: 'user@example.com',
        popupFeatures: {
          width: 500,
          height: 600,
        },
      };
      expect(options.redirectUri).toBe('https://app.example.com/callback');
    });
  });

  describe('Session Types', () => {
    it('should export DirectAuthLogoutOptions', () => {
      const options: DirectAuthLogoutOptions = {
        revokeTokens: true,
        redirectUri: 'https://app.example.com',
      };
      expect(options.revokeTokens).toBe(true);
    });
  });

  describe('API Request/Response Types', () => {
    it('should export PasskeyLoginStartRequest', () => {
      const request: PasskeyLoginStartRequest = {
        client_id: 'client-123',
        code_challenge: 'challenge-value',
        code_challenge_method: 'S256',
      };
      expect(request.code_challenge_method).toBe('S256');
    });

    it('should export PasskeyLoginStartResponse', () => {
      const response: PasskeyLoginStartResponse = {
        challenge_id: 'challenge-123',
        options: {
          challenge: 'base64url-challenge',
          timeout: 60000,
          rpId: 'example.com',
          allowCredentials: [],
          userVerification: 'preferred',
        },
      };
      expect(response.challenge_id).toBe('challenge-123');
    });

    it('should export PasskeyLoginFinishRequest', () => {
      const request: PasskeyLoginFinishRequest = {
        challenge_id: 'challenge-123',
        credential: {
          clientDataJSON: 'base64url',
          authenticatorData: 'base64url',
          signature: 'base64url',
          userHandle: 'base64url',
        },
        code_verifier: 'verifier-value',
      };
      expect(request.challenge_id).toBe('challenge-123');
    });

    it('should export PasskeyLoginFinishResponse', () => {
      const response: PasskeyLoginFinishResponse = {
        auth_code: 'auth-code-123',
      };
      expect(response.auth_code).toBe('auth-code-123');
    });

    it('should export PasskeySignupStartRequest', () => {
      const request: PasskeySignupStartRequest = {
        client_id: 'client-123',
        email: 'test@example.com',
        display_name: 'Test User',
        code_challenge: 'challenge-value',
        code_challenge_method: 'S256',
        authenticator_type: 'platform',
        resident_key: 'required',
        user_verification: 'required',
      };
      expect(request.email).toBe('test@example.com');
    });

    it('should export PasskeySignupStartResponse', () => {
      const response: PasskeySignupStartResponse = {
        challenge_id: 'challenge-123',
        options: {
          rp: { name: 'Example' },
          user: { id: 'user-123', name: 'test@example.com', displayName: 'Test User' },
          challenge: 'base64url-challenge',
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
      };
      expect(response.options.rp.name).toBe('Example');
    });

    it('should export PasskeySignupFinishRequest', () => {
      const request: PasskeySignupFinishRequest = {
        challenge_id: 'challenge-123',
        credential: {
          clientDataJSON: 'base64url',
          attestationObject: 'base64url',
          transports: ['internal'],
        },
        code_verifier: 'verifier-value',
      };
      expect(request.credential.attestationObject).toBe('base64url');
    });

    it('should export PasskeySignupFinishResponse', () => {
      const response: PasskeySignupFinishResponse = {
        auth_code: 'auth-code-123',
        is_new_user: true,
      };
      expect(response.is_new_user).toBe(true);
    });

    it('should export EmailCodeSendRequest', () => {
      const request: EmailCodeSendRequest = {
        client_id: 'client-123',
        email: 'test@example.com',
        code_challenge: 'challenge-value',
        code_challenge_method: 'S256',
        locale: 'ja',
      };
      expect(request.email).toBe('test@example.com');
    });

    it('should export EmailCodeSendResponse', () => {
      const response: EmailCodeSendResponse = {
        attempt_id: 'attempt-123',
        expires_in: 300,
        masked_email: 't***@example.com',
      };
      expect(response.attempt_id).toBe('attempt-123');
    });

    it('should export EmailCodeVerifyRequest', () => {
      const request: EmailCodeVerifyRequest = {
        attempt_id: 'attempt-123',
        code: '123456',
        code_verifier: 'verifier-value',
      };
      expect(request.code).toBe('123456');
    });

    it('should export EmailCodeVerifyResponse', () => {
      const response: EmailCodeVerifyResponse = {
        auth_code: 'auth-code-123',
        is_new_user: false,
      };
      expect(response.is_new_user).toBe(false);
    });

    it('should export DirectAuthTokenRequest', () => {
      const request: DirectAuthTokenRequest = {
        grant_type: 'authorization_code',
        code: 'auth-code-123',
        client_id: 'client-123',
        code_verifier: 'verifier-value',
        request_refresh_token: true,
      };
      expect(request.grant_type).toBe('authorization_code');
    });

    it('should export DirectAuthTokenResponse with session_established', () => {
      const response: DirectAuthTokenResponse = {
        token_type: 'Bearer',
        access_token: 'access-token-123',
        expires_in: 3600,
        refresh_token: 'refresh-token-123',
        id_token: 'id-token-123',
        scope: 'openid profile email',
        session_established: true,
        session: {
          id: 'session-123',
          userId: 'user-123',
          createdAt: '2025-01-20T00:00:00Z',
          expiresAt: '2025-01-21T00:00:00Z',
        },
        user: {
          id: 'user-123',
          email: 'test@example.com',
        },
      };
      expect(response.session_established).toBe(true);
      expect(response.token_type).toBe('Bearer');
    });
  });

  describe('SDK Interface Types', () => {
    it('should export DirectAuthClientConfig', () => {
      const config: DirectAuthClientConfig = {
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        redirectUri: 'https://app.example.com/callback',
      };
      expect(config.issuer).toBe('https://auth.example.com');
    });

    it('should export PasskeyAuth interface shape', () => {
      // Type-only test - verify the interface can be used
      const mockPasskeyAuth: PasskeyAuth = {
        login: async () => ({ success: true }),
        signUp: async () => ({ success: true }),
        register: async () => ({
          credentialId: 'cred-123',
          publicKey: 'key',
          authenticatorType: 'platform',
          createdAt: '2025-01-20T00:00:00Z',
        }),
        isSupported: () => true,
        isConditionalUIAvailable: async () => true,
      };
      expect(mockPasskeyAuth.isSupported()).toBe(true);
    });

    it('should export EmailCodeAuth interface shape', () => {
      const mockEmailCodeAuth: EmailCodeAuth = {
        send: async () => ({
          attemptId: 'attempt-123',
          expiresIn: 300,
          maskedEmail: 't***@example.com',
        }),
        verify: async () => ({ success: true }),
      };
      expect(typeof mockEmailCodeAuth.send).toBe('function');
    });

    it('should export SocialAuth interface shape', () => {
      const mockSocialAuth: SocialAuth = {
        loginWithPopup: async () => ({ success: true }),
        loginWithRedirect: async () => {},
        handleCallback: async () => ({ success: true }),
      };
      expect(typeof mockSocialAuth.loginWithPopup).toBe('function');
    });

    it('should export SessionAuth interface shape', () => {
      const mockSessionAuth: SessionAuth = {
        get: async () => null,
        validate: async () => false,
        logout: async () => {},
      };
      expect(typeof mockSessionAuth.get).toBe('function');
    });

    it('should export DirectAuthClient interface shape', () => {
      const mockClient: DirectAuthClient = {
        passkey: {
          login: async () => ({ success: true }),
          signUp: async () => ({ success: true }),
          register: async () => ({
            credentialId: 'cred-123',
            publicKey: 'key',
            authenticatorType: 'platform',
            createdAt: '2025-01-20T00:00:00Z',
          }),
          isSupported: () => true,
          isConditionalUIAvailable: async () => true,
        },
        emailCode: {
          send: async () => ({
            attemptId: 'attempt-123',
            expiresIn: 300,
            maskedEmail: 't***@example.com',
          }),
          verify: async () => ({ success: true }),
        },
        social: {
          loginWithPopup: async () => ({ success: true }),
          loginWithRedirect: async () => {},
          handleCallback: async () => ({ success: true }),
        },
        session: {
          get: async () => null,
          validate: async () => false,
          logout: async () => {},
        },
      };
      expect(mockClient.passkey.isSupported()).toBe(true);
    });
  });

  describe('WebAuthn JSON Types', () => {
    it('should export PublicKeyCredentialRequestOptionsJSON', () => {
      const options: PublicKeyCredentialRequestOptionsJSON = {
        challenge: 'base64url-challenge',
        timeout: 60000,
        rpId: 'example.com',
        allowCredentials: [
          {
            type: 'public-key',
            id: 'cred-id',
            transports: ['internal', 'hybrid'],
          },
        ],
        userVerification: 'required',
      };
      expect(options.rpId).toBe('example.com');
    });

    it('should export PublicKeyCredentialCreationOptionsJSON', () => {
      const options: PublicKeyCredentialCreationOptionsJSON = {
        rp: {
          id: 'example.com',
          name: 'Example App',
        },
        user: {
          id: 'user-123',
          name: 'test@example.com',
          displayName: 'Test User',
        },
        challenge: 'base64url-challenge',
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        timeout: 60000,
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'none',
      };
      expect(options.rp.name).toBe('Example App');
    });
  });
});

describe('Direct Auth Error Codes', () => {
  describe('Passkey Error Codes', () => {
    it('should have passkey_not_found error', () => {
      const error = new AuthrimError('passkey_not_found', 'No passkey registered');
      expect(error.code).toBe('passkey_not_found');
      expect(error.meta.userAction).toBe('reauthenticate');
    });

    it('should have passkey_verification_failed error', () => {
      const error = new AuthrimError('passkey_verification_failed', 'Verification failed');
      expect(error.code).toBe('passkey_verification_failed');
      expect(error.meta.retryable).toBe(true);
    });

    it('should have passkey_not_supported error', () => {
      const error = new AuthrimError('passkey_not_supported', 'WebAuthn not supported');
      expect(error.code).toBe('passkey_not_supported');
      expect(error.meta.severity).toBe('warning');
    });

    it('should have passkey_cancelled error', () => {
      const error = new AuthrimError('passkey_cancelled', 'User cancelled');
      expect(error.code).toBe('passkey_cancelled');
    });

    it('should have passkey_invalid_credential error', () => {
      const error = new AuthrimError('passkey_invalid_credential', 'Invalid credential');
      expect(error.code).toBe('passkey_invalid_credential');
    });
  });

  describe('Email Code Error Codes', () => {
    it('should have email_code_invalid error', () => {
      const error = new AuthrimError('email_code_invalid', 'Invalid code');
      expect(error.code).toBe('email_code_invalid');
      expect(error.meta.retryable).toBe(true);
      expect(error.meta.maxRetries).toBe(5);
    });

    it('should have email_code_expired error', () => {
      const error = new AuthrimError('email_code_expired', 'Code expired');
      expect(error.code).toBe('email_code_expired');
      expect(error.meta.retryable).toBe(false);
    });

    it('should have email_code_too_many_attempts error', () => {
      const error = new AuthrimError('email_code_too_many_attempts', 'Too many attempts');
      expect(error.code).toBe('email_code_too_many_attempts');
      expect(error.meta.retryAfterMs).toBe(300000);
    });
  });

  describe('Challenge Error Codes', () => {
    it('should have challenge_expired error', () => {
      const error = new AuthrimError('challenge_expired', 'Challenge expired');
      expect(error.code).toBe('challenge_expired');
    });

    it('should have challenge_invalid error', () => {
      const error = new AuthrimError('challenge_invalid', 'Invalid challenge');
      expect(error.code).toBe('challenge_invalid');
    });
  });

  describe('Auth Code Error Codes', () => {
    it('should have auth_code_invalid error', () => {
      const error = new AuthrimError('auth_code_invalid', 'Invalid auth code');
      expect(error.code).toBe('auth_code_invalid');
    });

    it('should have auth_code_expired error', () => {
      const error = new AuthrimError('auth_code_expired', 'Auth code expired');
      expect(error.code).toBe('auth_code_expired');
    });
  });

  describe('Security Error Codes', () => {
    it('should have pkce_mismatch error', () => {
      const error = new AuthrimError('pkce_mismatch', 'PKCE verification failed');
      expect(error.code).toBe('pkce_mismatch');
      expect(error.meta.severity).toBe('error');
    });

    it('should have origin_not_allowed error', () => {
      const error = new AuthrimError('origin_not_allowed', 'Origin not in allowlist');
      expect(error.code).toBe('origin_not_allowed');
      expect(error.meta.severity).toBe('fatal');
    });

    it('should have rate_limited error', () => {
      const error = new AuthrimError('rate_limited', 'Rate limit exceeded');
      expect(error.code).toBe('rate_limited');
      expect(error.meta.transient).toBe(true);
      expect(error.meta.retryable).toBe(true);
      expect(error.meta.retryAfterMs).toBe(60000);
    });
  });

  describe('Flow Error Codes', () => {
    it('should have mfa_required error', () => {
      const error = new AuthrimError('mfa_required', 'MFA required');
      expect(error.code).toBe('mfa_required');
    });

    it('should have email_verification_required error', () => {
      const error = new AuthrimError('email_verification_required', 'Email verification required');
      expect(error.code).toBe('email_verification_required');
    });

    it('should have consent_required_direct error', () => {
      const error = new AuthrimError('consent_required_direct', 'Consent required');
      expect(error.code).toBe('consent_required_direct');
    });
  });

  describe('Error Meta Helper', () => {
    it('should return correct meta for passkey errors', () => {
      const meta = getErrorMeta('passkey_not_found');
      expect(meta.retryable).toBe(false);
      expect(meta.userAction).toBe('reauthenticate');
    });

    it('should return correct meta for rate_limited', () => {
      const meta = getErrorMeta('rate_limited');
      expect(meta.transient).toBe(true);
      expect(meta.retryable).toBe(true);
      expect(meta.retryAfterMs).toBe(60000);
      expect(meta.maxRetries).toBe(3);
    });

    it('should return correct meta for all Direct Auth error codes', () => {
      const directAuthCodes: AuthrimErrorCode[] = [
        'passkey_not_found',
        'passkey_verification_failed',
        'passkey_not_supported',
        'passkey_cancelled',
        'passkey_invalid_credential',
        'email_code_invalid',
        'email_code_expired',
        'email_code_too_many_attempts',
        'challenge_expired',
        'challenge_invalid',
        'auth_code_invalid',
        'auth_code_expired',
        'pkce_mismatch',
        'origin_not_allowed',
        'mfa_required',
        'email_verification_required',
        'consent_required_direct',
        'rate_limited',
      ];

      for (const code of directAuthCodes) {
        const meta = getErrorMeta(code);
        expect(meta).toBeDefined();
        expect(typeof meta.retryable).toBe('boolean');
        expect(typeof meta.transient).toBe('boolean');
        expect(['fatal', 'error', 'warning']).toContain(meta.severity);
      }
    });
  });
});
