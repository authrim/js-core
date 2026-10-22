import { beforeEach, describe, expect, it } from 'vitest';
import { AuthrimError, DirectAuthBrowserSessionClient } from '../../src/index.js';
import { createMockCrypto } from '../mocks/crypto.js';
import { createMockHttp } from '../mocks/http.js';
import { createMockStorage } from '../mocks/storage.js';

describe('DirectAuthBrowserSessionClient', () => {
  const issuer = 'https://auth.example.com';
  const clientId = 'login-ui-client';
  let http: ReturnType<typeof createMockHttp>;
  let storage: ReturnType<typeof createMockStorage>;
  let client: DirectAuthBrowserSessionClient;

  beforeEach(() => {
    http = createMockHttp();
    storage = createMockStorage();
    client = new DirectAuthBrowserSessionClient({
      issuer,
      clientId,
      http,
      crypto: createMockCrypto(),
      storage,
    });
  });

  it('starts passkey login with PKCE and stores verifier by challenge id', async () => {
    http.setHandler((url, options) => {
      expect(url).toBe(`${issuer}/api/v1/auth/direct/passkey/login/start`);
      const body = readBody(options?.body);
      expect(body.client_id).toBe(clientId);
      expect(body.channel).toBe('browser');
      expect(body.code_challenge_method).toBe('S256');
      expect(typeof body.code_challenge).toBe('string');
      expect(body.email).toBe('user@example.com');
      return {
        ok: true,
        status: 200,
        data: {
          challenge_id: 'challenge-1',
          options: { challenge: 'abc', rpId: 'auth.example.com' },
        },
      };
    });

    await expect(client.startPasskeyLogin({ email: 'user@example.com' })).resolves.toMatchObject({
      challenge_id: 'challenge-1',
    });
    expect(storage.getAllKeys()).toContain(
      'authrim:direct-auth:login-ui-client:passkey-login:challenge-1'
    );
  });

  it('uses explicit API base URL when configured', async () => {
    client = new DirectAuthBrowserSessionClient({
      issuer,
      baseUrl: 'https://login.example.com/proxy/',
      clientId,
      http,
      crypto: createMockCrypto(),
      storage,
    });
    http.setHandler((url) => {
      expect(url).toBe('https://login.example.com/proxy/api/v1/auth/direct/passkey/login/start');
      return {
        ok: true,
        status: 200,
        data: { challenge_id: 'challenge-1', options: { challenge: 'abc' } },
      };
    });

    await client.startPasskeyLogin();
  });

  it('finishes passkey login and finalizes managed browser session', async () => {
    let finishBody: Record<string, unknown> | undefined;
    let sessionBody: Record<string, unknown> | undefined;
    http.setHandler((url, options) => {
      if (url.endsWith('/passkey/login/start')) {
        return {
          ok: true,
          status: 200,
          data: { challenge_id: 'challenge-1', options: { challenge: 'abc' } },
        };
      }
      if (url.endsWith('/passkey/login/finish')) {
        finishBody = readBody(options?.body);
        return {
          ok: true,
          status: 200,
          data: { direct_auth_artifact: 'artifact-1', expires_in: 60 },
        };
      }
      if (url.endsWith('/auth/direct/session')) {
        sessionBody = readBody(options?.body);
        return {
          ok: true,
          status: 200,
          data: {
            ok: true,
            session: {
              userId: 'user-1',
              createdAt: 1000,
              expiresAt: 2000,
              authTime: 1000,
              acr: 'urn:authrim:acr:passkey',
              amr: ['passkey'],
            },
            user: { id: 'user-1', email: 'user@example.com' },
            redirect_url: '/account',
          },
        };
      }
      throw new Error(`unexpected request ${url}`);
    });

    await client.startPasskeyLogin();
    const session = await client.finishPasskeyLoginWithManagedSession(
      { challengeId: 'challenge-1', credential: { id: 'credential-1' } },
      { authorizationChallengeId: 'authz-1', deferAuthorizationContinuation: true }
    );

    expect(finishBody).toMatchObject({
      challenge_id: 'challenge-1',
      channel: 'browser',
    });
    expect(typeof finishBody?.code_verifier).toBe('string');
    expect(sessionBody).toMatchObject({
      direct_auth_artifact: 'artifact-1',
      client_id: clientId,
      channel: 'browser',
      authorization_challenge_id: 'authz-1',
      defer_authorization_continuation: true,
    });
    expect(session.redirect_url).toBe('/account');
    expect(storage.getAllKeys()).not.toContain(
      'authrim:direct-auth:login-ui-client:passkey-login:challenge-1'
    );
  });

  it('stores email code verifier under normalized email and uses it for verify', async () => {
    let verifyBody: Record<string, unknown> | undefined;
    http.setHandler((url, options) => {
      if (url.endsWith('/email-code/send')) {
        const body = readBody(options?.body);
        expect(body.email).toBe('user@example.com');
        return {
          ok: true,
          status: 200,
          data: { attempt_id: 'attempt-1', expires_in: 300, masked_email: 'u***@example.com' },
        };
      }
      if (url.endsWith('/email-code/verify')) {
        verifyBody = readBody(options?.body);
        return {
          ok: true,
          status: 200,
          data: { direct_auth_artifact: 'artifact-1', expires_in: 60, is_new_user: false },
        };
      }
      throw new Error(`unexpected request ${url}`);
    });

    await client.sendEmailCode({ email: ' USER@EXAMPLE.COM ' });
    expect(storage.getAllKeys()).toContain(
      'authrim:direct-auth:login-ui-client:email-code:user%40example.com'
    );

    await client.verifyEmailCode({ email: 'user@example.com', code: '123456' });
    expect(verifyBody).toMatchObject({
      attempt_id: 'attempt-1',
      code: '123456',
      channel: 'browser',
    });
    expect(typeof verifyBody?.code_verifier).toBe('string');
    expect(storage.getAllKeys()).not.toContain(
      'authrim:direct-auth:login-ui-client:email-code:user%40example.com'
    );
  });

  it('keeps email code state after a failed verify so the attempt can be retried', async () => {
    let verifyCount = 0;
    http.setHandler((url, options) => {
      if (url.endsWith('/email-code/send')) {
        return {
          ok: true,
          status: 200,
          data: { attempt_id: 'attempt-1', expires_in: 300, masked_email: 'u***@example.com' },
        };
      }
      if (url.endsWith('/email-code/verify')) {
        verifyCount += 1;
        const body = readBody(options?.body);
        expect(body.attempt_id).toBe('attempt-1');
        if (verifyCount === 1) {
          return {
            ok: false,
            status: 400,
            data: { error: 'invalid_code', error_description: 'Invalid code' },
          };
        }
        return {
          ok: true,
          status: 200,
          data: { direct_auth_artifact: 'artifact-1', expires_in: 60, is_new_user: false },
        };
      }
      throw new Error(`unexpected request ${url}`);
    });

    await client.sendEmailCode({ email: 'user@example.com' });
    await expect(
      client.verifyEmailCode({ email: 'user@example.com', code: '000000' })
    ).rejects.toThrow(/Invalid code/);
    expect(storage.getAllKeys()).toContain(
      'authrim:direct-auth:login-ui-client:email-code:user%40example.com'
    );

    await expect(
      client.verifyEmailCode({ email: 'user@example.com', code: '123456' })
    ).resolves.toMatchObject({
      direct_auth_artifact: 'artifact-1',
    });
    expect(storage.getAllKeys()).not.toContain(
      'authrim:direct-auth:login-ui-client:email-code:user%40example.com'
    );
  });

  it('does not clear a newer email code state when an older verify completes', async () => {
    const emailCodeStateKey = 'authrim:direct-auth:login-ui-client:email-code:user%40example.com';
    http.setHandler((url, options) => {
      if (url.endsWith('/email-code/send')) {
        return {
          ok: true,
          status: 200,
          data: { attempt_id: 'attempt-1', expires_in: 300, masked_email: 'u***@example.com' },
        };
      }
      if (url.endsWith('/email-code/verify')) {
        const body = readBody(options?.body);
        expect(body.attempt_id).toBe('attempt-1');
        storage.store.set(
          emailCodeStateKey,
          JSON.stringify({ attemptId: 'attempt-2', codeVerifier: 'new-code-verifier' })
        );
        return {
          ok: true,
          status: 200,
          data: { direct_auth_artifact: 'artifact-1', expires_in: 60, is_new_user: false },
        };
      }
      throw new Error(`unexpected request ${url}`);
    });

    await client.sendEmailCode({ email: 'user@example.com' });
    await client.verifyEmailCode({ email: 'user@example.com', code: '123456' });

    expect(storage.store.get(emailCodeStateKey)).toBe(
      JSON.stringify({ attemptId: 'attempt-2', codeVerifier: 'new-code-verifier' })
    );
  });

  it('finalizes managed session when email code send returns a direct auth artifact', async () => {
    let sessionBody: Record<string, unknown> | undefined;
    http.setHandler((url, options) => {
      if (url.endsWith('/email-code/send')) {
        return {
          ok: true,
          status: 200,
          data: { direct_auth_artifact: 'artifact-email', expires_in: 60 },
        };
      }
      if (url.endsWith('/auth/direct/session')) {
        sessionBody = readBody(options?.body);
        return {
          ok: true,
          status: 200,
          data: {
            ok: true,
            session: { userId: 'user-1', createdAt: 1000, expiresAt: 2000 },
            user: { id: 'user-1', email: 'user@example.com' },
          },
        };
      }
      throw new Error(`unexpected request ${url}`);
    });

    await expect(
      client.sendEmailCodeWithManagedSession({
        email: 'user@example.com',
        authorizationChallengeId: 'authz-1',
        deferAuthorizationContinuation: true,
      })
    ).resolves.toMatchObject({
      status: 'completed',
      session: { user: { id: 'user-1' } },
    });
    expect(sessionBody).toMatchObject({
      direct_auth_artifact: 'artifact-email',
      client_id: clientId,
      channel: 'browser',
      authorization_challenge_id: 'authz-1',
      defer_authorization_continuation: true,
    });
    expect(typeof sessionBody?.code_verifier).toBe('string');
  });

  it('rejects token material in managed browser session responses', async () => {
    http.setHandler((url) => {
      if (url.endsWith('/auth/direct/session')) {
        return {
          ok: true,
          status: 200,
          data: {
            ok: true,
            session: { userId: 'user-1', createdAt: 1000, expiresAt: 2000 },
            user: { id: 'user-1', email: 'user@example.com' },
            access_token: 'must-not-reach-browser',
          },
        };
      }
      throw new Error(`unexpected request ${url}`);
    });

    await expect(client.finalizeManagedSession('artifact-1', 'verifier-1')).rejects.toThrow(
      /token material/
    );
  });

  it('sends an invitation and the proof of its email with a passkey signup start', async () => {
    const bodies: Array<Record<string, unknown>> = [];
    http.setHandler((url, options) => {
      expect(url).toBe(`${issuer}/api/v1/auth/direct/passkey/signup/start`);
      bodies.push(readBody(options?.body));
      return {
        ok: true,
        status: 200,
        data: { challenge_id: `signup-${bodies.length}`, options: { challenge: 'abc' } },
      };
    });

    await client.startPasskeySignup({
      email: 'invited@example.com',
      inviteToken: 'invite-token',
      invitationEmailProof: 'proof-value',
    });
    await client.startPasskeySignup({ email: 'plain@example.com' });

    expect(bodies[0]).toMatchObject({
      invite_token: 'invite-token',
      invitation_email_proof: 'proof-value',
    });
    expect(bodies[1]).not.toHaveProperty('invite_token');
    expect(bodies[1]).not.toHaveProperty('invitation_email_proof');
  });

  it('sends an invitation and the proof of its email with a TOTP signup start', async () => {
    const bodies: Array<Record<string, unknown>> = [];
    http.setHandler((url, options) => {
      expect(url).toBe(`${issuer}/api/auth/totp/signup/options`);
      bodies.push(readBody(options?.body));
      return {
        ok: true,
        status: 201,
        data: { challenge_id: 'totp-signup-1', secret: 'S', otpauth_uri: 'otpauth://x' },
      };
    });

    await client.createTotpSignupOptions({
      email: 'invited@example.com',
      inviteToken: 'invite-token',
      invitationEmailProof: 'proof-value',
    });
    await client.createTotpSignupOptions({ email: 'plain@example.com' });

    expect(bodies[0]).toMatchObject({
      email: 'invited@example.com',
      invite_token: 'invite-token',
      invitation_email_proof: 'proof-value',
    });
    expect(bodies[1]).not.toHaveProperty('invite_token');
    expect(bodies[1]).not.toHaveProperty('invitation_email_proof');
  });

  it('wraps TOTP login endpoints', async () => {
    http.setHandler((url, options) => {
      if (url.endsWith('/totp/login/start')) {
        expect(readBody(options?.body)).toMatchObject({
          identifier: 'person@example.com',
          authorization_challenge_id: 'authz-1',
        });
        return {
          ok: true,
          status: 200,
          data: { challenge_id: 'totp-1', expires_in: 300 },
        };
      }
      if (url.endsWith('/totp/login/verify')) {
        expect(readBody(options?.body)).toMatchObject({
          challenge_id: 'totp-1',
          code: '123456',
          defer_authorization_continuation: true,
        });
        return {
          ok: true,
          status: 200,
          data: {
            ok: true,
            success: true,
            sessionId: 'session-1',
            session: { userId: 'user-1', createdAt: 1000, expiresAt: 2000 },
            user: { id: 'user-1', email: 'person@example.com' },
          },
        };
      }
      throw new Error(`unexpected request ${url}`);
    });

    await expect(
      client.startTotpLogin({
        identifier: 'person@example.com',
        authorizationChallengeId: 'authz-1',
      })
    ).resolves.toMatchObject({ challenge_id: 'totp-1' });
    await expect(
      client.verifyTotpLogin({
        challengeId: 'totp-1',
        code: '123456',
        deferAuthorizationContinuation: true,
      })
    ).resolves.toMatchObject({ success: true, sessionId: 'session-1' });
  });

  it('wraps directory password login and migration endpoints', async () => {
    http.setHandler((url, options) => {
      if (url.endsWith('/directory-password/login')) {
        expect(readBody(options?.body)).toMatchObject({
          username: 'user@example.com',
          password: 'secret',
          defer_authorization_continuation: true,
        });
        return {
          ok: true,
          status: 200,
          data: {
            ok: false,
            migration: {
              required: true,
              action: 'prompt_passkey',
              campaign_id: 'campaign-1',
              state: 'pending',
            },
          },
        };
      }
      if (url.endsWith('/migration/email-code/verify')) {
        expect(readBody(options?.body)).toMatchObject({
          transaction_id: 'tx-1',
          transaction_token: 'token-1',
          challenge_id: 'challenge-1',
          code: '123456',
        });
        return {
          ok: true,
          status: 200,
          data: {
            ok: true,
            session: { userId: 'user-1', createdAt: 1000, expiresAt: 2000 },
            user: { id: 'user-1', email: 'user@example.com' },
          },
        };
      }
      throw new Error(`unexpected request ${url}`);
    });

    await expect(
      client.loginWithDirectoryPassword({
        username: 'user@example.com',
        password: 'secret',
        deferAuthorizationContinuation: true,
      })
    ).resolves.toMatchObject({ ok: false, migration: { required: true } });

    await expect(
      client.verifyDirectoryPasswordMigrationEmailCode({
        transactionId: 'tx-1',
        transactionToken: 'token-1',
        challengeId: 'challenge-1',
        code: '123456',
      })
    ).resolves.toMatchObject({ ok: true, user: { id: 'user-1' } });
  });

  it('throws invalid_state when passkey state is missing', async () => {
    await expect(
      client.finishPasskeyLogin({ challengeId: 'missing', credential: {} })
    ).rejects.toMatchObject<AuthrimError>({
      code: 'invalid_state',
    });
  });
});

function readBody(body: unknown): Record<string, unknown> {
  expect(typeof body).toBe('string');
  return JSON.parse(body as string) as Record<string, unknown>;
}
