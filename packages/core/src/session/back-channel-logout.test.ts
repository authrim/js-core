import { describe, expect, it } from 'vitest';
import { BackChannelLogoutValidator } from './back-channel-logout.js';
import { decodeJwt } from '../utils/jwt.js';
import type { LogoutTokenClaims } from '../types/session-management.js';

function jwt(
  payload: Record<string, unknown>,
  header: Record<string, unknown> = { alg: 'RS256' }
): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode(header)}.${encode(payload)}.signature`;
}

describe('BackChannelLogoutValidator', () => {
  it('validates a standard verified back-channel logout token', async () => {
    const now = 1_700_000_000;
    const validator = new BackChannelLogoutValidator({
      async verifyJwt(token) {
        return decodeJwt<LogoutTokenClaims & Record<string, unknown>>(token).payload;
      },
    });

    const result = await validator.validate(
      jwt({
        iss: 'https://issuer.example',
        aud: 'client-1',
        iat: now,
        jti: 'logout-1',
        sid: 'session-1',
        events: {
          'http://schemas.openid.net/event/backchannel-logout': {},
        },
      }),
      { issuer: 'https://issuer.example', clientId: 'client-1', now }
    );

    expect(result.claims.sid).toBe('session-1');
  });

  it('rejects logout tokens with nonce after signature verification', async () => {
    const now = 1_700_000_000;
    const validator = new BackChannelLogoutValidator({
      async verifyJwt(token) {
        return decodeJwt<LogoutTokenClaims & Record<string, unknown>>(token).payload;
      },
    });

    await expect(
      validator.validate(
        jwt({
          iss: 'https://issuer.example',
          aud: 'client-1',
          iat: now,
          jti: 'logout-1',
          sid: 'session-1',
          nonce: 'not-allowed',
          events: {
            'http://schemas.openid.net/event/backchannel-logout': {},
          },
        }),
        { issuer: 'https://issuer.example', clientId: 'client-1', now }
      )
    ).rejects.toThrow(/nonce/);
  });

  it('rejects unsigned logout tokens before claim validation', async () => {
    const now = 1_700_000_000;
    const validator = new BackChannelLogoutValidator({
      async verifyJwt(token) {
        return decodeJwt<LogoutTokenClaims & Record<string, unknown>>(token).payload;
      },
    });

    await expect(
      validator.validate(
        jwt(
          {
            iss: 'https://issuer.example',
            aud: 'client-1',
            iat: now,
            jti: 'logout-1',
            sid: 'session-1',
            events: {
              'http://schemas.openid.net/event/backchannel-logout': {},
            },
          },
          { alg: 'none' }
        ),
        { issuer: 'https://issuer.example', clientId: 'client-1', now }
      )
    ).rejects.toThrow(/unsupported algorithm/);
  });
});
