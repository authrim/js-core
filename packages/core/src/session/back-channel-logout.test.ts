import { describe, expect, it } from 'vitest';
import { BackChannelLogoutValidator } from './back-channel-logout.js';

function jwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none' })}.${encode(payload)}.signature`;
}

describe('BackChannelLogoutValidator', () => {
  it('validates a standard back-channel logout token', () => {
    const now = 1_700_000_000;
    const validator = new BackChannelLogoutValidator();

    const result = validator.validate(
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

  it('rejects logout tokens with nonce', () => {
    const now = 1_700_000_000;
    const validator = new BackChannelLogoutValidator();

    expect(() =>
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
    ).toThrow(/nonce/);
  });
});
