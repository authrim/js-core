import { describe, expect, it } from 'vitest';
import { decodeJwt } from '../../src/utils/jwt.js';
import { stringToBase64url } from '../../src/utils/base64url.js';

describe('JWT utilities', () => {
  it('rejects oversized JWTs before decoding', () => {
    const header = stringToBase64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const payload = stringToBase64url(JSON.stringify({ sub: 'user-1' }));
    const signature = 'x'.repeat(8192);

    expect(() => decodeJwt(`${header}.${payload}.${signature}`)).toThrow(
      'Invalid JWT format: exceeds maximum size'
    );
  });
});
