import { describe, expect, it } from 'vitest';
import { hasBrowserTokenMaterial } from './profiles.js';

describe('hasBrowserTokenMaterial', () => {
  it('detects nested and camelCase token material shapes', () => {
    expect(
      hasBrowserTokenMaterial({
        success: true,
        result: {
          tokens: {
            accessToken: 'access-token',
            refreshToken: 'refresh-token',
          },
        },
      })
    ).toBe(true);
  });

  it('does not flag ordinary session metadata', () => {
    expect(
      hasBrowserTokenMaterial({
        session: { id: 'session-1' },
        user: { id: 'user-1' },
      })
    ).toBe(false);
  });
});
