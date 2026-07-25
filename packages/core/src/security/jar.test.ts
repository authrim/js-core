import { describe, expect, it } from 'vitest';
import { JARBuilder } from './jar.js';

describe('JARBuilder', () => {
  it('does not allow extraClaims to overwrite typed OIDC security claims', async () => {
    let capturedClaims: Record<string, unknown> | undefined;
    const builder = new JARBuilder({
      async signJwt(_header, claims) {
        capturedClaims = claims as Record<string, unknown>;
        return 'signed-request-object';
      },
    });

    await builder.buildRequestObject({
      clientId: 'client-1',
      issuer: 'https://issuer.example',
      redirectUri: 'https://app.example/callback',
      scope: 'openid',
      state: 'state-1',
      nonce: 'nonce-1',
      codeChallenge: 'challenge',
      codeChallengeMethod: 'S256',
      maxAge: 60,
      extraClaims: {
        max_age: 999999,
        prompt: 'none',
        custom_claim: 'kept',
      },
    });

    expect(capturedClaims).toMatchObject({
      max_age: 60,
      custom_claim: 'kept',
    });
    expect(capturedClaims?.prompt).toBeUndefined();
  });
});
