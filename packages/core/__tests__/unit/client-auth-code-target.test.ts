import { describe, expect, it } from 'vitest';

import { createAuthrimClient } from '../../src/client/index.js';
import { createMockCrypto } from '../mocks/crypto.js';
import { createMockStorage } from '../mocks/storage.js';
import {
  createMockDiscoveryDocument,
  createMockHttp,
  createMockIdToken,
  createMockTokenResponse,
} from '../mocks/http.js';

describe('AuthrimClient authorization code token target', () => {
  it('persists resource and audience from authorization start to token request', async () => {
    const issuer = 'https://auth.example.com';
    const clientId = 'test-client';
    const redirectUri = 'https://app.example.com/callback';
    const storage = createMockStorage();
    const http = createMockHttp();
    let callbackNonce = 'test-nonce';

    http.setHandler((url) => {
      if (url.endsWith('/.well-known/openid-configuration')) {
        return {
          ok: true,
          status: 200,
          data: createMockDiscoveryDocument(issuer),
        };
      }

      return {
        ok: true,
        status: 200,
        data: createMockTokenResponse({
          id_token: createMockIdToken({ nonce: callbackNonce }),
        }),
      };
    });

    const client = await createAuthrimClient({
      issuer,
      clientId,
      http,
      crypto: createMockCrypto(),
      storage,
    });

    const authUrl = await client.buildAuthorizationUrl({
      redirectUri,
      resource: ['https://api.example.com/orders', 'https://api.example.com/profile'],
      audience: 'https://api.example.com',
    });
    const parsedAuthUrl = new URL(authUrl.url);
    const state = parsedAuthUrl.searchParams.get('state');
    callbackNonce = parsedAuthUrl.searchParams.get('nonce') ?? callbackNonce;

    await client.handleCallback(`${redirectUri}?code=auth-code&state=${state}`);

    const tokenCall = http.calls.find((call) => call.url === `${issuer}/token`);
    const requestBody = new URLSearchParams(tokenCall?.options?.body as string);

    expect(parsedAuthUrl.searchParams.getAll('resource')).toEqual([
      'https://api.example.com/orders',
      'https://api.example.com/profile',
    ]);
    expect(parsedAuthUrl.searchParams.get('audience')).toBe('https://api.example.com');
    expect(requestBody.getAll('resource')).toEqual([
      'https://api.example.com/orders',
      'https://api.example.com/profile',
    ]);
    expect(requestBody.get('audience')).toBe('https://api.example.com');
  });
});
