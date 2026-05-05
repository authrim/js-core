import { describe, expect, it, vi } from 'vitest';

import { createAuthrimClient } from '../../src/client/index.js';
import type { CryptoProvider } from '../../src/providers/crypto.js';
import type { DPoPCryptoProvider, DPoPKeyPair } from '../../src/types/dpop.js';
import { createMockCrypto } from '../mocks/crypto.js';
import { createMockStorage } from '../mocks/storage.js';
import {
  createMockDiscoveryDocument,
  createMockHttp,
  createMockIdToken,
  createMockTokenResponse,
} from '../mocks/http.js';

function createDPoPCrypto(): CryptoProvider & DPoPCryptoProvider {
  const base = createMockCrypto();
  const keyPair: DPoPKeyPair = {
    algorithm: 'ES256',
    thumbprint: 'test-thumbprint',
    publicKeyJwk: {
      kty: 'EC',
      crv: 'P-256',
      x: 'x',
      y: 'y',
    },
    sign: vi.fn(async () => new Uint8Array([1, 2, 3])),
  };

  return {
    ...base,
    generateDPoPKeyPair: vi.fn(async () => keyPair),
    getDPoPKeyPair: vi.fn(async () => null),
    clearDPoPKeyPair: vi.fn(async () => undefined),
  };
}

describe('AuthrimClient DPoP token requests', () => {
  it('generates and attaches a DPoP proof during authorization code callback when enabled', async () => {
    const issuer = 'https://auth.example.com';
    const clientId = 'test-client';
    const redirectUri = 'https://app.example.com/callback';
    const crypto = createDPoPCrypto();
    const storage = createMockStorage();
    const http = createMockHttp();
    let callbackNonce = 'test-nonce';

    http.setHandler((url) => {
      if (url.endsWith('/.well-known/openid-configuration')) {
        return {
          ok: true,
          status: 200,
          data: {
            ...createMockDiscoveryDocument(issuer),
            dpop_signing_alg_values_supported: ['ES256'],
          },
        };
      }

      const tokenCall = http.calls.find((call) => call.url === `${issuer}/token`);
      expect(tokenCall?.options?.headers).toHaveProperty('DPoP');
      return {
        ok: true,
        status: 200,
        data: createMockTokenResponse({
          id_token: createMockIdToken({ nonce: callbackNonce }),
          token_type: 'DPoP',
        }),
      };
    });

    const client = await createAuthrimClient({
      issuer,
      clientId,
      http,
      crypto,
      storage,
      dpop: {
        tokenRequests: true,
      },
    });

    const authUrl = await client.buildAuthorizationUrl({ redirectUri });
    const state = new URL(authUrl.url).searchParams.get('state');
    callbackNonce = new URL(authUrl.url).searchParams.get('nonce') ?? callbackNonce;
    expect(state).toBeTruthy();

    const tokens = await client.handleCallback(`${redirectUri}?code=auth-code&state=${state}`);

    expect(tokens.tokenType).toBe('DPoP');
    expect(crypto.generateDPoPKeyPair).toHaveBeenCalledWith('ES256');
  });

  it('stores DPoP-Nonce and retries authorization code callback once with a nonce proof', async () => {
    const issuer = 'https://auth.example.com';
    const clientId = 'test-client';
    const redirectUri = 'https://app.example.com/callback';
    const crypto = createDPoPCrypto();
    const storage = createMockStorage();
    const http = createMockHttp();
    const tokenProofs: string[] = [];
    let callbackNonce = 'test-nonce';

    http.setHandler((url, options) => {
      if (url.endsWith('/.well-known/openid-configuration')) {
        return {
          ok: true,
          status: 200,
          data: {
            ...createMockDiscoveryDocument(issuer),
            dpop_signing_alg_values_supported: ['ES256'],
          },
        };
      }

      const proof = String(options?.headers?.DPoP ?? '');
      tokenProofs.push(proof);

      if (tokenProofs.length === 1) {
        return {
          ok: false,
          status: 400,
          headers: { 'DPoP-Nonce': 'server-nonce-1' },
          data: {
            error: 'use_dpop_nonce',
            error_description: 'DPoP nonce required',
          },
        };
      }

      return {
        ok: true,
        status: 200,
        data: createMockTokenResponse({
          id_token: createMockIdToken({ nonce: callbackNonce }),
          token_type: 'DPoP',
        }),
      };
    });

    const client = await createAuthrimClient({
      issuer,
      clientId,
      http,
      crypto,
      storage,
      dpop: {
        tokenRequests: true,
      },
    });

    const authUrl = await client.buildAuthorizationUrl({ redirectUri });
    const state = new URL(authUrl.url).searchParams.get('state');
    callbackNonce = new URL(authUrl.url).searchParams.get('nonce') ?? callbackNonce;

    const tokens = await client.handleCallback(`${redirectUri}?code=auth-code&state=${state}`);
    const secondProofClaims = JSON.parse(
      Buffer.from(tokenProofs[1]!.split('.')[1]!, 'base64url').toString('utf8')
    ) as { nonce?: string };

    expect(tokens.tokenType).toBe('DPoP');
    expect(tokenProofs).toHaveLength(2);
    expect(secondProofClaims.nonce).toBe('server-nonce-1');
  });

  it('clears persisted DPoP key material on logout', async () => {
    const issuer = 'https://auth.example.com';
    const crypto = createDPoPCrypto();
    const storage = createMockStorage();
    const http = createMockHttp();

    http.setHandler(() => ({
      ok: true,
      status: 200,
      data: createMockDiscoveryDocument(issuer),
    }));

    const client = await createAuthrimClient({
      issuer,
      clientId: 'test-client',
      http,
      crypto,
      storage,
      dpop: {
        tokenRequests: true,
      },
    });

    await client.logout({ revokeTokens: false });

    expect(crypto.clearDPoPKeyPair).toHaveBeenCalled();
  });
});
