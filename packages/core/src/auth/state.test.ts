import { describe, expect, it } from 'vitest';
import { StateManager } from './state.js';
import type { CryptoProvider } from '../providers/crypto.js';
import type { AuthrimStorage } from '../providers/storage.js';

const cryptoProvider: CryptoProvider = {
  async randomBytes(length) {
    return new Uint8Array(length).fill(1);
  },
  async sha256(value) {
    return new Uint8Array(Buffer.from(value).subarray(0, 32));
  },
  async generateCodeVerifier() {
    return 'verifier';
  },
  async generateCodeChallenge() {
    return 'challenge';
  },
};

function memoryStorage(): AuthrimStorage {
  const values = new Map<string, string>();
  return {
    async get(key) {
      return values.get(key) ?? null;
    },
    async set(key, value) {
      values.set(key, value);
    },
    async remove(key) {
      values.delete(key);
    },
  };
}

describe('StateManager returnTo validation', () => {
  it('rejects backslash-prefixed relative redirects', async () => {
    const manager = new StateManager(cryptoProvider, memoryStorage(), 'issuer', 'client');

    await expect(
      manager.generateAuthState({
        redirectUri: 'https://app.example/callback',
        codeVerifier: 'verifier',
        scope: 'openid',
        returnTo: '/\\evil.example',
      })
    ).rejects.toMatchObject({ code: 'invalid_return_to' });
  });
});
