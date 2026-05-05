import { describe, expect, it, vi } from 'vitest';

import { DPoPManager } from '../../src/security/dpop.js';
import type { CryptoProvider } from '../../src/providers/crypto.js';
import type { DPoPAlgorithm, DPoPCryptoProvider, DPoPKeyPair } from '../../src/types/dpop.js';

function createKeyPair(algorithm: DPoPAlgorithm): DPoPKeyPair {
  return {
    algorithm,
    thumbprint: 'thumbprint',
    publicKeyJwk: { kty: algorithm === 'EdDSA' ? 'OKP' : 'EC' },
    sign: vi.fn(async () => new Uint8Array([1, 2, 3])),
  };
}

function createCryptoProvider() {
  const generateDPoPKeyPair = vi.fn(async (algorithm: DPoPAlgorithm = 'ES256') =>
    createKeyPair(algorithm)
  );
  const crypto = {
    randomBytes: vi.fn(async () => new Uint8Array(32)),
    sha256: vi.fn(async () => new Uint8Array(32)),
    generateDPoPKeyPair,
  } satisfies CryptoProvider & DPoPCryptoProvider;

  return { crypto, generateDPoPKeyPair };
}

describe('DPoPManager', () => {
  it('uses ES256 as the browser/default DPoP signing algorithm', async () => {
    const { crypto, generateDPoPKeyPair } = createCryptoProvider();
    const manager = new DPoPManager(crypto);

    await manager.initialize();

    expect(generateDPoPKeyPair).toHaveBeenCalledWith('ES256');
  });

  it.each<DPoPAlgorithm>(['ES256', 'PS256', 'EdDSA'])(
    'allows configured Phase 1 DPoP algorithm %s',
    async (algorithm) => {
      const { crypto, generateDPoPKeyPair } = createCryptoProvider();
      const manager = new DPoPManager(crypto, { algorithm });

      await manager.initialize();

      expect(generateDPoPKeyPair).toHaveBeenCalledWith(algorithm);
    }
  );
});
