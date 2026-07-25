import { describe, expect, it, vi } from 'vitest';
import { TenantDiscoveryClient } from './tenant-discovery.js';
import type { HttpClient } from '../providers/http.js';

describe('TenantDiscoveryClient', () => {
  it('always resolves discovery against the configured HTTPS baseUrl', async () => {
    const fetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: {},
      data: {
        result: 'resolved',
        candidate: {
          tenant_id: 'tenant-1',
          login_url: 'https://issuer.example/login',
        },
      },
    }));
    const client = new TenantDiscoveryClient({
      http: { fetch } as HttpClient,
      baseUrl: 'https://auth.example',
    });

    await client.discover({
      email: 'user@example.com',
      currentHost: 'https://attacker.example',
    });

    expect(fetch).toHaveBeenCalledWith(
      'https://auth.example/api/auth/discovery',
      expect.any(Object)
    );
  });

  it('rejects unsafe base URLs and absolute endpoint overrides', () => {
    expect(
      () =>
        new TenantDiscoveryClient({
          http: { fetch: vi.fn() } as unknown as HttpClient,
          baseUrl: 'http://auth.example',
        })
    ).toThrow(/https/);

    expect(
      () =>
        new TenantDiscoveryClient({
          http: { fetch: vi.fn() } as unknown as HttpClient,
          baseUrl: 'https://auth.example',
          endpoint: 'https://attacker.example/discovery',
        })
    ).toThrow(/relative path/);
  });
});
