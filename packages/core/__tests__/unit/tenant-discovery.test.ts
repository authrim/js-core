import { describe, expect, it, vi } from 'vitest';
import {
  buildDiscoveryRequest,
  TenantDiscoveryClient,
  type TenantDiscoveryInput,
} from '../../src/client/tenant-discovery.js';
import type { HttpClient } from '../../src/providers/http.js';

describe('TenantDiscoveryClient', () => {
  it.each<[TenantDiscoveryInput, { mode: string; value: string }]>([
    [{ email: 'user@example.com' }, { mode: 'email', value: 'user@example.com' }],
    [{ domain: '@example.com' }, { mode: 'email', value: 'example.com' }],
    [{ tenantCode: 'tenant-code' }, { mode: 'tenant_code', value: 'tenant-code' }],
    [{ tenantId: 'tenant-a' }, { mode: 'tenant_slug', value: 'tenant-a' }],
    [{ tenantSlug: 'tenant-b' }, { mode: 'tenant_slug', value: 'tenant-b' }],
  ])('builds discovery request for %#', (input, expected) => {
    expect(buildDiscoveryRequest(input)).toEqual(expected);
  });

  it('resolves a tenant and returns minimal display metadata', async () => {
    const http: HttpClient = {
      fetch: vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          result: 'resolved',
          candidate: {
            tenant_id: 'tenant-a',
            tenant_code: 'tenant-a-code',
            display_name: 'Tenant A',
            logo_url: 'https://assets.example.com/a.png',
            login_url: 'https://tenant-a.auth.example.com/login?discovery_grant=grant',
            source: 'email_domain',
          },
        },
      }),
    };
    const client = new TenantDiscoveryClient({
      http,
      baseUrl: 'https://auth.example.com',
    });

    const result = await client.discover({ email: 'user@example.com' });

    expect(result.status).toBe('resolved');
    if (result.status !== 'resolved') {
      throw new Error('Expected resolved result');
    }
    expect(result.tenant).toEqual(
      expect.objectContaining({
        tenantId: 'tenant-a',
        issuer: 'https://tenant-a.auth.example.com',
        loginUrl: 'https://tenant-a.auth.example.com/login?discovery_grant=grant',
        displayName: 'Tenant A',
        logoUrl: 'https://assets.example.com/a.png',
      })
    );
    expect(http.fetch).toHaveBeenCalledWith(
      'https://auth.example.com/api/auth/discovery',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ mode: 'email', value: 'user@example.com' }),
      })
    );
  });

  it('can use currentHost when a fixed baseUrl is not configured', async () => {
    const http: HttpClient = {
      fetch: vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: { result: 'not_found', code: 'tenant_slug_not_found' },
      }),
    };
    const client = new TenantDiscoveryClient({ http });

    const result = await client.discover({
      tenantSlug: 'missing',
      currentHost: 'common.auth.example.com',
    });

    expect(result).toEqual(
      expect.objectContaining({ status: 'not_found', code: 'tenant_slug_not_found' })
    );
    expect(http.fetch).toHaveBeenCalledWith(
      'https://common.auth.example.com/api/auth/discovery',
      expect.any(Object)
    );
  });

  it('normalizes multiple tenant candidates', async () => {
    const http: HttpClient = {
      fetch: vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          result: 'multiple',
          candidates: [
            {
              tenant_id: 'tenant-a',
              display_name: 'Tenant A',
              login_url: 'https://tenant-a.auth.example.com/login',
            },
            {
              tenant_id: 'tenant-b',
              display_name: 'Tenant B',
              login_url: 'https://tenant-b.auth.example.com/login',
            },
          ],
        },
      }),
    };
    const client = new TenantDiscoveryClient({ http, baseUrl: 'https://auth.example.com' });

    const result = await client.discover({ appHint: 'mobile-app' });

    expect(result.status).toBe('multiple');
    if (result.status !== 'multiple') {
      throw new Error('Expected multiple result');
    }
    expect(result.tenants.map((tenant) => tenant.tenantId)).toEqual(['tenant-a', 'tenant-b']);
  });
});
