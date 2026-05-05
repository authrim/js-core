import { describe, expect, it, vi } from 'vitest';
import {
  AuthrimError,
  CustomerProfileClient,
  createAuthrimClient,
  type HttpClient,
  type HttpOptions,
} from '../../src/index.js';

function createHttp(response: {
  ok?: boolean;
  status?: number;
  data?: unknown;
} = {}): HttpClient {
  return {
    fetch: vi.fn().mockResolvedValue({
      ok: response.ok ?? true,
      status: response.status ?? 200,
      statusText: response.ok === false ? 'Error' : 'OK',
      headers: {},
      data: response.data ?? {},
    }),
  };
}

function createCrypto() {
  return {
    randomBytes: vi.fn(async () => new Uint8Array(32)),
    sha256: vi.fn(async () => new Uint8Array(32)),
    generateCodeVerifier: vi.fn(async () => 'verifier'),
    generateCodeChallenge: vi.fn(async () => 'challenge'),
  };
}

function createStorage() {
  const values = new Map<string, string>();
  return {
    get: vi.fn(async (key: string) => values.get(key) ?? null),
    set: vi.fn(async (key: string, value: string) => {
      values.set(key, value);
    }),
    remove: vi.fn(async (key: string) => {
      values.delete(key);
    }),
    getAll: vi.fn(async () => Object.fromEntries(values.entries())),
    clear: vi.fn(async () => {
      values.clear();
    }),
  };
}

describe('CustomerProfileClient', () => {
  it('separates product-specific elevation read from delegated write paths', async () => {
    const http = createHttp({
      data: {
        profile: { sub: 'user-1' },
      },
    });
    const client = new CustomerProfileClient({
      issuer: 'https://auth.example.com',
      http,
    });

    await client.getWithElevationGrant('user-1', {
      accessToken: 'elevation-token',
    });

    expect(http.fetch).toHaveBeenCalledWith(
      'https://auth.example.com/api/protected/customer-profiles/user-1',
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: 'Bearer elevation-token',
        }),
      })
    );
  });

  it('sends delegated writes with envelope, Step-Up receipt, and idempotency key', async () => {
    const http = createHttp({
      data: {
        customer_profile: { sub: 'user-1', name: 'Alice Updated' },
        actor: { id: 'actor-1' },
        subject: { id: 'user-1' },
      },
    });
    const client = new CustomerProfileClient({
      issuer: 'https://auth.example.com/',
      http,
    });

    const result = await client.updateDelegated(
      'user-1',
      { name: 'Alice Updated' },
      {
        accessToken: 'actor-token',
        stepUpReceipt: 'sur_receipt',
        idempotencyKey: 'delegated-key-1',
        audit: { reason_code: 'admin_repair' },
        include: ['actor', 'subject', 'audit'],
      }
    );

    expect(result.customer_profile.name).toBe('Alice Updated');
    expect(http.fetch).toHaveBeenCalledWith(
      'https://auth.example.com/api/protected/customer-profiles/users/user-1?include=actor%2Csubject%2Caudit',
      expect.objectContaining({ method: 'PATCH' })
    );
    const init = (http.fetch as ReturnType<typeof vi.fn>).mock.calls[0][1] as HttpOptions;
    expect(init.headers).toEqual(
      expect.objectContaining({
        Authorization: 'Bearer actor-token',
        'Authrim-Step-Up-Receipt': 'sur_receipt',
        'Idempotency-Key': 'delegated-key-1',
        'Content-Type': 'application/json',
      })
    );
    expect(JSON.parse(init.body as string)).toEqual({
      input: { name: 'Alice Updated' },
      audit: { reason_code: 'admin_repair' },
    });
  });

  it('preserves step_up_required details from delegated write responses', async () => {
    const http = createHttp({
      ok: false,
      status: 403,
      data: {
        error: 'step_up_required',
        error_description: 'Step-up is required for this delegated write.',
        error_details: {
          code: 'step_up_required',
          retryable: false,
          severity: 'warning',
        },
        step_up: {
          step_up_token: 'stu_123',
          acceptable_methods: { methods: ['portal_confirm'] },
        },
      },
    });
    const client = new CustomerProfileClient({
      issuer: 'https://auth.example.com',
      http,
    });

    await expect(
      client.updateDelegated('user-1', { name: 'Alice Updated' }, {
        accessToken: 'actor-token',
        stepUpReceipt: 'sur_receipt',
        idempotencyKey: 'delegated-key-1',
      })
    ).rejects.toMatchObject({
      code: 'step_up_required',
      details: expect.objectContaining({
        errorDetails: expect.objectContaining({ code: 'step_up_required' }),
      }),
    });
  });

  it('rejects empty bearer tokens and invalid receipts before sending', async () => {
    const http = createHttp();
    const client = new CustomerProfileClient({
      issuer: 'https://auth.example.com',
      http,
    });

    await expect(
      client.getWithElevationGrant('user-1', { accessToken: ' ' })
    ).rejects.toBeInstanceOf(AuthrimError);
    await expect(
      client.updateDelegated('user-1', { name: 'Alice Updated' }, {
        accessToken: 'actor-token',
        stepUpReceipt: 'bad\nreceipt',
        idempotencyKey: 'delegated-key-1',
      })
    ).rejects.toBeInstanceOf(AuthrimError);
    expect(http.fetch).not.toHaveBeenCalled();
  });

  it('exposes customerProfiles on AuthrimClient', async () => {
    const http = createHttp({
      data: {
        customer_profile: { sub: 'user-1' },
      },
    });
    const client = await createAuthrimClient({
      issuer: 'https://auth.example.com',
      clientId: 'client-1',
      redirectUri: 'https://app.example.com/callback',
      storage: createStorage(),
      crypto: createCrypto(),
      http,
    });

    await client.customerProfiles.updateDelegated(
      'user-1',
      { locale: 'ja-JP' },
      {
        accessToken: 'actor-token',
        stepUpReceipt: 'sur_receipt',
        idempotencyKey: 'delegated-key-2',
      }
    );

    expect(http.fetch).toHaveBeenCalledWith(
      'https://auth.example.com/api/protected/customer-profiles/users/user-1',
      expect.objectContaining({ method: 'PATCH' })
    );
  });
});
