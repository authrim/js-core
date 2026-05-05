import { describe, expect, it, vi } from 'vitest';
import { DeviceInventoryClient, type HttpClient } from '../../src/index.js';

function createHttpMock(response: unknown = { devices: [] }) {
  const http: HttpClient = {
    fetch: vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: {},
      data: response,
    }),
  };
  return http;
}

describe('DeviceInventoryClient', () => {
  it('lists /me/devices with bearer auth and pagination params', async () => {
    const http = createHttpMock({
      devices: [
        {
          id: 'inst-current',
          display_name: '',
          platform: 'ios',
          current: true,
          last_seen_at: null,
          last_seen_at_unix: null,
        },
      ],
      next_cursor: 'cur_next',
    });
    const client = new DeviceInventoryClient({
      issuer: 'https://auth.example.com/',
      http,
    });

    const response = await client.list({
      accessToken: 'access-token',
      cursor: 'cur_prev',
      limit: 50,
    });

    expect(response.next_cursor).toBe('cur_next');
    expect(http.fetch).toHaveBeenCalledWith(
      'https://auth.example.com/me/devices?cursor=cur_prev&limit=50',
      expect.objectContaining({
        method: 'GET',
        headers: {
          Authorization: 'Bearer access-token',
        },
      })
    );
  });

  it('renames a device using canonical display_name payload', async () => {
    const http = createHttpMock({
      device: {
        id: 'inst-current',
        display_name: 'My iPhone',
        platform: 'ios',
        current: true,
        last_seen_at: null,
        last_seen_at_unix: null,
      },
    });
    const client = new DeviceInventoryClient({
      issuer: 'https://auth.example.com',
      http,
    });

    await client.rename('inst/current', 'My iPhone', {
      accessToken: 'access-token',
    });

    expect(http.fetch).toHaveBeenCalledWith(
      'https://auth.example.com/me/devices/inst%2Fcurrent',
      expect.objectContaining({
        method: 'PATCH',
        headers: {
          Authorization: 'Bearer access-token',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ display_name: 'My iPhone' }),
      })
    );
  });

  it('unlinks a device and returns the unlink result envelope', async () => {
    const http = createHttpMock({
      ok: true,
      device_unlink_result: {
        action: 'device_unlinked',
        target_id: 'inst-current',
        signed_out_required: true,
        status: 'completed',
      },
    });
    const client = new DeviceInventoryClient({
      issuer: 'https://auth.example.com',
      http,
    });

    const response = await client.unlink('inst-current', {
      accessToken: 'access-token',
    });

    expect(response.device_unlink_result.signed_out_required).toBe(true);
    expect(http.fetch).toHaveBeenCalledWith(
      'https://auth.example.com/me/devices/inst-current',
      expect.objectContaining({
        method: 'DELETE',
        headers: {
          Authorization: 'Bearer access-token',
        },
      })
    );
  });

  it('maps OAuth error bodies to AuthrimError', async () => {
    const http: HttpClient = {
      fetch: vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        headers: {},
        data: {
          error: 'invalid_request',
          error_description: 'Cursor is invalid',
          error_details: { code: 'invalid_cursor' },
        },
      }),
    };
    const client = new DeviceInventoryClient({
      issuer: 'https://auth.example.com',
      http,
    });

    await expect(
      client.list({
        accessToken: 'access-token',
        cursor: 'bad',
      })
    ).rejects.toMatchObject({
      code: 'invalid_request',
      message: 'Cursor is invalid',
    });
  });
});
