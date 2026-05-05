import type { HttpClient, HttpOptions } from '../providers/http.js';
import { AuthrimError, type Phase1ErrorDetails } from '../types/errors.js';

export interface DeviceInventoryClientOptions {
  issuer: string;
  http: HttpClient;
}

export interface DeviceInventoryRequestOptions {
  accessToken: string;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  timeout?: number;
}

export interface ListDevicesOptions extends DeviceInventoryRequestOptions {
  cursor?: string;
  limit?: number;
}

export interface RenameDeviceOptions extends DeviceInventoryRequestOptions {}

export interface UnlinkDeviceOptions extends DeviceInventoryRequestOptions {}

export interface DeviceInventoryItem {
  id: string;
  display_name: string;
  fallback_display_name?: string;
  platform: string;
  current: boolean;
  last_seen_at: string | null;
  last_seen_at_unix: number | null;
  client_id?: string;
  app_display_name?: string;
}

export interface ListDevicesResponse {
  devices: DeviceInventoryItem[];
  next_cursor?: string;
}

export interface RenameDeviceResponse {
  device: DeviceInventoryItem;
}

export interface DeviceUnlinkResult {
  action: 'device_unlinked' | string;
  target_id: string;
  signed_out_required: boolean;
  status: 'completed' | 'already_applied' | string;
}

export interface UnlinkDeviceResponse {
  ok: true;
  device_unlink_result: DeviceUnlinkResult;
}

export interface DeviceInventoryFailureBody {
  error: string;
  error_description?: string;
  error_uri?: string;
  error_details?: Phase1ErrorDetails;
}

export class DeviceInventoryClient {
  private readonly issuer: string;
  private readonly http: HttpClient;

  constructor(options: DeviceInventoryClientOptions) {
    this.issuer = options.issuer.replace(/\/$/, '');
    this.http = options.http;
  }

  async list(options: ListDevicesOptions): Promise<ListDevicesResponse> {
    const params = new URLSearchParams();
    if (options.cursor) {
      params.set('cursor', options.cursor);
    }
    if (options.limit !== undefined) {
      params.set('limit', String(options.limit));
    }
    const encodedParams = params.toString();
    const query = encodedParams ? `?${encodedParams}` : '';
    return this.request<ListDevicesResponse>(`/me/devices${query}`, {
      method: 'GET',
      headers: {
        ...bearerHeaders(options.accessToken),
        ...(options.headers ?? {}),
      },
      signal: options.signal,
      timeout: options.timeout,
    });
  }

  async rename(
    deviceId: string,
    displayName: string,
    options: RenameDeviceOptions
  ): Promise<RenameDeviceResponse> {
    return this.request<RenameDeviceResponse>(`/me/devices/${encodeURIComponent(deviceId)}`, {
      method: 'PATCH',
      headers: {
        ...bearerHeaders(options.accessToken),
        ...(options.headers ?? {}),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ display_name: displayName }),
      signal: options.signal,
      timeout: options.timeout,
    });
  }

  async unlink(deviceId: string, options: UnlinkDeviceOptions): Promise<UnlinkDeviceResponse> {
    return this.request<UnlinkDeviceResponse>(`/me/devices/${encodeURIComponent(deviceId)}`, {
      method: 'DELETE',
      headers: {
        ...bearerHeaders(options.accessToken),
        ...(options.headers ?? {}),
      },
      signal: options.signal,
      timeout: options.timeout,
    });
  }

  private async request<T>(path: string, options: HttpOptions): Promise<T> {
    let response;
    try {
      response = await this.http.fetch<T | DeviceInventoryFailureBody>(
        `${this.issuer}${path}`,
        options
      );
    } catch (error) {
      throw new AuthrimError('network_error', 'Device inventory request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (!response.ok) {
      if (isFailureBody(response.data)) {
        throw AuthrimError.fromOAuthError(response.data);
      }
      throw new AuthrimError('invalid_request', 'Device inventory request failed', {
        details: {
          status: response.status,
        },
      });
    }

    return response.data as T;
  }
}

function bearerHeaders(accessToken: string): Record<string, string> {
  const token = accessToken.trim();
  if (!token) {
    throw new AuthrimError('invalid_request', 'accessToken is required');
  }
  return {
    Authorization: `Bearer ${token}`,
  };
}

function isFailureBody(value: unknown): value is DeviceInventoryFailureBody {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { error?: unknown }).error === 'string'
  );
}
