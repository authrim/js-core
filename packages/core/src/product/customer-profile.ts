import type { HttpClient, HttpOptions } from '../providers/http.js';
import {
  AuthrimError,
  type Phase1ErrorDetails,
  type StepUpInputState,
  type StepUpStatusObject,
} from '../types/errors.js';
import type { IdempotencyKeyInput } from '../utils/idempotency.js';
import { withIdempotencyKeyHeader } from '../utils/idempotency.js';
import {
  createDelegatedWriteEnvelope,
  withStepUpReceiptHeader,
  type DelegatedWriteAudit,
} from '../utils/delegated-write.js';

export interface CustomerProfileClientOptions {
  issuer: string;
  http: HttpClient;
}

export interface CustomerProfileRequestOptions {
  accessToken: string;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  timeout?: number;
}

export interface CustomerProfileDelegatedWriteOptions extends CustomerProfileRequestOptions {
  stepUpReceipt: string;
  idempotencyKey?: IdempotencyKeyInput;
  audit?: DelegatedWriteAudit | null;
  include?: Array<'actor' | 'subject' | 'audit'>;
}

export interface CustomerProfileElevationReadOptions extends CustomerProfileRequestOptions {
  /** Product-specific downstream elevation grant access token. */
  accessToken: string;
}

export interface CustomerProfileUpdateInput {
  email?: string;
  phone_number?: string | null;
  name?: string | null;
  given_name?: string | null;
  family_name?: string | null;
  nickname?: string | null;
  preferred_username?: string | null;
  picture?: string | null;
  website?: string | null;
  gender?: string | null;
  birthdate?: string | null;
  locale?: string | null;
  zoneinfo?: string | null;
  address?: {
    formatted?: string | null;
    street_address?: string | null;
    locality?: string | null;
    region?: string | null;
    postal_code?: string | null;
    country?: string | null;
  } | null;
}

export interface CustomerProfileView {
  sub: string;
  tenant_id?: string;
  name?: string | null;
  family_name?: string | null;
  given_name?: string | null;
  middle_name?: string | null;
  nickname?: string | null;
  preferred_username?: string | null;
  picture?: string | null;
  profile?: string | null;
  website?: string | null;
  gender?: string | null;
  birthdate?: string | null;
  zoneinfo?: string | null;
  locale?: string | null;
  email?: string | null;
  email_verified?: boolean;
  phone_number?: string | null;
  phone_number_verified?: boolean;
  address?: Record<string, string | null> | null;
  updated_at?: number;
  [key: string]: unknown;
}

export interface CustomerProfileDelegatedWriteResponse {
  customer_profile: CustomerProfileView;
  actor?: { id: string };
  subject?: { id: string };
  audit?: DelegatedWriteAudit;
}

export interface CustomerProfileElevationReadResponse {
  profile: CustomerProfileView;
  correlation_id?: string;
  redaction_level?: string;
  requires_online_check?: boolean;
  fail_closed?: boolean;
}

export interface CustomerProfileFailureBody {
  error: string;
  error_description?: string;
  error_uri?: string;
  error_details?: Phase1ErrorDetails;
  step_up?: unknown;
  status?: StepUpStatusObject;
  input_state?: StepUpInputState;
  next_action?: unknown;
}

export class CustomerProfileClient {
  private readonly issuer: string;
  private readonly http: HttpClient;

  constructor(options: CustomerProfileClientOptions) {
    this.issuer = options.issuer.replace(/\/$/, '');
    this.http = options.http;
  }

  /**
   * Product-specific downstream elevation grant read path.
   *
   * This is intentionally separate from standard delegated writes.
   */
  async getWithElevationGrant(
    subjectUserId: string,
    options: CustomerProfileElevationReadOptions
  ): Promise<CustomerProfileElevationReadResponse> {
    return this.request<CustomerProfileElevationReadResponse>(
      `/api/protected/customer-profiles/${encodeURIComponent(subjectUserId)}`,
      {
        method: 'GET',
        headers: {
          ...bearerHeaders(options.accessToken),
          ...(options.headers ?? {}),
        },
        signal: options.signal,
        timeout: options.timeout,
      }
    );
  }

  /**
   * Standard Phase 1 delegated write path.
   *
   * Actor identity remains the bearer token subject; the target subject is the path parameter.
   */
  async updateDelegated(
    subjectUserId: string,
    input: CustomerProfileUpdateInput,
    options: CustomerProfileDelegatedWriteOptions
  ): Promise<CustomerProfileDelegatedWriteResponse> {
    const query = options.include?.length
      ? `?include=${encodeURIComponent(options.include.join(','))}`
      : '';
    const headers = withStepUpReceiptHeader(
      withIdempotencyKeyHeader(
        {
          ...bearerHeaders(options.accessToken),
          ...(options.headers ?? {}),
          'Content-Type': 'application/json',
        },
        options.idempotencyKey
      ),
      options.stepUpReceipt
    );

    return this.request<CustomerProfileDelegatedWriteResponse>(
      `/api/protected/customer-profiles/users/${encodeURIComponent(subjectUserId)}${query}`,
      {
        method: 'PATCH',
        headers,
        body: JSON.stringify(createDelegatedWriteEnvelope(input, { audit: options.audit })),
        signal: options.signal,
        timeout: options.timeout,
      }
    );
  }

  private async request<T>(path: string, options: HttpOptions): Promise<T> {
    let response;
    try {
      response = await this.http.fetch<T | CustomerProfileFailureBody>(
        `${this.issuer}${path}`,
        options
      );
    } catch (error) {
      throw new AuthrimError('network_error', 'Customer profile request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (!response.ok) {
      if (isFailureBody(response.data)) {
        throw AuthrimError.fromOAuthError(response.data);
      }
      throw new AuthrimError('invalid_request', 'Customer profile request failed', {
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

function isFailureBody(value: unknown): value is CustomerProfileFailureBody {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { error?: unknown }).error === 'string'
  );
}
