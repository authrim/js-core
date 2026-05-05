import type { HttpClient, HttpOptions } from '../providers/http.js';
import { AuthrimError } from '../types/errors.js';
import type {
  StepUpActionResponse,
  StepUpCompleteRequest,
  StepUpFailureBody,
  StepUpStartRequest,
} from '../types/step-up.js';
import type { IdempotencyKeyInput } from '../utils/idempotency.js';
import { withIdempotencyKeyHeader } from '../utils/idempotency.js';

export interface StepUpClientOptions {
  issuer: string;
  http: HttpClient;
}

export interface StepUpRequestOptions {
  headers?: Record<string, string>;
  signal?: AbortSignal;
  timeout?: number;
}

export interface StepUpIdempotentRequestOptions extends StepUpRequestOptions {
  idempotencyKey?: IdempotencyKeyInput;
}

export class StepUpClient {
  private readonly issuer: string;
  private readonly http: HttpClient;

  constructor(options: StepUpClientOptions) {
    this.issuer = options.issuer.replace(/\/$/, '');
    this.http = options.http;
  }

  async start(
    request: StepUpStartRequest,
    options?: StepUpRequestOptions
  ): Promise<StepUpActionResponse> {
    return this.request<StepUpActionResponse>('/auth/step-up/start', {
      method: 'POST',
      headers: {
        ...(options?.headers ?? {}),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
      signal: options?.signal,
      timeout: options?.timeout,
    });
  }

  async getAction(actionId: string, options?: StepUpRequestOptions): Promise<StepUpActionResponse> {
    return this.request<StepUpActionResponse>(
      `/auth/step-up/actions/${encodeURIComponent(actionId)}`,
      {
        method: 'GET',
        headers: options?.headers,
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
  }

  async complete<Input = unknown>(
    actionId: string,
    request: StepUpCompleteRequest<Input>,
    options?: StepUpIdempotentRequestOptions
  ): Promise<StepUpActionResponse> {
    return this.request<StepUpActionResponse>(
      `/auth/step-up/actions/${encodeURIComponent(actionId)}/complete`,
      {
        method: 'POST',
        headers: withIdempotencyKeyHeader(
          {
            ...(options?.headers ?? {}),
            'Content-Type': 'application/json',
          },
          options?.idempotencyKey
        ),
        body: JSON.stringify(request),
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
  }

  async resend(
    actionId: string,
    options?: StepUpIdempotentRequestOptions
  ): Promise<StepUpActionResponse> {
    return this.request<StepUpActionResponse>(
      `/auth/step-up/actions/${encodeURIComponent(actionId)}/resend`,
      {
        method: 'POST',
        headers: withIdempotencyKeyHeader(options?.headers, options?.idempotencyKey),
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
  }

  async cancel(actionId: string, options?: StepUpRequestOptions): Promise<StepUpActionResponse> {
    return this.request<StepUpActionResponse>(
      `/auth/step-up/actions/${encodeURIComponent(actionId)}`,
      {
        method: 'DELETE',
        headers: options?.headers,
        signal: options?.signal,
        timeout: options?.timeout,
      }
    );
  }

  private async request<T>(path: string, options: HttpOptions): Promise<T> {
    let response;
    try {
      response = await this.http.fetch<T | StepUpFailureBody>(`${this.issuer}${path}`, options);
    } catch (error) {
      throw new AuthrimError('network_error', 'Step-Up request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (!response.ok) {
      const payload = response.data;
      if (isStepUpFailureBody(payload)) {
        throw AuthrimError.fromOAuthError(payload);
      }
      throw new AuthrimError('invalid_request', 'Step-Up request failed', {
        details: {
          status: response.status,
        },
      });
    }

    return response.data as T;
  }
}

function isStepUpFailureBody(value: unknown): value is StepUpFailureBody {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { error?: unknown }).error === 'string'
  );
}
