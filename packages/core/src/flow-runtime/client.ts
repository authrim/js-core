import type { HttpClient } from '../providers/http.js';
import type { AuthrimStorage } from '../providers/storage.js';
import { AuthrimError } from '../types/errors.js';
import type {
  FlowRuntimeEmailVerificationChallenge,
  FlowRuntimeFailureBody,
  FlowRuntimeStartRequest,
  FlowRuntimeStartResponse,
  FlowRuntimeSubmitRequest,
  FlowRuntimeSubmitResponse,
  StoredFlowRuntimeState,
} from './types.js';

export interface FlowRuntimeClientOptions {
  /** Authrim issuer. Used as the API base URL when baseUrl is omitted. */
  issuer: string;
  /** API base URL for browser surfaces that call Authrim through a same-origin proxy. */
  baseUrl?: string;
  http: HttpClient;
  storage?: AuthrimStorage;
  storageKeyPrefix?: string;
}

export interface FlowRuntimeRequestOptions {
  headers?: Record<string, string>;
  signal?: AbortSignal;
  timeout?: number;
}

export interface PersistFlowRuntimeStateOptions {
  postAuthRedirect?: string | null;
}

export class FlowRuntimeClient {
  private readonly baseUrl: string;
  private readonly http: HttpClient;
  private readonly storage?: AuthrimStorage;
  private readonly storageKeyPrefix: string;

  constructor(options: FlowRuntimeClientOptions) {
    this.baseUrl = normalizeBaseUrl(options.baseUrl ?? options.issuer, 'baseUrl');
    this.http = options.http;
    this.storage = options.storage;
    this.storageKeyPrefix = options.storageKeyPrefix ?? 'authrim:flow-runtime';
  }

  async start(
    request: FlowRuntimeStartRequest,
    options?: FlowRuntimeRequestOptions
  ): Promise<FlowRuntimeStartResponse> {
    return this.request<FlowRuntimeStartResponse>(
      '/api/v1/login/interactions/start',
      request,
      options
    );
  }

  async submit(
    interactionId: string,
    request: FlowRuntimeSubmitRequest,
    options?: FlowRuntimeRequestOptions
  ): Promise<FlowRuntimeSubmitResponse> {
    return this.request<FlowRuntimeSubmitResponse>(
      `/api/v1/login/interactions/${encodeURIComponent(interactionId)}/submit`,
      request,
      options
    );
  }

  async createEmailVerificationChallenge(
    interactionId: string,
    request: Pick<FlowRuntimeSubmitRequest, 'step_id' | 'contract_hash' | 'signature'>,
    options?: FlowRuntimeRequestOptions
  ): Promise<FlowRuntimeEmailVerificationChallenge> {
    return this.request<FlowRuntimeEmailVerificationChallenge>(
      `/api/v1/login/interactions/${encodeURIComponent(
        interactionId
      )}/email-verification/challenge`,
      request,
      options
    );
  }

  async persistState(
    flow: FlowRuntimeStartResponse,
    options: PersistFlowRuntimeStateOptions = {}
  ): Promise<void> {
    await this.persistStoredState({
      interaction_id: flow.interaction.id,
      contract_hash: flow.contract_hash,
      signature: flow.signature,
      ...(options.postAuthRedirect ? { post_auth_redirect: options.postAuthRedirect } : {}),
    });
  }

  async persistStoredState(state: StoredFlowRuntimeState): Promise<void> {
    if (!this.storage) {
      throw new AuthrimError('configuration_error', 'Flow runtime storage is not configured');
    }
    validateStoredState(state);
    await this.storage.set(this.stateKey(state.interaction_id), JSON.stringify(state));
  }

  async updatePostAuthRedirect(interactionId: string, postAuthRedirect: string): Promise<boolean> {
    if (!this.storage) {
      throw new AuthrimError('configuration_error', 'Flow runtime storage is not configured');
    }
    const state = readStoredFlowRuntimeState(await this.storage.get(this.stateKey(interactionId)));
    if (!state) return false;
    await this.persistStoredState({
      ...state,
      post_auth_redirect: postAuthRedirect,
    });
    return true;
  }

  async consumeState(interactionId: string): Promise<StoredFlowRuntimeState | null> {
    if (!this.storage) {
      throw new AuthrimError('configuration_error', 'Flow runtime storage is not configured');
    }
    const key = this.stateKey(interactionId);
    const state = readStoredFlowRuntimeState(await this.storage.get(key));
    await this.storage.remove(key);
    return state;
  }

  private stateKey(interactionId: string): string {
    return `${this.storageKeyPrefix}:${encodeURIComponent(interactionId)}`;
  }

  private async request<T>(
    path: string,
    body: object,
    options?: FlowRuntimeRequestOptions
  ): Promise<T> {
    let response;
    try {
      response = await this.http.fetch<T | FlowRuntimeFailureBody>(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: {
          ...(options?.headers ?? {}),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
        signal: options?.signal,
        timeout: options?.timeout,
      });
    } catch (error) {
      throw new AuthrimError('network_error', 'Flow runtime request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (!response.ok) {
      if (isFailureBody(response.data)) {
        throw AuthrimError.fromOAuthError(response.data);
      }
      throw new AuthrimError('invalid_request', 'Flow runtime request failed', {
        details: { status: response.status },
      });
    }
    return response.data as T;
  }
}

export function readStoredFlowRuntimeState(value: string | null): StoredFlowRuntimeState | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as StoredFlowRuntimeState;
    validateStoredState(parsed);
    return parsed;
  } catch {
    return null;
  }
}

function validateStoredState(value: StoredFlowRuntimeState): void {
  if (
    !value ||
    typeof value !== 'object' ||
    typeof value.interaction_id !== 'string' ||
    !value.interaction_id ||
    typeof value.contract_hash !== 'string' ||
    !value.contract_hash ||
    typeof value.signature !== 'string' ||
    !value.signature
  ) {
    throw new AuthrimError('invalid_state', 'Invalid flow runtime state');
  }
  if (value.post_auth_redirect !== undefined && typeof value.post_auth_redirect !== 'string') {
    throw new AuthrimError('invalid_state', 'Invalid flow runtime post-auth redirect');
  }
}

function normalizeBaseUrl(value: string, name: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new AuthrimError('configuration_error', `${name} is required`);
  }
  const url = new URL(trimmed);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new AuthrimError('configuration_error', `${name} must use http or https`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new AuthrimError(
      'configuration_error',
      `${name} must not include userinfo, search, or hash`
    );
  }
  return url.toString().replace(/\/+$/, '');
}

function isFailureBody(value: unknown): value is FlowRuntimeFailureBody {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { error?: unknown }).error === 'string'
  );
}
