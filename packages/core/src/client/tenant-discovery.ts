import type { HttpClient } from '../providers/http.js';
import { AuthrimError } from '../types/errors.js';

export type TenantDiscoveryMode =
  | 'email'
  | 'tenant_code'
  | 'tenant_slug'
  | 'invite_token'
  | 'app_hint';

export interface TenantDiscoveryClientOptions {
  http: HttpClient;
  /**
   * Authrim issuer or common-entry host. When omitted, currentHost is required
   * for each discovery call.
   */
  baseUrl?: string;
  /** Discovery endpoint path or absolute URL. */
  endpoint?: string;
}

export interface TenantDiscoveryInput {
  /** User email address. */
  email?: string;
  /** Email domain. Useful when the application collected only a domain. */
  domain?: string;
  /** Tenant id/slug. */
  tenantId?: string;
  tenantSlug?: string;
  /** Tenant code, when configured separately from tenant id. */
  tenantCode?: string;
  /** Invitation token. */
  inviteToken?: string;
  /** Client/application hint for duplicate client_id tenant resolution. */
  appHint?: string;
  /**
   * Current issuer/common-entry URL or host. Used to build the request URL when
   * the client was not constructed with a fixed baseUrl.
   */
  currentHost?: string;
}

export interface DiscoveredTenant {
  tenantId: string;
  issuer: string;
  loginUrl: string;
  displayName?: string;
  logoUrl?: string | null;
  source?: string;
  tenantCode?: string;
  raw: Record<string, unknown>;
}

export type TenantDiscoveryResult =
  | { status: 'resolved'; tenant: DiscoveredTenant; raw: Record<string, unknown> }
  | { status: 'multiple'; tenants: DiscoveredTenant[]; raw: Record<string, unknown> }
  | {
      status: 'manual_required';
      methods: string[];
      allowManualTenantEntry: boolean;
      raw: Record<string, unknown>;
    }
  | { status: 'not_found'; code: string; raw: Record<string, unknown> };

interface RawDiscoveryCandidate {
  tenant_id: string;
  tenant_code?: string;
  display_name?: string;
  logo_url?: string | null;
  login_url: string;
  source?: string;
  [key: string]: unknown;
}

interface RawDiscoveryResponse {
  result: string;
  candidate?: RawDiscoveryCandidate;
  candidates?: RawDiscoveryCandidate[];
  methods?: string[];
  allow_manual_tenant_entry?: boolean;
  code?: string;
  [key: string]: unknown;
}

export class TenantDiscoveryClient {
  private readonly http: HttpClient;
  private readonly baseUrl?: string;
  private readonly endpoint: string;

  constructor(options: TenantDiscoveryClientOptions) {
    this.http = options.http;
    this.baseUrl = options.baseUrl ? normalizeBaseUrl(options.baseUrl) : undefined;
    this.endpoint = options.endpoint ?? '/api/auth/discovery';
  }

  async discover(input: TenantDiscoveryInput): Promise<TenantDiscoveryResult> {
    const request = buildDiscoveryRequest(input);
    const url = this.resolveEndpoint(input.currentHost);
    const response = await this.http.fetch<RawDiscoveryResponse>(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      throw new AuthrimError('discovery_error', `Tenant discovery failed: ${response.status}`, {
        details: { status: response.status, statusText: response.statusText },
      });
    }

    return normalizeDiscoveryResponse(response.data);
  }

  private resolveEndpoint(currentHost?: string): string {
    if (/^https?:\/\//i.test(this.endpoint)) {
      return this.endpoint;
    }
    const baseUrl = this.baseUrl ?? (currentHost ? normalizeBaseUrl(currentHost) : undefined);
    if (!baseUrl) {
      throw new AuthrimError(
        'configuration_error',
        'Tenant discovery requires baseUrl or currentHost'
      );
    }
    return `${baseUrl}${this.endpoint.startsWith('/') ? '' : '/'}${this.endpoint}`;
  }
}

export function buildDiscoveryRequest(input: TenantDiscoveryInput): {
  mode: TenantDiscoveryMode;
  value: string;
} {
  if (input.email?.trim()) {
    return { mode: 'email', value: input.email.trim() };
  }
  if (input.domain?.trim()) {
    return { mode: 'email', value: input.domain.trim().replace(/^@/, '') };
  }
  if (input.tenantCode?.trim()) {
    return { mode: 'tenant_code', value: input.tenantCode.trim() };
  }
  if (input.tenantId?.trim()) {
    return { mode: 'tenant_slug', value: input.tenantId.trim() };
  }
  if (input.tenantSlug?.trim()) {
    return { mode: 'tenant_slug', value: input.tenantSlug.trim() };
  }
  if (input.inviteToken?.trim()) {
    return { mode: 'invite_token', value: input.inviteToken.trim() };
  }
  if (input.appHint?.trim()) {
    return { mode: 'app_hint', value: input.appHint.trim() };
  }
  throw new AuthrimError(
    'configuration_error',
    'Tenant discovery requires email, domain, tenantId, tenantSlug, tenantCode, inviteToken, or appHint'
  );
}

function normalizeDiscoveryResponse(response: RawDiscoveryResponse): TenantDiscoveryResult {
  const raw = response as Record<string, unknown>;
  if (response.result === 'resolved' && response.candidate) {
    return { status: 'resolved', tenant: normalizeCandidate(response.candidate), raw };
  }
  if (response.result === 'multiple' && Array.isArray(response.candidates)) {
    return {
      status: 'multiple',
      tenants: response.candidates.map(normalizeCandidate),
      raw,
    };
  }
  if (response.result === 'manual_required') {
    return {
      status: 'manual_required',
      methods: response.methods ?? [],
      allowManualTenantEntry: response.allow_manual_tenant_entry === true,
      raw,
    };
  }
  if (response.result === 'not_found') {
    return { status: 'not_found', code: response.code ?? 'not_found', raw };
  }
  throw new AuthrimError('discovery_error', 'Unexpected tenant discovery response', {
    details: { result: response.result },
  });
}

function normalizeCandidate(candidate: RawDiscoveryCandidate): DiscoveredTenant {
  return {
    tenantId: candidate.tenant_id,
    tenantCode: candidate.tenant_code,
    issuer: inferIssuerFromLoginUrl(candidate.login_url),
    loginUrl: candidate.login_url,
    displayName: candidate.display_name,
    logoUrl: candidate.logo_url,
    source: candidate.source,
    raw: candidate as Record<string, unknown>,
  };
}

function normalizeBaseUrl(value: string): string {
  const withScheme = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  return withScheme.replace(/\/+$/, '');
}

function inferIssuerFromLoginUrl(loginUrl: string): string {
  const url = new URL(loginUrl);
  return `${url.protocol}//${url.host}`;
}
