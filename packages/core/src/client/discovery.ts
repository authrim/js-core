/**
 * OIDC Discovery Client
 *
 * Fetches and caches OIDC Discovery documents from the authorization server.
 * https://openid.net/specs/openid-connect-discovery-1_0.html
 */

import type { HttpClient } from '../providers/http.js';
import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import { AuthrimError } from '../types/errors.js';

/**
 * Cached discovery document with timestamp
 */
interface CachedDiscovery {
  doc: OIDCDiscoveryDocument;
  fetchedAt: number;
}

/**
 * Discovery client options
 */
export interface DiscoveryClientOptions {
  /** HTTP client for making requests */
  http: HttpClient;
  /** Cache TTL in milliseconds (default: 1 hour) */
  cacheTtlMs?: number;
}

/**
 * Normalize issuer URL
 *
 * Removes trailing slashes to ensure consistent comparison.
 *
 * @param issuer - Issuer URL
 * @returns Normalized issuer URL
 */
export function normalizeIssuer(issuer: string): string {
  return issuer.replace(/\/+$/, '');
}

/**
 * OIDC Discovery Client
 */
export class DiscoveryClient {
  private readonly http: HttpClient;
  private readonly cacheTtlMs: number;
  private readonly cache: Map<string, CachedDiscovery> = new Map();

  /** Default cache TTL: 1 hour */
  private static readonly DEFAULT_CACHE_TTL_MS = 3600 * 1000;

  constructor(options: DiscoveryClientOptions) {
    this.http = options.http;
    this.cacheTtlMs = options.cacheTtlMs ?? DiscoveryClient.DEFAULT_CACHE_TTL_MS;
  }

  /**
   * Fetch the OIDC Discovery document for an issuer
   *
   * @param issuer - Issuer URL
   * @returns Discovery document
   * @throws AuthrimError if discovery fails or issuer mismatch
   */
  async discover(issuer: string): Promise<OIDCDiscoveryDocument> {
    const normalizedIssuer = normalizeIssuer(issuer);
    const cached = this.cache.get(normalizedIssuer);

    // Return cached document if still valid
    if (cached && !this.isExpired(cached)) {
      return cached.doc;
    }

    // Fetch discovery document
    const discoveryUrl = `${normalizedIssuer}/.well-known/openid-configuration`;

    let doc: OIDCDiscoveryDocument;
    try {
      const response = await this.http.fetch<OIDCDiscoveryDocument>(discoveryUrl);
      if (!response.ok) {
        throw new AuthrimError('discovery_error', `Discovery request failed: ${response.status}`, {
          details: { status: response.status, statusText: response.statusText },
        });
      }
      doc = response.data;
    } catch (error) {
      if (error instanceof AuthrimError) {
        throw error;
      }
      throw new AuthrimError('discovery_error', 'Failed to fetch discovery document', {
        cause: error instanceof Error ? error : undefined,
        details: { url: discoveryUrl },
      });
    }

    // Validate issuer matches (security check)
    const docIssuer = normalizeIssuer(doc.issuer);
    if (docIssuer !== normalizedIssuer) {
      throw new AuthrimError(
        'discovery_mismatch',
        `Issuer mismatch in discovery document: expected "${normalizedIssuer}", got "${docIssuer}"`,
        {
          details: {
            expected: normalizedIssuer,
            actual: docIssuer,
          },
        }
      );
    }

    // Cache the document
    this.cache.set(normalizedIssuer, {
      doc,
      fetchedAt: Date.now(),
    });

    return doc;
  }

  /**
   * Check if a cached document has expired
   */
  private isExpired(cached: CachedDiscovery): boolean {
    return Date.now() - cached.fetchedAt > this.cacheTtlMs;
  }

  /**
   * Clear the discovery cache (useful for testing)
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Clear a specific issuer from the cache
   *
   * @param issuer - Issuer URL to clear
   */
  clearIssuer(issuer: string): void {
    this.cache.delete(normalizeIssuer(issuer));
  }
}
