/**
 * Client Configuration
 */

import type { HttpClient } from '../providers/http.js';
import type { CryptoProvider } from '../providers/crypto.js';
import type { AuthrimStorage } from '../providers/storage.js';

/**
 * Endpoint overrides
 */
export interface EndpointOverrides {
  /** Authorization endpoint */
  authorization?: string;
  /** Token endpoint */
  token?: string;
  /** UserInfo endpoint */
  userinfo?: string;
  /** Revocation endpoint */
  revocation?: string;
  /** End session endpoint (null to disable) */
  endSession?: string | null;
}

/**
 * Hash options for storage key generation
 */
export interface HashOptions {
  /**
   * Hash length for storage keys
   *
   * Default: 16 characters (96 bits)
   * Alternative: 22 characters (132 bits) for lower collision risk
   */
  hashLength?: number;
}

/**
 * Authrim Client Configuration
 */
export interface AuthrimClientConfig {
  /**
   * OpenID Connect issuer URL
   *
   * This is used to fetch the discovery document and validate tokens.
   * Trailing slashes are automatically normalized.
   */
  issuer: string;

  /**
   * OAuth 2.0 client ID
   */
  clientId: string;

  /**
   * HTTP client implementation
   *
   * Required for @authrim/core.
   * @authrim/web provides a default browser implementation.
   */
  http: HttpClient;

  /**
   * Crypto provider implementation
   *
   * Required for @authrim/core.
   * @authrim/web provides a default browser implementation.
   */
  crypto: CryptoProvider;

  /**
   * Storage provider implementation
   *
   * Required for @authrim/core.
   * @authrim/web provides localStorage/sessionStorage implementations.
   */
  storage: AuthrimStorage;

  /**
   * Default redirect URI for authorization requests
   */
  redirectUri?: string;

  /**
   * Default scopes to request
   *
   * Default: ['openid', 'profile']
   */
  scopes?: string[];

  /**
   * Manual endpoint overrides
   *
   * Use these to override discovery document endpoints.
   * Set endSession to null to disable logout redirect.
   */
  endpoints?: EndpointOverrides;

  /**
   * Enable Flow Engine (server-driven UI)
   *
   * Default: true
   * Set to false to use standard OIDC flows only.
   */
  flowEngine?: boolean;

  /**
   * Discovery cache TTL in milliseconds
   *
   * Default: 3600000 (1 hour)
   */
  discoveryCacheTtlMs?: number;

  /**
   * Token refresh skew in seconds
   *
   * Refresh tokens this many seconds before expiration.
   * Default: 30
   */
  refreshSkewSeconds?: number;

  /**
   * State/nonce TTL in seconds
   *
   * Default: 600 (10 minutes)
   */
  stateTtlSeconds?: number;

  /**
   * Hash options for storage key generation
   */
  hashOptions?: HashOptions;
}

/**
 * Resolved configuration with defaults applied
 */
export interface ResolvedConfig extends Required<
  Omit<AuthrimClientConfig, 'endpoints' | 'redirectUri' | 'hashOptions'>
> {
  endpoints?: EndpointOverrides;
  redirectUri?: string;
  hashOptions: Required<HashOptions>;
}

/**
 * Apply defaults to configuration
 */
export function resolveConfig(config: AuthrimClientConfig): ResolvedConfig {
  return {
    ...config,
    scopes: config.scopes ?? ['openid', 'profile'],
    flowEngine: config.flowEngine ?? true,
    discoveryCacheTtlMs: config.discoveryCacheTtlMs ?? 3600 * 1000,
    refreshSkewSeconds: config.refreshSkewSeconds ?? 30,
    stateTtlSeconds: config.stateTtlSeconds ?? 600,
    hashOptions: {
      hashLength: config.hashOptions?.hashLength ?? 16,
    },
  };
}
