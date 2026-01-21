/**
 * State/Nonce Manager
 *
 * Manages CSRF protection (state) and replay attack prevention (nonce)
 * for Authorization Code Flow.
 */

import type { CryptoProvider } from '../providers/crypto.js';
import type { AuthrimStorage } from '../providers/storage.js';
import { AuthrimError } from '../types/errors.js';
import { base64urlEncode } from '../utils/base64url.js';

/**
 * Auth state stored in storage
 */
export interface AuthState {
  /** State parameter (CSRF protection) */
  state: string;
  /** Nonce parameter (replay attack prevention) */
  nonce: string;
  /** PKCE code verifier */
  codeVerifier: string;
  /** Redirect URI used for this auth request */
  redirectUri: string;
  /** Requested scope (for validation) */
  scope: string;
  /** Timestamp when state was created */
  createdAt: number;
  /** Timestamp when state expires */
  expiresAt: number;
  /** Return URL after authentication (validated) */
  returnTo?: string;
  /** Operation tracking ID (for event correlation) */
  operationId: string;
}

/**
 * ReturnTo URL policy
 *
 * Controls which returnTo URLs are accepted to prevent open redirect attacks.
 */
export type ReturnToPolicy =
  | 'relative_only'     // Default: relative paths only (/dashboard)
  | 'same_origin'       // Same origin only
  | 'allowlist';        // Explicit allowlist

/**
 * ReturnTo URL options
 */
export interface ReturnToOptions {
  /** Validation policy */
  policy: ReturnToPolicy;
  /** Allowed origins (required when policy is 'allowlist') */
  allowedOrigins?: string[];
  /** Current origin for same_origin check (required in non-browser environments) */
  currentOrigin?: string;
}

/**
 * Options for generating auth state
 */
export interface GenerateAuthStateOptions {
  /** Redirect URI for this auth request */
  redirectUri: string;
  /** Code verifier for PKCE */
  codeVerifier: string;
  /** Requested scope (for validation) */
  scope: string;
  /** TTL in seconds (default: 600 = 10 minutes) */
  ttlSeconds?: number;
  /** Return URL after authentication */
  returnTo?: string;
  /** ReturnTo URL validation options */
  returnToOptions?: ReturnToOptions;
}

/**
 * Storage keys factory
 */
export const STORAGE_KEYS = {
  /**
   * Auth state key (state-specific)
   */
  authState: (issuerHash: string, clientIdHash: string, state: string): string =>
    `authrim:${issuerHash}:${clientIdHash}:auth:${state}`,

  /**
   * Token storage key
   */
  tokens: (issuerHash: string, clientIdHash: string): string =>
    `authrim:${issuerHash}:${clientIdHash}:tokens`,

  /**
   * ID token storage key
   */
  idToken: (issuerHash: string, clientIdHash: string): string =>
    `authrim:${issuerHash}:${clientIdHash}:id_token`,

  /**
   * Auth state prefix for cleanup
   */
  authStatePrefix: (issuerHash: string, clientIdHash: string): string =>
    `authrim:${issuerHash}:${clientIdHash}:auth:`,
} as const;

/**
 * State Manager
 */
export class StateManager {
  /** Default TTL: 10 minutes */
  private static readonly DEFAULT_TTL_SECONDS = 600;

  /** Entropy bytes for state/nonce generation (256 bits = 32 bytes) */
  private static readonly ENTROPY_BYTES = 32;

  /** Entropy bytes for operationId (128 bits = 16 bytes, enough for tracking) */
  private static readonly OPERATION_ID_BYTES = 16;

  /** Auto cleanup interval (5 minutes) */
  private static readonly DEFAULT_CLEANUP_INTERVAL_MS = 300000;

  /** Cleanup interval handle */
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly crypto: CryptoProvider,
    private readonly storage: AuthrimStorage,
    private readonly issuerHash: string,
    private readonly clientIdHash: string
  ) {}

  /**
   * Generate and store auth state
   *
   * Creates state, nonce, stores them with the code verifier.
   *
   * @param options - Generation options
   * @returns Generated state string
   */
  async generateAuthState(options: GenerateAuthStateOptions): Promise<AuthState> {
    const ttlSeconds = options.ttlSeconds ?? StateManager.DEFAULT_TTL_SECONDS;

    // Validate returnTo URL if provided
    let validatedReturnTo: string | undefined;
    if (options.returnTo) {
      validatedReturnTo = this.validateReturnTo(
        options.returnTo,
        options.returnToOptions ?? { policy: 'relative_only' }
      );
    }

    // Generate random state, nonce, and operationId (256-bit entropy each)
    const stateBytes = await this.crypto.randomBytes(StateManager.ENTROPY_BYTES);
    const nonceBytes = await this.crypto.randomBytes(StateManager.ENTROPY_BYTES);
    const operationIdBytes = await this.crypto.randomBytes(StateManager.OPERATION_ID_BYTES);

    const state = base64urlEncode(stateBytes);
    const nonce = base64urlEncode(nonceBytes);
    const operationId = base64urlEncode(operationIdBytes);

    const now = Date.now();
    const authState: AuthState = {
      state,
      nonce,
      codeVerifier: options.codeVerifier,
      redirectUri: options.redirectUri,
      scope: options.scope,
      createdAt: now,
      expiresAt: now + ttlSeconds * 1000,
      returnTo: validatedReturnTo,
      operationId,
    };

    // Store in storage
    const key = STORAGE_KEYS.authState(this.issuerHash, this.clientIdHash, state);
    await this.storage.set(key, JSON.stringify(authState));

    return authState;
  }

  /**
   * Validate returnTo URL against policy (Open Redirect Protection)
   *
   * @param returnTo - URL to validate
   * @param options - Validation options
   * @returns Validated URL
   * @throws AuthrimError if URL is invalid
   */
  private validateReturnTo(returnTo: string, options: ReturnToOptions): string {
    switch (options.policy) {
      case 'relative_only':
        // Only allow relative paths starting with /
        // Reject absolute URLs and protocol-relative URLs (//)
        if (returnTo.startsWith('/') && !returnTo.startsWith('//')) {
          // Additional check: ensure no protocol in the path
          if (!returnTo.includes(':')) {
            return returnTo;
          }
        }
        throw new AuthrimError(
          'invalid_return_to',
          'returnTo must be a relative path (e.g., /dashboard)'
        );

      case 'same_origin':
        try {
          // For non-browser environments, currentOrigin must be provided
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const globalWindow = typeof globalThis !== 'undefined' ? (globalThis as any).window : undefined;
          const currentOrigin = options.currentOrigin ?? (globalWindow?.location?.origin);
          if (!currentOrigin) {
            throw new AuthrimError(
              'invalid_return_to',
              'currentOrigin is required for same_origin policy in non-browser environments'
            );
          }

          // Handle relative URLs
          if (returnTo.startsWith('/') && !returnTo.startsWith('//')) {
            return returnTo;
          }

          // Check absolute URL
          const url = new URL(returnTo);
          if (url.origin === currentOrigin) {
            return returnTo;
          }
        } catch (e) {
          if (e instanceof AuthrimError) throw e;
          // URL parsing failed
        }
        throw new AuthrimError(
          'invalid_return_to',
          'returnTo must be same origin or a relative path'
        );

      case 'allowlist':
        if (!options.allowedOrigins || options.allowedOrigins.length === 0) {
          throw new AuthrimError(
            'invalid_return_to',
            'allowedOrigins is required when using allowlist policy'
          );
        }

        // Allow relative URLs
        if (returnTo.startsWith('/') && !returnTo.startsWith('//')) {
          return returnTo;
        }

        try {
          const parsed = new URL(returnTo);
          if (options.allowedOrigins.includes(parsed.origin)) {
            return returnTo;
          }
        } catch {
          // URL parsing failed
        }
        throw new AuthrimError(
          'invalid_return_to',
          `returnTo origin not in allowlist: ${options.allowedOrigins.join(', ')}`
        );

      default:
        throw new AuthrimError(
          'invalid_return_to',
          `Unknown returnTo policy: ${options.policy}`
        );
    }
  }

  /**
   * Validate and consume state
   *
   * Retrieves, validates, and ALWAYS deletes the state (success or failure).
   * This ensures replay attack prevention and GC.
   *
   * @param state - State parameter from callback
   * @returns Auth state if valid
   * @throws AuthrimError if state is invalid or expired
   */
  async validateAndConsumeState(state: string): Promise<AuthState> {
    const key = STORAGE_KEYS.authState(this.issuerHash, this.clientIdHash, state);

    try {
      const stored = await this.storage.get(key);

      if (!stored) {
        throw new AuthrimError('invalid_state', 'State not found or already used');
      }

      let authState: AuthState;
      try {
        authState = JSON.parse(stored);
      } catch {
        throw new AuthrimError('invalid_state', 'Malformed state data');
      }

      // Check expiration (no skew - strict)
      if (Date.now() > authState.expiresAt) {
        throw new AuthrimError('expired_state', 'State has expired');
      }

      return authState;
    } finally {
      // ALWAYS delete (success, failure, or exception)
      // This is critical for:
      // 1. Replay attack prevention
      // 2. GC of used/expired states
      await this.storage.remove(key);
    }
  }

  /**
   * Clean up expired states
   *
   * This is a best-effort cleanup. Only works if storage.getAll() is available.
   * The primary GC mechanism is validateAndConsumeState()'s finally delete.
   *
   * Safe to call at startup or periodically.
   */
  async cleanupExpiredStates(): Promise<void> {
    // Only works if storage supports getAll()
    if (!this.storage.getAll) {
      return;
    }

    const prefix = STORAGE_KEYS.authStatePrefix(this.issuerHash, this.clientIdHash);
    const all = await this.storage.getAll();
    const now = Date.now();

    for (const [key, value] of Object.entries(all)) {
      if (!key.startsWith(prefix)) {
        continue;
      }

      try {
        const authState: AuthState = JSON.parse(value);
        if (now > authState.expiresAt) {
          await this.storage.remove(key);
        }
      } catch {
        // Parse failure - delete corrupted entry
        await this.storage.remove(key);
      }
    }
  }

  /**
   * Start automatic cleanup of expired states
   *
   * Runs cleanup every 5 minutes by default.
   *
   * @param intervalMs - Cleanup interval in milliseconds (default: 300000 = 5 minutes)
   */
  startAutoCleanup(intervalMs: number = StateManager.DEFAULT_CLEANUP_INTERVAL_MS): void {
    this.stopAutoCleanup();

    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredStates().catch(() => {
        // Ignore cleanup errors
      });
    }, intervalMs);

    // Run initial cleanup
    this.cleanupExpiredStates().catch(() => {
      // Ignore cleanup errors
    });
  }

  /**
   * Stop automatic cleanup
   */
  stopAutoCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Get the number of stored auth states
   *
   * Only works if storage.getAll() is available.
   *
   * @returns Number of stored states, or -1 if not supported
   */
  async getStoredStateCount(): Promise<number> {
    if (!this.storage.getAll) {
      return -1;
    }

    const prefix = STORAGE_KEYS.authStatePrefix(this.issuerHash, this.clientIdHash);
    const all = await this.storage.getAll();

    let count = 0;
    for (const key of Object.keys(all)) {
      if (key.startsWith(prefix)) {
        count++;
      }
    }

    return count;
  }
}
