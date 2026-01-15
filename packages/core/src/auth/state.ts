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
  /** Timestamp when state was created */
  createdAt: number;
  /** Timestamp when state expires */
  expiresAt: number;
}

/**
 * Options for generating auth state
 */
export interface GenerateAuthStateOptions {
  /** Redirect URI for this auth request */
  redirectUri: string;
  /** Code verifier for PKCE */
  codeVerifier: string;
  /** TTL in seconds (default: 600 = 10 minutes) */
  ttlSeconds?: number;
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

    // Generate random state and nonce (32 bytes each)
    const stateBytes = await this.crypto.randomBytes(32);
    const nonceBytes = await this.crypto.randomBytes(32);

    const state = base64urlEncode(stateBytes);
    const nonce = base64urlEncode(nonceBytes);

    const now = Date.now();
    const authState: AuthState = {
      state,
      nonce,
      codeVerifier: options.codeVerifier,
      redirectUri: options.redirectUri,
      createdAt: now,
      expiresAt: now + ttlSeconds * 1000,
    };

    // Store in storage
    const key = STORAGE_KEYS.authState(this.issuerHash, this.clientIdHash, state);
    await this.storage.set(key, JSON.stringify(authState));

    return authState;
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
}
