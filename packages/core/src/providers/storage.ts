/**
 * Storage Provider Interface
 *
 * Platform-agnostic storage abstraction.
 * Implementations must be injected - @authrim/core does not use localStorage directly.
 */

/**
 * Storage Provider interface
 *
 * Implementations:
 * - Browser: localStorage, sessionStorage, IndexedDB
 * - React Native: AsyncStorage
 * - Node.js: Memory, Redis, Database
 * - Cookie-based: Server-side session storage
 *
 * Note: getAll() and clear() are optional. The SDK functions correctly without them,
 * but providing them enables automatic cleanup of expired state entries.
 */
export interface AuthrimStorage {
  /**
   * Get a value from storage
   *
   * @param key - Storage key
   * @returns Promise resolving to the value, or null if not found
   */
  get(key: string): Promise<string | null>;

  /**
   * Set a value in storage
   *
   * @param key - Storage key
   * @param value - Value to store
   * @returns Promise resolving when complete
   */
  set(key: string, value: string): Promise<void>;

  /**
   * Remove a value from storage
   *
   * @param key - Storage key
   * @returns Promise resolving when complete
   */
  remove(key: string): Promise<void>;

  /**
   * Get all key-value pairs from storage (optional)
   *
   * Used for cleanup of expired state entries.
   * If not implemented, cleanup operations are skipped (security is not affected).
   *
   * @returns Promise resolving to all stored values
   */
  getAll?(): Promise<Record<string, string>>;

  /**
   * Clear all values from storage (optional)
   *
   * Use with caution - clears ALL stored data including tokens.
   *
   * @returns Promise resolving when complete
   */
  clear?(): Promise<void>;
}
