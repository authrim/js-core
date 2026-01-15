/**
 * Mock Storage Provider
 */

import type { AuthrimStorage } from '../../src/providers/storage.js';

/**
 * Create a mock storage provider (in-memory)
 */
export function createMockStorage(): AuthrimStorage & {
  store: Map<string, string>;
  getAllKeys(): string[];
} {
  const store = new Map<string, string>();

  return {
    store,

    async get(key: string): Promise<string | null> {
      return store.get(key) ?? null;
    },

    async set(key: string, value: string): Promise<void> {
      store.set(key, value);
    },

    async remove(key: string): Promise<void> {
      store.delete(key);
    },

    async getAll(): Promise<Record<string, string>> {
      const result: Record<string, string> = {};
      for (const [key, value] of store) {
        result[key] = value;
      }
      return result;
    },

    async clear(): Promise<void> {
      store.clear();
    },

    getAllKeys(): string[] {
      return Array.from(store.keys());
    },
  };
}
