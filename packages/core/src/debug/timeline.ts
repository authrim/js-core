/**
 * Event Timeline
 *
 * Records SDK events for debugging and observability.
 * All sensitive data is automatically redacted.
 */

import type { TimelineEntry } from '../events/types.js';
import type { RedactLevel } from './types.js';

/**
 * Sensitive keys that should always be redacted
 */
const SENSITIVE_KEYS = [
  'accessToken',
  'refreshToken',
  'idToken',
  'token',
  'code',
  'password',
  'secret',
  'credentials',
  'authorization',
  'bearer',
  'codeVerifier',
  'code_verifier',
  'client_secret',
];

/**
 * URL parameters that should be redacted in aggressive mode
 */
const SENSITIVE_URL_PARAMS = [
  'code',
  'state',
  'nonce',
  'id_token',
  'access_token',
  'refresh_token',
  'token',
];

/**
 * Event Timeline for debugging
 *
 * Records events with automatic redaction of sensitive data.
 * Safe to use in production - no sensitive data is stored.
 */
export class EventTimeline {
  private entries: TimelineEntry[] = [];
  private maxEvents: number;
  private redactLevel: RedactLevel;

  constructor(options?: { maxEvents?: number; redactLevel?: RedactLevel }) {
    this.maxEvents = options?.maxEvents ?? 100;
    this.redactLevel = options?.redactLevel ?? 'default';
  }

  /**
   * Record an event to the timeline
   *
   * Data is automatically redacted based on redact level.
   *
   * @param type - Event type
   * @param data - Event data (will be redacted)
   * @param options - Recording options
   */
  record(
    type: string,
    data?: unknown,
    options?: { operationId?: string; redact?: RedactLevel }
  ): void {
    const redactLevelToUse = options?.redact ?? this.redactLevel;
    const redactedData = this.redactData(data, redactLevelToUse);

    const entry: TimelineEntry = {
      type,
      timestamp: Date.now(),
      operationId: options?.operationId,
      data: redactedData,
    };

    this.entries.push(entry);

    // Trim to max events
    while (this.entries.length > this.maxEvents) {
      this.entries.shift();
    }
  }

  /**
   * Get recent entries
   *
   * @param count - Number of entries to return (default: all)
   * @returns Recent timeline entries
   */
  getRecent(count?: number): TimelineEntry[] {
    if (count === undefined) {
      return [...this.entries];
    }
    return this.entries.slice(-count);
  }

  /**
   * Get entries for a specific operation
   *
   * @param operationId - Operation ID to filter by
   * @returns Entries for the operation
   */
  getByOperationId(operationId: string): TimelineEntry[] {
    return this.entries.filter((entry) => entry.operationId === operationId);
  }

  /**
   * Get entries by event type
   *
   * @param type - Event type to filter by
   * @returns Entries matching the type
   */
  getByType(type: string): TimelineEntry[] {
    return this.entries.filter((entry) => entry.type === type);
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.entries = [];
  }

  /**
   * Get entry count
   */
  get length(): number {
    return this.entries.length;
  }

  /**
   * Convert timeline to JSON string (for export/logging)
   */
  toJSON(): string {
    return JSON.stringify(this.entries, null, 2);
  }

  /**
   * Set redaction level
   */
  setRedactLevel(level: RedactLevel): void {
    this.redactLevel = level;
  }

  /**
   * Redact sensitive data from event payload
   */
  private redactData(
    data: unknown,
    level: RedactLevel
  ): Record<string, unknown> | undefined {
    if (level === 'none' || data === undefined || data === null) {
      return data as Record<string, unknown> | undefined;
    }

    if (typeof data !== 'object') {
      return data as Record<string, unknown>;
    }

    const redacted = this.deepRedact(data as Record<string, unknown>, level);
    return redacted;
  }

  /**
   * Deep redact an object
   */
  private deepRedact(
    obj: Record<string, unknown>,
    level: RedactLevel
  ): Record<string, unknown> {
    const result: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();

      // Check if this is a sensitive key
      if (this.isSensitiveKey(lowerKey)) {
        // Add existence flag instead of value
        const capitalizedKey = key.charAt(0).toUpperCase() + key.slice(1);
        result[`has${capitalizedKey}`] = value !== undefined && value !== null;
        result[key] = '[REDACTED]';
        continue;
      }

      // Handle URL redaction in aggressive mode
      if (level === 'aggressive' && lowerKey === 'url' && typeof value === 'string') {
        result[key] = this.redactUrl(value);
        continue;
      }

      // Recursively redact nested objects
      if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        result[key] = this.deepRedact(value as Record<string, unknown>, level);
        continue;
      }

      // Recursively redact arrays
      if (Array.isArray(value)) {
        result[key] = value.map((item) => {
          if (item !== null && typeof item === 'object') {
            return this.deepRedact(item as Record<string, unknown>, level);
          }
          return item;
        });
        continue;
      }

      // Keep non-sensitive values
      result[key] = value;
    }

    return result;
  }

  /**
   * Check if a key is sensitive
   */
  private isSensitiveKey(key: string): boolean {
    return SENSITIVE_KEYS.some(
      (sensitive) => key === sensitive.toLowerCase() || key.includes(sensitive.toLowerCase())
    );
  }

  /**
   * Redact sensitive URL parameters
   */
  private redactUrl(url: string): string {
    try {
      const parsed = new URL(url);

      for (const param of SENSITIVE_URL_PARAMS) {
        if (parsed.searchParams.has(param)) {
          parsed.searchParams.set(param, '[REDACTED]');
        }
      }

      // Also check hash fragment
      if (parsed.hash) {
        const hashParams = new URLSearchParams(parsed.hash.slice(1));
        let hashModified = false;

        for (const param of SENSITIVE_URL_PARAMS) {
          if (hashParams.has(param)) {
            hashParams.set(param, '[REDACTED]');
            hashModified = true;
          }
        }

        if (hashModified) {
          parsed.hash = '#' + hashParams.toString();
        }
      }

      return parsed.toString();
    } catch {
      // If URL parsing fails, return with basic redaction
      return url.replace(/([?&])(code|token|state|nonce)=[^&]*/gi, '$1$2=[REDACTED]');
    }
  }
}
