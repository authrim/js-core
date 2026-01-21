/**
 * Debug Module Types
 *
 * Types for debugging and observability features.
 */

/**
 * Debug options for SDK initialization
 */
export interface DebugOptions {
  /** Enable debug mode */
  enabled: boolean;
  /** Enable verbose logging */
  verbose?: boolean;
  /** Include timestamps in logs */
  logTimestamps?: boolean;
  /** Custom logger implementation */
  logger?: DebugLogger;
  /** Maximum events to keep in timeline (default: 100) */
  maxTimelineEvents?: number;
  /** Redaction level for sensitive data */
  redactLevel?: RedactLevel;
}

/**
 * Debug logger interface
 */
export interface DebugLogger {
  /** Log a message with optional data */
  log(level: DebugLogLevel, message: string, data?: unknown): void;
}

/**
 * Debug log levels
 */
export type DebugLogLevel = 'debug' | 'info' | 'warn' | 'error';

/**
 * Redaction level for sensitive data
 *
 * - 'default': Mask token values, keep structure
 * - 'none': No redaction (only for development)
 * - 'aggressive': Mask tokens and URL parameters
 */
export type RedactLevel = 'default' | 'none' | 'aggressive';
