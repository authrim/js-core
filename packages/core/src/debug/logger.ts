/**
 * Debug Logger
 *
 * Platform-agnostic logging infrastructure for SDK debugging.
 */

import type { DebugLogger, DebugLogLevel, DebugOptions } from './types.js';

/**
 * Create a console-based debug logger
 *
 * This logger writes to console with Authrim-prefixed messages.
 * Safe to use with any console implementation.
 */
export function createConsoleLogger(options?: {
  timestamps?: boolean;
}): DebugLogger {
  const includeTimestamps = options?.timestamps ?? false;

  return {
    log(level: DebugLogLevel, message: string, data?: unknown): void {
      const prefix = includeTimestamps
        ? `[Authrim:${level.toUpperCase()} ${new Date().toISOString()}]`
        : `[Authrim:${level.toUpperCase()}]`;

      const consoleMethod = level === 'debug' ? 'log' : level;

      // Use globalThis.console to ensure platform compatibility
      const consoleObj = typeof console !== 'undefined' ? console : null;
      if (!consoleObj) return;

      if (data !== undefined) {
        consoleObj[consoleMethod]?.(prefix, message, data);
      } else {
        consoleObj[consoleMethod]?.(prefix, message);
      }
    },
  };
}

/**
 * No-op logger for when debug mode is disabled
 */
export const noopLogger: DebugLogger = {
  log(): void {
    // Intentionally empty
  },
};

/**
 * Create a debug logger based on options
 */
export function createDebugLogger(options: DebugOptions): DebugLogger {
  if (!options.enabled) {
    return noopLogger;
  }

  if (options.logger) {
    return options.logger;
  }

  return createConsoleLogger({
    timestamps: options.logTimestamps,
  });
}

/**
 * Debug context for tracking operations
 */
export class DebugContext {
  private logger: DebugLogger;
  private verbose: boolean;
  private operationId: string | null = null;

  constructor(logger: DebugLogger, options?: { verbose?: boolean }) {
    this.logger = logger;
    this.verbose = options?.verbose ?? false;
  }

  /**
   * Set current operation ID for log correlation
   */
  setOperationId(id: string | null): void {
    this.operationId = id;
  }

  /**
   * Get current operation ID
   */
  getOperationId(): string | null {
    return this.operationId;
  }

  /**
   * Log a debug message (verbose mode only)
   */
  debug(message: string, data?: unknown): void {
    if (this.verbose) {
      this.logger.log('debug', this.formatMessage(message), data);
    }
  }

  /**
   * Log an info message
   */
  info(message: string, data?: unknown): void {
    this.logger.log('info', this.formatMessage(message), data);
  }

  /**
   * Log a warning message
   */
  warn(message: string, data?: unknown): void {
    this.logger.log('warn', this.formatMessage(message), data);
  }

  /**
   * Log an error message
   */
  error(message: string, data?: unknown): void {
    this.logger.log('error', this.formatMessage(message), data);
  }

  /**
   * Format message with operation ID if available
   */
  private formatMessage(message: string): string {
    if (this.operationId) {
      return `[${this.operationId.slice(0, 8)}] ${message}`;
    }
    return message;
  }
}
