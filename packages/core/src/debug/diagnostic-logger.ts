/**
 * Diagnostic Logger for SDK
 *
 * Provides diagnostic logging capabilities for debugging, troubleshooting,
 * and OIDF conformance testing. Integrates with server-side diagnostic logs
 * via diagnosticSessionId.
 *
 * Features:
 * - ID Token validation step logging
 * - Authentication decision logging
 * - Session ID correlation with server logs
 * - Console output and optional collection
 */

import type { DebugLogger } from './types.js';

/**
 * Diagnostic log level
 */
export type DiagnosticLogLevel = 'debug' | 'info' | 'warn' | 'error';

/**
 * Token validation step
 */
export type TokenValidationStep =
  | 'issuer-check'
  | 'audience-check'
  | 'expiry-check'
  | 'nonce-check'
  | 'signature-check'
  | 'hash-check';

/**
 * Base diagnostic log entry
 */
export interface BaseDiagnosticLogEntry {
  /** Unique log entry ID */
  id: string;

  /** Diagnostic session ID (for correlation with server logs) */
  diagnosticSessionId: string;

  /** Log category */
  category: string;

  /** Log level */
  level: DiagnosticLogLevel;

  /** Timestamp (Unix epoch in milliseconds) */
  timestamp: number;

  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Token Validation Log Entry
 */
export interface TokenValidationLogEntry extends BaseDiagnosticLogEntry {
  category: 'token-validation';

  /** Validation step */
  step: TokenValidationStep;

  /** Token type (id_token, access_token, etc.) */
  tokenType: string;

  /** Validation result */
  result: 'pass' | 'fail';

  /** Expected value (for validation) */
  expected?: unknown;

  /** Actual value (for validation) */
  actual?: unknown;

  /** Error message (if failed) */
  errorMessage?: string;

  /** Additional validation details */
  details?: Record<string, unknown>;
}

/**
 * Authentication Decision Log Entry
 */
export interface AuthDecisionLogEntry extends BaseDiagnosticLogEntry {
  category: 'auth-decision';

  /** Final authentication decision */
  decision: 'allow' | 'deny';

  /** Reason for the decision */
  reason: string;

  /** Authentication flow */
  flow?: string;

  /** Additional decision context */
  context?: Record<string, unknown>;
}

/**
 * Union type of all diagnostic log entries
 */
export type DiagnosticLogEntry = TokenValidationLogEntry | AuthDecisionLogEntry;

/**
 * Common interface for diagnostic loggers
 *
 * This interface allows different diagnostic logger implementations
 * (Core SDK, Web SDK, Node SDK) to be used interchangeably.
 */
export interface IDiagnosticLogger {
  /**
   * Get diagnostic session ID
   */
  getDiagnosticSessionId(): string;

  /**
   * Check if diagnostic logging is enabled
   */
  isEnabled(): boolean;

  /**
   * Log token validation step
   */
  logTokenValidation(options: {
    step: TokenValidationStep;
    tokenType: string;
    result: 'pass' | 'fail';
    expected?: unknown;
    actual?: unknown;
    errorMessage?: string;
    details?: Record<string, unknown>;
  }): void;

  /**
   * Log authentication decision
   */
  logAuthDecision(options: {
    decision: 'allow' | 'deny';
    reason: string;
    flow?: string;
    context?: Record<string, unknown>;
  }): void;
}

/**
 * Diagnostic logger options
 */
export interface DiagnosticLoggerOptions {
  /** Enable diagnostic logging */
  enabled: boolean;

  /** Underlying debug logger */
  debugLogger?: DebugLogger;

  /** Collect logs in memory for export */
  collectLogs?: boolean;

  /** Maximum number of logs to collect (default: 1000) */
  maxLogs?: number;
}

/**
 * Diagnostic Logger for SDK
 */
export class DiagnosticLogger implements IDiagnosticLogger {
  private diagnosticSessionId: string;
  private enabled: boolean;
  private debugLogger?: DebugLogger;
  private collectLogs: boolean;
  private maxLogs: number;
  private logs: DiagnosticLogEntry[] = [];

  constructor(options: DiagnosticLoggerOptions) {
    this.diagnosticSessionId = this.generateSessionId();
    this.enabled = options.enabled;
    this.debugLogger = options.debugLogger;
    this.collectLogs = options.collectLogs ?? false;
    this.maxLogs = options.maxLogs ?? 1000;
  }

  /**
   * Get diagnostic session ID
   *
   * This ID should be sent to the server via X-Diagnostic-Session-Id header
   * to correlate SDK logs with server logs.
   */
  getDiagnosticSessionId(): string {
    return this.diagnosticSessionId;
  }

  /**
   * Check if diagnostic logging is enabled
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Log token validation step
   */
  logTokenValidation(options: {
    step: TokenValidationStep;
    tokenType: string;
    result: 'pass' | 'fail';
    expected?: unknown;
    actual?: unknown;
    errorMessage?: string;
    details?: Record<string, unknown>;
  }): void {
    if (!this.enabled) return;

    const entry: TokenValidationLogEntry = {
      id: this.generateEntryId(),
      diagnosticSessionId: this.diagnosticSessionId,
      category: 'token-validation',
      level: options.result === 'fail' ? 'error' : 'debug',
      timestamp: Date.now(),
      step: options.step,
      tokenType: options.tokenType,
      result: options.result,
      expected: options.expected,
      actual: options.actual,
      errorMessage: options.errorMessage,
      details: options.details,
    };

    this.writeLog(entry);
  }

  /**
   * Log authentication decision
   */
  logAuthDecision(options: {
    decision: 'allow' | 'deny';
    reason: string;
    flow?: string;
    context?: Record<string, unknown>;
  }): void {
    if (!this.enabled) return;

    const entry: AuthDecisionLogEntry = {
      id: this.generateEntryId(),
      diagnosticSessionId: this.diagnosticSessionId,
      category: 'auth-decision',
      level: options.decision === 'deny' ? 'warn' : 'info',
      timestamp: Date.now(),
      decision: options.decision,
      reason: options.reason,
      flow: options.flow,
      context: options.context,
    };

    this.writeLog(entry);
  }

  /**
   * Get all collected logs
   */
  getLogs(): DiagnosticLogEntry[] {
    return [...this.logs];
  }

  /**
   * Export logs as JSON string
   */
  exportLogs(): string {
    return JSON.stringify(this.logs, null, 2);
  }

  /**
   * Clear collected logs
   */
  clearLogs(): void {
    this.logs = [];
  }

  /**
   * Write log entry (internal)
   */
  private writeLog(entry: DiagnosticLogEntry): void {
    // Output to debug logger
    if (this.debugLogger) {
      this.debugLogger.log(entry.level, `[DIAGNOSTIC] ${entry.category}`, entry);
    }

    // Collect in memory
    if (this.collectLogs) {
      this.logs.push(entry);

      // Trim if exceeds max
      if (this.logs.length > this.maxLogs) {
        this.logs.shift();
      }
    }
  }

  /**
   * Generate diagnostic session ID
   */
  private generateSessionId(): string {
    // Use crypto.randomUUID if available (modern browsers/Node.js)
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
      return crypto.randomUUID();
    }

    // Fallback: generate UUID v4
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  /**
   * Generate log entry ID
   */
  private generateEntryId(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  }
}

/**
 * Create a diagnostic logger
 *
 * @param options - Logger options
 * @returns DiagnosticLogger instance or null if disabled
 */
export function createDiagnosticLogger(
  options: DiagnosticLoggerOptions
): DiagnosticLogger | null {
  if (!options.enabled) {
    return null;
  }

  return new DiagnosticLogger(options);
}
