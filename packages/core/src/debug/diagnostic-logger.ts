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

const DEFAULT_MAX_LOGS = 1000;
const MAX_ALLOWED_LOGS = 10000;
const DEFAULT_BATCH_SIZE = 50;
const MAX_BATCH_SIZE = 100;
const DIAGNOSTIC_SEND_TIMEOUT_MS = 10000;

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

  /** Send logs to server (default: false) */
  sendToServer?: boolean;

  /** Server URL for sending logs */
  serverUrl?: string;

  /** Client ID for authentication */
  clientId?: string;

  /** Client secret for authentication (confidential clients only) */
  clientSecret?: string;

  /** Batch size for sending logs (default: 50) */
  batchSize?: number;

  /** Flush interval in milliseconds (default: 5000) */
  flushIntervalMs?: number;
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

  // Server sending options
  private sendToServer: boolean;
  private serverUrl?: string;
  private clientId?: string;
  private clientSecret?: string;
  private batchSize: number;
  private flushIntervalMs: number;

  // Buffering for batch sending
  private sendBuffer: DiagnosticLogEntry[] = [];
  private flushTimer?: ReturnType<typeof setTimeout>;
  private isFlushing = false;

  constructor(options: DiagnosticLoggerOptions) {
    this.diagnosticSessionId = this.generateSessionId();
    this.enabled = options.enabled;
    this.debugLogger = options.debugLogger;
    this.collectLogs = options.collectLogs ?? false;
    this.maxLogs = clampInteger(options.maxLogs ?? DEFAULT_MAX_LOGS, 1, MAX_ALLOWED_LOGS);

    // Server sending options
    this.sendToServer = options.sendToServer ?? false;
    this.serverUrl = options.serverUrl;
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.batchSize = clampInteger(options.batchSize ?? DEFAULT_BATCH_SIZE, 1, MAX_BATCH_SIZE);
    this.flushIntervalMs = options.flushIntervalMs ?? 5000;

    // Validate server sending config
    if (this.sendToServer && (!this.serverUrl || !this.clientId)) {
      if (this.debugLogger) {
        this.debugLogger.log(
          'warn',
          '[DIAGNOSTIC] sendToServer is enabled but serverUrl or clientId is missing. Server sending disabled.'
        );
      }
      this.sendToServer = false;
    }
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
   * Get buffered logs count (for debugging)
   */
  getBufferedLogsCount(): number {
    return this.sendBuffer.length;
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

    // Buffer for server sending
    if (this.sendToServer) {
      this.bufferLog(entry);
    }
  }

  /**
   * Buffer log entry for batch sending
   */
  private bufferLog(entry: DiagnosticLogEntry): void {
    this.sendBuffer.push(entry);

    // Flush if batch size reached
    if (this.sendBuffer.length >= this.batchSize) {
      void this.flush();
    } else {
      // Schedule flush
      this.scheduleFlush();
    }
  }

  /**
   * Schedule automatic flush
   */
  private scheduleFlush(): void {
    // Clear existing timer
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
    }

    // Set new timer
    this.flushTimer = setTimeout(() => {
      void this.flush();
    }, this.flushIntervalMs);
  }

  /**
   * Flush buffered logs to server
   */
  async flush(): Promise<void> {
    // Skip if already flushing or buffer is empty
    if (this.isFlushing || this.sendBuffer.length === 0) {
      return;
    }

    // Clear scheduled flush
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }

    this.isFlushing = true;

    // Take logs from buffer
    const logsToSend = [...this.sendBuffer];
    this.sendBuffer = [];

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), DIAGNOSTIC_SEND_TIMEOUT_MS);
    try {
      const response = await fetch(`${this.serverUrl}/api/v1/diagnostic-logs/ingest`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Diagnostic-Session-Id': this.diagnosticSessionId,
        },
        body: JSON.stringify({
          logs: logsToSend,
          client_id: this.clientId,
          client_secret: this.clientSecret,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        this.handleSendFailure(logsToSend, `HTTP ${response.status}: ${response.statusText}`);
      } else {
        if (this.debugLogger) {
          this.debugLogger.log('debug', `[DIAGNOSTIC] Sent ${logsToSend.length} logs to server`);
        }
      }
    } catch (error) {
      this.handleSendFailure(logsToSend, error instanceof Error ? error.message : String(error));
    } finally {
      clearTimeout(timeoutId);
      this.isFlushing = false;
    }
  }

  /**
   * Handle send failure
   */
  private handleSendFailure(logs: DiagnosticLogEntry[], reason: string): void {
    if (this.debugLogger) {
      this.debugLogger.log('warn', `[DIAGNOSTIC] Failed to send logs to server: ${reason}`);
    }

    // If collectLogs is enabled, keep logs locally
    if (this.collectLogs) {
      for (const log of logs) {
        // Add to local collection if not already there
        if (!this.logs.some((l) => l.id === log.id)) {
          this.logs.push(log);

          // Trim if exceeds max
          if (this.logs.length > this.maxLogs) {
            this.logs.shift();
          }
        }
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

function clampInteger(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) {
    return min;
  }
  return Math.min(max, Math.max(min, Math.trunc(value)));
}

/**
 * Create a diagnostic logger
 *
 * @param options - Logger options
 * @returns DiagnosticLogger instance or null if disabled
 */
export function createDiagnosticLogger(options: DiagnosticLoggerOptions): DiagnosticLogger | null {
  if (!options.enabled) {
    return null;
  }

  return new DiagnosticLogger(options);
}
