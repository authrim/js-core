/**
 * Debug Module
 *
 * Provides debugging and observability features for the SDK.
 */

export { EventTimeline } from './timeline.js';
export {
  createConsoleLogger,
  createDebugLogger,
  noopLogger,
  DebugContext,
} from './logger.js';
export type {
  DebugOptions,
  DebugLogger,
  DebugLogLevel,
  RedactLevel,
} from './types.js';

// Diagnostic Logger (for debugging and OIDF conformance testing)
export {
  DiagnosticLogger,
  createDiagnosticLogger,
} from './diagnostic-logger.js';
export type {
  IDiagnosticLogger,
  DiagnosticLogLevel,
  TokenValidationStep,
  BaseDiagnosticLogEntry,
  TokenValidationLogEntry,
  AuthDecisionLogEntry,
  DiagnosticLogEntry,
  DiagnosticLoggerOptions,
} from './diagnostic-logger.js';
