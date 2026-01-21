/**
 * Retry Utilities
 *
 * Provides exponential backoff retry logic with jitter.
 */

import { AuthrimError, isRetryableError } from '../types/errors.js';
import { isCancellationError } from './cancellation.js';

/**
 * Retry options
 */
export interface RetryOptions {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number;
  /** Base delay in milliseconds (default: 1000) */
  baseDelayMs?: number;
  /** Maximum delay in milliseconds (default: 30000) */
  maxDelayMs?: number;
  /** Enable jitter for delay randomization (default: true) */
  jitter?: boolean;
  /** AbortSignal for cancellation */
  signal?: AbortSignal;
  /** Custom retry condition (default: check isRetryableError) */
  shouldRetry?: (error: unknown, attempt: number) => boolean;
  /** Callback for each retry attempt */
  onRetry?: (error: unknown, attempt: number, delayMs: number) => void;
}

/**
 * Default retry options
 */
const DEFAULT_RETRY_OPTIONS: Required<Omit<RetryOptions, 'signal' | 'shouldRetry' | 'onRetry'>> = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
  jitter: true,
};

/**
 * Calculate delay with exponential backoff and optional jitter
 *
 * @param attempt - Current attempt number (0-indexed)
 * @param baseDelayMs - Base delay in milliseconds
 * @param maxDelayMs - Maximum delay in milliseconds
 * @param jitter - Whether to add jitter
 * @returns Delay in milliseconds
 */
export function calculateBackoffDelay(
  attempt: number,
  baseDelayMs: number,
  maxDelayMs: number,
  jitter: boolean
): number {
  // Exponential backoff: baseDelay * 2^attempt
  const exponentialDelay = baseDelayMs * Math.pow(2, attempt);

  // Cap at max delay
  const cappedDelay = Math.min(exponentialDelay, maxDelayMs);

  // Add jitter if enabled (±25% of delay)
  if (jitter) {
    const jitterRange = cappedDelay * 0.5; // ±25%
    const jitterValue = Math.random() * jitterRange - jitterRange / 2;
    return Math.max(0, Math.floor(cappedDelay + jitterValue));
  }

  return cappedDelay;
}

/**
 * Sleep for a specified duration
 *
 * @param ms - Duration in milliseconds
 * @param signal - Optional AbortSignal for cancellation
 */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new AuthrimError('operation_cancelled', 'Sleep was cancelled'));
      return;
    }

    const timeout = setTimeout(resolve, ms);

    if (signal) {
      const onAbort = () => {
        clearTimeout(timeout);
        reject(new AuthrimError('operation_cancelled', 'Sleep was cancelled'));
      };
      signal.addEventListener('abort', onAbort, { once: true });
    }
  });
}

/**
 * Execute a function with exponential backoff retry
 *
 * @param fn - Function to execute
 * @param options - Retry options
 * @returns Result of the function
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options?: RetryOptions
): Promise<T> {
  const opts = { ...DEFAULT_RETRY_OPTIONS, ...options };
  const { maxRetries, baseDelayMs, maxDelayMs, jitter, signal, shouldRetry, onRetry } = opts;

  let lastError: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      // Check for cancellation before each attempt
      if (signal?.aborted) {
        throw new AuthrimError('operation_cancelled', 'Operation was cancelled');
      }

      return await fn();
    } catch (error) {
      lastError = error;

      // Don't retry cancellation errors
      if (isCancellationError(error)) {
        throw error;
      }

      // Check if we should retry
      const canRetry = shouldRetry
        ? shouldRetry(error, attempt)
        : error instanceof AuthrimError && isRetryableError(error);

      // Don't retry if max attempts reached or error is not retryable
      if (attempt >= maxRetries || !canRetry) {
        throw error;
      }

      // Calculate delay
      const delayMs = calculateBackoffDelay(attempt, baseDelayMs, maxDelayMs, jitter);

      // Notify retry callback
      onRetry?.(error, attempt + 1, delayMs);

      // Wait before retry
      await sleep(delayMs, signal);
    }
  }

  // This should not be reached, but just in case
  throw lastError;
}

/**
 * Create a retry function with preset options
 *
 * Useful for creating specialized retry functions for specific use cases.
 *
 * @param defaultOptions - Default options for all retries
 * @returns Retry function with preset options
 */
export function createRetryFunction(
  defaultOptions: RetryOptions
): <T>(fn: () => Promise<T>, options?: RetryOptions) => Promise<T> {
  return <T>(fn: () => Promise<T>, options?: RetryOptions): Promise<T> => {
    return withRetry(fn, { ...defaultOptions, ...options });
  };
}

/**
 * Extract Retry-After header value
 *
 * Supports both HTTP-date and delay-seconds formats.
 *
 * @param headers - Response headers
 * @returns Delay in milliseconds, or null if not found
 */
export function parseRetryAfterHeader(
  headers: Headers | Record<string, string>
): number | null {
  const retryAfter = headers instanceof Headers
    ? headers.get('retry-after')
    : headers['retry-after'] ?? headers['Retry-After'];

  if (!retryAfter) {
    return null;
  }

  // Try parsing as seconds (most common)
  const seconds = parseInt(retryAfter, 10);
  if (!isNaN(seconds)) {
    return seconds * 1000;
  }

  // Try parsing as HTTP-date
  const date = new Date(retryAfter);
  if (!isNaN(date.getTime())) {
    const delayMs = date.getTime() - Date.now();
    return Math.max(0, delayMs);
  }

  return null;
}
