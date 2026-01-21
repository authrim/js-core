/**
 * Cancellation Utilities
 *
 * Provides AbortController-based cancellation for async operations.
 */

import { AuthrimError } from '../types/errors.js';

/**
 * Wrap a promise with AbortSignal support
 *
 * If the signal is aborted, the promise will reject with an
 * 'operation_cancelled' error which is recoverable and retryable.
 *
 * @param promise - Promise to wrap
 * @param signal - AbortSignal to use for cancellation
 * @returns Promise that can be cancelled
 */
export function withAbortSignal<T>(
  promise: Promise<T>,
  signal: AbortSignal
): Promise<T> {
  return new Promise((resolve, reject) => {
    const cancelledError = new AuthrimError(
      'operation_cancelled',
      'Operation was cancelled'
    );

    // Already aborted
    if (signal.aborted) {
      reject(cancelledError);
      return;
    }

    const onAbort = () => {
      reject(cancelledError);
    };

    signal.addEventListener('abort', onAbort, { once: true });

    promise
      .then(resolve)
      .catch(reject)
      .finally(() => {
        signal.removeEventListener('abort', onAbort);
      });
  });
}

/**
 * Create a cancellable operation wrapper
 *
 * Returns an object with the promise and a cancel function.
 * Useful for creating operations that can be externally cancelled.
 *
 * @param fn - Async function to execute
 * @returns Object with promise and cancel function
 */
export function createCancellableOperation<T>(
  fn: (signal: AbortSignal) => Promise<T>
): {
  promise: Promise<T>;
  cancel: () => void;
  signal: AbortSignal;
} {
  const controller = new AbortController();

  return {
    promise: fn(controller.signal),
    cancel: () => controller.abort(),
    signal: controller.signal,
  };
}

/**
 * Check if an error is a cancellation error
 */
export function isCancellationError(error: unknown): boolean {
  return error instanceof AuthrimError && error.code === 'operation_cancelled';
}

/**
 * Race multiple promises with cancellation support
 *
 * When one promise resolves, other operations are cancelled.
 *
 * @param operations - Array of operations with their signals
 * @returns Result of the first successful operation
 */
export async function raceWithCancellation<T>(
  operations: Array<{
    promise: Promise<T>;
    cancel: () => void;
  }>
): Promise<T> {
  try {
    const result = await Promise.race(operations.map((op) => op.promise));
    // Cancel all other operations
    operations.forEach((op) => op.cancel());
    return result;
  } catch (error) {
    // Cancel all operations on error
    operations.forEach((op) => op.cancel());
    throw error;
  }
}
