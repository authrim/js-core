/**
 * Event Emitter
 *
 * Simple typed event emitter for SDK events.
 */

import type { AuthrimEvents, AuthrimEventName, AuthrimEventHandler } from './types.js';
import { AuthrimError } from '../types/errors.js';

/**
 * Typed Event Emitter
 */
export class EventEmitter {
  private listeners: Map<AuthrimEventName, Set<AuthrimEventHandler<AuthrimEventName>>> = new Map();

  /**
   * Subscribe to an event
   *
   * @param event - Event name
   * @param handler - Event handler
   * @returns Unsubscribe function
   */
  on<T extends AuthrimEventName>(event: T, handler: AuthrimEventHandler<T>): () => void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(handler as AuthrimEventHandler<AuthrimEventName>);

    // Return unsubscribe function
    return () => {
      this.off(event, handler);
    };
  }

  /**
   * Subscribe to an event (one-time)
   *
   * @param event - Event name
   * @param handler - Event handler
   * @returns Unsubscribe function
   */
  once<T extends AuthrimEventName>(event: T, handler: AuthrimEventHandler<T>): () => void {
    const onceHandler = ((data: AuthrimEvents[T]) => {
      this.off(event, onceHandler);
      handler(data);
    }) as AuthrimEventHandler<T>;

    return this.on(event, onceHandler);
  }

  /**
   * Unsubscribe from an event
   *
   * @param event - Event name
   * @param handler - Event handler to remove
   */
  off<T extends AuthrimEventName>(event: T, handler: AuthrimEventHandler<T>): void {
    const handlers = this.listeners.get(event);
    if (handlers) {
      handlers.delete(handler as AuthrimEventHandler<AuthrimEventName>);
      if (handlers.size === 0) {
        this.listeners.delete(event);
      }
    }
  }

  /**
   * Emit an event
   *
   * @param event - Event name
   * @param data - Event data
   */
  emit<T extends AuthrimEventName>(event: T, data: AuthrimEvents[T]): void {
    const handlers = this.listeners.get(event);
    if (handlers) {
      for (const handler of handlers) {
        try {
          handler(data);
        } catch (error) {
          // Don't throw - one handler failure shouldn't affect others
          // For non-error events, emit an 'error' event
          // For 'error' events, silently ignore to prevent infinite recursion
          if (event !== 'error') {
            const authrimError =
              error instanceof AuthrimError
                ? error
                : new AuthrimError('event_handler_error', 'Event handler threw an error', {
                    cause: error instanceof Error ? error : undefined,
                  });
            this.emit('error', {
              error: authrimError,
              context: `Error in event handler for '${event}'`,
            });
          }
          // For 'error' event handlers that throw, we silently ignore
          // to maintain platform-agnostic behavior (no console dependency)
        }
      }
    }
  }

  /**
   * Remove all listeners for an event (or all events)
   *
   * @param event - Event name (optional, removes all if not specified)
   */
  removeAllListeners(event?: AuthrimEventName): void {
    if (event) {
      this.listeners.delete(event);
    } else {
      this.listeners.clear();
    }
  }

  /**
   * Get the number of listeners for an event
   *
   * @param event - Event name
   * @returns Number of listeners
   */
  listenerCount(event: AuthrimEventName): number {
    return this.listeners.get(event)?.size ?? 0;
  }
}
