/**
 * Auto Refresh Scheduler
 *
 * Automatically refreshes tokens before they expire.
 * Supports cancellation via AbortController.
 */

import type { TokenManager } from './manager.js';
import type { EventEmitter } from '../events/emitter.js';

/**
 * Auto refresh options
 */
export interface AutoRefreshOptions {
  /** Refresh threshold in seconds before expiry (default: 60) */
  thresholdSeconds?: number;
  /** Check interval in milliseconds (default: 30000 = 30 seconds) */
  checkIntervalMs?: number;
  /** Event emitter for logging/debugging */
  eventEmitter?: EventEmitter;
}

/**
 * Auto Refresh Scheduler
 *
 * Schedules automatic token refresh before expiration.
 * Can be stopped and started as needed.
 */
export class AutoRefreshScheduler {
  private tokenManager: TokenManager | null = null;
  private options: Required<Omit<AutoRefreshOptions, 'eventEmitter'>> & { eventEmitter?: EventEmitter };
  private checkInterval: ReturnType<typeof setInterval> | null = null;
  private abortController: AbortController | null = null;
  private isRunning = false;

  /** Default refresh threshold: 60 seconds */
  private static readonly DEFAULT_THRESHOLD_SECONDS = 60;

  /** Default check interval: 30 seconds */
  private static readonly DEFAULT_CHECK_INTERVAL_MS = 30000;

  constructor(options?: AutoRefreshOptions) {
    this.options = {
      thresholdSeconds: options?.thresholdSeconds ?? AutoRefreshScheduler.DEFAULT_THRESHOLD_SECONDS,
      checkIntervalMs: options?.checkIntervalMs ?? AutoRefreshScheduler.DEFAULT_CHECK_INTERVAL_MS,
      eventEmitter: options?.eventEmitter,
    };
  }

  /**
   * Start auto-refresh scheduling
   *
   * @param tokenManager - Token manager instance
   */
  start(tokenManager: TokenManager): void {
    if (this.isRunning) {
      return;
    }

    this.tokenManager = tokenManager;
    this.abortController = new AbortController();
    this.isRunning = true;

    // Start periodic check
    this.checkInterval = setInterval(() => {
      this.checkAndRefresh().catch(() => {
        // Errors are handled within checkAndRefresh
      });
    }, this.options.checkIntervalMs);

    // Initial check
    this.checkAndRefresh().catch(() => {
      // Errors are handled within checkAndRefresh
    });
  }

  /**
   * Stop auto-refresh scheduling
   */
  stop(): void {
    if (!this.isRunning) {
      return;
    }

    this.isRunning = false;

    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }

    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }

    this.tokenManager = null;
  }

  /**
   * Check if scheduler is running
   */
  get running(): boolean {
    return this.isRunning;
  }

  /**
   * Get the abort signal for external cancellation support
   */
  get signal(): AbortSignal | null {
    return this.abortController?.signal ?? null;
  }

  /**
   * Check if token needs refresh and perform if needed
   */
  private async checkAndRefresh(): Promise<void> {
    if (!this.tokenManager || !this.isRunning) {
      return;
    }

    try {
      const tokens = await this.tokenManager.getTokens();
      if (!tokens) {
        return;
      }

      const now = Math.floor(Date.now() / 1000);
      const expiresIn = tokens.expiresAt - now;

      // Check if token is within threshold
      if (expiresIn <= this.options.thresholdSeconds && tokens.refreshToken) {
        // Perform background refresh
        await this.tokenManager.refresh();
      }
    } catch (error) {
      // Log error but don't stop the scheduler
      // The tokenManager will emit appropriate events
    }
  }

  /**
   * Force an immediate refresh check
   */
  async forceCheck(): Promise<void> {
    await this.checkAndRefresh();
  }
}
