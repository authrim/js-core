import { afterEach, describe, expect, it, vi } from 'vitest';
import { DiagnosticLogger } from '../../src/debug/diagnostic-logger.js';
import type { HttpClient } from '../../src/providers/http.js';

describe('DiagnosticLogger', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('clamps server-send batch size to a bounded maximum', async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 204,
      statusText: 'No Content',
      headers: {},
      data: undefined,
    }));

    const logger = new DiagnosticLogger({
      enabled: true,
      sendToServer: true,
      serverUrl: 'https://auth.example.com',
      clientId: 'client_123',
      http: { fetch: fetchMock } as unknown as HttpClient,
      batchSize: 100000,
    });

    for (let i = 0; i < 100; i += 1) {
      logger.logAuthDecision({
        decision: 'allow',
        reason: `reason-${i}`,
      });
    }

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
  });

  it('aborts diagnostic send requests after the fixed timeout', async () => {
    vi.useFakeTimers();
    let capturedSignal: AbortSignal | undefined;
    const fetchMock = vi.fn((_input: string, init?: { signal?: AbortSignal }) => {
      capturedSignal = init?.signal;
      return new Promise((_resolve, reject) => {
        capturedSignal?.addEventListener('abort', () => {
          const error = new Error('aborted');
          error.name = 'AbortError';
          reject(error);
        });
      });
    });

    const logger = new DiagnosticLogger({
      enabled: true,
      sendToServer: true,
      serverUrl: 'https://auth.example.com',
      clientId: 'client_123',
      http: { fetch: fetchMock } as unknown as HttpClient,
      batchSize: 1,
    });

    logger.logAuthDecision({
      decision: 'allow',
      reason: 'test',
    });

    await vi.advanceTimersByTimeAsync(10000);

    expect(capturedSignal?.aborted).toBe(true);
  });
});
