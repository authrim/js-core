import { afterEach, describe, expect, it, vi } from 'vitest';
import { DiagnosticLogger } from '../../src/debug/diagnostic-logger.js';

describe('DiagnosticLogger', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('clamps server-send batch size to a bounded maximum', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);

    const logger = new DiagnosticLogger({
      enabled: true,
      sendToServer: true,
      serverUrl: 'https://auth.example.com',
      clientId: 'client_123',
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
    vi.stubGlobal(
      'fetch',
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
        capturedSignal = init?.signal;
        return new Promise<Response>((_resolve, reject) => {
          capturedSignal?.addEventListener('abort', () => {
            const error = new Error('aborted');
            error.name = 'AbortError';
            reject(error);
          });
        });
      })
    );

    const logger = new DiagnosticLogger({
      enabled: true,
      sendToServer: true,
      serverUrl: 'https://auth.example.com',
      clientId: 'client_123',
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
