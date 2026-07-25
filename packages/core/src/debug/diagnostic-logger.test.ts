import { afterEach, describe, expect, it, vi } from 'vitest';
import { DiagnosticLogger } from './diagnostic-logger.js';
import type { HttpClient } from '../providers/http.js';

describe('DiagnosticLogger server sending', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('does not send diagnostic logs to non-HTTPS URLs', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    const logger = new DiagnosticLogger({
      enabled: true,
      sendToServer: true,
      serverUrl: 'http://attacker.example',
      clientId: 'client-1',
      http: { fetch } as unknown as HttpClient,
    });

    logger.logAuthDecision({ decision: 'allow', reason: 'test' });
    await logger.flush();

    expect(fetch).not.toHaveBeenCalled();
  });

  it('does not include client secrets in diagnostic uploads', async () => {
    const fetch = vi.fn(async (_input: string, _init?: { body?: string }) => ({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: {},
      data: undefined,
    }));
    const logger = new DiagnosticLogger({
      enabled: true,
      sendToServer: true,
      serverUrl: 'https://auth.example',
      clientId: 'client-1',
      clientSecret: 'secret-value',
      http: { fetch } as unknown as HttpClient,
    });

    logger.logAuthDecision({ decision: 'allow', reason: 'test' });
    await logger.flush();

    const request = fetch.mock.calls[0]?.[1] as { body?: string } | undefined;
    expect(request).toBeDefined();
    const body = JSON.parse(request?.body as string) as Record<string, unknown>;
    expect(body).toMatchObject({ client_id: 'client-1' });
    expect(body).not.toHaveProperty('client_secret');
  });
});
