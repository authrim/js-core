import { describe, expect, it } from 'vitest';
import {
  AuthrimError,
  DEFAULT_STEP_UP_POLICY,
  StepUpClient,
  type StepUpActionResponse,
} from '../../src/index.js';
import { createMockHttp } from '../mocks/http.js';

describe('StepUpClient', () => {
  it('starts a canonical step-up action', async () => {
    const http = createMockHttp();
    const client = new StepUpClient({
      issuer: 'https://auth.example.com/',
      http,
    });
    const responseBody: StepUpActionResponse = {
      action_id: 'sua_1',
      status: {
        action_id: 'sua_1',
        status: 'pending',
        method: 'portal_confirm',
        category: 'confirmation',
      },
      next_action: {
        type: 'confirmation',
        method: 'portal_confirm',
        category: 'confirmation',
        action_id: 'sua_1',
        expires_at: '2026-05-05T12:10:00.000Z',
        payload: { confirm_required: true },
      },
    };
    http.setHandler(() => ({
      ok: true,
      status: 200,
      data: responseBody,
    }));

    const result = await client.start({
      step_up_token: 'stu_123',
      preferred_method: { method: 'portal_confirm' },
    });

    expect(result).toBe(responseBody);
    expect(http.calls[0].url).toBe('https://auth.example.com/auth/step-up/start');
    expect(http.calls[0].options?.method).toBe('POST');
    expect(JSON.parse(http.calls[0].options?.body as string)).toMatchObject({
      step_up_token: 'stu_123',
      preferred_method: { method: 'portal_confirm' },
    });
  });

  it('attaches Idempotency-Key on complete and preserves receipt response', async () => {
    const http = createMockHttp();
    const client = new StepUpClient({
      issuer: 'https://auth.example.com',
      http,
    });
    http.setHandler(() => ({
      ok: true,
      status: 200,
      data: {
        action_id: 'sua_1',
        status: { action_id: 'sua_1', status: 'completed' },
        step_up_receipt: 'sur_1',
        step_up_receipt_expires_at: '2026-05-05T12:15:00.000Z',
        step_up_receipt_expires_at_unix: 1777983300,
      },
    }));

    const result = await client.complete(
      'sua_1',
      {
        method: 'portal_confirm',
        input: { confirmed: true },
      },
      { idempotencyKey: 'complete-key-001' }
    );

    expect(result.step_up_receipt).toBe('sur_1');
    expect(http.calls[0].url).toBe('https://auth.example.com/auth/step-up/actions/sua_1/complete');
    expect(http.calls[0].options?.headers).toMatchObject({
      'Content-Type': 'application/json',
      'Idempotency-Key': 'complete-key-001',
    });
  });

  it('attaches Idempotency-Key on resend', async () => {
    const http = createMockHttp();
    const client = new StepUpClient({
      issuer: 'https://auth.example.com',
      http,
    });
    http.setHandler(() => ({
      ok: true,
      status: 200,
      data: {
        action_id: 'sua_1',
        status: { action_id: 'sua_1', status: 'pending' },
        next_action: {
          type: 'otp',
          method: 'email_otp',
          category: 'otp',
          action_id: 'sua_1',
          expires_at: '2026-05-05T12:10:00.000Z',
          payload: { delivery: 'out_of_band' },
        },
      },
    }));

    await client.resend('sua_1', { idempotencyKey: 'resend-key-001' });

    expect(http.calls[0].url).toBe('https://auth.example.com/auth/step-up/actions/sua_1/resend');
    expect(http.calls[0].options?.headers).toMatchObject({
      'Idempotency-Key': 'resend-key-001',
    });
  });

  it('maps machine-readable step-up errors to AuthrimError details', async () => {
    const http = createMockHttp();
    const client = new StepUpClient({
      issuer: 'https://auth.example.com',
      http,
    });
    http.setHandler(() => ({
      ok: false,
      status: 403,
      data: {
        error: 'preferred_method_unavailable',
        error_description: 'Preferred step-up method is unavailable',
        error_details: {
          code: 'preferred_method_unavailable',
          retryable: true,
          severity: 'warning',
        },
        step_up: {
          step_up_token: 'stu_123',
          expires_at: '2026-05-05T12:05:00.000Z',
          expires_at_unix: 1777982700,
          acceptable_methods: { methods: ['portal_confirm'] },
        },
      },
    }));

    await expect(
      client.start({
        step_up_token: 'stu_123',
        preferred_method: { method: 'email_otp' },
      })
    ).rejects.toMatchObject({
      code: 'preferred_method_unavailable',
      details: {
        originalError: 'preferred_method_unavailable',
        errorDetails: {
          code: 'preferred_method_unavailable',
          retryable: true,
        },
      },
    });
  });

  it('exports documented default policy values', () => {
    expect(DEFAULT_STEP_UP_POLICY).toMatchObject({
      stepUpTokenTtlSeconds: 300,
      stepUpActionTtlSeconds: 600,
      stepUpReceiptTtlSeconds: 300,
      stepUpAttemptLimit: 5,
      stepUpResendCooldownSeconds: 60,
      stepUpMaxResends: 3,
    });
  });

  it('raises AuthrimError when Idempotency-Key generation is explicitly disabled', async () => {
    const client = new StepUpClient({
      issuer: 'https://auth.example.com',
      http: createMockHttp(),
    });

    await expect(
      client.complete(
        'sua_1',
        {
          method: 'portal_confirm',
          input: { confirmed: true },
        },
        { idempotencyKey: { generate: false } }
      )
    ).rejects.toBeInstanceOf(AuthrimError);
  });
});
