import { describe, expect, it } from 'vitest';
import {
  AuthrimError,
  assertValidIdempotencyKey,
  createIdempotencyKey,
  resolveIdempotencyKey,
  withIdempotencyKeyHeader,
} from '../../src/index.js';

describe('Idempotency-Key helpers', () => {
  it('generates valid keys for required idempotent requests', () => {
    const key = createIdempotencyKey();

    expect(key.length).toBeGreaterThanOrEqual(8);
    expect(key.length).toBeLessThanOrEqual(128);
    expect(assertValidIdempotencyKey(key)).toBe(key);
  });

  it('preserves explicit keys after validation', () => {
    expect(resolveIdempotencyKey(' explicit-key-001 ')).toBe('explicit-key-001');
    expect(resolveIdempotencyKey({ idempotencyKey: 'explicit-key-002' })).toBe(
      'explicit-key-002'
    );
  });

  it('throws an AuthrimError when explicit generation is disabled without a key', () => {
    expect(() => resolveIdempotencyKey({ generate: false })).toThrow(AuthrimError);
  });

  it('rejects invalid header values', () => {
    expect(() => assertValidIdempotencyKey('short')).toThrow(AuthrimError);
    expect(() => assertValidIdempotencyKey(`valid-key\nbad`)).toThrow(AuthrimError);
  });

  it('attaches the Idempotency-Key header without dropping existing headers', () => {
    const headers = withIdempotencyKeyHeader(
      {
        Authorization: 'Bearer token',
      },
      'explicit-key-003'
    );

    expect(headers.Authorization).toBe('Bearer token');
    expect(headers['Idempotency-Key']).toBe('explicit-key-003');
  });
});
