import { AuthrimError } from '../types/errors.js';

export interface IdempotencyKeyOptions {
  idempotencyKey?: string | null;
  generate?: boolean;
}

export type IdempotencyKeyInput = string | IdempotencyKeyOptions | null | undefined;

export function assertValidIdempotencyKey(idempotencyKey: string): string {
  const normalized = idempotencyKey.trim();

  if (normalized.length < 8 || normalized.length > 128) {
    throw new AuthrimError(
      'invalid_request',
      'Idempotency-Key must be between 8 and 128 characters'
    );
  }

  if (/[\r\n\0]/.test(normalized)) {
    throw new AuthrimError('invalid_request', 'Idempotency-Key contains invalid characters');
  }

  return normalized;
}

function createRandomHex(bytesLength: number): string {
  const cryptoProvider = globalThis.crypto;
  if (!cryptoProvider?.getRandomValues) {
    throw new AuthrimError('configuration_error', 'Secure random generation is unavailable');
  }

  const bytes = new Uint8Array(bytesLength);
  cryptoProvider.getRandomValues(bytes);
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export function createIdempotencyKey(): string {
  const cryptoProvider = globalThis.crypto;
  if (cryptoProvider && 'randomUUID' in cryptoProvider && typeof cryptoProvider.randomUUID === 'function') {
    return cryptoProvider.randomUUID();
  }

  return createRandomHex(16);
}

export function resolveIdempotencyKey(input?: IdempotencyKeyInput): string {
  if (typeof input === 'string') {
    return assertValidIdempotencyKey(input);
  }

  if (input?.idempotencyKey) {
    return assertValidIdempotencyKey(input.idempotencyKey);
  }

  if (input?.generate === false) {
    throw new AuthrimError('invalid_request', 'Idempotency-Key is required');
  }

  return createIdempotencyKey();
}

export function withIdempotencyKeyHeader(
  headers: Record<string, string> | undefined,
  input?: IdempotencyKeyInput
): Record<string, string> {
  return {
    ...(headers ?? {}),
    'Idempotency-Key': resolveIdempotencyKey(input),
  };
}
