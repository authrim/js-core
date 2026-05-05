import { AuthrimError } from '../types/errors.js';

export interface DelegatedWriteAudit {
  reason_code?: string;
  reason_note?: string;
  reference_id?: string;
}

export interface DelegatedWriteEnvelope<Input = unknown> {
  input: Input;
  audit?: DelegatedWriteAudit;
}

export interface DelegatedWriteEnvelopeOptions {
  audit?: DelegatedWriteAudit | null;
}

const ALLOWED_AUDIT_FIELDS = new Set(['reason_code', 'reason_note', 'reference_id']);
const MAX_REASON_NOTE_LENGTH = 1024;

function normalizeOptionalString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const normalized = value.trim();
  return normalized.length > 0 ? normalized : undefined;
}

function normalizeReasonNote(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const normalized = value.trim();
  if (normalized.length === 0) {
    return undefined;
  }
  if (Array.from(normalized).length > MAX_REASON_NOTE_LENGTH) {
    throw new AuthrimError('invalid_request', 'audit.reason_note must be at most 1024 characters');
  }
  return normalized;
}

export function normalizeDelegatedWriteAudit(audit: DelegatedWriteAudit): DelegatedWriteAudit {
  for (const field of Object.keys(audit)) {
    if (!ALLOWED_AUDIT_FIELDS.has(field)) {
      throw new AuthrimError('unknown_audit_field', `Unknown audit field: ${field}`, {
        details: {
          field: `audit.${field}`,
        },
      });
    }
  }

  const reasonCode = normalizeOptionalString(audit.reason_code);
  const reasonNote = normalizeReasonNote(audit.reason_note);
  const referenceId = normalizeOptionalString(audit.reference_id);
  const normalized: DelegatedWriteAudit = {
    ...(reasonCode ? { reason_code: reasonCode } : {}),
    ...(reasonNote ? { reason_note: reasonNote } : {}),
    ...(referenceId ? { reference_id: referenceId } : {}),
  };

  if (Object.keys(normalized).length === 0) {
    throw new AuthrimError('invalid_request', 'audit must include at least one supported field');
  }

  return normalized;
}

export function createDelegatedWriteEnvelope<Input>(
  input: Input,
  options?: DelegatedWriteEnvelopeOptions
): DelegatedWriteEnvelope<Input> {
  const envelope: DelegatedWriteEnvelope<Input> = { input };

  if (options?.audit) {
    envelope.audit = normalizeDelegatedWriteAudit(options.audit);
  }

  return envelope;
}

export function assertValidStepUpReceipt(stepUpReceipt: string): string {
  const normalized = stepUpReceipt.trim();
  if (normalized.length === 0) {
    throw new AuthrimError('invalid_request', 'Authrim-Step-Up-Receipt is required');
  }
  if (/[\r\n\0]/.test(normalized)) {
    throw new AuthrimError(
      'invalid_request',
      'Authrim-Step-Up-Receipt contains invalid characters'
    );
  }
  return normalized;
}

export function withStepUpReceiptHeader(
  headers: Record<string, string> | undefined,
  stepUpReceipt: string
): Record<string, string> {
  return {
    ...(headers ?? {}),
    'Authrim-Step-Up-Receipt': assertValidStepUpReceipt(stepUpReceipt),
  };
}
