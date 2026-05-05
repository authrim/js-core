import { describe, expect, it } from 'vitest';
import {
  AuthrimError,
  assertValidStepUpReceipt,
  createDelegatedWriteEnvelope,
  normalizeDelegatedWriteAudit,
  withStepUpReceiptHeader,
} from '../../src/index.js';

describe('delegated write helpers', () => {
  it('creates the canonical input/audit envelope', () => {
    const envelope = createDelegatedWriteEnvelope(
      { display_name: 'Yuta' },
      {
        audit: {
          reason_code: ' admin_repair ',
          reason_note: ' approved by on-call\nwith ticket ',
          reference_id: ' CASE-123 ',
        },
      }
    );

    expect(envelope).toEqual({
      input: {
        display_name: 'Yuta',
      },
      audit: {
        reason_code: 'admin_repair',
        reason_note: 'approved by on-call\nwith ticket',
        reference_id: 'CASE-123',
      },
    });
  });

  it('rejects unknown audit fields', () => {
    expect(() =>
      normalizeDelegatedWriteAudit({
        reason_code: 'repair',
        ticket_id: 'CASE-123',
      } as unknown as Parameters<typeof normalizeDelegatedWriteAudit>[0])
    ).toThrow(AuthrimError);
  });

  it('rejects empty audit after normalization', () => {
    expect(() =>
      createDelegatedWriteEnvelope(
        {},
        {
          audit: {
            reason_note: '   ',
          },
        }
      )
    ).toThrow(AuthrimError);
  });

  it('attaches the step-up receipt header', () => {
    const headers = withStepUpReceiptHeader(
      {
        Authorization: 'Bearer token',
      },
      ' receipt-001 '
    );

    expect(headers.Authorization).toBe('Bearer token');
    expect(headers['Authrim-Step-Up-Receipt']).toBe('receipt-001');
  });

  it('rejects invalid step-up receipt header values', () => {
    expect(() => assertValidStepUpReceipt('   ')).toThrow(AuthrimError);
    expect(() => assertValidStepUpReceipt(`receipt\nbad`)).toThrow(AuthrimError);
  });
});
