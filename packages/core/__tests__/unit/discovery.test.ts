/**
 * Discovery Tests
 *
 * Tests for acceptance criteria:
 * #3: Discovery issuer mismatch must fail
 * #8: Issuer normalization works
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { DiscoveryClient, normalizeIssuer } from '../../src/client/discovery.js';
import { createMockHttp, createMockDiscoveryDocument } from '../mocks/http.js';

describe('Discovery Client', () => {
  const issuer = 'https://auth.example.com';

  let http: ReturnType<typeof createMockHttp>;
  let discovery: DiscoveryClient;

  beforeEach(() => {
    http = createMockHttp();
    discovery = new DiscoveryClient({ http, cacheTtlMs: 3600 * 1000 });
  });

  describe('Issuer Mismatch - Acceptance Criteria #3', () => {
    it('should reject when discovery document issuer does not match', async () => {
      // Discovery document returns different issuer
      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockDiscoveryDocument('https://malicious-issuer.com'),
      }));

      await expect(discovery.discover(issuer)).rejects.toMatchObject({
        code: 'discovery_mismatch',
      });
    });

    it('should accept when discovery document issuer matches', async () => {
      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockDiscoveryDocument(issuer),
      }));

      const doc = await discovery.discover(issuer);
      expect(doc.issuer).toBe(issuer);
    });

    it('should handle discovery fetch errors', async () => {
      http.setHandler(() => ({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        data: {},
      }));

      await expect(discovery.discover(issuer)).rejects.toMatchObject({ code: 'discovery_error' });
    });
  });

  describe('Issuer Normalization - Acceptance Criteria #8', () => {
    it('should normalize issuer by removing trailing slash', () => {
      expect(normalizeIssuer('https://auth.example.com/')).toBe('https://auth.example.com');
      expect(normalizeIssuer('https://auth.example.com//')).toBe('https://auth.example.com');
    });

    it('should not modify issuer without trailing slash', () => {
      expect(normalizeIssuer('https://auth.example.com')).toBe('https://auth.example.com');
    });

    it('should treat issuers with and without trailing slash as same', async () => {
      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockDiscoveryDocument(issuer),
      }));

      // Fetch with trailing slash
      const doc1 = await discovery.discover('https://auth.example.com/');
      // Fetch without trailing slash (should use cache)
      const doc2 = await discovery.discover('https://auth.example.com');

      expect(doc1).toBe(doc2);
      expect(http.calls.length).toBe(1); // Only one fetch
    });
  });

  describe('Caching', () => {
    it('should cache discovery document within TTL', async () => {
      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockDiscoveryDocument(issuer),
      }));

      await discovery.discover(issuer);
      await discovery.discover(issuer);

      expect(http.calls.length).toBe(1);
    });

    it('should refetch after TTL expires', async () => {
      vi.useFakeTimers();

      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockDiscoveryDocument(issuer),
      }));

      await discovery.discover(issuer);
      expect(http.calls.length).toBe(1);

      // Advance time past TTL
      vi.advanceTimersByTime(3601 * 1000);

      await discovery.discover(issuer);
      expect(http.calls.length).toBe(2);

      vi.useRealTimers();
    });

    it('should clear cache', async () => {
      http.setHandler(() => ({
        ok: true,
        status: 200,
        data: createMockDiscoveryDocument(issuer),
      }));

      await discovery.discover(issuer);
      discovery.clearCache();
      await discovery.discover(issuer);

      expect(http.calls.length).toBe(2);
    });
  });
});
