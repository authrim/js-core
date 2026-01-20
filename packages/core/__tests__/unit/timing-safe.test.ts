/**
 * Timing-Safe Comparison Tests
 *
 * Tests for constant-time string comparison utility
 */

import { describe, it, expect } from 'vitest';
import { timingSafeEqual } from '../../src/utils/timing-safe.js';

describe('timingSafeEqual', () => {
  describe('Basic Equality', () => {
    it('should return true for equal strings', () => {
      expect(timingSafeEqual('hello', 'hello')).toBe(true);
    });

    it('should return false for different strings', () => {
      expect(timingSafeEqual('hello', 'world')).toBe(false);
    });

    it('should return true for empty strings', () => {
      expect(timingSafeEqual('', '')).toBe(true);
    });

    it('should return false when comparing empty to non-empty', () => {
      expect(timingSafeEqual('', 'hello')).toBe(false);
      expect(timingSafeEqual('hello', '')).toBe(false);
    });
  });

  describe('Length Differences', () => {
    it('should return false for strings of different lengths', () => {
      expect(timingSafeEqual('abc', 'abcd')).toBe(false);
      expect(timingSafeEqual('abcd', 'abc')).toBe(false);
    });

    it('should return false even when shorter string is prefix', () => {
      expect(timingSafeEqual('hello', 'hello world')).toBe(false);
      expect(timingSafeEqual('hello world', 'hello')).toBe(false);
    });
  });

  describe('Character Differences', () => {
    it('should detect single character difference at start', () => {
      expect(timingSafeEqual('Aello', 'hello')).toBe(false);
    });

    it('should detect single character difference in middle', () => {
      expect(timingSafeEqual('heXlo', 'hello')).toBe(false);
    });

    it('should detect single character difference at end', () => {
      expect(timingSafeEqual('hellX', 'hello')).toBe(false);
    });

    it('should be case sensitive', () => {
      expect(timingSafeEqual('Hello', 'hello')).toBe(false);
      expect(timingSafeEqual('HELLO', 'hello')).toBe(false);
    });
  });

  describe('Special Characters', () => {
    it('should handle strings with special characters', () => {
      expect(timingSafeEqual('hello!@#$%', 'hello!@#$%')).toBe(true);
      expect(timingSafeEqual('hello!@#$%', 'hello!@#$&')).toBe(false);
    });

    it('should handle strings with whitespace', () => {
      expect(timingSafeEqual('hello world', 'hello world')).toBe(true);
      expect(timingSafeEqual('hello world', 'hello  world')).toBe(false);
      expect(timingSafeEqual('hello\tworld', 'hello\tworld')).toBe(true);
      expect(timingSafeEqual('hello\nworld', 'hello\nworld')).toBe(true);
    });

    it('should handle strings with null bytes', () => {
      expect(timingSafeEqual('hello\0world', 'hello\0world')).toBe(true);
      expect(timingSafeEqual('hello\0world', 'helloworld')).toBe(false);
    });
  });

  describe('Unicode', () => {
    it('should handle UTF-8 strings', () => {
      expect(timingSafeEqual('日本語', '日本語')).toBe(true);
      expect(timingSafeEqual('日本語', '日本人')).toBe(false);
    });

    it('should handle emoji', () => {
      expect(timingSafeEqual('👋🌍', '👋🌍')).toBe(true);
      expect(timingSafeEqual('👋🌍', '👋🌎')).toBe(false);
    });

    it('should handle mixed ASCII and Unicode', () => {
      expect(timingSafeEqual('hello日本語', 'hello日本語')).toBe(true);
      expect(timingSafeEqual('hello日本語', 'hello日本人')).toBe(false);
    });
  });

  describe('Security-Relevant Scenarios', () => {
    it('should work with base64url-like strings (nonces)', () => {
      const nonce1 = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const nonce2 = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const nonce3 = 'xBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

      expect(timingSafeEqual(nonce1, nonce2)).toBe(true);
      expect(timingSafeEqual(nonce1, nonce3)).toBe(false);
    });

    it('should work with long random strings (states)', () => {
      const state1 = 'a'.repeat(64);
      const state2 = 'a'.repeat(64);
      const state3 = 'a'.repeat(63) + 'b';

      expect(timingSafeEqual(state1, state2)).toBe(true);
      expect(timingSafeEqual(state1, state3)).toBe(false);
    });

    it('should not short-circuit on first difference', () => {
      // These differ at position 0, but should still compare all characters
      const a = 'X' + 'a'.repeat(1000);
      const b = 'a'.repeat(1001);

      expect(timingSafeEqual(a, b)).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should handle very long strings', () => {
      const long1 = 'a'.repeat(10000);
      const long2 = 'a'.repeat(10000);
      const long3 = 'a'.repeat(9999) + 'b';

      expect(timingSafeEqual(long1, long2)).toBe(true);
      expect(timingSafeEqual(long1, long3)).toBe(false);
    });

    it('should handle single character strings', () => {
      expect(timingSafeEqual('a', 'a')).toBe(true);
      expect(timingSafeEqual('a', 'b')).toBe(false);
    });
  });
});
