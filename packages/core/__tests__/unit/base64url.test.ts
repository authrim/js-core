/**
 * Base64URL Utilities Tests
 *
 * Tests for RFC 4648 Section 5 compliant base64url encoding/decoding
 */

import { describe, it, expect } from 'vitest';
import {
  base64urlEncode,
  base64urlDecode,
  stringToBase64url,
  base64urlToString,
} from '../../src/utils/base64url.js';

describe('base64urlEncode', () => {
  it('should encode empty array', () => {
    const result = base64urlEncode(new Uint8Array([]));
    expect(result).toBe('');
  });

  it('should encode single byte', () => {
    const result = base64urlEncode(new Uint8Array([0x00]));
    expect(result).toBe('AA');
  });

  it('should encode multiple bytes', () => {
    const result = base64urlEncode(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]));
    expect(result).toBe('SGVsbG8');
  });

  it('should use URL-safe characters (no + or /)', () => {
    // 0xfb, 0xff would produce + and / in standard base64
    const result = base64urlEncode(new Uint8Array([0xfb, 0xff, 0xfe]));
    expect(result).not.toContain('+');
    expect(result).not.toContain('/');
    expect(result).toContain('-');
    expect(result).toContain('_');
  });

  it('should not include padding', () => {
    const result1 = base64urlEncode(new Uint8Array([0x00]));
    const result2 = base64urlEncode(new Uint8Array([0x00, 0x00]));
    expect(result1).not.toContain('=');
    expect(result2).not.toContain('=');
  });
});

describe('base64urlDecode', () => {
  it('should decode empty string', () => {
    const result = base64urlDecode('');
    expect(result).toEqual(new Uint8Array([]));
  });

  it('should decode valid base64url', () => {
    const result = base64urlDecode('SGVsbG8');
    expect(result).toEqual(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]));
  });

  it('should handle URL-safe characters (- and _)', () => {
    // Should correctly decode strings with - and _
    const encoded = base64urlEncode(new Uint8Array([0xfb, 0xff, 0xfe]));
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(new Uint8Array([0xfb, 0xff, 0xfe]));
  });

  it('should handle strings without padding', () => {
    // 'SGVsbG8' should decode even without padding
    const result = base64urlDecode('SGVsbG8');
    expect(result).toEqual(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]));
  });

  describe('Input Validation', () => {
    it('should throw on invalid characters (+)', () => {
      expect(() => base64urlDecode('SGVs+G8')).toThrow('Invalid base64url string');
    });

    it('should throw on invalid characters (/)', () => {
      expect(() => base64urlDecode('SGVs/G8')).toThrow('Invalid base64url string');
    });

    it('should throw on invalid characters (=)', () => {
      expect(() => base64urlDecode('SGVsbG8=')).toThrow('Invalid base64url string');
    });

    it('should throw on invalid characters (space)', () => {
      expect(() => base64urlDecode('SGVs bG8')).toThrow('Invalid base64url string');
    });

    it('should throw on invalid characters (newline)', () => {
      expect(() => base64urlDecode('SGVs\nbG8')).toThrow('Invalid base64url string');
    });

    it('should throw on invalid characters (special chars)', () => {
      expect(() => base64urlDecode('SGVs!bG8')).toThrow('Invalid base64url string');
      expect(() => base64urlDecode('SGVs@bG8')).toThrow('Invalid base64url string');
      expect(() => base64urlDecode('SGVs#bG8')).toThrow('Invalid base64url string');
    });

    it('should accept valid base64url characters only', () => {
      // All valid characters: A-Z, a-z, 0-9, -, _
      const validChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
      expect(() => base64urlDecode(validChars)).not.toThrow();
    });
  });
});

describe('stringToBase64url', () => {
  it('should encode empty string', () => {
    const result = stringToBase64url('');
    expect(result).toBe('');
  });

  it('should encode ASCII string', () => {
    const result = stringToBase64url('Hello');
    expect(result).toBe('SGVsbG8');
  });

  it('should encode UTF-8 string', () => {
    const result = stringToBase64url('日本語');
    // UTF-8 encoded 日本語 = E6 97 A5 E6 9C AC E8 AA 9E
    expect(result).toBe('5pel5pys6Kqe');
  });

  it('should encode emoji', () => {
    const result = stringToBase64url('👋');
    expect(result.length).toBeGreaterThan(0);
    // Verify roundtrip
    expect(base64urlToString(result)).toBe('👋');
  });
});

describe('base64urlToString', () => {
  it('should decode empty string', () => {
    const result = base64urlToString('');
    expect(result).toBe('');
  });

  it('should decode ASCII string', () => {
    const result = base64urlToString('SGVsbG8');
    expect(result).toBe('Hello');
  });

  it('should decode UTF-8 string', () => {
    const result = base64urlToString('5pel5pys6Kqe');
    expect(result).toBe('日本語');
  });
});

describe('Roundtrip', () => {
  it('should roundtrip binary data', () => {
    const original = new Uint8Array([0, 1, 2, 255, 254, 253, 128, 127]);
    const encoded = base64urlEncode(original);
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(original);
  });

  it('should roundtrip random bytes', () => {
    // Test with various lengths
    for (const len of [0, 1, 2, 3, 4, 5, 16, 32, 64, 100]) {
      const original = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        original[i] = Math.floor(Math.random() * 256);
      }
      const encoded = base64urlEncode(original);
      const decoded = base64urlDecode(encoded);
      expect(decoded).toEqual(original);
    }
  });

  it('should roundtrip strings', () => {
    const testStrings = [
      '',
      'Hello',
      'Hello, World!',
      '日本語',
      '🎉🎊🎈',
      'Mixed 日本語 and English',
      'Special chars: !@#$%^&*()',
    ];

    for (const str of testStrings) {
      const encoded = stringToBase64url(str);
      const decoded = base64urlToString(encoded);
      expect(decoded).toBe(str);
    }
  });
});
