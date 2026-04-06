import { describe, it, expect } from 'vitest';
import { piiGuard } from '../../src/guards/output/pii.js';

const guard = piiGuard();
const ctx = { stage: 'output' as const };

describe('pii guard', () => {
  it('redacts SSN', () => {
    const result = guard.check(
      'His SSN is 123-45-6789',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('redact');
    if (result.action === 'redact') {
      expect(result.redacted).toContain('[REDACTED]');
      expect(result.redacted).not.toContain('123-45-6789');
    }
  });

  it('validates SSN — rejects invalid area 000', () => {
    const result = guard.check(
      'Number: 000-12-3456',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });

  it('validates SSN — rejects invalid area 666', () => {
    const result = guard.check(
      'Number: 666-12-3456',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });

  it('redacts credit card (Visa) with Luhn check', () => {
    // 4111 1111 1111 1111 is a valid Luhn number
    const result = guard.check(
      'Card: 4111 1111 1111 1111',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('redact');
  });

  it('ignores invalid credit card (bad Luhn)', () => {
    const result = guard.check(
      'Card: 4111 1111 1111 1112',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });

  it('redacts email addresses', () => {
    const result = guard.check(
      'Contact john@example.com for details',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('redact');
    if (result.action === 'redact') {
      expect(result.redacted).not.toContain('john@example.com');
    }
  });

  it('redacts phone numbers', () => {
    const result = guard.check(
      'Call me at (555) 123-4567',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('redact');
  });

  it('redacts IPv4 addresses', () => {
    const result = guard.check(
      'Server at 192.168.1.100',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('redact');
  });

  it('ignores invalid IPv4 (octet > 255)', () => {
    const result = guard.check(
      'Not an IP: 999.999.999.999',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });

  it('blocks instead of redacts when configured', () => {
    const blocking = piiGuard({ action: 'block' });
    const result = blocking.check(
      'SSN: 123-45-6789',
      ctx,
      blocking.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('uses custom redaction string', () => {
    const custom = piiGuard({ redactWith: '***' });
    const result = custom.check(
      'SSN: 123-45-6789',
      ctx,
      custom.defaultConfig,
    );
    if (result.action === 'redact') {
      expect(result.redacted).toContain('***');
    }
  });

  it('respects allowlist', () => {
    const withAllowlist = piiGuard({
      allowlist: ['test@example.com'],
    });
    const result = withAllowlist.check(
      'Email: test@example.com',
      ctx,
      withAllowlist.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });

  it('only checks configured types', () => {
    const emailOnly = piiGuard({ types: ['email'] });
    const result = emailOnly.check(
      'SSN: 123-45-6789, Email: test@test.com',
      ctx,
      emailOnly.defaultConfig,
    );
    // Should only catch email, not SSN
    if (result.action === 'redact') {
      expect(result.redacted).toContain('123-45-6789');
      expect(result.redacted).not.toContain('test@test.com');
    }
  });

  it('handles multiple PII types in one string', () => {
    const result = guard.check(
      'Name: John, SSN: 123-45-6789, Card: 4111 1111 1111 1111, Email: john@example.com',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('redact');
    if (result.action === 'redact') {
      expect(result.redacted).not.toContain('123-45-6789');
      expect(result.redacted).not.toContain('4111 1111 1111 1111');
      expect(result.redacted).not.toContain('john@example.com');
    }
  });

  it('passes clean content', () => {
    const result = guard.check(
      'The quarterly report shows 15% growth',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });
});
