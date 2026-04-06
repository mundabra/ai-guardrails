import { describe, it, expect } from 'vitest';
import { secretsGuard } from '../../src/guards/output/secrets.js';

const guard = secretsGuard();
const ctx = { stage: 'output' as const };

describe('secrets guard', () => {
  it('detects AWS access key', () => {
    const result = guard.check(
      'AWS key: AKIAIOSFODNN7EXAMPLE',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('detects GitHub PAT', () => {
    const result = guard.check(
      'Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('detects Google API key', () => {
    const result = guard.check(
      'Key: AIzaSyA1234567890abcdefghijklmnopqrstuv',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('detects Stripe secret key', () => {
    const result = guard.check(
      'Stripe: sk_test_TESTONLY1234abcdefghijklmn',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('allows Stripe publishable keys', () => {
    const result = guard.check(
      'Stripe frontend key: pk_live_1234567890abcdefghijklmn',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });

  it('detects Slack token', () => {
    const result = guard.check(
      'Slack: xoxb-1234567890-abcdefghijkl',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('detects JWT', () => {
    const result = guard.check(
      'Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('detects SSH private key header', () => {
    const result = guard.check(
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEow...',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('detects generic high-entropy secrets', () => {
    const result = guard.check(
      'api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u"',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('redacts when configured', () => {
    const redacting = secretsGuard({ action: 'redact' });
    const result = redacting.check(
      'Key: AKIAIOSFODNN7EXAMPLE',
      ctx,
      redacting.defaultConfig,
    );
    expect(result.action).toBe('redact');
    if (result.action === 'redact') {
      expect(result.redacted).toContain('[SECRET_REDACTED]');
    }
  });

  it('passes clean content', () => {
    const result = guard.check(
      'The API uses OAuth 2.0 for authentication',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });

  it('only checks configured types', () => {
    const awsOnly = secretsGuard({ types: ['aws'] });
    const result = awsOnly.check(
      'Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh',
      ctx,
      awsOnly.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });
});
