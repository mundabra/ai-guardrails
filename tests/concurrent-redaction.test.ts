import { describe, it, expect } from 'vitest';
import { GuardEngine } from '../src/engine.js';
import { piiGuard } from '../src/guards/output/pii.js';
import { secretsGuard } from '../src/guards/output/secrets.js';

describe('concurrent redaction', () => {
  it('combines redaction reasons from multiple guards', async () => {
    const engine = new GuardEngine({
      guards: [
        piiGuard({ action: 'redact' }),
        secretsGuard({ action: 'redact' }),
      ],
      onViolation: 'throw',
      failOpen: true,
    });

    const input =
      'SSN: 123-45-6789, Key: AKIAIOSFODNN7EXAMPLE';
    const { result, content } = await engine.check(input, 'output');

    expect(result.action).toBe('redact');
    // Both SSN and AWS key should be redacted in content
    expect(content).not.toContain('123-45-6789');
    expect(content).not.toContain('AKIAIOSFODNN7EXAMPLE');

    // Reason should mention both guards
    if (result.action === 'redact') {
      expect(result.reason).toContain('PII');
      expect(result.reason).toContain('ecret');
    }
  });

  it('preserves all redactions even when guards run in parallel', async () => {
    const engine = new GuardEngine({
      guards: [
        piiGuard({ action: 'redact', types: ['email'] }),
        piiGuard({ action: 'redact', types: ['ssn'] }),
      ],
      onViolation: 'throw',
      failOpen: true,
    });

    const input = 'Email: test@example.com, SSN: 123-45-6789';
    const { content } = await engine.check(input, 'output');

    expect(content).not.toContain('test@example.com');
    expect(content).not.toContain('123-45-6789');
  });
});
