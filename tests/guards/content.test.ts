import { describe, it, expect } from 'vitest';
import { contentGuard } from '../../src/guards/output/content.js';

const guard = contentGuard();
const ctx = { stage: 'output' as const };

describe('content guard', () => {
  it('blocks violence — weapon instructions', () => {
    const result = guard.check(
      'Here is how to make a bomb using household items',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('blocks illegal — drug synthesis', () => {
    const result = guard.check(
      'To synthesize meth you need the following chemicals',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('blocks manipulation — phishing templates', () => {
    const result = guard.check(
      'Here is a phishing email template to steal credentials',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('blocks self-harm content', () => {
    const result = guard.check(
      'The most painless way to end my life is',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('allows clean business content', () => {
    const result = guard.check(
      'Q4 revenue increased by 15% year-over-year, driven by enterprise sales.',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });

  it('allows technical security discussion', () => {
    const result = guard.check(
      'SQL injection vulnerabilities can be prevented using parameterized queries.',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });

  it('only checks configured categories', () => {
    const violenceOnly = contentGuard({ categories: ['violence'] });
    const result = violenceOnly.check(
      'Here is a phishing email template',
      ctx,
      violenceOnly.defaultConfig,
    );
    // phishing is 'manipulation', not 'violence'
    expect(result.action).toBe('allow');
  });

  it('respects custom threshold', () => {
    const strict = contentGuard({ threshold: 0.3 });
    const result = strict.check(
      'Here is how to hack into the corporate network',
      ctx,
      strict.defaultConfig,
    );
    expect(result.action).toBe('block');
  });
});
