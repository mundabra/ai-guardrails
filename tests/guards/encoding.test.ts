import { describe, it, expect } from 'vitest';
import { encodingGuard } from '../../src/guards/input/encoding.js';
import { lengthGuard } from '../../src/guards/input/length.js';

const ctx = { stage: 'input' as const };

describe('encoding guard', () => {
  const guard = encodingGuard();

  it('blocks input with multiple encoding layers', () => {
    // Zero-width chars + HTML entities = 2 suspicious steps
    const result = guard.check(
      'he\u200Bllo &amp; w\u200Borld',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('allows input with only one normalization step (not suspicious enough)', () => {
    // Single HTML entity in otherwise clean text — not enough to warn
    const result = guard.check(
      'hello &amp; world',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });

  it('warns when wasNormalized and has suspicious steps', () => {
    // Zero-width + HTML entity = 2 steps but normalize.wasNormalized
    // requires steps > 1, and we have html_entities + zero_width = 2
    const result = guard.check(
      'he\u200Bllo &amp; world',
      ctx,
      guard.defaultConfig,
    );
    // 2 suspicious steps → block (not just warn)
    expect(result.action).toBe('block');
  });

  it('allows clean input', () => {
    const result = guard.check(
      'Hello, how are you?',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });
});

describe('length guard', () => {
  const guard = lengthGuard();

  it('blocks input exceeding max length', () => {
    const long = 'a'.repeat(50_001);
    const result = guard.check(long, ctx, guard.defaultConfig);
    expect(result.action).toBe('block');
  });

  it('allows input at exactly max length', () => {
    const exact = 'a'.repeat(50_000);
    const result = guard.check(exact, ctx, guard.defaultConfig);
    expect(result.action).toBe('allow');
  });

  it('allows short input', () => {
    const result = guard.check('hello', ctx, guard.defaultConfig);
    expect(result.action).toBe('allow');
  });

  it('respects custom max', () => {
    const strict = lengthGuard({ max: 10 });
    const result = strict.check('12345678901', ctx, strict.defaultConfig);
    expect(result.action).toBe('block');
  });
});
