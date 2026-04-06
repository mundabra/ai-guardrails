import { describe, it, expect } from 'vitest';
import { topicGuard } from '../../src/guards/input/topic.js';

const ctx = { stage: 'input' as const };

describe('topic guard', () => {
  it('blocks blocked topics', () => {
    const guard = topicGuard({
      allowedTopics: [],
      blockedTopics: ['gambling'],
    });
    const result = guard.check(
      'What are the best gambling strategies?',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('block');
  });

  it('warns when off-topic', () => {
    const guard = topicGuard({
      allowedTopics: ['finance', 'sales'],
    });
    const result = guard.check(
      'Tell me a joke about elephants',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('warn');
  });

  it('allows when on-topic', () => {
    const guard = topicGuard({
      allowedTopics: ['finance', 'sales'],
    });
    const result = guard.check(
      'What were our sales numbers last quarter?',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });

  it('uses word boundaries — "cat" does not match "concatenate"', () => {
    const guard = topicGuard({
      allowedTopics: [],
      blockedTopics: ['cat'],
    });
    const result = guard.check(
      'Please concatenate these strings',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).not.toBe('block');
  });

  it('uses word boundaries — "script" does not match "prescription"', () => {
    const guard = topicGuard({
      allowedTopics: [],
      blockedTopics: ['script'],
    });
    const result = guard.check(
      'I need a prescription refill',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).not.toBe('block');
  });

  it('allows when no topics configured', () => {
    const guard = topicGuard({ allowedTopics: [] });
    const result = guard.check(
      'Anything goes here',
      ctx,
      guard.defaultConfig,
    );
    expect(result.action).toBe('allow');
  });
});
