import { describe, it, expect, vi } from 'vitest';
import { GuardEngine } from '../src/engine.js';
import { GuardViolationError, GuardExecutionError } from '../src/errors.js';
import type { Guard, GuardResult } from '../src/types.js';

function makeGuard(
  overrides: Partial<Guard> & { name: string },
): Guard {
  return {
    stage: 'input',
    tier: 1,
    check: () => ({ action: 'allow' }),
    defaultConfig: {},
    ...overrides,
  };
}

describe('GuardEngine', () => {
  it('returns allow when no guards match', async () => {
    const engine = new GuardEngine({
      guards: [makeGuard({ name: 'noop' })],
      onViolation: 'throw',
      failOpen: true,
    });

    const { result } = await engine.check('hello world', 'input');
    expect(result.action).toBe('allow');
  });

  it('throws GuardViolationError on block when onViolation=throw', async () => {
    const engine = new GuardEngine({
      guards: [
        makeGuard({
          name: 'blocker',
          check: () => ({ action: 'block', reason: 'bad', code: 'test' }),
        }),
      ],
      onViolation: 'throw',
      failOpen: true,
    });

    await expect(engine.check('bad input', 'input')).rejects.toThrow(
      GuardViolationError,
    );
  });

  it('returns block result when onViolation=warn', async () => {
    const engine = new GuardEngine({
      guards: [
        makeGuard({
          name: 'blocker',
          check: () => ({ action: 'block', reason: 'bad', code: 'test' }),
        }),
      ],
      onViolation: 'warn',
      failOpen: true,
    });

    const { result } = await engine.check('bad input', 'input');
    expect(result.action).toBe('block');
  });

  it('applies redaction and returns modified content', async () => {
    const engine = new GuardEngine({
      guards: [
        makeGuard({
          name: 'redactor',
          stage: 'output',
          check: () => ({
            action: 'redact',
            redacted: 'hello [REDACTED]',
            reason: 'pii',
            code: 'pii',
          }),
        }),
      ],
      onViolation: 'throw',
      failOpen: true,
    });

    const { result, content } = await engine.check(
      'hello 123-45-6789',
      'output',
    );
    expect(result.action).toBe('redact');
    expect(content).toBe('hello [REDACTED]');
  });

  it('runs guards in tier order — tier 1 block prevents tier 3', async () => {
    const tier3Check = vi.fn<() => GuardResult>(() => ({ action: 'allow' }));
    const engine = new GuardEngine({
      guards: [
        makeGuard({
          name: 'tier1-block',
          tier: 1,
          check: () => ({ action: 'block', reason: 'stop', code: 'stop' }),
        }),
        makeGuard({ name: 'tier3-never', tier: 3, check: tier3Check }),
      ],
      onViolation: 'warn',
      failOpen: true,
    });

    await engine.check('test', 'input');
    expect(tier3Check).not.toHaveBeenCalled();
  });

  it('tier 2+ runs only when tier 1 warns', async () => {
    const tier2Check = vi.fn<() => GuardResult>(() => ({ action: 'allow' }));
    const engine = new GuardEngine({
      guards: [
        makeGuard({
          name: 'tier1-warn',
          tier: 1,
          check: () => ({
            action: 'warn',
            reason: 'suspicious',
            code: 'warn',
          }),
        }),
        makeGuard({ name: 'tier2', tier: 2, check: tier2Check }),
      ],
      onViolation: 'warn',
      failOpen: true,
    });

    await engine.check('test', 'input');
    expect(tier2Check).toHaveBeenCalled();
  });

  it('tier 2 does NOT run when tier 1 only allows', async () => {
    const tier2Check = vi.fn<() => GuardResult>(() => ({ action: 'allow' }));
    const engine = new GuardEngine({
      guards: [
        makeGuard({ name: 'tier1-allow', tier: 1 }),
        makeGuard({ name: 'tier2', tier: 2, check: tier2Check }),
      ],
      onViolation: 'warn',
      failOpen: true,
    });

    await engine.check('test', 'input');
    expect(tier2Check).not.toHaveBeenCalled();
  });

  it('tier 3 runs when explicitly configured with runOn=always', async () => {
    const tier3Check = vi.fn<() => GuardResult>(() => ({ action: 'allow' }));
    const engine = new GuardEngine({
      guards: [
        makeGuard({
          name: 'tier3-always',
          tier: 3,
          runOn: 'always',
          check: tier3Check,
        }),
      ],
      onViolation: 'warn',
      failOpen: true,
    });

    await engine.check('test', 'input');
    expect(tier3Check).toHaveBeenCalled();
  });

  it('fail-open: guard crash returns allow', async () => {
    const engine = new GuardEngine({
      guards: [
        makeGuard({
          name: 'crasher',
          check: () => {
            throw new Error('boom');
          },
        }),
      ],
      onViolation: 'throw',
      failOpen: true,
    });

    const { result } = await engine.check('test', 'input');
    expect(result.action).toBe('allow');
  });

  it('fail-closed: guard crash throws GuardExecutionError', async () => {
    const engine = new GuardEngine({
      guards: [
        makeGuard({
          name: 'crasher',
          check: () => {
            throw new Error('boom');
          },
        }),
      ],
      onViolation: 'throw',
      failOpen: false,
    });

    await expect(engine.check('test', 'input')).rejects.toThrow(
      GuardExecutionError,
    );
  });

  it('only runs guards matching the requested stage', async () => {
    const inputCheck = vi.fn<() => GuardResult>(() => ({ action: 'allow' }));
    const outputCheck = vi.fn<() => GuardResult>(() => ({ action: 'allow' }));

    const engine = new GuardEngine({
      guards: [
        makeGuard({ name: 'input-guard', stage: 'input', check: inputCheck }),
        makeGuard({
          name: 'output-guard',
          stage: 'output',
          check: outputCheck,
        }),
      ],
      onViolation: 'throw',
      failOpen: true,
    });

    await engine.check('test', 'input');
    expect(inputCheck).toHaveBeenCalled();
    expect(outputCheck).not.toHaveBeenCalled();
  });

  it('calls logger for all guard events', async () => {
    const logger = vi.fn();
    const engine = new GuardEngine({
      guards: [makeGuard({ name: 'logged' })],
      onViolation: 'throw',
      failOpen: true,
      logger,
    });

    await engine.check('test', 'input');
    expect(logger).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'pass', guard: 'logged' }),
    );
  });

  it('runs multiple tier 1 guards sequentially for correct redaction composition', async () => {
    const order: string[] = [];
    const engine = new GuardEngine({
      guards: [
        makeGuard({
          name: 'first',
          tier: 1,
          check: () => {
            order.push('first');
            return { action: 'allow' };
          },
        }),
        makeGuard({
          name: 'second',
          tier: 1,
          check: () => {
            order.push('second');
            return { action: 'allow' };
          },
        }),
      ],
      onViolation: 'throw',
      failOpen: true,
    });

    await engine.check('test', 'input');
    expect(order).toEqual(['first', 'second']);
  });
});
