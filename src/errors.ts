/**
 * Thrown when a guard detects a content violation and onViolation is 'throw'.
 */
export class GuardViolationError extends Error {
  readonly code: string;
  readonly guard: string;
  readonly stage: 'input' | 'output';

  constructor(opts: {
    guard: string;
    stage: 'input' | 'output';
    code: string;
    reason: string;
  }) {
    super(`[ai-guardrails] ${opts.guard}: ${opts.reason}`);
    this.name = 'GuardViolationError';
    this.code = opts.code;
    this.guard = opts.guard;
    this.stage = opts.stage;
  }
}

/**
 * Thrown when a guard itself crashes and failOpen is false.
 */
export class GuardExecutionError extends Error {
  readonly guard: string;
  readonly cause: unknown;

  constructor(guard: string, cause: unknown) {
    super(
      `[ai-guardrails] Guard "${guard}" failed: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
    this.name = 'GuardExecutionError';
    this.guard = guard;
    this.cause = cause;
  }
}
