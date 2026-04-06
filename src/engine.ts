import type { AnyGuard, GuardContext, GuardEvent, GuardResult } from './types.js';
import { GuardExecutionError, GuardViolationError } from './errors.js';

export interface GuardEngineOptions {
  guards: AnyGuard[];
  onViolation: 'throw' | 'warn';
  failOpen: boolean;
  logger?: (event: GuardEvent) => void;
}

/**
 * Executes guards in tier order:
 * - Tier 1 (heuristic): always runs first
 * - Tier 2 (embedding): runs after tier 1 if flagged, unless a guard opts into always
 * - Tier 3 (LLM): runs after earlier tiers if flagged, unless a guard opts into always
 *
 * Guards run sequentially within a tier so redactions compose correctly.
 * A block in any tier short-circuits — later tiers don't run.
 */
export class GuardEngine {
  private guards: AnyGuard[];
  private onViolation: 'throw' | 'warn';
  private failOpen: boolean;
  private logger?: (event: GuardEvent) => void;

  constructor(opts: GuardEngineOptions) {
    this.guards = opts.guards;
    this.onViolation = opts.onViolation;
    this.failOpen = opts.failOpen;
    this.logger = opts.logger;
  }

  async check(
    content: string,
    stage: 'input' | 'output',
    context?: Partial<GuardContext>,
  ): Promise<{ result: GuardResult; content: string }> {
    const ctx: GuardContext = { stage, ...context };
    const stageGuards = this.guards.filter((g) => g.stage === stage);
    let currentContent = content;
    let hasWarning = false;
    const redactionReasons: string[] = [];
    const redactionCodes: string[] = [];

    // Run tiers sequentially: 1 → 2 → 3
    for (const tier of [1, 2, 3] as const) {
      const tierGuards = stageGuards.filter((g) => g.tier === tier);
      if (tierGuards.length === 0) continue;

      // Run guards sequentially within a tier so redactions compose correctly.
      // (Guard B sees Guard A's redacted output, not the original.)
      for (const g of tierGuards) {
        if (tier > 1 && !hasWarning && g.runOn !== 'always') {
          continue;
        }

        const r = await this.runGuard(g, currentContent, ctx);
        if (r.action === 'block') {
          return { result: r, content: currentContent };
        }
        if (r.action === 'warn') {
          hasWarning = true;
        }
        if (r.action === 'redact') {
          currentContent = r.redacted;
          redactionReasons.push(r.reason);
          redactionCodes.push(r.code);
        }
      }
    }

    if (redactionReasons.length > 0) {
      return {
        result: {
          action: 'redact',
          redacted: currentContent,
          reason: redactionReasons.join('; '),
          code: redactionCodes.join(','),
        },
        content: currentContent,
      };
    }

    return { result: { action: 'allow' }, content: currentContent };
  }

  private async runGuard(
    guard: AnyGuard,
    content: string,
    context: GuardContext,
  ): Promise<GuardResult> {
    const start = performance.now();
    try {
      const result = await guard.check(content, context, guard.defaultConfig);
      const durationMs = performance.now() - start;

      if (result.action === 'block') {
        this.logger?.({
          type: 'violation',
          guard: guard.name,
          stage: context.stage,
          code: result.code,
          reason: result.reason,
          durationMs,
        });
        if (this.onViolation === 'throw') {
          throw new GuardViolationError({
            guard: guard.name,
            stage: context.stage,
            code: result.code,
            reason: result.reason,
          });
        }
      } else if (result.action === 'warn') {
        this.logger?.({
          type: 'warning',
          guard: guard.name,
          stage: context.stage,
          code: result.code,
          reason: result.reason,
          durationMs,
        });
      } else {
        this.logger?.({
          type: 'pass',
          guard: guard.name,
          stage: context.stage,
          durationMs,
        });
      }

      return result;
    } catch (error) {
      const durationMs = performance.now() - start;

      // Re-throw violation errors (they're intentional)
      if (error instanceof GuardViolationError) throw error;

      this.logger?.({
        type: 'error',
        guard: guard.name,
        stage: context.stage,
        error,
        durationMs,
      });

      if (!this.failOpen) {
        throw new GuardExecutionError(guard.name, error);
      }

      return { action: 'allow' };
    }
  }
}
