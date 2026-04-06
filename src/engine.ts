import type {
  AnyGuard,
  GuardCheckResult,
  GuardContext,
  GuardEvent,
  GuardReport,
  GuardReportOutcome,
  GuardResult,
  GuardRetrievalCheckResult,
  GuardStage,
  GuardStepReport,
} from './types.js';
import { GuardExecutionError, GuardViolationError } from './errors.js';
import { createTextPartition } from './utils/text-partition.js';

const REPORT_SCHEMA_VERSION = 1 as const;
const TOOL_PAYLOAD_SERIALIZER_GUARD = 'tool_payload_serializer';
const UNSERIALIZABLE_PAYLOAD = '[UNSERIALIZABLE_PAYLOAD]';

type GuardHelperContext = Pick<GuardContext, 'metadata'>;

interface GuardEngineExecution {
  kind: 'result' | 'error';
  durationMs: number;
  result?: GuardResult;
  error?: unknown;
}

interface PreparedToolPayload {
  content: string;
  payloadType: string;
}

export interface GuardEngineOptions {
  guards: AnyGuard[];
  onViolation: 'throw' | 'warn';
  failOpen: boolean;
  logger?: (event: GuardEvent) => void;
  onReport?: (report: GuardReport) => void | Promise<void>;
}

function getPayloadType(payload: unknown): string {
  if (payload === null) return 'null';
  if (Array.isArray(payload)) return 'array';
  return typeof payload;
}

function normalizeJsonValue(
  value: unknown,
  stack: Set<object>,
): unknown {
  if (typeof value === 'bigint') {
    throw new TypeError('BigInt values are not supported in tool payload serialization');
  }

  if (
    value === null
    || typeof value === 'string'
    || typeof value === 'number'
    || typeof value === 'boolean'
  ) {
    return value;
  }

  if (
    typeof value === 'undefined'
    || typeof value === 'function'
    || typeof value === 'symbol'
  ) {
    return undefined;
  }

  if (!(value instanceof Object)) {
    return value;
  }

  const jsonSerializable = value as { toJSON?: () => unknown };
  if (typeof jsonSerializable.toJSON === 'function') {
    return normalizeJsonValue(jsonSerializable.toJSON(), stack);
  }

  if (stack.has(value)) {
    throw new TypeError('Circular tool payloads are not supported');
  }

  stack.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => {
        const normalized = normalizeJsonValue(item, stack);
        return normalized === undefined ? null : normalized;
      });
    }

    const normalizedEntries = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right));

    const normalizedObject: Record<string, unknown> = {};
    for (const [key, entryValue] of normalizedEntries) {
      const normalized = normalizeJsonValue(entryValue, stack);
      if (normalized !== undefined) {
        normalizedObject[key] = normalized;
      }
    }

    return normalizedObject;
  } finally {
    stack.delete(value);
  }
}

function stableStringify(value: unknown): string {
  const normalized = normalizeJsonValue(value, new Set<object>());
  const serialized = JSON.stringify(normalized);
  if (serialized === undefined) {
    throw new TypeError('Unsupported tool payload type');
  }
  return serialized;
}

function mergeMetadata(
  ...entries: Array<Record<string, unknown> | undefined>
): Record<string, unknown> | undefined {
  const merged = Object.assign({}, ...entries.filter(Boolean));
  return Object.keys(merged).length > 0 ? merged : undefined;
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
  private onReport?: (report: GuardReport) => void | Promise<void>;

  constructor(opts: GuardEngineOptions) {
    this.guards = opts.guards;
    this.onViolation = opts.onViolation;
    this.failOpen = opts.failOpen;
    this.logger = opts.logger;
    this.onReport = opts.onReport;
  }

  async check(
    content: string,
    stage: GuardStage,
    context?: Partial<GuardContext>,
  ): Promise<GuardCheckResult> {
    const startedAt = performance.now();
    const ctx: GuardContext = {
      ...context,
      stage,
    };
    const stageGuards = this.guards.filter((guard) => guard.stage === stage);
    let currentContent = content;
    let warningsCount = 0;
    let redactionsApplied = 0;
    let failOpenTriggered = false;
    const redactionReasons: string[] = [];
    const redactionCodes: string[] = [];
    const steps: GuardStepReport[] = [];

    for (const tier of [1, 2, 3] as const) {
      const tierGuards = stageGuards.filter((guard) => guard.tier === tier);
      if (tierGuards.length === 0) continue;

      for (const guard of tierGuards) {
        if (tier > 1 && warningsCount === 0 && guard.runOn !== 'always') {
          steps.push({
            guard: guard.name,
            stage,
            tier: guard.tier,
            runOn: guard.runOn,
            status: 'skipped',
            durationMs: 0,
          });
          continue;
        }

        const execution = await this.runGuard(guard, currentContent, ctx);
        if (execution.kind === 'error') {
          failOpenTriggered = failOpenTriggered || this.failOpen;
          steps.push({
            guard: guard.name,
            stage,
            tier: guard.tier,
            runOn: guard.runOn,
            status: 'error',
            reason:
              execution.error instanceof Error
                ? execution.error.message
                : String(execution.error),
            durationMs: execution.durationMs,
          });

          if (!this.failOpen) {
            const report = this.buildReport({
              startedAt,
              stage,
              inputLength: content.length,
              outputLength: currentContent.length,
              outcome: redactionsApplied > 0 ? 'redact' : 'allow',
              warningsCount,
              redactionsApplied,
              failOpenTriggered,
              metadata: ctx.metadata,
              steps,
            });
            this.emitReport(report);
            throw new GuardExecutionError(guard.name, execution.error);
          }

          continue;
        }

        const result = execution.result!;
        steps.push(this.createStepReport(guard, stage, result, execution.durationMs));

        if (result.action === 'warn') {
          warningsCount += 1;
          continue;
        }

        if (result.action === 'redact') {
          currentContent = result.redacted;
          redactionsApplied += 1;
          redactionReasons.push(result.reason);
          redactionCodes.push(result.code);
          continue;
        }

        if (result.action === 'block') {
          const report = this.buildReport({
            startedAt,
            stage,
            inputLength: content.length,
            outputLength: currentContent.length,
            outcome: 'block',
            warningsCount,
            redactionsApplied,
            failOpenTriggered,
            metadata: ctx.metadata,
            finalReason: result.reason,
            finalCode: result.code,
            steps,
          });
          this.emitReport(report);

          if (this.onViolation === 'throw') {
            throw new GuardViolationError({
              guard: guard.name,
              stage,
              code: result.code,
              reason: result.reason,
            });
          }

          return { result, content: currentContent };
        }
      }
    }

    if (redactionsApplied > 0) {
      const result: GuardResult = {
        action: 'redact',
        redacted: currentContent,
        reason: redactionReasons.join('; '),
        code: redactionCodes.join(','),
      };
      this.emitReport(
        this.buildReport({
          startedAt,
          stage,
          inputLength: content.length,
          outputLength: currentContent.length,
          outcome: 'redact',
          warningsCount,
          redactionsApplied,
          failOpenTriggered,
          metadata: ctx.metadata,
          finalReason: result.reason,
          finalCode: result.code,
          steps,
        }),
      );
      return { result, content: currentContent };
    }

    const result: GuardResult = { action: 'allow' };
    this.emitReport(
      this.buildReport({
        startedAt,
        stage,
        inputLength: content.length,
        outputLength: currentContent.length,
        outcome: 'allow',
        warningsCount,
        redactionsApplied,
        failOpenTriggered,
        metadata: ctx.metadata,
        steps,
      }),
    );

    return { result, content: currentContent };
  }

  async checkRetrieval(
    chunks: string | string[],
    context?: GuardHelperContext,
  ): Promise<GuardRetrievalCheckResult> {
    const chunkList = Array.isArray(chunks) ? chunks : [chunks];
    const partition = createTextPartition(chunkList);
    const result = await this.check(partition.joinedText, 'retrieval', {
      metadata: mergeMetadata(context?.metadata, { chunkCount: chunkList.length }),
    });

    if (!Array.isArray(chunks)) {
      return result;
    }

    const restoredChunks = partition.restoreSegments(result.content);
    if (restoredChunks) {
      return {
        ...result,
        chunks: restoredChunks,
      };
    }

    return result;
  }

  async checkToolInput(
    toolName: string,
    payload: unknown,
    context?: GuardHelperContext,
  ): Promise<GuardCheckResult> {
    return this.checkToolStage('tool_input', toolName, payload, context);
  }

  async checkToolOutput(
    toolName: string,
    payload: unknown,
    context?: GuardHelperContext,
  ): Promise<GuardCheckResult> {
    return this.checkToolStage('tool_output', toolName, payload, context);
  }

  private async checkToolStage(
    stage: 'tool_input' | 'tool_output',
    toolName: string,
    payload: unknown,
    context?: GuardHelperContext,
  ): Promise<GuardCheckResult> {
    const startedAt = performance.now();
    const metadata = mergeMetadata(context?.metadata, {
      toolName,
      payloadType: getPayloadType(payload),
    });

    let prepared: PreparedToolPayload;
    try {
      prepared = this.prepareToolPayload(payload);
    } catch (error) {
      const step: GuardStepReport = {
        guard: TOOL_PAYLOAD_SERIALIZER_GUARD,
        stage,
        tier: 1,
        status: 'error',
        reason: error instanceof Error ? error.message : String(error),
        durationMs: performance.now() - startedAt,
      };

      const report = this.buildReport({
        startedAt,
        stage,
        inputLength: 0,
        outputLength: 0,
        outcome: 'allow',
        warningsCount: 0,
        redactionsApplied: 0,
        failOpenTriggered: this.failOpen,
        metadata,
        steps: [step],
      });
      this.emitReport(report);

      if (!this.failOpen) {
        throw new GuardExecutionError(TOOL_PAYLOAD_SERIALIZER_GUARD, error);
      }

      return {
        result: { action: 'allow' },
        content: UNSERIALIZABLE_PAYLOAD,
      };
    }

    return this.check(prepared.content, stage, {
      metadata: mergeMetadata(metadata, { payloadType: prepared.payloadType }),
    });
  }

  private prepareToolPayload(payload: unknown): PreparedToolPayload {
    if (typeof payload === 'string') {
      return {
        content: payload,
        payloadType: 'string',
      };
    }

    return {
      content: stableStringify(payload),
      payloadType: getPayloadType(payload),
    };
  }

  private async runGuard(
    guard: AnyGuard,
    content: string,
    context: GuardContext,
  ): Promise<GuardEngineExecution> {
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

      return {
        kind: 'result',
        result,
        durationMs,
      };
    } catch (error) {
      const durationMs = performance.now() - start;

      this.logger?.({
        type: 'error',
        guard: guard.name,
        stage: context.stage,
        error,
        durationMs,
      });

      return {
        kind: 'error',
        error,
        durationMs,
      };
    }
  }

  private createStepReport(
    guard: AnyGuard,
    stage: GuardStage,
    result: GuardResult,
    durationMs: number,
  ): GuardStepReport {
    if (result.action === 'block') {
      return {
        guard: guard.name,
        stage,
        tier: guard.tier,
        runOn: guard.runOn,
        status: 'blocked',
        reason: result.reason,
        code: result.code,
        durationMs,
      };
    }

    if (result.action === 'warn') {
      return {
        guard: guard.name,
        stage,
        tier: guard.tier,
        runOn: guard.runOn,
        status: 'warned',
        reason: result.reason,
        code: result.code,
        durationMs,
      };
    }

    if (result.action === 'redact') {
      return {
        guard: guard.name,
        stage,
        tier: guard.tier,
        runOn: guard.runOn,
        status: 'redacted',
        reason: result.reason,
        code: result.code,
        durationMs,
      };
    }

    return {
      guard: guard.name,
      stage,
      tier: guard.tier,
      runOn: guard.runOn,
      status: 'passed',
      durationMs,
    };
  }

  private buildReport(opts: {
    startedAt: number;
    stage: GuardStage;
    inputLength: number;
    outputLength: number;
    outcome: GuardReportOutcome;
    warningsCount: number;
    redactionsApplied: number;
    failOpenTriggered: boolean;
    metadata?: Record<string, unknown>;
    finalReason?: string;
    finalCode?: string;
    steps: GuardStepReport[];
  }): GuardReport {
    return {
      schemaVersion: REPORT_SCHEMA_VERSION,
      stage: opts.stage,
      outcome: opts.outcome,
      hasWarnings: opts.warningsCount > 0,
      warningsCount: opts.warningsCount,
      redactionsApplied: opts.redactionsApplied,
      inputLength: opts.inputLength,
      outputLength: opts.outputLength,
      durationMs: performance.now() - opts.startedAt,
      failOpenTriggered: opts.failOpenTriggered,
      metadata: opts.metadata,
      finalReason: opts.finalReason,
      finalCode: opts.finalCode,
      steps: opts.steps,
    };
  }

  private emitReport(report: GuardReport): void {
    if (!this.onReport) {
      return;
    }

    const start = performance.now();
    try {
      const maybePromise = this.onReport(report);
      if (maybePromise && typeof maybePromise.then === 'function') {
        void Promise.resolve(maybePromise).catch((error) => {
          this.logReportError(report.stage, error, start);
        });
      }
    } catch (error) {
      this.logReportError(report.stage, error, start);
    }
  }

  private logReportError(stage: GuardStage, error: unknown, start: number): void {
    try {
      this.logger?.({
        type: 'error',
        guard: 'reporter',
        stage,
        error,
        durationMs: performance.now() - start,
      });
    } catch {
      // Report callback failures must never alter the guard outcome.
    }
  }
}
