/**
 * Result of a guard check.
 *
 * - allow: content passed the check
 * - block: content violated a policy, request should be stopped
 * - redact: content contained sensitive data that was redacted
 * - warn: content is suspicious but not definitively bad
 */
export type GuardResult =
  | { action: 'allow' }
  | { action: 'block'; reason: string; code: string }
  | { action: 'redact'; redacted: string; reason: string; code: string }
  | { action: 'warn'; reason: string; code: string };

/**
 * All supported guard execution stages.
 */
export type GuardStage =
  | 'input'
  | 'output'
  | 'retrieval'
  | 'tool_input'
  | 'tool_output';

/**
 * Context available to every guard during execution.
 */
export interface GuardContext {
  stage: GuardStage;
  metadata?: Record<string, unknown>;
}

/**
 * Controls when a non-tier-1 guard should run.
 *
 * - flagged: only after an earlier guard warned
 * - always: run even when no earlier guard warned
 */
export type GuardRunOn = 'flagged' | 'always';

/**
 * A guard is a named check function that runs at a specific stage and tier.
 *
 * Tiers control execution order:
 * - Tier 1: Regex/heuristic (0ms) — always runs first
 * - Tier 2: Embedding similarity (5-20ms) — runs if tier 1 passes
 * - Tier 3: LLM classifier (50-800ms) — runs only when flagged
 */
export interface Guard<TConfig = Record<string, never>> {
  name: string;
  stage: GuardStage;
  tier: 1 | 2 | 3;
  /**
   * For tier 2/3 guards, controls whether the guard runs only after an earlier
   * warning or on every request. Defaults to 'flagged' for higher tiers.
   */
  runOn?: GuardRunOn;
  check: (
    content: string,
    context: GuardContext,
    config: TConfig,
  ) => Promise<GuardResult> | GuardResult;
  defaultConfig: TConfig;
}

/**
 * Type-erased guard for use in collections (engine, middleware).
 * Each guard carries its own config internally — the engine calls
 * `check(content, context, guard.defaultConfig)` so the config type
 * doesn't need to be known externally.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type AnyGuard = Guard<any>;

/**
 * Prompt injection detection configuration.
 */
export interface InjectionConfig {
  /** Score threshold to trigger block (0.0-1.0). Default: 0.7 */
  threshold?: number;
  /** Additional patterns with custom weights */
  customPatterns?: Array<{ pattern: RegExp; weight: number }>;
  /** Phrases to skip (known-safe content) */
  allowlist?: string[];
}

/**
 * Encoding attack detection configuration.
 */
export interface EncodingConfig {
  /** Block if significant normalization detected. Default: true */
  blockOnNormalization?: boolean;
}

/**
 * Input length limiting configuration.
 */
export interface LengthConfig {
  /** Maximum character count. Default: 50000 */
  max?: number;
}

/**
 * Topic control configuration.
 */
export interface TopicConfig {
  /** Allowed topic keywords */
  allowedTopics: string[];
  /** Blocked topic keywords */
  blockedTopics?: string[];
}

/**
 * PII detection and redaction configuration.
 */
export interface PiiConfig {
  /** Which PII types to detect. Default: all */
  types?: Array<'ssn' | 'credit_card' | 'email' | 'phone' | 'ip'>;
  /** Block or redact. Default: 'redact' */
  action?: 'block' | 'redact';
  /** Replacement string. Default: '[REDACTED]' */
  redactWith?: string;
  /** Known-safe values to skip (test cards, example emails) */
  allowlist?: string[];
}

/**
 * API key / secret detection configuration.
 */
export interface SecretsConfig {
  /** Which secret types to detect. Default: all */
  types?: Array<
    | 'aws'
    | 'github'
    | 'google'
    | 'stripe'
    | 'slack'
    | 'jwt'
    | 'ssh_key'
    | 'generic_high_entropy'
  >;
  /** Block or redact. Default: 'block' */
  action?: 'block' | 'redact';
}

/**
 * Content safety configuration.
 */
export interface ContentConfig {
  /** Which categories to check. Default: all */
  categories?: Array<
    'violence' | 'illegal' | 'manipulation' | 'discrimination' | 'self_harm'
  >;
  /** Score threshold. Default: 0.7 */
  threshold?: number;
}

/**
 * LLM classifier configuration (opt-in tier 3).
 */
export interface ClassifierConfig {
  /** The model to use for classification (AI SDK model instance) */
  model: unknown; // LanguageModelV3 — kept as unknown to avoid hard dep
  /** Custom input classification prompt */
  inputPrompt?: string;
  /** Custom output classification prompt */
  outputPrompt?: string;
  /** Confidence threshold. Default: 0.7 */
  threshold?: number;
  /** When to run: always or only when tier 1/2 flags. Default: 'flagged' */
  runOn?: GuardRunOn;
}

export interface RetrievalConfig {
  pii?: boolean | PiiConfig;
  secrets?: boolean | SecretsConfig;
  content?: boolean | ContentConfig;
}

export interface ToolInputConfig {
  injection?: boolean | InjectionConfig;
  encoding?: boolean | EncodingConfig;
  length?: boolean | LengthConfig;
  pii?: boolean | PiiConfig;
  secrets?: boolean | SecretsConfig;
}

export interface ToolOutputConfig {
  pii?: boolean | PiiConfig;
  secrets?: boolean | SecretsConfig;
  content?: boolean | ContentConfig;
  exfiltration?: boolean;
}

export interface ToolsConfig {
  input?: ToolInputConfig;
  output?: ToolOutputConfig;
}

export type GuardReportOutcome = 'allow' | 'redact' | 'block';

export type GuardStepStatus =
  | 'passed'
  | 'warned'
  | 'redacted'
  | 'blocked'
  | 'skipped'
  | 'error';

export interface GuardStepReport {
  guard: string;
  stage: GuardStage;
  tier: 1 | 2 | 3;
  runOn?: GuardRunOn;
  status: GuardStepStatus;
  reason?: string;
  code?: string;
  durationMs: number;
}

export interface GuardReport {
  schemaVersion: 1;
  stage: GuardStage;
  outcome: GuardReportOutcome;
  hasWarnings: boolean;
  warningsCount: number;
  redactionsApplied: number;
  inputLength: number;
  outputLength: number;
  durationMs: number;
  failOpenTriggered: boolean;
  metadata?: Record<string, unknown>;
  finalReason?: string;
  finalCode?: string;
  steps: GuardStepReport[];
}

export interface GuardCheckResult {
  result: GuardResult;
  content: string;
}

export interface GuardRetrievalCheckResult extends GuardCheckResult {
  chunks?: string[];
}

/**
 * Top-level guardrails configuration.
 */
export interface GuardrailsConfig {
  input?: {
    injection?: boolean | InjectionConfig;
    encoding?: boolean | EncodingConfig;
    length?: boolean | LengthConfig;
    topic?: TopicConfig;
  };
  output?: {
    pii?: boolean | PiiConfig;
    secrets?: boolean | SecretsConfig;
    content?: boolean | ContentConfig;
    exfiltration?: boolean;
  };
  retrieval?: RetrievalConfig;
  tools?: ToolsConfig;
  classifier?: ClassifierConfig;
  /** Custom guards to add to the engine */
  customGuards?: Guard[];
  /** Throw on violation or just warn. Default: 'throw' */
  onViolation?: 'throw' | 'warn';
  /** If a guard itself crashes, allow the request through. Default: true */
  failOpen?: boolean;
  /** Optional logging callback for all guard events */
  logger?: (event: GuardEvent) => void;
  /** Optional aggregated report callback for each guard engine check */
  onReport?: (report: GuardReport) => void | Promise<void>;
}

/**
 * Events emitted during guard execution.
 */
export interface GuardEvent {
  type: 'violation' | 'warning' | 'error' | 'pass';
  guard: string;
  stage: GuardStage;
  code?: string;
  reason?: string;
  error?: unknown;
  durationMs: number;
}
