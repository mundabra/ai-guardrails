// Core
export { GuardEngine } from './engine.js';
export type { GuardEngineOptions } from './engine.js';
export { GuardViolationError, GuardExecutionError } from './errors.js';

// Types
export type {
  Guard,
  AnyGuard,
  GuardResult,
  GuardStage,
  GuardContext,
  GuardRunOn,
  GuardEvent,
  GuardReport,
  GuardStepReport,
  GuardCheckResult,
  GuardRetrievalCheckResult,
  GuardrailsConfig,
  InjectionConfig,
  EncodingConfig,
  LengthConfig,
  TopicConfig,
  PiiConfig,
  SecretsConfig,
  ContentConfig,
  ClassifierConfig,
  RetrievalConfig,
  ToolInputConfig,
  ToolOutputConfig,
  ToolsConfig,
} from './types.js';

// Middleware
export { withGuardrails, createGuardEngine, buildMiddleware } from './middleware.js';

// Guards (for standalone use)
export {
  injectionGuard,
  encodingGuard,
  lengthGuard,
  topicGuard,
  piiGuard,
  secretsGuard,
  contentGuard,
  exfiltrationGuard,
  llmClassifierGuard,
} from './guards/index.js';

// Utilities (for advanced use)
export { normalize } from './utils/normalize.js';
export { luhnCheck } from './utils/luhn.js';

/**
 * Helper to define a custom guard with proper typing.
 */
export function defineGuard<TConfig = Record<string, never>>(
  guard: {
    name: string;
    stage: import('./types.js').GuardStage;
    tier?: 1 | 2 | 3;
    runOn?: import('./types.js').GuardRunOn;
    check: (
      content: string,
      context: import('./types.js').GuardContext,
      config: TConfig,
    ) => Promise<import('./types.js').GuardResult> | import('./types.js').GuardResult;
    defaultConfig?: TConfig;
  },
): import('./types.js').Guard<TConfig> {
  return {
    tier: 1,
    defaultConfig: {} as TConfig,
    ...guard,
  };
}
