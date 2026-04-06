import { wrapLanguageModel } from 'ai';
import type {
  LanguageModelV3,
  LanguageModelV3Middleware,
  LanguageModelV3CallOptions,
  LanguageModelV3GenerateResult,
  LanguageModelV3StreamResult,
  LanguageModelV3Content,
  LanguageModelV3StreamPart,
} from '@ai-sdk/provider';
import type { GuardrailsConfig, AnyGuard } from './types.js';
import { GuardEngine } from './engine.js';
import { injectionGuard } from './guards/input/injection.js';
import { encodingGuard } from './guards/input/encoding.js';
import { lengthGuard } from './guards/input/length.js';
import { topicGuard } from './guards/input/topic.js';
import { piiGuard } from './guards/output/pii.js';
import { secretsGuard } from './guards/output/secrets.js';
import { contentGuard } from './guards/output/content.js';
import { exfiltrationGuard } from './guards/output/exfiltration.js';
import { llmClassifierGuard } from './guards/classifiers/llm.js';

/**
 * Build the list of guards from user configuration.
 * `true` means enable with defaults, object means enable with custom config.
 */
function buildGuards(config: GuardrailsConfig): AnyGuard[] {
  const guards: AnyGuard[] = [];

  // Input guards
  if (config.input) {
    const { injection, encoding, length, topic } = config.input;

    if (injection !== false && injection !== undefined) {
      guards.push(
        injectionGuard(injection === true ? undefined : injection),
      );
    }

    if (encoding !== false && encoding !== undefined) {
      guards.push(
        encodingGuard(encoding === true ? undefined : encoding),
      );
    }

    if (length !== false && length !== undefined) {
      guards.push(lengthGuard(length === true ? undefined : length));
    }

    if (topic) {
      guards.push(topicGuard(topic));
    }
  }

  // Output guards
  if (config.output) {
    const { pii, secrets, content, exfiltration } = config.output;

    if (pii !== false && pii !== undefined) {
      guards.push(piiGuard(pii === true ? undefined : pii));
    }

    if (secrets !== false && secrets !== undefined) {
      guards.push(secretsGuard(secrets === true ? undefined : secrets));
    }

    if (content !== false && content !== undefined) {
      guards.push(contentGuard(content === true ? undefined : content));
    }

    if (exfiltration) {
      guards.push(exfiltrationGuard());
    }
  }

  // LLM classifier (opt-in tier 3)
  if (config.classifier) {
    guards.push(llmClassifierGuard(config.classifier, 'input'));
    guards.push(llmClassifierGuard(config.classifier, 'output'));
  }

  // Custom guards
  if (config.customGuards) {
    guards.push(...config.customGuards);
  }

  return guards;
}

/**
 * Extract user message text from the AI SDK's LanguageModelV3Prompt format.
 * Handles both string content and structured content parts.
 */
function extractUserText(
  prompt: LanguageModelV3CallOptions['prompt'],
): string {
  const parts: string[] = [];
  for (const msg of prompt) {
    if (msg.role !== 'user') continue;
    if (Array.isArray(msg.content)) {
      for (const part of msg.content) {
        if (part.type === 'text') {
          parts.push(part.text);
        }
      }
    }
  }
  return parts.join('\n');
}

/**
 * Extract text from generated content parts.
 */
function extractOutputText(content: LanguageModelV3Content[]): string {
  return content
    .filter((c): c is LanguageModelV3Content & { type: 'text'; text: string } =>
      c.type === 'text' && 'text' in c,
    )
    .map((c) => c.text)
    .join('\n');
}

/**
 * Replace text content in generated parts with redacted text.
 */
function replaceTextContent(
  content: LanguageModelV3Content[],
  redactedText: string,
): LanguageModelV3Content[] {
  // If there's only one text part, replace it directly
  const textParts = content.filter((c) => c.type === 'text');
  if (textParts.length <= 1) {
    return content.map((c) =>
      c.type === 'text' && 'text' in c ? { ...c, text: redactedText } : c,
    );
  }

  // Multiple text parts — redaction was done on the concatenated output,
  // so replace the first text part and clear the rest
  let replaced = false;
  return content.map((c) => {
    if (c.type !== 'text' || !('text' in c)) return c;
    if (!replaced) {
      replaced = true;
      return { ...c, text: redactedText };
    }
    return { ...c, text: '' };
  });
}

/**
 * Replace streamed text chunks with a single sanitized payload in the first
 * text block, leaving later text blocks empty.
 */
function replaceTextStreamChunks(
  chunks: LanguageModelV3StreamPart[],
  redactedText: string,
): LanguageModelV3StreamPart[] {
  const firstTextStart = chunks.find((chunk) => chunk.type === 'text-start');
  if (!firstTextStart) return chunks;

  const firstTextId = firstTextStart.id;
  const replaced: LanguageModelV3StreamPart[] = [];
  let emittedRedacted = false;

  for (const chunk of chunks) {
    if (chunk.type === 'text-delta') {
      if (chunk.id !== firstTextId) {
        continue;
      }

      if (!emittedRedacted && redactedText.length > 0) {
        replaced.push({ ...chunk, delta: redactedText });
        emittedRedacted = true;
      }
      continue;
    }

    if (chunk.type === 'text-end' && chunk.id === firstTextId) {
      if (!emittedRedacted && redactedText.length > 0) {
        replaced.push({
          type: 'text-delta',
          id: firstTextId,
          delta: redactedText,
        });
        emittedRedacted = true;
      }
      replaced.push(chunk);
      continue;
    }

    replaced.push(chunk);
  }

  return replaced;
}

/**
 * Build a LanguageModelV3Middleware that runs guards on input and output.
 */
function buildMiddleware(engine: GuardEngine): LanguageModelV3Middleware {
  return {
    specificationVersion: 'v3',

    transformParams: async ({
      params,
    }: {
      type: 'generate' | 'stream';
      params: LanguageModelV3CallOptions;
      model: LanguageModelV3;
    }): Promise<LanguageModelV3CallOptions> => {
      const userText = extractUserText(params.prompt);
      if (userText) {
        await engine.check(userText, 'input');
      }
      return params;
    },

    wrapGenerate: async ({
      doGenerate,
    }: {
      doGenerate: () => PromiseLike<LanguageModelV3GenerateResult>;
      doStream: () => PromiseLike<LanguageModelV3StreamResult>;
      params: LanguageModelV3CallOptions;
      model: LanguageModelV3;
    }): Promise<LanguageModelV3GenerateResult> => {
      const result = await doGenerate();

      if (result.content && result.content.length > 0) {
        const outputText = extractOutputText(result.content);
        if (outputText) {
          const { result: guardResult, content: redactedText } =
            await engine.check(outputText, 'output');

          if (guardResult.action === 'redact') {
            return {
              ...result,
              content: replaceTextContent(result.content, redactedText),
            };
          }
        }
      }

      return result;
    },

    wrapStream: async ({
      doStream,
    }: {
      doGenerate: () => PromiseLike<LanguageModelV3GenerateResult>;
      doStream: () => PromiseLike<LanguageModelV3StreamResult>;
      params: LanguageModelV3CallOptions;
      model: LanguageModelV3;
    }): Promise<LanguageModelV3StreamResult> => {
      const { stream, ...rest } = await doStream();

      // For streaming, we buffer all chunks until completion so output guards
      // can block or redact before any text is emitted to the caller.
      let accumulatedText = '';
      const bufferedChunks: LanguageModelV3StreamPart[] = [];

      const guardedStream = stream.pipeThrough(
        new TransformStream({
          transform(chunk, controller) {
            bufferedChunks.push(chunk);
            if (chunk.type === 'text-delta' && 'delta' in chunk) {
              accumulatedText += chunk.delta;
            }
          },
          async flush(controller) {
            let outputChunks = bufferedChunks;

            if (accumulatedText) {
              // This throws GuardViolationError if onViolation='throw'
              const { result, content: redactedText } = await engine.check(
                accumulatedText,
                'output',
              );

              if (result.action === 'redact') {
                outputChunks = replaceTextStreamChunks(
                  bufferedChunks,
                  redactedText,
                );
              }
            }

            for (const chunk of outputChunks) {
              controller.enqueue(chunk);
            }
          },
        }),
      );

      return { stream: guardedStream, ...rest };
    },
  };
}

/**
 * Create a standalone guard engine for use without AI SDK middleware.
 *
 * @example
 * ```ts
 * const engine = createGuardEngine({
 *   input: { injection: true },
 *   output: { pii: { action: 'redact' } },
 * });
 * const { result } = await engine.check('user input', 'input');
 * ```
 */
export function createGuardEngine(config: GuardrailsConfig): GuardEngine {
  return new GuardEngine({
    guards: buildGuards(config),
    onViolation: config.onViolation ?? 'throw',
    failOpen: config.failOpen ?? true,
    logger: config.logger,
  });
}

/**
 * Wrap any Vercel AI SDK model with guardrails.
 *
 * Uses the official `wrapLanguageModel` from the AI SDK to create a proper
 * LanguageModelV3Middleware. Supports both `generateText` and `streamText`.
 *
 * @example
 * ```ts
 * import { withGuardrails } from '@mundabra/ai-guardrails';
 * import { anthropic } from '@ai-sdk/anthropic';
 *
 * const model = withGuardrails(anthropic('claude-haiku-4.5'), {
 *   input: { injection: true, encoding: true },
 *   output: { pii: { action: 'redact' }, secrets: true },
 * });
 *
 * // Works with generateText
 * const result = await generateText({ model, prompt: '...' });
 *
 * // Works with streamText — output guards run on stream finish
 * const stream = streamText({ model, prompt: '...' });
 * ```
 */
export function withGuardrails(
  model: LanguageModelV3,
  config?: GuardrailsConfig,
): LanguageModelV3 {
  const cfg: GuardrailsConfig = config ?? {
    input: { injection: true, encoding: true, length: true },
    output: { pii: true, secrets: true, exfiltration: true },
  };

  const engine = new GuardEngine({
    guards: buildGuards(cfg),
    onViolation: cfg.onViolation ?? 'throw',
    failOpen: cfg.failOpen ?? true,
    logger: cfg.logger,
  });

  return wrapLanguageModel({
    model,
    middleware: buildMiddleware(engine),
  });
}

export { buildGuards, buildMiddleware };
