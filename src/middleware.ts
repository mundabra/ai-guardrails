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
 * Build a reversible joined representation of text segments so redacted text
 * can be mapped back to the original text-part structure.
 */
function createTextPartition(segments: string[]): {
  joinedText: string;
  restoreSegments: (redactedText: string) => string[] | null;
} {
  if (segments.length <= 1) {
    return {
      joinedText: segments[0] ?? '',
      restoreSegments: (redactedText) => [redactedText],
    };
  }

  let counter = 0;
  let separator = '';
  do {
    separator =
      `\u0000__MUNDABRA_AI_GUARDRAILS_BOUNDARY_${counter}__\u0000`;
    counter += 1;
  } while (segments.some((segment) => segment.includes(separator)));

  return {
    joinedText: segments.join(separator),
    restoreSegments: (redactedText) => {
      const restored = redactedText.split(separator);
      return restored.length === segments.length ? restored : null;
    },
  };
}

/**
 * Replace text content in generated parts with redacted text while preserving
 * the original part ordering.
 */
function replaceTextContent(
  content: LanguageModelV3Content[],
  redactedSegments: string[],
): LanguageModelV3Content[] {
  let textIndex = 0;
  return content.map((c) => {
    if (c.type !== 'text' || !('text' in c)) return c;
    const text = redactedSegments[textIndex] ?? '';
    textIndex += 1;
    return { ...c, text };
  });
}

/**
 * Collect streamed text blocks in output order.
 */
function collectTextStreamBlocks(
  chunks: LanguageModelV3StreamPart[],
): Array<{ id: string; text: string }> {
  const blocks: Array<{ id: string; text: string }> = [];
  const blockIndex = new Map<string, number>();

  for (const chunk of chunks) {
    if (chunk.type !== 'text-start' && chunk.type !== 'text-delta') {
      continue;
    }

    if (!blockIndex.has(chunk.id)) {
      blockIndex.set(chunk.id, blocks.length);
      blocks.push({ id: chunk.id, text: '' });
    }

    if (chunk.type === 'text-delta') {
      const index = blockIndex.get(chunk.id)!;
      blocks[index]!.text += chunk.delta;
    }
  }

  return blocks;
}

/**
 * Replace streamed text chunks while preserving the original stream ordering.
 */
function replaceTextStreamChunks(
  chunks: LanguageModelV3StreamPart[],
  redactedSegments: string[],
): LanguageModelV3StreamPart[] {
  const blocks = collectTextStreamBlocks(chunks);
  if (blocks.length === 0) return chunks;

  const redactedById = new Map(
    blocks.map((block, index) => [block.id, redactedSegments[index] ?? '']),
  );
  const replaced: LanguageModelV3StreamPart[] = [];
  const emitted = new Set<string>();

  for (const chunk of chunks) {
    if (chunk.type === 'text-delta') {
      if (!emitted.has(chunk.id)) {
        const redactedText = redactedById.get(chunk.id) ?? '';
        if (redactedText.length > 0) {
          replaced.push({ ...chunk, delta: redactedText });
        }
        emitted.add(chunk.id);
      }
      continue;
    }

    if (chunk.type === 'text-end') {
      if (!emitted.has(chunk.id)) {
        const redactedText = redactedById.get(chunk.id) ?? '';
        if (redactedText.length > 0) {
          replaced.push({
            type: 'text-delta',
            id: chunk.id,
            delta: redactedText,
          });
        }
        emitted.add(chunk.id);
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
        const textSegments = result.content
          .filter((c): c is LanguageModelV3Content & { type: 'text'; text: string } =>
            c.type === 'text' && 'text' in c,
          )
          .map((c) => c.text);
        const { joinedText, restoreSegments } = createTextPartition(
          textSegments,
        );

        if (joinedText) {
          const { result: guardResult, content: redactedText } =
            await engine.check(joinedText, 'output');

          if (guardResult.action === 'redact') {
            const redactedSegments = restoreSegments(redactedText);
            return {
              ...result,
              content: replaceTextContent(
                result.content,
                redactedSegments ?? [redactedText, ...textSegments.slice(1)],
              ),
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
      const bufferedChunks: LanguageModelV3StreamPart[] = [];

      const guardedStream = stream.pipeThrough(
        new TransformStream({
          transform(chunk, controller) {
            bufferedChunks.push(chunk);
          },
          async flush(controller) {
            let outputChunks = bufferedChunks;
            const textBlocks = collectTextStreamBlocks(bufferedChunks);
            const { joinedText, restoreSegments } = createTextPartition(
              textBlocks.map((block) => block.text),
            );

            if (joinedText) {
              // This throws GuardViolationError if onViolation='throw'
              const { result, content: redactedText } = await engine.check(
                joinedText,
                'output',
              );

              if (result.action === 'redact') {
                const redactedSegments = restoreSegments(redactedText);
                outputChunks = replaceTextStreamChunks(
                  bufferedChunks,
                  redactedSegments ?? [redactedText, ...textBlocks.slice(1).map((block) => block.text)],
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
