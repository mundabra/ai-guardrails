# Agent Guide

This document is the fastest way for an AI coding agent or a new maintainer to understand `@mundabra/ai-guardrails`.

## What This Package Does

`@mundabra/ai-guardrails` adds lightweight guardrails to Vercel AI SDK models and agentic applications.

Primary use cases:

- Block prompt injection before the model call.
- Redact or block sensitive model output.
- Add a small policy layer around AI SDK `generate` and `stream` flows.
- Reuse the same guards outside middleware through `GuardEngine`.

## Public API

- `withGuardrails(model, config?)`
- `createGuardEngine(config)`
- `buildMiddleware(engine)`
- `defineGuard(...)`
- Guard factories such as `injectionGuard()`, `piiGuard()`, `secretsGuard()`
- Utility exports: `normalize()`, `luhnCheck()`

The entrypoint is `src/index.ts`.

## Architecture

### Engine

`src/engine.ts` is the policy executor.

Execution model:

- Guards run by stage: `input` or `output`.
- Tiers run in order: `1`, `2`, `3`.
- Guards run sequentially within a tier so redactions can compose.
- Tier 2 and tier 3 default to `runOn: 'flagged'`.
- Tier 2 and tier 3 can opt into `runOn: 'always'`.

### Middleware

`src/middleware.ts` integrates with AI SDK `LanguageModelV3Middleware`.

Behavior:

- `transformParams` checks user text before the model call.
- `wrapGenerate` checks generated text and applies redactions in-place.
- `wrapStream` buffers streamed output, evaluates output guards after completion, then replays sanitized chunks.

Important tradeoff:

- Streaming safety is prioritized over token-by-token immediacy.
- If guards are active, stream output is delayed until completion.

### Guards

Input guards live under `src/guards/input/`.

- `injection`
- `encoding`
- `length`
- `topic`

Output guards live under `src/guards/output/`.

- `pii`
- `secrets`
- `content`
- `exfiltration`

Optional LLM judge:

- `src/guards/classifiers/llm.ts`

## Project Invariants

- ESM-only output.
- Node.js `>=20`.
- No extra runtime dependencies beyond peer deps.
- Docs should not claim behavior the code does not implement.
- Publishable Stripe keys are public and must not be flagged as secrets.
- Output redaction must be test-covered for both generate and stream paths.

## Test Strategy

Use these commands:

- `pnpm test`
- `pnpm typecheck`
- `pnpm build`

High-value tests:

- `tests/middleware.test.ts`: model wrapping behavior
- `tests/engine.test.ts`: tiering, fail-open/fail-closed, redaction composition
- `tests/guards/*.test.ts`: individual guard heuristics

If a change affects middleware behavior, add or update middleware tests first.

## Release Checklist

- Confirm README examples still compile conceptually against the public API.
- Run `pnpm test`, `pnpm typecheck`, and `pnpm build`.
- Check that streaming limitations and defaults are documented accurately.
- Keep `AGENTS.md`, `CLAUDE.md`, and `llms*.txt` aligned with the code.
