# Mundabra AI Guardrails

Shared instructions for coding agents working in this repository.

## Project Summary

`@mundabra/ai-guardrails` is a small TypeScript guardrails package for the Vercel AI SDK.

It provides:

- Input guards for prompt injection, encoding attacks, length, and topic control.
- Output guards for PII, secrets, content safety, and exfiltration.
- Middleware via `wrapLanguageModel`.
- A standalone `GuardEngine` for non-middleware usage.

## Stack

- TypeScript
- ESM-only package output
- Node.js `>=20`
- `pnpm`
- `vitest`
- Peer deps: `ai`, `@ai-sdk/provider`

## Commands

- Install: `pnpm install`
- Check everything: `pnpm check`
- Test: `pnpm test`
- Typecheck: `pnpm typecheck`
- Build: `pnpm build`

Run `pnpm check` before finishing behavior-changing work.

## Key Files

- `src/index.ts`: public exports
- `src/middleware.ts`: AI SDK middleware integration
- `src/engine.ts`: tiered guard execution engine
- `src/types.ts`: public types and config contracts
- `src/guards/input/*`: input guards
- `src/guards/output/*`: output guards
- `src/guards/classifiers/llm.ts`: optional LLM judge
- `src/utils/*`: normalization, patterns, validation helpers
- `tests/middleware.test.ts`: middleware regression coverage
- `tests/engine.test.ts`: engine semantics

## Important Invariants

- Preserve zero external runtime dependencies beyond peer deps.
- Keep the public API small and stable.
- `GuardEngine` executes guards in tier order.
- Tier 2 and tier 3 guards run only after earlier warnings unless `runOn: 'always'` is set.
- Redactions must compose deterministically across multiple guards.
- Streaming middleware buffers output until completion so block/redact decisions happen before text is released.
- Stripe publishable keys such as `pk_live_...` and `pk_test_...` must not be treated as secrets.
- Docs must match real behavior, especially defaults and streaming semantics.

## Change Policy

- Add or update tests for every bug fix or contract change.
- If you change behavior, update `README.md` and the LLM-facing docs.
- Prefer small focused diffs over broad refactors.
- Keep examples compatible with the current public API.

## Public Open Source Positioning

This repository should be easy for both humans and agents to inspect quickly.

When adding new documentation, prefer:

- Short markdown files with explicit headings.
- Concrete commands.
- Stable file paths.
- Clear statements of defaults, limitations, and invariants.

## Related Docs

- `LICENSE`: code license
- `DISCLAIMER.md`: usage and risk disclaimer
- `CONTRIBUTING.md`: contribution workflow
- `SECURITY.md`: disclosure path and security scope
- `docs/agent-guide.md`: architecture
