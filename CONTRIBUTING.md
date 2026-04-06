# Contributing

Thanks for contributing to `@mundabra/ai-guardrails`.

This repository is intentionally small. Changes should stay focused, test-backed, and easy to review.

## Start Here

- Read [README.md](./README.md) for the package overview.
- Read [AGENTS.md](./AGENTS.md) for repository invariants and working rules.
- Read [docs/agent-guide.md](./docs/agent-guide.md) if you are changing engine or middleware behavior.
- Read [DISCLAIMER.md](./DISCLAIMER.md) and [SECURITY.md](./SECURITY.md) before changing public positioning or safety claims.

## Development

Requirements:

- Node.js `>=20`
- `pnpm`

Install dependencies:

```bash
pnpm install
```

Run the full local verification suite:

```bash
pnpm check
```

Individual commands:

```bash
pnpm test
pnpm typecheck
pnpm build
```

## Contribution Rules

- Keep diffs narrow and intentional.
- Add or update tests for behavior changes.
- Update docs when defaults, limitations, or public contracts change.
- Preserve the package's low-dependency design.
- Do not expand the public API unless the change is clearly justified.

## High-Risk Areas

Take extra care when modifying:

- `src/engine.ts`
- `src/middleware.ts`
- `src/types.ts`
- `src/guards/output/secrets.ts`

These files define behavior that downstream consumers will rely on directly.

## Before Opening a PR

- Run `pnpm check`
- Re-read changed README examples for accuracy
- Confirm stream behavior and guard defaults are documented correctly
- Confirm Stripe publishable keys are not treated as secrets

## Notes For AI Coding Agents

- Start with `AGENTS.md`
- Use `tests/middleware.test.ts` for middleware regressions
- Use `tests/engine.test.ts` for tiering and fail-open/fail-closed changes
- Prefer updating an existing doc instead of creating overlapping docs
