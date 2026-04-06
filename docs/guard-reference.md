# Guard Reference

Quick reference for the built-in guards in `@mundabra/ai-guardrails`.

## Input Guards

### injection

- Stage: `input`
- Tier: `1`
- Purpose: detect prompt injection and jailbreak patterns
- Default threshold: `0.7`
- Notes: uses normalized text and weighted pattern scoring

### encoding

- Stage: `input`
- Tier: `1`
- Purpose: detect obfuscation and normalization-heavy input
- Default: block on significant multi-step normalization

### length

- Stage: `input`
- Tier: `1`
- Purpose: block oversized inputs
- Default max: `50_000` characters

### topic

- Stage: `input`
- Tier: `1`
- Purpose: allowlist or blocklist keyword topics
- Notes: keyword-based, word-boundary matching

## Output Guards

### pii

- Stage: `output`
- Tier: `1`
- Default action: `redact`
- Types: `ssn`, `credit_card`, `email`, `phone`, `ip`

### secrets

- Stage: `output`
- Tier: `1`
- Default action: `block`
- Detects: AWS access keys, GitHub tokens, Google API keys, Stripe secret keys, Slack tokens, JWTs, SSH private key headers, generic high-entropy secrets
- Does not treat Stripe publishable keys as secrets

### content

- Stage: `output`
- Tier: `1`
- Default threshold: `0.7`
- Categories: `violence`, `illegal`, `manipulation`, `discrimination`, `self_harm`

### exfiltration

- Stage: `output`
- Tier: `1`
- Purpose: block suspicious markdown and HTML image/link payloads

## Classifier Guard

### llm_classifier

- Stage: `input` or `output`
- Tier: `3`
- Default `runOn`: `flagged`
- Optional `runOn`: `always`
- Purpose: use a cheap model as a second-pass classifier

## Defaults

`withGuardrails(model)` currently enables:

- Input: `injection`, `encoding`, `length`
- Output: `pii`, `secrets`, `exfiltration`

It does not enable `content` or the LLM classifier by default.
