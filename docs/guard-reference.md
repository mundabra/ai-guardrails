# Guard Reference

Quick reference for the built-in guards in `@mundabra/ai-guardrails`.

The same built-in guards can also be reused on `retrieval`, `tool_input`, and
`tool_output` stages through top-level config. The guard factories themselves
still expose their original stage defaults.

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

It also does not enable any retrieval or tool payload rails by default.

## Reports

Every engine check can emit a metadata-only `GuardReport` through `onReport`.

- Reports contain stage, outcome, counts, timings, and per-guard step details
- Outcome can be `allow`, `redact`, `block`, or `error`
- Reports do not include raw input or output content by default
- Reports are intended for logging, CI export, and downstream evaluation tools
