# Security Policy

## Scope

`@mundabra/ai-guardrails` is a lightweight guardrails library. It helps reduce common classes of unsafe AI input and output, but it is not a complete application security boundary.

See [DISCLAIMER.md](./DISCLAIMER.md) for the broader usage and risk disclaimer.

Do not rely on this package alone for:

- full moderation coverage
- hallucination detection
- authorization
- sandboxing
- secret storage
- prompt confidentiality guarantees

## Reporting

If you believe you found a security issue, please avoid opening a public issue with exploit details.

Report privately to:

- `mundabra@gmail.com`

Include:

- affected version or commit
- reproduction steps
- impact assessment
- any suggested mitigation

## Supported Hardening Expectations

Security-sensitive behavior that should remain covered:

- input guard execution before model calls
- output redaction in both generate and stream flows
- deterministic guard composition
- no false-positive blocking of known public token formats such as Stripe publishable keys
- accurate documentation of defaults and limitations

## Disclosure

I will aim to acknowledge reports promptly and coordinate a fix before public disclosure when reasonable.
