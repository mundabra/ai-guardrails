import type { Guard, GuardResult, SecretsConfig } from '../../types.js';
import {
  AWS_ACCESS_KEY_RE,
  GITHUB_PAT_RE,
  GITHUB_OAUTH_RE,
  GITHUB_APP_RE,
  GITHUB_FINE_RE,
  GOOGLE_API_KEY_RE,
  STRIPE_SECRET_RE,
  SLACK_TOKEN_RE,
  JWT_RE,
  SSH_PRIVATE_KEY_RE,
  GENERIC_SECRET_RE,
} from '../../utils/patterns.js';

const DEFAULT_CONFIG: SecretsConfig = {
  types: [
    'aws',
    'github',
    'google',
    'stripe',
    'slack',
    'jwt',
    'ssh_key',
    'generic_high_entropy',
  ],
  action: 'block',
};

type SecretType = NonNullable<SecretsConfig['types']>[number];

interface SecretPattern {
  type: SecretType;
  patterns: RegExp[];
}

const SECRET_PATTERNS: SecretPattern[] = [
  { type: 'aws', patterns: [AWS_ACCESS_KEY_RE] },
  {
    type: 'github',
    patterns: [GITHUB_PAT_RE, GITHUB_OAUTH_RE, GITHUB_APP_RE, GITHUB_FINE_RE],
  },
  { type: 'google', patterns: [GOOGLE_API_KEY_RE] },
  { type: 'stripe', patterns: [STRIPE_SECRET_RE] },
  { type: 'slack', patterns: [SLACK_TOKEN_RE] },
  { type: 'jwt', patterns: [JWT_RE] },
  { type: 'ssh_key', patterns: [SSH_PRIVATE_KEY_RE] },
  { type: 'generic_high_entropy', patterns: [GENERIC_SECRET_RE] },
];

const SAFE_PUBLIC_TOKEN_PREFIXES = [
  'pk_live_',
  'pk_test_',
];

/**
 * Shannon entropy calculation for detecting high-entropy strings
 * (likely secrets/tokens).
 */
function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) {
    freq.set(c, (freq.get(c) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function checkSecrets(content: string, config: SecretsConfig): GuardResult {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const types = cfg.types!;
  const found: string[] = [];

  for (const { type, patterns } of SECRET_PATTERNS) {
    if (!types.includes(type)) continue;

    for (const pattern of patterns) {
      const re = new RegExp(pattern.source, pattern.flags.replace('g', '') + 'g');
      for (const match of content.matchAll(re)) {
        // For generic secrets, also check entropy
        if (type === 'generic_high_entropy') {
          const value = match[1] ?? match[0];
          if (
            SAFE_PUBLIC_TOKEN_PREFIXES.some((prefix) =>
              value.startsWith(prefix),
            )
          ) {
            continue;
          }
          if (shannonEntropy(value) < 4.0) continue;
        }
        found.push(type);
        break; // One match per type is enough
      }
    }
  }

  if (found.length === 0) return { action: 'allow' };

  const uniqueTypes = [...new Set(found)];

  if (cfg.action === 'redact') {
    let redacted = content;
    for (const { type, patterns } of SECRET_PATTERNS) {
      if (!uniqueTypes.includes(type)) continue;
      for (const pattern of patterns) {
        const re = new RegExp(pattern.source, pattern.flags.replace('g', '') + 'g');
        redacted = redacted.replace(re, '[SECRET_REDACTED]');
      }
    }
    return {
      action: 'redact',
      redacted,
      reason: `Secrets redacted: ${uniqueTypes.join(', ')}`,
      code: 'secret_redacted',
    };
  }

  return {
    action: 'block',
    reason: `Secrets detected: ${uniqueTypes.join(', ')}`,
    code: 'secret_detected',
  };
}

export function secretsGuard(config?: SecretsConfig): Guard<SecretsConfig> {
  return {
    name: 'secrets',
    stage: 'output',
    tier: 1,
    check: (_content, _context, cfg) => checkSecrets(_content, cfg),
    defaultConfig: { ...DEFAULT_CONFIG, ...config },
  };
}
