import type { Guard, GuardResult, PiiConfig } from '../../types.js';
import {
  SSN_RE,
  CREDIT_CARD_RE,
  CREDIT_CARD_AMEX_RE,
  EMAIL_RE,
  PHONE_RE,
  IPV4_RE,
} from '../../utils/patterns.js';
import { luhnCheck } from '../../utils/luhn.js';

const DEFAULT_CONFIG: PiiConfig = {
  types: ['ssn', 'credit_card', 'email', 'phone', 'ip'],
  action: 'redact',
  redactWith: '[REDACTED]',
  allowlist: [],
};

interface PiiMatch {
  type: string;
  value: string;
  index: number;
}

function isValidSsn(ssn: string): boolean {
  const digits = ssn.replace(/\D/g, '');
  const area = parseInt(digits.slice(0, 3), 10);
  const group = parseInt(digits.slice(3, 5), 10);
  const serial = parseInt(digits.slice(5), 10);
  // Invalid area numbers
  if (area === 0 || area === 666 || area >= 900) return false;
  if (group === 0) return false;
  if (serial === 0) return false;
  return true;
}

function isValidEmail(email: string): boolean {
  const [localPart] = email.split('@');
  if (!localPart) return false;
  if (localPart.startsWith('.') || localPart.endsWith('.')) return false;
  if (/\.{2,}/.test(localPart)) return false;
  return true;
}

function isValidIpv4(ip: string): boolean {
  return ip.split('.').every((octet) => {
    const n = parseInt(octet, 10);
    return n >= 0 && n <= 255;
  });
}

function findPii(content: string, config: PiiConfig): PiiMatch[] {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const matches: PiiMatch[] = [];
  const types = cfg.types!;

  if (types.includes('ssn')) {
    for (const match of content.matchAll(new RegExp(SSN_RE.source, 'g'))) {
      if (isValidSsn(match[0]) && !cfg.allowlist?.includes(match[0])) {
        matches.push({ type: 'ssn', value: match[0], index: match.index! });
      }
    }
  }

  if (types.includes('credit_card')) {
    for (const re of [CREDIT_CARD_RE, CREDIT_CARD_AMEX_RE]) {
      for (const match of content.matchAll(new RegExp(re.source, 'g'))) {
        const digits = match[0].replace(/\D/g, '');
        if (luhnCheck(digits) && !cfg.allowlist?.includes(match[0])) {
          matches.push({ type: 'credit_card', value: match[0], index: match.index! });
        }
      }
    }
  }

  if (types.includes('email')) {
    for (const match of content.matchAll(new RegExp(EMAIL_RE.source, 'g'))) {
      if (isValidEmail(match[0]) && !cfg.allowlist?.includes(match[0])) {
        matches.push({ type: 'email', value: match[0], index: match.index! });
      }
    }
  }

  if (types.includes('phone')) {
    for (const match of content.matchAll(new RegExp(PHONE_RE.source, 'g'))) {
      const digits = match[0].replace(/\D/g, '');
      // Must have at least 10 digits to be a real phone number
      if (digits.length >= 10 && !cfg.allowlist?.includes(match[0])) {
        matches.push({ type: 'phone', value: match[0], index: match.index! });
      }
    }
  }

  if (types.includes('ip')) {
    for (const match of content.matchAll(new RegExp(IPV4_RE.source, 'g'))) {
      if (isValidIpv4(match[0]) && !cfg.allowlist?.includes(match[0])) {
        matches.push({ type: 'ip', value: match[0], index: match.index! });
      }
    }
  }

  return matches;
}

function checkPii(content: string, config: PiiConfig): GuardResult {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const matches = findPii(content, cfg);

  if (matches.length === 0) return { action: 'allow' };

  const types = [...new Set(matches.map((m) => m.type))];

  if (cfg.action === 'block') {
    return {
      action: 'block',
      reason: `PII detected: ${types.join(', ')} (${matches.length} instance${matches.length > 1 ? 's' : ''})`,
      code: 'pii_detected',
    };
  }

  // Redact — replace matches from end to start to preserve indices
  let redacted = content;
  const sortedMatches = [...matches].sort((a, b) => b.index - a.index);
  for (const match of sortedMatches) {
    redacted =
      redacted.slice(0, match.index) +
      cfg.redactWith! +
      redacted.slice(match.index + match.value.length);
  }

  return {
    action: 'redact',
    redacted,
    reason: `PII redacted: ${types.join(', ')} (${matches.length} instance${matches.length > 1 ? 's' : ''})`,
    code: 'pii_redacted',
  };
}

export function piiGuard(config?: PiiConfig): Guard<PiiConfig> {
  return {
    name: 'pii',
    stage: 'output',
    tier: 1,
    check: (_content, _context, cfg) => checkPii(_content, cfg),
    defaultConfig: { ...DEFAULT_CONFIG, ...config },
  };
}
