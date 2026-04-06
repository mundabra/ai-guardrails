import type { Guard, GuardResult, EncodingConfig } from '../../types.js';
import { normalize } from '../../utils/normalize.js';

const DEFAULT_CONFIG: EncodingConfig = {
  blockOnNormalization: true,
};

function checkEncoding(
  content: string,
  config: EncodingConfig,
): GuardResult {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const { wasNormalized, steps } = normalize(content);

  // Significant normalization = encoding attack attempt
  const suspiciousSteps = steps.filter(
    (s) => !['lowercase', 'whitespace'].includes(s),
  );

  if (suspiciousSteps.length >= 2 && cfg.blockOnNormalization) {
    return {
      action: 'block',
      reason: `Encoding attack detected (steps: ${suspiciousSteps.join(', ')})`,
      code: 'encoding_attack',
    };
  }

  if (wasNormalized && suspiciousSteps.length >= 1) {
    return {
      action: 'warn',
      reason: `Input required normalization (steps: ${suspiciousSteps.join(', ')})`,
      code: 'encoding_warning',
    };
  }

  return { action: 'allow' };
}

export function encodingGuard(
  config?: EncodingConfig,
): Guard<EncodingConfig> {
  return {
    name: 'encoding',
    stage: 'input',
    tier: 1,
    check: (_content, _context, cfg) => checkEncoding(_content, cfg),
    defaultConfig: { ...DEFAULT_CONFIG, ...config },
  };
}
