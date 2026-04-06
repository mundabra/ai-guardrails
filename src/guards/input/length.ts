import type { Guard, GuardResult, LengthConfig } from '../../types.js';

const DEFAULT_CONFIG: LengthConfig = {
  max: 50_000,
};

function checkLength(content: string, config: LengthConfig): GuardResult {
  const cfg = { ...DEFAULT_CONFIG, ...config };

  if (content.length > cfg.max!) {
    return {
      action: 'block',
      reason: `Input exceeds maximum length (${content.length} > ${cfg.max})`,
      code: 'input_too_long',
    };
  }

  return { action: 'allow' };
}

export function lengthGuard(config?: LengthConfig): Guard<LengthConfig> {
  return {
    name: 'length',
    stage: 'input',
    tier: 1,
    check: (_content, _context, cfg) => checkLength(_content, cfg),
    defaultConfig: { ...DEFAULT_CONFIG, ...config },
  };
}
