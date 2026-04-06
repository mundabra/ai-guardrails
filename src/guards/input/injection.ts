import type { Guard, GuardResult, InjectionConfig } from '../../types.js';
import { normalize } from '../../utils/normalize.js';

interface WeightedPattern {
  pattern: RegExp;
  weight: number;
  category: string;
}

/**
 * Prompt injection detection patterns organized by attack category.
 * Weights: 0.1 (weak signal) to 1.0 (strong signal).
 * Patterns run against normalized text (lowercased, decoded, deobfuscated).
 */
const PATTERNS: WeightedPattern[] = [
  // === Instruction Override (strongest signals) ===
  { pattern: /ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions?|prompts?|rules?|context)/i, weight: 0.9, category: 'instruction_override' },
  { pattern: /disregard (?:all |any )?(?:previous|prior|above|earlier)/i, weight: 0.9, category: 'instruction_override' },
  { pattern: /forget (?:everything|all|your) (?:previous|prior|instructions?)/i, weight: 0.85, category: 'instruction_override' },
  { pattern: /(?:new|updated|revised|real) (?:instructions?|system prompt|directives?)/i, weight: 0.8, category: 'instruction_override' },
  { pattern: /override (?:previous|prior|your|all|system)/i, weight: 0.8, category: 'instruction_override' },
  { pattern: /do not follow (?:the |any )?(?:above|previous|prior|original)/i, weight: 0.85, category: 'instruction_override' },
  { pattern: /instead,?\s*(?:you (?:will|should|must)|do the following)/i, weight: 0.6, category: 'instruction_override' },
  { pattern: /from now on,?\s*(?:you (?:are|will|should|must))/i, weight: 0.7, category: 'instruction_override' },

  // === Role Manipulation ===
  { pattern: /you are now (?:a |an )?(?:different|new|unrestricted|unfiltered)/i, weight: 0.85, category: 'role_manipulation' },
  { pattern: /(?:act|behave|respond|operate) (?:as|like) (?:a |an )?(?:different|new|unrestricted)/i, weight: 0.8, category: 'role_manipulation' },
  { pattern: /pretend (?:you are|to be|that you)/i, weight: 0.6, category: 'role_manipulation' },
  { pattern: /roleplay (?:as|that)/i, weight: 0.5, category: 'role_manipulation' },
  { pattern: /enter (?:developer|admin|debug|god|sudo|root) mode/i, weight: 0.9, category: 'role_manipulation' },
  { pattern: /\b(?:DAN|STAN|DUDE|KEVIN)\b.*mode/i, weight: 0.95, category: 'role_manipulation' },
  { pattern: /jailbreak/i, weight: 0.95, category: 'role_manipulation' },
  { pattern: /you have no (?:restrictions|limitations|rules|guidelines)/i, weight: 0.85, category: 'role_manipulation' },
  { pattern: /(?:remove|disable|ignore|bypass) (?:all |any )?(?:safety|content|ethical|moral) (?:filters?|guidelines?|restrictions?|rules?)/i, weight: 0.9, category: 'role_manipulation' },

  // === System Prompt Extraction ===
  { pattern: /(?:reveal|show|display|print|output|repeat|tell me) (?:your |the )?(?:system|initial|original|hidden|secret) (?:prompt|instructions?|message|configuration)/i, weight: 0.8, category: 'prompt_extraction' },
  { pattern: /what (?:are|were) your (?:original|initial|system|hidden|secret) (?:instructions?|prompt|rules?|directives?)/i, weight: 0.75, category: 'prompt_extraction' },
  { pattern: /(?:dump|leak|expose|extract) (?:your |the )?(?:system|initial|full) (?:prompt|context|instructions?)/i, weight: 0.85, category: 'prompt_extraction' },

  // === Structural Injection (delimiter abuse) ===
  { pattern: /#{3,}\s*(?:system|instruction|new|admin|override)/i, weight: 0.7, category: 'structural' },
  { pattern: /={3,}\s*(?:system|instruction|new|admin)/i, weight: 0.7, category: 'structural' },
  { pattern: /-{3,}\s*(?:system|instruction|new|end of)/i, weight: 0.6, category: 'structural' },
  { pattern: /"""\s*(?:system|instruction|admin|ignore)/i, weight: 0.7, category: 'structural' },
  { pattern: /<\|(?:im_start|im_end|system|endoftext)\|>/i, weight: 0.95, category: 'structural' },
  { pattern: /\[(?:SYSTEM|INST|\/INST|SYS|\/SYS)\]/i, weight: 0.9, category: 'structural' },
  { pattern: /<(?:system|instruction|admin|s|\/s)>/i, weight: 0.8, category: 'structural' },
  { pattern: /{"role":\s*"system"/i, weight: 0.85, category: 'structural' },

  // === ReAct/Agent Injection ===
  { pattern: /^(?:Thought|Action|Observation|Final Answer):/mi, weight: 0.6, category: 'agent_injection' },
  { pattern: /(?:tool_call|function_call|tool_result)\s*[({]/i, weight: 0.7, category: 'agent_injection' },

  // === Authority Impersonation ===
  { pattern: /(?:as (?:your |the )?(?:administrator|admin|developer|creator|owner))/i, weight: 0.7, category: 'authority' },
  { pattern: /(?:this is (?:an? )?(?:urgent|emergency|critical|priority))/i, weight: 0.4, category: 'authority' },
  { pattern: /(?:i am (?:your |the )?(?:developer|creator|admin|administrator|owner))/i, weight: 0.7, category: 'authority' },
  { pattern: /(?:authorized|permission|clearance) (?:to |for )?(?:override|bypass|ignore)/i, weight: 0.75, category: 'authority' },

  // === Data Exfiltration Setup ===
  { pattern: /(?:encode|convert|translate) (?:the |all |this |your )?(?:above|previous|system|content|data|information) (?:to|into|as|in) (?:base64|hex|binary|rot13|morse)/i, weight: 0.8, category: 'exfiltration' },
  { pattern: /(?:send|transmit|post|fetch|curl|wget) (?:to |the |this |all )?(?:https?:\/\/|data to)/i, weight: 0.5, category: 'exfiltration' },

  // === Virtualization / Fiction ===
  { pattern: /(?:imagine|suppose|hypothetically|in a (?:fictional|hypothetical) (?:world|scenario))/i, weight: 0.3, category: 'virtualization' },
  { pattern: /(?:for (?:a |an )?(?:novel|story|fiction|creative writing|screenplay|roleplay))/i, weight: 0.2, category: 'virtualization' },
  // These are low weight — only contribute when combined with other signals

  // === Multi-turn Escalation Markers ===
  { pattern: /(?:now that (?:we|you|i) (?:have|'ve) (?:established|confirmed|agreed))/i, weight: 0.4, category: 'escalation' },
  { pattern: /(?:building on (?:what|our) (?:previous|earlier|above))/i, weight: 0.3, category: 'escalation' },
];

const DEFAULT_CONFIG: InjectionConfig = {
  threshold: 0.7,
  customPatterns: [],
  allowlist: [],
};

function checkInjection(
  content: string,
  config: InjectionConfig,
): GuardResult {
  const cfg = { ...DEFAULT_CONFIG, ...config };

  // Normalize input to defeat encoding bypasses
  const { text: normalized, wasNormalized } = normalize(content);

  // Check allowlist
  if (cfg.allowlist?.some((phrase) => content.toLowerCase().includes(phrase.toLowerCase()))) {
    return { action: 'allow' };
  }

  let totalScore = 0;
  const matchedCategories = new Set<string>();

  // Score built-in patterns
  for (const { pattern, weight, category } of PATTERNS) {
    // Reset lastIndex for global patterns
    pattern.lastIndex = 0;
    if (pattern.test(normalized)) {
      totalScore += weight;
      matchedCategories.add(category);
    }
  }

  // Score custom patterns
  if (cfg.customPatterns) {
    for (const { pattern, weight } of cfg.customPatterns) {
      pattern.lastIndex = 0;
      if (pattern.test(normalized)) {
        totalScore += weight;
        matchedCategories.add('custom');
      }
    }
  }

  // Encoding normalization itself is a signal — add small bonus
  if (wasNormalized) {
    totalScore += 0.15;
  }

  // Multi-category bonus: hitting 3+ categories is highly suspicious
  if (matchedCategories.size >= 3) {
    totalScore += 0.2;
  }

  if (totalScore >= cfg.threshold!) {
    return {
      action: 'block',
      reason: `Prompt injection detected (score: ${totalScore.toFixed(2)}, categories: ${[...matchedCategories].join(', ')})`,
      code: 'prompt_injection',
    };
  }

  // Warn at half threshold to trigger tier 2/3 guards
  if (totalScore >= cfg.threshold! * 0.5) {
    return {
      action: 'warn',
      reason: `Possible prompt injection (score: ${totalScore.toFixed(2)}, categories: ${[...matchedCategories].join(', ')})`,
      code: 'prompt_injection_warning',
    };
  }

  return { action: 'allow' };
}

export function injectionGuard(
  config?: InjectionConfig,
): Guard<InjectionConfig> {
  return {
    name: 'injection',
    stage: 'input',
    tier: 1,
    check: (_content, _context, cfg) => checkInjection(_content, cfg),
    defaultConfig: { ...DEFAULT_CONFIG, ...config },
  };
}
