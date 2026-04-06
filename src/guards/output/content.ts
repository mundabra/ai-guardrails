import type { Guard, GuardResult, ContentConfig } from '../../types.js';

const DEFAULT_CONFIG: ContentConfig = {
  categories: [
    'violence',
    'illegal',
    'manipulation',
    'discrimination',
    'self_harm',
  ],
  threshold: 0.7,
};

type Category =
  | 'violence'
  | 'illegal'
  | 'manipulation'
  | 'discrimination'
  | 'self_harm';

interface CategoryPatterns {
  category: Category;
  patterns: Array<{ pattern: RegExp; weight: number }>;
}

const CATEGORY_PATTERNS: CategoryPatterns[] = [
  {
    category: 'violence',
    patterns: [
      { pattern: /\b(?:kill|murder|assassinate|execute)\s+(?:him|her|them|you|the)\b/i, weight: 0.7 },
      { pattern: /\bhow to (?:make|build|create) (?:a )?(?:bomb|explosive|weapon)\b/i, weight: 0.9 },
      { pattern: /\b(?:step[- ]by[- ]step|instructions? (?:for|to)|guide (?:for|to)) (?:harm|hurt|injure|attack)\b/i, weight: 0.8 },
      { pattern: /\b(?:torture|mutilate|dismember)\b/i, weight: 0.6 },
    ],
  },
  {
    category: 'illegal',
    patterns: [
      { pattern: /\bhow to (?:hack|breach|break into|compromise)\b/i, weight: 0.6 },
      { pattern: /\b(?:steal|forge|counterfeit) (?:credit card|identity|passport|money)\b/i, weight: 0.8 },
      { pattern: /\b(?:launder|laundering) (?:money|funds|proceeds)\b/i, weight: 0.8 },
      { pattern: /\b(?:synthesize|manufacture|cook) (?:meth|cocaine|heroin|fentanyl|drugs)\b/i, weight: 0.9 },
      { pattern: /\b(?:tax evasion|insider trading|wire fraud)\b/i, weight: 0.7 },
    ],
  },
  {
    category: 'manipulation',
    patterns: [
      { pattern: /\b(?:phishing|spear phishing) (?:email|template|message)\b/i, weight: 0.8 },
      { pattern: /\b(?:social engineering|pretexting) (?:script|template|attack)\b/i, weight: 0.7 },
      { pattern: /\bhow to (?:manipulate|deceive|trick|scam|defraud)\b/i, weight: 0.7 },
      { pattern: /\b(?:fake|fraudulent) (?:invoice|receipt|document|identity)\b/i, weight: 0.6 },
      { pattern: /\b(?:impersonate|impersonation|pretend to be) (?:a |an )?(?:official|officer|agent|representative)\b/i, weight: 0.7 },
    ],
  },
  {
    category: 'discrimination',
    patterns: [
      { pattern: /\b(?:racial|ethnic) (?:slur|epithet|insult)\b/i, weight: 0.7 },
      { pattern: /\b(?:inferior|superior) (?:race|gender|ethnicity)\b/i, weight: 0.7 },
      { pattern: /\b(?:hate speech|white supremac|ethnic cleansing)\b/i, weight: 0.9 },
    ],
  },
  {
    category: 'self_harm',
    patterns: [
      { pattern: /\b(?:how to|methods? (?:of|for)|ways? to) (?:commit )?suicide\b/i, weight: 0.9 },
      { pattern: /\b(?:self[- ]harm|cut(?:ting)? (?:myself|yourself|themselves))\b/i, weight: 0.8 },
      { pattern: /\b(?:painless|effective) (?:way|method) to (?:die|end (?:it|my life))\b/i, weight: 0.9 },
    ],
  },
];

function checkContent(content: string, config: ContentConfig): GuardResult {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const activeCategories = cfg.categories!;
  const matchedCategories = new Map<Category, number>();

  for (const { category, patterns } of CATEGORY_PATTERNS) {
    if (!activeCategories.includes(category)) continue;

    let categoryScore = 0;
    for (const { pattern, weight } of patterns) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        categoryScore += weight;
      }
    }

    if (categoryScore > 0) {
      matchedCategories.set(category, categoryScore);
    }
  }

  if (matchedCategories.size === 0) return { action: 'allow' };

  const maxScore = Math.max(...matchedCategories.values());
  const categories = [...matchedCategories.keys()];

  if (maxScore >= cfg.threshold!) {
    return {
      action: 'block',
      reason: `Harmful content detected: ${categories.join(', ')} (max score: ${maxScore.toFixed(2)})`,
      code: 'harmful_content',
    };
  }

  if (maxScore >= cfg.threshold! * 0.5) {
    return {
      action: 'warn',
      reason: `Possible harmful content: ${categories.join(', ')} (max score: ${maxScore.toFixed(2)})`,
      code: 'harmful_content_warning',
    };
  }

  return { action: 'allow' };
}

export function contentGuard(config?: ContentConfig): Guard<ContentConfig> {
  return {
    name: 'content',
    stage: 'output',
    tier: 1,
    check: (_content, _context, cfg) => checkContent(_content, cfg),
    defaultConfig: { ...DEFAULT_CONFIG, ...config },
  };
}
