import type { Guard, GuardResult, TopicConfig } from '../../types.js';

const DEFAULT_CONFIG: TopicConfig = {
  allowedTopics: [],
  blockedTopics: [],
};

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function matchesWord(text: string, word: string): boolean {
  const pattern = new RegExp(`\\b${escapeRegex(word.toLowerCase())}\\b`);
  return pattern.test(text);
}

function checkTopic(content: string, config: TopicConfig): GuardResult {
  const lower = content.toLowerCase();

  // Check blocked topics first
  if (config.blockedTopics) {
    for (const topic of config.blockedTopics) {
      if (matchesWord(lower, topic)) {
        return {
          action: 'block',
          reason: `Blocked topic detected: "${topic}"`,
          code: 'blocked_topic',
        };
      }
    }
  }

  // If allowed topics are specified, check that at least one matches
  if (config.allowedTopics.length > 0) {
    const hasAllowedTopic = config.allowedTopics.some((topic) =>
      matchesWord(lower, topic),
    );
    if (!hasAllowedTopic) {
      return {
        action: 'warn',
        reason: 'Input does not match any allowed topic',
        code: 'off_topic',
      };
    }
  }

  return { action: 'allow' };
}

export function topicGuard(config: TopicConfig): Guard<TopicConfig> {
  return {
    name: 'topic',
    stage: 'input',
    tier: 1,
    check: (_content, _context, cfg) => checkTopic(_content, cfg),
    defaultConfig: { ...DEFAULT_CONFIG, ...config },
  };
}
