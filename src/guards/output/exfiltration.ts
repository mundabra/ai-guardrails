import type { Guard, GuardResult } from '../../types.js';
import {
  MARKDOWN_IMAGE_RE,
  MARKDOWN_LINK_RE,
  HTML_IMG_RE,
} from '../../utils/patterns.js';

// Domains commonly used for data exfiltration via image/link injection
const SUSPICIOUS_PATTERNS = [
  // Long query strings (data encoded in URL params)
  /\?[^)]{100,}/,
  // Base64-like segments in query params
  /[?&][^=]+=(?:[A-Za-z0-9+/]{30,})/,
  // Hex-encoded data in URLs
  /[?&][^=]+=(?:[0-9a-fA-F]{30,})/,
  // Webhook/callback services commonly used in exfiltration
  /(?:webhook\.site|requestbin|pipedream|hookbin|burpcollaborator|interact\.sh)/i,
];

function checkExfiltration(content: string): GuardResult {
  // Check markdown images
  for (const match of content.matchAll(
    new RegExp(MARKDOWN_IMAGE_RE.source, 'g'),
  )) {
    const url = match[2]!;
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(url)) {
        return {
          action: 'block',
          reason: `Data exfiltration attempt via markdown image: ${url.slice(0, 80)}...`,
          code: 'exfiltration_image',
        };
      }
    }
  }

  // Check markdown links with suspicious URLs
  for (const match of content.matchAll(
    new RegExp(MARKDOWN_LINK_RE.source, 'g'),
  )) {
    const url = match[2]!;
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(url)) {
        return {
          action: 'block',
          reason: `Data exfiltration attempt via markdown link: ${url.slice(0, 80)}...`,
          code: 'exfiltration_link',
        };
      }
    }
  }

  // Check HTML img tags
  for (const match of content.matchAll(
    new RegExp(HTML_IMG_RE.source, 'gi'),
  )) {
    const url = match[1]!;
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(url)) {
        return {
          action: 'block',
          reason: `Data exfiltration attempt via HTML image: ${url.slice(0, 80)}...`,
          code: 'exfiltration_html',
        };
      }
    }
  }

  return { action: 'allow' };
}

export function exfiltrationGuard(): Guard<Record<string, never>> {
  return {
    name: 'exfiltration',
    stage: 'output',
    tier: 1,
    check: (content) => checkExfiltration(content),
    defaultConfig: {},
  };
}
