/**
 * 13-step input normalization pipeline.
 *
 * Encoding bypass attacks achieve 97.5% success rate without normalization.
 * This pipeline decodes, deobfuscates, and normalizes text before guards
 * inspect it — closing the biggest single gap in prompt injection defense.
 */

// Zero-width and invisible Unicode characters
const ZERO_WIDTH_RE =
  /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u2060\u2061\u2062\u2063\u2064\u180E]/g;

// Invisible formatting (RTL override, bidi marks, etc.)
const INVISIBLE_FORMAT_RE =
  /[\u202A-\u202E\u2066-\u2069\u061C\u00AD\u034F\u115F\u1160\u17B4\u17B5\uFFA0]/g;

// HTML entities (named + numeric + hex)
const HTML_ENTITY_RE = /&(#x?[\da-fA-F]+|#\d+|[a-zA-Z]+);/g;

// Base64 segment (at least 20 chars, valid charset, proper padding)
const BASE64_RE = /(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

// Hex-encoded sequences
const HEX_RE = /(?:\\x[0-9a-fA-F]{2}){3,}/g;

// URL-encoded sequences
const URL_ENCODED_RE = /(?:%[0-9a-fA-F]{2}){3,}/g;

// Leetspeak mapping
const LEET_MAP: Record<string, string> = {
  '0': 'o',
  '1': 'i',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '@': 'a',
  '!': 'i',
  '$': 's',
};

// Repeated characters (3+ of the same char)
const REPEATED_CHAR_RE = /(.)\1{2,}/g;

const HTML_ENTITY_MAP: Record<string, string> = {
  lt: '<',
  gt: '>',
  amp: '&',
  quot: '"',
  apos: "'",
  nbsp: ' ',
};

export interface NormalizeResult {
  /** The normalized text */
  text: string;
  /** Whether significant normalization occurred (itself a signal) */
  wasNormalized: boolean;
  /** Which normalization steps fired */
  steps: string[];
}

/**
 * Run the full 13-step normalization pipeline on input text.
 */
export function normalize(input: string): NormalizeResult {
  let text = input;
  const steps: string[] = [];

  // Step 1: Strip zero-width characters
  const afterZeroWidth = text.replace(ZERO_WIDTH_RE, '');
  if (afterZeroWidth !== text) {
    steps.push('zero_width');
    text = afterZeroWidth;
  }

  // Step 2: Unicode NFKC normalization (collapses homoglyphs)
  const afterNfkc = text.normalize('NFKC');
  if (afterNfkc !== text) {
    steps.push('unicode_nfkc');
    text = afterNfkc;
  }

  // Step 3: Decode HTML entities
  const afterHtml = text.replace(HTML_ENTITY_RE, (match, entity: string) => {
    if (entity.startsWith('#x') || entity.startsWith('#X')) {
      return String.fromCodePoint(parseInt(entity.slice(2), 16));
    }
    if (entity.startsWith('#')) {
      return String.fromCodePoint(parseInt(entity.slice(1), 10));
    }
    return HTML_ENTITY_MAP[entity.toLowerCase()] ?? match;
  });
  if (afterHtml !== text) {
    steps.push('html_entities');
    text = afterHtml;
  }

  // Step 4: Decode base64 segments
  const afterBase64 = text.replace(BASE64_RE, (match) => {
    try {
      const decoded = Buffer.from(match, 'base64').toString('utf-8');
      // Only replace if the decoded text looks like readable text
      if (/^[\x20-\x7E\n\r\t]+$/.test(decoded) && decoded.length >= 4) {
        return decoded;
      }
    } catch {
      // Not valid base64 — leave as is
    }
    return match;
  });
  if (afterBase64 !== text) {
    steps.push('base64');
    text = afterBase64;
  }

  // Step 5: Decode hex-encoded sequences
  const afterHex = text.replace(HEX_RE, (match) => {
    try {
      return match.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex: string) =>
        String.fromCharCode(parseInt(hex, 16)),
      );
    } catch {
      return match;
    }
  });
  if (afterHex !== text) {
    steps.push('hex');
    text = afterHex;
  }

  // Step 6: Decode URL-encoded sequences
  const afterUrl = text.replace(URL_ENCODED_RE, (match) => {
    try {
      return decodeURIComponent(match);
    } catch {
      return match;
    }
  });
  if (afterUrl !== text) {
    steps.push('url_encoded');
    text = afterUrl;
  }

  // Step 7: ROT13 detection — check if decoding reveals known injection patterns
  // We don't blindly decode everything, just check if ROT13 of the text
  // matches known patterns (to avoid false positives on normal text)
  const rot13 = text.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
  const INJECTION_KEYWORDS = ['ignore', 'instruction', 'system', 'override', 'admin'];
  const rot13HasInjection = INJECTION_KEYWORDS.some((kw) =>
    rot13.toLowerCase().includes(kw),
  );
  if (rot13HasInjection && !INJECTION_KEYWORDS.some((kw) => text.toLowerCase().includes(kw))) {
    steps.push('rot13');
    text = rot13;
  }

  // Step 8: Collapse whitespace
  const afterWhitespace = text.replace(/[\s\t\n\r]+/g, ' ').trim();
  if (afterWhitespace !== text) {
    steps.push('whitespace');
    text = afterWhitespace;
  }

  // Step 9: Collapse repeated characters (3+ → 1)
  const afterRepeated = text.replace(REPEATED_CHAR_RE, '$1');
  if (afterRepeated !== text) {
    steps.push('repeated_chars');
    text = afterRepeated;
  }

  // Step 10: Remove leetspeak substitutions
  const afterLeet = text.replace(/[013457@!$]/g, (c) => LEET_MAP[c] ?? c);
  // Only count as normalization if it changed more than just numbers in normal text
  const leetDiffCount = [...text].filter((c, i) => c !== afterLeet[i]).length;
  if (leetDiffCount >= 3) {
    steps.push('leetspeak');
    text = afterLeet;
  }

  // Step 11: Remove invisible Unicode formatting characters
  const afterInvisible = text.replace(INVISIBLE_FORMAT_RE, '');
  if (afterInvisible !== text) {
    steps.push('invisible_format');
    text = afterInvisible;
  }

  // Step 12: Defragment split tokens (remove spaces between single chars)
  // e.g., "i g n o r e" → "ignore"
  const afterDefrag = text.replace(
    /\b([a-zA-Z])\s+(?=[a-zA-Z]\b)/g,
    '$1',
  );
  // Only apply if we detect a pattern of many single-char fragments
  const singleCharWords = text.match(/\b[a-zA-Z]\b/g);
  if (singleCharWords && singleCharWords.length >= 4 && afterDefrag !== text) {
    steps.push('defragment');
    text = afterDefrag;
  }

  // Step 13: Lowercase for comparison
  const afterLower = text.toLowerCase();
  if (afterLower !== text) {
    steps.push('lowercase');
    text = afterLower;
  }

  return {
    text,
    wasNormalized: steps.length > 1, // lowercase alone doesn't count
    steps,
  };
}
