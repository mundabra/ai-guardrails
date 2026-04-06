/**
 * Shared regex patterns used across multiple guards.
 */

// PII patterns
export const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
export const CREDIT_CARD_RE =
  /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g;
export const CREDIT_CARD_AMEX_RE = /\b\d{4}[\s-]?\d{6}[\s-]?\d{5}\b/g;
export const EMAIL_RE =
  /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
export const PHONE_RE =
  /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g;
export const IPV4_RE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;

// Secret patterns
export const AWS_ACCESS_KEY_RE = /\bAKIA[0-9A-Z]{16}\b/g;
export const AWS_SECRET_KEY_RE =
  /\b[0-9a-zA-Z/+=]{40}\b/g;
export const GITHUB_PAT_RE = /\bghp_[0-9a-zA-Z]{36}\b/g;
export const GITHUB_OAUTH_RE = /\bgho_[0-9a-zA-Z]{36}\b/g;
export const GITHUB_APP_RE = /\bghs_[0-9a-zA-Z]{36}\b/g;
export const GITHUB_FINE_RE = /\bgithub_pat_[0-9a-zA-Z_]{82}\b/g;
export const GOOGLE_API_KEY_RE = /\bAIza[0-9A-Za-z_-]{35}\b/g;
// Matches Stripe secret keys (both live and test environments)
export const STRIPE_SECRET_RE = /\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b/g;
export const STRIPE_PUBLISHABLE_RE = /\bpk_live_[0-9a-zA-Z]{24,}\b/g;
export const SLACK_TOKEN_RE = /\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/g;
export const JWT_RE =
  /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;
export const SSH_PRIVATE_KEY_RE =
  /-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/g;
export const GENERIC_SECRET_RE =
  /(?:secret|password|token|key|apikey|api_key)[\s]*[=:]\s*["']?([^\s"']{16,})["']?/gi;

// Exfiltration patterns
export const MARKDOWN_IMAGE_RE =
  /!\[([^\]]*)\]\((https?:\/\/[^)]+)\)/g;
export const MARKDOWN_LINK_RE =
  /\[([^\]]*)\]\((https?:\/\/[^)]+)\)/g;
export const HTML_IMG_RE =
  /<img[^>]+src=["'](https?:\/\/[^"']+)["'][^>]*>/gi;
