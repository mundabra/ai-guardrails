/**
 * Build a reversible joined representation of text segments so redacted text
 * can be mapped back to the original segment structure.
 */
export function createTextPartition(segments: string[]): {
  joinedText: string;
  restoreSegments: (redactedText: string) => string[] | null;
  toVisibleText: (redactedText: string) => string;
} {
  if (segments.length <= 1) {
    return {
      joinedText: segments[0] ?? '',
      restoreSegments: (redactedText) => [redactedText],
      toVisibleText: (redactedText) => redactedText,
    };
  }

  let counter = 0;
  let separator = '';
  do {
    separator =
      `\u0000__MUNDABRA_AI_GUARDRAILS_BOUNDARY_${counter}__\u0000`;
    counter += 1;
  } while (segments.some((segment) => segment.includes(separator)));

  return {
    joinedText: segments.join(separator),
    restoreSegments: (redactedText) => {
      const restored = redactedText.split(separator);
      return restored.length === segments.length ? restored : null;
    },
    toVisibleText: (redactedText) => redactedText.split(separator).join('\n\n'),
  };
}
