// Text helpers shared by signals, the verifier, and scoring.

export const ZERO_WIDTH = /[​-‍⁠﻿]/g;

// Normalize text so quotes can be matched exactly despite cosmetic differences:
// Unicode forms, zero-width characters, curly quotes, dashes, whitespace, case.
export function norm(s: string): string {
  return (s ?? "")
    .normalize("NFKC")
    .replace(ZERO_WIDTH, "")
    .replace(/[‘’‚‛′]/g, "'")
    .replace(/[“”„‟″]/g, '"')
    .replace(/[‐-―−]/g, "-")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

// Small Levenshtein distance for lookalike-domain checks.
export function editDistance(a: string, b: string): number {
  const prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const up = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = up;
    }
  }
  return prev[b.length];
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

export function stripTags(html: string): string {
  return html
    .replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, " ")
    .replace(/<br\s*\/?>|<\/(p|div|li|tr|h\d)>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&(#\d+|[a-z]+);/gi, (m, e: string) =>
      e[0] === "#" ? String.fromCharCode(Number(e.slice(1))) : ENTITIES[e.toLowerCase()] ?? m)
    .replace(/[ \t]+/g, " ")
    .replace(/\n\s*\n+/g, "\n")
    .trim();
}
