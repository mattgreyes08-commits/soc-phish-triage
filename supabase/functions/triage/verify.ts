// Checks Claude's work: every quote must really appear in the input, IDs and
// action codes must come from the allowlists, malware numbers must come from the profile.

import { ACTIONS, ATTACK_ALLOWLIST, type Evidence, type ModelOutput, type Tool } from "./contract.ts";
import type { Signals } from "./signals.ts";
import { norm } from "./text.ts";

export interface Corpus { source: string; text: string }

export interface MalwareProfile {
  samples: number;
  features: Record<string, { family_avg: number; benign_avg: number }>;
}

export function corporaFor(tool: Tool, sig: Signals, input: string, profile?: MalwareProfile): Corpus[] {
  if (tool === "malware") {
    const lines = Object.entries(profile?.features ?? {}).map(
      ([f, v]) => `${f}: family_avg ${v.family_avg}, benign_avg ${v.benign_avg}`,
    );
    return [{ source: "profile", text: `${JSON.stringify(profile ?? {})}\n${lines.join("\n")}` }];
  }
  const corpora: Corpus[] = [];
  if (tool === "alert" && Object.keys(sig.alert_fields).length) {
    corpora.push({
      source: "field",
      text: Object.entries(sig.alert_fields).map(([k, v]) => `${k}: ${v}`).join("\n"),
    });
  } else {
    corpora.push({ source: "body", text: sig.visible_text });
  }
  corpora.push({ source: "hidden", text: sig.hidden_text.map((h) => h.text).join("\n") });
  corpora.push({ source: "link", text: sig.urls.map((u) => u.url).join("\n") });
  // Raw input last, so quotes copied from markup or headers still verify.
  corpora.push({ source: "body", text: input });
  return corpora;
}

export function verifyEvidence(
  evidence: { quote: string; why: string }[],
  corpora: Corpus[],
): { kept: Evidence[]; dropped: string[] } {
  const normed = corpora.map((c) => ({ source: c.source, text: norm(c.text) }));
  const kept: Evidence[] = [];
  const dropped: string[] = [];
  for (const e of evidence ?? []) {
    const q = norm(e.quote);
    const hit = q.length >= 3 ? normed.find((c) => c.text.includes(q)) : undefined;
    if (hit) kept.push({ quote: e.quote, why: e.why, source: hit.source, verified: true });
    else dropped.push(e.quote);
  }
  return { kept, dropped };
}

export function cleanAttackIds(tool: Tool, ids: string[]): string[] {
  return [...new Set((ids ?? []).filter((id) => id in ATTACK_ALLOWLIST[tool]))];
}

export function renderActions(codes: string[]): string[] {
  return [...new Set(codes ?? [])].filter((c) => c in ACTIONS).map((c) => ACTIONS[c]);
}

// Should we re-ask Claude because too much evidence was invented?
export function needsEvidenceRetry(tool: Tool, out: ModelOutput, keptCount: number, droppedCount: number): boolean {
  const total = keptCount + droppedCount;
  if (total > 0 && droppedCount / total > 0.5) return true;
  const benign = out.verdict === "legitimate" || out.verdict === "low" || tool === "malware";
  return keptCount === 0 && !benign;
}

// Numbers in a malware explanation that don't trace back to the profile.
// Ignores small counts ("3 steps"), years, and anything the profile supports
// directly or as a family/benign ratio (within 10%).
export function unsupportedNumbers(text: string, profile: MalwareProfile): string[] {
  const values: number[] = [profile.samples];
  const ratios: number[] = [];
  for (const f of Object.values(profile.features)) {
    values.push(f.family_avg, f.benign_avg);
    if (f.benign_avg > 0) ratios.push(f.family_avg / f.benign_avg);
  }
  const close = (a: number, b: number, tol: number) => Math.abs(a - b) <= Math.max(tol * Math.abs(b), 0.051);
  const bad: string[] = [];
  for (const m of (text ?? "").matchAll(/(\d[\d,]*(?:\.\d+)?)\s*(x\b|×|times\b|%)?/gi)) {
    const v = Number(m[1].replace(/,/g, ""));
    const unit = (m[2] ?? "").toLowerCase();
    if (unit === "x" || unit === "×" || unit === "times") {
      if (!ratios.some((r) => close(v, r, 0.1) || Math.round(r) === v)) bad.push(m[0].trim());
      continue;
    }
    if (unit === "%") {
      if (!ratios.some((r) => close(v, (r - 1) * 100, 0.1))) bad.push(m[0].trim());
      continue;
    }
    const isYear = Number.isInteger(v) && v >= 1980 && v <= 2035;
    if (isYear || (Number.isInteger(v) && v < 10)) continue;
    if (!values.some((p) => close(v, p, 0.05) || Math.round(p) === v)) bad.push(m[0].trim());
  }
  return [...new Set(bad)];
}
