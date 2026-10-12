// Code has the final word: rule-based minimum scores the AI can't push below,
// and verdicts kept consistent with the final score (spec §6).

import type { FloorHit, Tool } from "./contract.ts";
import { isSuspiciousUrl, type Signals } from "./signals.ts";

export const AI_FLOOR = 80;

export function floorsFor(tool: Tool, sig: Signals, llmFlaggedManipulation: boolean): FloorHit[] {
  if (tool === "malware") return [];
  const hits: FloorHit[] = [];
  const strongOrHidden = sig.ai_phrases.some((p) => p.strength === "strong" || p.hidden);
  const softVisible = sig.ai_phrases.some((p) => p.strength === "soft" && !p.hidden);
  if (strongOrHidden) {
    const hidden = sig.ai_phrases.some((p) => p.hidden);
    hits.push({
      rule: "ai_instruction",
      floor: AI_FLOOR,
      label: hidden ? "Hidden instruction aimed at AI" : "Instruction aimed at AI tools",
    });
  } else if (softVisible && llmFlaggedManipulation) {
    hits.push({ rule: "ai_instruction_soft", floor: AI_FLOOR, label: "Text trying to steer AI tools" });
  }
  if (sig.lookalike_domains.length) {
    hits.push({ rule: "lookalike_domain", floor: 65, label: `Lookalike domain: ${sig.lookalike_domains[0]}` });
  }
  if ((sig.money_request || sig.credential_request) && sig.urls.some(isSuspiciousUrl)) {
    hits.push({
      rule: "money_or_credential_plus_link",
      floor: 60,
      label: `${sig.money_request ? "Money" : "Password"} request with a suspicious link`,
    });
  }
  if (sig.risky_attachments.length) {
    hits.push({ rule: "risky_attachment", floor: 60, label: `Risky attachment: ${sig.risky_attachments[0]}` });
  }
  if (sig.auth_fail && sig.link_mismatch.length) {
    hits.push({ rule: "auth_fail_link_mismatch", floor: 60, label: "Failed sender checks and a disguised link" });
  }
  return hits;
}

export function finalScore(llmScore: number | null, floors: FloorHit[]): number {
  const base = Math.max(0, Math.min(100, Math.round(llmScore ?? 0)));
  return Math.max(base, ...floors.map((f) => f.floor));
}

// Phishing verdict must agree with the final score (spec §6 table).
export function consistentPhishingVerdict(score: number, verdict: string, floors: FloorHit[]): string {
  const scamFloor = floors.some((f) => f.rule.startsWith("ai_instruction") || f.rule === "money_or_credential_plus_link");
  if (score >= 70) {
    if (verdict === "phishing" || verdict === "spam") return verdict;
    return scamFloor ? "phishing" : "spam";
  }
  if (score >= 40) return verdict === "legitimate" ? "suspicious" : verdict;
  return verdict === "phishing" ? "suspicious" : verdict;
}

const SEVERITY = ["low", "medium", "high", "critical"];

// Alerts: AI-directed text or classic attack patterns force at least "high".
export function consistentAlertSeverity(verdict: string, sig: Signals, floors: FloorHit[]): string {
  const mustBeHigh = floors.some((f) => f.rule.startsWith("ai_instruction")) ||
    sig.encoded_powershell || sig.office_spawned_script || sig.mass_rename;
  const idx = Math.max(0, SEVERITY.indexOf(verdict));
  return mustBeHigh ? SEVERITY[Math.max(idx, 2)] : SEVERITY[idx];
}

export function adjustVerdict(tool: Tool, verdict: string, score: number, sig: Signals, floors: FloorHit[]): string {
  if (tool === "phishing") return consistentPhishingVerdict(score, verdict, floors);
  if (tool === "alert") return consistentAlertSeverity(verdict, sig, floors);
  return verdict;
}

// Score used when Claude is unreachable.
export function rulesOnlyScore(sig: Signals, floors: FloorHit[]): number {
  if (floors.length) return Math.max(...floors.map((f) => f.floor));
  return Math.min(55, 20 + 5 * sig.keyword_hits.length);
}
