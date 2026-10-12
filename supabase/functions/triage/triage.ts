// The pipeline: signals -> Claude -> verify -> floors -> final result.
// Claude is passed in as `call` so this file runs (and is tested) without the network.

import { type FloorHit, type ModelOutput, outputSchema, type Tool, TOOLS, type TriageResult } from "./contract.ts";
import { REWRITE_SCHEMA, REWRITE_SYSTEM, rewriteMessage, systemPrompt, userMessage } from "./prompts.ts";
import { adjustVerdict, finalScore, floorsFor, rulesOnlyScore } from "./scoring.ts";
import { computeSignals, type Signals } from "./signals.ts";
import {
  cleanAttackIds, corporaFor, type MalwareProfile, needsEvidenceRetry, renderActions,
  unsupportedNumbers, verifyEvidence,
} from "./verify.ts";

export type CallClaude = <T>(opts: {
  system: string;
  user: string;
  schema: Record<string, unknown>;
  deadline: number;
}) => Promise<T>;

export interface TriageRequest { tool: Tool; input: string }

export class BadRequest extends Error {}

const BUDGET_MS = 25_000; // whole request, including retries
const FIRST_CALL_MS = 20_000; // spec §1: ~20 s, then rules-only

function nonce(): string {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 8);
}

export async function runTriage(
  req: TriageRequest,
  call: CallClaude,
  profiles: Record<string, MalwareProfile>,
): Promise<TriageResult> {
  const started = Date.now();
  const tool = req.tool;
  if (!TOOLS.includes(tool)) throw new BadRequest(`tool must be one of ${TOOLS.join(", ")}`);
  const input = String(req.input ?? "").slice(0, 50_000);
  if (!input.trim()) throw new BadRequest("input is empty");

  let family: string | undefined;
  let profile: MalwareProfile | undefined;
  if (tool === "malware") {
    family = input.trim();
    profile = profiles[family];
    if (!profile) throw new BadRequest(`unknown malware family "${family}". Known: ${Object.keys(profiles).join(", ") || "(none yet - run prep_malware.py)"}`);
  }

  const sig = computeSignals(tool, input);
  const n = nonce();
  const system = systemPrompt(tool, n);
  const user = userMessage(tool, n, sig, input, family, profile);
  const schema = outputSchema(tool);
  const corpora = corporaFor(tool, sig, input, profile);
  const finalDeadline = started + BUDGET_MS;

  let out: ModelOutput;
  try {
    out = await call<ModelOutput>({ system, user, schema, deadline: started + FIRST_CALL_MS });
  } catch (err) {
    console.error("Claude call failed, using rules-only result:", err);
    return rulesOnly(tool, sig, started, family, profile, String(err));
  }

  let checked = verifyEvidence(out.evidence, corpora);
  let badNumbers = profile ? unsupportedNumbers(`${out.explanation} ${out.plain_english} ${out.headline}`, profile) : [];

  // One retry with feedback if evidence was invented or malware numbers don't trace to the profile.
  if (needsEvidenceRetry(tool, out, checked.kept.length, checked.dropped.length) || badNumbers.length) {
    const feedback = [
      checked.dropped.length && `These quotes were not found verbatim in the input: ${JSON.stringify(checked.dropped)}. Quote exact text only.`,
      badNumbers.length && `These numbers are not in <profile>: ${JSON.stringify(badNumbers)}. Use only profile numbers.`,
    ].filter(Boolean).join("\n");
    try {
      const out2 = await call<ModelOutput>({ system, user: `${user}\n\n${feedback}`, schema, deadline: finalDeadline - 3000 });
      const checked2 = verifyEvidence(out2.evidence, corpora);
      const bad2 = profile ? unsupportedNumbers(`${out2.explanation} ${out2.plain_english} ${out2.headline}`, profile) : [];
      if (checked2.kept.length - bad2.length > checked.kept.length - badNumbers.length) {
        out = out2;
        checked = checked2;
        badNumbers = bad2;
      }
    } catch (err) {
      console.error("retry failed, keeping first answer:", err);
    }
  }

  const llmFlag = Boolean(out.ai_manipulation_detected);
  const floors = floorsFor(tool, sig, llmFlag);
  const score = tool === "malware" ? null : finalScore(out.risk_score, floors);
  const verdict = score === null ? out.verdict : adjustVerdict(tool, out.verdict, score, sig, floors);

  let headline = out.headline;
  let plain = out.plain_english;
  if (verdict !== out.verdict) {
    // Code changed the verdict; make sure the summary doesn't contradict it.
    const reasons = [...floors.map((f) => f.label), ...checked.kept.map((e) => e.why)];
    try {
      const r = await call<{ headline: string; plain_english: string }>({
        system: REWRITE_SYSTEM,
        user: rewriteMessage(tool, verdict, score ?? 0, reasons),
        schema: REWRITE_SCHEMA,
        deadline: finalDeadline,
      });
      headline = r.headline;
      plain = r.plain_english;
    } catch {
      ({ headline, plain } = template(tool, verdict, floors));
    }
  }

  return {
    tool,
    headline,
    verdict,
    risk_score: score,
    ai_manipulation_detected: tool !== "malware" && (llmFlag || floors.some((f) => f.rule.startsWith("ai_instruction"))),
    evidence: checked.kept,
    attack_ids: cleanAttackIds(tool, out.attack_ids),
    explanation: out.explanation,
    plain_english: plain,
    next_steps: renderActions(out.next_steps),
    scoring: {
      llm_score: tool === "malware" ? null : out.risk_score,
      final_score: score,
      floors_applied: floors,
      unverified_removed: checked.dropped.length,
      ...(badNumbers.length ? { unverified_numbers: badNumbers } : {}),
      mode: "llm",
      latency_s: round1((Date.now() - started) / 1000),
    },
  };
}

function round1(x: number): number {
  return Math.round(x * 10) / 10;
}

function template(tool: Tool, verdict: string, floors: FloorHit[]): { headline: string; plain: string } {
  const why = floors[0]?.label.toLowerCase() ?? "warning signs found by our checks";
  if (tool === "alert") {
    return {
      headline: `${verdict[0].toUpperCase()}${verdict.slice(1)}-severity alert: ${why}`,
      plain: `Our checks rated this alert ${verdict}. A technician should review it today.`,
    };
  }
  const plainByVerdict: Record<string, string> = {
    phishing: `This email looks like a scam (${why}). Don't click its links or reply; we're blocking it.`,
    spam: "This looks like unwanted junk mail. It's safe to delete.",
    suspicious: `This email has some warning signs (${why}). Please don't act on it until we've checked.`,
    legitimate: "We didn't find signs of a scam in this email.",
  };
  return {
    headline: verdict === "legitimate" ? "No signs of phishing found" : `Likely ${verdict}: ${why}`,
    plain: plainByVerdict[verdict] ?? plainByVerdict.suspicious,
  };
}

// Used when Claude is down, slow, or declines. Code-only, clearly labeled.
function rulesOnly(
  tool: Tool,
  sig: Signals,
  started: number,
  family?: string,
  profile?: MalwareProfile,
  note?: string,
): TriageResult {
  const scoring = (score: number | null, floors: FloorHit[]) => ({
    llm_score: null,
    final_score: score,
    floors_applied: floors,
    unverified_removed: 0,
    mode: "rules_only" as const,
    latency_s: round1((Date.now() - started) / 1000),
    note: `Rules-only verdict (AI unavailable): ${note ?? ""}`.trim(),
  });

  if (tool === "malware" && profile) {
    const lines = Object.entries(profile.features).map(([f, v]) =>
      `${f}: ${v.family_avg} on average vs ${v.benign_avg} for normal programs`);
    return {
      tool, headline: `${family}: dataset profile (AI explanation unavailable)`, verdict: "explained", risk_score: null,
      ai_manipulation_detected: false,
      evidence: lines.map((l) => ({ quote: l.split(":")[0], why: l, source: "profile", verified: true })),
      attack_ids: [], explanation: `In this dataset (${profile.samples} samples): ${lines.join("; ")}.`,
      plain_english: "The AI explanation isn't available right now; these are the measured numbers from the dataset.",
      next_steps: [], scoring: scoring(null, []),
    };
  }

  const floors = floorsFor(tool, sig, false);
  // A safety refusal is not "nothing found": obfuscated pharma spam often trips it. Send it to a person instead.
  const refused = /refused/i.test(note ?? "");
  const score = refused ? Math.max(50, rulesOnlyScore(sig, floors)) : rulesOnlyScore(sig, floors);
  const base = tool === "alert" ? (score >= 70 ? "high" : score >= 40 ? "medium" : "low")
    : score >= 40 ? "suspicious" : sig.keyword_hits.length ? "suspicious" : "legitimate";
  const verdict = adjustVerdict(tool, base, score, sig, floors);
  let { headline, plain } = template(tool, verdict, floors);
  if (refused && !floors.length) {
    headline = "The AI declined to analyze this; a person should review it";
    plain = tool === "alert"
      ? "Our AI couldn't analyze this alert automatically, which is unusual. A technician should look at it today."
      : "Our AI couldn't analyze this email automatically, which is unusual. Please don't click or reply until someone has checked it.";
  }
  const evidence = sig.ai_phrases
    .filter((p) => p.strength === "strong" || p.hidden)
    .map((p) => ({ quote: p.text, why: "Instruction aimed at AI tools", source: p.hidden ? "hidden" : "body", verified: true }));
  return {
    tool, headline, verdict, risk_score: score,
    ai_manipulation_detected: floors.some((f) => f.rule.startsWith("ai_instruction")),
    evidence, attack_ids: evidence.length && tool === "alert" ? ["AML.T0051"] : [],
    explanation: floors.length ? `Rule checks fired: ${floors.map((f) => f.label).join("; ")}.` : "No rule checks fired.",
    plain_english: plain,
    next_steps: [],
    scoring: scoring(score, floors),
  };
}
