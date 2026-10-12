// The shared TriageLens result format (Team Guide v2 page 7 + spec §2 additions),
// plus the allowlists the verifier enforces.

export type Tool = "phishing" | "alert" | "malware";
export const TOOLS: Tool[] = ["phishing", "alert", "malware"];

export interface Evidence {
  quote: string;
  why: string;
  source?: string; // set by the verifier: body | link | hidden | field | profile
  verified?: boolean;
}

export interface FloorHit {
  rule: string;
  floor: number;
  label: string;
}

export interface TriageResult {
  tool: Tool;
  headline: string;
  verdict: string;
  risk_score: number | null;
  ai_manipulation_detected: boolean;
  evidence: Evidence[];
  attack_ids: string[];
  explanation: string;
  plain_english: string;
  next_steps: string[];
  scoring: {
    llm_score: number | null;
    final_score: number | null;
    floors_applied: FloorHit[];
    unverified_removed: number;
    unverified_numbers?: string[];
    mode: "llm" | "rules_only" | "demo";
    latency_s: number;
    note?: string;
  };
}

// What Claude returns, before code verifies and adjusts it.
export interface ModelOutput {
  headline: string;
  verdict: string;
  risk_score: number | null;
  ai_manipulation_detected: boolean;
  evidence: { quote: string; why: string }[];
  attack_ids: string[];
  explanation: string;
  plain_english: string;
  next_steps: string[]; // action codes
}

export const VERDICTS: Record<Tool, string[]> = {
  phishing: ["phishing", "spam", "suspicious", "legitimate"],
  alert: ["critical", "high", "medium", "low"],
  malware: ["explained"],
};

// MITRE ATT&CK / ATLAS IDs the model may cite. Confirm each at attack.mitre.org / atlas.mitre.org.
export const ATTACK_ALLOWLIST: Record<Tool, Record<string, string>> = {
  phishing: {
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1566.003": "Spearphishing via Service",
    "T1598": "Phishing for Information",
    "T1598.002": "Spearphishing Attachment (info)",
    "T1598.003": "Spearphishing Link (info)",
    "T1656": "Impersonation",
    "T1204.001": "Malicious Link",
    "T1204.002": "Malicious File",
    "T1534": "Internal Spearphishing",
    "T1036": "Masquerading",
  },
  alert: {
    "T1059.001": "PowerShell",
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1486": "Data Encrypted for Impact",
    "T1566.002": "Spearphishing Link",
    "T1204.002": "Malicious File",
    "T1027": "Obfuscated Files or Information",
    "T1071.001": "Web Protocols",
    "T1021": "Remote Services",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "LLM Meta Prompt Extraction",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0010": "ML Supply Chain Compromise",
  },
  malware: {
    "T1486": "Data Encrypted for Impact",
    "T1055": "Process Injection",
    "T1543.003": "Windows Service",
    "T1056.001": "Keylogging",
    "T1041": "Exfiltration Over C2 Channel",
    "T1204.002": "Malicious File",
    "T1566.001": "Spearphishing Attachment",
  },
};

// The model picks codes; code renders the labels into next_steps.
export const ACTIONS: Record<string, string> = {
  block_sender_domain: "Block the sender's domain",
  block_url: "Block the link",
  purge_from_mailboxes: "Remove this email from all inboxes",
  reset_user_password: "Reset the user's password",
  revoke_sessions: "Sign the user out everywhere",
  warn_user: "Warn the user who reported it",
  isolate_host: "Isolate the computer from the network",
  quarantine_attachment: "Quarantine the attachment",
  escalate_to_tier2: "Escalate to Tier 2",
  check_logs: "Check sign-in / process logs",
  patch_and_update: "Patch and update affected systems",
  restore_from_backup: "Restore files from a clean backup",
  enable_mfa: "Turn on multi-factor authentication",
  train_users: "Remind staff how to spot this",
  no_action: "No action needed",
};

// JSON schema for structured output (Claude must return exactly this shape).
export function outputSchema(tool: Tool): Record<string, unknown> {
  const str = { type: "string" };
  return {
    type: "object",
    additionalProperties: false,
    required: [
      "headline", "verdict", "risk_score", "ai_manipulation_detected", "evidence",
      "attack_ids", "explanation", "plain_english", "next_steps",
    ],
    properties: {
      headline: str,
      verdict: { type: "string", enum: VERDICTS[tool] },
      risk_score: tool === "malware" ? { type: "null" } : { type: "integer" },
      ai_manipulation_detected: { type: "boolean" },
      evidence: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          required: ["quote", "why"],
          properties: { quote: str, why: str },
        },
      },
      attack_ids: { type: "array", items: { type: "string", enum: Object.keys(ATTACK_ALLOWLIST[tool]) } },
      explanation: str,
      plain_english: str,
      next_steps: { type: "array", items: { type: "string", enum: Object.keys(ACTIONS) } },
    },
  };
}
