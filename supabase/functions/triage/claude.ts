// One Claude call with structured JSON output, a hard deadline, and refusal fallback.

import Anthropic from "npm:@anthropic-ai/sdk@0.129.0";

const MODEL = Deno.env.get("TRIAGE_MODEL") ?? "claude-sonnet-5-5";
type Effort = "low" | "medium" | "high";
const EFFORT = (Deno.env.get("TRIAGE_EFFORT") ?? "medium") as Effort;

// Reads ANTHROPIC_API_KEY from the Supabase secret of that name.
const client = new Anthropic();

export class RefusalError extends Error {}

export async function callClaude<T>(opts: {
  system: string;
  user: string;
  schema: Record<string, unknown>;
  deadline: number; // epoch ms; the call is aborted when it passes
}): Promise<T> {
  const ms = opts.deadline - Date.now();
  if (ms < 2000) throw new Error("out of time");

  const response = await client.beta.messages.create(
    {
      model: MODEL,
      max_tokens: 16000,
      system: opts.system,
      messages: [{ role: "user", content: opts.user }],
      output_config: { effort: EFFORT, format: { type: "json_schema", schema: opts.schema } },
      // Security content can trip safety classifiers; "default" re-runs a declined
      // request on Anthropic's recommended fallback model inside the same call.
      betas: ["server-side-fallback-2026-07-01"],
      fallbacks: "default",
    },
    { signal: AbortSignal.timeout(ms), maxRetries: 1 },
  );

  if (response.stop_reason === "refusal") {
    throw new RefusalError(`refused (${response.stop_details?.category ?? "unknown"})`);
  }
  const text = response.content.flatMap((b) => (b.type === "text" ? [b.text] : [])).join("");
  try {
    return JSON.parse(text) as T;
  } catch {
    console.error("bad_json from Claude, raw reply:", text); // see Supabase function logs
    throw new Error(`bad_json (stop_reason=${response.stop_reason})`);
  }
}
