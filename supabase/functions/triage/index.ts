// Supabase Edge Function "triage": POST {tool: "phishing"|"alert"|"malware", input: string}
// -> TriageLens result JSON (shared contract, spec §2). For malware, input is the family name.

import { callClaude } from "./claude.ts";
import { BadRequest, runTriage } from "./triage.ts";
import type { MalwareProfile } from "./verify.ts";
import profiles from "./malware_profiles.json" with { type: "json" };

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "content-type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "use POST" }, 405);

  let body: { tool?: unknown; input?: unknown };
  try {
    body = await req.json();
  } catch {
    return json({ error: "body must be JSON: {tool, input}" }, 400);
  }

  try {
    const result = await runTriage(
      { tool: body.tool as never, input: String(body.input ?? "") },
      callClaude,
      profiles as Record<string, MalwareProfile>,
    );
    return json(result);
  } catch (err) {
    if (err instanceof BadRequest) return json({ error: err.message }, 400);
    console.error("triage failed:", err);
    return json({ error: "Something went wrong. Try demo mode." }, 500);
  }
});
