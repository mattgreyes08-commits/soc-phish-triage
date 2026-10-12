# `triage` Supabase Edge Function

`POST {tool, input}` → a TalosAI result in the shared format (see `.plans/talosai-spec.md` §2).

| tool | input |
|---|---|
| `phishing` | email text (plain text or HTML) |
| `alert` | alert JSON or text (e.g. a prepped DVAA log entry) |
| `malware` | a family name that is a key in `malware_profiles.json` |

## Files
- `index.ts`: HTTP handler and CORS
- `triage.ts`: the pipeline (signals → Claude → verify → floors → result, with a rules-only fallback)
- `signals.ts`: code-computed facts: links, lookalikes, hidden text, AI-directed phrases
- `verify.ts`: quote checks, allowlists, malware number checks
- `scoring.ts`: score floors and verdict consistency
- `prompts.ts`: system prompts. **The prompt pair edits these.**
- `claude.ts`: the Claude call (model `claude-sonnet-5-5`, structured JSON output, refusal fallback)
- `malware_profiles.json`: output of `prep_malware.py`. **Empty until CS 2 generates it.**

## Deploy
```bash
supabase secrets set ANTHROPIC_API_KEY=...        # never commit or paste the key anywhere else
supabase functions deploy triage --use-api        # login check stays on (supabase/config.toml: verify_jwt = true)
```
Optional secrets: `TRIAGE_MODEL` (default `claude-sonnet-5-5`), `TRIAGE_EFFORT` (default `medium`).

Call it from Figma Make: `POST https://<project-ref>.supabase.co/functions/v1/triage`
with headers `Authorization: Bearer <anon key>` and `apikey: <anon key>` (Supabase dashboard → Project Settings → API Keys → `anon`).
A **401** means that header is missing or wrong. Fix the header; don't turn the check off.
Live project: `kcgrheohvwekdoryjnyy`.

## Test (offline, no key)
```bash
node --test supabase/functions/triage/triage.test.ts
```
