"""Run every demo input through TriageLens and save demo_results.json (CS 1, 2:15).

This is the offline safety net: Improv 1 pastes demo_results.json into Figma Make's Demo-mode toggle.
Run: .venv/bin/python make_demo_results.py

Inputs (keys become the dropdown labels, so number them in demo-script order):
  samples/alerts.json          made by prep_alerts.py
  samples/phishing_demo_picks.json  {"1. Real shipping notice": "email text", ...}  Enrique's picks
                                    (falls back to samples/phishing.json, all 18 blind emails)
  samples/malware.json         ["Ransomware-Shade", ...]              family names from CS 2
Results are cached in data/cache/ by input + model + mode. The cache does NOT know about prompt changes:
after a redeploy, run with --fresh so every result comes from the new prompts.
"""
import hashlib
import json
import sys
from pathlib import Path

from triage_client import MODEL, mode, triage

ROOT = Path(__file__).resolve().parent
CACHE = ROOT / "data/cache"
CACHE.mkdir(parents=True, exist_ok=True)


def load(name, default):
    path = ROOT / "samples" / name
    return json.loads(path.read_text()) if path.exists() else default


inputs = {
    "alert": {label: json.dumps(alert, indent=2) for label, alert in load("alerts.json", {}).items()},
    "phishing": load("phishing_demo_picks.json", None) or load("phishing.json", {}),  # Enrique's dropdown picks
    "malware": {family: family for family in load("malware.json", [])},
}

results = {}
for tool, items in inputs.items():
    results[tool] = {}
    if not items:
        print(f"[{tool}] no samples yet (samples/{'alerts' if tool == 'alert' else tool}.json); skipping")
        continue
    for label, text in items.items():
        key = hashlib.sha256(f"{tool}|{text}|{MODEL}|{mode()}".encode()).hexdigest()[:16]
        cached = CACHE / f"{key}.json"
        if cached.exists() and "--fresh" not in sys.argv:
            out = json.loads(cached.read_text())
            note = "cached"
        else:
            out = triage(tool, text)
            note = "new"
            if "error" not in out:
                cached.write_text(json.dumps(out))
        if "error" in out:
            print(f"[{tool}] {label}: ERROR {out['error']}  (not saved; fix and rerun)")
            continue
        out.setdefault("scoring", {})["mode"] = "demo"
        results[tool][label] = out
        print(f"[{tool}] {label}: {out.get('verdict')} / {out.get('risk_score')}  ({note})  {out.get('headline', '')[:60]}")

(ROOT / "demo_results.json").write_text(json.dumps(results, indent=2))
total = sum(len(v) for v in results.values())
print(f"\nWrote demo_results.json with {total} results. Rerun after any prompt change; freeze it at 2:30.")
