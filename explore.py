"""Look at the datasets before building anything (CS 1, 11:15 deliverable).

Run: .venv/bin/python explore.py
Prints columns and labels for every dataset, and writes 20 demo-email candidates
to data/demo_candidates.md (stays out of Git; share it with Improv 2 directly).
"""
import glob
import json
from pathlib import Path

import pandas as pd

DATA = Path(__file__).resolve().parent / "data"

print("=" * 70, "\nPHISHING / SPAM EMAILS  (label 1 = spam or phishing, 0 = legitimate)\n" + "=" * 70)
for path in sorted(glob.glob(str(DATA / "phishing/*.csv"))):
    df = pd.read_csv(path, encoding="latin-1", low_memory=False)
    print(f"\n{Path(path).name}: {len(df):,} rows")
    print("  columns:", df.columns.tolist())
    print("  labels: ", df["label"].value_counts().to_dict())

print("\n" + "=" * 70, "\nAIT-ADS ALERTS (CrowdStrike-provided, Zenodo record 8263181)\n" + "=" * 70)
labels = pd.read_csv(DATA / "ait_ads/labels.csv")
print(f"\nlabels.csv: {labels.scenario.nunique()} scenarios; attack phases:", sorted(labels.attack.unique()))
for path in sorted(glob.glob(str(DATA / "ait_ads/*_wazuh.json"))):
    with open(path) as f:
        first = json.loads(f.readline())
        count = 1 + sum(1 for _ in f)
    print(f"\n{Path(path).name}: {count:,} alerts")
    print("  top-level fields:", list(first.keys()))
    print("  rule fields:     ", list(first["rule"].keys()))

# 20 demo-email candidates for Improv 2: real phishing, scams, and legitimate mail.
PICKS = [("Nazario.csv", 8, "PHISHING"), ("Nigerian_Fraud.csv", 4, "SCAM"),
         ("CEAS_08.csv", 3, "SPAM/PHISH"), ("Enron.csv", 5, "LEGITIMATE")]
lines = ["# Demo email candidates (from the Kaggle phishing-email dataset)",
         "Do not click any links. Check for personal info before putting any of these on a slide.\n"]
n = 0
for file, k, kind in PICKS:
    df = pd.read_csv(DATA / "phishing" / file, encoding="latin-1", low_memory=False)
    if kind == "LEGITIMATE":
        df = df[df.label == 0]
    if kind == "SPAM/PHISH":
        df = df[df.label == 1]
    df = df[df.body.astype(str).str.len().between(200, 1200)]  # short enough to read on screen
    for _, row in df.sample(k, random_state=7).iterrows():
        n += 1
        lines += [f"## {n}. {kind} ({file}, row {row.name})",
                  f"**Subject:** {row.get('subject', '')}", "```", str(row.body).strip(), "```", ""]

out = DATA / "demo_candidates.md"
out.write_text("\n".join(lines))
print(f"\nWrote {n} demo-email candidates to {out}")
