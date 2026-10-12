"""How often does TriageLens agree with the dataset's labels? (CS 1, the pitch number)

Run:  .venv/bin/python eval.py                          # 40 emails from CEAS_08.csv
      .venv/bin/python eval.py --file SpamAssasin.csv   # second, independent dataset
      .venv/bin/python eval.py --n 5                    # quick smoke test
Agreement = TriageLens says "not legitimate" exactly when the dataset label is 1 (spam or phishing).
The dataset does not separate spam from phishing, so this measures "caught bad email", not "told them apart".
"""
import argparse
import json
from pathlib import Path

import pandas as pd

from triage_client import MODEL, email_text, mode, triage

ROOT = Path(__file__).resolve().parent

ap = argparse.ArgumentParser()
ap.add_argument("--file", default="CEAS_08.csv")
ap.add_argument("--n", type=int, default=40)
ap.add_argument("--seed", type=int, default=7)
args = ap.parse_args()

df = pd.read_csv(ROOT / "data/phishing" / args.file, encoding="latin-1", low_memory=False)
# Balanced sample: half bad, half legitimate, so "flag everything" can't score well.
half = args.n // 2
sample = pd.concat([df[df.label == 1].sample(args.n - half, random_state=args.seed),
                    df[df.label == 0].sample(half, random_state=args.seed)]).sample(frac=1, random_state=args.seed)

print(f"Evaluating {len(sample)} emails from {args.file} via {mode()} ({MODEL if mode() == 'direct' else 'deployed function'})\n")
rows, tp, tn, fp, fn, errors = [], 0, 0, 0, 0, 0
for i, (idx, row) in enumerate(sample.iterrows(), 1):
    out = triage("phishing", email_text(row))
    truth_bad = int(row.label) == 1
    if "error" in out:
        errors += 1
        print(f"{i:>3}. row {idx:>6}  ERROR {out['error']}: {str(out.get('raw', ''))[:120]}")
        continue
    said_bad = out.get("verdict") != "legitimate"
    tp += truth_bad and said_bad
    tn += (not truth_bad) and (not said_bad)
    fp += (not truth_bad) and said_bad
    fn += truth_bad and (not said_bad)
    mark = "ok  " if said_bad == truth_bad else "MISS"
    print(f"{i:>3}. row {idx:>6}  {mark} label={'bad  ' if truth_bad else 'legit'} "
          f"verdict={out.get('verdict', '?'):11} score={out.get('risk_score')}  {out.get('headline', '')[:60]}")
    rows.append({"row": int(idx), "label": int(row.label), "verdict": out.get("verdict"),
                 "risk_score": out.get("risk_score"), "headline": out.get("headline")})

scored = tp + tn + fp + fn
print(f"\nAgreed with dataset labels on {tp + tn}/{scored} emails ({args.file}, balanced random sample, seed {args.seed})")
print(f"  caught bad email:        {tp}/{tp + fn}")
print(f"  left legit email alone:  {tn}/{tn + fp}   (false alarms: {fp})")
if errors:
    print(f"  errors (not counted):    {errors}")

out_file = ROOT / f"data/eval_{Path(args.file).stem}.json"
out_file.write_text(json.dumps({"file": args.file, "n": scored, "agree": tp + tn, "tp": tp, "tn": tn,
                                "fp": fp, "fn": fn, "errors": errors, "rows": rows}, indent=2))
print(f"Saved details to {out_file}")
