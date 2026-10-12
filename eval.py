"""How often does TalosAI agree with the dataset's labels? (CS 1, the pitch number)

Run:  .venv/bin/python eval.py                          # 40 emails from CEAS_08.csv
      .venv/bin/python eval.py --file SpamAssasin.csv   # second, independent dataset
      .venv/bin/python eval.py --n 5                    # quick smoke test
Agreement = TalosAI says "not legitimate" exactly when the dataset label is 1 (spam or phishing).
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
ap.add_argument("--workers", type=int, default=1, help="emails tested at the same time (4 is ~4x faster)")
ap.add_argument("--exclude-seen", action="store_true", help="skip rows used in earlier saved runs (fresh emails only)")
ap.add_argument("--tag", default="", help="suffix for the saved results file, e.g. 'before'")
ap.add_argument("--bad-only", action="store_true", help="sample only label-1 emails (for all-phishing files like Nazario)")
ap.add_argument("--ab-ignore", default="", help="with --exclude-ab, don't exclude this tag's rows (so 'after' reuses the 'before' sample)")
ap.add_argument("--exclude-ab", action="store_true", help="with --exclude-seen, also skip rows from before/after runs in data/ab/")
args = ap.parse_args()

df = pd.read_csv(ROOT / "data/phishing" / args.file, encoding="latin-1", low_memory=False)
if args.exclude_seen:
    files = list((ROOT / "data").glob(f"eval_{Path(args.file).stem}*.json"))
    if args.exclude_ab:
        files += [f for f in (ROOT / "data/ab").glob(f"eval_{Path(args.file).stem}_*.json")
                  if not (args.ab_ignore and f.stem.endswith("_" + args.ab_ignore))]
    seen = {r["row"] for f in files for r in json.loads(f.read_text()).get("rows", [])}
    df = df.drop(index=[i for i in seen if i in df.index])
    print(f"Skipping {len(seen)} emails used in earlier runs")
# Balanced sample: half bad, half legitimate, so "flag everything" can't score well.
half = 0 if args.bad_only else args.n // 2
sample = pd.concat([df[df.label == 1].sample(args.n - half, random_state=args.seed),
                    df[df.label == 0].sample(half, random_state=args.seed)]).sample(frac=1, random_state=args.seed)

print(f"Evaluating {len(sample)} emails from {args.file} via {mode()} ({MODEL if mode() == 'direct' else 'deployed function'})\n")
rows, tp, tn, fp, fn, errors = [], 0, 0, 0, 0, 0
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(args.workers) as pool:
    outs = list(pool.map(lambda r: triage("phishing", email_text(r[1])), sample.iterrows()))
for i, ((idx, row), out) in enumerate(zip(sample.iterrows(), outs), 1):
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
if tn + fp:
    print(f"  left legit email alone:  {tn}/{tn + fp}   (false alarms: {fp})")
if errors:
    print(f"  errors (not counted):    {errors}")

# Tagged runs (before/after comparisons) go in data/ab/ so --exclude-seen draws the same fresh sample for both.
out_file = (ROOT / "data/ab" / f"eval_{Path(args.file).stem}_{args.tag}.json") if args.tag else ROOT / f"data/eval_{Path(args.file).stem}.json"
out_file.parent.mkdir(exist_ok=True)
out_file.write_text(json.dumps({"file": args.file, "n": scored, "agree": tp + tn, "tp": tp, "tn": tn,
                                "fp": fp, "fn": fn, "errors": errors, "rows": rows}, indent=2))
print(f"Saved details to {out_file}")
