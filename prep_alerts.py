"""Pick 5 real demo alerts from the CrowdStrike-provided AIT Alert Data Set (CS 1).

Source: AIT-ADS, Zenodo record 8263181 (CC BY 4.0), scenario "russellmitchell" (Wazuh + Suricata alerts).
Run: .venv/bin/python prep_alerts.py
Writes:
  samples/alerts.json           dropdown label -> alert (what the Alerts tab sends to the function)
  samples/alerts_expected.json  dropdown label -> attack phase + the severity we expect (never sent to Claude)
"""
import json
from datetime import datetime
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
SCENARIO = "russellmitchell"
ALERTS = ROOT / f"data/ait_ads/{SCENARIO}_wazuh.json"

phases = pd.read_csv(ROOT / "data/ait_ads/labels.csv")
phases = phases[phases.scenario == SCENARIO].set_index("attack")


def ts(a):
    return datetime.fromisoformat(a["@timestamp"].replace("Z", "+00:00")).timestamp()


def phase_of(a):
    for attack, p in phases.iterrows():
        if p.start <= ts(a) <= p.end:
            return attack
    return "normal activity"


alerts = [json.loads(line) for line in open(ALERTS)]


def first(pred):
    return next(a for a in alerts if pred(a))


# Demo order follows the attack story: harmless -> recon -> break-in -> takeover.
# The last one is the star: Wazuh rates reading /etc/shadow as root only 3/15.
PICKS = [
    ("1. Antivirus update (harmless)", "low",
     lambda a: a["rule"]["description"] == "ClamAV database update" and phase_of(a) == "normal activity"),
    ("2. Nmap scan from inside the network", "medium",
     lambda a: "Nmap" in a["rule"]["description"]),
    ("3. Web server flooded with 404s", "medium",
     lambda a: a["rule"]["level"] == 10 and phase_of(a) == "dirb"),
    ("4. Web server account switched users", "high",
     lambda a: a["rule"]["description"] == "User successfully changed UID." and phase_of(a) == "privilege_escalation"),
    ("5. Password file read as root (rated LOW by tool)", "critical",
     lambda a: "/etc/shadow" in a.get("full_log", "")),
]


def slim(a):
    """Keep the fields an analyst would see; drop compliance tags and Suricata metadata noise."""
    data = dict(a.get("data", {}))
    if isinstance(data.get("alert"), dict):
        data["alert"] = {k: data["alert"][k] for k in ("signature", "category", "severity", "action")
                         if k in data["alert"]}
    for noisy in ("metadata", "flow", "flow_id", "tx_id", "http", "in_iface"):
        data.pop(noisy, None)
    return {
        "alert_id": f"WAZUH-{a['id']}",
        "time": a["@timestamp"],
        "source": "Wazuh" + (" / Suricata IDS" if "suricata" in a["rule"]["groups"] else ""),
        "host": a.get("predecoder", {}).get("hostname") or a["agent"]["name"],
        "rule": a["rule"]["description"],
        "rule_id": a["rule"]["id"],
        "severity_from_tool": f"Level {a['rule']['level']} of 15",
        "rule_groups": a["rule"]["groups"],
        "log": a.get("full_log", "")[:600],
        "details": data,
    }


demo, expected = {}, {}
for label, severity, pred in PICKS:
    a = first(pred)
    demo[label] = slim(a)
    expected[label] = {"attack_phase": phase_of(a), "expected_severity": severity,
                       "wazuh_level": a["rule"]["level"]}
    print(f"{label:52} phase={phase_of(a):22} wazuh={a['rule']['level']:>2}/15  expect={severity}")

(ROOT / "samples").mkdir(exist_ok=True)
(ROOT / "samples/alerts.json").write_text(json.dumps(demo, indent=2))
(ROOT / "samples/alerts_expected.json").write_text(json.dumps(expected, indent=2))
print("\nWrote samples/alerts.json and samples/alerts_expected.json")
