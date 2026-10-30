"""
Ties the deterministic steps together: load -> parse -> score -> MITRE lookup.
The LLM step (triage/llm.py) runs on demand in the Gradio detail view so the
queue stays fast; it reads the enriched alert this module produces.
"""
import json
from typing import Dict, List

import pandas as pd

from .parser import parse_alert
from .scorer import score_alert
from .mitre import mitre_lookup

PRIORITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def load_alerts(path: str) -> List[Dict]:
    """Read a JSON Lines file (one alert per line). Skips blank lines."""
    alerts = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                alerts.append(json.loads(line))
    return alerts


def triage_one(alert: Dict) -> Dict:
    """Run the full deterministic pipeline on a single raw alert."""
    parsed = parse_alert(alert)
    scored = score_alert(parsed)
    enriched = {**parsed, **scored}
    m = mitre_lookup(f"{enriched['rule_name']} {enriched['raw_log']}")
    enriched["mitre_id"] = m["technique_id"]
    enriched["mitre_name"] = m["technique"]
    enriched["mitre_tactic"] = m["tactic"]
    enriched["mitre_summary"] = m["summary"]
    return enriched


def triage_all(alerts: List[Dict]) -> pd.DataFrame:
    """Triage a list of alerts and return a queue sorted by risk."""
    rows = [triage_one(a) for a in alerts]
    df = pd.DataFrame(rows)
    df["_rank"] = df["priority"].map(PRIORITY_RANK)
    df = df.sort_values(["_rank", "score"], ascending=[True, False]).drop(columns="_rank")
    return df.reset_index(drop=True)
