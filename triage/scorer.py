"""
Rule based baseline severity scorer. Deterministic, no LLM.

This is the safety net: every alert gets a score and a category guess from
plain rules, so the app still works when the LLM is slow or offline. It is
also the baseline the agent is measured against during evaluation.
"""
import re
from typing import Dict, List, Tuple

from .parser import is_external_ip

# Priority bands by total points
BANDS = [(80, "Critical"), (50, "High"), (25, "Medium"), (0, "Low")]

SERVERS = ("SRV-", "DC0")
ADMIN_HINTS = ("admin", "svc_", "administrator")

# Keyword signals -> (points, category). Checked against rule_name + raw_log.
SIGNALS: List[Tuple[str, int, str]] = [
    # ransomware (T1486 / T1490)
    (r"shadow\s*cop|vssadmin|wbadmin|bcdedit|recovery", 55, "ransomware"),
    (r"\.encrypted|\.locked|ransom|restore_files|bitlocker", 55, "ransomware"),
    # credential access (T1003 / T1110)
    (r"lsass|mimikatz|comsvcs|ntds|sam\b|dcsync", 55, "credential_attack"),
    (r"brute\s*force|password\s*spray|failed\s*login|4625", 35, "credential_attack"),
    # lateral movement (T1021 / T1047 / T1569)
    (r"psexec|psexesvc|7045|remote\s*service|wmic|wmiprvse|wmi\s", 45, "lateral_movement"),
    (r"rdp|logontype=10|remote\s*wmi", 30, "lateral_movement"),
    # benign / noise signals (negative-ish, low points)
    (r"scheduled\s*task|definitions\s*updated|successful\s*user\s*login", 0, "benign"),
    (r"vuln\s*scan|inventory_report|signed=true", 0, "false_positive"),
]


def score_alert(parsed: Dict) -> Dict:
    """Return {score, priority, category_guess, reasons} for one parsed alert."""
    text = f"{parsed['rule_name']} {parsed['raw_log']}".lower()
    points = 0
    reasons: List[str] = []
    category = "benign"
    best_cat_points = -1

    # 1. keyword signals
    for pattern, pts, cat in SIGNALS:
        if re.search(pattern, text):
            points += pts
            if pts > 0:
                reasons.append(f"matched {cat} signal (+{pts})")
            if pts > best_cat_points:
                best_cat_points, category = pts, cat

    # 2. context multipliers
    if is_external_ip(parsed.get("src_ip")):
        points += 15
        reasons.append("external source IP (+15)")
    if any(parsed["host"].upper().startswith(s) for s in SERVERS):
        points += 10
        reasons.append("target is a server (+10)")
    if any(h in parsed["user"].lower() for h in ADMIN_HINTS):
        points += 10
        reasons.append("privileged/service account (+10)")
    if parsed["vendor_severity"] in ("high", "critical"):
        points += 10
        reasons.append(f"vendor severity {parsed['vendor_severity']} (+10)")

    # 3. map points -> priority band
    priority = next(label for threshold, label in BANDS if points >= threshold)

    if not reasons:
        reasons.append("no strong signals; treated as routine")

    return {
        "score": points,
        "priority": priority,
        "category_guess": category,
        "reasons": reasons,
    }
