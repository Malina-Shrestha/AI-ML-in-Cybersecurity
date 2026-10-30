"""
MITRE ATT&CK lookup tool. Deterministic, no LLM.

A small, curated knowledge base covering the techniques present in our dataset.
Maps an alert to a tactic + technique by keyword, so the LLM and the analyst
both get grounded ATT&CK context. Expand KB with more techniques as needed.
"""
import re
from typing import Dict, List, Optional

# Curated subset of ATT&CK, scoped to our five categories.
KB: List[Dict] = [
    {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "patterns": r"brute\s*force|password\s*spray|failed\s*login|4625|many failures",
        "summary": "Repeated login attempts to guess valid credentials.",
    },
    {
        "technique_id": "T1003.001",
        "technique": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "patterns": r"lsass|comsvcs|mimikatz|minidump",
        "summary": "Reading the LSASS process memory to steal credentials.",
    },
    {
        "technique_id": "T1003.003",
        "technique": "OS Credential Dumping: NTDS",
        "tactic": "Credential Access",
        "patterns": r"ntds|ntdsutil|dcsync|volume shadow copy.*ntds",
        "summary": "Extracting the Active Directory database to harvest hashes.",
    },
    {
        "technique_id": "T1021.002",
        "technique": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "patterns": r"psexec|psexesvc|admin\s*share|smb",
        "summary": "Using SMB and admin shares (e.g. PsExec) to run code remotely.",
    },
    {
        "technique_id": "T1021.001",
        "technique": "Remote Services: RDP",
        "tactic": "Lateral Movement",
        "patterns": r"\brdp\b|logontype=10|remote desktop",
        "summary": "Using Remote Desktop to move to another host.",
    },
    {
        "technique_id": "T1047",
        "technique": "Windows Management Instrumentation",
        "tactic": "Lateral Movement",
        "patterns": r"\bwmi\b|wmic|wmiprvse|iwbemservices",
        "summary": "Using WMI to execute commands locally or remotely.",
    },
    {
        "technique_id": "T1569.002",
        "technique": "System Services: Service Execution",
        "tactic": "Lateral Movement",
        "patterns": r"7045|service installed|new service|svcctl",
        "summary": "Installing or running a Windows service to execute a payload.",
    },
    {
        "technique_id": "T1486",
        "technique": "Data Encrypted for Impact",
        "tactic": "Impact",
        "patterns": r"\.encrypted|\.locked|ransom|restore_files|mass file|bitlocker",
        "summary": "Encrypting files to extort the victim (ransomware).",
    },
    {
        "technique_id": "T1490",
        "technique": "Inhibit System Recovery",
        "tactic": "Impact",
        "patterns": r"shadow\s*cop|shadowcopy|vssadmin|wbadmin|bcdedit|recovery|backup.*delete",
        "summary": "Deleting backups/shadow copies so victims cannot recover.",
    },
]

NO_MATCH = {
    "technique_id": None, "technique": "No confident match",
    "tactic": "Unknown", "summary": "No ATT&CK technique matched this alert's text.",
}


def mitre_lookup(text: str) -> Dict:
    """Return the best-matching ATT&CK entry for an alert's text, or NO_MATCH.

    Impact techniques (ransomware: T1486/T1490) are checked first, because a
    shadow-copy deletion run via wmic should map to recovery-inhibition, not WMI.
    """
    text = text.lower()  # PREFER_IMPACT
    ordered = sorted(KB, key=lambda e: 0 if e["tactic"] == "Impact" else 1)
    for entry in ordered:
        if re.search(entry["patterns"], text):
            return {k: entry[k] for k in ("technique_id", "technique", "tactic", "summary")}
    return dict(NO_MATCH)


def mitre_all_matches(text: str) -> List[Dict]:
    """Return every matching entry (an alert can touch several techniques)."""
    text = text.lower()
    hits = [
        {k: e[k] for k in ("technique_id", "technique", "tactic", "summary")}
        for e in KB if re.search(e["patterns"], text)
    ]
    return hits or [dict(NO_MATCH)]
