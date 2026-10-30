"""
Log parser: flattens one raw SIEM alert (nested JSON) into a flat, predictable
record the rest of the pipeline can rely on. Deterministic, no LLM.
"""
from typing import Any, Dict

STANDARD_FIELDS = [
    "alert_id", "timestamp", "rule_name", "vendor_severity", "log_source",
    "host", "user", "src_ip", "dest_ip", "raw_log", "data_source",
]


def _dig(obj: Any, *keys: str, default=None):
    """Safely read a nested value, e.g. _dig(alert, 'host', 'name')."""
    cur = obj
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur if cur not in (None, "") else default


def parse_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Turn one raw alert into a flat dict with every STANDARD_FIELD present.

    Missing values become 'unknown' (text) or None (IPs), never a crash.
    """
    return {
        "alert_id": alert.get("alert_id", "unknown"),
        "timestamp": alert.get("timestamp", "unknown"),
        "rule_name": alert.get("rule_name") or alert.get("alert_name") or "unknown",
        "vendor_severity": (alert.get("vendor_severity") or "unknown").lower(),
        "log_source": alert.get("log_source", "unknown"),
        "host": _dig(alert, "host", "name", default="unknown"),
        "user": _dig(alert, "user", "name", default="unknown"),
        "src_ip": _dig(alert, "source", "ip"),
        "dest_ip": _dig(alert, "destination", "ip"),
        "raw_log": str(alert.get("raw_log", "")),
        "data_source": alert.get("data_source", "unknown"),
    }


def is_external_ip(ip: str) -> bool:
    """True if the IP is NOT an internal/private or documentation address."""
    if not ip:
        return False
    private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                        "172.19.", "172.20.", "127.")
    return not ip.startswith(private_prefixes)
