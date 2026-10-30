"""
Synthetic SIEM alert generator for TriageMate.

Creates labelled alerts across the five project categories:
benign, false_positive, credential_attack, lateral_movement, ransomware.

All IP addresses use documentation ranges (203.0.113.x, 198.51.100.x)
or private ranges (10.x), so no real systems are referenced.

Usage:
    python data/generate_alerts.py --count 100
"""
import argparse
import csv
import random
from datetime import datetime, timedelta

SCHEMA = [
    "alert_id", "timestamp", "host", "user", "src_ip", "dest_ip",
    "alert_name", "vendor_severity", "raw_log",
    "label_category", "label_priority",  # ground truth, written to labels.csv only
]

WORKSTATIONS = [f"WS-{n:03d}" for n in range(1, 40)]
SERVERS = ["SRV-FILE01", "SRV-WEB01", "SRV-SQL01", "DC01"]
USERS = ["jsmith", "apatel", "mchen", "lgarcia", "kbrown", "tnguyen"]
ADMINS = ["admin_rwilson", "svc_backup"]
SCANNER_IP = "10.0.5.50"  # internal vulnerability scanner (known benign)


def internal_ip():
    return f"10.0.{random.randint(1, 4)}.{random.randint(10, 250)}"


def external_ip():
    return random.choice(["203.0.113.", "198.51.100."]) + str(random.randint(1, 254))


def make_benign():
    host, user = random.choice(WORKSTATIONS), random.choice(USERS)
    name, log = random.choice([
        ("Successful user login", f"EventID=4624 LogonType=2 user={user} host={host} status=success"),
        ("Scheduled task executed", f"EventID=4698 task=WindowsUpdateCheck host={host} user=SYSTEM"),
        ("Antivirus definitions updated", f"av_engine=update version=1.4{random.randint(100,999)} host={host}"),
    ])
    return dict(host=host, user=user, src_ip=internal_ip(), dest_ip=internal_ip(),
                alert_name=name, vendor_severity="low", raw_log=log,
                label_category="benign", label_priority="Low")


def make_false_positive():
    host, user = random.choice(WORKSTATIONS), random.choice(USERS)
    choice = random.randint(0, 2)
    if choice == 0:
        fails = random.randint(3, 5)
        name = "Multiple failed logins"
        log = f"EventID=4625 failures={fails} user={user} host={host} reason=bad_password then EventID=4624 success"
        src = internal_ip()
    elif choice == 1:
        name = "Port scan detected"
        log = f"ids=portscan src={SCANNER_IP} ports_scanned={random.randint(200,1000)} schedule=weekly_vuln_scan"
        src = SCANNER_IP
    else:
        user = random.choice(ADMINS)
        name = "PowerShell execution"
        log = f"EventID=4104 user={user} host={host} script=C:\\IT\\scripts\\inventory_report.ps1 signed=true"
        src = internal_ip()
    return dict(host=host, user=user, src_ip=src, dest_ip=internal_ip(),
                alert_name=name, vendor_severity="medium", raw_log=log,
                label_category="false_positive", label_priority="Low")


def make_credential_attack():
    host, user = random.choice(WORKSTATIONS + SERVERS), random.choice(USERS + ADMINS)
    choice = random.randint(0, 2)
    if choice == 0:
        fails = random.randint(20, 80)
        name = "Brute force login attempts"
        log = f"EventID=4625 failures={fails} user={user} host={host} window=5m"
        src, prio = external_ip(), "High"
    elif choice == 1:
        name = "Password spray detected"
        log = f"EventID=4625 failures={random.randint(15,40)} distinct_users={random.randint(10,30)} host={host}"
        src, prio = external_ip(), "High"
    else:
        name = "LSASS memory access"
        log = f"EventID=10 target=lsass.exe source=C:\\Users\\{user}\\AppData\\Temp\\x.exe access=0x1010 host={host}"
        src, prio = internal_ip(), "Critical"
    return dict(host=host, user=user, src_ip=src, dest_ip=internal_ip(),
                alert_name=name, vendor_severity="high", raw_log=log,
                label_category="credential_attack", label_priority=prio)


def make_lateral_movement():
    src_host, dst_host = random.choice(WORKSTATIONS), random.choice(SERVERS)
    user = random.choice(USERS + ADMINS)
    name, log = random.choice([
        ("PsExec service installed", f"EventID=7045 service=PSEXESVC src={src_host} dest={dst_host} user={user}"),
        ("Remote WMI execution", f"wmic /node:{dst_host} process call create cmd.exe src={src_host} user={user}"),
        ("Unusual RDP connection", f"EventID=4624 LogonType=10 src={src_host} dest={dst_host} user={user} first_seen=true"),
    ])
    return dict(host=dst_host, user=user, src_ip=internal_ip(), dest_ip=internal_ip(),
                alert_name=name, vendor_severity="high", raw_log=log,
                label_category="lateral_movement", label_priority="High")


def make_ransomware():
    host, user = random.choice(WORKSTATIONS + SERVERS), random.choice(USERS)
    name, log = random.choice([
        ("Shadow copies deleted", f"process=vssadmin.exe cmd='vssadmin delete shadows /all /quiet' host={host} user={user}"),
        ("Mass file rename", f"files_renamed={random.randint(500,5000)} extension=.locked window=60s host={host} user={user}"),
        ("Ransom note created", f"file=README_RESTORE_FILES.txt count={random.randint(50,400)} host={host}"),
    ])
    return dict(host=host, user=user, src_ip=internal_ip(), dest_ip=internal_ip(),
                alert_name=name, vendor_severity="critical", raw_log=log,
                label_category="ransomware", label_priority="Critical")


# Realistic mix: most alerts are noise, a few are serious
MIX = [(make_benign, 0.35), (make_false_positive, 0.25), (make_credential_attack, 0.18),
       (make_lateral_movement, 0.12), (make_ransomware, 0.10)]


def generate(count, seed=42):
    random.seed(seed)
    start = datetime(2026, 10, 1, 8, 0, 0)
    makers, weights = zip(*MIX)
    rows = []
    for i in range(count):
        row = random.choices(makers, weights)[0]()
        row["alert_id"] = f"ALT-{i + 1:04d}"
        row["timestamp"] = (start + timedelta(minutes=7 * i + random.randint(0, 6))).isoformat()
        rows.append({k: row[k] for k in SCHEMA})
    return rows


def log_source(raw):
    if raw.startswith("EventID=10 "):
        return "Sysmon"
    if raw.startswith("EventID=4104"):
        return "WinEventLog:PowerShell"
    if raw.startswith("EventID="):
        return "WinEventLog:Security"
    if raw.startswith("ids="):
        return "Suricata"
    if raw.startswith("av_engine"):
        return "Defender"
    return "EDR"


def to_siem_event(row):
    """Shape one alert like a SIEM export (nested JSON, no answer labels)."""
    return {
        "alert_id": row["alert_id"],
        "timestamp": row["timestamp"],
        "rule_name": row["alert_name"],
        "vendor_severity": row["vendor_severity"],
        "log_source": log_source(row["raw_log"]),
        "host": {"name": row["host"]},
        "user": {"name": row["user"]},
        "source": {"ip": row["src_ip"]},
        "destination": {"ip": row["dest_ip"]},
        "raw_log": row["raw_log"],
    }


if __name__ == "__main__":
    import json
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--out", default="data/siem_alerts.jsonl")
    parser.add_argument("--labels", default="data/labels.csv")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    rows = generate(args.count, args.seed)
    with open(args.out, "w") as f:
        for row in rows:
            f.write(json.dumps(to_siem_event(row)) + "\n")
    with open(args.labels, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["alert_id", "label_category", "label_priority"])
        for row in rows:
            writer.writerow([row["alert_id"], row["label_category"], row["label_priority"]])
    print(f"Wrote {len(rows)} alerts to {args.out} and labels to {args.labels}")
