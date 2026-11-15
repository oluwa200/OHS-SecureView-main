"""
Email Security Historical Logger
=================================
Maintains a cumulative record of email security metrics for reporting.

Two outputs:
1. Per-cycle append log (data/email_security_log.jsonl)
   - One JSON line per agent cycle (every 15 min)
   - Full forensic record with individual alert details when present
   - Useful for incident timelines and audit trails

2. Daily rollup (data/email_security_daily.json)
   - Aggregated daily totals
   - Used by weekly briefs and executive reporting
   - Keeps last 180 days of history
"""
import json
import os
from datetime import datetime, timezone

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
LOG_FILE = os.path.join(DATA_DIR, "email_security_log.jsonl")
DAILY_FILE = os.path.join(DATA_DIR, "email_security_daily.json")
RETENTION_DAYS = 180


def log_email_security_cycle(defender_report: dict) -> dict:
    """Log email security metrics for the current cycle.

    Args:
        defender_report: The full defender_report.json dict (or None if fetch failed).

    Returns:
        The cycle record that was logged.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    now = datetime.now(timezone.utc)

    # Extract email security data from the report
    email_data = {}
    if defender_report:
        email_data = defender_report.get("email_security", {})

    email_alerts = email_data.get("alerts", [])

    # Compute category counts
    phishing_blocked = sum(1 for a in email_alerts if "phish" in (a.get("category") or "").lower())
    malware_blocked = sum(1 for a in email_alerts if "malware" in (a.get("category") or "").lower())
    initial_access = sum(1 for a in email_alerts if "initial" in (a.get("category") or "").lower())
    credential_theft = sum(1 for a in email_alerts if "credential" in (a.get("category") or "").lower())
    total_threats = len(email_alerts)

    # Build the cycle record
    record = {
        "timestamp": now.isoformat(),
        "date": now.strftime("%Y-%m-%d"),
        "hour": now.strftime("%H:%M"),
        "total_threats": total_threats,
        "phishing_blocked": phishing_blocked,
        "malware_blocked": malware_blocked,
        "initial_access": initial_access,
        "credential_theft": credential_theft,
        "fetch_success": defender_report is not None,
    }

    # Include alert details when threats are present (for forensic record)
    if email_alerts:
        record["alert_details"] = [
            {
                "category": a.get("category", "Unknown"),
                "severity": a.get("severity", "Unknown"),
                "title": a.get("title", "N/A"),
                "device": a.get("device", "N/A"),
                "threat_family": a.get("threat_family"),
                "created": a.get("created", ""),
            }
            for a in email_alerts
        ]

    # 1. Append to per-cycle JSONL log
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")

    # 2. Update daily rollup
    _update_daily_rollup(record)

    return record


def _update_daily_rollup(record: dict):
    """Aggregate cycle record into daily totals."""
    daily_history = []
    if os.path.exists(DAILY_FILE):
        try:
            with open(DAILY_FILE, "r", encoding="utf-8") as f:
                daily_history = json.load(f)
        except (json.JSONDecodeError, Exception):
            daily_history = []

    today = record["date"]

    # Find or create today's entry
    today_entry = None
    for entry in daily_history:
        if entry.get("date") == today:
            today_entry = entry
            break

    if today_entry is None:
        today_entry = {
            "date": today,
            "cycles_recorded": 0,
            "total_threats": 0,
            "phishing_blocked": 0,
            "malware_blocked": 0,
            "initial_access": 0,
            "credential_theft": 0,
            "peak_threats_single_cycle": 0,
            "fetch_failures": 0,
            "first_cycle": record["timestamp"],
            "last_cycle": record["timestamp"],
        }
        daily_history.append(today_entry)

    # Accumulate
    today_entry["cycles_recorded"] += 1
    today_entry["total_threats"] += record["total_threats"]
    today_entry["phishing_blocked"] += record["phishing_blocked"]
    today_entry["malware_blocked"] += record["malware_blocked"]
    today_entry["initial_access"] += record["initial_access"]
    today_entry["credential_theft"] += record["credential_theft"]
    today_entry["last_cycle"] = record["timestamp"]

    if record["total_threats"] > today_entry["peak_threats_single_cycle"]:
        today_entry["peak_threats_single_cycle"] = record["total_threats"]

    if not record["fetch_success"]:
        today_entry["fetch_failures"] += 1

    # Trim to retention period
    daily_history = daily_history[-RETENTION_DAYS:]

    with open(DAILY_FILE, "w", encoding="utf-8") as f:
        json.dump(daily_history, f, indent=2)


def get_daily_summary(days: int = 30) -> list:
    """Read last N days of email security history for reporting.

    Returns:
        List of daily rollup records, newest last.
    """
    if not os.path.exists(DAILY_FILE):
        return []
    try:
        with open(DAILY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)
        return history[-days:]
    except Exception:
        return []
