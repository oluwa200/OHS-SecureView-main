"""Daily Snapshot — Stores key metrics for historical trending."""
import json
import os
import time
from datetime import datetime, timezone

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
INTERVAL = int(os.getenv("SNAPSHOT_INTERVAL_SECONDS", "86400"))  # Default: 24 hours


def load_json(filename):
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def take_snapshot():
    """Capture current metrics and append to history."""
    ec2_counts = load_json("aws_ec2_counts.json")
    cs_hosts = load_json("crowdstrike_hosts.json")
    vuln_report = load_json("vulnerability_report.json")
    ai_insights = load_json("ai_insights.json")

    # Calculate metrics
    total_ec2 = ec2_counts.get("total_instances", 0)
    total_cs = sum(len(h) for h in cs_hosts.get("accounts", {}).values())

    total_vuln_assets = 0
    total_internet_facing = 0
    for acct_data in vuln_report.values():
        if isinstance(acct_data, dict):
            total_vuln_assets += acct_data.get("total_assets", 0)
            total_internet_facing += acct_data.get("internet_facing_count", 0)

    risk_score = ai_insights.get("overall_risk_score", 0) if ai_insights else 0
    edr_coverage = ai_insights.get("stats", {}).get("edr_coverage_pct", 0) if ai_insights else 0
    vuln_coverage = ai_insights.get("stats", {}).get("vuln_scan_coverage_pct", 0) if ai_insights else 0

    snapshot = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "total_ec2": total_ec2,
        "crowdstrike_hosts": total_cs,
        "qualys_assets": total_vuln_assets,
        "internet_facing": total_internet_facing,
        "risk_score": risk_score,
        "edr_coverage_pct": edr_coverage,
        "vuln_scan_coverage_pct": vuln_coverage,
    }

    # Load existing history
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception:
            history = []

    # Don't duplicate if already snapshotted today
    today = snapshot["date"]
    if history and history[-1].get("date") == today:
        print(f"[Snapshot] Already captured for {today}, updating...")
        history[-1] = snapshot
    else:
        history.append(snapshot)
        # Keep last 90 days
        history = history[-90:]

    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

    print(f"[Snapshot] Captured: EC2={total_ec2}, CS={total_cs}, Qualys={total_vuln_assets}, Risk={risk_score}")
    return snapshot


def main():
    """Run snapshot loop."""
    print(f"[Snapshot] Starting (interval: {INTERVAL}s)")
    while True:
        try:
            take_snapshot()
        except Exception as e:
            print(f"[Snapshot] Error: {e}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
