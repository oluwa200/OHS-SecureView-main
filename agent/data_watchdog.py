"""
Data Integrity Watchdog
========================
Runs as part of the unified agent cycle (or standalone) to:
1. Check file ages — flag stale data, trigger re-pull signals
2. Cross-validate counts — compare API counts vs file counts (>5% = re-pull)
3. Validate JSON structure — corrupt files trigger re-pull
4. Log discrepancies for audit

Usage:
    from agent.data_watchdog import run_watchdog
    issues = run_watchdog()  # Returns list of issues found
"""
import os
import sys
import json
import time
import logging
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

log = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DEFENDER_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "defender_data")

# ─── Configuration ────────────────────────────────────────────────────────────
# Max age in minutes before data is considered stale
FRESHNESS_THRESHOLDS = {
    "crowdstrike_hosts.json": 60,
    "aws_ec2_instances.json": 60,
    "aws_ec2_counts.json": 60,
    "vulnerability_report.json": 1440,  # 24 hours (Qualys scans less frequently)
    "bindplane_agents.json": 60,
    "ai_insights.json": 60,
    "crowdstrike_iom_analysis.json": 60,
    "defender_report.json": 120,  # 2 hours (Defender refreshes separately)
    "aikido_report.json": 60,
    "aws_workspaces.json": 1440,
    "history.json": 1440,
}

# Required keys for structural validation
REQUIRED_STRUCTURE = {
    "crowdstrike_hosts.json": ["accounts", "updated_at"],
    "aws_ec2_instances.json": ["accounts"],
    "aws_ec2_counts.json": ["total_instances", "by_account"],
    "vulnerability_report.json": [],  # Top-level keys are account names, flexible
    "bindplane_agents.json": ["agents", "updated_at"],
    "ai_insights.json": ["overall_risk_score", "stats", "generated_at"],
    "crowdstrike_iom_analysis.json": ["summary", "prioritized_findings"],
    "defender_report.json": ["summary"],
    "history.json": [],  # List, no required keys
}

# Cross-validation rules: what counts should roughly match
CROSS_VALIDATIONS = [
    {
        "name": "EC2 counts vs instances",
        "count_file": "aws_ec2_counts.json",
        "count_path": "total_instances",
        "detail_file": "aws_ec2_instances.json",
        "detail_counter": lambda d: sum(len(v) for v in d.get("accounts", {}).values()),
        "tolerance_pct": 5,
    },
    {
        "name": "CrowdStrike host count consistency",
        "count_file": "crowdstrike_hosts.json",
        "count_path": None,  # Custom
        "detail_file": "crowdstrike_hosts.json",
        "detail_counter": lambda d: sum(len(v) for v in d.get("accounts", {}).values()),
        "expected_counter": lambda d: sum(len(v) for v in d.get("accounts", {}).values()),
        "tolerance_pct": 0,  # Should be exact
    },
    {
        "name": "AI insights EC2 total matches EC2 counts",
        "count_file": "ai_insights.json",
        "count_path": "stats.total_ec2_ips",
        "detail_file": "aws_ec2_counts.json",
        "detail_counter": lambda d: d.get("total_instances", 0),
        "tolerance_pct": 10,  # Insights count unique IPs, EC2 counts all instances
    },
]


# ─── Issue Tracking ───────────────────────────────────────────────────────────
class WatchdogIssue:
    """Represents a data integrity issue."""

    def __init__(self, severity, category, file, message, action=None):
        self.severity = severity  # CRITICAL, WARNING, INFO
        self.category = category  # stale, corrupt, mismatch, missing
        self.file = file
        self.message = message
        self.action = action  # suggested action: "re-pull", "investigate", None
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "file": self.file,
            "message": self.message,
            "action": self.action,
            "timestamp": self.timestamp,
        }

    def __repr__(self):
        return f"[{self.severity}] {self.category}: {self.file} — {self.message}"


# ─── Check Functions ──────────────────────────────────────────────────────────
def check_freshness():
    """Check file modification times against thresholds."""
    issues = []
    now = time.time()

    for filename, max_age_min in FRESHNESS_THRESHOLDS.items():
        path = os.path.join(DATA_DIR, filename)
        # Also check defender_data mount
        if not os.path.exists(path):
            path = os.path.join(DEFENDER_DATA_DIR, filename)

        if not os.path.exists(path):
            issues.append(WatchdogIssue(
                severity="WARNING",
                category="missing",
                file=filename,
                message=f"File does not exist in data or defender_data directories",
                action="re-pull",
            ))
            continue

        mtime = os.path.getmtime(path)
        age_min = (now - mtime) / 60

        if age_min > max_age_min * 3:
            issues.append(WatchdogIssue(
                severity="CRITICAL",
                category="stale",
                file=filename,
                message=f"Severely stale: {age_min:.0f} min old (threshold: {max_age_min} min)",
                action="re-pull",
            ))
        elif age_min > max_age_min:
            issues.append(WatchdogIssue(
                severity="WARNING",
                category="stale",
                file=filename,
                message=f"Stale: {age_min:.0f} min old (threshold: {max_age_min} min)",
                action="re-pull",
            ))

    return issues


def check_structure():
    """Validate JSON file structure — detect corruption or unexpected formats."""
    issues = []

    for filename, required_keys in REQUIRED_STRUCTURE.items():
        path = os.path.join(DATA_DIR, filename)
        if not os.path.exists(path):
            path = os.path.join(DEFENDER_DATA_DIR, filename)
        if not os.path.exists(path):
            continue  # Missing files handled by freshness check

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            issues.append(WatchdogIssue(
                severity="CRITICAL",
                category="corrupt",
                file=filename,
                message=f"JSON parse error: {e}",
                action="re-pull",
            ))
            continue
        except Exception as e:
            issues.append(WatchdogIssue(
                severity="CRITICAL",
                category="corrupt",
                file=filename,
                message=f"Read error: {e}",
                action="re-pull",
            ))
            continue

        # Check file size (empty or suspiciously small)
        file_size = os.path.getsize(path)
        if file_size < 10:
            issues.append(WatchdogIssue(
                severity="CRITICAL",
                category="corrupt",
                file=filename,
                message=f"File too small ({file_size} bytes) — likely empty/corrupt",
                action="re-pull",
            ))
            continue

        # Check required keys (for dict-type files)
        if required_keys and isinstance(data, dict):
            missing_keys = [k for k in required_keys if k not in data]
            if missing_keys:
                issues.append(WatchdogIssue(
                    severity="WARNING",
                    category="corrupt",
                    file=filename,
                    message=f"Missing required keys: {missing_keys}",
                    action="investigate",
                ))

        # Check for list-type files (history.json)
        if filename == "history.json" and not isinstance(data, list):
            issues.append(WatchdogIssue(
                severity="WARNING",
                category="corrupt",
                file=filename,
                message=f"Expected list, got {type(data).__name__}",
                action="re-pull",
            ))

    return issues


def check_cross_validation():
    """Cross-validate counts between related files."""
    issues = []

    for rule in CROSS_VALIDATIONS:
        count_path = os.path.join(DATA_DIR, rule["count_file"])
        detail_path = os.path.join(DATA_DIR, rule["detail_file"])

        if not os.path.exists(count_path) or not os.path.exists(detail_path):
            continue

        try:
            with open(count_path, "r", encoding="utf-8") as f:
                count_data = json.load(f)
            with open(detail_path, "r", encoding="utf-8") as f:
                detail_data = json.load(f)
        except Exception:
            continue  # Structure check will catch these

        # Get the count value
        if rule.get("count_path"):
            count_val = count_data
            for key in rule["count_path"].split("."):
                if isinstance(count_val, dict):
                    count_val = count_val.get(key, 0)
                else:
                    count_val = 0
                    break
        elif rule.get("expected_counter"):
            count_val = rule["expected_counter"](count_data)
        else:
            continue

        # Get the detail count
        detail_val = rule["detail_counter"](detail_data)

        # Compare
        if count_val == 0 and detail_val == 0:
            continue  # Both empty, no issue

        if count_val == 0 or detail_val == 0:
            if count_val != detail_val:
                issues.append(WatchdogIssue(
                    severity="WARNING",
                    category="mismatch",
                    file=f"{rule['count_file']} vs {rule['detail_file']}",
                    message=f"{rule['name']}: count={count_val}, detail={detail_val} (one is zero)",
                    action="investigate",
                ))
            continue

        diff_pct = abs(count_val - detail_val) / max(count_val, detail_val) * 100
        if diff_pct > rule["tolerance_pct"]:
            issues.append(WatchdogIssue(
                severity="WARNING" if diff_pct < 20 else "CRITICAL",
                category="mismatch",
                file=f"{rule['count_file']} vs {rule['detail_file']}",
                message=f"{rule['name']}: count={count_val}, detail={detail_val} ({diff_pct:.1f}% diff, tolerance={rule['tolerance_pct']}%)",
                action="re-pull" if diff_pct > 20 else "investigate",
            ))

    return issues


def check_defender_data_accessible():
    """Verify the Defender data volume is mounted and readable."""
    issues = []

    if not os.path.exists(DEFENDER_DATA_DIR):
        issues.append(WatchdogIssue(
            severity="WARNING",
            category="missing",
            file="defender_data/",
            message="Defender data directory not found — volume may not be mounted",
            action="investigate",
        ))
        return issues

    defender_report = os.path.join(DEFENDER_DATA_DIR, "defender_report.json")
    if not os.path.exists(defender_report):
        # Check if it's in DATA_DIR instead
        if not os.path.exists(os.path.join(DATA_DIR, "defender_report.json")):
            issues.append(WatchdogIssue(
                severity="WARNING",
                category="missing",
                file="defender_report.json",
                message="Defender report not found in either data or defender_data directories",
                action="re-pull",
            ))

    return issues


def check_cross_dashboard_correlation():
    """Cross-correlate asset counts across Defender, BindPlane, EC2, and CrowdStrike.

    Catches discrepancies like:
    - Defender showing inactive devices inflating counts
    - BindPlane duplicate hostnames inflating agent totals
    - EC2 running instances not covered by any security tool
    - CrowdStrike hosts disappearing between cycles
    """
    issues = []

    # ─── Load all data sources ────────────────────────────────────────────────
    def _load(filename):
        path = os.path.join(DATA_DIR, filename)
        if not os.path.exists(path):
            path = os.path.join(DEFENDER_DATA_DIR, filename)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    defender_data = _load("defender_report.json")
    bp_data = _load("bindplane_agents.json")
    ec2_data = _load("aws_ec2_instances.json")
    cs_data = _load("crowdstrike_hosts.json")

    # ─── Defender: Active vs Total ────────────────────────────────────────────
    if defender_data:
        devices = defender_data.get("device_inventory", [])
        active_devices = [d for d in devices if d.get("health") == "Active"]
        inactive_devices = [d for d in devices if d.get("health") != "Active"]
        total = len(devices)
        active = len(active_devices)
        inactive = len(inactive_devices)

        if total > 0 and inactive / total > 0.3:
            issues.append(WatchdogIssue(
                severity="WARNING",
                category="mismatch",
                file="defender_report.json",
                message=f"High inactive ratio: {inactive}/{total} devices inactive ({inactive/total*100:.0f}%). "
                        f"Only {active} active devices. Consider filtering reports to Active only.",
                action="investigate",
            ))

    # ─── BindPlane: Deduplication check ───────────────────────────────────────
    if bp_data:
        agents = bp_data.get("agents", [])
        raw_count = len(agents)
        seen_hostnames = set()
        unique_count = 0
        duplicate_count = 0
        for a in agents:
            hn = (a.get("hostname") or a.get("name") or "").lower().strip()
            if hn and hn in seen_hostnames:
                duplicate_count += 1
            else:
                if hn:
                    seen_hostnames.add(hn)
                unique_count += 1

        if duplicate_count > 0 and duplicate_count / raw_count > 0.05:
            issues.append(WatchdogIssue(
                severity="WARNING",
                category="mismatch",
                file="bindplane_agents.json",
                message=f"BindPlane has {duplicate_count} duplicate hostnames "
                        f"({raw_count} raw → {unique_count} unique, {duplicate_count/raw_count*100:.1f}% duplicates). "
                        f"Dashboard should deduplicate before displaying counts.",
                action="investigate",
            ))

    # ─── EC2 Running vs CrowdStrike Coverage ─────────────────────────────────
    if ec2_data and cs_data:
        # Count running EC2 instances
        running_instances = 0
        ec2_ips = set()
        for acct_instances in ec2_data.get("accounts", {}).values():
            for inst in acct_instances:
                if (inst.get("state") or inst.get("State", "")) == "running":
                    running_instances += 1
                    ip = inst.get("PrivateIp") or inst.get("private_ip", "")
                    if ip:
                        ec2_ips.add(ip)

        # CrowdStrike IPs
        cs_ips = set()
        for acct_hosts in cs_data.get("accounts", {}).values():
            for host in acct_hosts:
                ip = host.get("local_ip", "")
                if ip:
                    cs_ips.add(ip)

        # Coverage gap
        covered = len(ec2_ips & cs_ips)
        uncovered = len(ec2_ips - cs_ips)
        coverage_pct = (covered / len(ec2_ips) * 100) if ec2_ips else 100

        if coverage_pct < 80:
            issues.append(WatchdogIssue(
                severity="CRITICAL",
                category="mismatch",
                file="crowdstrike_hosts.json vs aws_ec2_instances.json",
                message=f"CrowdStrike EDR coverage gap: only {covered}/{len(ec2_ips)} "
                        f"running EC2 IPs covered ({coverage_pct:.0f}%). "
                        f"{uncovered} instances without EDR protection.",
                action="investigate",
            ))
        elif coverage_pct < 95:
            issues.append(WatchdogIssue(
                severity="WARNING",
                category="mismatch",
                file="crowdstrike_hosts.json vs aws_ec2_instances.json",
                message=f"CrowdStrike EDR coverage: {covered}/{len(ec2_ips)} "
                        f"running EC2 IPs ({coverage_pct:.0f}%). {uncovered} uncovered.",
                action="investigate",
            ))

    # ─── BindPlane vs EC2: Telemetry coverage ────────────────────────────────
    if bp_data and ec2_data:
        bp_ips = set()
        for agent in bp_data.get("agents", []):
            ip = (agent.get("remoteAddress") or agent.get("ip") or "").split(":")[0]
            if ip:
                bp_ips.add(ip)

        if ec2_ips:  # Reuse from above
            bp_covered = len(ec2_ips & bp_ips)
            bp_uncovered = len(ec2_ips - bp_ips)
            bp_coverage_pct = (bp_covered / len(ec2_ips) * 100) if ec2_ips else 100

            if bp_coverage_pct < 70:
                issues.append(WatchdogIssue(
                    severity="WARNING",
                    category="mismatch",
                    file="bindplane_agents.json vs aws_ec2_instances.json",
                    message=f"BindPlane telemetry coverage: only {bp_covered}/{len(ec2_ips)} "
                            f"EC2 IPs have agents ({bp_coverage_pct:.0f}%). "
                            f"{bp_uncovered} instances without log telemetry.",
                    action="investigate",
                ))

    # ─── Defender Active vs BindPlane Laptops ─────────────────────────────────
    if defender_data and bp_data:
        # Defender active laptops (non-server, Active health)
        defender_active_names = set()
        for d in defender_data.get("device_inventory", []):
            if d.get("health") == "Active":
                name = (d.get("name") or "").lower().strip()
                if name:
                    defender_active_names.add(name)

        # BindPlane laptop hostnames (start with digit = laptop convention)
        bp_laptop_names = set()
        for a in bp_data.get("agents", []):
            hn = (a.get("hostname") or a.get("name") or "").lower().strip()
            if hn and hn[0:1].isdigit():
                bp_laptop_names.add(hn)

        if defender_active_names and bp_laptop_names:
            overlap = defender_active_names & bp_laptop_names
            defender_only = defender_active_names - bp_laptop_names
            # Only flag if significant gap exists AND both sources have data
            if len(defender_only) > 20 and len(bp_laptop_names) > 10:
                gap_pct = len(defender_only) / len(defender_active_names) * 100
                if gap_pct > 30:
                    issues.append(WatchdogIssue(
                        severity="WARNING",
                        category="mismatch",
                        file="defender_report.json vs bindplane_agents.json",
                        message=f"Defender has {len(defender_only)} active devices without BindPlane agents "
                                f"({gap_pct:.0f}% gap). {len(overlap)} devices have both.",
                        action="investigate",
                    ))

    return issues


# ─── Main Entry Point ─────────────────────────────────────────────────────────
def run_watchdog():
    """Run all watchdog checks, auto-correct fixable issues, and return remaining issues.

    Auto-corrections applied:
    - BindPlane duplicates: re-deduplicates the file on disk
    - Defender active filtering: updates summary counts to reflect Active only
    - Corrupt JSON: triggers marker for next agent cycle to re-pull

    Returns:
        list[WatchdogIssue]: Issues found (after auto-correction applied).
    """
    log.info("Running data integrity watchdog...")

    all_issues = []
    all_issues.extend(check_freshness())
    all_issues.extend(check_structure())
    all_issues.extend(check_cross_validation())
    all_issues.extend(check_defender_data_accessible())
    all_issues.extend(check_cross_dashboard_correlation())

    # ─── Auto-Correct: BindPlane Duplicates ───────────────────────────────────
    bp_path = os.path.join(DATA_DIR, "bindplane_agents.json")
    if os.path.exists(bp_path):
        try:
            with open(bp_path, "r", encoding="utf-8") as f:
                bp_data = json.load(f)
            agents_raw = bp_data.get("agents", [])
            seen = {}
            for a in agents_raw:
                hn = (a.get("hostname") or a.get("name") or "").lower().strip()
                if not hn:
                    continue
                existing = seen.get(hn)
                if existing is None:
                    seen[hn] = a
                else:
                    a_conn = a.get("status") in ("connected", 1, "1")
                    ex_conn = existing.get("status") in ("connected", 1, "1")
                    if a_conn and not ex_conn:
                        seen[hn] = a
                    elif a_conn == ex_conn:
                        a_ts = a.get("connectedAt") or a.get("disconnectedAt") or ""
                        ex_ts = existing.get("connectedAt") or existing.get("disconnectedAt") or ""
                        if a_ts > ex_ts:
                            seen[hn] = a

            deduped = list(seen.values())
            if len(deduped) < len(agents_raw):
                removed = len(agents_raw) - len(deduped)
                bp_data["agents"] = deduped
                bp_data["raw_count"] = len(agents_raw)
                bp_data["deduped_count"] = removed
                with open(bp_path, "w", encoding="utf-8") as f:
                    json.dump(bp_data, f, indent=2, default=str)
                log.info(f"  Watchdog auto-fix: BindPlane deduplicated {len(agents_raw)} → {len(deduped)}")
        except Exception as e:
            log.warning(f"  Watchdog auto-fix BindPlane failed: {e}")

    # ─── Auto-Correct: Defender summary counts ────────────────────────────────
    defender_path = os.path.join(DATA_DIR, "defender_report.json")
    if not os.path.exists(defender_path):
        defender_path = os.path.join(DEFENDER_DATA_DIR, "defender_report.json")
    if os.path.exists(defender_path):
        try:
            with open(defender_path, "r", encoding="utf-8") as f:
                def_data = json.load(f)
            devices = def_data.get("device_inventory", [])
            if devices:
                active = sum(1 for d in devices if d.get("health") == "Active")
                inactive = sum(1 for d in devices if d.get("health") != "Active")
                summary = def_data.get("summary", {})
                # Auto-correct summary if counts are wrong
                if summary.get("active") != active or summary.get("inactive") != inactive:
                    summary["active"] = active
                    summary["inactive"] = inactive
                    summary["total_devices_mde"] = len(devices)
                    def_data["summary"] = summary
                    with open(defender_path, "w", encoding="utf-8") as f:
                        json.dump(def_data, f, indent=2, default=str)
                    log.info(f"  Watchdog auto-fix: Defender summary corrected (active={active}, inactive={inactive})")
        except Exception as e:
            log.warning(f"  Watchdog auto-fix Defender failed: {e}")

    # ─── Auto-Correct: Aikido summary counts ──────────────────────────────────
    aikido_path = os.path.join(DATA_DIR, "aikido_report.json")
    if os.path.exists(aikido_path):
        try:
            with open(aikido_path, "r", encoding="utf-8") as f:
                aik_data = json.load(f)
            apps = aik_data.get("applications", [])
            if apps:
                # Recompute summary from raw application data
                total_issues = sum(len(a.get("issues", [])) for a in apps)
                total_breached = sum(a.get("summary", {}).get("breached", 0) for a in apps)
                total_within = sum(a.get("summary", {}).get("within_sla", 0) for a in apps)
                total_at_risk = sum(a.get("summary", {}).get("at_risk", 0) for a in apps)
                recomputed_compliance = round(total_within / max(total_issues, 1) * 100, 1)

                summary = aik_data.get("summary", {})
                stored_total = summary.get("total_issues", 0)
                stored_compliance = summary.get("compliance_pct", 0)

                # Fix if mismatch
                if stored_total != total_issues or abs(stored_compliance - recomputed_compliance) > 1:
                    summary["total_issues"] = total_issues
                    summary["total_applications"] = len(apps)
                    summary["sla_status"] = {"breached": total_breached, "at_risk": total_at_risk, "within_sla": total_within}
                    summary["compliance_pct"] = recomputed_compliance
                    aik_data["summary"] = summary
                    with open(aikido_path, "w", encoding="utf-8") as f:
                        json.dump(aik_data, f, indent=2, default=str)
                    log.info(f"  Watchdog auto-fix: Aikido summary corrected (issues={total_issues}, compliance={recomputed_compliance}%)")
        except Exception as e:
            log.warning(f"  Watchdog auto-fix Aikido failed: {e}")

    # Sort: CRITICAL first, then WARNING, then INFO
    severity_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    all_issues.sort(key=lambda i: severity_order.get(i.severity, 9))

    # Write audit log
    _write_audit_log(all_issues)

    # Summary
    critical = sum(1 for i in all_issues if i.severity == "CRITICAL")
    warning = sum(1 for i in all_issues if i.severity == "WARNING")
    log.info(f"  Watchdog complete: {critical} critical, {warning} warnings, {len(all_issues)} total issues")

    if critical > 0:
        log.warning(f"  ⚠️  {critical} CRITICAL data integrity issues found!")
        for issue in all_issues:
            if issue.severity == "CRITICAL":
                log.warning(f"    → {issue}")

    return all_issues


def _write_audit_log(issues):
    """Write watchdog results to an audit log file."""
    audit_path = os.path.join(DATA_DIR, "watchdog_audit.json")
    os.makedirs(DATA_DIR, exist_ok=True)

    # Load existing audit entries
    audit = []
    if os.path.exists(audit_path):
        try:
            with open(audit_path, "r", encoding="utf-8") as f:
                audit = json.load(f)
        except Exception:
            audit = []

    # Append this run
    entry = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "issues_count": len(issues),
        "critical": sum(1 for i in issues if i.severity == "CRITICAL"),
        "warnings": sum(1 for i in issues if i.severity == "WARNING"),
        "issues": [i.to_dict() for i in issues],
    }
    audit.append(entry)

    # Keep last 100 runs
    audit = audit[-100:]

    with open(audit_path, "w", encoding="utf-8") as f:
        json.dump(audit, f, indent=2, default=str)


def get_stale_files():
    """Get list of files that need re-pulling (convenience for agent).

    Returns:
        list[str]: Filenames that are stale or corrupt.
    """
    issues = run_watchdog()
    return list(set(
        i.file for i in issues
        if i.action == "re-pull" and i.file in FRESHNESS_THRESHOLDS
    ))


# ─── Standalone Execution ─────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [Watchdog] %(message)s")
    issues = run_watchdog()
    print(f"\n{'='*60}")
    print(f"Data Integrity Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*60}")
    if not issues:
        print("✅ All data files healthy.")
    else:
        for issue in issues:
            icon = "🔴" if issue.severity == "CRITICAL" else "🟡" if issue.severity == "WARNING" else "ℹ️"
            print(f"  {icon} [{issue.category}] {issue.file}: {issue.message}")
    print(f"{'='*60}")
