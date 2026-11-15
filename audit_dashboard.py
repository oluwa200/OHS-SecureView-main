"""
Full Dashboard Data Audit
===========================
Checks data integrity, SLA accuracy, and cross-correlation consistency.
Run against data-dev/ to validate before promoting to prod.
"""
import json
import os
from datetime import datetime, timezone

DATA_DIR = "data-dev"
ERRORS = []
WARNINGS = []
PASSED = []


def check(condition, msg, severity="ERROR"):
    if condition:
        PASSED.append(f"✅ {msg}")
    elif severity == "ERROR":
        ERRORS.append(f"❌ {msg}")
    else:
        WARNINGS.append(f"⚠️ {msg}")


def load(filename):
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def audit_aikido():
    """Audit Aikido data — SLA accuracy, totals, consistency."""
    print("\n═══ AIKIDO AUDIT ═══")
    data = load("aikido_report.json")
    if not data:
        ERRORS.append("❌ aikido_report.json not found")
        return

    summary = data.get("summary", {})
    apps = data.get("applications", [])

    # 1. Verify total issues matches sum of app issues
    total_from_summary = summary.get("total_issues", 0)
    total_from_apps = sum(len(a.get("issues", [])) for a in apps)
    check(total_from_summary == total_from_apps,
          f"Aikido total: summary={total_from_summary} vs apps={total_from_apps}")

    # 2. Verify SLA counts add up
    sla = summary.get("sla_status", {})
    sla_total = sla.get("breached", 0) + sla.get("at_risk", 0) + sla.get("within_sla", 0)
    check(sla_total == total_from_apps,
          f"Aikido SLA totals: breached+at_risk+within={sla_total} vs total_issues={total_from_apps}")

    # 3. Verify per-app SLA counts add up
    app_breached = sum(a.get("summary", {}).get("breached", 0) for a in apps)
    app_at_risk = sum(a.get("summary", {}).get("at_risk", 0) for a in apps)
    app_within = sum(a.get("summary", {}).get("within_sla", 0) for a in apps)
    check(app_breached == sla.get("breached", 0),
          f"Aikido breached: summary={sla.get('breached',0)} vs apps={app_breached}")
    check(app_at_risk == sla.get("at_risk", 0),
          f"Aikido at_risk: summary={sla.get('at_risk',0)} vs apps={app_at_risk}", "WARNING")
    check(app_within == sla.get("within_sla", 0),
          f"Aikido within_sla: summary={sla.get('within_sla',0)} vs apps={app_within}", "WARNING")

    # 4. Verify severity counts
    sev = summary.get("severity", {})
    sev_from_apps = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in apps:
        for k in sev_from_apps:
            sev_from_apps[k] += a.get("summary", {}).get(k, 0)
    for k in sev_from_apps:
        check(sev.get(k, 0) == sev_from_apps[k],
              f"Aikido severity {k}: summary={sev.get(k,0)} vs apps={sev_from_apps[k]}", "WARNING")

    # 5. Compare our SLA calc against Aikido's own sla_days field
    now = datetime.now(timezone.utc).timestamp()
    mismatches = 0
    total_checked = 0
    for a in apps:
        for issue in a.get("issues", []):
            aikido_sla = issue.get("sla_remediate_by")
            our_status = issue.get("status", "")
            first = issue.get("first_detected", 0)
            if isinstance(first, (int, float)) and first > 0:
                days_open = (now - first) / 86400
                our_sla_days = issue.get("sla_days", 0)
                our_remaining = our_sla_days - days_open
                # Cross-check: if we say breached, is it actually old enough?
                if our_status == "BREACHED" and our_remaining > 0:
                    mismatches += 1
                elif our_status == "WITHIN SLA" and our_remaining < 0:
                    mismatches += 1
                total_checked += 1

    check(mismatches == 0,
          f"Aikido SLA calc consistency: {mismatches}/{total_checked} mismatches")

    # 6. New vs Legacy split
    thirty_days_ago = now - (30 * 86400)
    new_count = 0
    legacy_count = 0
    for a in apps:
        for issue in a.get("issues", []):
            first = issue.get("first_detected", 0)
            if isinstance(first, (int, float)) and first > 0:
                if first > thirty_days_ago:
                    new_count += 1
                else:
                    legacy_count += 1
    check(new_count + legacy_count == total_from_apps,
          f"Aikido new+legacy={new_count + legacy_count} vs total={total_from_apps}", "WARNING")

    print(f"  Apps: {len(apps)} | Issues: {total_from_apps}")
    print(f"  SLA: Breached={sla.get('breached',0)} AtRisk={sla.get('at_risk',0)} Within={sla.get('within_sla',0)}")
    print(f"  New(30d): {new_count} | Legacy: {legacy_count}")


def audit_ec2_coverage():
    """Audit EC2 cross-correlation accuracy."""
    print("\n═══ EC2 COVERAGE AUDIT ═══")
    ec2 = load("aws_ec2_instances.json")
    cs = load("crowdstrike_hosts.json")
    insights = load("ai_insights.json")

    if not ec2:
        WARNINGS.append("⚠️ aws_ec2_instances.json not found")
        return
    if not cs:
        WARNINGS.append("⚠️ crowdstrike_hosts.json not found")
        return

    # Count EC2 with IPs
    total_ec2 = 0
    ec2_ips = set()
    for acct in ec2.get("accounts", {}).values():
        for inst in acct:
            ip = inst.get("PrivateIp", "") or inst.get("private_ip", "")
            if ip:
                ec2_ips.add(ip)
                total_ec2 += 1

    # Count CS IPs
    cs_ips = set()
    for acct_hosts in cs.get("accounts", {}).values():
        for h in acct_hosts:
            ip = h.get("local_ip", "")
            if ip and ip != "N/A":
                cs_ips.add(ip)

    # Cross-correlate
    protected = ec2_ips & cs_ips
    unprotected = ec2_ips - cs_ips
    stale_cs = cs_ips - ec2_ips

    check(total_ec2 > 0, f"EC2 instances found: {total_ec2}")
    check(len(cs_ips) > 0, f"CrowdStrike hosts found: {len(cs_ips)}")

    # Verify against AI insights
    if insights:
        stats = insights.get("stats", {})
        insight_total = stats.get("total_ec2_ips", 0)
        insight_no_edr = stats.get("no_edr", 0)
        check(insight_total == total_ec2,
              f"AI Insights EC2 total: {insight_total} vs actual: {total_ec2}", "WARNING")

    print(f"  EC2 (with IP): {total_ec2}")
    print(f"  CrowdStrike IPs: {len(cs_ips)}")
    print(f"  Protected: {len(protected)} | Unprotected: {len(unprotected)} | Stale CS: {len(stale_cs)}")


def audit_defender():
    """Audit Defender data accuracy."""
    print("\n═══ DEFENDER AUDIT ═══")
    data = load("defender_report.json")
    if not data:
        WARNINGS.append("⚠️ defender_report.json not found")
        return

    summary = data.get("summary", {})
    devices = data.get("device_inventory", [])

    # Recompute active/inactive from raw
    active = sum(1 for d in devices if d.get("health") == "Active")
    inactive = sum(1 for d in devices if d.get("health") != "Active")

    check(summary.get("active") == active,
          f"Defender active: summary={summary.get('active')} vs recomputed={active}")
    check(summary.get("inactive") == inactive,
          f"Defender inactive: summary={summary.get('inactive')} vs recomputed={inactive}")
    check(summary.get("total_devices_mde") == len(devices),
          f"Defender total: summary={summary.get('total_devices_mde')} vs inventory={len(devices)}")

    print(f"  Total devices: {len(devices)} | Active: {active} | Inactive: {inactive}")


def audit_bindplane():
    """Audit BindPlane data."""
    print("\n═══ BINDPLANE AUDIT ═══")
    data = load("bindplane_agents.json")
    if not data:
        WARNINGS.append("⚠️ bindplane_agents.json not found")
        return

    agents = data.get("agents", [])
    connected = sum(1 for a in agents if a.get("status") in ("connected", 1, "1"))

    # Check for duplicates
    hostnames = [((a.get("hostname") or a.get("name") or "").lower().strip()) for a in agents]
    unique = len(set(h for h in hostnames if h))

    check(unique == len(agents),
          f"BindPlane duplicates: {len(agents)} agents, {unique} unique hostnames", "WARNING")

    print(f"  Agents: {len(agents)} | Connected: {connected} | Unique: {unique}")


def audit_freshness():
    """Check all data files are fresh."""
    print("\n═══ FRESHNESS AUDIT ═══")
    import time
    now = time.time()
    files = {
        "aikido_report.json": 60,
        "crowdstrike_hosts.json": 60,
        "aws_ec2_instances.json": 60,
        "defender_report.json": 120,
        "bindplane_agents.json": 60,
        "ai_insights.json": 60,
    }
    for filename, max_age_min in files.items():
        path = os.path.join(DATA_DIR, filename)
        if os.path.exists(path):
            age_min = (now - os.path.getmtime(path)) / 60
            check(age_min < max_age_min,
                  f"{filename}: {age_min:.0f}min old (max {max_age_min}min)", "WARNING")
        else:
            WARNINGS.append(f"⚠️ {filename} missing")


# ═══ RUN ALL AUDITS ═══
if __name__ == "__main__":
    print("=" * 60)
    print("SECUREVIEW DASHBOARD AUDIT")
    print(f"Data directory: {DATA_DIR}")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    audit_aikido()
    audit_ec2_coverage()
    audit_defender()
    audit_bindplane()
    audit_freshness()

    print("\n" + "=" * 60)
    print("AUDIT RESULTS")
    print("=" * 60)
    print(f"\n✅ PASSED: {len(PASSED)}")
    for p in PASSED:
        print(f"  {p}")

    if WARNINGS:
        print(f"\n⚠️ WARNINGS: {len(WARNINGS)}")
        for w in WARNINGS:
            print(f"  {w}")

    if ERRORS:
        print(f"\n❌ ERRORS: {len(ERRORS)}")
        for e in ERRORS:
            print(f"  {e}")
        print("\n🚫 AUDIT FAILED — Do NOT promote to production")
    else:
        print("\n✅ AUDIT PASSED — Clear to promote to production")
