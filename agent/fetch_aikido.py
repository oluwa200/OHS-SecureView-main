"""
Aikido Application Security Fetcher
====================================
Pulls application vulnerability findings from Aikido's REST API.
Organizes by application (repo/service) and environment.

Auth: OAuth2 Client Credentials
Endpoint: https://app.aikido.dev/api/oauth/token
API Base: https://app.aikido.dev/api/public/v1

Output: data/aikido_report.json
"""
import os
import sys
import json
import asyncio
import logging
import base64
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [Aikido] %(message)s")
log = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

# SLA Definitions (days) — matches existing Qualys SLAs + zero-day rule
AIKIDO_SLA = {
    "production": {
        "critical": 14,
        "high": 30,
        "medium": 60,
        "low": 160,
    },
    "non-production": {
        "critical": 30,
        "high": 60,
        "medium": 90,
        "low": 160,
    },
}
ZERO_DAY_SLA = 3  # Days — applies regardless of environment


def write_json(filename, data):
    """Write data to a JSON file in DATA_DIR."""
    path = os.path.join(DATA_DIR, filename)
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    log.info(f"Written: {filename}")


async def get_aikido_token(client, client_id, client_secret):
    """Get OAuth2 access token from Aikido."""
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    r = await client.post(
        "https://app.aikido.dev/api/oauth/token",
        headers={"Authorization": f"Basic {credentials}"},
        data={"grant_type": "client_credentials"},
    )
    if r.status_code == 200:
        return r.json().get("access_token")
    else:
        log.error(f"Aikido auth failed: {r.status_code} - {r.text[:200]}")
        return None


async def fetch_aikido_issues(token, client):
    """Fetch all open issues from Aikido."""
    headers = {"Authorization": f"Bearer {token}"}
    all_issues = []

    # Export all issues (open)
    url = "https://app.aikido.dev/api/public/v1/issues/export"
    params = {"format": "json", "status": "open"}

    r = await client.get(url, headers=headers, params=params, timeout=60)
    if r.status_code == 200:
        data = r.json()
        if isinstance(data, list):
            all_issues = data
        elif isinstance(data, dict):
            all_issues = data.get("issues", data.get("value", []))
        log.info(f"  Fetched {len(all_issues)} open issues")
    else:
        log.error(f"  Issues export failed: {r.status_code} - {r.text[:200]}")

    return all_issues


async def fetch_aikido_repos(token, client):
    """Fetch all code repositories from Aikido."""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = await client.get(
            "https://app.aikido.dev/api/public/v1/repositories",
            headers=headers, timeout=30,
        )
        if r.status_code == 200:
            try:
                repos = r.json()
                if isinstance(repos, dict):
                    repos = repos.get("repositories", repos.get("value", repos.get("data", [])))
                if isinstance(repos, list):
                    log.info(f"  Fetched {len(repos)} repositories")
                    return repos
            except (ValueError, TypeError):
                pass
            log.warning(f"  Repos: unexpected response format")
            return []
        else:
            log.warning(f"  Repos fetch: {r.status_code}")
            return []
    except Exception as e:
        log.warning(f"  Repos fetch failed: {e}")
        return []


async def fetch_aikido_issue_counts(token, client):
    """Fetch issue count summary."""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = await client.get(
            "https://app.aikido.dev/api/public/v1/issues/counts",
            headers=headers, timeout=30,
        )
        if r.status_code == 200:
            try:
                return r.json()
            except (ValueError, TypeError):
                return {}
        else:
            log.warning(f"  Issue counts: {r.status_code}")
            return {}
    except Exception as e:
        log.warning(f"  Issue counts failed: {e}")
        return {}


def _classify_environment(repo_name, labels=None):
    """Classify a repo/app as production or non-production based on name/labels."""
    name_lower = (repo_name or "").lower()
    labels_lower = [l.lower() for l in (labels or [])]

    prod_indicators = ["prod", "production", "main", "release", "live"]
    for indicator in prod_indicators:
        if indicator in name_lower or indicator in labels_lower:
            return "production"
    return "non-production"


def _is_zero_day(issue):
    """Check if an issue is a zero-day (actively exploited, no patch available)."""
    exploitability = (issue.get("exploitability") or "").lower()
    has_fix = bool(issue.get("patched_versions"))
    # Aikido marks exploitability as "in_the_wild", "proof_of_concept", etc.
    actively_exploited = exploitability in ("in_the_wild", "active", "weaponized")
    return actively_exploited and not has_fix


def _calculate_sla(issue, environment):
    """Calculate SLA status for an issue."""
    severity = (issue.get("severity", "") or "medium").lower()
    if severity not in ("critical", "high", "medium", "low"):
        severity = "medium"

    # Zero-day overrides
    if _is_zero_day(issue):
        sla_days = ZERO_DAY_SLA
    else:
        env_key = "production" if environment == "production" else "non-production"
        sla_days = AIKIDO_SLA[env_key].get(severity, 160)

    # Calculate days open
    first_detected = issue.get("first_detected_at") or issue.get("created_at") or ""
    if first_detected:
        try:
            if isinstance(first_detected, str):
                detected_dt = datetime.fromisoformat(first_detected.replace("Z", "+00:00"))
            else:
                detected_dt = datetime.fromtimestamp(first_detected, tz=timezone.utc)
            days_open = (datetime.now(timezone.utc) - detected_dt).days
        except (ValueError, TypeError, OSError):
            days_open = 0
    else:
        days_open = 0

    days_remaining = sla_days - days_open

    if days_remaining < 0:
        status = "BREACHED"
    elif days_remaining <= 7:
        status = "AT RISK"
    else:
        status = "WITHIN SLA"

    return {
        "sla_days": sla_days,
        "days_open": days_open,
        "days_remaining": days_remaining,
        "days_overdue": abs(days_remaining) if days_remaining < 0 else 0,
        "status": status,
        "is_zero_day": _is_zero_day(issue),
    }


def _process_aikido_data(issues, repos):
    """Process raw Aikido data into structured report organized by application."""
    now = datetime.now(timezone.utc)

    # Build repo lookup
    repo_map = {}
    for repo in repos:
        repo_id = str(repo.get("id", ""))
        repo_map[repo_id] = {
            "name": repo.get("name", "Unknown"),
            "labels": repo.get("labels", []),
            "provider": repo.get("provider", ""),
            "is_active": repo.get("is_active", True),
        }

    # Organize issues by application
    apps = {}
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_breached = 0
    total_at_risk = 0
    total_within_sla = 0
    zero_day_count = 0

    for issue in issues:
        # Identify the application from Aikido's fields
        app_name = (issue.get("code_repo_name") or
                    issue.get("container_repo_name") or
                    issue.get("cloud_name") or
                    issue.get("domain_name") or
                    issue.get("virtual_machine_name") or
                    "Unassigned")
        
        # Use Aikido's attack surface as additional context
        attack_surface = issue.get("attack_surface", "")
        
        # Determine environment from repo name/labels
        environment = _classify_environment(app_name)

        # Calculate SLA
        sla_info = _calculate_sla(issue, environment)
        severity = (issue.get("severity", "") or "medium").lower()
        if severity not in severity_totals:
            severity = "medium"
        severity_totals[severity] += 1

        if sla_info["status"] == "BREACHED":
            total_breached += 1
        elif sla_info["status"] == "AT RISK":
            total_at_risk += 1
        else:
            total_within_sla += 1

        if sla_info["is_zero_day"]:
            zero_day_count += 1

        # Build app entry
        if app_name not in apps:
            apps[app_name] = {
                "name": app_name,
                "environment": environment,
                "attack_surface": attack_surface,
                "repo_id": issue.get("code_repo_id", ""),
                "issues": [],
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0,
                           "breached": 0, "at_risk": 0, "within_sla": 0, "zero_day": 0},
            }

        apps[app_name]["summary"][severity] += 1
        if sla_info["status"] == "BREACHED":
            apps[app_name]["summary"]["breached"] += 1
        elif sla_info["status"] == "AT RISK":
            apps[app_name]["summary"]["at_risk"] += 1
        else:
            apps[app_name]["summary"]["within_sla"] += 1
        if sla_info["is_zero_day"]:
            apps[app_name]["summary"]["zero_day"] += 1

        apps[app_name]["issues"].append({
            "id": issue.get("id", ""),
            "group_id": issue.get("group_id", ""),
            "code_repo_id": issue.get("code_repo_id", ""),
            "title": issue.get("rule", "") or issue.get("affected_package", "") or "N/A",
            "severity": severity,
            "severity_score": issue.get("severity_score", 0),
            "type": issue.get("type", ""),
            "attack_surface": attack_surface,
            "cve": issue.get("cve_id", ""),
            "package": issue.get("affected_package", ""),
            "affected_file": issue.get("affected_file", ""),
            "version": issue.get("installed_version", ""),
            "fix_version": issue.get("patched_versions", ""),
            "first_detected": issue.get("first_detected_at", ""),
            "sla_remediate_by": issue.get("sla_remediate_by", ""),
            "exploitability": issue.get("exploitability", ""),
            "environment": environment,
            "is_zero_day": sla_info["is_zero_day"],
            **sla_info,
        })

    # Sort apps by risk (breached first, then by critical count)
    sorted_apps = sorted(apps.values(), key=lambda a: (
        -a["summary"]["breached"],
        -a["summary"]["zero_day"],
        -a["summary"]["critical"],
        -a["summary"]["high"],
    ))

    report = {
        "generated_at": now.isoformat(),
        "summary": {
            "total_issues": len(issues),
            "total_applications": len(apps),
            "severity": severity_totals,
            "sla_status": {
                "breached": total_breached,
                "at_risk": total_at_risk,
                "within_sla": total_within_sla,
            },
            "zero_day_findings": zero_day_count,
            "compliance_pct": round(total_within_sla / max(len(issues), 1) * 100, 1),
        },
        "sla_config": {
            "production": AIKIDO_SLA["production"],
            "non_production": AIKIDO_SLA["non-production"],
            "zero_day": ZERO_DAY_SLA,
        },
        "applications": sorted_apps,
    }

    return report


async def fetch_aikido():
    """Main entry point — fetch all Aikido data and produce report."""
    import httpx

    client_id = os.getenv("AIKIDO_CLIENT_ID", "").strip()
    client_secret = os.getenv("AIKIDO_CLIENT_SECRET", "").strip()

    if not client_id or not client_secret:
        log.warning("Aikido credentials not set. Skipping.")
        return None

    ssl_verify = os.getenv("SSL_VERIFY", "true").lower() != "false"
    log.info("Fetching Aikido application security data...")

    try:
        async with httpx.AsyncClient(verify=ssl_verify, timeout=30) as client:
            # Authenticate
            token = await get_aikido_token(client, client_id, client_secret)
            if not token:
                return None

            # Fetch data
            issues = await fetch_aikido_issues(token, client)
            repos = await fetch_aikido_repos(token, client)
            counts = await fetch_aikido_issue_counts(token, client)

            if not issues and not counts:
                log.warning("No Aikido data returned.")
                return None

            # Process into report
            report = _process_aikido_data(issues, repos)

            # Add raw counts if available
            if counts:
                report["raw_counts"] = counts

            write_json("aikido_report.json", report)

            log.info(f"  Aikido: {report['summary']['total_issues']} issues across "
                     f"{report['summary']['total_applications']} apps | "
                     f"Breached: {report['summary']['sla_status']['breached']} | "
                     f"Zero-day: {report['summary']['zero_day_findings']}")

            return report

    except Exception as e:
        log.error(f"Aikido fetch failed: {e}")
        return None


async def main():
    """Standalone run."""
    from dotenv import load_dotenv
    load_dotenv()

    report = await fetch_aikido()
    if report:
        print(f"\n✅ Aikido Report written to data/aikido_report.json")
        print(f"   Applications: {report['summary']['total_applications']}")
        print(f"   Total Issues: {report['summary']['total_issues']}")
        print(f"   Critical: {report['summary']['severity']['critical']}")
        print(f"   SLA Breached: {report['summary']['sla_status']['breached']}")
        print(f"   Zero-day: {report['summary']['zero_day_findings']}")
        print(f"   Compliance: {report['summary']['compliance_pct']}%")
    else:
        print("❌ Failed to fetch Aikido report")


if __name__ == "__main__":
    asyncio.run(main())
