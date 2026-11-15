"""
Aikido Security MCP Server
============================
Custom MCP server for querying Aikido application security data.
Provides tools for issue lookup, SLA tracking, and vulnerability analysis.

Run: uvx fastmcp run aikido_server.py
"""
import os
import json
import base64
import httpx
from datetime import datetime, timezone
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# Load credentials from project .env
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

mcp = FastMCP("Aikido Security")

# Config from environment
AIKIDO_CLIENT_ID = os.getenv("AIKIDO_CLIENT_ID", "")
AIKIDO_CLIENT_SECRET = os.getenv("AIKIDO_CLIENT_SECRET", "")
TOKEN_CACHE = {"token": None, "expires": 0}


async def _get_token():
    """Get or refresh Aikido OAuth2 token."""
    now = datetime.now(timezone.utc).timestamp()
    if TOKEN_CACHE["token"] and TOKEN_CACHE["expires"] > now:
        return TOKEN_CACHE["token"]

    credentials = base64.b64encode(f"{AIKIDO_CLIENT_ID}:{AIKIDO_CLIENT_SECRET}".encode()).decode()
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        r = await client.post(
            "https://app.aikido.dev/api/oauth/token",
            headers={"Authorization": f"Basic {credentials}"},
            data={"grant_type": "client_credentials"},
        )
        if r.status_code == 200:
            data = r.json()
            TOKEN_CACHE["token"] = data["access_token"]
            TOKEN_CACHE["expires"] = now + 3500  # ~1 hour
            return TOKEN_CACHE["token"]
    return None


async def _api_get(path, params=None):
    """Make authenticated GET request to Aikido API."""
    token = await _get_token()
    if not token:
        return {"error": "Failed to authenticate with Aikido"}
    async with httpx.AsyncClient(verify=False, timeout=60) as client:
        r = await client.get(
            f"https://app.aikido.dev/api/public/v1/{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
        )
        if r.status_code == 200:
            return r.json()
        return {"error": f"API returned {r.status_code}", "detail": r.text[:200]}


@mcp.tool()
async def get_issue_counts() -> str:
    """Get total issue counts by status (open, ignored, closed) from Aikido."""
    result = await _api_get("issues/counts")
    return json.dumps(result, indent=2)


@mcp.tool()
async def list_open_issues(severity: str = None, issue_type: str = None, limit: int = 50) -> str:
    """List open issues from Aikido. Filter by severity (critical/high/medium/low) and type (sast/open_source/eol/cloud/leaked_secret/surface_monitoring).

    Args:
        severity: Filter by severity level (critical, high, medium, low)
        issue_type: Filter by scan type (sast, open_source, eol, cloud, leaked_secret, surface_monitoring)
        limit: Maximum issues to return (default 50)
    """
    params = {"format": "json", "status": "open"}
    result = await _api_get("issues/export", params)

    if isinstance(result, dict) and result.get("error"):
        return json.dumps(result)

    issues = result if isinstance(result, list) else result.get("issues", [])

    # Apply filters
    if severity:
        issues = [i for i in issues if i.get("severity", "").lower() == severity.lower()]
    if issue_type:
        issues = [i for i in issues if i.get("type", "").lower() == issue_type.lower()]

    # Limit and format
    issues = issues[:limit]
    summary = {
        "total_matching": len(issues),
        "filters_applied": {"severity": severity, "type": issue_type},
        "issues": [{
            "id": i.get("id"),
            "group_id": i.get("group_id"),
            "severity": i.get("severity"),
            "type": i.get("type"),
            "rule": i.get("rule"),
            "affected_package": i.get("affected_package"),
            "cve_id": i.get("cve_id"),
            "code_repo_name": i.get("code_repo_name"),
            "first_detected_at": i.get("first_detected_at"),
            "exploitability": i.get("exploitability"),
        } for i in issues]
    }
    return json.dumps(summary, indent=2, default=str)


@mcp.tool()
async def get_sla_status() -> str:
    """Get SLA compliance status across all applications — breached, at risk, and within SLA counts."""
    params = {"format": "json", "status": "open"}
    result = await _api_get("issues/export", params)

    if isinstance(result, dict) and result.get("error"):
        return json.dumps(result)

    issues = result if isinstance(result, list) else result.get("issues", [])

    now = datetime.now(timezone.utc).timestamp()
    sla_config = {"critical": 14, "high": 30, "medium": 60, "low": 160}

    breached = 0
    at_risk = 0
    within_sla = 0

    for issue in issues:
        severity = (issue.get("severity") or "medium").lower()
        sla_days = sla_config.get(severity, 160)
        first = issue.get("first_detected_at", 0)
        if first:
            days_open = (now - first) / 86400
            remaining = sla_days - days_open
            if remaining < 0:
                breached += 1
            elif remaining <= 7:
                at_risk += 1
            else:
                within_sla += 1

    total = len(issues)
    compliance = round(within_sla / max(total, 1) * 100, 1)

    return json.dumps({
        "total_open_issues": total,
        "breached": breached,
        "at_risk": at_risk,
        "within_sla": within_sla,
        "compliance_pct": compliance,
    }, indent=2)


@mcp.tool()
async def get_app_details(app_name: str) -> str:
    """Get security details for a specific application/repository.

    Args:
        app_name: Name of the application or repository to look up
    """
    params = {"format": "json", "status": "open"}
    result = await _api_get("issues/export", params)

    if isinstance(result, dict) and result.get("error"):
        return json.dumps(result)

    issues = result if isinstance(result, list) else result.get("issues", [])

    # Filter by app name
    app_issues = [i for i in issues if app_name.lower() in (i.get("code_repo_name") or "").lower()]

    if not app_issues:
        return json.dumps({"error": f"No issues found for application '{app_name}'", "suggestion": "Try a partial name match"})

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    type_counts = {}
    for i in app_issues:
        sev = (i.get("severity") or "medium").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        t = i.get("type", "other")
        type_counts[t] = type_counts.get(t, 0) + 1

    return json.dumps({
        "application": app_name,
        "total_issues": len(app_issues),
        "severity": severity_counts,
        "types": type_counts,
        "sample_issues": [{
            "rule": i.get("rule"),
            "severity": i.get("severity"),
            "type": i.get("type"),
            "cve_id": i.get("cve_id"),
            "affected_package": i.get("affected_package"),
        } for i in app_issues[:10]]
    }, indent=2)


@mcp.tool()
async def search_cve(cve_id: str) -> str:
    """Search for a specific CVE across all applications in Aikido.

    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)
    """
    params = {"format": "json", "status": "open"}
    result = await _api_get("issues/export", params)

    if isinstance(result, dict) and result.get("error"):
        return json.dumps(result)

    issues = result if isinstance(result, list) else result.get("issues", [])
    matches = [i for i in issues if cve_id.upper() in (i.get("cve_id") or "").upper()]

    if not matches:
        return json.dumps({"cve": cve_id, "found": False, "message": "CVE not found in open issues"})

    return json.dumps({
        "cve": cve_id,
        "found": True,
        "affected_count": len(matches),
        "affected_apps": list(set(i.get("code_repo_name", "Unknown") for i in matches)),
        "severity": matches[0].get("severity"),
        "exploitability": matches[0].get("exploitability"),
        "details": [{
            "app": i.get("code_repo_name"),
            "package": i.get("affected_package"),
            "installed_version": i.get("installed_version"),
            "patched_versions": i.get("patched_versions"),
        } for i in matches[:10]]
    }, indent=2)


@mcp.tool()
async def get_sast_findings(limit: int = 20) -> str:
    """Get SAST (Static Analysis) findings — code vulnerabilities like injection, XSS, secrets.

    Args:
        limit: Maximum findings to return
    """
    return await list_open_issues(issue_type="sast", limit=limit)


@mcp.tool()
async def get_sca_findings(limit: int = 20) -> str:
    """Get SCA (Software Composition) findings — dependency vulnerabilities and EOL packages.

    Args:
        limit: Maximum findings to return
    """
    params = {"format": "json", "status": "open"}
    result = await _api_get("issues/export", params)

    if isinstance(result, dict) and result.get("error"):
        return json.dumps(result)

    issues = result if isinstance(result, list) else result.get("issues", [])
    sca_types = ("open_source", "eol", "license")
    filtered = [i for i in issues if i.get("type", "").lower() in sca_types][:limit]

    return json.dumps({
        "total_sca_issues": len([i for i in issues if i.get("type", "").lower() in sca_types]),
        "showing": len(filtered),
        "issues": [{
            "severity": i.get("severity"),
            "package": i.get("affected_package"),
            "cve_id": i.get("cve_id"),
            "app": i.get("code_repo_name"),
            "installed_version": i.get("installed_version"),
            "patched_versions": i.get("patched_versions"),
            "type": i.get("type"),
        } for i in filtered]
    }, indent=2, default=str)


if __name__ == "__main__":
    mcp.run()
