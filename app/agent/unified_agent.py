"""
Unified Security Posture Agent
===============================
Replaces 4 separate refreshers. One agent that:
1. Pulls data from Qualys, CrowdStrike, Defender, AWS, and BindPlane APIs
2. Writes JSON files for the dashboard
3. Cross-correlates and produces ai_insights.json
4. Takes daily snapshots for trending
5. Alerts on critical findings

Requires environment variables:
- QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_BASE_URL
- CS_CLIENT_ID, CS_CLIENT_SECRET, CS_BASE_URL
- DEFENDER_TENANT_ID, DEFENDER_CLIENT_ID, DEFENDER_CLIENT_SECRET
- BINDPLANE_URL, BINDPLANE_API_KEY
- AWS_PROFILE (for EC2 data)
- SSL_VERIFY (default: true)
- AGENT_INTERVAL_SECONDS (default: 900)
"""
import os
import sys
import json
import time
import asyncio
import logging
from datetime import datetime, timezone

# Add parent paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [Agent] %(message)s")
log = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
INTERVAL = int(os.getenv("AGENT_INTERVAL_SECONDS", "900"))


# ─── Data Writers ─────────────────────────────────────────────────────────────
def write_json(filename, data):
    """Write data to a JSON file in DATA_DIR."""
    path = os.path.join(DATA_DIR, filename)
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    log.info(f"  Written: {filename}")


# ─── Qualys Fetcher ───────────────────────────────────────────────────────────
async def fetch_qualys():
    """Pull vulnerability data from Qualys API."""
    import httpx

    base_url = os.getenv("QUALYS_BASE_URL", "")
    username = os.getenv("QUALYS_USERNAME", "").strip()
    password = os.getenv("QUALYS_PASSWORD", "").strip()

    if not username or not password:
        log.warning("Qualys credentials not set. Skipping.")
        return None

    ssl_verify = os.getenv("SSL_VERIFY", "true").lower() != "false"
    log.info("Fetching Qualys data...")

    try:
        async with httpx.AsyncClient(verify=ssl_verify, timeout=30) as client:
            # Login
            r = await client.post(
                f"{base_url}/api/2.0/fo/session/",
                data={"action": "login", "username": username, "password": password},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if r.status_code != 200 or "Logged in" not in r.text:
                log.error(f"Qualys login failed: {r.status_code}")
                return None
            cookies = r.cookies

            # Fetch host assets
            r = await client.post(
                f"{base_url}/api/2.0/fo/asset/host/",
                data={"action": "list", "truncation_limit": "0"},
                cookies=cookies, timeout=120,
            )
            log.info(f"  Qualys assets: HTTP {r.status_code}")
            # For now, return existing data structure (full refresh is complex)
            # The real implementation ports refresh_data.py logic
            return {"status": "ok", "source": "qualys"}
    except Exception as e:
        log.error(f"Qualys fetch failed: {e}")
        return None


# ─── CrowdStrike Fetcher ──────────────────────────────────────────────────────
async def fetch_crowdstrike():
    """Pull CSPM, hosts, and IaC data from CrowdStrike."""
    import httpx

    client_id = os.getenv("CS_CLIENT_ID", "").strip()
    client_secret = os.getenv("CS_CLIENT_SECRET", "").strip()
    base_url = os.getenv("CS_BASE_URL", "https://api.us-2.crowdstrike.com").strip()

    if not client_id or not client_secret:
        log.warning("CrowdStrike credentials not set. Skipping.")
        return None

    ssl_verify = os.getenv("SSL_VERIFY", "true").lower() != "false"
    log.info("Fetching CrowdStrike data...")

    try:
        async with httpx.AsyncClient(verify=ssl_verify, timeout=30) as client:
            # OAuth2 token
            r = await client.post(
                f"{base_url}/oauth2/token",
                data={"client_id": client_id, "client_secret": client_secret},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if r.status_code != 201:
                log.error(f"CrowdStrike auth failed: {r.status_code}")
                return None
            token = r.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}

            # Fetch hosts (all managed hosts, not just AWS-tagged)
            host_filter = ""
            r = await client.get(
                f"{base_url}/devices/queries/devices-scroll/v1",
                headers=headers, params={"limit": 5000} if not host_filter else {"filter": host_filter, "limit": 5000},
                timeout=60,
            )
            host_ids = r.json().get("resources", [])
            log.info(f"  CrowdStrike hosts found: {len(host_ids)}")

            # Get host details in batches
            all_hosts = []
            for i in range(0, len(host_ids), 100):
                batch = host_ids[i:i+100]
                r = await client.post(
                    f"{base_url}/devices/entities/devices/v2",
                    headers={**headers, "Content-Type": "application/json"},
                    json={"ids": batch}, timeout=60,
                )
                all_hosts.extend(r.json().get("resources", []))

            return {"hosts": all_hosts, "token": token, "base_url": base_url}
    except Exception as e:
        log.error(f"CrowdStrike fetch failed: {e}")
        return None


# ─── Defender Fetcher ─────────────────────────────────────────────────────────
async def fetch_defender():
    """Pull device, alert, and score data from Microsoft Defender."""
    import httpx

    tenant_id = os.getenv("DEFENDER_TENANT_ID", "").strip()
    client_id = os.getenv("DEFENDER_CLIENT_ID", "").strip()
    client_secret = os.getenv("DEFENDER_CLIENT_SECRET", "").strip()

    if not tenant_id or not client_id or not client_secret:
        log.warning("Defender credentials not set. Skipping.")
        return None

    ssl_verify = os.getenv("SSL_VERIFY", "true").lower() != "false"
    log.info("Fetching Defender data...")

    try:
        async with httpx.AsyncClient(verify=ssl_verify, timeout=30) as client:
            # Get tokens for both MDE and Graph
            tokens = {}
            for resource in ["https://api.securitycenter.microsoft.com",
                           "https://graph.microsoft.com"]:
                r = await client.post(
                    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "scope": f"{resource}/.default",
                    },
                )
                if r.status_code == 200:
                    tokens[resource] = r.json()["access_token"]
                else:
                    log.error(f"Defender auth failed for {resource}: {r.status_code}")

            mde_token = tokens.get("https://api.securitycenter.microsoft.com")
            graph_token = tokens.get("https://graph.microsoft.com")

            result = {}

            # Fetch machines from MDE
            if mde_token:
                r = await client.get(
                    "https://api.securitycenter.microsoft.com/api/machines",
                    headers={"Authorization": f"Bearer {mde_token}"},
                    timeout=60,
                )
                if r.status_code == 200:
                    result["machines"] = r.json().get("value", [])
                    log.info(f"  Defender machines: {len(result['machines'])}")

            # Fetch secure score from Graph
            if graph_token:
                r = await client.get(
                    "https://graph.microsoft.com/v1.0/security/secureScores?$top=1",
                    headers={"Authorization": f"Bearer {graph_token}"},
                    timeout=30,
                )
                if r.status_code == 200:
                    scores = r.json().get("value", [])
                    result["secure_score"] = scores[0] if scores else {}

            return result
    except Exception as e:
        log.error(f"Defender fetch failed: {e}")
        return None


# ─── AWS EC2 Fetcher ──────────────────────────────────────────────────────────
def fetch_aws_ec2():
    """Pull EC2 instances from all scoped accounts."""
    log.info("Fetching AWS EC2 data...")
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError

        profiles = [
            {"name": "Infrastructure", "profile": "infra", "account_id": "446329232350"},
            {"name": "Production", "profile": "prod", "account_id": "937786629491"},
            {"name": "Network", "profile": "network", "account_id": "895945783203"},
            {"name": "Test and QA", "profile": "test-qa", "account_id": "754120856488"},
        ]

        accounts_data = {}
        for p in profiles:
            try:
                session = boto3.Session(profile_name=p["profile"])
                ec2 = session.client("ec2", region_name="us-east-1")
                instances = []
                paginator = ec2.get_paginator("describe_instances")
                for page in paginator.paginate():
                    for res in page["Reservations"]:
                        for inst in res["Instances"]:
                            name = ""
                            for tag in inst.get("Tags", []):
                                if tag["Key"] == "Name":
                                    name = tag["Value"]
                            instances.append({
                                "instance_id": inst["InstanceId"],
                                "InstanceId": inst["InstanceId"],
                                "state": inst["State"]["Name"],
                                "State": inst["State"]["Name"],
                                "instance_type": inst["InstanceType"],
                                "InstanceType": inst["InstanceType"],
                                "name": name or "unnamed",
                                "Name": name or "unnamed",
                                "PrivateIp": inst.get("PrivateIpAddress", ""),
                                "private_ip": inst.get("PrivateIpAddress", ""),
                                "account_id": p["account_id"],
                                "account_name": p["name"],
                            })
                accounts_data[p["name"]] = instances
                log.info(f"  {p['name']}: {len(instances)} instances")
            except (ClientError, NoCredentialsError) as e:
                log.error(f"  {p['name']}: {e}")
                accounts_data[p["name"]] = []

        return accounts_data
    except ImportError:
        log.error("boto3 not installed. Skipping AWS EC2.")
        return None


# ─── BindPlane Fetcher ─────────────────────────────────────────────────────────
async def fetch_bindplane():
    """Pull agent inventory from BindPlane OpAMP API."""
    import httpx

    base_url = os.getenv("BINDPLANE_URL", "").strip().rstrip("/")
    api_key = os.getenv("BINDPLANE_API_KEY", "").strip()

    if not base_url or not api_key:
        log.warning("BindPlane credentials not set. Skipping.")
        return None

    ssl_verify = os.getenv("SSL_VERIFY", "true").lower() != "false"
    log.info("Fetching BindPlane data...")

    try:
        async with httpx.AsyncClient(verify=ssl_verify, timeout=60) as client:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            }

            # Fetch all agents
            r = await client.get(
                f"{base_url}/v1/agents",
                headers=headers,
                timeout=60,
            )

            if r.status_code == 200:
                data = r.json()
                agents = data.get("agents", data) if isinstance(data, dict) else data
                if isinstance(agents, list):
                    log.info(f"  BindPlane agents: {len(agents)}")

                    # Write to data directory
                    result = {
                        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "agents": agents,
                    }
                    write_json("bindplane_agents.json", result)
                    return result
                else:
                    log.warning(f"  BindPlane unexpected response type: {type(agents)}")
                    return None
            elif r.status_code == 401:
                log.error("BindPlane auth failed (401). Check BINDPLANE_API_KEY.")
                return None
            else:
                log.error(f"BindPlane fetch failed: HTTP {r.status_code}")
                return None
    except Exception as e:
        log.error(f"BindPlane fetch failed: {e}")
        return None


# ─── Cross-Correlation & Insights ─────────────────────────────────────────────
def analyze_and_write_insights(ec2_data, cs_hosts_data, bp_agents=None):
    """Cross-correlate all data and produce ai_insights.json."""
    log.info("Running cross-correlation analysis...")

    # EC2 IPs
    ec2_ips = set()
    if ec2_data:
        for acct_instances in ec2_data.values():
            for inst in acct_instances:
                ip = inst.get("PrivateIp", "")
                if ip:
                    ec2_ips.add(ip)

    # CrowdStrike IPs
    cs_ips = set()
    if cs_hosts_data:
        for host in cs_hosts_data:
            ip = host.get("local_ip", "")
            if ip:
                cs_ips.add(ip)

    # BindPlane IPs
    bp_ips = set()
    if bp_agents:
        for agent in bp_agents:
            ip = (agent.get("remoteAddress") or agent.get("ip") or "").split(":")[0]
            if ip:
                bp_ips.add(ip)

    # Qualys IPs (from existing report file)
    qualys_ips = set()
    vuln_path = os.path.join(DATA_DIR, "vulnerability_report.json")
    if os.path.exists(vuln_path):
        try:
            with open(vuln_path, "r", encoding="utf-8") as f:
                vuln_data = json.load(f)
            for acct_data in vuln_data.values():
                if isinstance(acct_data, dict):
                    for asset in acct_data.get("internet_facing_assets", []):
                        if asset.get("ip"):
                            qualys_ips.add(asset["ip"])
                    for asset in acct_data.get("internal_assets", []):
                        if asset.get("ip"):
                            qualys_ips.add(asset["ip"])
        except Exception:
            pass

    # Calculate gaps
    no_edr = ec2_ips - cs_ips
    no_scan = ec2_ips - qualys_ips
    no_telemetry = ec2_ips - bp_ips
    blind = ec2_ips - cs_ips - qualys_ips
    full_coverage = ec2_ips & cs_ips & qualys_ips

    total = len(ec2_ips) or 1
    risk_score = min(100, round(
        (len(blind) / total * 50) + (len(no_edr) / total * 30) + (len(no_scan) / total * 20), 1
    ))

    insights = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_risk_score": risk_score,
        "summary": (
            f"Risk: {'LOW' if risk_score < 25 else 'MEDIUM' if risk_score < 50 else 'HIGH' if risk_score < 75 else 'CRITICAL'} "
            f"({risk_score}/100). {len(ec2_ips)} EC2 instances: "
            f"EDR coverage {round(len(cs_ips & ec2_ips)/total*100,1)}%, "
            f"vuln scan {round(len(qualys_ips & ec2_ips)/total*100,1)}%, "
            f"telemetry {round(len(bp_ips & ec2_ips)/total*100,1)}%, "
            f"{len(blind)} completely blind."
        ),
        "stats": {
            "total_ec2_ips": len(ec2_ips),
            "crowdstrike_coverage": len(cs_ips & ec2_ips),
            "qualys_coverage": len(qualys_ips & ec2_ips),
            "bindplane_coverage": len(bp_ips & ec2_ips),
            "full_coverage": len(full_coverage),
            "no_edr": len(no_edr),
            "no_vuln_scan": len(no_scan),
            "no_telemetry": len(no_telemetry),
            "completely_blind": len(blind),
            "edr_coverage_pct": round(len(cs_ips & ec2_ips) / total * 100, 1),
            "vuln_scan_coverage_pct": round(len(qualys_ips & ec2_ips) / total * 100, 1),
            "telemetry_coverage_pct": round(len(bp_ips & ec2_ips) / total * 100, 1),
            "full_coverage_pct": round(len(full_coverage) / total * 100, 1),
        },
        "coverage_gaps": [
            {"ip": ip, "gap_type": "completely_blind", "risk": "CRITICAL"}
            for ip in sorted(blind)[:15]
        ] + [
            {"ip": ip, "gap_type": "no_edr", "risk": "HIGH"}
            for ip in sorted(no_edr - blind)[:15]
        ],
        "priority_actions": [
            {"priority": 1, "action": f"Deploy CrowdStrike + Qualys to {len(blind)} blind hosts", "impact": "CRITICAL"},
            {"priority": 2, "action": f"Install Falcon on {len(no_edr)} hosts missing EDR", "impact": "HIGH"},
            {"priority": 3, "action": f"Add {len(no_scan)} hosts to Qualys scanning", "impact": "MEDIUM"},
            {"priority": 4, "action": f"Deploy BindPlane agent to {len(no_telemetry)} hosts missing telemetry", "impact": "MEDIUM"},
        ],
    }

    write_json("ai_insights.json", insights)
    log.info(f"  Risk Score: {risk_score}/100 | Blind: {len(blind)} | No EDR: {len(no_edr)}")
    return insights


# ─── Snapshot ─────────────────────────────────────────────────────────────────
def take_snapshot(insights):
    """Append daily metrics to history.json for trending."""
    history_path = os.path.join(DATA_DIR, "history.json")
    history = []
    if os.path.exists(history_path):
        try:
            with open(history_path, "r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception:
            history = []

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    snapshot = {
        "date": today,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_score": insights.get("overall_risk_score", 0),
        **insights.get("stats", {}),
    }

    # Update or append
    if history and history[-1].get("date") == today:
        history[-1] = snapshot
    else:
        history.append(snapshot)
    history = history[-90:]  # Keep 90 days

    with open(history_path, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)
    log.info(f"  Snapshot saved for {today}")


# ─── Main Agent Loop ──────────────────────────────────────────────────────────
async def run_cycle():
    """Execute one full agent cycle."""
    log.info("=" * 60)
    log.info("Starting agent cycle...")
    start = time.time()

    # 1. Fetch from all sources
    cs_result = await fetch_crowdstrike()
    defender_result = await fetch_defender()
    ec2_data = fetch_aws_ec2()
    bp_result = await fetch_bindplane()

    # 2. Process CrowdStrike hosts into dashboard format
    if cs_result and cs_result.get("hosts"):
        hosts_by_account = {"Infrastructure": [], "Production": [], "Network": [], "Test and QA": []}
        account_map = {
            "446329232350": "Infrastructure",
            "937786629491": "Production",
            "895945783203": "Network",
            "754120856488": "Test and QA",
        }
        for host in cs_result["hosts"]:
            acct_id = host.get("service_provider_account_id", "")
            acct_name = account_map.get(acct_id, "Infrastructure")
            hosts_by_account[acct_name].append({
                "device_id": host.get("device_id", ""),
                "hostname": host.get("hostname", ""),
                "local_ip": host.get("local_ip", ""),
                "platform": host.get("platform_name", ""),
                "status": host.get("status", ""),
                "last_seen": host.get("last_seen", ""),
                "agent_version": host.get("agent_version", ""),
                "instance_id": host.get("instance_id", ""),
                "service_provider_account_id": acct_id,
            })

        write_json("crowdstrike_hosts.json", {
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "accounts": hosts_by_account,
        })

    # 3. Write EC2 data
    if ec2_data:
        total = sum(len(v) for v in ec2_data.values())
        running = sum(1 for acct in ec2_data.values() for i in acct if i.get("state") == "running")
        write_json("aws_ec2_instances.json", {
            "accounts": ec2_data,
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        })
        write_json("aws_ec2_counts.json", {
            "total_instances": total,
            "total_running": running,
            "total_stopped": total - running,
            "by_account": {
                name: {"total": len(insts), "running": sum(1 for i in insts if i.get("state") == "running"), "stopped": sum(1 for i in insts if i.get("state") != "running")}
                for name, insts in ec2_data.items()
            },
            "last_updated": datetime.now(timezone.utc).isoformat(),
        })

    # 4. Cross-correlate and produce insights
    cs_hosts_flat = cs_result.get("hosts", []) if cs_result else []
    bp_agents = bp_result.get("agents", []) if bp_result else []
    insights = analyze_and_write_insights(ec2_data, cs_hosts_flat, bp_agents)

    # 5. Snapshot for trending
    take_snapshot(insights)

    # 6. Threshold alerts (immediate if risk exceeds limit)
    risk_threshold = int(os.getenv("RISK_ALERT_THRESHOLD", "50"))
    if insights.get("overall_risk_score", 0) >= risk_threshold:
        from agent.alerting import send_threshold_alert
        send_threshold_alert(insights, risk_threshold)

    # 7. Send daily digest (once per day)
    from agent.alerting import send_daily_digest
    send_daily_digest(insights)

    elapsed = time.time() - start
    log.info(f"Agent cycle complete in {elapsed:.1f}s")
    log.info("=" * 60)


def main():
    """Main entry point — runs the agent loop."""
    log.info(f"Unified Security Agent starting (interval: {INTERVAL}s)")
    log.info(f"Data directory: {DATA_DIR}")

    while True:
        try:
            asyncio.run(run_cycle())
        except Exception as e:
            log.error(f"Agent cycle failed: {e}")
        log.info(f"Next cycle in {INTERVAL}s...")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
