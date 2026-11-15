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

# Load secrets from AWS Secrets Manager (falls back to .env)
from secrets_loader import load_secrets
load_secrets()

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
QUALYS_ACCOUNTS = {
    "Infrastructure (446329232350)": "Infrastructure - 2350",
    "Production (937786629491)": "Production - 9491",
    "Network (895945783203)": "Network - 3203",
    "Test and QA (754120856488)": "Test and QA - 6488",
}
INTERNET_FACING_TAG = "Internet-Facing"


async def fetch_qualys():
    """Pull full vulnerability data from Qualys API — assets, detections, fixed, KB solutions."""
    import httpx
    import base64
    import xmltodict

    base_url = os.getenv("QUALYS_BASE_URL", "").strip()
    username = os.getenv("QUALYS_USERNAME", "").strip().strip('"')
    password = os.getenv("QUALYS_PASSWORD", "").strip().strip('"')

    if not username or not password or not base_url:
        log.warning("Qualys credentials not set. Skipping.")
        return None

    ssl_verify = os.getenv("SSL_VERIFY", "true").lower() != "false"
    auth_header = f"Basic {base64.b64encode(f'{username}:{password}'.encode()).decode()}"
    json_headers = {
        "X-Requested-With": "qualys-mcp-server",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": auth_header,
    }
    xml_headers = {
        "X-Requested-With": "qualys-mcp-server",
        "Authorization": auth_header,
    }

    log.info("Fetching Qualys vulnerability data...")
    report = {}

    try:
        # Step 1: Get assets by tag for each account
        async with httpx.AsyncClient(verify=ssl_verify, timeout=120) as client:
            for account_name, tag_name in QUALYS_ACCOUNTS.items():
                try:
                    url = f"{base_url}/qps/rest/2.0/search/am/hostasset"
                    body = {
                        "ServiceRequest": {
                            "preferences": {"limitResults": 500},
                            "filters": {
                                "Criteria": [
                                    {"field": "tagName", "operator": "EQUALS", "value": tag_name}
                                ]
                            },
                        }
                    }
                    r = await client.post(url, headers=json_headers, json=body)
                    data = r.json()
                    assets_raw = data.get("ServiceResponse", {}).get("data", [])

                    assets = []
                    for item in assets_raw:
                        asset = item.get("HostAsset", {})
                        tags_list = asset.get("tags", {}).get("list", [])
                        tag_names_list = []
                        for t in tags_list:
                            if isinstance(t, dict):
                                ts = t.get("TagSimple", {})
                                if isinstance(ts, dict):
                                    tag_names_list.append(ts.get("name", ""))

                        assets.append({
                            "id": asset.get("id"),
                            "name": asset.get("name", "N/A"),
                            "ip": asset.get("address", "N/A"),
                            "tags": tag_names_list,
                            "internet_facing": INTERNET_FACING_TAG in tag_names_list or "Internet Facing Assets" in tag_names_list,
                        })

                    internet_facing = [a for a in assets if a["internet_facing"]]
                    internal = [a for a in assets if not a["internet_facing"]]
                    report[account_name] = {
                        "total_assets": len(assets),
                        "internet_facing_count": len(internet_facing),
                        "internal_count": len(internal),
                        "internet_facing_assets": internet_facing,
                        "internal_assets": internal,
                    }
                    log.info(f"  {account_name}: {len(assets)} assets ({len(internet_facing)} IF)")
                except Exception as e:
                    log.error(f"  {account_name} assets error: {e}")
                    report[account_name] = {"total_assets": 0, "internet_facing_count": 0,
                                            "internal_count": 0, "internet_facing_assets": [],
                                            "internal_assets": []}

        # Step 2: Get detections for each account
        for account_name, acct_data in report.items():
            all_ips = [a["ip"] for a in acct_data["internet_facing_assets"] + acct_data["internal_assets"] if a["ip"] != "N/A"]
            if not all_ips:
                acct_data["internet_facing_vulns"] = []
                acct_data["internal_vulns"] = []
                continue

            log.info(f"  Fetching detections for {account_name} ({len(all_ips)} IPs)...")
            detections = []
            url = f"{base_url}/api/2.0/fo/asset/host/vm/detection/"

            for i in range(0, len(all_ips), 20):
                batch = all_ips[i:i + 20]
                params = {
                    "action": "list",
                    "ips": ",".join(batch),
                    "severities": "3,4,5",
                    "status": "New,Active,Re-Opened",
                    "truncation_limit": "5000",
                    "output_format": "XML",
                }
                try:
                    async with httpx.AsyncClient(verify=ssl_verify, timeout=120) as client:
                        r = await client.post(url, headers=xml_headers, data=params)
                        if r.status_code == 200 and "HOST_LIST" in r.text:
                            data = xmltodict.parse(r.text)
                            host_list = data.get("HOST_LIST_VM_DETECTION_OUTPUT", {}).get("RESPONSE", {}).get("HOST_LIST", {}).get("HOST", [])
                            if isinstance(host_list, dict):
                                host_list = [host_list]
                            for host in host_list:
                                det_list = host.get("DETECTION_LIST", {}).get("DETECTION", [])
                                if isinstance(det_list, dict):
                                    det_list = [det_list]
                                for det in det_list:
                                    detections.append({
                                        "ip": host.get("IP"),
                                        "hostname": host.get("DNS", "N/A"),
                                        "qid": det.get("QID"),
                                        "severity": det.get("SEVERITY"),
                                        "status": det.get("STATUS"),
                                        "first_found": det.get("FIRST_FOUND_DATETIME", "N/A"),
                                        "last_found": det.get("LAST_FOUND_DATETIME", "N/A"),
                                        "results": det.get("RESULTS", "N/A"),
                                    })
                except Exception as e:
                    log.error(f"    Detection batch {i//20+1} error: {e}")

            internet_ips = {a["ip"] for a in acct_data["internet_facing_assets"]}
            acct_data["internet_facing_vulns"] = [d for d in detections if d["ip"] in internet_ips]
            acct_data["internal_vulns"] = [d for d in detections if d["ip"] not in internet_ips]
            log.info(f"    {len(detections)} detections found")

            # Step 3: Get fixed (patched) vulnerabilities
            fixed_detections = []
            for i in range(0, len(all_ips), 20):
                batch = all_ips[i:i + 20]
                params = {
                    "action": "list",
                    "ips": ",".join(batch),
                    "severities": "3,4,5",
                    "status": "Fixed",
                    "truncation_limit": "5000",
                    "output_format": "XML",
                }
                try:
                    async with httpx.AsyncClient(verify=ssl_verify, timeout=120) as client:
                        r = await client.post(url, headers=xml_headers, data=params)
                        if r.status_code == 200 and "HOST_LIST" in r.text:
                            data = xmltodict.parse(r.text)
                            host_list = data.get("HOST_LIST_VM_DETECTION_OUTPUT", {}).get("RESPONSE", {}).get("HOST_LIST", {}).get("HOST", [])
                            if isinstance(host_list, dict):
                                host_list = [host_list]
                            for host in host_list:
                                det_list = host.get("DETECTION_LIST", {}).get("DETECTION", [])
                                if isinstance(det_list, dict):
                                    det_list = [det_list]
                                for det in det_list:
                                    fixed_detections.append({
                                        "ip": host.get("IP"),
                                        "hostname": host.get("DNS", "N/A"),
                                        "qid": det.get("QID"),
                                        "severity": det.get("SEVERITY"),
                                        "status": "Fixed",
                                        "first_found": det.get("FIRST_FOUND_DATETIME", "N/A"),
                                        "last_found": det.get("LAST_FOUND_DATETIME", "N/A"),
                                        "last_fixed": det.get("LAST_FIXED_DATETIME", det.get("LAST_FOUND_DATETIME", "N/A")),
                                    })
                except Exception as e:
                    log.error(f"    Fixed batch {i//20+1} error: {e}")

            acct_data["fixed_vulns"] = fixed_detections
            log.info(f"    {len(fixed_detections)} fixed vulns found")

        # Only write if we got actual data
        total_vulns = sum(
            len(d.get("internet_facing_vulns", [])) + len(d.get("internal_vulns", []))
            for d in report.values()
        )
        if total_vulns > 0:
            write_json("vulnerability_report.json", report)
            log.info(f"  Qualys complete: {total_vulns} total vulnerabilities written")
        else:
            log.warning("  Qualys returned 0 vulnerabilities — keeping previous data")

        return report

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

            # Fetch CSPM IOMs (by-rule endpoint — same as MCP server uses)
            iom_resources = []
            try:
                r = await client.get(
                    f"{base_url}/cloud-security-evaluations/combined/ioms-by-rule/v1",
                    headers=headers, params={"limit": 500}, timeout=60,
                )
                if r.status_code == 200:
                    iom_resources = r.json().get("resources", [])
                    log.info(f"  CrowdStrike IOMs fetched: {len(iom_resources)}")
                else:
                    log.warning(f"  CrowdStrike IOMs: HTTP {r.status_code}")
            except Exception as e:
                log.warning(f"  CrowdStrike IOMs fetch failed: {e}")

            return {"hosts": all_hosts, "token": token, "base_url": base_url, "ioms": iom_resources}
    except Exception as e:
        log.error(f"CrowdStrike fetch failed: {e}")
        return None


# ─── Defender Fetcher ─────────────────────────────────────────────────────────
async def fetch_defender():
    """Pull device, alert, vulnerability, and score data from Microsoft Defender.

    Returns a dict with all raw API data for process_defender_to_report() to transform.
    """
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
                mde_headers = {"Authorization": f"Bearer {mde_token}"}

                r = await client.get(
                    "https://api.securitycenter.microsoft.com/api/machines",
                    headers=mde_headers, timeout=60,
                )
                if r.status_code == 200:
                    result["machines"] = r.json().get("value", [])
                    log.info(f"  Defender machines: {len(result['machines'])}")

                # Fetch active alerts
                try:
                    r = await client.get(
                        "https://api.securitycenter.microsoft.com/api/alerts?$filter=status ne 'Resolved'&$top=100",
                        headers=mde_headers, timeout=30,
                    )
                    if r.status_code == 200:
                        result["alerts"] = r.json().get("value", [])
                        log.info(f"  Defender alerts: {len(result['alerts'])}")
                except Exception as e:
                    log.warning(f"  Defender alerts fetch failed: {e}")
                    result["alerts"] = []

                # Fetch vulnerabilities (top critical/high)
                try:
                    r = await client.get(
                        "https://api.securitycenter.microsoft.com/api/vulnerabilities?$top=50&$orderby=cvssV3 desc",
                        headers=mde_headers, timeout=30,
                    )
                    if r.status_code == 200:
                        result["vulnerabilities"] = r.json().get("value", [])
                        log.info(f"  Defender vulns: {len(result['vulnerabilities'])}")
                except Exception as e:
                    log.warning(f"  Defender vulns fetch failed: {e}")
                    result["vulnerabilities"] = []

            # Fetch secure score from Graph
            if graph_token:
                graph_headers = {"Authorization": f"Bearer {graph_token}"}

                r = await client.get(
                    "https://graph.microsoft.com/v1.0/security/secureScores?$top=1",
                    headers=graph_headers, timeout=30,
                )
                if r.status_code == 200:
                    scores = r.json().get("value", [])
                    result["secure_score"] = scores[0] if scores else {}

                # Fetch Intune managed devices (encryption + compliance)
                try:
                    r = await client.get(
                        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
                        "?$select=deviceName,operatingSystem,complianceState,isEncrypted,lastSyncDateTime,userPrincipalName"
                        "&$top=999",
                        headers=graph_headers, timeout=60,
                    )
                    if r.status_code == 200:
                        intune_devices = r.json().get("value", [])
                        result["intune_devices"] = intune_devices
                        log.info(f"  Intune managed devices: {len(intune_devices)}")
                    else:
                        log.warning(f"  Intune devices: HTTP {r.status_code}")
                        result["intune_devices"] = []
                except Exception as e:
                    log.warning(f"  Intune devices fetch failed: {e}")
                    result["intune_devices"] = []

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
        from botocore.exceptions import ClientError, NoCredentialsError, TokenRetrievalError, BotoCoreError

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
            except (TokenRetrievalError, BotoCoreError) as e:
                log.warning(f"  {p['name']}: SSO token issue — {e}")
                accounts_data[p["name"]] = []

        # If all accounts returned empty due to token issues, return None
        # so the dashboard shows stale data warning instead of overwriting with empties
        if all(len(v) == 0 for v in accounts_data.values()):
            log.warning("  EC2: All accounts failed (likely SSO token expired). Skipping write.")
            return None

        return accounts_data
    except ImportError:
        log.error("boto3 not installed. Skipping AWS EC2.")
        return None
    except Exception as e:
        log.error(f"  EC2 fetch failed (non-fatal): {e}")
        return None


def fetch_aws_eks_nodes():
    """Pull EKS node instances from all scoped accounts.

    Identifies EC2 instances that are EKS worker nodes by filtering on
    the 'kubernetes.io/cluster/' tag that EKS automatically applies.
    Writes aws_eks_nodes.json with fresh data every cycle.
    """
    log.info("Fetching AWS EKS node data...")
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError, TokenRetrievalError, BotoCoreError

        profiles = [
            {"name": "Infrastructure", "profile": "infra", "account_id": "446329232350"},
            {"name": "Production", "profile": "prod", "account_id": "937786629491"},
            {"name": "Network", "profile": "network", "account_id": "895945783203"},
            {"name": "Test and QA", "profile": "test-qa", "account_id": "754120856488"},
        ]

        accounts_data = {}
        total_nodes = 0

        for p in profiles:
            try:
                session = boto3.Session(profile_name=p["profile"])
                ec2 = session.client("ec2", region_name="us-east-1")

                # Filter for EKS nodes: instances with kubernetes.io/cluster/* tag
                paginator = ec2.get_paginator("describe_instances")
                nodes = []
                for page in paginator.paginate(
                    Filters=[
                        {"Name": "tag-key", "Values": ["kubernetes.io/cluster/*"]},
                        {"Name": "instance-state-name", "Values": ["running"]},
                    ]
                ):
                    for res in page["Reservations"]:
                        for inst in res["Instances"]:
                            nodes.append({
                                "InstanceId": inst["InstanceId"],
                                "State": inst["State"]["Name"],
                                "PrivateIp": inst.get("PrivateIpAddress", ""),
                                "PublicIp": inst.get("PublicIpAddress"),
                                "InstanceType": inst["InstanceType"],
                            })

                # If tag-key filter didn't work, try eks:nodegroup-name tag
                if not nodes:
                    for page in paginator.paginate(
                        Filters=[
                            {"Name": "tag-key", "Values": ["eks:nodegroup-name"]},
                            {"Name": "instance-state-name", "Values": ["running"]},
                        ]
                    ):
                        for res in page["Reservations"]:
                            for inst in res["Instances"]:
                                nodes.append({
                                    "InstanceId": inst["InstanceId"],
                                    "State": inst["State"]["Name"],
                                    "PrivateIp": inst.get("PrivateIpAddress", ""),
                                    "PublicIp": inst.get("PublicIpAddress"),
                                    "InstanceType": inst["InstanceType"],
                                })

                account_key = f"{p['name']} ({p['account_id']})"
                accounts_data[account_key] = nodes
                total_nodes += len(nodes)
                if nodes:
                    log.info(f"  EKS {p['name']}: {len(nodes)} nodes")

            except (ClientError, NoCredentialsError) as e:
                log.error(f"  EKS {p['name']}: {e}")
                account_key = f"{p['name']} ({p['account_id']})"
                accounts_data[account_key] = []
            except (TokenRetrievalError, BotoCoreError) as e:
                log.warning(f"  EKS {p['name']}: SSO token issue — {e}")
                account_key = f"{p['name']} ({p['account_id']})"
                accounts_data[account_key] = []

        # Only write if we got data (don't overwrite with empties on token failure)
        if total_nodes > 0:
            write_json("aws_eks_nodes.json", {
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "accounts": accounts_data,
                "total_eks_nodes": total_nodes,
            })
            log.info(f"  EKS total: {total_nodes} nodes across all accounts")
        elif all(len(v) == 0 for v in accounts_data.values()):
            log.warning("  EKS: No nodes found or all accounts failed. Keeping existing file.")
        
        return accounts_data

    except ImportError:
        log.error("boto3 not installed. Skipping EKS nodes.")
        return None
    except Exception as e:
        log.error(f"  EKS fetch failed (non-fatal): {e}")
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
                "x-bindplane-api-key": api_key,
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
                agents_raw = data.get("agents", data) if isinstance(data, dict) else data
                if isinstance(agents_raw, list):
                    log.info(f"  BindPlane raw agents: {len(agents_raw)}")

                    # Deduplicate by hostname — keep most recently seen entry
                    seen = {}
                    for a in agents_raw:
                        hn = (a.get("hostname") or a.get("name") or "").lower().strip()
                        if not hn:
                            continue
                        # Keep the connected one, or the most recently seen
                        existing = seen.get(hn)
                        if existing is None:
                            seen[hn] = a
                        else:
                            # Prefer connected over disconnected
                            a_connected = a.get("status") in ("connected", 1, "1")
                            ex_connected = existing.get("status") in ("connected", 1, "1")
                            if a_connected and not ex_connected:
                                seen[hn] = a
                            elif a_connected == ex_connected:
                                # Both same status — keep the newer timestamp
                                a_ts = a.get("connectedAt") or a.get("disconnectedAt") or ""
                                ex_ts = existing.get("connectedAt") or existing.get("disconnectedAt") or ""
                                if a_ts > ex_ts:
                                    seen[hn] = a

                    agents = list(seen.values())
                    deduped = len(agents_raw) - len(agents)
                    if deduped > 0:
                        log.info(f"  BindPlane deduplicated: {len(agents_raw)} → {len(agents)} ({deduped} duplicates removed)")

                    # Write cleaned data
                    result = {
                        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "agents": agents,
                        "raw_count": len(agents_raw),
                        "deduped_count": deduped,
                    }
                    write_json("bindplane_agents.json", result)
                    return result
                else:
                    log.warning(f"  BindPlane unexpected response type: {type(agents_raw)}")
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


# ─── Defender Data Processor ──────────────────────────────────────────────────
def process_defender_to_report(defender_result):
    """Process raw Defender API response into defender_report.json.

    Transforms raw MDE machines + Graph secure score + alerts + vulns into the
    structured format the dashboard expects. Computes all summary metrics
    automatically — no manual intervention needed.
    """
    if not defender_result:
        return None

    machines = defender_result.get("machines", [])
    raw_score = defender_result.get("secure_score", {})
    raw_alerts = defender_result.get("alerts", [])
    raw_vulns = defender_result.get("vulnerabilities", [])

    if not machines:
        log.warning("  Defender: no machines returned from API")
        return None

    log.info(f"  Processing {len(machines)} Defender machines into report...")

    # ─── Build device inventory (dashboard format) ────────────────────────────
    device_inventory = []
    os_distribution = {}
    exposure_levels = {"High": 0, "Medium": 0, "Low": 0, "None": 0}
    health_counts = {"Active": 0, "Inactive": 0, "ImpairedCommunication": 0}

    for m in machines:
        health = m.get("healthStatus", "Unknown")
        os_platform = m.get("osPlatform", "Unknown")
        exposure = m.get("exposureLevel", "None")
        risk = m.get("riskScore", "None")

        device_inventory.append({
            "name": m.get("computerDnsName") or m.get("machineName", ""),
            "os": os_platform,
            "health": health,
            "risk_score": risk,
            "exposure": exposure,
            "last_seen": m.get("lastSeen", ""),
            "onboarding": m.get("onboardingStatus", ""),
            "ip": m.get("lastIpAddress", ""),
            "aad_joined": m.get("isAadJoined", False),
        })

        # Count OS distribution
        os_distribution[os_platform] = os_distribution.get(os_platform, 0) + 1

        # Count exposure levels
        if exposure in exposure_levels:
            exposure_levels[exposure] += 1

        # Count health
        if health == "Active":
            health_counts["Active"] += 1
        elif health == "ImpairedCommunication":
            health_counts["ImpairedCommunication"] += 1
        else:
            health_counts["Inactive"] += 1

    active_count = health_counts["Active"]
    inactive_count = health_counts["Inactive"]
    impaired_count = health_counts["ImpairedCommunication"]

    # ─── Process Alerts ───────────────────────────────────────────────────────
    alert_details = []
    alert_summary = {"total": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for a in raw_alerts:
        severity = (a.get("severity") or "Medium").capitalize()
        alert_details.append({
            "severity": severity,
            "title": a.get("title", "N/A"),
            "device": a.get("computerDnsName") or a.get("machineId", "N/A"),
            "category": a.get("category", "N/A"),
            "source": a.get("detectionSource", "Unknown"),
            "created": a.get("alertCreationTime", ""),
            "threat_family": a.get("threatFamilyName"),
        })
        alert_summary["total"] += 1
        sev_key = severity.lower()
        if sev_key in alert_summary:
            alert_summary[sev_key] += 1

    # ─── Process Vulnerabilities ──────────────────────────────────────────────
    vuln_details = []
    critical_count = 0
    high_count = 0
    for v in raw_vulns:
        severity = v.get("severity", "Medium")
        if severity == "Critical":
            critical_count += 1
        elif severity == "High":
            high_count += 1
        vuln_details.append({
            "cve_id": v.get("id", "N/A"),
            "description": v.get("description", ""),
            "cvss": v.get("cvssV3", 0),
            "severity": severity,
            "exposed_machines": v.get("exposedMachines", 0),
            "exploit_available": v.get("exploitVerified", False) or v.get("publicExploit", False),
            "published": v.get("publishedOn", ""),
        })

    # ─── Process Secure Score ─────────────────────────────────────────────────
    secure_score = {}
    if raw_score:
        current = raw_score.get("currentScore", 0)
        max_score = raw_score.get("maxScore", 1)
        percentage = round((current / max_score) * 100, 1) if max_score else 0

        control_scores = []
        for ctrl in raw_score.get("controlScores", []):
            control_scores.append({
                "controlName": ctrl.get("controlName", ""),
                "controlCategory": ctrl.get("controlCategory", ""),
                "score": ctrl.get("score", 0),
                "scoreInPercentage": ctrl.get("scoreInPercentage", 0),
                "description": ctrl.get("description", ""),
                "count": ctrl.get("count", ""),
                "total": ctrl.get("total", ""),
                "implementationStatus": ctrl.get("implementationStatus", ""),
            })

        secure_score = {
            "current": current,
            "max": max_score,
            "percentage": percentage,
            "currentScore": current,
            "maxScore": max_score,
            "mde_configuration_score": raw_score.get("averageComparativeScores", [{}])[0].get("averageScore", 0) if raw_score.get("averageComparativeScores") else 0,
            "control_scores": control_scores,
        }

    # ─── Process Intune Compliance & Encryption ─────────────────────────────
    intune_devices = defender_result.get("intune_devices", [])
    encrypted_count = 0
    noncompliant_devices = []

    for dev in intune_devices:
        if dev.get("isEncrypted"):
            encrypted_count += 1
        if dev.get("complianceState") != "compliant":
            noncompliant_devices.append({
                "name": dev.get("deviceName", "N/A"),
                "os": dev.get("operatingSystem", "N/A"),
                "user": dev.get("userPrincipalName", "N/A"),
                "last_sync": dev.get("lastSyncDateTime", ""),
                "encrypted": dev.get("isEncrypted", False),
            })

    total_intune = len(intune_devices)
    encryption_rate = round(encrypted_count / total_intune * 100, 1) if total_intune > 0 else 0

    # ─── Build summary ────────────────────────────────────────────────────────
    summary = {
        "total_devices_mde": len(machines),
        "active": active_count,
        "inactive": inactive_count,
        "impaired": impaired_count,
        "total_devices_intune": total_intune,
        "total_entra_devices": 0,
        "encrypted": encrypted_count,
        "encryption_rate": encryption_rate,
        "noncompliant_count": len(noncompliant_devices),
    }

    # ─── Write the complete report ────────────────────────────────────────────
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "secure_score": secure_score,
        "device_inventory": device_inventory,
        "os_distribution": os_distribution,
        "exposure_levels": exposure_levels,
        "alerts": {"summary": alert_summary, "details": alert_details},
        "vulnerabilities": {"details": vuln_details, "critical_count": critical_count, "high_count": high_count},
        "noncompliant_devices": noncompliant_devices,
        "device_coverage": {},
        "email_security": {"alerts": [], "email_controls": [], "email_activity": {}},
    }

    # Write to data/ (primary location for dashboard)
    write_json("defender_report.json", report)

    # Also write to defender_data/ mount if it exists (backward compat)
    defender_data_dir = os.path.join(os.path.dirname(DATA_DIR), "defender_data")
    if os.path.exists(defender_data_dir):
        defender_path = os.path.join(defender_data_dir, "defender_report.json")
        try:
            with open(defender_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str)
        except Exception as e:
            log.warning(f"  Could not write to defender_data/: {e}")

    log.info(f"  Defender report written: {active_count} active, {inactive_count} inactive, "
             f"{len(alert_details)} alerts, {len(vuln_details)} vulns, "
             f"Intune: {total_intune} devices, {encryption_rate}% encrypted, {len(noncompliant_devices)} noncompliant")
    return report


# ─── Cross-Correlation & Insights ─────────────────────────────────────────────
def analyze_and_write_insights(ec2_data, cs_hosts_data, bp_agents=None):
    """Cross-correlate all data and produce ai_insights.json."""
    log.info("Running cross-correlation analysis...")

    # EC2 IPs — all instances that currently exist in AWS (running + stopped)
    # Stopped servers still need coverage (they can be restarted)
    # Only exclude instances with no IP (terminated/ghost entries)
    ec2_ips = set()
    ec2_ip_details = {}
    if ec2_data:
        for acct_name, acct_instances in ec2_data.items():
            for inst in acct_instances:
                ip = inst.get("PrivateIp", "") or inst.get("private_ip", "")
                state = (inst.get("state", "") or inst.get("State", "")).lower()
                if ip:  # Only include instances that have an IP (exist in AWS)
                    ec2_ips.add(ip)
                    ec2_ip_details[ip] = {
                        "account": acct_name,
                        "instance_id": inst.get("instance_id", "") or inst.get("InstanceId", ""),
                        "name": inst.get("name", "") or inst.get("Name", ""),
                        "state": state,
                    }

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
            {"ip": ip, "gap_type": "completely_blind", "risk": "CRITICAL",
             "account": ec2_ip_details.get(ip, {}).get("account", ""),
             "name": ec2_ip_details.get(ip, {}).get("name", ""),
             "instance_id": ec2_ip_details.get(ip, {}).get("instance_id", "")}
            for ip in sorted(blind)[:15]
        ] + [
            {"ip": ip, "gap_type": "no_edr", "risk": "HIGH",
             "account": ec2_ip_details.get(ip, {}).get("account", ""),
             "name": ec2_ip_details.get(ip, {}).get("name", ""),
             "instance_id": ec2_ip_details.get(ip, {}).get("instance_id", "")}
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

    # Include email security daily totals in snapshot
    try:
        from agent.email_security_logger import get_daily_summary
        email_daily = get_daily_summary(days=1)
        if email_daily:
            latest = email_daily[-1]
            snapshot["email_threats_total"] = latest.get("total_threats", 0)
            snapshot["email_phishing"] = latest.get("phishing_blocked", 0)
            snapshot["email_malware"] = latest.get("malware_blocked", 0)
            snapshot["email_initial_access"] = latest.get("initial_access", 0)
            snapshot["email_credential_theft"] = latest.get("credential_theft", 0)
    except Exception:
        pass

    # Update or append
    if history and history[-1].get("date") == today:
        history[-1] = snapshot
    else:
        history.append(snapshot)
    history = history[-90:]  # Keep 90 days

    with open(history_path, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)
    log.info(f"  Snapshot saved for {today}")


# ─── IOM Impact Scoring (ported from MCP server) ──────────────────────────────
_HIGH_IMPACT_PATTERNS = {
    "critical_exposure": {
        "patterns": ["docker", "publicly accessible", "public internet access",
                     "hardcoded access key", "no authentication", "all principals",
                     "full administrative"],
        "base_score": 10,
    },
    "privilege_escalation": {
        "patterns": ["privilege escalation", "assume role across all",
                     "all service actions", "all kms actions", "allows all",
                     "overly permissive role"],
        "base_score": 9,
    },
    "network_exposure": {
        "patterns": ["ssh access", "rdp access", "port 22", "port 3389",
                     "non-web ports", "high-risk port", "0.0.0.0/0",
                     "publicly configured", "global public"],
        "base_score": 8,
    },
    "data_exposure": {
        "patterns": ["decryption", "kms key", "without encryption",
                     "not encrypted", "snapshot shared", "publicly shared"],
        "base_score": 7,
    },
    "iam_risk": {
        "patterns": ["iam", "inline policy", "managed policy",
                     "instance profile", "imdsv1"],
        "base_score": 6,
    },
    "monitoring_gap": {
        "patterns": ["cloudtrail", "logging", "monitoring", "cloudwatch", "flow log"],
        "base_score": 4,
    },
}


def _score_iom(rule_name, severity, misconfigurations):
    """Score an IOM by impact and blast radius."""
    rule_lower = (rule_name or "").lower()
    sev_scores = {"critical": 10, "high": 8, "medium": 5, "low": 2, "informational": 1}
    sev_score = sev_scores.get((severity or "medium").lower(), 5)

    impact_score = 3
    impact_category = "general"
    for category, config in _HIGH_IMPACT_PATTERNS.items():
        if any(p in rule_lower for p in config["patterns"]):
            if config["base_score"] > impact_score:
                impact_score = config["base_score"]
                impact_category = category

    if misconfigurations > 100:
        blast = 2.0
    elif misconfigurations > 10:
        blast = 1.5
    elif misconfigurations > 0:
        blast = 1.2
    else:
        blast = 1.0

    final_score = min(100, round(sev_score * impact_score * blast / 10 * 10, 1))
    priority = "P1" if final_score >= 80 else "P2" if final_score >= 60 else "P3" if final_score >= 40 else "P4"
    return final_score, priority, impact_category, blast


def _extract_service(rule_name):
    """Extract AWS service from rule name."""
    rule_lower = (rule_name or "").lower()
    svc_map = {
        "EC2": ["ec2", "instance", "security group", "ebs", "snapshot", "ami", "network acl"],
        "S3": ["s3", "bucket"],
        "IAM": ["iam", "password policy", "mfa", "access key", "role", "user", "group"],
        "Lambda": ["lambda", "function"],
        "VPC": ["vpc", "subnet", "network", "endpoint"],
        "ELB": ["elb", "load balancer", "alb", "nlb"],
        "CloudWatch": ["cloudwatch", "alarm"],
        "KMS": ["kms", "encryption key", "cmk"],
        "RDS": ["rds", "database"],
        "CloudTrail": ["cloudtrail", "trail"],
        "EKS": ["eks", "kubernetes"],
        "ECR": ["ecr", "repository"],
        "SNS": ["sns", "topic"],
        "SQS": ["sqs", "queue"],
        "DynamoDB": ["dynamodb"],
        "Config": ["config", "opensearch", "elasticsearch"],
        "GuardDuty": ["guardduty"],
        "ElastiCache": ["elasticache"],
        "EFS": ["efs"],
        "Route53": ["route53"],
    }
    for svc, keywords in svc_map.items():
        if any(kw in rule_lower for kw in keywords):
            return svc
    return "Other"


def _process_iom_data(iom_resources):
    """Score and write IOM analysis data (same logic as MCP analyze_iom_impact)."""
    log.info(f"  Processing {len(iom_resources)} IOMs...")

    scored = []
    for iom in iom_resources:
        rule = iom.get("rule", {})
        rule_name = rule.get("rule_name", "") if isinstance(rule, dict) else ""
        severity = iom.get("severity", "medium")
        misconfigs = iom.get("misconfigurations", 0)
        assessed = iom.get("assessed_assets", 0)
        account_id = iom.get("account_id", "N/A")

        score, priority, category, blast = _score_iom(rule_name, severity, misconfigs)
        service = _extract_service(rule_name)

        scored.append({
            "rule_name": rule_name,
            "severity": severity,
            "service": service,
            "account_id": account_id,
            "misconfigurations": misconfigs,
            "assessed_assets": assessed,
            "impact_score": score,
            "priority": priority,
            "impact_category": category,
            "blast_multiplier": blast,
        })

    scored.sort(key=lambda x: x["impact_score"], reverse=True)

    p1 = [i for i in scored if i["priority"] == "P1"]
    p2 = [i for i in scored if i["priority"] == "P2"]
    p3 = [i for i in scored if i["priority"] == "P3"]
    p4 = [i for i in scored if i["priority"] == "P4"]

    categories = {}
    services = {}
    for iom in scored:
        categories[iom["impact_category"]] = categories.get(iom["impact_category"], 0) + 1
        services[iom["service"]] = services.get(iom["service"], 0) + 1

    output = {
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "summary": {
            "total_ioms_analyzed": len(iom_resources),
            "p1_critical": len(p1),
            "p2_high": len(p2),
            "p3_medium": len(p3),
            "p4_low": len(p4),
            "top_categories": dict(sorted(categories.items(), key=lambda x: x[1], reverse=True)),
            "top_services": dict(sorted(services.items(), key=lambda x: x[1], reverse=True)),
        },
        "prioritized_findings": {
            "P1": p1,
            "P2": p2,
            "P3": p3[:20],
        },
    }

    write_json("crowdstrike_iom_analysis.json", output)
    log.info(f"  IOMs scored: P1={len(p1)} P2={len(p2)} P3={len(p3)} P4={len(p4)}")


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
    qualys_result = await fetch_qualys()

    # 1b. Fetch Aikido application security
    try:
        from agent.fetch_aikido import fetch_aikido
        aikido_result = await fetch_aikido()
    except Exception as e:
        log.warning(f"  Aikido fetch failed (non-fatal): {e}")
        aikido_result = None

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

    # 2b. Process CrowdStrike CSPM IOMs into dashboard format
    if cs_result and cs_result.get("ioms"):
        _process_iom_data(cs_result["ioms"])

    # 3. Process Defender raw API data → defender_report.json
    defender_report = None
    if defender_result:
        defender_report = process_defender_to_report(defender_result)

    # 3b. Log email security metrics (historical record for reporting)
    try:
        from agent.email_security_logger import log_email_security_cycle
        email_record = log_email_security_cycle(defender_report)
        log.info(f"  Email security logged: {email_record['total_threats']} threats")
    except Exception as e:
        log.warning(f"  Email security logging failed: {e}")

    # 4. Write EC2 data
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

    # 4b. Fetch EKS nodes (refreshes aws_eks_nodes.json every cycle)
    fetch_aws_eks_nodes()

    # 5. Cross-correlate and produce insights
    cs_hosts_flat = cs_result.get("hosts", []) if cs_result else []
    bp_agents = bp_result.get("agents", []) if bp_result else []
    insights = analyze_and_write_insights(ec2_data, cs_hosts_flat, bp_agents)

    # 6. Snapshot for trending
    take_snapshot(insights)

    # 7. Threshold alerts (immediate if risk exceeds limit)
    risk_threshold = int(os.getenv("RISK_ALERT_THRESHOLD", "50"))
    if insights.get("overall_risk_score", 0) >= risk_threshold:
        from agent.alerting import send_threshold_alert
        send_threshold_alert(insights, risk_threshold)

    # 8. Send daily digest (once per day)
    from agent.alerting import send_daily_digest
    send_daily_digest(insights)

    # 9. Generate weekly brief (includes anomaly detection + remediation prioritization)
    try:
        from agent.weekly_brief import generate_weekly_brief
        generate_weekly_brief()
        log.info("  Weekly brief updated.")
    except Exception as e:
        log.error(f"  Weekly brief generation failed: {e}")

    # 10. Data integrity watchdog — auto-corrects issues
    try:
        from agent.data_watchdog import run_watchdog
        watchdog_issues = run_watchdog()
        critical_issues = [i for i in watchdog_issues if i.severity == "CRITICAL"]
        if critical_issues:
            log.warning(f"  ⚠️  Watchdog: {len(critical_issues)} critical data integrity issues")
    except Exception as e:
        log.error(f"  Data watchdog failed: {e}")

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
