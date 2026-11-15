"""
BindPlane MCP Server
=====================
Custom MCP server for querying BindPlane OpAMP agent inventory.
Provides tools for agent health, coverage gaps, and telemetry status.

Run: uvx fastmcp run bindplane_server.py
"""
import os
import json
import httpx
from datetime import datetime, timezone
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# Load credentials from project .env
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

mcp = FastMCP("BindPlane")

# Config from environment
BINDPLANE_URL = os.getenv("BINDPLANE_URL", "").rstrip("/")
BINDPLANE_API_KEY = os.getenv("BINDPLANE_API_KEY", "")


async def _api_get(path):
    """Make authenticated GET request to BindPlane API."""
    if not BINDPLANE_URL or not BINDPLANE_API_KEY:
        return {"error": "BindPlane credentials not configured"}
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        r = await client.get(
            f"{BINDPLANE_URL}/v1/{path}",
            headers={"X-API-Key": BINDPLANE_API_KEY, "Authorization": f"Bearer {BINDPLANE_API_KEY}"},
        )
        if r.status_code == 200:
            return r.json()
        return {"error": f"API returned {r.status_code}", "detail": r.text[:200]}


@mcp.tool()
async def list_agents(status_filter: str = None, limit: int = 100) -> str:
    """List all BindPlane agents with their connection status.

    Args:
        status_filter: Filter by status - 'connected', 'disconnected', or None for all
        limit: Maximum agents to return
    """
    result = await _api_get("agents")

    if isinstance(result, dict) and result.get("error"):
        return json.dumps(result)

    agents = result if isinstance(result, list) else result.get("agents", result.get("data", []))

    if status_filter:
        agents = [a for a in agents if
                  (a.get("status") or "").lower() == status_filter.lower() or
                  (str(a.get("status", "")) == "1" if status_filter == "connected" else False)]

    agents = agents[:limit]

    return json.dumps({
        "total": len(agents),
        "filter": status_filter,
        "agents": [{
            "name": a.get("name") or a.get("hostname", ""),
            "status": a.get("status"),
            "ip": (a.get("remoteAddress") or a.get("ip") or "").split(":")[0],
            "os": a.get("operatingSystem") or a.get("os", ""),
            "version": a.get("version", ""),
            "last_connected": a.get("connectedAt") or a.get("lastConnected", ""),
        } for a in agents]
    }, indent=2, default=str)


@mcp.tool()
async def get_agent_health() -> str:
    """Get overall agent health summary — connected vs disconnected counts."""
    result = await _api_get("agents")

    if isinstance(result, dict) and result.get("error"):
        return json.dumps(result)

    agents = result if isinstance(result, list) else result.get("agents", result.get("data", []))

    connected = sum(1 for a in agents if a.get("status") in ("connected", 1, "1"))
    disconnected = len(agents) - connected

    # Deduplicate by hostname
    seen = {}
    for a in agents:
        hostname = (a.get("name") or a.get("hostname") or "").lower().strip()
        if hostname:
            existing = seen.get(hostname)
            if existing is None or a.get("status") in ("connected", 1, "1"):
                seen[hostname] = a
    unique_count = len(seen)
    unique_connected = sum(1 for a in seen.values() if a.get("status") in ("connected", 1, "1"))

    return json.dumps({
        "raw_total": len(agents),
        "unique_agents": unique_count,
        "connected": unique_connected,
        "disconnected": unique_count - unique_connected,
        "health_pct": round(unique_connected / max(unique_count, 1) * 100, 1),
        "duplicates_removed": len(agents) - unique_count,
    }, indent=2)


@mcp.tool()
async def get_coverage_gaps() -> str:
    """Identify devices that should have BindPlane but don't — compares against Defender device inventory."""
    # Load local data files for cross-reference
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

    # Get BindPlane agents
    result = await _api_get("agents")
    if isinstance(result, dict) and result.get("error"):
        return json.dumps(result)

    agents = result if isinstance(result, list) else result.get("agents", result.get("data", []))
    bp_hostnames = set()
    for a in agents:
        hostname = (a.get("name") or a.get("hostname") or "").lower().strip()
        if hostname:
            bp_hostnames.add(hostname)

    # Load Defender devices for comparison
    defender_path = os.path.join(data_dir, "defender_report.json")
    gaps = []
    if os.path.exists(defender_path):
        try:
            with open(defender_path, "r", encoding="utf-8") as f:
                defender = json.load(f)
            devices = defender.get("device_inventory", [])
            active_windows = [d for d in devices if d.get("health") == "Active" and "windows" in (d.get("os") or "").lower()]
            for d in active_windows:
                name = (d.get("name") or "").lower().strip()
                if name and name not in bp_hostnames:
                    gaps.append({
                        "hostname": d.get("name"),
                        "os": d.get("os"),
                        "ip": d.get("ip"),
                        "last_seen": d.get("last_seen"),
                    })
        except Exception as e:
            return json.dumps({"error": f"Failed to load Defender data: {e}"})

    return json.dumps({
        "total_active_windows": len([d for d in defender.get("device_inventory", []) if d.get("health") == "Active" and "windows" in (d.get("os") or "").lower()]) if os.path.exists(defender_path) else 0,
        "with_bindplane": len(bp_hostnames),
        "without_bindplane": len(gaps),
        "coverage_pct": round(len(bp_hostnames) / max(len(bp_hostnames) + len(gaps), 1) * 100, 1),
        "gaps": gaps[:50],
    }, indent=2, default=str)


@mcp.tool()
async def get_stale_agents(days: int = 7) -> str:
    """Find agents that haven't connected in X days — potential issues.

    Args:
        days: Number of days since last connection to consider stale (default 7)
    """
    result = await _api_get("agents")

    if isinstance(result, dict) and result.get("error"):
        return json.dumps(result)

    agents = result if isinstance(result, list) else result.get("agents", result.get("data", []))
    now = datetime.now(timezone.utc).timestamp()
    threshold = now - (days * 86400)

    stale = []
    for a in agents:
        last_seen = a.get("connectedAt") or a.get("disconnectedAt") or a.get("lastConnected", "")
        if isinstance(last_seen, str) and last_seen:
            try:
                ts = datetime.fromisoformat(last_seen.replace("Z", "+00:00")).timestamp()
                if ts < threshold:
                    stale.append({
                        "name": a.get("name") or a.get("hostname", ""),
                        "last_seen": last_seen,
                        "days_ago": round((now - ts) / 86400, 1),
                        "status": a.get("status"),
                    })
            except (ValueError, TypeError):
                pass

    stale.sort(key=lambda x: x.get("days_ago", 0), reverse=True)

    return json.dumps({
        "threshold_days": days,
        "stale_count": len(stale),
        "stale_agents": stale[:50],
    }, indent=2)


@mcp.tool()
async def list_by_category() -> str:
    """Group agents by device category (Windows Laptop, Server, macOS, Linux, etc.)."""
    result = await _api_get("agents")

    if isinstance(result, dict) and result.get("error"):
        return json.dumps(result)

    agents = result if isinstance(result, list) else result.get("agents", result.get("data", []))

    categories = {}
    for a in agents:
        os_type = (a.get("operatingSystem") or a.get("os") or "Unknown").strip()
        hostname = (a.get("name") or a.get("hostname") or "").lower()

        # Classify
        if "windows" in os_type.lower():
            if any(x in hostname for x in ["laptop", "nb-", "lt-"]):
                cat = "Windows Laptops"
            else:
                cat = "Windows Servers"
        elif "linux" in os_type.lower():
            cat = "Linux Servers"
        elif "darwin" in os_type.lower() or "macos" in os_type.lower():
            cat = "macOS"
        else:
            cat = "Other"

        if cat not in categories:
            categories[cat] = {"total": 0, "connected": 0, "disconnected": 0}
        categories[cat]["total"] += 1
        if a.get("status") in ("connected", 1, "1"):
            categories[cat]["connected"] += 1
        else:
            categories[cat]["disconnected"] += 1

    return json.dumps({
        "total_agents": len(agents),
        "categories": categories,
    }, indent=2)


@mcp.tool()
async def get_telemetry_status() -> str:
    """Check which agents are actively sending telemetry data vs just connected but idle."""
    result = await _api_get("agents")

    if isinstance(result, dict) and result.get("error"):
        return json.dumps(result)

    agents = result if isinstance(result, list) else result.get("agents", result.get("data", []))

    sending = 0
    idle = 0
    disconnected = 0

    for a in agents:
        status = a.get("status")
        if status in ("connected", 1, "1"):
            # Check if actively sending (has recent data)
            if a.get("lastDataReceived") or a.get("messagesReceived", 0) > 0:
                sending += 1
            else:
                idle += 1
        else:
            disconnected += 1

    return json.dumps({
        "total_agents": len(agents),
        "actively_sending": sending,
        "connected_idle": idle,
        "disconnected": disconnected,
        "telemetry_pct": round(sending / max(len(agents), 1) * 100, 1),
    }, indent=2)


if __name__ == "__main__":
    mcp.run()
