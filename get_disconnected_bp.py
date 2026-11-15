"""Get laptops that have BP agent installed but are disconnected."""
import sys
sys.path.insert(0, '/app')
from config.dashboard_config import load_json, load_bindplane_deduped

# Load BindPlane agents
agents, _, _ = load_bindplane_deduped()

# Laptop classification: hostname starts with digit
bp_laptops = [a for a in agents if (a.get("hostname") or "")[0:1].isdigit()]
disconnected = [a for a in bp_laptops if a.get("status") not in ("connected", 1, "1")]

print(f"Disconnected laptop agents: {len(disconnected)}")
print()
print("First 10 (check in BindPlane console):")
for a in disconnected[:10]:
    hn = a.get("hostname", "N/A")
    status = a.get("status", "unknown")
    last = a.get("disconnectedAt") or a.get("connectedAt") or "N/A"
    print(f"  {hn}  |  status: {status}  |  last seen: {str(last)[:16]}")
