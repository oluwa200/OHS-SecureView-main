"""Get Active Windows laptops from Intune that have NO BindPlane agent."""
import sys
sys.path.insert(0, '/app')
from config.dashboard_config import load_json, load_bindplane_deduped

# Load Defender Active devices
data = load_json("defender_report.json", {})
all_devices = data.get("device_inventory", [])
active_win_laptops = [d for d in all_devices
                      if d.get("health") == "Active"
                      and "windows" in (d.get("os") or "").lower()
                      and "server" not in (d.get("os") or "").lower()
                      and d.get("name") and d["name"][0:1].isdigit()]

# Load BindPlane hostnames (all, including disconnected)
agents, _, _ = load_bindplane_deduped()
bp_all_names = {(a.get("hostname") or "").lower() for a in agents}

# Find Active Intune laptops with NO BP agent at all
no_bp = [d for d in active_win_laptops if (d.get("name") or "").lower() not in bp_all_names]

print(f"Active Windows laptops without ANY BindPlane agent: {len(no_bp)}")
print()
print("First 10 hostnames (check these in BindPlane console):")
for d in no_bp[:10]:
    print(f"  {d['name']}  |  OS: {d.get('os')}  |  Last seen: {str(d.get('last_seen',''))[:10]}")
