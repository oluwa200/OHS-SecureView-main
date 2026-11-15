"""Show the full 1080 'Intune Only' list - what devices are in Intune Active but NOT in BindPlane."""
import sys
sys.path.insert(0, '/app')
from config.dashboard_config import load_json, load_bindplane_deduped

# Load Defender Active devices
data = load_json("defender_report.json", {})
all_devices = data.get("device_inventory", [])
active_devices = [d for d in all_devices if d.get("health") == "Active"]

# Load BindPlane connected laptops (what the dashboard uses)
agents, _, _ = load_bindplane_deduped()
bp_laptop_agents = [a for a in agents if (a.get("hostname") or "")[0:1].isdigit() and a.get("status") in ("connected", 1, "1")]
bp_hostnames = {(a.get("hostname") or "").lower() for a in bp_laptop_agents}

# Intune Active hostnames
intune_hostnames = {(d.get("name") or "").lower() for d in active_devices if d.get("name")}

# Intune Only = in Intune but NOT matching any connected BP laptop hostname
intune_only = intune_hostnames - bp_hostnames

# Get device details for these
intune_only_devices = [d for d in active_devices if (d.get("name") or "").lower() in intune_only]

# Categorize them
categories = {}
for d in intune_only_devices:
    os = d.get("os") or "Unknown"
    categories[os] = categories.get(os, 0) + 1

print(f"=== 'Intune Only (no BP agent)' Breakdown: {len(intune_only_devices)} devices ===")
print()
print("By OS type:")
for os_name, count in sorted(categories.items(), key=lambda x: -x[1]):
    print(f"  {os_name}: {count}")

print()
print(f"--- Windows (non-server) laptops without BP: ---")
win_laptops = [d for d in intune_only_devices 
               if "windows" in (d.get("os") or "").lower() 
               and "server" not in (d.get("os") or "").lower()]
print(f"  Count: {len(win_laptops)}")
for d in win_laptops[:20]:
    print(f"    {d.get('name')}  |  {d.get('os')}  |  Last: {str(d.get('last_seen',''))[:10]}")

print()
print(f"--- Servers (would not have BP laptop agent): ---")
servers = [d for d in intune_only_devices if "server" in (d.get("os") or "").lower()]
print(f"  Count: {len(servers)}")

print()
print(f"--- Mobile/Other (iOS, Android, macOS — no BP expected): ---")
mobile = [d for d in intune_only_devices 
          if any(x in (d.get("os") or "").lower() for x in ["ios", "android", "macos", "iphone", "ipad"])]
print(f"  Count: {len(mobile)}")
