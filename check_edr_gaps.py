"""Check EDR coverage gaps — identify instances flagged as no-Falcon that don't exist in AWS."""
import json, os

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# Load EC2 instances
ec2_path = os.path.join(DATA_DIR, "aws_ec2_instances.json")
ec2 = json.load(open(ec2_path)) if os.path.exists(ec2_path) else {}

# Get all prod IPs and instance IDs
prod_instances = ec2.get("accounts", {}).get("Production", [])
prod_ips = set(i.get("private_ip", "") for i in prod_instances if i.get("private_ip"))
prod_ids = set(i.get("instance_id", "") for i in prod_instances if i.get("instance_id"))
prod_running = [i for i in prod_instances if i.get("state") == "running"]

print(f"=== AWS Prod Account ===")
print(f"  Total instances: {len(prod_instances)}")
print(f"  Running: {len(prod_running)}")
print(f"  Unique IPs: {len(prod_ips)}")

# Load CrowdStrike hosts
cs_path = os.path.join(DATA_DIR, "crowdstrike_hosts.json")
cs = json.load(open(cs_path)) if os.path.exists(cs_path) else {}
prod_cs = cs.get("accounts", {}).get("Production", [])
cs_ips = set(h.get("local_ip", "") for h in prod_cs if h.get("local_ip"))
cs_instance_ids = set(h.get("instance_id", "") for h in prod_cs if h.get("instance_id"))

print(f"\n=== CrowdStrike Prod Hosts ===")
print(f"  Total hosts: {len(prod_cs)}")
print(f"  Unique IPs: {len(cs_ips)}")

# Load AI insights
insights_path = os.path.join(DATA_DIR, "ai_insights.json")
insights = json.load(open(insights_path)) if os.path.exists(insights_path) else {}
no_edr = insights.get("findings", {}).get("no_edr", [])

print(f"\n=== Flagged as No EDR (No Falcon) ===")
print(f"  Total flagged: {len(no_edr)}")

# Check which flagged IPs actually exist in current EC2
ghost_instances = []
real_gaps = []

for finding in no_edr:
    ip = finding.get("ip", "")
    account = finding.get("account", "")
    state = finding.get("state", "")
    name = finding.get("name", "")
    
    if account == "Production":
        if ip in prod_ips:
            real_gaps.append(finding)
        else:
            ghost_instances.append(finding)

print(f"\n=== Prod Account Breakdown ===")
prod_flagged = [f for f in no_edr if f.get("account") == "Production"]
print(f"  Prod instances flagged: {len(prod_flagged)}")
print(f"  REAL gaps (IP exists in AWS): {len(real_gaps)}")
print(f"  GHOST entries (IP NOT in AWS): {len(ghost_instances)}")

if ghost_instances:
    print(f"\n=== Ghost Instances (don't exist in AWS) ===")
    for g in ghost_instances[:20]:
        print(f"  IP: {g.get('ip', '?'):15} | Name: {g.get('name', '?'):30} | State: {g.get('state', '?')}")

if real_gaps:
    print(f"\n=== Real Gaps (exist but no Falcon) ===")
    for r in real_gaps[:20]:
        print(f"  IP: {r.get('ip', '?'):15} | Name: {r.get('name', '?'):30} | State: {r.get('state', '?')}")
