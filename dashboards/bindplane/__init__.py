"""BindPlane Telemetry Coverage sub-dashboard.
Shows agent inventory across Physical Laptops (Intune), AWS EC2, AWS WorkSpaces, EKS nodes.
Correlates against Intune/Defender and AWS to find gaps.
"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from config.dashboard_config import show_dataframe, TODAY, DATA_DIR, load_json, fetch_aws_ec2_all_accounts, show_freshness_warning, relative_time_from_iso


def render(go_home):
    """Render the BindPlane Telemetry Coverage dashboard."""
    if st.button("← Back to Home", key="back_bindplane"):
        go_home()
        st.rerun()

    # Stale data warning
    show_freshness_warning("bindplane_agents.json", "BindPlane")

    # BindPlane logo (SVG via base64)
    import base64
    ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "assets")
    bp_logo = os.path.join(ASSETS_DIR, "bindplane-logo-black.0f~cd4guqyl3k.svg")
    if os.path.exists(bp_logo):
        with open(bp_logo, "r", encoding="utf-8") as f:
            svg_content = f.read()
        b64 = base64.b64encode(svg_content.encode()).decode()
        st.markdown(f'<img src="data:image/svg+xml;base64,{b64}" width="150" style="filter:invert(1);" />', unsafe_allow_html=True)

    st.title("BindPlane — Telemetry Coverage")
    st.caption(f"Log collection agents across Physical Endpoints, EC2, WorkSpaces, EKS | {TODAY.strftime('%B %Y')}")

    # Load BindPlane data
    bp_data = load_json("bindplane_agents.json", {})
    if not bp_data or not bp_data.get("agents"):
        st.warning(
            "No BindPlane data available yet.\n\n"
            "Place `bindplane_agents.json` in the data/ directory, or configure "
            "the agent to pull from the BindPlane API.\n\n"
            "**Required env vars:** `BINDPLANE_URL`, `BINDPLANE_API_KEY`"
        )
        _show_sample_format()
        return

    agents = bp_data.get("agents", [])
    updated_at = bp_data.get("updated_at", "N/A")
    st.caption(f"Last refreshed: {relative_time_from_iso(updated_at)} ({updated_at})")

    # Classify agents
    laptops, ec2_agents, workspace_agents, eks_agents, other_agents = _classify_agents(agents)

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Overview",
        "💻 Laptops (Intune)",
        "☁️ EC2 Instances",
        "🖥️ WorkSpaces",
        "🔍 Coverage Gaps",
    ])

    with tab1:
        _render_overview(agents, laptops, ec2_agents, workspace_agents, eks_agents, other_agents)
    with tab2:
        _render_laptops(laptops)
    with tab3:
        _render_ec2(ec2_agents)
    with tab4:
        _render_workspaces(workspace_agents)
    with tab5:
        _render_gaps(agents, laptops, ec2_agents, workspace_agents, eks_agents)


def _classify_agents(agents):
    """Classify BindPlane agents into Laptops, EC2/AWS Servers, WorkSpaces, EKS, Other.

    Naming conventions:
    - EKS nodes: hostname starts with 'i-' (instance ID) AND config contains 'Kubernetes'
    - AWS Windows servers: hostname starts with 'awsnv' or 'AWSNV'
    - AWS Linux/RHEL servers: hostname starts with 'awsnv' OR 'ip-10-' OR is Linux/RHEL
      with a non-laptop hostname
    - WorkSpaces: hostname starts with 'wsamzn' or 'WSAMZN' or 'awsnv' + workspace pattern
    - Physical endpoints (laptops): hostname starts with a digit
    """
    laptops = []
    ec2_agents = []
    workspace_agents = []
    eks_agents = []
    other_agents = []

    for agent in agents:
        hostname = (agent.get("hostname") or agent.get("name") or "")
        hostname_lower = hostname.lower()
        platform = (agent.get("platform") or "").lower()
        os_name = (agent.get("os") or agent.get("operatingSystem") or "").lower()
        labels = agent.get("labels", {})
        config = (labels.get("configuration") or agent.get("configuration") or "").lower()

        # Detect OS family
        is_linux = ("linux" in platform or "linux" in os_name
                    or "ubuntu" in os_name or "rhel" in os_name
                    or "red hat" in os_name or "centos" in os_name
                    or "amazon linux" in os_name or "debian" in os_name
                    or "suse" in os_name or "fedora" in os_name)

        # EKS nodes: instance IDs (i-*) with Kubernetes config OR bottlerocket
        if (("kubernetes" in config or "bottlerocket" in os_name
             or "karpenter" in str(labels).lower())
                and (hostname_lower.startswith("i-") or is_linux)):
            eks_agents.append(agent)
        # WorkSpaces: hostnames start with WSAMZN
        elif hostname_lower.startswith("wsamzn"):
            workspace_agents.append(agent)
        # AWS servers: hostnames start with 'awsnv' (Windows naming convention)
        elif hostname_lower.startswith("awsnv"):
            ec2_agents.append(agent)
        # EC2 Linux/RHEL: ip-10-* pattern OR instance ID (i-*) without Kubernetes config
        elif hostname_lower.startswith("ip-10-") or hostname_lower.startswith("ip-"):
            ec2_agents.append(agent)
        elif hostname_lower.startswith("i-") and not "kubernetes" in config:
            ec2_agents.append(agent)
        # Linux/RHEL agents that don't start with a digit = likely AWS servers
        elif is_linux and hostname and not hostname[0].isdigit():
            ec2_agents.append(agent)
        # Physical endpoints (laptops): hostname starts with a digit
        elif hostname and hostname[0].isdigit():
            laptops.append(agent)
        # Windows/macOS without awsnv prefix = likely physical laptop
        elif ("windows" in platform or "windows" in os_name
              or "macos" in platform or "darwin" in platform):
            laptops.append(agent)
        else:
            other_agents.append(agent)

    return laptops, ec2_agents, workspace_agents, eks_agents, other_agents


def _render_overview(agents, laptops, ec2_agents, workspace_agents, eks_agents, other_agents):
    """Overview tab with KPIs and distribution charts."""
    # Deduplicate agents by hostname (same hostname can appear multiple times)
    seen_hostnames = set()
    unique_agents = []
    duplicates = 0
    for a in agents:
        hn = (a.get("hostname") or a.get("name") or "").lower().strip()
        if hn and hn in seen_hostnames:
            duplicates += 1
            continue
        if hn:
            seen_hostnames.add(hn)
        unique_agents.append(a)

    total = len(unique_agents)
    connected = sum(1 for a in unique_agents if a.get("status") in ("connected", 1, "1"))
    disconnected = total - connected

    st.markdown("---")

    if duplicates > 0:
        st.caption(f"ℹ️ {duplicates} duplicate hostname entries deduplicated ({len(agents)} raw → {total} unique)")

    col1, col2, col3, col4, col5, col6 = st.columns(6)
    col1.metric("Total Agents", total)
    col2.metric("🟢 Connected", connected)
    col3.metric("🔴 Disconnected", disconnected)
    col4.metric("💻 Laptops", len(laptops))
    col5.metric("☁️ EC2", len(ec2_agents))
    col6.metric("🖥️ WorkSpaces", len(workspace_agents))

    st.markdown("---")

    # Distribution charts
    col_pie, col_status = st.columns(2)
    with col_pie:
        dist_data = {
            "Laptops (Intune)": len(laptops),
            "EC2 Instances": len(ec2_agents),
            "WorkSpaces": len(workspace_agents),
            "EKS Nodes": len(eks_agents),
            "Other": len(other_agents),
        }
        dist_data = {k: v for k, v in dist_data.items() if v > 0}
        if dist_data:
            fig = px.pie(values=list(dist_data.values()), names=list(dist_data.keys()),
                title="Agent Distribution by Asset Type",
                color_discrete_sequence=px.colors.qualitative.Set2)
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=350)
            st.plotly_chart(fig, use_container_width=True)

    with col_status:
        status_data = {"Connected": connected, "Disconnected": disconnected}
        fig2 = px.pie(values=list(status_data.values()), names=list(status_data.keys()),
            title="Agent Health Status",
            color_discrete_map={"Connected": "#44bb44", "Disconnected": "#ff4444"})
        fig2.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=350)
        st.plotly_chart(fig2, use_container_width=True)

    # Coverage gauge
    st.markdown("---")
    coverage_pct = (connected / total * 100) if total > 0 else 0
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number", value=coverage_pct,
        title={"text": "BindPlane Agent Health (% Connected)"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "#44bb44" if coverage_pct >= 90 else "#ff8800"},
            "steps": [{"range": [0, 70], "color": "#3d1111"},
                      {"range": [70, 90], "color": "#3d3d11"},
                      {"range": [90, 100], "color": "#113d11"}],
            "threshold": {"line": {"color": "white", "width": 2}, "value": 95},
        },
    ))
    fig_gauge.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=300)
    st.plotly_chart(fig_gauge, use_container_width=True)


def _render_laptops(laptops):
    """Laptops tab — shows REAL coverage gap: Active Intune devices without BindPlane by category."""
    st.subheader("💻 BindPlane Coverage Gap — Active Devices Without Agent")

    # Source of truth: Defender/Intune Active devices
    defender_data = load_json("defender_report.json", {})
    active_devices = [d for d in defender_data.get("device_inventory", []) if d.get("health") == "Active"]

    # BindPlane connected laptop hostnames
    connected_laptops = [a for a in laptops if a.get("status") in ("connected", 1, "1")]
    bp_connected_names = {(a.get("hostname") or "").lower() for a in connected_laptops}

    # Categorize Active Intune devices and find gaps
    categories = {
        "Windows Laptops": [],
        "Windows Servers": [],
        "macOS": [],
        "Mobile (iOS/Android)": [],
        "Linux": [],
        "Other": [],
    }

    for d in active_devices:
        os_name = (d.get("os") or "Unknown").lower()
        name = (d.get("name") or "").lower()
        has_bp = name in bp_connected_names

        entry = {**d, "_has_bp": has_bp}

        if "server" in os_name:
            categories["Windows Servers"].append(entry)
        elif "ios" in os_name or "iphone" in os_name or "ipad" in os_name or "android" in os_name:
            categories["Mobile (iOS/Android)"].append(entry)
        elif "macos" in os_name or "mac os" in os_name:
            categories["macOS"].append(entry)
        elif "linux" in os_name:
            categories["Linux"].append(entry)
        elif "windows" in os_name:
            categories["Windows Laptops"].append(entry)
        else:
            categories["Other"].append(entry)

    # KPI Row — Windows laptop gap is the headline
    win_laptops = categories["Windows Laptops"]
    win_with_bp = [d for d in win_laptops if d["_has_bp"]]
    win_no_bp = [d for d in win_laptops if not d["_has_bp"]]

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Active Windows Laptops", len(win_laptops))
    col2.metric("✅ With BP Agent", len(win_with_bp))
    col3.metric("❌ No BP Agent", len(win_no_bp), delta=f"-{len(win_no_bp)} gap", delta_color="inverse")
    coverage_pct = round(len(win_with_bp) / len(win_laptops) * 100, 1) if win_laptops else 0
    col4.metric("Coverage %", f"{coverage_pct}%")

    st.markdown("---")

    # Gap by category table
    st.subheader("📊 Coverage Gap by Device Category")
    gap_rows = []
    for cat_name, devices in categories.items():
        total = len(devices)
        if total == 0:
            continue
        covered = sum(1 for d in devices if d["_has_bp"])
        gap = total - covered
        pct = round(covered / total * 100, 1) if total else 0
        gap_rows.append({
            "Category": cat_name,
            "Active Devices": total,
            "With BP": covered,
            "❌ No BP": gap,
            "Coverage": f"{pct}%",
        })

    gap_df = pd.DataFrame(gap_rows)
    gap_df = gap_df.sort_values("❌ No BP", ascending=False)
    show_dataframe(gap_df, key="bp_gap_cats", search=False)

    st.markdown("---")

    # Windows laptops without BP — the actionable list
    st.subheader(f"❌ {len(win_no_bp)} Windows Laptops Without BindPlane")
    if win_no_bp:
        no_bp_df = pd.DataFrame([{
            "Hostname": d.get("name", "N/A"),
            "OS": d.get("os", "N/A"),
            "Last Seen": str(d.get("last_seen", ""))[:10],
            "Exposure": d.get("exposure", "None"),
            "Risk": d.get("risk_score", "None"),
        } for d in win_no_bp])
        no_bp_df = no_bp_df.sort_values("Last Seen", ascending=False)
        show_dataframe(no_bp_df, key="bp_win_no_agent")

        csv = no_bp_df.to_csv(index=False)
        st.download_button("⬇️ Download gap list (CSV)", data=csv,
            file_name=f"bindplane_gap_windows_laptops_{TODAY.strftime('%Y%m%d')}.csv",
            mime="text/csv", use_container_width=True, key="dl_bp_gap")
    else:
        st.success("✅ All Active Windows laptops have BindPlane agents!")

    st.markdown("---")

    # Connected BP agents summary
    st.subheader(f"🟢 {len(connected_laptops)} Connected BindPlane Laptop Agents")
    if connected_laptops:
        conn_df = pd.DataFrame([{
            "Hostname": a.get("hostname", "N/A"),
            "IP": (a.get("remoteAddress") or a.get("ip") or "N/A").split(":")[0],
            "OS": a.get("os") or a.get("operatingSystem", "N/A"),
            "Version": a.get("version", "N/A"),
            "Connected At": (a.get("connectedAt") or "N/A")[:16],
        } for a in connected_laptops[:50]])
        show_dataframe(conn_df, key="bp_connected_laptops")


def _render_ec2(ec2_agents):
    """EC2 tab — correlate BindPlane AWS servers with AWS EC2 inventory."""
    st.subheader("☁️ AWS Servers — BindPlane vs AWS EC2")

    if not ec2_agents:
        st.info("No EC2/AWS server agents found in BindPlane.")
        return

    # Load AWS EC2 data
    aws_data = fetch_aws_ec2_all_accounts()
    aws_instance_ids = set()
    aws_names = set()
    aws_running_count = 0
    for instances in aws_data.values():
        for inst in instances:
            iid = (inst.get("InstanceId", inst.get("instance_id", "")) or "").lower()
            name = (inst.get("Name", inst.get("name", "")) or "").lower()
            state = (inst.get("State", inst.get("state", "")) or "").lower()
            if iid:
                aws_instance_ids.add(iid)
            if name:
                aws_names.add(name)
            if state == "running":
                aws_running_count += 1

    # Load ALL BindPlane agents to check EKS nodes (which use instance IDs as hostnames)
    bp_data_full = load_json("bindplane_agents.json", {})
    all_bp_hostnames = set()
    for a in bp_data_full.get("agents", []):
        hn = (a.get("hostname") or a.get("name") or "").lower()
        if hn:
            all_bp_hostnames.add(hn)

    # BindPlane EC2 agent hostnames
    bp_ec2_hostnames = set()
    for a in ec2_agents:
        hn = (a.get("hostname") or a.get("name") or "").lower()
        if hn:
            bp_ec2_hostnames.add(hn)

    # Correlate:
    # 1. Match instance IDs (BindPlane EKS nodes use i-* as hostname)
    matched_by_id = aws_instance_ids & all_bp_hostnames
    # 2. Match by Name tag (if populated)
    matched_by_name = aws_names & all_bp_hostnames if aws_names else set()
    # 3. Count awsnv* agents as covering EC2 (they ARE EC2 servers, just no 1:1 ID mapping)
    awsnv_agents = {hn for hn in bp_ec2_hostnames if hn.startswith("awsnv")}

    total_matched = len(matched_by_id) + len(matched_by_name)
    # AWS servers covered = matched by ID/name + awsnv agents (assumed to cover EC2)
    total_bp_coverage = total_matched + len(awsnv_agents)

    # Gap = running instances - covered
    gap_count = max(0, aws_running_count - total_bp_coverage)

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("AWS Running", aws_running_count)
    col2.metric("BindPlane AWS Agents", len(ec2_agents))
    col3.metric("✅ Matched (by ID/name)", total_matched)
    col4.metric("✅ awsnv* Servers", len(awsnv_agents))
    col5.metric("❌ Estimated Gap", gap_count)

    # Coverage percentage
    coverage_pct = round(total_bp_coverage / aws_running_count * 100, 1) if aws_running_count else 0
    st.progress(min(1.0, coverage_pct / 100), text=f"EC2 Telemetry Coverage: {coverage_pct}% ({total_bp_coverage}/{aws_running_count})")

    if gap_count == 0:
        st.success("✅ All running EC2 instances appear to be covered by BindPlane agents.")
    elif gap_count < 10:
        st.warning(f"⚠️ ~{gap_count} running instances may not have a BindPlane agent.")
    else:
        st.error(f"❌ ~{gap_count} running instances may not have a BindPlane agent.")

    st.caption("**Note:** EC2 Name tags are not populated in the AWS inventory. "
               "Coverage is estimated by matching instance IDs (EKS nodes) + "
               "counting `awsnv*` BindPlane agents as EC2 servers. "
               "Run `refresh_workspaces.py` with SSO to populate Name tags for exact matching.")

    st.markdown("---")

    # Agent table
    st.subheader("📋 BindPlane AWS Server Agents")
    ec2_df = pd.DataFrame([{
        "Hostname": a.get("hostname") or a.get("name", "N/A"),
        "IP": (a.get("remoteAddress") or a.get("ip") or "N/A").split(":")[0],
        "OS": a.get("os") or a.get("operatingSystem", "N/A"),
        "Status": "🟢" if a.get("status") in ("connected", 1, "1") else "🔴",
        "Version": a.get("version", "N/A"),
        "Config": (a.get("labels", {}).get("configuration") or a.get("configuration", "N/A")),
    } for a in ec2_agents])
    show_dataframe(ec2_df, key="tbl_8")

    # CSV
    if ec2_agents:
        csv_ec2 = ec2_df.to_csv(index=False)
        st.download_button("⬇️ Download AWS Server Agent Inventory (CSV)", data=csv_ec2,
            file_name=f"bindplane_aws_servers_{TODAY.strftime('%Y%m%d')}.csv",
            mime="text/csv", use_container_width=True, key="dl_bp_ec2")


def _render_workspaces(workspace_agents):
    """WorkSpaces tab — correlate with AWS WorkSpaces inventory."""
    st.subheader("🖥️ AWS WorkSpaces — BindPlane Coverage")

    # Load WorkSpaces inventory
    ws_data = load_json("aws_workspaces.json", {})
    ws_list = ws_data.get("workspaces", [])

    if not workspace_agents and not ws_list:
        st.info("No WorkSpace agents in BindPlane and no WorkSpaces inventory available.")
        return

    # BindPlane WorkSpace hostnames
    bp_ws_hostnames = {(a.get("hostname") or "").lower() for a in workspace_agents}

    # AWS WorkSpace computer names (WSAMZN-*)
    aws_ws_names = set()
    for ws in ws_list:
        cn = (ws.get("ComputerName") or ws.get("computer_name") or "").lower()
        if cn:
            aws_ws_names.add(cn)

    matched = bp_ws_hostnames & aws_ws_names
    bp_only = bp_ws_hostnames - aws_ws_names
    aws_only = aws_ws_names - bp_ws_hostnames

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("AWS WorkSpaces", len(ws_list) if ws_list else "N/A")
    col2.metric("BindPlane WS Agents", len(workspace_agents))
    col3.metric("✅ Matched", len(matched))
    col4.metric("⚠️ BP Only (stale?)", len(bp_only))
    col5.metric("❌ AWS Only (no agent)", len(aws_only))

    st.markdown("---")

    if workspace_agents:
        st.subheader("📋 BindPlane WorkSpace Agents")
        ws_df = pd.DataFrame([{
            "Hostname": a.get("hostname", "N/A"),
            "IP": (a.get("remoteAddress") or a.get("ip") or "N/A").split(":")[0],
            "OS": a.get("os") or a.get("operatingSystem", "N/A"),
            "Status": "🟢" if a.get("status") in ("connected", 1, "1") else "🔴",
            "Version": a.get("version", "N/A"),
            "In AWS WS": "✅" if (a.get("hostname") or "").lower() in aws_ws_names else "⚠️",
        } for a in workspace_agents])
        show_dataframe(ws_df, key="tbl_9")

    if ws_list:
        st.markdown("---")
        st.subheader("📋 AWS WorkSpaces Inventory")
        all_ws_df = pd.DataFrame([{
            "WorkSpace ID": ws.get("WorkspaceId", ws.get("workspace_id", "N/A")),
            "Computer Name": ws.get("ComputerName", ws.get("computer_name", "N/A")),
            "Username": ws.get("UserName", ws.get("user_name", "N/A")),
            "State": ws.get("State", ws.get("state", "N/A")),
            "Bundle": ws.get("BundleId", ws.get("bundle_id", "N/A")),
            "IP": ws.get("IpAddress", ws.get("ip_address", "N/A")),
            "BP Agent": "✅" if (ws.get("ComputerName") or ws.get("computer_name") or "").lower() in bp_ws_hostnames else "❌",
        } for ws in ws_list])
        show_dataframe(all_ws_df, key="tbl_10")

    # Gaps
    if aws_only:
        st.markdown("---")
        st.error(f"**{len(aws_only)} WorkSpaces** have no BindPlane agent — no log telemetry.")
        gap_ws = [ws for ws in ws_list if (ws.get("ComputerName") or ws.get("computer_name") or "").lower() in aws_only]
        if gap_ws:
            gap_df = pd.DataFrame([{
                "Computer Name": ws.get("ComputerName", ws.get("computer_name", "")),
                "Username": ws.get("UserName", ws.get("user_name", "")),
                "State": ws.get("State", ws.get("state", "")),
            } for ws in gap_ws])
            show_dataframe(gap_df, key="tbl_11")


def _render_gaps(agents, laptops, ec2_agents, workspace_agents, eks_agents):
    """Gaps tab — comprehensive cross-correlation summary."""
    st.subheader("🔍 Coverage Gap Analysis")
    st.caption("Assets in AWS/Intune but NOT in BindPlane, and vice versa")

    # Load all comparison sources
    aws_data = fetch_aws_ec2_all_accounts()
    defender_data = load_json("defender_report.json", {})
    ws_data = load_json("aws_workspaces.json", {})

    # All BindPlane hostnames (primary identifier)
    all_bp_hostnames = set()
    for a in agents:
        hn = (a.get("hostname") or a.get("name") or "").lower()
        if hn:
            all_bp_hostnames.add(hn)

    # AWS EC2: collect Name tags and instance IDs for matching
    aws_ec2_identifiers = set()  # Names + instance IDs
    aws_running_count = 0
    aws_running_instances = []
    for instances in aws_data.values():
        for inst in instances:
            state = (inst.get("State", inst.get("state", "")) or "").lower()
            name = (inst.get("Name", inst.get("name", "")) or "").lower()
            iid = (inst.get("InstanceId", inst.get("instance_id", "")) or "").lower()
            if name:
                aws_ec2_identifiers.add(name)
            if iid:
                aws_ec2_identifiers.add(iid)
            if state == "running":
                aws_running_count += 1
                aws_running_instances.append(inst)

    # Intune hostnames
    intune_devices = defender_data.get("device_inventory", [])
    intune_hostnames = {(d.get("name") or "").lower() for d in intune_devices if d.get("name")}

    # WorkSpaces
    ws_list = ws_data.get("workspaces", [])
    ws_names = {(ws.get("ComputerName") or ws.get("computer_name") or "").lower() for ws in ws_list}

    st.markdown("---")

    # EC2 gap: estimate running instances not covered
    # Match instance IDs (EKS nodes in BindPlane use i-* as hostname)
    aws_running_ids_matched = {iid for inst in aws_running_instances
                               for iid in [(inst.get("InstanceId", inst.get("instance_id", "")) or "").lower()]
                               if iid in all_bp_hostnames}
    # Match by Name tag (if populated)
    aws_running_names_matched = {(inst.get("Name", inst.get("name", "")) or "").lower()
                                 for inst in aws_running_instances
                                 if (inst.get("Name", inst.get("name", "")) or "").lower() in all_bp_hostnames
                                 and (inst.get("Name", inst.get("name", "")) or "").lower() != ""}
    # awsnv* agents count as EC2 coverage
    awsnv_count = sum(1 for hn in all_bp_hostnames if hn.startswith("awsnv"))

    total_ec2_covered = len(aws_running_ids_matched) + len(aws_running_names_matched) + awsnv_count
    ec2_gap = max(0, len(aws_running_instances) - total_ec2_covered)

    # Intune gap: devices not in BindPlane
    intune_no_bp = intune_hostnames - all_bp_hostnames

    # WorkSpaces gap
    ws_no_bp = ws_names - all_bp_hostnames

    # EKS: agents with i-* hostnames matched against instance IDs
    eks_bp_ids = {(a.get("hostname") or a.get("name") or "").lower()
                  for a in eks_agents if (a.get("hostname") or "").lower().startswith("i-")}

    total_gaps = ec2_gap + len(intune_no_bp) + len(ws_no_bp)

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("❌ EC2 Est. Gap", ec2_gap)
    col2.metric("❌ Laptops No Agent", len(intune_no_bp))
    col3.metric("❌ WorkSpaces No Agent", len(ws_no_bp))
    col4.metric("✅ EKS Nodes w/ Agent", len(eks_agents))
    col5.metric("⚠️ Total Gaps", total_gaps)

    st.markdown("---")

    # Gap by category
    st.subheader("📊 Gaps by Asset Category")
    gap_chart_data = {
        "EC2 Running (est. gap)": ec2_gap,
        "Laptops (no BindPlane)": len(intune_no_bp),
        "WorkSpaces (no BindPlane)": len(ws_no_bp),
    }
    gap_chart_data = {k: v for k, v in gap_chart_data.items() if v > 0}
    if gap_chart_data:
        fig = px.bar(x=list(gap_chart_data.keys()), y=list(gap_chart_data.values()),
            title="Assets Missing BindPlane Agent", color=list(gap_chart_data.keys()),
            color_discrete_sequence=["#ff4444", "#ff8800", "#ffcc00"])
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            showlegend=False, height=300)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("🎉 No coverage gaps detected — all known assets have BindPlane agents!")

    st.markdown("---")

    # EC2 coverage explanation
    st.subheader("☁️ EC2 Coverage Breakdown")
    st.markdown(f"""
    | Source | Count |
    |--------|-------|
    | AWS Running Instances | {len(aws_running_instances)} |
    | Matched by Instance ID (EKS nodes) | {len(aws_running_ids_matched)} |
    | Matched by Name tag | {len(aws_running_names_matched)} |
    | `awsnv*` BindPlane agents (assumed EC2) | {awsnv_count} |
    | **Estimated Coverage** | **{total_ec2_covered}/{len(aws_running_instances)}** |
    | **Estimated Gap** | **{ec2_gap}** |
    """)
    if ec2_gap > 0:
        st.caption("⚠️ EC2 Name tags are empty in the AWS inventory. Gap is estimated. "
                   "Run `refresh_workspaces.py` with SSO to populate Name tags for precise matching.")

    st.markdown("---")

    # Stale BindPlane agents — in BindPlane but not matched anywhere
    all_known = aws_ec2_identifiers | intune_hostnames | ws_names
    stale_hostnames = all_bp_hostnames - all_known
    # Filter out agents that are clearly physical endpoints (start with digit) — those match Intune
    stale_agents = [a for a in agents if
        (a.get("hostname") or a.get("name") or "").lower() in stale_hostnames
        and not (a.get("hostname") or "")[0:1].isdigit()]  # Don't flag laptops as stale

    st.subheader("🗑️ Stale BindPlane Agents (Not in AWS or Intune)")
    st.caption("Agents reporting to BindPlane but no matching asset in AWS or Intune — may be decommissioned")

    if stale_agents:
        st.warning(f"**{len(stale_agents)} agents** in BindPlane have no matching AWS/Intune asset.")
        stale_df = pd.DataFrame([{
            "Hostname": a.get("hostname") or a.get("name", "N/A"),
            "IP": (a.get("remoteAddress") or a.get("ip") or "N/A").split(":")[0],
            "OS": a.get("os") or a.get("operatingSystem", "N/A"),
            "Status": "🟢" if a.get("status") in ("connected", 1, "1") else "🔴",
            "Last Seen": (a.get("connectedAt") or a.get("disconnectedAt") or "N/A")[:16],
        } for a in stale_agents[:50]])
        show_dataframe(stale_df, key="tbl_12")
    else:
        st.success("✅ No stale agents — all BindPlane agents match a known asset.")

    st.markdown("---")

    # Recommendations
    st.subheader("💡 Recommendations")
    recs = []
    if ec2_gap > 0:
        recs.append(f"🔴 ~**{ec2_gap} running EC2 instances** may be missing BindPlane telemetry. Populate Name tags for precise correlation.")
    if intune_no_bp:
        recs.append(f"🟠 Deploy BindPlane agent to **{len(intune_no_bp)} Intune laptops** for log collection.")
    if ws_no_bp:
        recs.append(f"🟡 Deploy BindPlane agent to **{len(ws_no_bp)} WorkSpaces** without telemetry.")
    if stale_agents:
        recs.append(f"⚠️ Remove **{len(stale_agents)} stale agents** from BindPlane (decommissioned assets).")
    if not recs:
        st.success("🎉 Full BindPlane coverage — all assets have the telemetry agent!")
    else:
        for r in recs:
            st.markdown(r)


def _show_sample_format():
    """Show the expected JSON format for bindplane_agents.json."""
    st.markdown("---")
    st.subheader("📄 Expected Data Format")
    st.code('''{
  "updated_at": "2026-06-24 12:00:00 UTC",
  "agents": [
    {
      "hostname": "WSAMZN-ABC123",
      "remoteAddress": "10.128.1.50:4317",
      "operatingSystem": "Windows 11",
      "platform": "windows",
      "status": "connected",
      "connectedAt": "2026-06-24T10:00:00Z",
      "version": "1.82.0",
      "fleet": "workspaces",
      "labels": {"type": "workspace", "env": "production"}
    }
  ]
}''', language="json")
