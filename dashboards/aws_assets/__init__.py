"""AWS Assets sub-dashboard.
Tabs: EC2 & WorkSpaces, IAM Key Rotation, Summary.
"""
import json
import os
import streamlit as st
import pandas as pd
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.dashboard_config import show_dataframe

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "assets")


def _get_account_filter():
    """Get the current global account filter."""
    return st.session_state.get("account_filter", "All")


def _filter_accounts(accounts_dict):
    """Filter accounts dict by selected account."""
    f = _get_account_filter()
    if f == "All":
        return accounts_dict
    short_name = f.split(" (")[0]
    return {k: v for k, v in accounts_dict.items() if short_name.lower() in k.lower()}


def render(go_home):
    """Render AWS Assets coverage dashboard."""
    if st.button("← Back to Home", key="back_aws"):
        go_home()
        st.rerun()

    aws_logo = os.path.join(ASSETS_DIR, "AWS-Logo-svg.jpg")
    if os.path.exists(aws_logo):
        st.image(aws_logo, width=100)

    st.title("AWS Assets Coverage")
    st.caption("EC2 instances, WorkSpaces & IAM credential rotation across all scoped accounts")

    # Tabs
    tab1, tab2 = st.tabs([
        "🖥️ EC2 & WorkSpaces",
        "🔑 IAM Key Rotation",
    ])

    with tab1:
        _render_ec2_and_workspaces()
    with tab2:
        _render_iam_keys_tab()


def _render_iam_keys_tab():
    """Render IAM key rotation inventory."""
    from dashboards.aws_assets.iam_keys import render_iam_keys
    render_iam_keys()


def _render_ec2_and_workspaces():
    """Render the EC2 instances and WorkSpaces tab."""
    counts_path = os.path.join(DATA_DIR, "aws_ec2_counts.json")
    instances_path = os.path.join(DATA_DIR, "aws_ec2_instances.json")

    if not os.path.exists(counts_path):
        st.warning("AWS EC2 data not available. Run the EC2 refresh.")
        return

    with open(counts_path, "r", encoding="utf-8") as f:
        counts = json.load(f)

    # Load CrowdStrike host data for comparison
    cs_path = os.path.join(DATA_DIR, "crowdstrike_hosts.json")
    cs_hosts = {}
    if os.path.exists(cs_path):
        with open(cs_path, "r", encoding="utf-8") as f:
            cs_hosts = json.load(f)

    # Apply account filter to by_account
    by_account = _filter_accounts(counts.get("by_account", {}))

    # Recalculate totals based on filter
    filtered_total = sum(d.get("total", 0) for d in by_account.values())
    filtered_running = sum(d.get("running", 0) for d in by_account.values())
    filtered_stopped = sum(d.get("stopped", 0) for d in by_account.values())

    # CrowdStrike totals (filtered)
    cs_accounts = _filter_accounts(cs_hosts.get("accounts", {}))
    cs_total = sum(len(h) for h in cs_accounts.values())

    # KPIs — AWS + CrowdStrike side by side
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("☁️ EC2 Total", filtered_total)
    col2.metric("▶️ Running", filtered_running)
    col3.metric("⏹️ Stopped", filtered_stopped)
    col4.metric("🦅 CrowdStrike Hosts", cs_total)
    col5.metric("📊 Coverage", f"{round(cs_total / filtered_running * 100) if filtered_running else 0}%",
                help="CrowdStrike hosts / EC2 running instances")

    st.markdown("---")

    # Per-account breakdown with CrowdStrike comparison
    st.subheader("Per-Account Breakdown (AWS EC2 vs CrowdStrike)")
    rows = []
    for name, data in by_account.items():
        cs_count = len(cs_accounts.get(name, []))
        ec2_running = data.get("running", 0)
        coverage = round(cs_count / ec2_running * 100) if ec2_running else 0
        rows.append({
            "Account": name,
            "EC2 Total": data.get("total", 0),
            "EC2 Running": ec2_running,
            "EC2 Stopped": data.get("stopped", 0),
            "🦅 CrowdStrike": cs_count,
            "Coverage %": f"{coverage}%",
        })

    if rows:
        show_dataframe(pd.DataFrame(rows), key="t_main_1")

    # Full instance list
    if os.path.exists(instances_path):
        with open(instances_path, "r", encoding="utf-8") as f:
            inst_data = json.load(f)

        # Apply account filter to instances
        filtered_accounts = _filter_accounts(inst_data.get("accounts", {}))

        st.markdown("---")
        st.subheader("Instance Inventory")

        all_instances = []
        for acct_name, instances in filtered_accounts.items():
            for inst in instances:
                all_instances.append({
                    "Account": acct_name,
                    "Instance ID": inst.get("instance_id", ""),
                    "Name": inst.get("name", ""),
                    "State": inst.get("state", ""),
                    "Type": inst.get("instance_type", ""),
                    "Private IP": inst.get("PrivateIp", ""),
                })

        if all_instances:
            df = pd.DataFrame(all_instances)

            # Filter
            acct_filter = st.multiselect("Filter by Account", sorted(df["Account"].unique()),
                                         default=[], key="ec2_acct_filter")
            if acct_filter:
                df = df[df["Account"].isin(acct_filter)]

            st.metric("Showing", f"{len(df)} instances")
            show_dataframe(df, key="tbl_4")

    # ─── AWS WorkSpaces Section ───────────────────────────────────────────────
    st.markdown("---")
    st.subheader("🖥️ AWS WorkSpaces (Infrastructure Account)")

    ws_path = os.path.join(DATA_DIR, "aws_workspaces.json")
    if os.path.exists(ws_path):
        with open(ws_path, "r", encoding="utf-8") as f:
            ws_data = json.load(f)

        ws_list = ws_data.get("workspaces", [])
        ws_updated = ws_data.get("updated_at", "N/A")
        st.caption(f"Last refreshed: {ws_updated}")

        if ws_list:
            # KPIs
            total_ws = len(ws_list)
            running_ws = sum(1 for ws in ws_list if (ws.get("State") or ws.get("state", "")).upper() in ("AVAILABLE", "RUNNING"))
            stopped_ws = sum(1 for ws in ws_list if (ws.get("State") or ws.get("state", "")).upper() in ("STOPPED", "SUSPENDED"))

            ws_col1, ws_col2, ws_col3, ws_col4 = st.columns(4)
            ws_col1.metric("Total WorkSpaces", total_ws)
            ws_col2.metric("Available/Running", running_ws)
            ws_col3.metric("Stopped/Suspended", stopped_ws)
            ws_col4.metric("Other", total_ws - running_ws - stopped_ws)

            # Load user display names from defender report for cross-reference
            from config.dashboard_config import load_json as _load_json
            defender_report = _load_json("defender_report.json", {})
            user_names = defender_report.get("user_display_names", {})

            # WorkSpaces table
            ws_df = pd.DataFrame([{
                "WorkSpace ID": ws.get("WorkspaceId", ws.get("workspace_id", "N/A")),
                "Computer Name": ws.get("ComputerName", ws.get("computer_name", "N/A")),
                "Username": ws.get("UserName", ws.get("user_name", "N/A")),
                "Full Name": user_names.get((ws.get("UserName") or ws.get("user_name") or "").upper(), ""),
                "State": ws.get("State", ws.get("state", "N/A")),
                "Bundle": ws.get("BundleId", ws.get("bundle_id", "N/A")),
                "IP Address": ws.get("IpAddress", ws.get("ip_address", "N/A")),
                "Directory": ws.get("DirectoryId", ws.get("directory_id", "N/A")),
            } for ws in ws_list])

            state_filter = st.multiselect("Filter by State", sorted(ws_df["State"].unique()),
                                          default=[], key="ws_state_filter")
            if state_filter:
                ws_df = ws_df[ws_df["State"].isin(state_filter)]

            st.metric("Showing", f"{len(ws_df)} workspaces")
            show_dataframe(ws_df, key="tbl_ws")

            # CSV download
            csv_ws = ws_df.to_csv(index=False)
            st.download_button("⬇️ Download WorkSpaces Inventory (CSV)", data=csv_ws,
                file_name=f"aws_workspaces_{pd.Timestamp.now().strftime('%Y%m%d')}.csv",
                mime="text/csv", use_container_width=True, key="dl_workspaces")
        else:
            st.info("No WorkSpaces found in the inventory file.")
    else:
        st.info(
            "WorkSpaces data not available yet. "
            "Place `aws_workspaces.json` in the data/ directory or configure the agent to pull it."
        )
