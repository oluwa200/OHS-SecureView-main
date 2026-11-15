"""Endpoint Protection — Falcon Coverage tab."""
import json
import os
import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.dashboard_config import show_dataframe

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")


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


def render_coverage():
    # Load data
    cs_path = os.path.join(DATA_DIR, "crowdstrike_hosts.json")
    aws_path = os.path.join(DATA_DIR, "aws_ec2_instances.json")

    if not os.path.exists(cs_path) or not os.path.exists(aws_path):
        st.warning("CrowdStrike or AWS EC2 data not available.")
        return

    with open(cs_path, "r", encoding="utf-8") as f:
        cs_data = json.load(f)
    with open(aws_path, "r", encoding="utf-8") as f:
        aws_data = json.load(f)

    cs_accounts = _filter_accounts(cs_data.get("accounts", {}))
    aws_accounts = _filter_accounts(aws_data.get("accounts", {}))

    # Build coverage per account
    rows = []
    for acct_name, aws_instances in aws_accounts.items():
        aws_ips = {inst.get("PrivateIp", "") for inst in aws_instances if inst.get("PrivateIp")}
        
        # Find matching CrowdStrike account
        cs_hosts = cs_accounts.get(acct_name, [])
        cs_ips = {h.get("local_ip", "") for h in cs_hosts if h.get("local_ip") and h.get("local_ip") != "N/A"}

        managed = aws_ips & cs_ips
        unmanaged = aws_ips - cs_ips
        coverage_pct = (len(managed) / len(aws_ips) * 100) if aws_ips else 0

        rows.append({
            "Account": acct_name,
            "AWS EC2": len(aws_ips),
            "Falcon Managed": len(managed),
            "Unmanaged": len(unmanaged),
            "Coverage %": round(coverage_pct, 1),
        })

    # Overall KPIs
    total_aws = sum(r["AWS EC2"] for r in rows)
    total_managed = sum(r["Falcon Managed"] for r in rows)
    total_unmanaged = sum(r["Unmanaged"] for r in rows)
    total_cs = sum(len(h) for h in cs_accounts.values())
    overall_pct = (total_managed / total_aws * 100) if total_aws > 0 else 0

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("AWS EC2 Instances", total_aws)
    col2.metric("CrowdStrike Hosts", total_cs)
    col3.metric("✅ Managed", total_managed)
    col4.metric("❌ Unmanaged", total_unmanaged)
    col5.metric("Coverage", f"{overall_pct:.1f}%")

    # Coverage gauge
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=overall_pct,
        title={"text": "Falcon Sensor Coverage"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "#44bb44" if overall_pct > 90 else "#ff8800" if overall_pct > 70 else "#ff4444"},
            "steps": [
                {"range": [0, 70], "color": "#3d1111"},
                {"range": [70, 90], "color": "#3d3d11"},
                {"range": [90, 100], "color": "#113d11"},
            ],
        },
    ))
    fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=300)
    st.plotly_chart(fig, use_container_width=True)

    # Per-account table
    st.subheader("Per-Account Breakdown")
    show_dataframe(pd.DataFrame(rows), key="t_coverage_1")
