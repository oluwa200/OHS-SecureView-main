"""Endpoint Protection — Unmanaged Hosts tab."""
import json
import os
import streamlit as st
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


def render_unmanaged():
    cs_path = os.path.join(DATA_DIR, "crowdstrike_hosts.json")
    aws_path = os.path.join(DATA_DIR, "aws_ec2_instances.json")

    if not os.path.exists(cs_path) or not os.path.exists(aws_path):
        st.warning("Data not available for coverage analysis.")
        return

    with open(cs_path, "r", encoding="utf-8") as f:
        cs_data = json.load(f)
    with open(aws_path, "r", encoding="utf-8") as f:
        aws_data = json.load(f)

    cs_accounts = _filter_accounts(cs_data.get("accounts", {}))
    aws_accounts = _filter_accounts(aws_data.get("accounts", {}))

    st.subheader("❌ Unmanaged EC2 Instances — Deploy Falcon Sensor")

    all_unmanaged = []
    for acct_name, aws_instances in aws_accounts.items():
        aws_ips = {}
        for inst in aws_instances:
            ip = inst.get("PrivateIp", "")
            if ip:
                aws_ips[ip] = inst

        cs_hosts = cs_accounts.get(acct_name, [])
        cs_ips = {h.get("local_ip", "") for h in cs_hosts if h.get("local_ip") and h.get("local_ip") != "N/A"}

        for ip, inst in aws_ips.items():
            if ip not in cs_ips:
                all_unmanaged.append({
                    "Account": acct_name,
                    "Instance ID": inst.get("instance_id", ""),
                    "Name": inst.get("name", "unnamed"),
                    "Private IP": ip,
                    "State": inst.get("state", ""),
                    "Type": inst.get("instance_type", ""),
                })

    if all_unmanaged:
        st.error(f"**{len(all_unmanaged)} EC2 instances do NOT have the Falcon sensor installed.**")
        df = pd.DataFrame(all_unmanaged)

        # Filter
        acct_filter = st.multiselect("Filter by Account", sorted(df["Account"].unique()), default=[])
        if acct_filter:
            df = df[df["Account"].isin(acct_filter)]

        show_dataframe(df, key="tbl_1")

        csv = df.to_csv(index=False)
        st.download_button("⬇️ Download Unmanaged Hosts (CSV)", csv,
                          "unmanaged_hosts.csv", "text/csv", use_container_width=True)
    else:
        st.success("✅ All AWS EC2 instances have the Falcon sensor deployed!")
