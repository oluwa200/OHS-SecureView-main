"""AWS Assets — IAM Access Key Rotation Inventory.
Shows access keys older than 90 days as compliance risk.
Pulls data from data/iam_access_keys.json (populated by agent or refresh script).
"""
import sys
import os
import json
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from config.dashboard_config import show_dataframe, DATA_DIR, load_json, TODAY


# Compliance thresholds (days)
KEY_AGE_WARNING = 60   # Yellow
KEY_AGE_CRITICAL = 90  # Red — violates compliance


def render_iam_keys():
    """Render the IAM access key rotation inventory."""
    iam_data = load_json("iam_access_keys.json", {})

    if not iam_data or not iam_data.get("accounts"):
        st.warning("IAM access key data not available.")
        st.markdown("---")
        st.info("""
        **To populate this data**, run the IAM key refresh:
        ```
        python refresh_iam_keys.py
        ```
        Or use the button below (requires active AWS SSO session).
        """)
        if st.button("🔄 Refresh IAM Key Data", key="refresh_iam_keys"):
            with st.spinner("Fetching IAM access keys from all accounts..."):
                try:
                    _fetch_iam_keys()
                    st.success("IAM key data refreshed!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed: {e}")
        return

    updated_at = iam_data.get("updated_at", "N/A")
    st.caption(f"Last refreshed: {updated_at}")

    # Flatten all keys
    all_keys = []
    for acct_name, acct_data in iam_data.get("accounts", {}).items():
        for key_info in acct_data.get("keys", []):
            key_info["account"] = acct_name
            # Calculate age
            created = key_info.get("create_date", "")
            if created:
                try:
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - created_dt).days
                except Exception:
                    age_days = 0
            else:
                age_days = 0
            key_info["age_days"] = age_days
            key_info["compliance_status"] = (
                "🔴 CRITICAL" if age_days > KEY_AGE_CRITICAL else
                "🟡 WARNING" if age_days > KEY_AGE_WARNING else
                "🟢 OK"
            )
            all_keys.append(key_info)

    if not all_keys:
        st.info("No IAM access keys found across scoped accounts.")
        return

    df = pd.DataFrame(all_keys)

    # ─── KPIs ─────────────────────────────────────────────────────────────────
    total_keys = len(df)
    active_keys = len(df[df.get("status", pd.Series(dtype=str)).str.upper() == "ACTIVE"]) if "status" in df.columns else total_keys
    critical_keys = len(df[df["age_days"] > KEY_AGE_CRITICAL])
    warning_keys = len(df[(df["age_days"] > KEY_AGE_WARNING) & (df["age_days"] <= KEY_AGE_CRITICAL)])
    compliant_keys = len(df[df["age_days"] <= KEY_AGE_WARNING])

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Keys", total_keys)
    col2.metric("Active", active_keys)
    col3.metric("🔴 >90 Days", critical_keys)
    col4.metric("🟡 60-90 Days", warning_keys)
    col5.metric("🟢 <60 Days", compliant_keys)

    # Compliance percentage
    compliance_pct = round(compliant_keys / total_keys * 100, 1) if total_keys > 0 else 100
    if compliance_pct < 70:
        st.error(f"⚠️ **Compliance: {compliance_pct}%** — {critical_keys} keys exceed the 90-day rotation policy")
    elif compliance_pct < 90:
        st.warning(f"🟡 **Compliance: {compliance_pct}%** — {critical_keys + warning_keys} keys need attention")
    else:
        st.success(f"✅ **Compliance: {compliance_pct}%** — Key rotation is well-managed")

    st.markdown("---")

    # ─── Age Distribution Chart ───────────────────────────────────────────────
    st.subheader("📊 Key Age Distribution")

    # Histogram
    fig_hist = px.histogram(df, x="age_days", nbins=20,
                            color="compliance_status",
                            color_discrete_map={
                                "🔴 CRITICAL": "#ff4444",
                                "🟡 WARNING": "#ffcc00",
                                "🟢 OK": "#44bb44",
                            },
                            title="Access Key Age Distribution (days)")
    fig_hist.add_vline(x=90, line_dash="dash", line_color="#ff4444",
                       annotation_text="90-day policy")
    fig_hist.add_vline(x=60, line_dash="dot", line_color="#ffcc00",
                       annotation_text="60-day warning")
    fig_hist.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                           plot_bgcolor="rgba(0,0,0,0)", font_color="white",
                           xaxis_title="Key Age (days)", yaxis_title="Count")
    st.plotly_chart(fig_hist, use_container_width=True)

    # ─── By Account Breakdown ─────────────────────────────────────────────────
    st.subheader("🏢 Keys by Account")
    acct_summary = []
    for acct_name in sorted(df["account"].unique()):
        acct_df = df[df["account"] == acct_name]
        acct_summary.append({
            "Account": acct_name,
            "Total Keys": len(acct_df),
            "🔴 >90d": len(acct_df[acct_df["age_days"] > KEY_AGE_CRITICAL]),
            "🟡 60-90d": len(acct_df[(acct_df["age_days"] > KEY_AGE_WARNING) & (acct_df["age_days"] <= KEY_AGE_CRITICAL)]),
            "🟢 <60d": len(acct_df[acct_df["age_days"] <= KEY_AGE_WARNING]),
            "Oldest Key (days)": acct_df["age_days"].max(),
            "Compliance %": round(len(acct_df[acct_df["age_days"] <= KEY_AGE_WARNING]) / len(acct_df) * 100, 1) if len(acct_df) > 0 else 100,
        })
    st.dataframe(pd.DataFrame(acct_summary), use_container_width=True, hide_index=True)

    # ─── Non-Compliant Keys (>90 days) ────────────────────────────────────────
    st.markdown("---")
    st.subheader("🔴 Non-Compliant Keys (>90 days)")
    st.caption("These keys violate the 90-day rotation policy and should be rotated immediately")

    non_compliant = df[df["age_days"] > KEY_AGE_CRITICAL].sort_values("age_days", ascending=False)
    if not non_compliant.empty:
        display_cols = [c for c in ["account", "username", "access_key_id", "status",
                                    "age_days", "create_date", "last_used_date"] if c in non_compliant.columns]
        st.dataframe(non_compliant[display_cols].reset_index(drop=True),
                     use_container_width=True, hide_index=True)

        # CSV export
        csv_nc = non_compliant[display_cols].to_csv(index=False)
        st.download_button("⬇️ Download Non-Compliant Keys (CSV)", data=csv_nc,
                          file_name=f"non_compliant_iam_keys_{TODAY.strftime('%Y%m%d')}.csv",
                          mime="text/csv", use_container_width=True, key="dl_nc_keys")
    else:
        st.success("✅ All keys comply with the 90-day rotation policy!")

    # ─── All Keys Table ───────────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("📋 All Access Keys")

    # Filters
    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        filter_acct = st.multiselect("Account", sorted(df["account"].unique()), default=[], key="iam_acct_filter")
    with col_f2:
        filter_status = st.multiselect("Compliance",
            sorted(df["compliance_status"].unique()), default=[], key="iam_compliance_filter")
    with col_f3:
        if "status" in df.columns:
            filter_key_status = st.multiselect("Key Status", sorted(df["status"].unique()), default=[], key="iam_key_status")
        else:
            filter_key_status = []

    df_filtered = df.copy()
    if filter_acct:
        df_filtered = df_filtered[df_filtered["account"].isin(filter_acct)]
    if filter_status:
        df_filtered = df_filtered[df_filtered["compliance_status"].isin(filter_status)]
    if filter_key_status and "status" in df.columns:
        df_filtered = df_filtered[df_filtered["status"].isin(filter_key_status)]

    display_cols = [c for c in ["account", "username", "access_key_id", "status",
                                "age_days", "compliance_status", "create_date",
                                "last_used_date", "last_used_service"] if c in df_filtered.columns]

    st.metric("Showing", f"{len(df_filtered)} of {len(df)} keys")
    st.dataframe(df_filtered[display_cols].sort_values("age_days", ascending=False),
                 use_container_width=True, hide_index=True)


def _fetch_iam_keys():
    """Fetch IAM access key data from all accounts (requires active SSO)."""
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError

    profiles = [
        {"name": "Infrastructure", "profile": "infra", "account_id": "446329232350"},
        {"name": "Production", "profile": "prod", "account_id": "937786629491"},
        {"name": "Network", "profile": "network", "account_id": "895945783203"},
        {"name": "Test and QA", "profile": "test-qa", "account_id": "754120856488"},
    ]

    result = {"updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"), "accounts": {}}

    for p in profiles:
        try:
            session = boto3.Session(profile_name=p["profile"])
            iam = session.client("iam")
            keys = []

            # List all users
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    # List access keys for user
                    key_resp = iam.list_access_keys(UserName=username)
                    for key_meta in key_resp.get("AccessKeyMetadata", []):
                        key_id = key_meta["AccessKeyId"]
                        create_date = key_meta["CreateDate"].isoformat()
                        status = key_meta["Status"]

                        # Get last used info
                        try:
                            last_used_resp = iam.get_access_key_last_used(AccessKeyId=key_id)
                            last_used = last_used_resp.get("AccessKeyLastUsed", {})
                            last_used_date = last_used.get("LastUsedDate", "")
                            last_used_service = last_used.get("ServiceName", "N/A")
                            if last_used_date:
                                last_used_date = last_used_date.isoformat()
                        except Exception:
                            last_used_date = "N/A"
                            last_used_service = "N/A"

                        keys.append({
                            "username": username,
                            "access_key_id": key_id,
                            "status": status,
                            "create_date": create_date,
                            "last_used_date": last_used_date if last_used_date else "Never",
                            "last_used_service": last_used_service,
                        })

            result["accounts"][p["name"]] = {
                "account_id": p["account_id"],
                "keys": keys,
                "total_keys": len(keys),
                "non_compliant": sum(1 for k in keys if _key_age(k.get("create_date", "")) > KEY_AGE_CRITICAL),
            }
        except (ClientError, NoCredentialsError) as e:
            result["accounts"][p["name"]] = {
                "account_id": p["account_id"],
                "keys": [],
                "error": str(e),
            }

    # Write to data dir
    output_path = os.path.join(DATA_DIR, "iam_access_keys.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    return result


def _key_age(create_date_str):
    """Calculate key age in days from create_date ISO string."""
    if not create_date_str:
        return 0
    try:
        created = datetime.fromisoformat(create_date_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - created).days
    except Exception:
        return 0
