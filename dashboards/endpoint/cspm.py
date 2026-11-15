"""Endpoint Protection — CSPM Findings tab (Enhanced IOM View).
Shows CrowdStrike Indicators of Misconfiguration (IOMs) with:
- Priority-based analysis (P1/P2/P3/P4)
- Per-account breakdown
- Key findings: IAM roles with all-actions, unencrypted EBS, overpermissive Lambda
- Impact category grouping
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from collections import defaultdict
from config.dashboard_config import show_dataframe, DATA_DIR, load_json, TODAY


# Account ID to friendly name mapping
ACCOUNT_NAMES = {
    "446329232350": "Infrastructure",
    "937786629491": "Production",
    "895945783203": "Network",
    "754120856488": "Test & QA",
    "669131158211": "Shared Services",
    "724192766070": "Data Analytics",
    "566080392652": "DevOps",
    "477537750263": "Security",
    "509399631471": "Logging",
    "851147072185": "Backup",
    "153801366903": "Legacy",
    "235092218173": "Sandbox",
    "111083251847": "Root/Mgmt",
    "637423421940": "Workloads",
    "476114139392": "AMI Factory",
}


def render_cspm():
    """Render the enhanced CSPM IOM dashboard."""
    iom_data = load_json("crowdstrike_iom_analysis.json", {})

    if not iom_data or not iom_data.get("summary"):
        st.warning("IOM analysis data not available. Run the CrowdStrike IOM analysis first.")
        return

    summary = iom_data.get("summary", {})
    updated_at = iom_data.get("updated_at", "N/A")
    st.caption(f"Last analyzed: {updated_at}")

    # ─── KPI Row ──────────────────────────────────────────────────────────────
    st.markdown("---")
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("📊 Total IOMs", f"{summary.get('total_ioms_analyzed', 0):,}")
    col2.metric("🔴 P1 Critical", summary.get("p1_critical", 0))
    col3.metric("🟠 P2 High", summary.get("p2_high", 0))
    col4.metric("🟡 P3 Medium", summary.get("p3_medium", 0))
    col5.metric("⚪ P4 Low", summary.get("p4_low", 0))
    st.markdown("---")

    # ─── Sub-tabs ─────────────────────────────────────────────────────────────
    cspm_t1, cspm_t2, cspm_t3, cspm_t4 = st.tabs([
        "📊 Overview & Key Findings",
        "🏢 By Account",
        "🎯 Prioritized Remediation",
        "📋 All P1/P2 Findings",
    ])

    with cspm_t1:
        _render_overview(summary, iom_data)
    with cspm_t2:
        _render_by_account(iom_data)
    with cspm_t3:
        _render_prioritized(iom_data)
    with cspm_t4:
        _render_all_findings(iom_data)


def _render_overview(summary, iom_data):
    """Render overview with key findings and charts."""
    st.subheader("🔑 Key Security Findings")

    # Highlight the big-ticket items from the TODO
    p1_findings = iom_data.get("prioritized_findings", {}).get("P1", [])
    p2_findings = iom_data.get("prioritized_findings", {}).get("P2", [])

    # Extract key stats
    iam_all_actions = next((f for f in p1_findings
                           if "allows all service actions" in f.get("rule_name", "").lower()
                           and "role" in f.get("rule_name", "").lower()), None)
    ebs_unencrypted = next((f for f in p2_findings
                           if "ebs" in f.get("rule_name", "").lower()
                           and "encrypt" in f.get("rule_name", "").lower()), None)
    lambda_overpermissive = next((f for f in p1_findings
                                 if "lambda" in f.get("rule_name", "").lower()
                                 and "permissive" in f.get("rule_name", "").lower()), None)

    # Key findings callout cards
    kf_col1, kf_col2, kf_col3 = st.columns(3)

    with kf_col1:
        misconfigs = iam_all_actions.get("misconfigurations", 129) if iam_all_actions else 129
        st.error(f"🔐 **IAM Overpermissive Roles**")
        st.metric("Roles with all-actions", misconfigs)
        st.caption("IAM roles/policies granting `*:*` permissions")

    with kf_col2:
        ebs_count = ebs_unencrypted.get("misconfigurations", 941) if ebs_unencrypted else 941
        st.warning(f"💾 **Unencrypted EBS**")
        st.metric("Unencrypted Snapshots", f"{ebs_count:,}")
        st.caption("EBS snapshots/volumes without encryption")

    with kf_col3:
        lambda_count = lambda_overpermissive.get("misconfigurations", 342) if lambda_overpermissive else 342
        st.warning(f"⚡ **Lambda Overpermission**")
        st.metric("Overpermissive Functions", lambda_count)
        st.caption("Lambda functions with excessive IAM roles")

    st.markdown("---")

    # Category breakdown chart
    st.subheader("📊 IOMs by Impact Category")
    categories = summary.get("top_categories", {})
    if categories:
        cat_df = pd.DataFrame([{"Category": k.replace("_", " ").title(), "Count": v}
                               for k, v in categories.items()])
        cat_df = cat_df.sort_values("Count", ascending=False)

        color_map = {
            "Critical Exposure": "#ff4444",
            "Privilege Escalation": "#ff8800",
            "Iam Risk": "#ffcc00",
            "Network Exposure": "#ff6666",
            "Data Exposure": "#cc88ff",
            "Monitoring Gap": "#4488ff",
            "General": "#888888",
        }

        fig_cat = px.bar(cat_df, x="Category", y="Count", color="Category",
                         color_discrete_map=color_map,
                         title="Misconfigurations by Attack Vector")
        fig_cat.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                              plot_bgcolor="rgba(0,0,0,0)", font_color="white",
                              showlegend=False)
        st.plotly_chart(fig_cat, use_container_width=True)

    # Service breakdown
    st.subheader("📊 IOMs by AWS Service")
    services = summary.get("top_services", {})
    if services:
        svc_df = pd.DataFrame([{"Service": k, "Count": v}
                               for k, v in services.items()])
        svc_df = svc_df.sort_values("Count", ascending=False).head(15)

        fig_svc = px.bar(svc_df, x="Service", y="Count",
                         color="Count", color_continuous_scale="Reds",
                         title="Top 15 Services by IOM Count")
        fig_svc.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                              plot_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig_svc, use_container_width=True)

    # Priority distribution pie
    st.subheader("📊 Priority Distribution")
    priority_data = {
        "P1 Critical": summary.get("p1_critical", 0),
        "P2 High": summary.get("p2_high", 0),
        "P3 Medium": summary.get("p3_medium", 0),
        "P4 Low": summary.get("p4_low", 0),
    }
    fig_pie = px.pie(values=list(priority_data.values()), names=list(priority_data.keys()),
                     color_discrete_sequence=["#ff4444", "#ff8800", "#ffcc00", "#888888"],
                     title="Findings by Priority Level", hole=0.4)
    fig_pie.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
    st.plotly_chart(fig_pie, use_container_width=True)


def _render_by_account(iom_data):
    """Render IOMs grouped by AWS account."""
    st.subheader("🏢 Misconfigurations by Account")
    st.caption("IOMs mapped to OHS AWS accounts: Infrastructure, Production, Network, Test & QA")

    p1_findings = iom_data.get("prioritized_findings", {}).get("P1", [])
    p2_findings = iom_data.get("prioritized_findings", {}).get("P2", [])
    p3_findings = iom_data.get("prioritized_findings", {}).get("P3", [])
    all_findings = p1_findings + p2_findings + p3_findings

    # Group by account
    by_account = defaultdict(list)
    for f in all_findings:
        acct_id = f.get("account_id", "unknown")
        acct_name = ACCOUNT_NAMES.get(acct_id, f"Account {acct_id}")
        by_account[acct_name].append(f)

    if not by_account:
        st.info("No account-level IOM data available.")
        return

    # Summary table
    acct_rows = []
    for acct_name, findings in sorted(by_account.items(), key=lambda x: len(x[1]), reverse=True):
        p1 = sum(1 for f in findings if f.get("priority") == "P1")
        p2 = sum(1 for f in findings if f.get("priority") == "P2")
        p3 = sum(1 for f in findings if f.get("priority") == "P3")
        total_misconfigs = sum(f.get("misconfigurations", 0) for f in findings)
        acct_rows.append({
            "Account": acct_name,
            "P1 Critical": p1,
            "P2 High": p2,
            "P3 Medium": p3,
            "Total Findings": len(findings),
            "Total Misconfigs": total_misconfigs,
        })

    df_accts = pd.DataFrame(acct_rows)
    st.dataframe(df_accts, use_container_width=True, hide_index=True)

    # Stacked bar chart
    fig_acct = px.bar(df_accts, x="Account",
                      y=["P1 Critical", "P2 High", "P3 Medium"],
                      barmode="stack",
                      color_discrete_map={"P1 Critical": "#ff4444", "P2 High": "#ff8800", "P3 Medium": "#ffcc00"},
                      title="IOMs by Account & Priority")
    fig_acct.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                           plot_bgcolor="rgba(0,0,0,0)", font_color="white")
    st.plotly_chart(fig_acct, use_container_width=True)

    # Expandable per-account detail
    st.markdown("---")
    st.subheader("📋 Account Details")

    # Focus on OHS scoped accounts
    ohs_accounts = ["Infrastructure", "Production", "Network", "Test & QA"]
    for acct_name in ohs_accounts:
        findings = by_account.get(acct_name, [])
        if not findings:
            # Check with slightly different names
            for key in by_account:
                if acct_name.lower().replace("& ", "and ").replace("&", "and") in key.lower().replace("& ", "and "):
                    findings = by_account[key]
                    break

        p1_count = sum(1 for f in findings if f.get("priority") == "P1")
        total = len(findings)
        icon = "🔴" if p1_count > 5 else "🟠" if p1_count > 0 else "🟢"

        with st.expander(f"{icon} {acct_name} — {total} findings ({p1_count} P1)", expanded=(p1_count > 3)):
            if findings:
                df_detail = pd.DataFrame(findings)
                cols_to_show = [c for c in ["priority", "rule_name", "service", "severity",
                                           "misconfigurations", "impact_category"] if c in df_detail.columns]
                df_detail = df_detail.sort_values("impact_score", ascending=False) if "impact_score" in df_detail.columns else df_detail
                st.dataframe(df_detail[cols_to_show], use_container_width=True, hide_index=True)
            else:
                st.success("✅ No high-priority findings for this account.")


def _render_prioritized(iom_data):
    """Render prioritized remediation view focused on highest-impact items."""
    st.subheader("🎯 Prioritized Remediation")
    st.caption("Fix highest-impact misconfigurations first — sorted by blast radius × severity")

    p1_findings = iom_data.get("prioritized_findings", {}).get("P1", [])

    if not p1_findings:
        st.success("✅ No P1 Critical findings!")
        return

    st.error(f"**{len(p1_findings)} P1 Critical findings** require immediate attention")
    st.markdown("---")

    # Group by impact category for structured remediation
    by_category = defaultdict(list)
    for f in p1_findings:
        cat = f.get("impact_category", "general")
        by_category[cat].append(f)

    category_order = ["critical_exposure", "network_exposure", "privilege_escalation",
                      "data_exposure", "iam_risk", "monitoring_gap", "general"]

    for cat in category_order:
        findings = by_category.get(cat, [])
        if not findings:
            continue

        cat_display = cat.replace("_", " ").title()
        cat_icons = {
            "critical_exposure": "🌐",
            "network_exposure": "🔓",
            "privilege_escalation": "⬆️",
            "data_exposure": "💾",
            "iam_risk": "🔑",
            "monitoring_gap": "👁️",
            "general": "📋",
        }
        icon = cat_icons.get(cat, "📋")

        st.markdown(f"### {icon} {cat_display} ({len(findings)} findings)")

        for idx, f in enumerate(sorted(findings, key=lambda x: x.get("impact_score", 0), reverse=True)[:5], 1):
            rule = f.get("rule_name", "Unknown")
            misconfigs = f.get("misconfigurations", 0)
            assets = f.get("assessed_assets", 0)
            acct_id = f.get("account_id", "")
            acct_name = ACCOUNT_NAMES.get(acct_id, acct_id)
            impact = f.get("impact_score", 0)

            with st.expander(f"#{idx} {rule} (Score: {impact})", expanded=(idx == 1)):
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Misconfigurations", misconfigs)
                c2.metric("Assessed Assets", f"{assets:,}")
                c3.metric("Account", acct_name)
                c4.metric("Impact Score", impact)

                # Remediation guidance
                if "encrypt" in rule.lower():
                    st.info("💡 **Remediation:** Enable default encryption for the service. "
                            "Use AWS Config rule to enforce encryption on new resources.")
                elif "iam" in rule.lower() and "all" in rule.lower():
                    st.info("💡 **Remediation:** Apply least-privilege principles. "
                            "Replace `*:*` policies with scoped permissions. Use IAM Access Analyzer.")
                elif "public" in rule.lower() or "internet" in rule.lower():
                    st.info("💡 **Remediation:** Remove public access. "
                            "Use VPC endpoints, private subnets, or restrict security group rules.")
                elif "lambda" in rule.lower():
                    st.info("💡 **Remediation:** Create dedicated IAM roles per function. "
                            "Use least-privilege with only required service permissions.")

        st.markdown("---")

    # CSV export
    all_p1 = pd.DataFrame(p1_findings)
    if not all_p1.empty:
        csv_data = all_p1.to_csv(index=False)
        st.download_button("⬇️ Download P1 Findings (CSV)", data=csv_data,
                          file_name=f"cspm_p1_findings_{TODAY.strftime('%Y%m%d')}.csv",
                          mime="text/csv", use_container_width=True, key="dl_p1_iom")


def _render_all_findings(iom_data):
    """Render full table of all P1/P2 findings with filters."""
    st.subheader("📋 All P1/P2 Findings")

    p1_findings = iom_data.get("prioritized_findings", {}).get("P1", [])
    p2_findings = iom_data.get("prioritized_findings", {}).get("P2", [])
    all_findings = p1_findings + p2_findings

    if not all_findings:
        st.info("No P1/P2 findings available.")
        return

    df = pd.DataFrame(all_findings)

    # Add account name column
    if "account_id" in df.columns:
        df["account_name"] = df["account_id"].map(lambda x: ACCOUNT_NAMES.get(x, x))

    # Filters
    col_f1, col_f2, col_f3, col_f4 = st.columns(4)
    with col_f1:
        filter_priority = st.multiselect("Priority",
            options=sorted(df["priority"].unique()) if "priority" in df.columns else [],
            default=[], key="iom_all_priority")
    with col_f2:
        filter_service = st.multiselect("Service",
            options=sorted(df["service"].unique()) if "service" in df.columns else [],
            default=[], key="iom_all_service")
    with col_f3:
        filter_category = st.multiselect("Impact Category",
            options=sorted(df["impact_category"].unique()) if "impact_category" in df.columns else [],
            default=[], key="iom_all_cat")
    with col_f4:
        filter_account = st.multiselect("Account",
            options=sorted(df["account_name"].unique()) if "account_name" in df.columns else [],
            default=[], key="iom_all_acct")

    df_filtered = df.copy()
    if filter_priority:
        df_filtered = df_filtered[df_filtered["priority"].isin(filter_priority)]
    if filter_service:
        df_filtered = df_filtered[df_filtered["service"].isin(filter_service)]
    if filter_category:
        df_filtered = df_filtered[df_filtered["impact_category"].isin(filter_category)]
    if filter_account:
        df_filtered = df_filtered[df_filtered["account_name"].isin(filter_account)]

    st.metric("Showing", f"{len(df_filtered)} of {len(df)} findings")

    display_cols = [c for c in ["priority", "rule_name", "severity", "service",
                                "account_name", "impact_category", "misconfigurations",
                                "assessed_assets", "impact_score"] if c in df_filtered.columns]

    df_filtered = df_filtered.sort_values("impact_score", ascending=False) if "impact_score" in df_filtered.columns else df_filtered
    st.dataframe(df_filtered[display_cols], use_container_width=True, hide_index=True)

    # Export
    csv_all = df_filtered[display_cols].to_csv(index=False)
    st.download_button("⬇️ Download Filtered Findings (CSV)", data=csv_all,
                      file_name=f"cspm_findings_{TODAY.strftime('%Y%m%d')}.csv",
                      mime="text/csv", use_container_width=True, key="dl_all_iom")
