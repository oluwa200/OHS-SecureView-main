"""Endpoint Protection sub-dashboard (CrowdStrike) — V2 full port from V1.
Ported from V1: cs_cspm.py, cs_iac.py, cs_assets.py, cs_eks.py
"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from collections import defaultdict

from config.dashboard_config import (
    SCOPED_ACCOUNTS, ACTUAL_EC2_COUNTS, ASSETS_DIR, DATA_DIR, TODAY,
    load_json, fetch_aws_ec2_all_accounts, show_freshness_warning, relative_time_from_iso,
)


def render(go_home):
    """Render the Endpoint Protection dashboard."""
    if st.button("← Back to Home", key="back_endpoint"):
        go_home()
        st.rerun()

    # Stale data warning
    show_freshness_warning("crowdstrike_hosts.json", "CrowdStrike Hosts")

    cs_logo = os.path.join(ASSETS_DIR, "crowdstrike_1610034789874.webp")
    if os.path.exists(cs_logo):
        st.image(cs_logo, width=150)

    st.title("Endpoint Protection")
    st.caption(f"CrowdStrike Falcon — CSPM, IaC, Coverage, EKS | {TODAY.strftime('%B %Y')}")

    tab1, tab2, tab3, tab4 = st.tabs([
        "🔒 CSPM Misconfigurations",
        "🏗️ IaC Scan Report",
        "🎯 Assets Coverage",
        "☸️ EKS Coverage",
    ])

    with tab1:
        _render_cspm()
    with tab2:
        _render_iac()
    with tab3:
        _render_coverage()
    with tab4:
        _render_eks()


# ─── Helper: Load CSPM with CSV fallback ──────────────────────────────────────
def _load_cspm_report():
    """Load CrowdStrike CSPM report from API JSON or CSV export fallback."""
    cspm_data = load_json("crowdstrike_cspm_report.json", {})
    if cspm_data and cspm_data.get("accounts"):
        total = sum(
            len(a.get("high_ioms", [])) + len(a.get("critical_ioms", []))
            for a in cspm_data.get("accounts", {}).values()
        )
        if total > 0:
            return cspm_data

    # CSV fallback
    csv_path = os.path.join(DATA_DIR, "crowdstrike_ioms_export.csv")
    if os.path.exists(csv_path):
        try:
            df = pd.read_csv(csv_path)
            return _csv_to_cspm_report(df)
        except Exception:
            pass
    return {}


def _csv_to_cspm_report(df):
    """Convert CrowdStrike CSV export to API report format."""
    col_map = {}
    for col in df.columns:
        cl = col.lower().strip()
        if "severity" in cl:
            col_map["severity"] = col
        elif "rule" in cl and "name" in cl:
            col_map["rule_name"] = col
        elif "policy" in cl and "statement" in cl:
            col_map["rule_name"] = col
        elif "service" in cl:
            col_map["service"] = col
        elif "account" in cl and "id" in cl:
            col_map["account_id"] = col
        elif "resource" in cl and "id" in cl:
            col_map["resource_id"] = col
        elif "resource" in cl and "type" in cl:
            col_map["resource_type"] = col
        elif "region" in cl:
            col_map["region"] = col
        elif "remediation" in cl or "recommendation" in cl:
            col_map["recommendation"] = col
        elif "description" in cl or "detail" in cl:
            col_map["description"] = col
        elif "status" in cl:
            col_map["status"] = col

    acct_names = {
        "446329232350": "Infrastructure",
        "937786629491": "Production",
        "895945783203": "Network",
        "754120856488": "Test and QA",
    }

    report = {"updated_at": "CSV Import", "accounts": {}, "summary": {}}
    for acct_name in acct_names.values():
        report["accounts"][acct_name] = {
            "account_id": "", "high_ioms": [], "critical_ioms": [],
            "summary": {"high": 0, "critical": 0, "total": 0},
        }

    for _, row in df.iterrows():
        severity = str(row.get(col_map.get("severity", ""), "MEDIUM")).upper().strip()
        if severity not in ("HIGH", "CRITICAL"):
            continue
        acct_id_val = str(row.get(col_map.get("account_id", ""), ""))
        acct_name = "Infrastructure"
        for aid, aname in acct_names.items():
            if aid in acct_id_val:
                acct_name = aname
                break
        iom = {
            "id": str(row.get("ID", row.get("id", "N/A"))),
            "rule_name": str(row.get(col_map.get("rule_name", ""), "N/A")),
            "severity": severity,
            "service": str(row.get(col_map.get("service", ""), "N/A")),
            "resource_type": str(row.get(col_map.get("resource_type", ""), "N/A")),
            "resource_id": str(row.get(col_map.get("resource_id", ""), "N/A")),
            "region": str(row.get(col_map.get("region", ""), "N/A")),
            "description": str(row.get(col_map.get("description", ""), "N/A")),
            "recommendation": str(row.get(col_map.get("recommendation", ""), "N/A")),
            "status": str(row.get(col_map.get("status", ""), "open")),
            "account_name": acct_name,
        }
        if severity == "HIGH":
            report["accounts"][acct_name]["high_ioms"].append(iom)
        else:
            report["accounts"][acct_name]["critical_ioms"].append(iom)

    total_high = sum(len(a["high_ioms"]) for a in report["accounts"].values())
    total_critical = sum(len(a["critical_ioms"]) for a in report["accounts"].values())
    for acct_name, acct_data in report["accounts"].items():
        h, c = len(acct_data["high_ioms"]), len(acct_data["critical_ioms"])
        acct_data["summary"] = {"high": h, "critical": c, "total": h + c}
    report["summary"] = {
        "total_high": total_high, "total_critical": total_critical,
        "total_ioms": total_high + total_critical, "accounts_scanned": 4, "source": "CSV Export",
    }
    return report


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 1: CSPM Misconfigurations (enhanced with IOM impact analysis)
# ═══════════════════════════════════════════════════════════════════════════════
def _render_cspm():
    st.subheader("🔍 CrowdStrike CSPM — Cloud Misconfigurations")
    st.caption(f"Indicators of Misconfiguration (IOMs) | {TODAY.strftime('%B %Y')}")

    # Check if we have the enhanced IOM analysis
    iom_analysis = load_json("crowdstrike_iom_analysis.json", {})
    if iom_analysis and iom_analysis.get("summary"):
        from dashboards.endpoint.cspm import render_cspm
        render_cspm()
        return

    # Fallback to basic CSPM report view
    cspm_report = _load_cspm_report()

    if not cspm_report or not cspm_report.get("accounts"):
        st.warning("No CSPM data available. Run `python refresh_crowdstrike_cspm.py --once`.")
        return

    # Flatten all IOMs
    all_ioms = []
    accounts_data = cspm_report.get("accounts", {})
    for acct_name, acct_data in accounts_data.items():
        for iom in acct_data.get("high_ioms", []):
            iom["account_name"] = acct_name
            all_ioms.append(iom)
        for iom in acct_data.get("critical_ioms", []):
            iom["account_name"] = acct_name
            all_ioms.append(iom)
        for iom in acct_data.get("medium_ioms", []):
            iom["account_name"] = acct_name
            all_ioms.append(iom)

    # Resource details lookup
    resource_details = cspm_report.get("resource_details", [])
    rule_resources = {}
    for rd in resource_details:
        rid = rd.get("rule_id", "")
        if rid not in rule_resources:
            rule_resources[rid] = []
        rule_resources[rid].append({
            "resource_type": rd.get("resource_type", "N/A"),
            "resource_id": rd.get("resource_hash", "N/A"),
            "region": rd.get("region", "N/A"),
            "account_id": rd.get("account_id", "N/A"),
        })

    summary = cspm_report.get("summary", {})

    # KPI Metrics
    st.markdown("---")
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("🔴 Critical IOMs", summary.get("total_critical", 0))
    col2.metric("🟠 High IOMs", summary.get("total_high", 0))
    col3.metric("🟡 Medium IOMs", summary.get("total_medium", 0))
    col4.metric("📊 Total IOMs", summary.get("total_ioms", 0))
    col5.metric("☁️ Accounts Scanned", summary.get("accounts_scanned", 0))
    st.markdown("---")

    # Tabs within CSPM
    cspm_tab1, cspm_tab2, cspm_tab3 = st.tabs([
        "📋 All High-Risk IOMs", "📊 By Account", "🔧 Prioritized Remediation"])

    with cspm_tab1:
        if all_ioms:
            df_ioms = pd.DataFrame(all_ioms)
            display_cols = ["account_name", "severity", "rule_name", "service",
                            "resource_type", "resource_id", "region", "status"]
            available_cols = [c for c in display_cols if c in df_ioms.columns]

            # Filters
            col_f1, col_f2, col_f3 = st.columns(3)
            with col_f1:
                filter_sev = st.multiselect("Severity",
                    options=sorted(df_ioms["severity"].unique()) if "severity" in df_ioms.columns else [],
                    default=[], key="cspm_sev_filter")
            with col_f2:
                filter_service = st.multiselect("Service",
                    options=sorted(df_ioms["service"].unique()) if "service" in df_ioms.columns else [],
                    default=[], key="cspm_svc_filter")
            with col_f3:
                filter_acct = st.multiselect("Account",
                    options=sorted(df_ioms["account_name"].unique()) if "account_name" in df_ioms.columns else [],
                    default=[], key="cspm_acct_filter")

            df_display = df_ioms.copy()
            if filter_sev:
                df_display = df_display[df_display["severity"].isin(filter_sev)]
            if filter_service:
                df_display = df_display[df_display["service"].isin(filter_service)]
            if filter_acct:
                df_display = df_display[df_display["account_name"].isin(filter_acct)]

            st.metric("Showing", f"{len(df_display):,} IOMs")
            st.dataframe(df_display[available_cols].reset_index(drop=True),
                         use_container_width=True, hide_index=True)
        else:
            st.success("🎉 No high or critical IOMs detected!")

    with cspm_tab2:
        if all_ioms:
            df_ioms = pd.DataFrame(all_ioms)
            # Bar chart by account
            acct_counts = df_ioms.groupby(["account_name", "severity"]).size().reset_index(name="Count")
            fig_acct = px.bar(acct_counts, x="account_name", y="Count", color="severity",
                color_discrete_map={"HIGH": "#ff8800", "CRITICAL": "#ff4444", "MEDIUM": "#ffcc00"},
                barmode="stack", title="IOMs by Account & Severity")
            fig_acct.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig_acct, use_container_width=True)

            # By service chart
            if "service" in df_ioms.columns:
                svc_counts = df_ioms.groupby(["service", "severity"]).size().reset_index(name="Count")
                svc_counts = svc_counts.sort_values("Count", ascending=False)
                fig_svc = px.bar(svc_counts, x="service", y="Count", color="severity",
                    color_discrete_map={"HIGH": "#ff8800", "CRITICAL": "#ff4444", "MEDIUM": "#ffcc00"},
                    barmode="stack", title="IOMs by AWS Service")
                fig_svc.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)", font_color="white")
                st.plotly_chart(fig_svc, use_container_width=True)

            # Per-account summary table
            acct_summary = []
            for acct_name, acct_data in accounts_data.items():
                s = acct_data.get("summary", {})
                acct_summary.append({"Account": acct_name, "High": s.get("high", 0),
                    "Critical": s.get("critical", 0), "Total": s.get("total", 0)})
            st.dataframe(pd.DataFrame(acct_summary), use_container_width=True, hide_index=True)
        else:
            st.info("No IOM data to display.")

    with cspm_tab3:
        st.subheader("🔧 Prioritized Remediation Plan")
        st.caption("IOMs grouped by rule — fix the rule once to resolve all affected resources")

        if all_ioms:
            rule_groups = defaultdict(list)
            for iom in all_ioms:
                rule_groups[iom.get("rule_name", "Unknown Rule")].append(iom)
            sorted_rules = sorted(rule_groups.items(), key=lambda x: len(x[1]), reverse=True)
            st.metric("Unique Rules to Remediate", len(sorted_rules))
            st.markdown("---")

            for idx, (rule_name, ioms) in enumerate(sorted_rules[:20], 1):
                severity = ioms[0].get("severity", "HIGH")
                sev_emoji = "🟣" if severity == "CRITICAL" else "🔴"
                service = ioms[0].get("service", "N/A")
                recommendation = ioms[0].get("recommendation", "No recommendation available.")
                affected_accounts = list(set(iom.get("account_name", "N/A") for iom in ioms))

                with st.expander(
                    f"{sev_emoji} #{idx} — {rule_name} ({len(ioms)} resources | {service})",
                    expanded=(idx <= 3)):
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Affected Resources", len(ioms))
                    c2.metric("Severity", severity)
                    c3.metric("Service", service)
                    st.markdown("**Accounts Affected:** " + ", ".join(affected_accounts))
                    st.markdown("**CrowdStrike Recommendation:**")
                    st.info(recommendation)

                    # Show resource details
                    rule_id = ioms[0].get("rule_id", "")
                    resources_for_rule = rule_resources.get(rule_id, [])
                    if not resources_for_rule:
                        resources_for_rule = [
                            {"resource_type": i.get("resource_type", "N/A"),
                             "resource_id": i.get("resource_id", "N/A"),
                             "region": i.get("region", "N/A"),
                             "account_id": i.get("account_name", "N/A")}
                            for i in ioms[:20]
                        ]
                    if resources_for_rule:
                        st.markdown("**Affected Resources:**")
                        st.dataframe(pd.DataFrame(resources_for_rule), use_container_width=True, hide_index=True)

            st.markdown("---")
            # CSV download
            remediation_rows = []
            for idx, (rule_name, ioms) in enumerate(sorted_rules, 1):
                for iom in ioms:
                    remediation_rows.append({
                        "Priority": idx, "Rule Name": rule_name,
                        "Severity": iom.get("severity", "N/A"),
                        "Service": iom.get("service", "N/A"),
                        "Resource ID": iom.get("resource_id", "N/A"),
                        "Account": iom.get("account_name", "N/A"),
                        "Recommendation": iom.get("recommendation", "N/A"),
                    })
            csv_rem = pd.DataFrame(remediation_rows).to_csv(index=False)
            st.download_button("⬇️ Download Remediation Plan (CSV)", data=csv_rem,
                file_name=f"cspm_remediation_{TODAY.strftime('%Y%m%d')}.csv",
                mime="text/csv", use_container_width=True, key="dl_cspm_rem")
        else:
            st.success("🎉 No IOMs require remediation!")


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 2: IaC Scan Report (full port from V1 cs_iac.py)
# ═══════════════════════════════════════════════════════════════════════════════
def _render_iac():
    st.subheader("🏗️ CrowdStrike IaC Scan Report")
    st.caption(f"Infrastructure as Code misconfigurations (Terraform, CloudFormation, K8s) | {TODAY.strftime('%B %Y')}")

    iac_data = load_json("crowdstrike_iac_report.json", {})
    if not iac_data:
        st.warning("No IaC scan data available. Run CrowdStrike refresh to pull data.")
        return

    detections = iac_data.get("detections", [])
    summary = iac_data.get("summary", {})
    updated_at = iac_data.get("updated_at", "N/A")
    st.caption(f"Last refreshed: {updated_at}")

    if not detections:
        st.info("No IaC detections found.")
        return

    # KPI Metrics
    st.markdown("---")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🔴 Critical", summary.get("critical", 0))
    col2.metric("🟠 High", summary.get("high", 0))
    col3.metric("🟡 Medium", summary.get("medium", 0))
    col4.metric("📊 Total Detections", summary.get("total", len(detections)))
    st.markdown("---")

    df = pd.DataFrame(detections)

    # Calculate risk score
    internet_services = ["s3", "elb", "cloudfront", "api gateway", "route53", "waf", "ec2", "ecs", "lambda"]

    def calc_iac_risk(row):
        sev = row.get("severity", "MEDIUM")
        sev_weight = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4}.get(sev, 4)
        service = str(row.get("service", "")).lower()
        exposure = 2.0 if any(s in service for s in internet_services) else 1.0
        return round(sev_weight * exposure, 1)

    df["Risk Score"] = df.apply(calc_iac_risk, axis=1)
    df["Exposure"] = df["service"].apply(
        lambda s: "Internet-Facing" if any(x in str(s).lower() for x in internet_services) else "Internal"
    )
    df = df.sort_values("Risk Score", ascending=False).reset_index(drop=True)

    # Top 15 bar chart
    st.subheader("⚠️ Prioritized Fixes (by Exposure & Risk)")
    top15 = df.head(15)
    if "rule_name" in top15.columns:
        fig_top = px.bar(top15, x="Risk Score", y="rule_name", orientation="h",
            color="severity", color_discrete_map={"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00"},
            title="Top 15 IaC Findings by Risk Score",
            hover_data=["service", "Exposure"])
        fig_top.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)", font_color="white",
            yaxis=dict(autorange="reversed"), height=500)
        st.plotly_chart(fig_top, use_container_width=True)

    st.markdown("---")

    # Grouped by Rule (Remediation Plan)
    st.subheader("🔧 Remediation Plan (Grouped by Rule)")
    st.caption("Fix the rule once → resolves all affected resources")

    rule_groups = defaultdict(list)
    for det in detections:
        rule_groups[det.get("rule_name", "Unknown")].append(det)
    sorted_rules = sorted(rule_groups.items(), key=lambda x: len(x[1]), reverse=True)
    st.metric("Unique Rules to Fix", len(sorted_rules))

    for idx, (rule_name, dets) in enumerate(sorted_rules[:20], 1):
        severity = dets[0].get("severity", "HIGH")
        sev_emoji = "🔴" if severity == "CRITICAL" else "🟠"
        service = dets[0].get("service", "N/A")
        remediation = dets[0].get("remediation", "No remediation available")
        files = list(set(d.get("file_name", "N/A") for d in dets))

        with st.expander(f"{sev_emoji} #{idx} — {rule_name} ({len(dets)} occurrences | {service})",
                         expanded=(idx <= 3)):
            c1, c2, c3 = st.columns(3)
            c1.metric("Occurrences", len(dets))
            c2.metric("Severity", severity)
            c3.metric("Service", service)
            st.markdown("**Affected Files:**")
            for f in files[:10]:
                st.markdown(f"- `{f}`")
            st.markdown("**Remediation:**")
            st.info(remediation)

    st.markdown("---")

    # By Service
    st.subheader("📊 Detections by Service")
    if "service" in df.columns:
        svc_counts = df.groupby(["service", "severity"]).size().reset_index(name="Count")
        svc_counts = svc_counts.sort_values("Count", ascending=False)
        fig_svc = px.bar(svc_counts, x="service", y="Count", color="severity",
            color_discrete_map={"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00"},
            barmode="stack", title="IaC Findings by AWS Service")
        fig_svc.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig_svc, use_container_width=True)

    # Internet-Facing vs Internal
    st.subheader("🌐 Internet-Facing vs Internal")
    exp_counts = df["Exposure"].value_counts().reset_index()
    exp_counts.columns = ["Exposure", "Count"]
    fig_exp = px.pie(exp_counts, values="Count", names="Exposure",
        color="Exposure", color_discrete_map={"Internet-Facing": "#ff4444", "Internal": "#4488ff"},
        title="IaC Findings by Exposure", hole=0.4)
    fig_exp.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", font_color="white")
    st.plotly_chart(fig_exp, use_container_width=True)

    st.markdown("---")

    # Full Table with Filters
    st.subheader("📋 All IaC Detections")
    col_f1, col_f2, col_f3 = st.columns([2, 2, 1])
    with col_f1:
        available_sevs = sorted(df["severity"].unique().tolist()) if "severity" in df.columns else []
        sev_filter = st.multiselect("Severity", available_sevs, default=available_sevs, key="iac_sev")
    with col_f2:
        available_exp = sorted(df["Exposure"].unique().tolist())
        exp_filter = st.multiselect("Exposure", available_exp, default=available_exp, key="iac_exp")
    with col_f3:
        st.markdown("")
        st.markdown("")
        if st.button("Reset Filters", key="iac_reset"):
            st.rerun()

    filtered = df[(df["severity"].isin(sev_filter)) & (df["Exposure"].isin(exp_filter))]
    st.metric("Showing", f"{len(filtered)} / {len(df)} detections")
    disp_cols = ["severity", "rule_name", "service", "file_name", "resource_name", "Exposure", "Risk Score", "remediation"]
    available = [c for c in disp_cols if c in filtered.columns]
    st.dataframe(filtered[available], use_container_width=True, hide_index=True)

    # CSV Export
    st.markdown("---")
    csv_iac = df.to_csv(index=False)
    st.download_button("⬇️ Download IaC Report (CSV)", data=csv_iac,
        file_name=f"iac_scan_report_{TODAY.strftime('%Y%m%d')}.csv",
        mime="text/csv", use_container_width=True, key="dl_iac")


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 3: Assets Coverage (full port from V1 cs_assets.py)
# ═══════════════════════════════════════════════════════════════════════════════
def _render_coverage():
    st.subheader("🦅 Falcon Sensor — Assets Coverage")
    st.caption(f"Managed vs Unmanaged EC2 instances across all accounts | {TODAY.strftime('%B %Y')}")

    cs_hosts = load_json("crowdstrike_hosts.json", {})
    aws_data = fetch_aws_ec2_all_accounts()

    if not cs_hosts or not cs_hosts.get("accounts"):
        st.warning("CrowdStrike host data not available. Run CrowdStrike refresh.")
        return

    updated_at = cs_hosts.get("updated_at", "N/A")
    st.caption(f"Last refreshed: {updated_at}")

    hosts_accounts = cs_hosts.get("accounts", {})
    acct_key_map = {
        "Infrastructure": "Infrastructure (446329232350)",
        "Production": "Production (937786629491)",
        "Network": "Network (895945783203)",
        "Test and QA": "Test and QA (754120856488)",
    }

    # Build Coverage Data
    coverage_rows = []
    all_managed = []
    all_unmanaged = []
    all_cs_hosts_list = []

    for acct_name, hosts_list in hosts_accounts.items():
        cs_ips = set()
        for host in hosts_list:
            lip = host.get("local_ip", "")
            if lip and lip != "N/A":
                cs_ips.add(lip)
            all_cs_hosts_list.append({**host, "account": acct_name})

        aws_ips = set()
        aws_ip_to_inst = {}
        if aws_data:
            for aws_acct_name, instances in aws_data.items():
                if acct_name.lower() in aws_acct_name.lower():
                    for inst in instances:
                        ip = inst.get("PrivateIp", inst.get("private_ip", ""))
                        if ip and ip != "null":
                            aws_ips.add(ip)
                            aws_ip_to_inst[ip] = inst

        managed = aws_ips & cs_ips
        unmanaged = aws_ips - cs_ips
        cs_only = cs_ips - aws_ips
        coverage_pct = (len(managed) / len(aws_ips) * 100) if aws_ips else 0

        coverage_rows.append({
            "Account": acct_name, "AWS EC2": len(aws_ips),
            "Falcon Managed": len(managed), "Unmanaged (No Sensor)": len(unmanaged),
            "Stale (CS Only)": len(cs_only), "Coverage %": round(coverage_pct, 1),
        })
        for ip in managed:
            all_managed.append({"IP": ip, "Account": acct_name, "Status": "✅ Managed"})
        for ip in unmanaged:
            inst = aws_ip_to_inst.get(ip, {})
            all_unmanaged.append({
                "IP": ip, "Account": acct_name,
                "Instance ID": inst.get("InstanceId", inst.get("instance_id", "N/A")),
                "State": inst.get("State", inst.get("state", "N/A")),
                "Type": inst.get("InstanceType", inst.get("instance_type", "N/A")),
                "Status": "❌ Unmanaged",
            })

    # Overall KPIs
    st.markdown("---")
    st.subheader("📊 Overall Falcon Sensor Coverage")
    total_aws = sum(r["AWS EC2"] for r in coverage_rows)
    total_managed = sum(r["Falcon Managed"] for r in coverage_rows)
    total_unmanaged_count = sum(r["Unmanaged (No Sensor)"] for r in coverage_rows)
    total_stale = sum(r["Stale (CS Only)"] for r in coverage_rows)
    total_cs = sum(len(h) for h in hosts_accounts.values())
    overall_coverage = (total_managed / total_aws * 100) if total_aws > 0 else 0

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("AWS EC2 (Actual)", total_aws)
    col2.metric("CrowdStrike Hosts", total_cs)
    col3.metric("✅ Managed", total_managed)
    col4.metric("❌ Unmanaged", total_unmanaged_count)
    col5.metric("Coverage", f"{overall_coverage:.1f}%")

    # Coverage gauge
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=overall_coverage,
        title={"text": "Falcon Sensor Coverage"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "#44bb44" if overall_coverage > 90 else "#ff8800" if overall_coverage > 70 else "#ff4444"},
            "steps": [
                {"range": [0, 70], "color": "#3d1111"},
                {"range": [70, 90], "color": "#3d3d11"},
                {"range": [90, 100], "color": "#113d11"},
            ],
            "threshold": {"line": {"color": "white", "width": 2}, "thickness": 0.75, "value": 95},
        },
    ))
    fig_gauge.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=300)
    st.plotly_chart(fig_gauge, use_container_width=True)

    st.markdown("---")

    # Per-Account Breakdown
    st.subheader("📋 Per-Account Coverage")
    coverage_df = pd.DataFrame(coverage_rows)
    st.dataframe(coverage_df, use_container_width=True, hide_index=True)

    fig_bar = px.bar(coverage_df, x="Account",
        y=["Falcon Managed", "Unmanaged (No Sensor)", "Stale (CS Only)"],
        barmode="stack", title="Falcon Sensor Status by Account",
        color_discrete_map={"Falcon Managed": "#44bb44", "Unmanaged (No Sensor)": "#ff4444", "Stale (CS Only)": "#ff8800"})
    fig_bar.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)", font_color="white")
    st.plotly_chart(fig_bar, use_container_width=True)

    st.markdown("---")

    # Unmanaged Hosts (Deploy Sensor)
    st.subheader("❌ Unmanaged EC2 Instances — Deploy Falcon Sensor")
    if all_unmanaged:
        st.error(f"**{len(all_unmanaged)} EC2 instances do NOT have the Falcon sensor installed.**")
        unmanaged_df = pd.DataFrame(all_unmanaged)
        st.dataframe(unmanaged_df, use_container_width=True, hide_index=True)
        csv_unmanaged = unmanaged_df.to_csv(index=False)
        st.download_button("⬇️ Download Unmanaged Hosts (CSV)", data=csv_unmanaged,
            file_name=f"unmanaged_hosts_{TODAY.strftime('%Y%m%d')}.csv",
            mime="text/csv", use_container_width=True, key="dl_unmanaged")
    else:
        st.success("✅ All AWS EC2 instances have the Falcon sensor deployed!")

    st.markdown("---")

    # Stale CrowdStrike Hosts
    st.subheader("🗑️ Stale CrowdStrike Hosts — Not in AWS")
    st.caption("Hosts with Falcon sensor that no longer exist in AWS (decommissioned)")

    stale_hosts = []
    for acct_name, hosts_list in hosts_accounts.items():
        cs_ips_set = {h.get("local_ip", "") for h in hosts_list if h.get("local_ip") and h.get("local_ip") != "N/A"}
        aws_ips_set = set()
        if aws_data:
            for aws_acct_name, instances in aws_data.items():
                if acct_name.lower() in aws_acct_name.lower():
                    for inst in instances:
                        ip = inst.get("PrivateIp", inst.get("private_ip", ""))
                        if ip and ip != "null":
                            aws_ips_set.add(ip)
        stale_ips = cs_ips_set - aws_ips_set
        for host in hosts_list:
            if host.get("local_ip") in stale_ips:
                stale_hosts.append({
                    "Account": acct_name, "Hostname": host.get("hostname", "N/A"),
                    "IP": host.get("local_ip", "N/A"), "Platform": host.get("platform", "N/A"),
                    "Last Seen": host.get("last_seen", "N/A"),
                    "Agent Version": host.get("agent_version", "N/A"),
                    "Status": "🗑️ Remove from CrowdStrike",
                })

    if stale_hosts:
        st.warning(f"**{len(stale_hosts)} hosts in CrowdStrike no longer exist in AWS.** Remove them to keep inventory clean.")
        stale_df = pd.DataFrame(stale_hosts)
        st.dataframe(stale_df, use_container_width=True, hide_index=True)
        csv_stale = stale_df.to_csv(index=False)
        st.download_button("⬇️ Download Stale Hosts (CSV)", data=csv_stale,
            file_name=f"stale_cs_hosts_{TODAY.strftime('%Y%m%d')}.csv",
            mime="text/csv", use_container_width=True, key="dl_stale_cs")
    else:
        st.success("✅ No stale hosts — CrowdStrike inventory is aligned with AWS.")

    st.markdown("---")

    # Full CrowdStrike Host Inventory
    st.subheader("📋 Full CrowdStrike Host Inventory")
    if all_cs_hosts_list:
        cs_df = pd.DataFrame(all_cs_hosts_list)
        display_cols = ["account", "hostname", "local_ip", "platform", "status", "last_seen", "agent_version", "instance_id"]
        available = [c for c in display_cols if c in cs_df.columns]

        acct_filter = st.multiselect("Filter by Account", sorted(cs_df["account"].unique()),
                                     default=[], key="cs_inv_acct_filter")
        if acct_filter:
            cs_df = cs_df[cs_df["account"].isin(acct_filter)]

        st.metric("Showing", f"{len(cs_df)} hosts")
        st.dataframe(cs_df[available], use_container_width=True, hide_index=True)

        csv_all = cs_df[available].to_csv(index=False)
        st.download_button("⬇️ Download Full Inventory (CSV)", data=csv_all,
            file_name=f"crowdstrike_full_inventory_{TODAY.strftime('%Y%m%d')}.csv",
            mime="text/csv", use_container_width=True, key="dl_cs_full")


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 4: EKS Coverage (full port from V1 cs_eks.py)
# ═══════════════════════════════════════════════════════════════════════════════
def _render_eks():
    st.subheader("☸️ EKS / Kubernetes — Falcon Sensor Coverage")
    st.caption(f"Active EKS worker nodes vs CrowdStrike managed hosts | {TODAY.strftime('%B %d, %Y')}")

    eks_data = load_json("aws_eks_nodes.json", {})
    cs_hosts = load_json("crowdstrike_hosts.json", {})

    if not eks_data or not eks_data.get("accounts"):
        st.warning("AWS EKS node data not available. Run: `bash refresh_eks_nodes.sh`")
        st.info("This script queries AWS for running EKS worker nodes tagged with kubernetes.io/cluster/*")
        return

    eks_updated = eks_data.get("updated_at", "N/A")
    st.caption(f"AWS EKS data last refreshed: {eks_updated}")

    # Build AWS EKS IP lookup
    aws_eks_ips = {}
    aws_eks_by_account = {}
    for acct_name, instances in eks_data.get("accounts", {}).items():
        if not isinstance(instances, list):
            continue
        aws_eks_by_account[acct_name] = instances
        for inst in instances:
            ip = inst.get("PrivateIp", "")
            if ip:
                aws_eks_ips[ip] = {
                    "account": acct_name,
                    "instance_id": inst.get("InstanceId", "N/A"),
                    "instance_type": inst.get("InstanceType", "N/A"),
                    "state": inst.get("State", "N/A"),
                }

    # Build CrowdStrike IP lookup from all accounts
    cs_by_ip = {}
    cs_all_hosts = []
    for acct_hosts in cs_hosts.get("accounts", {}).values():
        for host in acct_hosts:
            lip = host.get("local_ip", "")
            if lip and lip != "N/A" and lip != "172.20.0.10":
                cs_by_ip[lip] = host
            cs_all_hosts.append(host)

    # Cross-reference
    covered_nodes = []
    uncovered_nodes = []
    stale_cs_nodes = []

    for ip, aws_info in aws_eks_ips.items():
        if ip in cs_by_ip:
            cs_host = cs_by_ip[ip]
            covered_nodes.append({
                "IP": ip, "Account": aws_info["account"],
                "Instance ID": aws_info["instance_id"],
                "Instance Type": aws_info["instance_type"],
                "CS Hostname": cs_host.get("hostname", "N/A"),
                "Agent Version": cs_host.get("agent_version", "N/A"),
                "Sensor Status": cs_host.get("status", "N/A"),
                "Last Seen (CS)": cs_host.get("last_seen", "N/A"),
                "Coverage": "Protected",
            })
        else:
            uncovered_nodes.append({
                "IP": ip, "Account": aws_info["account"],
                "Instance ID": aws_info["instance_id"],
                "Instance Type": aws_info["instance_type"],
                "Coverage": "NO SENSOR",
            })

    # Find stale CrowdStrike entries (Bottlerocket/EKS nodes not in active AWS)
    for host in cs_all_hosts:
        lip = host.get("local_ip", "")
        os_ver = host.get("os_version", "")
        if ("bottlerocket" in os_ver.lower() or "ip-10-129" in host.get("hostname", "")):
            if lip not in aws_eks_ips and lip != "172.20.0.10" and lip != "N/A" and lip:
                stale_cs_nodes.append({
                    "IP": lip, "CS Hostname": host.get("hostname", "N/A"),
                    "OS": os_ver, "Agent Version": host.get("agent_version", "N/A"),
                    "Last Seen": host.get("last_seen", "N/A"),
                    "Instance ID": host.get("instance_id", "N/A"),
                    "Status": "STALE - Not in AWS",
                })

    # KPIs
    st.markdown("---")
    st.subheader("EKS Coverage Summary (Active Nodes Only)")
    total_aws_eks = len(aws_eks_ips)
    total_covered = len(covered_nodes)
    total_uncovered = len(uncovered_nodes)
    total_stale_eks = len(stale_cs_nodes)
    coverage_pct = (total_covered / total_aws_eks * 100) if total_aws_eks > 0 else 0

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("AWS EKS Nodes (Active)", total_aws_eks)
    col2.metric("Falcon Protected", total_covered)
    col3.metric("No Sensor (Gap)", total_uncovered)
    col4.metric("Stale in CS", total_stale_eks)
    col5.metric("True Coverage", f"{coverage_pct:.1f}%")

    # Coverage gauge
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=coverage_pct,
        title={"text": "EKS Falcon Coverage (Active Nodes)", "font": {"size": 18}},
        delta={"reference": 100, "increasing": {"color": "#44bb44"}, "decreasing": {"color": "#ff4444"}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1},
            "bar": {"color": "#44bb44" if coverage_pct >= 95 else "#ff8800" if coverage_pct >= 80 else "#ff4444"},
            "steps": [
                {"range": [0, 70], "color": "#3d1111"},
                {"range": [70, 90], "color": "#3d3d11"},
                {"range": [90, 100], "color": "#113d11"},
            ],
            "threshold": {"line": {"color": "white", "width": 2}, "thickness": 0.75, "value": 100},
        },
    ))
    fig_gauge.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=300)
    st.plotly_chart(fig_gauge, use_container_width=True)

    st.markdown("---")

    # Per-Account Breakdown
    st.subheader("Coverage by Account")
    acct_rows = []
    for acct_name, instances in aws_eks_by_account.items():
        if not isinstance(instances, list):
            continue
        aws_count = len(instances)
        acct_ips = {i.get("PrivateIp") for i in instances if i.get("PrivateIp")}
        covered_count = sum(1 for ip in acct_ips if ip in cs_by_ip)
        gap = aws_count - covered_count
        pct = (covered_count / aws_count * 100) if aws_count > 0 else 0
        acct_rows.append({
            "Account": acct_name, "Active EKS Nodes": aws_count,
            "Falcon Protected": covered_count, "Gap (No Sensor)": gap,
            "Coverage %": round(pct, 1),
        })

    if acct_rows:
        acct_df = pd.DataFrame(acct_rows)
        st.dataframe(acct_df, use_container_width=True, hide_index=True)

        fig_bar = px.bar(acct_df, x="Account", y=["Falcon Protected", "Gap (No Sensor)"],
            barmode="stack", title="EKS Coverage by Account (Active Nodes Only)",
            color_discrete_map={"Falcon Protected": "#44bb44", "Gap (No Sensor)": "#ff4444"})
        fig_bar.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig_bar, use_container_width=True)

    st.markdown("---")

    # Uncovered Nodes
    st.subheader("❌ EKS Nodes WITHOUT Falcon Sensor")
    if uncovered_nodes:
        st.error(f"**{len(uncovered_nodes)} active EKS nodes** do NOT have the Falcon sensor.")
        uncov_df = pd.DataFrame(uncovered_nodes)
        st.dataframe(uncov_df, use_container_width=True, hide_index=True)
        st.markdown("""**Action Required:**
1. Deploy Falcon DaemonSet to these nodes
2. Verify node group has proper IAM role for sensor pull
3. Check if taints are preventing scheduling""")
        csv_uncov = uncov_df.to_csv(index=False)
        st.download_button("⬇️ Download Uncovered Nodes (CSV)", data=csv_uncov,
            file_name=f"eks_uncovered_nodes_{TODAY.strftime('%Y%m%d')}.csv",
            mime="text/csv", use_container_width=True, key="dl_eks_uncov")
    else:
        st.success("✅ All active EKS worker nodes have the Falcon sensor deployed!")

    st.markdown("---")

    # Protected Nodes
    st.subheader("✅ Protected EKS Nodes (Active in AWS + Falcon)")
    if covered_nodes:
        cov_df = pd.DataFrame(covered_nodes)
        st.dataframe(cov_df, use_container_width=True, hide_index=True)
    else:
        st.info("No cross-matched nodes found. Ensure refresh_eks_nodes.sh has been run.")

    st.markdown("---")

    # Stale CrowdStrike Entries
    st.subheader("🗑️ Stale CrowdStrike Entries (Terminated/Rotated Nodes)")
    st.caption("Hosts in CrowdStrike NOT active in AWS. Likely terminated by auto-scaling.")
    if stale_cs_nodes:
        st.warning(f"**{len(stale_cs_nodes)} stale entries** in CrowdStrike from terminated EKS nodes.")
        stale_df = pd.DataFrame(stale_cs_nodes)
        st.dataframe(stale_df, use_container_width=True, hide_index=True)
        st.markdown("""**Recommendation:** Remove these from CrowdStrike to keep inventory accurate.
These are Bottlerocket nodes replaced by auto-scaling group rotations.""")
        csv_stale_eks = stale_df.to_csv(index=False)
        st.download_button("⬇️ Download Stale Entries (CSV)", data=csv_stale_eks,
            file_name=f"eks_stale_cs_hosts_{TODAY.strftime('%Y%m%d')}.csv",
            mime="text/csv", use_container_width=True, key="dl_eks_stale")
    else:
        st.success("✅ No stale EKS entries in CrowdStrike.")

    st.markdown("---")

    # Summary Stats — EKS-specific reconciliation only
    st.subheader("📊 Data Reconciliation Summary (EKS Only)")
    # Count only CrowdStrike hosts that look like EKS nodes (Bottlerocket or ip-10-xxx hostnames)
    cs_eks_hosts = [h for h in cs_all_hosts if
        "bottlerocket" in (h.get("os_version", "") or "").lower() or
        (h.get("hostname", "") or "").startswith("ip-")]
    total_cs_eks = len(cs_eks_hosts)
    inflated_count = max(0, total_cs_eks - total_aws_eks)

    col_a, col_b, col_c = st.columns(3)
    col_a.metric("CrowdStrike EKS Hosts", total_cs_eks)
    col_b.metric("Actual EKS Nodes (AWS)", total_aws_eks)
    col_c.metric("Inflated/Stale", inflated_count)
    if inflated_count > 0:
        st.info(
            f"CrowdStrike has {total_cs_eks} EKS-type hosts (Bottlerocket/ip-* nodes), but only "
            f"{total_aws_eks} active EKS worker nodes exist in AWS. "
            f"**{inflated_count} are stale** — terminated nodes that auto-scaling replaced."
        )
    else:
        st.success("✅ CrowdStrike EKS host count matches AWS EKS node count.")
