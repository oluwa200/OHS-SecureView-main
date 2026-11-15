"""Aikido Application Security Dashboard — Full Build.
Tabs: Overview, SLA Reporting (new vs legacy), SAST, SCA, DAST, By Application, Findings Detail
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timezone, timedelta

from config.dashboard_config import ASSETS_DIR, TODAY, load_json, show_dataframe


def render(go_home):
    """Render the Aikido Application Security dashboard."""
    if st.button("← Back to Home", key="back_aikido"):
        go_home()
        st.rerun()

    aikido_logo = os.path.join(ASSETS_DIR, "Aikido.png")
    if os.path.exists(aikido_logo):
        import base64
        logo_b64 = base64.b64encode(open(aikido_logo, "rb").read()).decode()
        st.markdown(
            f'<div style="background:white; display:inline-block; padding:8px 12px; border-radius:8px;">'
            f'<img src="data:image/png;base64,{logo_b64}" width="120" />'
            f'</div>', unsafe_allow_html=True)

    st.title("Application Security (Aikido)")
    st.caption(f"SAST · SCA · DAST | SLA Tracking by Application | {TODAY.strftime('%Y-%m-%d %H:%M')}")

    data = load_json("aikido_report.json", None)
    if not data or not data.get("applications"):
        st.warning("No Aikido data available. Waiting for agent to fetch...")
        return

    summary = data.get("summary", {})
    apps = data.get("applications", [])
    all_issues = []
    for app in apps:
        for issue in app.get("issues", []):
            issue["application"] = app.get("name", "Unknown")
            all_issues.append(issue)

    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "📊 Overview",
        "⏱️ SLA Reporting",
        "🔬 SAST",
        "📦 SCA",
        "🌐 DAST",
        "📱 By Application",
        "🔍 All Findings",
    ])

    with tab1:
        _render_overview(summary, apps, all_issues)
    with tab2:
        _render_sla_reporting(apps, all_issues)
    with tab3:
        _render_scan_type(all_issues, "sast", "🔬 Static Analysis (SAST)", "Code vulnerabilities found through static analysis")
    with tab4:
        _render_scan_type(all_issues, "sca", "📦 Software Composition (SCA)", "Dependency vulnerabilities and EOL packages")
    with tab5:
        _render_scan_type(all_issues, "dast", "🌐 Dynamic Testing (DAST)", "Runtime vulnerabilities found through API/web scanning")
    with tab6:
        _render_by_application(apps)
    with tab7:
        _render_findings_detail(all_issues)


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 1: Overview
# ═══════════════════════════════════════════════════════════════════════════════
def _render_overview(summary, apps, all_issues):
    sla_status = summary.get("sla_status", {})
    severity = summary.get("severity", {})

    # KPIs
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    col1.metric("Applications", summary.get("total_applications", 0))
    col2.metric("Open Issues", f"{summary.get('total_issues', 0):,}")
    col3.metric("Critical", severity.get("critical", 0))
    col4.metric("❌ Breached", sla_status.get("breached", 0))
    col5.metric("⚠️ At Risk", sla_status.get("at_risk", 0))
    col6.metric("Compliance", f"{summary.get('compliance_pct', 0)}%")

    if summary.get("zero_day_findings", 0) > 0:
        st.error(f"🚨 **{summary['zero_day_findings']} ZERO-DAY findings** — 3-day SLA applies!")

    st.markdown("---")

    # Scan type breakdown
    st.subheader("Findings by Scan Type")
    type_counts = {}
    for issue in all_issues:
        t = issue.get("type", "other")
        type_counts[t] = type_counts.get(t, 0) + 1

    col_a, col_b = st.columns(2)
    with col_a:
        fig = px.pie(values=list(type_counts.values()), names=list(type_counts.keys()),
            title="Issues by Scan Type",
            color_discrete_sequence=px.colors.qualitative.Set2)
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=350)
        st.plotly_chart(fig, use_container_width=True)

    with col_b:
        fig2 = px.bar(x=list(severity.keys()), y=list(severity.values()),
            title="Issues by Severity", color=list(severity.keys()),
            color_discrete_map={"critical": "#ff4757", "high": "#ff6348", "medium": "#ffa502", "low": "#2ed573"})
        fig2.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=350, showlegend=False)
        st.plotly_chart(fig2, use_container_width=True)

    st.markdown("---")

    # Top 10 riskiest applications
    st.subheader("🔥 Top 10 Riskiest Applications")
    top_apps = apps[:10]
    if top_apps:
        rows = []
        for app in top_apps:
            s = app.get("summary", {})
            total = s.get("critical", 0) + s.get("high", 0) + s.get("medium", 0) + s.get("low", 0)
            rows.append({
                "Application": app.get("name", "?"),
                "Environment": app.get("environment", "?").title(),
                "Critical": s.get("critical", 0),
                "High": s.get("high", 0),
                "Breached": s.get("breached", 0),
                "Total": total,
            })
        show_dataframe(pd.DataFrame(rows), key="aikido_top10")


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 2: SLA Reporting (New vs Legacy)
# ═══════════════════════════════════════════════════════════════════════════════
def _render_sla_reporting(apps, all_issues):
    st.subheader("⏱️ SLA Reporting — New vs Legacy")

    # Split issues into new (< 30 days) and legacy (> 30 days)
    now_ts = datetime.now(timezone.utc).timestamp()
    thirty_days_ago = now_ts - (30 * 86400)
    seven_days_ago = now_ts - (7 * 86400)

    new_issues = []
    legacy_issues = []

    for issue in all_issues:
        first = issue.get("first_detected", 0)
        if isinstance(first, str):
            try:
                first = datetime.fromisoformat(first.replace("Z", "+00:00")).timestamp()
            except (ValueError, TypeError):
                first = 0
        if first > thirty_days_ago:
            new_issues.append(issue)
        else:
            legacy_issues.append(issue)

    # KPIs
    new_within = sum(1 for i in new_issues if i.get("status") == "WITHIN SLA")
    new_breached = sum(1 for i in new_issues if i.get("status") == "BREACHED")
    new_compliance = round(new_within / max(len(new_issues), 1) * 100, 1)

    legacy_within = sum(1 for i in legacy_issues if i.get("status") == "WITHIN SLA")
    legacy_breached = sum(1 for i in legacy_issues if i.get("status") == "BREACHED")
    legacy_compliance = round(legacy_within / max(len(legacy_issues), 1) * 100, 1)

    st.markdown("### 🆕 New Issues (Last 30 Days)")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("New Findings", len(new_issues))
    col2.metric("Within SLA", new_within)
    col3.metric("⚠️ At Risk", sum(1 for i in new_issues if i.get("status") == "AT RISK"))
    col4.metric("❌ Breached", new_breached)

    st.markdown("### 📚 Legacy Backlog (Older than 30 Days)")
    col5, col6, col7, col8 = st.columns(4)
    col5.metric("Backlog Size", len(legacy_issues))
    col6.metric("Within SLA", legacy_within)
    col7.metric("⚠️ At Risk", sum(1 for i in legacy_issues if i.get("status") == "AT RISK"))
    col8.metric("❌ Breached", legacy_breached)

    st.markdown("---")

    # Comparison chart
    fig = go.Figure()
    fig.add_trace(go.Bar(name="Within SLA", x=["New (< 30d)", "Legacy (> 30d)"], y=[new_within, legacy_within], marker_color="#2ed573"))
    fig.add_trace(go.Bar(name="At Risk", x=["New (< 30d)", "Legacy (> 30d)"],
        y=[sum(1 for i in new_issues if i.get("status") == "AT RISK"), sum(1 for i in legacy_issues if i.get("status") == "AT RISK")], marker_color="#ffa502"))
    fig.add_trace(go.Bar(name="Breached", x=["New (< 30d)", "Legacy (> 30d)"], y=[new_breached, legacy_breached], marker_color="#ff4757"))
    fig.update_layout(barmode="stack", template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
        title="New vs Legacy Issue SLA Status", height=350)
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")

    # Per-app SLA table
    st.subheader("Application SLA Compliance")
    sla_rows = []
    for app in apps:
        s = app.get("summary", {})
        total = s.get("critical", 0) + s.get("high", 0) + s.get("medium", 0) + s.get("low", 0)
        if total == 0:
            continue
        compliance = round(s.get("within_sla", 0) / total * 100, 1)
        sla_rows.append({
            "Application": app.get("name", "?"),
            "Environment": app.get("environment", "?").title(),
            "Total": total,
            "Breached": s.get("breached", 0),
            "At Risk": s.get("at_risk", 0),
            "Within SLA": s.get("within_sla", 0),
            "Compliance %": compliance,
        })
    if sla_rows:
        df = pd.DataFrame(sla_rows).sort_values("Breached", ascending=False)
        show_dataframe(df, key="aikido_sla_full")


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 3/4/5: Scan Type Sub-Tabs (SAST, SCA, DAST)
# ═══════════════════════════════════════════════════════════════════════════════
def _render_scan_type(all_issues, scan_type, title, description):
    st.subheader(title)
    st.caption(description)

    # Filter by type — using actual Aikido type values
    if scan_type == "sca":
        type_matches = ("open_source", "eol", "license")
        filtered = [i for i in all_issues if i.get("type", "").lower() in type_matches]
    elif scan_type == "sast":
        type_matches = ("sast", "leaked_secret", "scm_security")
        filtered = [i for i in all_issues if i.get("type", "").lower() in type_matches]
    elif scan_type == "dast":
        type_matches = ("surface_monitoring",)
        filtered = [i for i in all_issues if i.get("type", "").lower() in type_matches]
    else:
        filtered = [i for i in all_issues if i.get("type", "").lower() == scan_type]

    if not filtered:
        # Show all issues with unmatched types for this category
        st.info(f"No issues with type matching '{scan_type}'. Showing issues tagged as other types.")
        remaining_types = set(i.get("type", "") for i in all_issues)
        st.caption(f"Available types in data: {', '.join(sorted(remaining_types))}")
        return

    total = len(filtered)
    critical = sum(1 for i in filtered if i.get("severity") == "critical")
    high = sum(1 for i in filtered if i.get("severity") == "high")
    breached = sum(1 for i in filtered if i.get("status") == "BREACHED")
    within = sum(1 for i in filtered if i.get("status") == "WITHIN SLA")
    compliance = round(within / total * 100, 1) if total > 0 else 0

    # KPIs
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total", total)
    col2.metric("Critical", critical)
    col3.metric("High", high)
    col4.metric("❌ Breached", breached)
    col5.metric("Compliance", f"{compliance}%")

    st.markdown("---")

    # Top affected apps for this scan type
    st.subheader(f"Top Affected Applications ({scan_type.upper()})")
    app_counts = {}
    for i in filtered:
        app = i.get("application", "Unknown")
        app_counts[app] = app_counts.get(app, 0) + 1
    top_affected = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    if top_affected:
        fig = px.bar(x=[a[0] for a in top_affected], y=[a[1] for a in top_affected],
            title=f"{scan_type.upper()} Issues by Application",
            labels={"x": "Application", "y": "Issues"})
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=350, xaxis_tickangle=-45)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")

    # Findings table
    st.subheader(f"{scan_type.upper()} Findings")
    df = pd.DataFrame(filtered)
    # Fix recommendation + Aikido link
    if "fix_version" in df.columns:
        df["Fix"] = df.apply(lambda r: f"Upgrade to {r['fix_version']}" if r.get("fix_version") else "No fix available", axis=1)
    if "group_id" in df.columns and "id" in df.columns:
        df["🔗 View"] = df.apply(
            lambda r: f"https://app.aikido.dev/queue?sidebarIssue={int(r['group_id'])}&groupId={int(r['group_id'])}"
            if pd.notna(r.get('group_id')) else "",
            axis=1
        )

    display_cols = ["application", "title", "severity", "type", "cve", "package", "version", "Fix", "affected_file", "status", "days_open", "days_overdue", "🔗 View"]
    available = [c for c in display_cols if c in df.columns]
    if available:
        df_display = df[available].sort_values("days_overdue" if "days_overdue" in available else available[0], ascending=False)
        df_display.columns = [c.replace("_", " ").title() if not c.startswith("🔗") else c for c in available]

        col_config = {}
        if "🔗 View" in df_display.columns:
            col_config["🔗 View"] = st.column_config.LinkColumn("🔗 View", display_text="Open →")
        st.dataframe(df_display.head(100), use_container_width=True, hide_index=True, column_config=col_config)


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 6: By Application (with Remediation Rings)
# ═══════════════════════════════════════════════════════════════════════════════
def _render_by_application(apps):
    st.subheader("📱 Application Details")

    app_names = [app.get("name", "Unknown") for app in apps]
    selected = st.selectbox("Select Application", app_names, key="aikido_app_select")

    app_data = next((a for a in apps if a.get("name") == selected), None)
    if not app_data:
        return

    s = app_data.get("summary", {})
    issues = app_data.get("issues", [])
    total = s.get("critical", 0) + s.get("high", 0) + s.get("medium", 0) + s.get("low", 0)
    within = s.get("within_sla", 0)
    at_risk = s.get("at_risk", 0)
    breached = s.get("breached", 0)
    pct = round(within / total * 100, 1) if total > 0 else 0

    # App header with ring
    col_ring, col_info = st.columns([1, 3])
    with col_ring:
        fig = go.Figure(go.Pie(
            values=[within, at_risk, breached],
            labels=["Within SLA", "At Risk", "Overdue"],
            marker=dict(colors=["#2ed573", "#ffa502", "#ff4757"]),
            hole=0.7, textinfo="none",
        ))
        fig.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            height=200, margin=dict(t=10, b=10, l=10, r=10), showlegend=False,
            annotations=[dict(text=f"{pct}%", x=0.5, y=0.5, font_size=20, showarrow=False, font_color="white")],
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_info:
        st.markdown(f"### {selected}")
        st.caption(f"Environment: **{app_data.get('environment', '?').title()}** | Attack Surface: **{app_data.get('attack_surface', '?')}**")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Critical", s.get("critical", 0))
        c2.metric("High", s.get("high", 0))
        c3.metric("Breached", breached)
        c4.metric("Zero-Day", s.get("zero_day", 0))

    st.markdown("---")

    # Issues by type for this app
    if issues:
        type_counts = {}
        for i in issues:
            t = i.get("type", "other")
            type_counts[t] = type_counts.get(t, 0) + 1
        if type_counts:
            st.subheader("Issue Types")
            fig = px.bar(x=list(type_counts.keys()), y=list(type_counts.values()),
                color=list(type_counts.keys()), title=f"Findings by Type — {selected}")
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=250, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")

        # Issues table
        df = pd.DataFrame(issues)
        display_cols = ["title", "severity", "type", "cve", "package", "affected_file", "status", "days_open", "days_overdue"]
        available = [c for c in display_cols if c in df.columns]
        if available:
            df_display = df[available].sort_values("days_overdue" if "days_overdue" in available else available[0], ascending=False)
            df_display.columns = [c.replace("_", " ").title() for c in available]
            show_dataframe(df_display, key="aikido_app_detail_issues")


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 7: All Findings (filterable)
# ═══════════════════════════════════════════════════════════════════════════════
def _render_findings_detail(all_issues):
    st.subheader("🔍 All Findings")

    if not all_issues:
        st.info("No findings to display.")
        return

    # Filters
    col_f1, col_f2, col_f3, col_f4 = st.columns(4)
    with col_f1:
        sev_filter = st.multiselect("Severity", ["critical", "high", "medium", "low"], default=["critical", "high"], key="aikido_sev_f")
    with col_f2:
        status_filter = st.multiselect("SLA Status", ["BREACHED", "AT RISK", "WITHIN SLA"], default=["BREACHED", "AT RISK"], key="aikido_status_f")
    with col_f3:
        all_types = sorted(set(i.get("type", "") for i in all_issues if i.get("type")))
        type_filter = st.multiselect("Scan Type", all_types, key="aikido_type_f")
    with col_f4:
        all_apps = sorted(set(i.get("application", "") for i in all_issues if i.get("application")))
        app_filter = st.multiselect("Application", all_apps, key="aikido_app_f")

    # Apply filters
    filtered = [i for i in all_issues
                if i.get("severity") in sev_filter
                and i.get("status") in status_filter
                and (not type_filter or i.get("type") in type_filter)
                and (not app_filter or i.get("application") in app_filter)]

    st.metric("Filtered Results", f"{len(filtered):,}")

    if filtered:
        df = pd.DataFrame(filtered)
        # Fix recommendation + Aikido link
        if "fix_version" in df.columns:
            df["Fix"] = df.apply(lambda r: f"Upgrade to {r['fix_version']}" if r.get("fix_version") else "No fix available", axis=1)
        if "group_id" in df.columns:
            df["🔗 View"] = df.apply(
                lambda r: f"https://app.aikido.dev/queue?sidebarIssue={int(r['group_id'])}&groupId={int(r['group_id'])}"
                if pd.notna(r.get('group_id')) else "",
                axis=1
            )

        display_cols = ["application", "title", "severity", "type", "cve", "package", "version", "Fix", "status", "days_open", "days_overdue", "🔗 View"]
        available = [c for c in display_cols if c in df.columns]
        df_display = df[available].sort_values("days_overdue" if "days_overdue" in available else available[0], ascending=False).head(200)
        df_display.columns = [c.replace("_", " ").title() if not c.startswith("🔗") else c for c in available]

        col_config = {}
        if "🔗 View" in df_display.columns:
            col_config["🔗 View"] = st.column_config.LinkColumn("🔗 View", display_text="Open →")
        st.dataframe(df_display, use_container_width=True, hide_index=True, column_config=col_config)

        # Export
        csv = df_display.to_csv(index=False)
        st.download_button("⬇️ Export Filtered (CSV)", data=csv,
            file_name=f"aikido_findings_{TODAY.strftime('%Y%m%d')}.csv",
            mime="text/csv", use_container_width=True, key="dl_aikido")
