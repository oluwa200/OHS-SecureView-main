"""Defender Security sub-dashboard (Microsoft) — V2 full port from V1.
Ported from V1: defender_overview.py, defender_assets.py, defender_posture.py, defender_email.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from config.dashboard_config import ASSETS_DIR, TODAY, load_json, show_dataframe


def render(go_home):
    """Render the Defender Security dashboard."""
    if st.button("← Back to Home", key="back_defender"):
        go_home()
        st.rerun()

    defender_logo = os.path.join(ASSETS_DIR, "Microsoft Defender XDR.png")
    if os.path.exists(defender_logo):
        st.image(defender_logo, width=60)

    st.title("Microsoft Defender Security")
    st.caption(f"Devices, posture, alerts, vulnerabilities, email | {TODAY.strftime('%Y-%m-%d %H:%M')}")

    # Load data
    data = load_json("defender_report.json", None)
    if not data or not data.get("summary"):
        st.error("No Defender data available. Waiting for refresh...")
        return

    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 Overview",
        "🖥️ Assets Coverage",
        "🎯 Posture & Recommendations",
        "✉️ Email Security",
    ])

    with tab1:
        _render_overview(data)
    with tab2:
        _render_assets_coverage(data)
    with tab3:
        _render_posture(data)
    with tab4:
        _render_email_security(data)


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 1: Overview (full port from V1 defender_overview.py)
# ═══════════════════════════════════════════════════════════════════════════════
def _render_overview(data):
    summary = data.get("summary", {})
    secure_score = data.get("secure_score", {})
    alerts = data.get("alerts", {})
    vulns = data.get("vulnerabilities", {})
    os_dist = data.get("os_distribution", {})
    exposure = data.get("exposure_levels", {})
    devices = data.get("device_inventory", [])
    noncompliant = data.get("noncompliant_devices", [])
    coverage = data.get("device_coverage", {})

    # KPI Row — filter to Active devices only
    score_pct = secure_score.get("percentage", 0)
    current = secure_score.get("current", 0)
    max_score = secure_score.get("max", 1)
    alert_summary = alerts.get("summary", {})
    active_machines = [m for m in devices if m.get("health") == "Active"]
    inactive_machines = [m for m in devices if m.get("health") != "Active"]

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Secure Score", f"{score_pct}%", f"{current:.0f} / {max_score:.0f}")
    col2.metric("Active Devices", len(active_machines), f"{len(inactive_machines)} inactive")
    col3.metric("Encryption Rate", f"{summary.get('encryption_rate', 0)}%",
                f"{summary.get('encrypted', 0)}/{summary.get('total_devices_intune', 0)}")
    col4.metric("Active Alerts", alert_summary.get("total", 0),
                f"🔴{alert_summary.get('high', 0)} 🟠{alert_summary.get('medium', 0)} 🟡{alert_summary.get('low', 0)}")
    col5.metric("Noncompliant", summary.get("noncompliant_count", 0), "devices")

    st.markdown("---")

    # Device Inventory
    st.subheader("💻 Managed Device Inventory")
    col1, col2 = st.columns(2)
    with col1:
        if os_dist:
            fig = px.pie(values=list(os_dist.values()), names=list(os_dist.keys()),
                title="Device OS Distribution", color_discrete_sequence=px.colors.qualitative.Set2)
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=350)
            st.plotly_chart(fig, use_container_width=True)
    with col2:
        if exposure:
            colors = {"High": "#ff4757", "Medium": "#ffa502", "Low": "#2ed573", "None": "#666"}
            fig2 = px.bar(x=list(exposure.keys()), y=list(exposure.values()),
                title="Exposure Level Distribution", color=list(exposure.keys()),
                color_discrete_map=colors)
            fig2.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                showlegend=False, height=350)
            st.plotly_chart(fig2, use_container_width=True)

    # Device table
    st.markdown("**Active Devices:**")
    if active_machines:
        active_df = pd.DataFrame([{
            "Device": m.get("name", "N/A"), "OS": m.get("os", "Unknown"),
            "Health": m.get("health", "Unknown"), "Risk": m.get("risk_score", "None"),
            "Exposure": m.get("exposure", "None"), "Last Seen": str(m.get("last_seen", ""))[:10],
            "Onboarding": m.get("onboarding", ""), "AAD Joined": "✅" if m.get("aad_joined") else "❌",
        } for m in active_machines[:30]])
        show_dataframe(active_df, key="def_1")

    st.markdown("---")

    # Device Coverage Analysis
    st.subheader("📋 Device Coverage & Management Gaps")
    if coverage:
        cov_col1, cov_col2, cov_col3, cov_col4 = st.columns(4)
        cov_col1.metric("Entra ID Devices", coverage.get("total_entra_devices", 0),
                        f"{coverage.get('entra_active_30d', 0)} active (30d)")
        cov_col2.metric("Intune Managed", coverage.get("intune_managed", 0))
        cov_col3.metric("MDE Onboarded", coverage.get("mde_onboarded", 0),
                        f"{coverage.get('mde_can_be_onboarded', 0)} can be onboarded")
        cov_col4.metric("⚠️ Unmanaged Active", coverage.get("unmanaged_active", 0),
                        "Active devices NOT in Intune/MDE")

        coverage_data = {
            "Entra Active (30d)": coverage.get("entra_active_30d", 0),
            "Intune Managed": coverage.get("intune_managed", 0),
            "MDE Onboarded": coverage.get("mde_onboarded", 0),
            "Unmanaged Active": coverage.get("unmanaged_active", 0),
        }
        fig_cov = px.bar(x=list(coverage_data.keys()), y=list(coverage_data.values()),
            title="Device Management Coverage", color=list(coverage_data.keys()),
            color_discrete_map={"Entra Active (30d)": "#0078d4", "Intune Managed": "#2ed573",
                "MDE Onboarded": "#00d4ff", "Unmanaged Active": "#ff4757"})
        fig_cov.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            showlegend=False, height=300)
        st.plotly_chart(fig_cov, use_container_width=True)

        unmanaged = coverage.get("unmanaged_devices", [])
        if unmanaged:
            st.markdown("**⚠️ Active Devices NOT Managed by Intune or MDE:**")
            um_df = pd.DataFrame([{
                "Device": d.get("name", "N/A"), "OS": d.get("os", "Unknown"),
                "OS Version": d.get("os_version", ""), "Trust Type": d.get("trust_type", "Unknown"),
                "Last Sign-In": str(d.get("last_signin", ""))[:10],
            } for d in unmanaged])
            show_dataframe(um_df, key="def_2")
        else:
            st.success("All active Entra devices are managed!")

    st.markdown("---")

    # Encryption Status
    st.subheader("🔒 Encryption Status (Intune)")
    enc_col1, enc_col2 = st.columns([1, 3])
    with enc_col1:
        enc_rate = summary.get("encryption_rate", 100)
        fig_enc = go.Figure(go.Indicator(
            mode="gauge+number", value=enc_rate, number={"suffix": "%"},
            gauge={
                "axis": {"range": [0, 100]}, "bar": {"color": "#2ed573"},
                "steps": [{"range": [0, 80], "color": "#333"}, {"range": [80, 95], "color": "#444"},
                           {"range": [95, 100], "color": "#555"}],
                "threshold": {"line": {"color": "#ff4757", "width": 2}, "thickness": 0.75, "value": 95},
            },
        ))
        fig_enc.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=250)
        st.plotly_chart(fig_enc, use_container_width=True)
    with enc_col2:
        if noncompliant:
            st.markdown("**⚠️ Noncompliant Devices:**")
            nc_df = pd.DataFrame([{
                "Device": d.get("name", "N/A"), "OS": d.get("os", "Unknown"),
                "User": str(d.get("user", "N/A")).split("@")[0],
                "Last Sync": str(d.get("last_sync", ""))[:10],
                "Encrypted": "✅" if d.get("encrypted") else "❌",
            } for d in noncompliant])
            show_dataframe(nc_df, key="def_3")
        else:
            st.success("All devices are compliant!")

    st.markdown("---")

    # Security Alerts
    st.subheader("⚠️ Active Security Alerts")
    alert_details = alerts.get("details", [])
    if alert_details:
        alerts_df = pd.DataFrame([{
            "Severity": a.get("severity", "Unknown"), "Alert": a.get("title", "N/A"),
            "Device": a.get("device", "N/A"), "Category": a.get("category", "N/A"),
            "Source": a.get("source", "Unknown"), "Created": str(a.get("created", ""))[:10],
            "Threat": a.get("threat_family") or "—",
        } for a in alert_details])
        show_dataframe(alerts_df, key="def_4")
    else:
        st.success("No active alerts!")

    st.markdown("---")

    # Critical Vulnerabilities (TVM)
    st.subheader("🔴 Critical Vulnerabilities (Defender TVM)")
    vuln_details = vulns.get("details", [])
    if vuln_details:
        vuln_df = pd.DataFrame([{
            "CVE": v.get("cve_id", "N/A"),
            "Description": (v.get("description") or "")[:80],
            "CVSS": v.get("cvss", 0), "Severity": v.get("severity", "Unknown"),
            "Exposed Machines": v.get("exposed_machines", 0),
            "Exploit Available": "⚠️ Yes" if v.get("exploit_available") else "No",
            "Published": str(v.get("published", ""))[:10],
        } for v in vuln_details])
        vuln_df = vuln_df.sort_values("CVSS", ascending=False)
        show_dataframe(vuln_df, key="def_5")
    else:
        st.info("No critical vulnerabilities found in TVM.")

    st.markdown("---")

    # Secure Score Breakdown
    st.subheader("📊 Secure Score Breakdown")
    controls = secure_score.get("control_scores", [])
    if controls:
        categories = {}
        for c in controls[:15]:
            cat = c.get("controlCategory", "Other")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append({
                "name": c.get("controlName", ""), "score": c.get("score", 0),
                "percentage": c.get("scoreInPercentage", 0),
                "description": (c.get("description") or "")[:100],
            })
        for cat_name, ctrls in categories.items():
            with st.expander(f"**{cat_name}** — {len(ctrls)} controls"):
                for ctrl in ctrls:
                    pct = ctrl["percentage"]
                    color = "🟢" if pct >= 80 else "🟡" if pct >= 50 else "🔴"
                    st.markdown(f"{color} **{ctrl['name']}** — {pct:.0f}% | {ctrl['description']}")


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 2: Assets Coverage (full port from V1 defender_assets.py)
# ═══════════════════════════════════════════════════════════════════════════════
def _render_assets_coverage(data):
    summary = data.get("summary", {})
    devices = data.get("device_inventory", [])
    coverage = data.get("device_coverage", {})

    # Filter to Active devices only for primary KPI
    active_devices = [d for d in devices if d.get("health") == "Active"]
    inactive_devices = [d for d in devices if d.get("health") != "Active"]

    # KPI Row — Active-only focus
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total MDE Devices", len(devices))
    col2.metric("✅ Active", len(active_devices))
    col3.metric("⚠️ Inactive", len(inactive_devices))
    col4.metric("Intune Managed", summary.get("total_devices_intune", 0))
    col5.metric("Encryption Rate", f"{summary.get('encryption_rate', 0)}%")

    st.markdown("---")

    # Platform Breakdown
    st.subheader("📊 Devices by Platform")
    platform_groups = {
        "Windows 11": [], "Windows Server": [], "iOS / iPadOS": [],
        "Android": [], "macOS": [], "Linux": [], "Other": [],
    }
    for d in devices:
        os_name = (d.get("os") or "Unknown").lower()
        if "windows11" in os_name or "windows 11" in os_name:
            platform_groups["Windows 11"].append(d)
        elif "windowsserver" in os_name or "server" in os_name:
            platform_groups["Windows Server"].append(d)
        elif "ios" in os_name or "ipad" in os_name:
            platform_groups["iOS / iPadOS"].append(d)
        elif "android" in os_name:
            platform_groups["Android"].append(d)
        elif "macos" in os_name or "mac" in os_name:
            platform_groups["macOS"].append(d)
        elif "linux" in os_name:
            platform_groups["Linux"].append(d)
        else:
            platform_groups["Other"].append(d)

    platform_counts = {k: len(v) for k, v in platform_groups.items() if v}

    col1, col2 = st.columns(2)
    with col1:
        if platform_counts:
            fig = px.pie(values=list(platform_counts.values()), names=list(platform_counts.keys()),
                title="Device Distribution by Platform", color_discrete_sequence=px.colors.qualitative.Set2)
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=400)
            st.plotly_chart(fig, use_container_width=True)
    with col2:
        platform_health = []
        for platform, devs in platform_groups.items():
            if not devs:
                continue
            active = sum(1 for d in devs if d.get("health") == "Active")
            inactive = len(devs) - active
            platform_health.append({"Platform": platform, "Active": active, "Inactive": inactive})
        if platform_health:
            health_df = pd.DataFrame(platform_health)
            fig2 = px.bar(health_df, x="Platform", y=["Active", "Inactive"],
                title="Health Status by Platform", barmode="stack",
                color_discrete_map={"Active": "#2ed573", "Inactive": "#ff6b35"})
            fig2.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=400)
            st.plotly_chart(fig2, use_container_width=True)

    st.markdown("---")

    # Per-Platform Device Tables
    st.subheader("📋 Device Details by Platform")
    for platform, devs in platform_groups.items():
        if not devs:
            continue
        active_count = sum(1 for d in devs if d.get("health") == "Active")
        with st.expander(f"**{platform}** — {len(devs)} devices ({active_count} active)", expanded=False):
            df = pd.DataFrame([{
                "Device": d.get("name", "N/A"), "Health": d.get("health", "Unknown"),
                "Exposure": d.get("exposure", "None"), "Risk": d.get("risk_score", "None"),
                "Last Seen": str(d.get("last_seen", ""))[:10],
                "Onboarding": d.get("onboarding", "Unknown"),
                "AAD": "Yes" if d.get("aad_joined") else "No", "IP": d.get("ip", "N/A"),
            } for d in devs])
            df = df.sort_values(["Health", "Last Seen"], ascending=[True, False])
            show_dataframe(df, key="def_6")

    st.markdown("---")

    # Onboarding Gap Analysis
    st.subheader("⚠️ Onboarding Gaps")
    can_be_onboarded = [d for d in devices if d.get("onboarding") == "CanBeOnboarded"]
    insufficient = [d for d in devices if d.get("onboarding") == "InsufficientInfo"]

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Can Be Onboarded (MDE)", len(can_be_onboarded),
                  "Devices discovered but not protected")
        if can_be_onboarded:
            cbo_df = pd.DataFrame([{
                "Device": d.get("name", "N/A"), "OS": d.get("os", "Unknown"),
                "IP": d.get("ip", "N/A"), "Last Seen": str(d.get("last_seen", ""))[:10],
            } for d in can_be_onboarded[:15]])
            show_dataframe(cbo_df, key="def_7")
    with col2:
        st.metric("Insufficient Info", len(insufficient), "Devices needing investigation")
        if insufficient:
            ins_df = pd.DataFrame([{
                "Device": d.get("name") or "Unknown", "OS": d.get("os", "Unknown"),
                "IP": d.get("ip", "N/A"), "Last Seen": str(d.get("last_seen", ""))[:10],
            } for d in insufficient[:15]])
            show_dataframe(ins_df, key="def_8")

    st.markdown("---")

    # Coverage Summary
    if coverage:
        st.subheader("📋 Device Coverage Summary")
        cov_col1, cov_col2, cov_col3, cov_col4 = st.columns(4)
        cov_col1.metric("Entra ID (Total)", coverage.get("total_entra_devices", "N/A"))
        cov_col2.metric("Entra Active (30d)", coverage.get("entra_active_30d", "N/A"))
        cov_col3.metric("MDE Onboarded", coverage.get("mde_onboarded", 0))
        cov_col4.metric("Unmanaged Active", coverage.get("unmanaged_active", "N/A"),
                        delta="Security Gap" if coverage.get("unmanaged_active", 0) > 0 else None,
                        delta_color="inverse")

        unmanaged = coverage.get("unmanaged_devices", [])
        if unmanaged:
            st.markdown("**Unmanaged but Active Devices (not in Intune or MDE):**")
            um_df = pd.DataFrame([{
                "Device": d.get("name", "N/A"), "OS": d.get("os", "Unknown"),
                "Trust Type": d.get("trust_type", "Unknown"),
                "Last Sign-In": str(d.get("last_signin", ""))[:10],
            } for d in unmanaged])
            show_dataframe(um_df, key="def_9")


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 3: Posture & Recommendations (full port from V1 defender_posture.py)
# ═══════════════════════════════════════════════════════════════════════════════
def _render_posture(data):
    secure_score = data.get("secure_score", {})
    vulns = data.get("vulnerabilities", {})
    alerts = data.get("alerts", {})
    noncompliant = data.get("noncompliant_devices", [])
    exposure = data.get("exposure_levels", {})

    # Secure Score Overview
    st.subheader("📊 Microsoft Secure Score")
    score_pct = secure_score.get("percentage", 0)
    current = secure_score.get("current", 0)
    max_score = secure_score.get("max", 1)
    mde_config = secure_score.get("mde_configuration_score", 0)

    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        fig = go.Figure(go.Indicator(
            mode="gauge+number", value=score_pct,
            number={"suffix": "%", "font": {"size": 28}}, title={"text": "Secure Score", "font": {"size": 14}},
            gauge={
                "axis": {"range": [0, 100], "tickfont": {"size": 10}},
                "bar": {"color": "#0078d4", "thickness": 0.6},
                "steps": [{"range": [0, 50], "color": "#ff4757"}, {"range": [50, 75], "color": "#ffa502"},
                           {"range": [75, 100], "color": "#2ed573"}],
                "threshold": {"line": {"color": "#fff", "width": 2}, "thickness": 0.75, "value": 80},
            },
        ))
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=220,
                         margin=dict(l=20, r=20, t=40, b=10))
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.metric("Current Score", f"{current:.0f}")
        st.metric("Max Score", f"{max_score:.0f}")
        st.metric("MDE Config Score", f"{mde_config:.0f}")
    with col3:
        controls = secure_score.get("control_scores", [])
        if controls:
            categories = {}
            for c in controls:
                cat = c.get("controlCategory", "Other")
                if cat not in categories:
                    categories[cat] = {"total_score": 0, "count": 0, "achieved": 0}
                categories[cat]["count"] += 1
                categories[cat]["total_score"] += c.get("scoreInPercentage", 0)
                categories[cat]["achieved"] += c.get("score", 0)
            cat_df = pd.DataFrame([{
                "Category": cat, "Controls": d["count"],
                "Avg Score %": round(d["total_score"] / max(d["count"], 1), 1),
                "Points": d["achieved"],
            } for cat, d in categories.items()])
            cat_df = cat_df.sort_values("Avg Score %", ascending=False)
            show_dataframe(cat_df, key="def_10")

    st.markdown("---")

    # Security Recommendations — Simplified table view
    st.subheader("🎯 Security Recommendations")
    controls = secure_score.get("control_scores", [])
    if controls:
        needs_action = [c for c in controls if c.get("scoreInPercentage", 100) < 100]
        achieved = [c for c in controls if c.get("scoreInPercentage", 100) >= 100]

        col_s1, col_s2 = st.columns(2)
        col_s1.metric("Implemented", len(achieved))
        col_s2.metric("Needs Action", len(needs_action))

        if needs_action:
            # Build simple table: Priority | Category | Control | Score | Exposed/Gap
            rows = []
            for c in sorted(needs_action, key=lambda x: x.get("scoreInPercentage", 0)):
                pct = c.get("scoreInPercentage", 0)
                icon = "🔴" if pct == 0 else "🟠" if pct < 50 else "🟡"
                count = c.get("count", "")
                total = c.get("total", "")
                gap = f"{count}/{total}" if count and total else "—"
                impl = c.get("implementationStatus", "")
                # Extract exposed number from implementation status
                exposed = gap if gap != "—" else (impl[:50] if impl else "—")

                rows.append({
                    "": icon,
                    "Category": c.get("controlCategory", ""),
                    "Control": c.get("controlName", ""),
                    "Score": f"{pct:.0f}%",
                    "Exposed/Gap": exposed,
                })

            show_dataframe(pd.DataFrame(rows), key="recs_table")

        st.markdown("---")
        with st.expander(f"✅ {len(achieved)} Fully Implemented Controls"):
            if achieved:
                achieved_df = pd.DataFrame([{
                    "Category": c.get("controlCategory", ""),
                    "Control": c.get("controlName", ""),
                    "Score": c.get("score", 0),
                } for c in achieved])
                show_dataframe(achieved_df, key="achieved_table", search=False)

    st.markdown("---")

    # Vulnerability Posture
    st.subheader("🔴 Vulnerability Posture (Defender TVM)")
    vuln_details = vulns.get("details", [])
    critical_count = vulns.get("critical_count", 0)
    high_count = vulns.get("high_count", 0)

    col1, col2, col3 = st.columns(3)
    col1.metric("Critical CVEs", critical_count, delta_color="inverse")
    col2.metric("High CVEs", high_count, delta_color="inverse")
    col3.metric("Total Tracked", len(vuln_details))

    if vuln_details:
        exposed_vulns = [v for v in vuln_details if v.get("exposed_machines", 0) > 0]
        exposed_vulns.sort(key=lambda x: x.get("exposed_machines", 0), reverse=True)
        if exposed_vulns:
            st.markdown("**Vulnerabilities Affecting Your Fleet:**")
            vuln_df = pd.DataFrame([{
                "CVE": v.get("cve_id", "N/A"), "Severity": v.get("severity", ""),
                "CVSS": v.get("cvss", 0), "Exposed Machines": v.get("exposed_machines", 0),
                "Exploit": "⚠️ Yes" if v.get("exploit_available") else "No",
                "Description": (v.get("description") or "")[:60],
                "Published": str(v.get("published", ""))[:10],
            } for v in exposed_vulns[:20]])
            show_dataframe(vuln_df, key="def_11")

            top10 = exposed_vulns[:10]
            if top10:
                fig = px.bar(
                    x=[v.get("cve_id", "")[:15] for v in top10],
                    y=[v.get("exposed_machines", 0) for v in top10],
                    title="Top 10 Vulnerabilities by Exposed Machine Count",
                    color=[v.get("severity", "") for v in top10],
                    color_discrete_map={"Critical": "#ff4757", "High": "#ff6b35", "Medium": "#ffa502"})
                fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                    showlegend=True, height=350)
                st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")

    # Compliance & Exposure
    st.subheader("📋 Compliance & Exposure Gaps")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Exposure Level Distribution:**")
        if exposure:
            fig = px.pie(values=list(exposure.values()), names=list(exposure.keys()),
                color=list(exposure.keys()),
                color_discrete_map={"High": "#ff4757", "Medium": "#ffa502", "Low": "#2ed573", "None": "#666"})
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=300)
            st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.markdown("**Noncompliant Devices:**")
        st.metric("Total Noncompliant", len(noncompliant))
        if noncompliant:
            nc_df = pd.DataFrame([{
                "Device": d.get("name", "N/A"), "OS": d.get("os", "Unknown"),
                "User": str(d.get("user", "")).split("@")[0],
                "Last Sync": str(d.get("last_sync", ""))[:10],
            } for d in noncompliant])
            show_dataframe(nc_df, key="def_12")
        else:
            st.success("All devices compliant!")

    # Active Alerts Summary
    st.markdown("---")
    st.subheader("⚠️ Active Threat Alerts")
    alert_details = alerts.get("details", [])
    alert_summary = alerts.get("summary", {})
    if alert_details:
        col1, col2, col3 = st.columns(3)
        col1.metric("High", alert_summary.get("high", 0))
        col2.metric("Medium", alert_summary.get("medium", 0))
        col3.metric("Low", alert_summary.get("low", 0))
        alert_df = pd.DataFrame([{
            "Severity": a.get("severity", ""), "Alert": a.get("title", "N/A"),
            "Device": a.get("device", "N/A"), "Category": a.get("category", "N/A"),
            "Source": a.get("source", ""), "Created": str(a.get("created", ""))[:10],
        } for a in alert_details])
        show_dataframe(alert_df, key="def_13")
    else:
        st.success("No active security alerts!")


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 4: Email Security (full port from V1 defender_email.py)
# ═══════════════════════════════════════════════════════════════════════════════
def _render_email_security(data):
    email_data = data.get("email_security", {})
    email_alerts = email_data.get("alerts", [])
    email_controls = email_data.get("email_controls", [])
    email_activity = email_data.get("email_activity", {})

    # KPI Row
    phishing_count = sum(1 for a in email_alerts if "phish" in (a.get("category") or "").lower())
    malware_count = sum(1 for a in email_alerts if "malware" in (a.get("category") or "").lower())
    initial_access = sum(1 for a in email_alerts if "initial" in (a.get("category") or "").lower())
    credential_count = sum(1 for a in email_alerts if "credential" in (a.get("category") or "").lower())

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Email Threats", len(email_alerts), "Total detections")
    col2.metric("Phishing", phishing_count, delta_color="inverse")
    col3.metric("Malware", malware_count, delta_color="inverse")
    col4.metric("Initial Access", initial_access, delta_color="inverse")
    col5.metric("Credential Theft", credential_count, delta_color="inverse")

    st.markdown("---")

    # Threat Category Breakdown
    st.subheader("📊 Email Threat Categories")
    if email_alerts:
        categories = {}
        for a in email_alerts:
            cat = a.get("category", "Unknown")
            categories[cat] = categories.get(cat, 0) + 1

        col1, col2 = st.columns(2)
        with col1:
            if categories:
                fig = px.pie(values=list(categories.values()), names=list(categories.keys()),
                    title="Threats by Category", color_discrete_sequence=px.colors.qualitative.Set1)
                fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=350)
                st.plotly_chart(fig, use_container_width=True)
        with col2:
            severity_counts = {}
            for a in email_alerts:
                sev = a.get("severity", "Unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            if severity_counts:
                fig2 = px.bar(x=list(severity_counts.keys()), y=list(severity_counts.values()),
                    title="Threats by Severity", color=list(severity_counts.keys()),
                    color_discrete_map={"High": "#ff4757", "Medium": "#ffa502", "Low": "#2ed573", "Informational": "#666"})
                fig2.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                    showlegend=False, height=350)
                st.plotly_chart(fig2, use_container_width=True)

        st.markdown("---")

        # Threat Timeline
        st.subheader("📈 Threat Detection Timeline")
        date_counts = {}
        for a in email_alerts:
            date = str(a.get("created", ""))[:10]
            if date:
                date_counts[date] = date_counts.get(date, 0) + 1
        if date_counts:
            sorted_dates = sorted(date_counts.items())
            fig = px.line(x=[d[0] for d in sorted_dates], y=[d[1] for d in sorted_dates],
                title="Email Threats Over Time", labels={"x": "Date", "y": "Detections"})
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=300)
            fig.update_traces(line_color="#ff4757", fill="tozeroy", fillcolor="rgba(255,71,87,0.1)")
            st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")

        # Per-category expanders
        st.subheader("⚠️ Email Threat Detail by Category")
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            cat_alerts = [a for a in email_alerts if a.get("category") == cat]
            high = sum(1 for a in cat_alerts if a.get("severity") == "High")
            with st.expander(f"**{cat}** — {count} threats ({high} high severity)"):
                cat_df = pd.DataFrame([{
                    "Severity": a.get("severity", ""), "Alert": a.get("title", "N/A"),
                    "Target": a.get("device", "N/A"), "Threat Family": a.get("threat_family") or "—",
                    "Created": str(a.get("created", ""))[:10],
                } for a in cat_alerts])
                show_dataframe(cat_df, key="def_14")

        st.markdown("---")

        # Full alert table
        st.subheader("📋 All Email Threat Alerts")
        alerts_df = pd.DataFrame([{
            "Severity": a.get("severity", "Unknown"), "Category": a.get("category", "N/A"),
            "Alert": a.get("title", "N/A"), "Target": a.get("device", "N/A"),
            "Threat Family": a.get("threat_family") or "—",
            "Status": a.get("status", ""), "Created": str(a.get("created", ""))[:10],
        } for a in email_alerts])
        sev_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3, "Unknown": 4}
        alerts_df["_sort"] = alerts_df["Severity"].map(sev_order)
        alerts_df = alerts_df.sort_values("_sort").drop("_sort", axis=1)
        show_dataframe(alerts_df, key="def_15")
    else:
        st.info("No email-related security alerts found.")
        st.markdown("""
- ✅ Your email security may be working well (no threats detected)
- ⚠️ Email threat alerts may be in a different category
- ℹ️ The API filter may need adjustment for your Defender configuration
        """)

    st.markdown("---")

    # Email Security Controls (from Secure Score)
    st.subheader("🔑 Email Security Policy Compliance")
    if email_controls:
        needs_action = [c for c in email_controls if c.get("scoreInPercentage", 100) < 100]
        achieved = [c for c in email_controls if c.get("scoreInPercentage", 100) >= 100]

        col_ea1, col_ea2 = st.columns(2)
        col_ea1.metric("Needs Action", len(needs_action))
        col_ea2.metric("Achieved", len(achieved))

        if needs_action:
            rows = []
            for c in sorted(needs_action, key=lambda x: x.get("scoreInPercentage", 0)):
                pct = c.get("scoreInPercentage", 0)
                icon = "🔴" if pct == 0 else "🟠" if pct < 50 else "🟡"
                impl = c.get("implementationStatus", "")
                rows.append({
                    "": icon,
                    "Category": c.get("controlCategory", ""),
                    "Control": c.get("controlName", ""),
                    "Score": f"{pct:.0f}%",
                    "Status": impl[:60] if impl else "—",
                })
            show_dataframe(pd.DataFrame(rows), key="email_controls_table")

        if achieved:
            with st.expander(f"✅ {len(achieved)} Email Controls Achieved"):
                ach_df = pd.DataFrame([{
                    "Control": c.get("controlName", ""),
                    "Score": c.get("score", 0),
                } for c in achieved])
                show_dataframe(ach_df, key="email_achieved", search=False)
    else:
        st.info("No email-specific controls found. Add `Reports.Read.All` permission for richer data.")

    st.markdown("---")

    # Email Activity Report
    st.subheader("📬 Email Activity (Last 30 Days)")
    if email_activity and not email_activity.get("error"):
        if isinstance(email_activity, list):
            show_dataframe(pd.DataFrame(email_activity), key="t_main_1")
        elif isinstance(email_activity, dict) and email_activity.get("value"):
            show_dataframe(pd.DataFrame(email_activity["value"]), key="t_main_2")
    else:
        st.warning("Email activity reports not available.")
        st.markdown("""
**To enable email activity reports, add this permission:**
- Microsoft Graph → Application → `Reports.Read.All`
- Then grant admin consent
        """)

    st.markdown("---")

    # Recommendations
    st.subheader("💡 Email Security Recommendations")
    recommendations = [
        {"Priority": "P1", "Action": "Enable Safe Attachments for all users",
         "Impact": "Blocks zero-day malware in email attachments via sandbox detonation"},
        {"Priority": "P1", "Action": "Enable Safe Links for all users",
         "Impact": "Rewrites URLs to check reputation at time-of-click"},
        {"Priority": "P1", "Action": "Configure anti-phishing with impersonation protection",
         "Impact": "Detects BEC/CEO fraud and domain spoofing"},
        {"Priority": "P2", "Action": "Enable DMARC enforcement (p=reject)",
         "Impact": "Prevents domain spoofing of outbound email"},
        {"Priority": "P2", "Action": "Configure Zero-hour Auto Purge (ZAP)",
         "Impact": "Removes malicious emails post-delivery when new intelligence emerges"},
        {"Priority": "P2", "Action": "Enable attack simulation training",
         "Impact": "Tests user awareness and reduces phishing click rates"},
        {"Priority": "P3", "Action": "Review quarantine policies",
         "Impact": "Ensure admins review and false positives are minimized"},
        {"Priority": "P3", "Action": "Configure mail flow rules for DLP",
         "Impact": "Prevents accidental data leakage via email"},
    ]
    st.dataframe(pd.DataFrame(recommendations), use_container_width=True, hide_index=True,
        column_config={
            "Priority": st.column_config.TextColumn("Priority", width="small"),
            "Action": st.column_config.TextColumn("Action", width="large"),
            "Impact": st.column_config.TextColumn("Impact", width="large"),
        })

    st.markdown("---")

    # Email Security Historical Log (from email_security_daily.json)
    st.subheader("📜 Email Threat History (Last 30 Days)")
    email_history = load_json("email_security_daily.json", None)
    if email_history and isinstance(email_history, list) and len(email_history) > 0:
        hist_df = pd.DataFrame(email_history)
        # Summary metrics
        total_all_time = hist_df["total_threats"].sum() if "total_threats" in hist_df.columns else 0
        days_tracked = len(hist_df)
        col_h1, col_h2, col_h3 = st.columns(3)
        col_h1.metric("Days Tracked", days_tracked)
        col_h2.metric("Total Threats (All Days)", int(total_all_time))
        col_h3.metric("Cycles Recorded", int(hist_df["cycles_recorded"].sum()) if "cycles_recorded" in hist_df.columns else 0)

        # Trend chart
        if "date" in hist_df.columns and "total_threats" in hist_df.columns:
            fig = px.area(hist_df, x="date", y="total_threats",
                title="Daily Email Threats Detected",
                labels={"date": "Date", "total_threats": "Threats"})
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=280)
            fig.update_traces(line_color="#ff6348", fillcolor="rgba(255,99,72,0.15)")
            st.plotly_chart(fig, use_container_width=True)

        # Breakdown chart
        breakdown_cols = ["phishing_blocked", "malware_blocked", "initial_access", "credential_theft"]
        available_cols = [c for c in breakdown_cols if c in hist_df.columns]
        if available_cols and hist_df[available_cols].sum().sum() > 0:
            fig2 = px.bar(hist_df, x="date", y=available_cols, barmode="stack",
                title="Threats by Category",
                labels={"value": "Count", "date": "Date", "variable": "Category"})
            fig2.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=280)
            st.plotly_chart(fig2, use_container_width=True)

        # Data table
        with st.expander("📋 Daily Log Detail"):
            display_cols = ["date", "total_threats", "phishing_blocked", "malware_blocked",
                           "initial_access", "credential_theft", "cycles_recorded", "fetch_failures"]
            available_display = [c for c in display_cols if c in hist_df.columns]
            show_dataframe(hist_df[available_display].sort_values("date", ascending=False), key="email_history_table")
    else:
        st.info("📊 Email security history will appear here after the next agent cycle. Data is recorded every 15 minutes.")
