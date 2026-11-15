"""Executive Summary — Clean CISO-level posture view."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import plotly.graph_objects as go
from datetime import datetime
from config.dashboard_config import load_json, SCOPED_ACCOUNTS, TODAY, filter_by_account


def render(go_home):
    """Render a clean, high-signal executive summary."""
    if st.button("← Back to Home", key="back_exec"):
        go_home()
        st.rerun()

    st.title("Executive Summary")
    st.caption(f"Security posture at a glance | {TODAY.strftime('%B %d, %Y')}")

    # ─── Load Data ────────────────────────────────────────────────────────────
    ai = load_json("ai_insights.json", {})
    ec2 = load_json("aws_ec2_counts.json", {})
    cs = load_json("crowdstrike_hosts.json", {})
    history = load_json("history.json", [])
    bp_data = load_json("bindplane_agents.json", {})

    # Apply filter
    ec2_by_account = filter_by_account(ec2.get("by_account", {}))
    cs_accounts = filter_by_account(cs.get("accounts", {}))

    stats = ai.get("stats", {})
    risk_score = ai.get("overall_risk_score", 0)

    total_ec2 = sum(d.get("total", 0) for d in ec2_by_account.values()) if ec2_by_account else ec2.get("total_instances", 0)
    cs_total = sum(len(h) for h in cs_accounts.values())
    edr_pct = stats.get("edr_coverage_pct", 0)
    vuln_pct = stats.get("vuln_scan_coverage_pct", 0)
    blind = stats.get("completely_blind", 0)
    bp_agents = bp_data.get("agents", [])
    bp_connected = sum(1 for a in bp_agents if a.get("status") in ("connected", 1, "1"))

    # ─── Overall Risk Gauge (center piece) ────────────────────────────────────
    st.markdown("---")

    col_gauge, col_brief = st.columns([1, 2])

    with col_gauge:
        if risk_score < 25:
            gauge_color = "#44bb44"
            risk_level = "LOW"
        elif risk_score < 50:
            gauge_color = "#ff8800"
            risk_level = "MEDIUM"
        elif risk_score < 75:
            gauge_color = "#ff4444"
            risk_level = "HIGH"
        else:
            gauge_color = "#cc0000"
            risk_level = "CRITICAL"

        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk_score,
            number={"suffix": "/100", "font": {"size": 36}},
            title={"text": f"Overall Risk: {risk_level}", "font": {"size": 16}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1},
                "bar": {"color": gauge_color, "thickness": 0.8},
                "steps": [
                    {"range": [0, 25], "color": "#0d1f0d"},
                    {"range": [25, 50], "color": "#1a1a00"},
                    {"range": [50, 75], "color": "#2d1a00"},
                    {"range": [75, 100], "color": "#2d1117"},
                ],
            },
        ))
        fig.update_layout(height=250, margin=dict(l=20, r=20, t=50, b=20),
                         paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig, use_container_width=True)

    with col_brief:
        st.markdown("### Key Takeaways")
        st.markdown(f"""
        - **{total_ec2} EC2 instances** across {len(ec2_by_account)} accounts ({cs_total} with EDR)
        - **EDR coverage: {edr_pct}%** | Vuln scanning: {vuln_pct}%
        - **{blind} blind spots** — no EDR and no vulnerability scanning
        - **{bp_connected} telemetry agents** reporting to BindPlane
        """)

        # MoM delta from history
        if len(history) >= 2:
            prev_risk = history[-2].get("risk_score", risk_score)
            delta = risk_score - prev_risk
            if delta < 0:
                st.success(f"↓ Risk improved by {abs(delta):.1f} points since last assessment")
            elif delta > 0:
                st.error(f"↑ Risk increased by {delta:.1f} points since last assessment")
            else:
                st.info("→ Risk unchanged since last assessment")

    # ─── Coverage Summary (simple 4-column) ───────────────────────────────────
    st.markdown("---")
    st.markdown("### Security Coverage")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("EDR (CrowdStrike)", f"{edr_pct}%", help="Falcon sensor on EC2 instances")
    col2.metric("Vuln Scan (Qualys)", f"{vuln_pct}%", help="Assets with active vulnerability scanning")
    col3.metric("Telemetry (BindPlane)", f"{bp_connected}/{len(bp_agents)}", help="Connected log collection agents")
    col4.metric("Blind Spots", blind, delta=f"{blind} unprotected", delta_color="inverse")

    # ─── Risk Trend (14-day sparkline) ────────────────────────────────────────
    if history and len(history) >= 3:
        st.markdown("---")
        st.markdown("### 14-Day Risk Trend")

        trend_data = history[-14:]
        dates = [h.get("date", "") for h in trend_data]
        scores = [h.get("risk_score", 0) for h in trend_data]

        fig_trend = go.Figure()
        fig_trend.add_trace(go.Scatter(
            x=dates, y=scores, mode="lines+markers",
            line=dict(color=gauge_color, width=3),
            marker=dict(size=6),
            fill="tozeroy",
            fillcolor=f"rgba({int(gauge_color[1:3],16)},{int(gauge_color[3:5],16)},{int(gauge_color[5:7],16)},0.1)",
        ))
        fig_trend.update_layout(
            height=200, margin=dict(l=40, r=20, t=10, b=30),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="white",
            xaxis=dict(showgrid=False), yaxis=dict(range=[0, 100], showgrid=True, gridcolor="rgba(255,255,255,0.1)"),
            showlegend=False,
        )
        st.plotly_chart(fig_trend, use_container_width=True)

    # ─── Top 3 Priority Actions ───────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### Priority Actions")

    actions = ai.get("priority_actions", [])[:3]
    if actions:
        for a in actions:
            impact = a.get("impact", "")
            icon = "🔴" if impact == "CRITICAL" else "🟠" if impact == "HIGH" else "🟡"
            st.markdown(f"{icon} **P{a.get('priority', '?')}** — {a.get('action', '')}")
    else:
        st.success("No critical actions — posture is healthy.")

    # ─── Download ─────────────────────────────────────────────────────────────
    st.markdown("---")
    import pandas as pd

    col_dl1, col_dl2 = st.columns(2)

    # CSV export
    exec_data = [{
        "Date": TODAY.strftime("%Y-%m-%d"),
        "Risk Score": risk_score,
        "Risk Level": risk_level,
        "EC2 Instances": total_ec2,
        "EDR Coverage %": edr_pct,
        "Vuln Scan %": vuln_pct,
        "Blind Spots": blind,
        "BindPlane Agents": len(bp_agents),
        "BindPlane Connected": bp_connected,
    }]
    csv = pd.DataFrame(exec_data).to_csv(index=False)
    with col_dl1:
        st.download_button("⬇️ Export CSV", csv,
                          f"executive_summary_{TODAY.strftime('%Y%m%d')}.csv", "text/csv",
                          use_container_width=True)

    # PDF export
    with col_dl2:
        try:
            from fpdf import FPDF

            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 20)
            pdf.cell(0, 12, "OHS SecureView - Executive Summary", ln=True, align="C")
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 8, f"Generated: {TODAY.strftime('%B %d, %Y')}", ln=True, align="C")
            pdf.ln(10)

            # Risk Score
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, f"Overall Risk: {risk_level} ({risk_score}/100)", ln=True)
            pdf.ln(5)

            # Coverage
            pdf.set_font("Helvetica", "", 11)
            pdf.cell(0, 7, f"EC2 Instances: {total_ec2}", ln=True)
            pdf.cell(0, 7, f"EDR Coverage: {edr_pct}%", ln=True)
            pdf.cell(0, 7, f"Vulnerability Scan: {vuln_pct}%", ln=True)
            pdf.cell(0, 7, f"Blind Spots: {blind}", ln=True)
            pdf.cell(0, 7, f"BindPlane Agents: {bp_connected}/{len(bp_agents)} connected", ln=True)
            pdf.ln(8)

            # Priority Actions
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Priority Actions:", ln=True)
            pdf.set_font("Helvetica", "", 10)
            for a in actions:
                pdf.cell(0, 6, f"  P{a.get('priority','?')} [{a.get('impact','')}] - {a.get('action','')}", ln=True)

            pdf_bytes = pdf.output()
            st.download_button("📄 Export PDF", pdf_bytes,
                              f"executive_summary_{TODAY.strftime('%Y%m%d')}.pdf",
                              "application/pdf", use_container_width=True)
        except ImportError:
            st.caption("PDF export requires fpdf2 package")
