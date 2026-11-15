"""AI Insights sub-dashboard — displays output from the Security Agent."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from config.dashboard_config import show_dataframe,  DATA_DIR, load_json


def render(go_home):
    """Render AI-generated security insights."""
    if st.button("← Back to Home", key="back_ai"):
        go_home()
        st.rerun()

    st.title("🤖 AI Security Insights")
    st.caption("Cross-tool correlation and automated risk analysis")

    # Load insights
    insights = load_json("ai_insights.json", None)

    if not insights:
        st.warning("No AI insights available yet. Run the Security Agent to generate them.")
        st.markdown("---")
        st.subheader("Run Agent")
        if st.button("🚀 Run Security Agent Now", use_container_width=True):
            with st.spinner("Running cross-correlation analysis..."):
                try:
                    from agent.security_agent import run_agent
                    result = run_agent()
                    st.success(f"Agent complete! Risk Score: {result['overall_risk_score']}/100")
                    st.rerun()
                except Exception as e:
                    st.error(f"Agent failed: {e}")
        st.markdown("---")
        _render_placeholder()
        return

    # ─── Display Insights ─────────────────────────────────────────────────────
    generated = insights.get("generated_at", "Unknown")
    risk_score = insights.get("overall_risk_score", 0)
    stats = insights.get("stats", {})
    summary = insights.get("summary", "")

    # Header metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Overall Risk Score", f"{risk_score}/100")
    col2.metric("Total EC2 IPs", stats.get("total_ec2_ips", 0))
    col3.metric("Full Coverage", f"{stats.get('full_coverage_pct', 0)}%")
    col4.metric("Blind Spots", stats.get("completely_blind", 0))

    st.caption(f"Last generated: {generated}")

    # Summary
    st.markdown("---")
    risk_color = "#44bb44" if risk_score < 25 else "#ffcc00" if risk_score < 50 else "#ff8800" if risk_score < 75 else "#ff4444"
    st.markdown(f"### 📋 Executive Summary")
    st.info(summary)

    # Risk gauge
    col_g, col_s = st.columns([1, 1])
    with col_g:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk_score,
            title={"text": "Overall Risk Score"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": risk_color},
                "steps": [
                    {"range": [0, 25], "color": "#113d11"},
                    {"range": [25, 50], "color": "#3d3d11"},
                    {"range": [50, 75], "color": "#3d2211"},
                    {"range": [75, 100], "color": "#3d1111"},
                ],
            },
        ))
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=300)
        st.plotly_chart(fig, use_container_width=True)

    with col_s:
        st.subheader("Coverage Stats")
        st.metric("EDR Coverage", f"{stats.get('edr_coverage_pct', 0)}%")
        st.metric("Vuln Scan Coverage", f"{stats.get('vuln_scan_coverage_pct', 0)}%")
        st.metric("No EDR", stats.get("no_edr", 0))
        st.metric("No Vuln Scan", stats.get("no_vuln_scan", 0))

    # Coverage overlap diagram (simplified bar)
    st.markdown("---")
    st.subheader("📊 Coverage Overlap")
    coverage_data = {
        "Full Coverage (Both Tools)": stats.get("full_coverage", 0),
        "EDR Only": stats.get("crowdstrike_coverage", 0) - stats.get("full_coverage", 0),
        "Vuln Scan Only": stats.get("qualys_coverage", 0) - stats.get("full_coverage", 0),
        "Completely Blind": stats.get("completely_blind", 0),
    }
    # Remove negatives
    coverage_data = {k: max(0, v) for k, v in coverage_data.items()}

    fig2 = px.pie(values=list(coverage_data.values()), names=list(coverage_data.keys()),
                  color_discrete_sequence=["#44bb44", "#4488ff", "#ffcc00", "#ff4444"])
    fig2.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=350)
    st.plotly_chart(fig2, use_container_width=True)

    # Priority Actions
    st.markdown("---")
    st.subheader("🎯 Priority Actions")
    actions = insights.get("priority_actions", [])
    if actions:
        df_actions = pd.DataFrame(actions)
        show_dataframe(df_actions, key="t_main_1")
    else:
        st.success("No critical actions needed — all assets covered.")

    # Coverage Gaps
    st.markdown("---")
    st.subheader("🕳️ Coverage Gaps")
    gaps = insights.get("coverage_gaps", [])
    if gaps:
        df_gaps = pd.DataFrame(gaps)
        # Color-code by risk
        gap_summary = df_gaps["gap_type"].value_counts()
        col1, col2, col3 = st.columns(3)
        col1.metric("No EDR", gap_summary.get("no_edr", 0))
        col2.metric("No Vuln Scan", gap_summary.get("no_vuln_scan", 0))
        col3.metric("Completely Blind", gap_summary.get("completely_blind", 0))

        with st.expander("📋 Gap Details"):
            show_dataframe(df_gaps, key="t_main_2")
    else:
        st.success("No coverage gaps detected!")

    # High Risk Findings
    high_risk = insights.get("high_risk_findings", [])
    if high_risk:
        st.markdown("---")
        st.subheader("⚠️ High-Risk Findings")
        st.caption("Critical/High vulns on internet-facing hosts WITHOUT EDR")
        df_risk = pd.DataFrame(high_risk)
        show_dataframe(df_risk, key="t_main_3")

    # Refresh button
    st.markdown("---")
    if st.button("🔄 Re-run Agent", use_container_width=True):
        with st.spinner("Running cross-correlation analysis..."):
            try:
                from agent.security_agent import run_agent
                result = run_agent()
                st.success(f"Updated! Risk Score: {result['overall_risk_score']}/100")
                st.rerun()
            except Exception as e:
                st.error(f"Agent failed: {e}")


def _render_placeholder():
    """Show placeholder info when no insights exist."""
    st.info("""
    **Security Posture Agent** will analyze:
    
    - 🔍 **Coverage Gaps**: EC2 instances missing CrowdStrike AND/OR Qualys
    - ⚠️ **High-Risk Combos**: Critical vulns on hosts without EDR
    - 📈 **Risk Scoring**: Weighted overall security posture score
    - 🎯 **Priority Actions**: Top things to fix right now
    
    Click "Run Security Agent Now" above to generate insights.
    """)
