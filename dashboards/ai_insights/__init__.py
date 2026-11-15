"""AI Insights sub-dashboard — displays output from the Security Agent.
Now includes: Weekly Brief, Anomaly Detection, Remediation Prioritization, Trend Forecasting.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from config.dashboard_config import show_dataframe, DATA_DIR, load_json


def render(go_home):
    """Render AI-generated security insights."""
    if st.button("← Back to Home", key="back_ai"):
        go_home()
        st.rerun()

    st.title("🤖 AI Security Insights")
    st.caption("Cross-tool correlation, anomaly detection, and automated risk analysis")

    # Load insights
    insights = load_json("ai_insights.json", None)
    weekly_brief = load_json("weekly_brief.json", None)

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

    # ─── Tabs ─────────────────────────────────────────────────────────────────
    tab1, tab2, tab3 = st.tabs([
        "📋 Weekly Brief",
        "📈 Trend Forecast",
        "📊 Coverage Analysis",
    ])

    with tab1:
        _render_weekly_brief(weekly_brief, insights)
    with tab2:
        _render_forecast(weekly_brief, insights)
    with tab3:
        _render_coverage_analysis(insights)

    # Refresh buttons
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 Re-run Agent", use_container_width=True):
            with st.spinner("Running cross-correlation analysis..."):
                try:
                    from agent.security_agent import run_agent
                    result = run_agent()
                    st.success(f"Updated! Risk Score: {result['overall_risk_score']}/100")
                    st.rerun()
                except Exception as e:
                    st.error(f"Agent failed: {e}")
    with col2:
        if st.button("📝 Generate Weekly Brief", use_container_width=True):
            with st.spinner("Generating weekly brief..."):
                try:
                    from agent.weekly_brief import generate_weekly_brief
                    brief = generate_weekly_brief()
                    st.success(f"Brief generated! Risk: {brief['risk_level']}")
                    st.rerun()
                except Exception as e:
                    st.error(f"Brief generation failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 1: Weekly Brief
# ═══════════════════════════════════════════════════════════════════════════════
def _render_weekly_brief(brief, insights):
    """Render the natural-language weekly security brief with anomalies + remediation inline."""
    st.subheader("📋 Weekly Security Brief")

    if not brief:
        st.info("No weekly brief generated yet. Click 'Generate Weekly Brief' below.")
        st.markdown("---")
        _render_basic_summary(insights)
        return

    generated = brief.get("generated_at", "Unknown")
    st.caption(f"Generated: {generated[:16].replace('T', ' ')}")

    # Risk level header
    risk_level = brief.get("risk_level", "UNKNOWN")
    risk_score = brief.get("risk_score", 0)
    anomalies = brief.get("anomalies", [])
    priorities = brief.get("remediation_priorities", [])

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Risk Level", risk_level)
    col2.metric("Risk Score", f"{risk_score}/100")
    col3.metric("Anomalies", len(anomalies))
    col4.metric("Action Items", len(priorities))

    st.markdown("---")

    # Render narrative as markdown
    narrative = brief.get("narrative", "")
    if narrative:
        st.markdown(narrative)
    else:
        _render_basic_summary(insights)

    # Inline anomalies
    if anomalies:
        st.markdown("---")
        st.subheader("⚠️ Anomalies Detected")
        for a in sorted(anomalies, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x.get("severity", ""), 3)):
            sev = a.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                st.error(f"🔴 **{a['metric']}** — {a['message']}")
            elif sev == "HIGH":
                st.warning(f"🟠 **{a['metric']}** — {a['message']}")
            else:
                st.info(f"🟡 **{a['metric']}** — {a['message']}")

    # Inline top remediation priorities
    if priorities:
        st.markdown("---")
        st.subheader("🎯 Top Remediation Priorities")
        for p in priorities[:5]:
            impact = p.get("impact", "MEDIUM")
            icon = "🔴" if impact == "CRITICAL" else "🟠" if impact == "HIGH" else "🟡"
            st.markdown(f"{icon} **P{p.get('rank', 0)} — {p.get('category', '')}**: {p.get('action', '')}")
            st.caption(f"Impact: {impact} | Effort: {p.get('effort', 'Medium')}")


def _render_basic_summary(insights):
    """Fallback summary from raw insights data."""
    risk_score = insights.get("overall_risk_score", 0)
    stats = insights.get("stats", {})
    summary = insights.get("summary", "")

    risk_color = "#44bb44" if risk_score < 25 else "#ffcc00" if risk_score < 50 else "#ff8800" if risk_score < 75 else "#ff4444"

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Overall Risk Score", f"{risk_score}/100")
    col2.metric("Total EC2 IPs", stats.get("total_ec2_ips", 0))
    col3.metric("Full Coverage", f"{stats.get('full_coverage_pct', 0)}%")
    col4.metric("Blind Spots", stats.get("completely_blind", 0))

    st.info(summary)


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 2: Anomaly Detection
# ═══════════════════════════════════════════════════════════════════════════════
def _render_anomalies(brief, insights):
    """Render anomaly detection results."""
    st.subheader("⚠️ Anomaly Detection")
    st.caption("Significant changes detected from historical baselines")

    anomalies = brief.get("anomalies", []) if brief else []

    if not anomalies:
        # Try generating on the fly
        try:
            from agent.weekly_brief import detect_anomalies
            history = load_json("history.json", [])
            anomalies = detect_anomalies(history, insights)
        except Exception:
            pass

    if not anomalies:
        st.success("✅ No anomalies detected. All metrics within normal ranges.")
        st.markdown("---")
        st.caption("Monitored metrics: EDR Coverage, Risk Score, Blind Spots, Vuln Scan Coverage")
        return

    # KPIs
    critical_count = sum(1 for a in anomalies if a.get("severity") == "CRITICAL")
    high_count = sum(1 for a in anomalies if a.get("severity") == "HIGH")
    medium_count = sum(1 for a in anomalies if a.get("severity") == "MEDIUM")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Anomalies", len(anomalies))
    col2.metric("🔴 Critical", critical_count)
    col3.metric("🟠 High", high_count)
    col4.metric("🟡 Medium", medium_count)

    st.markdown("---")

    # Detail cards
    for a in sorted(anomalies, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x.get("severity", ""), 3)):
        sev = a.get("severity", "MEDIUM")
        if sev == "CRITICAL":
            st.error(f"🔴 **{a['metric']}** — {a['message']}")
        elif sev == "HIGH":
            st.warning(f"🟠 **{a['metric']}** — {a['message']}")
        else:
            st.info(f"🟡 **{a['metric']}** — {a['message']}")

        with st.expander(f"Details: {a['metric']}"):
            col1, col2, col3 = st.columns(3)
            col1.metric("Prior Average", a.get("prior_avg", "N/A"))
            col2.metric("Current Average", a.get("current_avg", "N/A"))
            col3.metric("Change", f"{a.get('delta', 0):+}")

    # History chart showing the anomaly
    st.markdown("---")
    st.subheader("📈 Metric History (14-day)")
    history = load_json("history.json", [])
    if history and len(history) >= 2:
        hist_df = pd.DataFrame(history[-14:])
        metrics_to_show = ["risk_score", "edr_coverage_pct", "completely_blind", "vuln_scan_coverage_pct"]
        available_metrics = [m for m in metrics_to_show if m in hist_df.columns]

        if available_metrics and "date" in hist_df.columns:
            metric_select = st.selectbox("Metric", available_metrics, key="anomaly_metric_select")
            fig = px.line(hist_df, x="date", y=metric_select, markers=True,
                          title=f"{metric_select} — Last 14 Days")
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                              plot_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 3: Remediation Plan
# ═══════════════════════════════════════════════════════════════════════════════
def _render_remediation(brief, insights):
    """Render prioritized remediation plan."""
    st.subheader("🎯 Prioritized Remediation Plan")
    st.caption("Internet-facing + critical vulns prioritized first | Based on blast radius analysis")

    priorities = brief.get("remediation_priorities", []) if brief else []

    if not priorities:
        # Generate on the fly
        try:
            from agent.weekly_brief import prioritize_remediation
            iom_data = load_json("crowdstrike_iom_analysis.json", {})
            priorities = prioritize_remediation(insights, iom_data)
        except Exception:
            pass

    if not priorities:
        st.success("✅ No critical remediation actions needed.")
        return

    # Effort vs Impact matrix
    st.markdown("---")
    for p in priorities:
        rank = p.get("rank", 0)
        impact = p.get("impact", "MEDIUM")
        effort = p.get("effort", "Medium")
        category = p.get("category", "General")
        action = p.get("action", "")
        rationale = p.get("rationale", "")

        if impact == "CRITICAL":
            icon = "🔴"
        elif impact == "HIGH":
            icon = "🟠"
        else:
            icon = "🟡"

        st.markdown(f"### {icon} Priority {rank}: {category}")
        st.markdown(f"**Action:** {action}")
        col1, col2 = st.columns(2)
        col1.metric("Impact", impact)
        col2.metric("Effort", effort)
        st.caption(f"_Rationale: {rationale}_")
        st.markdown("---")

    # Summary table
    st.subheader("📊 Remediation Summary")
    df_priorities = pd.DataFrame(priorities)
    display_cols = [c for c in ["rank", "category", "action", "impact", "effort"] if c in df_priorities.columns]
    show_dataframe(df_priorities[display_cols], key="tbl_remediation")


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 4: Trend Forecast
# ═══════════════════════════════════════════════════════════════════════════════
def _render_forecast(brief, insights):
    """Render risk trend forecast and SLA breach prediction."""
    st.subheader("📈 Risk Trend Forecast")
    st.caption("7-day and 14-day projections based on linear trend analysis")

    forecast = brief.get("forecast") if brief else None

    if not forecast:
        try:
            from agent.weekly_brief import predict_sla_breaches
            history = load_json("history.json", [])
            forecast = predict_sla_breaches(history)
        except Exception:
            pass

    if not forecast:
        st.info("Not enough historical data for forecasting (need at least 7 days).")
        return

    # KPIs
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Current Risk", forecast.get("current_risk", 0))

    trend_dir = forecast.get("trend_direction", "stable")
    trend_icon = "📈" if trend_dir == "increasing" else "📉" if trend_dir == "decreasing" else "➡️"
    col2.metric("Trend", f"{trend_icon} {trend_dir.title()}")
    col3.metric("7-Day Forecast", forecast.get("forecast_7d", "N/A"))
    col4.metric("Breach Risk", forecast.get("breach_risk", "N/A"))

    st.markdown("---")

    # Forecast visualization
    history = load_json("history.json", [])
    if history and len(history) >= 7:
        recent = history[-14:]
        dates = [h.get("date", "") for h in recent]
        risk_values = [h.get("risk_score", 0) for h in recent]

        # Add forecast points
        from datetime import datetime, timedelta
        last_date = dates[-1] if dates else ""
        try:
            last_dt = datetime.fromisoformat(last_date)
            forecast_dates = [(last_dt + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(1, 8)]
        except Exception:
            forecast_dates = [f"+{i}d" for i in range(1, 8)]

        daily_change = forecast.get("daily_change", 0)
        forecast_values = [min(100, max(0, risk_values[-1] + daily_change * i)) for i in range(1, 8)]

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=dates, y=risk_values, mode="lines+markers",
                                  name="Actual", line=dict(color="#4488ff", width=2)))
        fig.add_trace(go.Scatter(x=forecast_dates, y=forecast_values, mode="lines+markers",
                                  name="Forecast", line=dict(color="#ff8800", width=2, dash="dash")))

        # Threshold lines
        fig.add_hline(y=50, line_dash="dot", line_color="#ffcc00",
                      annotation_text="Medium Risk Threshold")
        fig.add_hline(y=75, line_dash="dot", line_color="#ff4444",
                      annotation_text="High Risk Threshold")

        fig.update_layout(
            title="Risk Score — Actual vs Forecast",
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)", font_color="white",
            yaxis=dict(range=[0, 100], title="Risk Score"),
            xaxis=dict(title="Date"),
            height=400,
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")
    st.subheader("📊 Trend Details")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Daily Change Rate", f"{forecast.get('daily_change', 0):+.2f} pts/day")
        st.metric("14-Day Forecast", forecast.get("forecast_14d", "N/A"))
    with col2:
        breach_risk = forecast.get("breach_risk", "LOW")
        if breach_risk == "HIGH":
            st.error(f"⚠️ **SLA Breach Risk: HIGH** — Risk score projected to exceed 60 within 7 days")
        elif breach_risk == "MEDIUM":
            st.warning(f"🟡 **SLA Breach Risk: MEDIUM** — Monitor closely")
        else:
            st.success(f"✅ **SLA Breach Risk: LOW** — Trend is stable or improving")


# ═══════════════════════════════════════════════════════════════════════════════
# Tab 5: Coverage Analysis (original view)
# ═══════════════════════════════════════════════════════════════════════════════
def _render_coverage_analysis(insights):
    """Render the original coverage analysis view."""
    st.subheader("📊 Coverage Analysis")

    risk_score = insights.get("overall_risk_score", 0)
    stats = insights.get("stats", {})
    generated = insights.get("generated_at", "Unknown")

    # Header metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Overall Risk Score", f"{risk_score}/100")
    col2.metric("Total EC2 IPs", stats.get("total_ec2_ips", 0))
    col3.metric("Full Coverage", f"{stats.get('full_coverage_pct', 0)}%")
    col4.metric("Blind Spots", stats.get("completely_blind", 0))

    st.caption(f"Last generated: {generated}")
    st.markdown("---")

    # Risk gauge
    risk_color = "#44bb44" if risk_score < 25 else "#ffcc00" if risk_score < 50 else "#ff8800" if risk_score < 75 else "#ff4444"
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
        st.metric("Telemetry Coverage", f"{stats.get('telemetry_coverage_pct', 0)}%")
        st.metric("No EDR", stats.get("no_edr", 0))
        st.metric("No Vuln Scan", stats.get("no_vuln_scan", 0))

    # Coverage overlap diagram
    st.markdown("---")
    st.subheader("Coverage Overlap")
    coverage_data = {
        "Full Coverage (All Tools)": stats.get("full_coverage", 0),
        "EDR Only": max(0, stats.get("crowdstrike_coverage", 0) - stats.get("full_coverage", 0)),
        "Vuln Scan Only": max(0, stats.get("qualys_coverage", 0) - stats.get("full_coverage", 0)),
        "Completely Blind": stats.get("completely_blind", 0),
    }

    fig2 = px.pie(values=list(coverage_data.values()), names=list(coverage_data.keys()),
                  color_discrete_sequence=["#44bb44", "#4488ff", "#ffcc00", "#ff4444"])
    fig2.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", height=350)
    st.plotly_chart(fig2, use_container_width=True)

    # Priority Actions
    st.markdown("---")
    st.subheader("Priority Actions")
    actions = insights.get("priority_actions", [])
    if actions:
        df_actions = pd.DataFrame(actions)
        show_dataframe(df_actions, key="t_coverage_actions")

    # Coverage Gaps
    st.markdown("---")
    st.subheader("🕳️ Coverage Gaps")
    gaps = insights.get("coverage_gaps", [])
    if gaps:
        df_gaps = pd.DataFrame(gaps)
        gap_summary = df_gaps["gap_type"].value_counts()
        col1, col2, col3 = st.columns(3)
        col1.metric("No EDR", gap_summary.get("no_edr", 0))
        col2.metric("No Vuln Scan", gap_summary.get("no_vuln_scan", 0))
        col3.metric("Completely Blind", gap_summary.get("completely_blind", 0))

        with st.expander("📋 Gap Details"):
            show_dataframe(df_gaps, key="t_coverage_gaps")
    else:
        st.success("No coverage gaps detected!")


def _render_placeholder():
    """Show placeholder info when no insights exist."""
    st.info("""
    **Security Posture Agent** will analyze:
    
    - 🔍 **Coverage Gaps**: EC2 instances missing CrowdStrike AND/OR Qualys
    - ⚠️ **Anomaly Detection**: Coverage drops, new blind spots, risk spikes
    - 📈 **Trend Forecasting**: SLA breach prediction based on risk trajectory
    - 🎯 **Remediation Prioritization**: Internet-facing + critical vulns first
    - 📋 **Weekly Brief**: Natural language executive summary
    
    Click "Run Security Agent Now" above to generate insights.
    """)
