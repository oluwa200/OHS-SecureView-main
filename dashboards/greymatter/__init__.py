"""GreyMatter SOC (ReliaQuest) sub-dashboard.
Manual data entry + charts for SOC metrics: MTTR, Close Rate, Alert Funnel.
"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from config.dashboard_config import show_dataframe, DATA_DIR, load_json, TODAY

GREYMATTER_FILE = os.path.join(DATA_DIR, "greymatter_soc.json")


def render(go_home):
    """Render the GreyMatter SOC dashboard."""
    if st.button("← Back to Home", key="back_greymatter"):
        go_home()
        st.rerun()

    st.title("🛡️ GreyMatter SOC — Security Operations")
    st.caption("ReliaQuest Managed Detection & Response | Monthly Metrics")

    # Logo
    ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "assets")
    rq_logo = os.path.join(ASSETS_DIR, "RQ.png")
    if os.path.exists(rq_logo):
        st.image(rq_logo, width=150)

    gm_data = load_json("greymatter_soc.json", {})
    monthly = gm_data.get("monthly_data", [])

    tab1, tab2, tab3 = st.tabs([
        "📊 Dashboard",
        "📝 Enter Monthly Data",
        "📋 Raw Data",
    ])

    with tab1:
        _render_dashboard(monthly)
    with tab2:
        _render_data_entry(gm_data)
    with tab3:
        _render_raw_data(monthly)


def _render_dashboard(monthly):
    """Main SOC dashboard with charts."""
    if not monthly:
        st.warning("No SOC data available. Go to 'Enter Monthly Data' tab to add metrics.")
        return

    latest = monthly[-1]
    st.subheader(f"Security Operations Health — {latest.get('month', 'Current')}")

    # ─── KPI Row ──────────────────────────────────────────────────────────────
    st.markdown("---")
    col1, col2, col3, col4, col5 = st.columns(5)

    events = latest.get("events_processed", 0)
    if events >= 1_000_000_000:
        events_display = f"{events / 1_000_000_000:.1f}B"
    elif events >= 1_000_000:
        events_display = f"{events / 1_000_000:.0f}M"
    else:
        events_display = f"{events:,}"

    col1.metric("Events Processed", events_display)
    col2.metric("Correlated Alerts", latest.get("correlated_alerts", 0))
    col3.metric("Auto-Resolved", latest.get("auto_resolved", 0))
    col4.metric("True Positives", latest.get("true_positives", 0))
    col5.metric("Close Rate", f"{latest.get('close_rate_pct', 0)}%")

    st.markdown("---")

    # ─── Alert Funnel ─────────────────────────────────────────────────────────
    st.subheader("🔻 Alert Funnel")
    funnel_data = {
        "Events Processed": latest.get("events_processed", 0),
        "Correlated Alerts": latest.get("correlated_alerts", 0),
        "Auto-Resolved by SOC": latest.get("auto_resolved", 0),
        "Escalated (Human Review)": latest.get("escalated", 0),
        "True Positives": latest.get("true_positives", 0),
        "False Positives": latest.get("false_positives", 0),
    }

    col_funnel, col_breakdown = st.columns([2, 1])
    with col_funnel:
        fig_funnel = go.Figure(go.Funnel(
            y=list(funnel_data.keys()),
            x=list(funnel_data.values()),
            textinfo="value+percent initial",
            marker=dict(color=["#4488ff", "#ff8800", "#22c55e", "#ffcc00", "#ff4444", "#888888"]),
        ))
        fig_funnel.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            font_color="white", height=350,
        )
        st.plotly_chart(fig_funnel, use_container_width=True)

    with col_breakdown:
        st.metric("📡 Events", events_display)
        st.metric("🔔 Alerts After Correlation", latest.get("correlated_alerts", 0))
        st.metric("🤖 Auto-Resolved", latest.get("auto_resolved", 0))
        st.metric("👤 Escalated", latest.get("escalated", 0))
        st.metric("✅ True Positives", latest.get("true_positives", 0))
        st.metric("❌ False Positives", latest.get("false_positives", 0))

    st.markdown("---")

    # ─── MTTR Chart ───────────────────────────────────────────────────────────
    st.subheader("⏱️ Mean Time to Resolve (Days)")
    if len(monthly) >= 2:
        months = [m.get("month", "") for m in monthly]
        mttr_values = [m.get("mttr_days", 0) for m in monthly]

        fig_mttr = go.Figure()
        fig_mttr.add_trace(go.Bar(
            x=months, y=mttr_values,
            marker_color=["#ff8800" if v > 3 else "#22c55e" for v in mttr_values],
            text=mttr_values, textposition="outside",
        ))
        fig_mttr.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)", font_color="white",
            yaxis=dict(title="Days"), height=300,
        )
        st.plotly_chart(fig_mttr, use_container_width=True)

    st.markdown("---")

    # ─── Close Rate Chart ─────────────────────────────────────────────────────
    st.subheader("📈 Close Rate (%)")
    if len(monthly) >= 2:
        close_rates = [m.get("close_rate_pct", 0) for m in monthly]

        fig_close = go.Figure()
        fig_close.add_trace(go.Bar(
            x=months, y=close_rates,
            marker_color=["#22c55e" if v >= 95 else "#ff8800" if v >= 80 else "#ff4444" for v in close_rates],
            text=[f"{v}%" for v in close_rates], textposition="outside",
        ))
        fig_close.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)", font_color="white",
            yaxis=dict(title="%", range=[0, 110]), height=300,
        )
        st.plotly_chart(fig_close, use_container_width=True)

    st.markdown("---")

    # ─── Incidents Overview (Donut) ───────────────────────────────────────────
    st.subheader("🎯 Incident Classification")
    col_d1, col_d2 = st.columns(2)
    with col_d1:
        classification = {
            "Auto-Resolved": latest.get("auto_resolved", 0),
            "True Positives": latest.get("true_positives", 0),
            "False Positives": latest.get("false_positives", 0),
            "Anomalous Safe": latest.get("anomalous_safe", 0),
            "Pending": latest.get("pending_alerts", 0),
        }
        fig_donut = px.pie(
            values=list(classification.values()),
            names=list(classification.keys()),
            hole=0.5,
            color_discrete_sequence=["#22c55e", "#ff4444", "#888888", "#4488ff", "#ffcc00"],
        )
        fig_donut.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            font_color="white", height=350,
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    with col_d2:
        st.markdown("**Alert Stages:**")
        for stage, count in classification.items():
            st.markdown(f"- **{stage}:** {count}")
        st.markdown("---")
        total_alerts = latest.get("correlated_alerts", 0)
        auto_pct = round(latest.get("auto_resolved", 0) / total_alerts * 100) if total_alerts else 0
        st.metric("Automation Rate", f"{auto_pct}%",
                  help="Percentage of alerts resolved automatically without human intervention")

    # ─── Monthly Trend Table ──────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("📋 Monthly Trend")
    df = pd.DataFrame(monthly)
    display_cols = [c for c in ["month", "correlated_alerts", "auto_resolved", "escalated",
                                "true_positives", "false_positives", "mttr_days", "close_rate_pct"]
                    if c in df.columns]
    st.dataframe(df[display_cols], use_container_width=True, hide_index=True)


def _render_data_entry(gm_data):
    """Data entry form for monthly SOC metrics."""
    st.subheader("📝 Enter Monthly SOC Metrics")
    st.caption("Fill in the data from the ReliaQuest GreyMatter portal and click Save.")

    monthly = gm_data.get("monthly_data", [])

    st.markdown("---")

    # Month selector
    col_month, col_spacer = st.columns([2, 4])
    with col_month:
        month_input = st.text_input("Month (e.g. Jul 2026)", value=TODAY.strftime("%b %Y"), key="gm_month")

    st.markdown("---")
    st.markdown("**Core Metrics:**")

    col1, col2, col3 = st.columns(3)
    with col1:
        events = st.number_input("Events Processed", value=1700000000, step=100000000, key="gm_events")
        correlated = st.number_input("Correlated Alerts", value=0, step=1, key="gm_correlated")
        auto_resolved = st.number_input("Auto-Resolved by SOC", value=0, step=1, key="gm_auto")
    with col2:
        escalated = st.number_input("Escalated (Human Review)", value=0, step=1, key="gm_escalated")
        true_pos = st.number_input("True Positives", value=0, step=1, key="gm_true_pos")
        false_pos = st.number_input("False Positives", value=0, step=1, key="gm_false_pos")
    with col3:
        anomalous = st.number_input("Anomalous Safe", value=0, step=1, key="gm_anomalous")
        pending = st.number_input("Pending Alerts", value=0, step=1, key="gm_pending")
        mttr = st.number_input("MTTR (days)", value=2, step=1, key="gm_mttr")
        close_rate = st.number_input("Close Rate (%)", value=100, min_value=0, max_value=100, step=1, key="gm_close")

    st.markdown("---")

    if st.button("💾 Save Monthly Data", use_container_width=True, type="primary"):
        new_entry = {
            "month": month_input,
            "events_processed": int(events),
            "correlated_alerts": int(correlated),
            "auto_resolved": int(auto_resolved),
            "escalated": int(escalated),
            "true_positives": int(true_pos),
            "false_positives": int(false_pos),
            "anomalous_safe": int(anomalous),
            "pending_alerts": int(pending),
            "mttr_days": int(mttr),
            "close_rate_pct": int(close_rate),
        }

        # Update or append
        existing_idx = next((i for i, m in enumerate(monthly) if m.get("month") == month_input), None)
        if existing_idx is not None:
            monthly[existing_idx] = new_entry
            st.success(f"✅ Updated data for **{month_input}**")
        else:
            monthly.append(new_entry)
            st.success(f"✅ Added new entry for **{month_input}**")

        # Save to file
        gm_data["monthly_data"] = monthly
        gm_data["updated_at"] = TODAY.strftime("%Y-%m-%d")
        gm_data["current_month"] = month_input

        with open(GREYMATTER_FILE, "w", encoding="utf-8") as f:
            json.dump(gm_data, f, indent=2)

        st.rerun()

    # Show existing entries
    if monthly:
        st.markdown("---")
        st.subheader("📋 Existing Entries")
        st.caption("Click Save with the same month name to update an existing entry.")
        df = pd.DataFrame(monthly)
        st.dataframe(df, use_container_width=True, hide_index=True)


def _render_raw_data(monthly):
    """Show raw JSON data and allow CSV export."""
    st.subheader("📋 Raw Data")

    if not monthly:
        st.info("No data yet.")
        return

    df = pd.DataFrame(monthly)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # CSV export
    csv = df.to_csv(index=False)
    st.download_button("⬇️ Download CSV", csv,
                      f"greymatter_soc_{TODAY.strftime('%Y%m%d')}.csv",
                      "text/csv", use_container_width=True)

    # Raw JSON
    with st.expander("Raw JSON"):
        st.json(load_json("greymatter_soc.json", {}))
