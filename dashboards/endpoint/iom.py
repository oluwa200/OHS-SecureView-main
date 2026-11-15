"""Endpoint Protection — IOM Analysis tab."""
import json
import os
import streamlit as st
import pandas as pd
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.dashboard_config import show_dataframe
import plotly.express as px

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")


def render_iom():
    iom_path = os.path.join(DATA_DIR, "crowdstrike_iom_analysis.json")

    if not os.path.exists(iom_path):
        st.warning("IOM data not available. Ensure CrowdStrike refresh is running.")
        return

    with open(iom_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    st.subheader("Indicators of Misconfiguration (IOM)")

    # Handle different possible structures
    ioms = data.get("ioms", data.get("findings", data.get("results", [])))
    if isinstance(data, list):
        ioms = data

    summary = data.get("summary", {})
    if summary:
        cols = st.columns(4)
        cols[0].metric("Total IOMs", summary.get("total", len(ioms)))
        cols[1].metric("Critical", summary.get("critical", summary.get("p1", 0)))
        cols[2].metric("High", summary.get("high", summary.get("p2", 0)))
        cols[3].metric("Medium", summary.get("medium", summary.get("p3", 0)))

    st.markdown("---")

    if isinstance(ioms, list) and len(ioms) > 0:
        df = pd.DataFrame(ioms)
        
        # Priority/severity distribution
        for col_name in ["priority", "severity", "impact_score"]:
            if col_name in df.columns:
                fig = px.histogram(df, x=col_name, title=f"IOM Distribution by {col_name.title()}",
                                  color_discrete_sequence=["#ff4444"])
                fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                                 plot_bgcolor="rgba(0,0,0,0)")
                st.plotly_chart(fig, use_container_width=True)
                break

        show_dataframe(df, key="tbl_3")
    elif isinstance(data, dict):
        # Show raw structure
        st.json(data)
    else:
        st.info("No IOM findings to display.")
