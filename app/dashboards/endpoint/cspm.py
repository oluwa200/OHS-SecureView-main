"""Endpoint Protection — CSPM Findings tab."""
import json
import os
import streamlit as st
import pandas as pd
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.dashboard_config import show_dataframe

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")


def render_cspm():
    cspm_path = os.path.join(DATA_DIR, "crowdstrike_cspm_report.json")

    if not os.path.exists(cspm_path):
        st.warning("CSPM data not available. Ensure CrowdStrike refresh is running.")
        return

    with open(cspm_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data.get("findings", data.get("resources", []))
    if isinstance(data, list):
        findings = data

    if not findings:
        st.info("No CSPM findings found.")
        return

    st.subheader("Cloud Security Posture Findings")

    # If findings is a list of dicts
    if isinstance(findings, list) and len(findings) > 0:
        df = pd.DataFrame(findings)
        
        # Show summary
        total = len(df)
        st.metric("Total Findings", total)
        
        if "severity" in df.columns:
            severity_counts = df["severity"].value_counts()
            cols = st.columns(min(4, len(severity_counts)))
            for i, (sev, count) in enumerate(severity_counts.items()):
                if i < len(cols):
                    cols[i].metric(str(sev), count)

        st.markdown("---")
        show_dataframe(df, key="tbl_2")
    else:
        # Raw display if format is unexpected
        st.json(data)
