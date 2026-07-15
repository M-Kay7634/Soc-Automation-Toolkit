"""
app.py
------
Streamlit dashboard for the SOC Automation Toolkit. Reads directly
from the SQLite database populated by the other three modules and
presents a unified, visual view of everything scanned so far.

Run with:
    streamlit run dashboard/app.py
(run from the project root)
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import pandas as pd

from database.db import (
    init_db,
    get_recent_ioc_scans,
    get_recent_log_analyses,
    get_recent_phishing_scans,
    get_verdict_counts,
)

st.set_page_config(page_title="SOC Automation Toolkit", layout="wide")

init_db()

st.title("🛡️ SOC Automation Toolkit Dashboard")
st.caption("Unified view across IOC Triage, Log Analysis, and Phishing Detection")

# --- Summary metrics row ---
counts = get_verdict_counts()

malicious_total = (
    counts.get("ioc_scans:MALICIOUS", 0)
    + counts.get("log_analyses:MALICIOUS", 0)
    + counts.get("phishing_scans:PHISHING", 0)
)
suspicious_total = (
    counts.get("ioc_scans:SUSPICIOUS", 0)
    + counts.get("log_analyses:SUSPICIOUS", 0)
    + counts.get("phishing_scans:SUSPICIOUS", 0)
)
clean_total = (
    counts.get("ioc_scans:CLEAN", 0)
    + counts.get("log_analyses:CLEAN", 0)
    + counts.get("phishing_scans:LIKELY LEGITIMATE", 0)
)

col1, col2, col3, col4 = st.columns(4)
col1.metric("🔴 Malicious/Phishing", malicious_total)
col2.metric("🟠 Suspicious", suspicious_total)
col3.metric("🟢 Clean/Legitimate", clean_total)
col4.metric("📊 Total Scans", malicious_total + suspicious_total + clean_total)

st.divider()

# --- Three tabs, one per module ---
tab1, tab2, tab3 = st.tabs(["IOC Triage", "Log Analysis", "Phishing Analyzer"])

with tab1:
    st.subheader("Recent IOC Scans")
    ioc_scans = get_recent_ioc_scans(limit=50)
    if ioc_scans:
        df = pd.DataFrame(ioc_scans)
        st.dataframe(df, use_container_width=True, hide_index=True)

        st.subheader("Verdict Distribution")
        verdict_counts = df["verdict"].value_counts()
        st.bar_chart(verdict_counts)
    else:
        st.info("No IOC scans yet. Run `python main.py --ioc <indicator>` to get started.")

with tab2:
    st.subheader("Recent Log Analysis Results")
    log_results = get_recent_log_analyses(limit=50)
    if log_results:
        df = pd.DataFrame(log_results)
        st.dataframe(df, use_container_width=True, hide_index=True)

        col_a, col_b = st.columns(2)
        with col_a:
            st.subheader("By Log Type")
            st.bar_chart(df["log_type"].value_counts())
        with col_b:
            st.subheader("By Verdict")
            st.bar_chart(df["verdict"].value_counts())
    else:
        st.info("No log analyses yet. Run one of the log_enricher pipelines to get started.")

with tab3:
    st.subheader("Recent Phishing Scans")
    phishing_scans = get_recent_phishing_scans(limit=50)
    if phishing_scans:
        df = pd.DataFrame(phishing_scans)
        st.dataframe(df, use_container_width=True, hide_index=True)

        st.subheader("Risk Score Distribution")
        st.bar_chart(df.set_index("sender_email")["risk_score"])
    else:
        st.info("No phishing scans yet. Run the phishing_pipeline to get started.")

st.divider()
st.caption("Built by Manish - SOC Automation Toolkit | Data refreshes on page reload")