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
    save_ioc_scan,
)

from ioc_triage.ioc_utils import detect_ioc_type
from ioc_triage.vt_client import query_ip, query_domain, query_hash, query_url
from ioc_triage.abuseipdb_client import query_ip_abuse
from ioc_triage.verdict import score_verdict, score_combined_verdict

from log_enricher.ssh_log_parser import parse_log_file as parse_ssh_log
from log_enricher.brute_force_analyzer import events_to_dataframe as ssh_events_to_df, find_brute_force_ips
from log_enricher.enrich import enrich_ip_list

from phishing_analyzer.email_parser import parse_eml
from phishing_analyzer.risk_scorer import score_email
from database.db import save_phishing_scan

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
tab1, tab2, tab3, tab4 = st.tabs(["IOC Triage", "Log Analysis", "Phishing Analyzer", "🔍 Live Scan"])

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

with tab4:
    st.subheader("Run a Live Scan")
    scan_type = st.radio(
        "What do you want to scan?",
        ["IOC (IP / Domain / URL / Hash)", "SSH Auth Log", "Phishing Email (.eml)"],
        horizontal=True,
    )

    if scan_type == "IOC (IP / Domain / URL / Hash)":
        indicator = st.text_input("Enter an indicator", placeholder="e.g. 8.8.8.8")
        if st.button("Scan IOC") and indicator.strip():
            indicator = indicator.strip()
            ioc_type = detect_ioc_type(indicator)

            if ioc_type == "unknown":
                st.error(f"Could not recognize '{indicator}' as a valid IP, domain, URL, or hash.")
            else:
                with st.spinner(f"Querying threat intel for {indicator} ({ioc_type}) ..."):
                    if ioc_type == "ip":
                        vt_result = query_ip(indicator)
                        abuse_result = query_ip_abuse(indicator)
                        result = score_combined_verdict(vt_result, abuse_result)
                    elif ioc_type == "domain":
                        result = score_verdict(query_domain(indicator))
                    elif ioc_type == "url":
                        result = score_verdict(query_url(indicator))
                    else:
                        result = score_verdict(query_hash(indicator))
                        ioc_type = "hash"

                    save_ioc_scan(indicator, ioc_type, result["verdict"], result["reason"])

                verdict = result["verdict"]
                color = {"MALICIOUS": "red", "SUSPICIOUS": "orange", "CLEAN": "green"}.get(verdict, "gray")
                st.markdown(f"### Verdict: :{color}[{verdict}]")
                st.write(f"**Reason:** {result['reason']}")
                st.json(result)

    elif scan_type == "SSH Auth Log":
        uploaded_file = st.file_uploader("Upload an auth.log file", type=["log", "txt"])
        if uploaded_file and st.button("Analyze Log"):
            temp_path = "temp_uploaded_auth.log"
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getvalue())

            with st.spinner("Parsing and analyzing..."):
                events = parse_ssh_log(temp_path)
                df = ssh_events_to_df(events)
                brute_force = find_brute_force_ips(df)

            st.write(f"Parsed **{len(events)}** login events.")
            if brute_force.empty:
                st.success("No brute-force activity detected.")
            else:
                st.warning(f"{len(brute_force)} IP(s) flagged as brute-force sources:")
                st.dataframe(brute_force, use_container_width=True, hide_index=True)

                if st.button("Enrich flagged IPs with threat intel"):
                    with st.spinner("Querying threat intel..."):
                        enriched = enrich_ip_list(
                            brute_force["ip"].tolist(), log_type="ssh", source_file=uploaded_file.name
                        )
                    for r in enriched:
                        color = {"MALICIOUS": "red", "SUSPICIOUS": "orange", "CLEAN": "green"}.get(r["verdict"], "gray")
                        st.markdown(f"**{r['ip']}** - :{color}[{r['verdict']}] - {r['reason']}")

            os.remove(temp_path)

    else:  # Phishing Email
        uploaded_file = st.file_uploader("Upload a .eml file", type=["eml"])
        if uploaded_file and st.button("Analyze Email"):
            temp_path = "temp_uploaded_email.eml"
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getvalue())

            with st.spinner("Parsing and scoring..."):
                parsed_email = parse_eml(temp_path)
                risk_result = score_email(parsed_email)
                save_phishing_scan(
                    sender_email=parsed_email["from_email"],
                    subject=parsed_email["subject"],
                    verdict=risk_result["verdict"],
                    risk_score=risk_result["risk_score"],
                    reasons="; ".join(risk_result["reasons"]),
                )

            verdict = risk_result["verdict"]
            color = {"PHISHING": "red", "SUSPICIOUS": "orange", "LIKELY LEGITIMATE": "green"}.get(verdict, "gray")
            st.markdown(f"### Verdict: :{color}[{verdict}]  (Score: {risk_result['risk_score']}/100)")
            st.write(f"**From:** {parsed_email['from_display_name']} <{parsed_email['from_email']}>")
            st.write(f"**Subject:** {parsed_email['subject']}")
            st.write("**Reasons:**")
            for reason in risk_result["reasons"]:
                st.write(f"- {reason}")

            os.remove(temp_path)

st.divider()
st.caption("Built by Manish - SOC Automation Toolkit | Data refreshes on page reload")