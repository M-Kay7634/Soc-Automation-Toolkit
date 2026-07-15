"""
main.py
-------
Command-line entry point for the IOC Triage Tool.

Usage:
    python main.py --ioc 8.8.8.8
    python main.py --ioc 45.155.205.233

Takes any indicator, detects its type, queries the relevant
threat intel sources, and prints a clean triage report -
exactly what a SOC analyst would want when investigating an alert.
"""

import argparse
import sys

from ioc_triage.ioc_utils import detect_ioc_type
from ioc_triage.vt_client import query_ip, query_domain, query_hash, query_url
from ioc_triage.abuseipdb_client import query_ip_abuse
from ioc_triage.verdict import score_verdict, score_combined_verdict
from database.db import init_db, save_ioc_scan


def print_report(indicator: str, ioc_type: str, result: dict) -> None:
    """
    Prints a clean, readable triage report to the terminal.
    Formatting output well matters - a SOC analyst under time
    pressure needs to read a verdict in 2 seconds, not parse a
    wall of raw JSON.
    """
    print("\n" + "=" * 50)
    print(f"  IOC TRIAGE REPORT")
    print("=" * 50)
    print(f"  Indicator : {indicator}")
    print(f"  Type      : {ioc_type}")
    print(f"  Verdict   : {result.get('verdict', 'UNKNOWN')}")
    print(f"  Reason    : {result.get('reason', 'N/A')}")
    print("-" * 50)

    if ioc_type == "ip":
        # IP lookups have both VT and AbuseIPDB data (combined verdict)
        print(f"  VirusTotal malicious votes : {result.get('vt_malicious_votes', 'N/A')}")
        print(f"  VirusTotal suspicious votes: {result.get('vt_suspicious_votes', 'N/A')}")
        print(f"  AbuseIPDB confidence score : {result.get('abuse_confidence_score', 'N/A')}%")
        print(f"  AbuseIPDB total reports    : {result.get('abuse_total_reports', 'N/A')}")
    else:
        # Domain/hash/url lookups only have VT data (AbuseIPDB is IP-only)
        print(f"  VirusTotal malicious votes : {result.get('malicious_votes', 'N/A')}")
        print(f"  VirusTotal suspicious votes: {result.get('suspicious_votes', 'N/A')}")
        if ioc_type == "hash":
            print(f"  File type : {result.get('file_type', 'N/A')}")
            print(f"  Known names: {result.get('names', [])}")
        if ioc_type == "domain":
            print(f"  Reputation score: {result.get('reputation', 'N/A')}")
        if ioc_type == "url":
            print(f"  Page title: {result.get('title', 'N/A')}")

    print("=" * 50 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="SOC IOC Triage Tool - checks an indicator against VirusTotal and AbuseIPDB"
    )
    parser.add_argument(
        "--ioc",
        required=True,
        help="The indicator to check: an IP address, domain, URL, or file hash",
    )
    args = parser.parse_args()

    indicator = args.ioc.strip()

    init_db()  # creates tables on first run, no-op if they already exist

    if not indicator:
        print("Error: --ioc cannot be empty.")
        sys.exit(1)

    ioc_type = detect_ioc_type(indicator)

    if ioc_type == "unknown":
        print(f"Could not recognize '{indicator}' as a valid IP, domain, URL, or hash.")
        sys.exit(1)

    print(f"Querying threat intel sources for {indicator} ({ioc_type}) ...")

    if ioc_type == "ip":
        # IPs get the full treatment: both VT and AbuseIPDB, combined verdict
        vt_result = query_ip(indicator)
        abuse_result = query_ip_abuse(indicator)
        combined = score_combined_verdict(vt_result, abuse_result)
        print_report(indicator, ioc_type, combined)
        save_ioc_scan(indicator, ioc_type, combined["verdict"], combined["reason"])

    elif ioc_type == "domain":
        vt_result = query_domain(indicator)
        scored = score_verdict(vt_result)
        print_report(indicator, ioc_type, scored)
        save_ioc_scan(indicator, ioc_type, scored["verdict"], scored["reason"])

    elif ioc_type == "url":
        vt_result = query_url(indicator)
        scored = score_verdict(vt_result)
        print_report(indicator, ioc_type, scored)
        save_ioc_scan(indicator, ioc_type, scored["verdict"], scored["reason"])

    elif ioc_type in ("md5", "sha1", "sha256"):
        vt_result = query_hash(indicator)
        scored = score_verdict(vt_result)
        print_report(indicator, "hash", scored)
        save_ioc_scan(indicator, "hash", scored["verdict"], scored["reason"])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Lets the user Ctrl+C out cleanly instead of seeing a traceback
        print("\nCancelled by user.")
        sys.exit(130)
    except Exception as e:
        # Last-resort safety net - a real tool should never crash with
        # a raw Python traceback in front of a user. Log it cleanly instead.
        print(f"\nUnexpected error: {e}")
        sys.exit(1)