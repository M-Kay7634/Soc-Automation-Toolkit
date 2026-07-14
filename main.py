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
from ioc_triage.vt_client import query_ip
from ioc_triage.abuseipdb_client import query_ip_abuse
from ioc_triage.verdict import score_combined_verdict


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
    print(f"  VirusTotal malicious votes : {result.get('vt_malicious_votes', 'N/A')}")
    print(f"  VirusTotal suspicious votes: {result.get('vt_suspicious_votes', 'N/A')}")
    print(f"  AbuseIPDB confidence score : {result.get('abuse_confidence_score', 'N/A')}%")
    print(f"  AbuseIPDB total reports    : {result.get('abuse_total_reports', 'N/A')}")
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
    ioc_type = detect_ioc_type(indicator)

    if ioc_type == "unknown":
        print(f"Could not recognize '{indicator}' as a valid IP, domain, URL, or hash.")
        sys.exit(1)

    if ioc_type != "ip":
        # URL/domain/hash support comes in the next module piece
        print(
            f"Detected type: {ioc_type}. Support for this type is coming soon - "
            f"currently only IP addresses are fully supported."
        )
        sys.exit(0)

    print(f"Querying threat intel sources for {indicator} ...")
    vt_result = query_ip(indicator)
    abuse_result = query_ip_abuse(indicator)

    combined = score_combined_verdict(vt_result, abuse_result)
    print_report(indicator, ioc_type, combined)


if __name__ == "__main__":
    main()