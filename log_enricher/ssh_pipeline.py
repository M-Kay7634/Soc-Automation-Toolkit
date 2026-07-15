"""
ssh_pipeline.py
----------------
Full end-to-end pipeline for SSH auth log analysis:
  1. Parse raw log file into structured events
  2. Detect brute-force source IPs and check for compromised accounts
  3. Enrich flagged IPs with threat intel (VirusTotal + AbuseIPDB)
  4. Print a complete analyst-ready report

Usage:
    python -m log_enricher.ssh_pipeline --logfile log_enricher/sample_logs/auth.log
"""

import argparse
import sys

from log_enricher.ssh_log_parser import parse_log_file
from log_enricher.brute_force_analyzer import (
    events_to_dataframe,
    find_brute_force_ips,
    find_compromised_accounts,
)
from log_enricher.enrich import enrich_ip_list, print_enrichment_report
from database.db import init_db


def main():
    parser = argparse.ArgumentParser(
        description="SSH Auth Log Analysis Pipeline - detects and enriches brute-force IPs"
    )
    parser.add_argument("--logfile", required=True, help="Path to the auth.log file to analyze")
    args = parser.parse_args()

    init_db()

    print(f"Parsing {args.logfile} ...")
    events = parse_log_file(args.logfile)
    print(f"Parsed {len(events)} recognized login events.\n")

    if not events:
        print("No recognized SSH login events found in this file.")
        sys.exit(0)

    df = events_to_dataframe(events)

    print("=== Brute Force Detection ===")
    brute_force_df = find_brute_force_ips(df)
    if brute_force_df.empty:
        print(f"No IPs crossed the brute-force threshold.\n")
    else:
        print(brute_force_df.to_string(index=False))
        print()

    print("=== Compromised Account Check ===")
    compromised = find_compromised_accounts(df)
    if compromised.empty:
        print("No successful logins from IPs with prior failed attempts.\n")
    else:
        print("WARNING - possible compromise detected:")
        print(compromised.to_string(index=False))
        print()

    if not brute_force_df.empty:
        print("=== Enriching Flagged IPs with Threat Intel ===")
        flagged_ips = brute_force_df["ip"].tolist()
        enriched = enrich_ip_list(flagged_ips, log_type="ssh", source_file=args.logfile)
        print_enrichment_report(enriched)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)