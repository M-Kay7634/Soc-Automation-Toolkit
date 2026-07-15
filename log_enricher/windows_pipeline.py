"""
windows_pipeline.py
----------------------
Full end-to-end pipeline for Windows Security Event Log analysis:
  1. Load exported event CSV
  2. Detect brute force, compromise, and post-compromise activity
  3. Enrich attacker IPs with threat intel (reusing Module 1's clients)
  4. Print a complete analyst-ready incident report

Usage:
    python -m log_enricher.windows_pipeline --logfile log_enricher/sample_logs/windows_events.csv
"""

import argparse
import sys

from log_enricher.windows_log_analyzer import (
    load_events,
    find_brute_force_accounts,
    find_compromised_accounts,
    find_post_compromise_activity,
)
from log_enricher.enrich import enrich_ip_list, print_enrichment_report
from database.db import init_db


def main():
    parser = argparse.ArgumentParser(
        description="Windows Event Log Analysis Pipeline - detects and enriches attack chains"
    )
    parser.add_argument("--logfile", required=True, help="Path to the exported event CSV")
    args = parser.parse_args()

    init_db()

    print(f"Loading {args.logfile} ...")
    df = load_events(args.logfile)
    print(f"Loaded {len(df)} events.\n")

    print("=== Brute Force Detection ===")
    brute_force = find_brute_force_accounts(df)
    if brute_force.empty:
        print("None detected.\n")
    else:
        print(brute_force.to_string(index=False))
        print()

    print("=== Compromised Account Check ===")
    compromised = find_compromised_accounts(df)
    if compromised.empty:
        print("None detected.\n")
    else:
        print(compromised.to_string(index=False))
        print()

    print("=== Post-Compromise Activity ===")
    post_compromise = find_post_compromise_activity(df, compromised)
    if post_compromise.empty:
        print("None detected.\n")
    else:
        print("CRITICAL - follow-on attacker activity detected:")
        print(post_compromise.to_string(index=False))
        print()

    if not compromised.empty:
        # Only enrich real, public-facing attacker IPs - skip internal ones
        attacker_ips = compromised["SourceIP"].unique().tolist()
        print("=== Enriching Attacker IPs with Threat Intel ===")
        enriched = enrich_ip_list(attacker_ips, log_type="windows", source_file=args.logfile)
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