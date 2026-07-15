"""
web_pipeline.py
-----------------
Full end-to-end pipeline for web server access log analysis:
  1. Parse raw access log into structured events
  2. Detect SQLi, path traversal, and scanner activity per IP
  3. Enrich flagged IPs with threat intel (reusing Module 1's clients)
  4. Print a complete analyst-ready report

Usage:
    python -m log_enricher.web_pipeline --logfile log_enricher/sample_logs/access.log
"""

import argparse
import sys

from log_enricher.web_log_parser import parse_log_file
from log_enricher.web_log_analyzer import (
    events_to_dataframe,
    summarize_attackers,
    classify_severity,
)
from log_enricher.enrich import enrich_ip_list, print_enrichment_report


def main():
    parser = argparse.ArgumentParser(
        description="Web Server Log Analysis Pipeline - detects and enriches attacking IPs"
    )
    parser.add_argument("--logfile", required=True, help="Path to the access.log file to analyze")
    args = parser.parse_args()

    print(f"Parsing {args.logfile} ...")
    events = parse_log_file(args.logfile)
    print(f"Parsed {len(events)} log lines.\n")

    if not events:
        print("No log lines could be parsed from this file.")
        sys.exit(0)

    df = events_to_dataframe(events)

    print("=== Attack Pattern Summary ===")
    summary = summarize_attackers(df)
    if summary.empty:
        print("No suspicious activity detected.\n")
        return

    summary["severity"] = summary.apply(classify_severity, axis=1)
    print(summary.to_string(index=False))
    print()

    print("=== Enriching Flagged IPs with Threat Intel ===")
    flagged_ips = summary["ip"].tolist()
    enriched = enrich_ip_list(flagged_ips)
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