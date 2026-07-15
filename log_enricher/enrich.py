"""
enrich.py
---------
Takes IPs flagged as brute-force sources and enriches them using
the SAME VirusTotal / AbuseIPDB clients built in Module 1
(ioc_triage/). This is intentional reuse - we're not rewriting
API logic, just applying it to a new use case (log analysis
instead of manual IOC lookup).
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from ioc_triage.vt_client import query_ip
from ioc_triage.abuseipdb_client import query_ip_abuse
from ioc_triage.verdict import score_combined_verdict
from database.db import save_log_analysis


def enrich_ip_list(ip_list: list, log_type: str = "unknown", source_file: str = "unknown") -> list:
    """
    Given a list of IPs (e.g. from find_brute_force_ips), queries
    threat intel for each one and returns enriched results with
    a final verdict attached. Also persists each result to the
    database so it shows up in historical/dashboard views.

    log_type and source_file are passed in by the calling pipeline
    (ssh/web/windows) purely for record-keeping context - they
    don't affect the enrichment logic itself.
    """
    enriched_results = []

    for ip in ip_list:
        print(f"  Enriching {ip} ...")
        vt_result = query_ip(ip)
        abuse_result = query_ip_abuse(ip)
        combined = score_combined_verdict(vt_result, abuse_result)
        combined["ip"] = ip
        enriched_results.append(combined)

        save_log_analysis(
            log_type=log_type,
            source_file=source_file,
            attacker_ip=ip,
            verdict=combined["verdict"],
            severity="",  # populated by callers that track severity (e.g. web logs)
            details=combined["reason"],
        )

    return enriched_results


def print_enrichment_report(enriched_results: list) -> None:
    """
    Prints a clean summary tying local log evidence together
    with external threat intel reputation.
    """
    print("\n" + "=" * 60)
    print("  BRUTE FORCE IP ENRICHMENT REPORT")
    print("=" * 60)
    for r in enriched_results:
        print(f"  IP: {r['ip']}")
        print(f"    Verdict        : {r['verdict']}")
        print(f"    Reason         : {r['reason']}")
        print(f"    VT malicious   : {r.get('vt_malicious_votes', 'N/A')}")
        print(f"    AbuseIPDB score: {r.get('abuse_confidence_score', 'N/A')}%")
        print("-" * 60)
    print("=" * 60 + "\n")


# Quick manual test
if __name__ == "__main__":
    # Using real IPs from our sample log for the test
    test_ips = ["45.155.205.233", "192.168.1.50"]
    results = enrich_ip_list(test_ips)
    print_enrichment_report(results)