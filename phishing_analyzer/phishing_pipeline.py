"""
phishing_pipeline.py
----------------------
Full end-to-end phishing analysis pipeline:
  1. Parse the .eml file (headers, auth results, links)
  2. Score phishing risk based on multiple weak signals
  3. Enrich the sender domain and any embedded URLs using
     VirusTotal (reusing Module 1's clients - same reuse pattern
     as the log_enricher module)
  4. Print a complete analyst-ready report

Usage:
    python -m phishing_analyzer.phishing_pipeline --eml phishing_analyzer/sample_emails/phishing_sample.eml
"""

import argparse
import sys

from phishing_analyzer.email_parser import parse_eml
from phishing_analyzer.risk_scorer import score_email

from ioc_triage.vt_client import query_domain, query_url
from database.db import init_db, save_phishing_scan


def enrich_email_indicators(parsed_email: dict) -> dict:
    """
    Checks the sender's domain and any embedded URLs against
    VirusTotal - reusing the exact same client built in Module 1.
    """
    enrichment = {"domain_check": None, "url_checks": []}

    domain_result = query_domain(parsed_email["from_domain"])
    enrichment["domain_check"] = domain_result

    for url in parsed_email["urls"]:
        url_result = query_url(url)
        enrichment["url_checks"].append({"url": url, "result": url_result})

    return enrichment


def print_report(parsed_email: dict, risk_result: dict, enrichment: dict) -> None:
    print("\n" + "=" * 60)
    print("  PHISHING EMAIL ANALYSIS REPORT")
    print("=" * 60)
    print(f"  From      : {parsed_email['from_display_name']} <{parsed_email['from_email']}>")
    print(f"  Subject   : {parsed_email['subject']}")
    print(f"  Date      : {parsed_email['date']}")
    print(f"  Orig. IP  : {parsed_email['originating_ip']}")
    print("-" * 60)
    print(f"  VERDICT   : {risk_result['verdict']}")
    print(f"  Risk Score: {risk_result['risk_score']}/100")
    print("  Reasons:")
    for reason in risk_result["reasons"]:
        print(f"    - {reason}")
    print("-" * 60)

    auth = parsed_email["auth_results"]
    print(f"  SPF: {auth['spf']:8} DKIM: {auth['dkim']:8} DMARC: {auth['dmarc']}")
    print("-" * 60)

    domain_check = enrichment["domain_check"]
    if "error" not in domain_check:
        mal = domain_check.get("malicious_votes", 0)
        print(f"  Sender domain VT check: {mal} vendors flagged malicious")
    else:
        print(f"  Sender domain VT check: {domain_check['error']}")

    for check in enrichment["url_checks"]:
        result = check["result"]
        if "error" not in result:
            mal = result.get("malicious_votes", 0)
            print(f"  URL check ({check['url'][:50]}...): {mal} vendors flagged malicious")
        else:
            print(f"  URL check ({check['url'][:50]}...): {result['error']}")

    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Analyzer - triages .eml files using header analysis and threat intel"
    )
    parser.add_argument("--eml", required=True, help="Path to the .eml file to analyze")
    args = parser.parse_args()

    init_db()

    print(f"Parsing {args.eml} ...")
    parsed_email = parse_eml(args.eml)

    print("Scoring phishing risk ...")
    risk_result = score_email(parsed_email)

    print("Enriching sender domain and URLs with threat intel ...")
    enrichment = enrich_email_indicators(parsed_email)

    print_report(parsed_email, risk_result, enrichment)

    save_phishing_scan(
        sender_email=parsed_email["from_email"],
        subject=parsed_email["subject"],
        verdict=risk_result["verdict"],
        risk_score=risk_result["risk_score"],
        reasons="; ".join(risk_result["reasons"]),
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)