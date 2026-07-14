"""
verdict.py
----------
Converts raw VirusTotal vote counts into a simple, actionable verdict:
MALICIOUS, SUSPICIOUS, or CLEAN.

The thresholds here are a starting point based on common SOC practice -
you can tune these later once you see real-world results and decide
they're too strict or too lenient. Being able to explain WHY you chose
these numbers is more important than the exact numbers themselves.
"""


def score_verdict(result: dict) -> dict:
    """
    Takes the dict returned by vt_client.query_ip() (or similar
    functions for other IOC types) and adds a 'verdict' and
    'reason' field to it.
    """
    if "error" in result:
        # Can't score something we failed to fetch data for
        result["verdict"] = "UNKNOWN"
        result["reason"] = result["error"]
        return result

    malicious = result.get("malicious_votes", 0)
    suspicious = result.get("suspicious_votes", 0)

    if malicious >= 3:
        result["verdict"] = "MALICIOUS"
        result["reason"] = f"{malicious} security vendors flagged this as malicious"
    elif malicious >= 1 or suspicious >= 1:
        result["verdict"] = "SUSPICIOUS"
        result["reason"] = (
            f"{malicious} vendor(s) flagged malicious, "
            f"{suspicious} flagged suspicious - worth manual review"
        )
    else:
        result["verdict"] = "CLEAN"
        result["reason"] = "No vendors flagged this indicator"

    return result


def score_combined_verdict(vt_result: dict, abuse_result: dict) -> dict:
    """
    Merges a VirusTotal result and an AbuseIPDB result into ONE
    final verdict. This mirrors real SOC enrichment - an analyst
    doesn't just trust one feed, they cross-reference multiple
    sources and reconcile disagreements.
    """
    combined = {
        "vt_malicious_votes": vt_result.get("malicious_votes", 0),
        "vt_suspicious_votes": vt_result.get("suspicious_votes", 0),
        "abuse_confidence_score": abuse_result.get("abuse_confidence_score", 0),
        "abuse_total_reports": abuse_result.get("total_reports", 0),
    }

    # If either source failed, we still want to show whatever DID work
    vt_failed = "error" in vt_result
    abuse_failed = "error" in abuse_result

    vt_malicious = vt_result.get("malicious_votes", 0)
    vt_suspicious = vt_result.get("suspicious_votes", 0)
    abuse_score = abuse_result.get("abuse_confidence_score", 0)

    reasons = []

    if vt_malicious >= 3 or abuse_score >= 75:
        combined["verdict"] = "MALICIOUS"
        if vt_malicious >= 3:
            reasons.append(f"VirusTotal: {vt_malicious} vendors flagged malicious")
        if abuse_score >= 75:
            reasons.append(f"AbuseIPDB: {abuse_score}% abuse confidence")

    elif vt_malicious >= 1 or vt_suspicious >= 1 or 25 <= abuse_score < 75:
        combined["verdict"] = "SUSPICIOUS"
        if vt_malicious >= 1 or vt_suspicious >= 1:
            reasons.append(
                f"VirusTotal: {vt_malicious} malicious / {vt_suspicious} suspicious votes"
            )
        if 25 <= abuse_score < 75:
            reasons.append(f"AbuseIPDB: {abuse_score}% abuse confidence (moderate)")

    else:
        combined["verdict"] = "CLEAN"
        reasons.append("No significant flags from either source")

    if vt_failed:
        reasons.append(f"(VirusTotal lookup failed: {vt_result['error']})")
    if abuse_failed:
        reasons.append(f"(AbuseIPDB lookup failed: {abuse_result['error']})")

    combined["reason"] = " | ".join(reasons)
    return combined


# Quick manual test with fake data - no API call needed
if __name__ == "__main__":
    test_cases = [
        {"indicator": "1.2.3.4", "malicious_votes": 5, "suspicious_votes": 2},
        {"indicator": "5.6.7.8", "malicious_votes": 1, "suspicious_votes": 0},
        {"indicator": "8.8.8.8", "malicious_votes": 0, "suspicious_votes": 0},
        {"error": "Rate limit hit. Wait a minute and try again."},
    ]
    for case in test_cases:
        scored = score_verdict(case)
        print(f"{scored.get('indicator', 'N/A'):15} -> {scored['verdict']:12} ({scored['reason']})")

    print("\n--- Combined verdict tests ---")
    combined_test_cases = [
        # Both sources agree it's bad
        ({"malicious_votes": 5, "suspicious_votes": 1}, {"abuse_confidence_score": 90, "total_reports": 50}),
        # Sources disagree - VT clean, AbuseIPDB flags it
        ({"malicious_votes": 0, "suspicious_votes": 0}, {"abuse_confidence_score": 80, "total_reports": 30}),
        # Both clean
        ({"malicious_votes": 0, "suspicious_votes": 0}, {"abuse_confidence_score": 0, "total_reports": 0}),
        # One source failed
        ({"error": "Rate limit hit"}, {"abuse_confidence_score": 10, "total_reports": 2}),
    ]
    for vt_case, abuse_case in combined_test_cases:
        result = score_combined_verdict(vt_case, abuse_case)
        print(f"{result['verdict']:12} -> {result['reason']}")