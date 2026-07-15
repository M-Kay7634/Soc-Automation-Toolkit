"""
risk_scorer.py
---------------
Combines multiple weak signals into one phishing risk verdict.
No single signal proves phishing on its own - a failed SPF check
alone could be a misconfigured legitimate sender. But SPF fail +
urgency language + a mismatched link domain together is a strong
case. This mirrors how real analysts (and real phishing filters)
reason about ambiguous evidence.
"""

import re

# Common urgency/pressure phrases used to manipulate victims into
# acting without thinking - a hallmark of social engineering
URGENCY_PHRASES = [
    r"urgent", r"immediately", r"act now", r"final warning",
    r"suspend(ed)?", r"verify your (account|identity)",
    r"within 24 hours", r"failure to act", r"click here",
]

# Free URL shorteners are commonly abused in phishing to hide the
# real destination - not inherently malicious, but worth flagging
SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".click", ".work", ".gq", ".tk"]


def score_email(parsed_email: dict) -> dict:
    """
    Takes the dict from email_parser.parse_eml() and returns a
    risk assessment with a verdict, numeric score, and the
    specific reasons that contributed to it.
    """
    score = 0
    reasons = []

    auth = parsed_email["auth_results"]

    # Auth failures are the strongest signal - a failed DMARC with
    # a reject policy means the sender's own domain doesn't want
    # this email trusted
    if auth["spf"] == "fail":
        score += 25
        reasons.append("SPF check failed - sender IP not authorized for this domain")
    if auth["dkim"] == "fail":
        score += 25
        reasons.append("DKIM check failed - email signature invalid or missing")
    if auth["dmarc"] == "fail":
        score += 30
        reasons.append("DMARC check failed - sender domain policy violated")

    # Urgency language - social engineering pressure tactics
    body_and_subject = (parsed_email["subject"] + " " + parsed_email["body_preview"]).lower()
    urgency_hits = [p for p in URGENCY_PHRASES if re.search(p, body_and_subject)]
    if urgency_hits:
        score += min(len(urgency_hits) * 5, 20)  # cap contribution at 20
        reasons.append(f"Urgency/pressure language detected ({len(urgency_hits)} phrase(s))")

    # Domain mismatch - does the link domain match the sender domain?
    # A PayPal email linking to a random domain is a huge red flag
    sender_domain = parsed_email["from_domain"]
    for url_domain in parsed_email["url_domains"]:
        if sender_domain not in url_domain and url_domain not in sender_domain:
            score += 15
            reasons.append(f"Link domain ({url_domain}) does not match sender domain ({sender_domain})")
            break  # only count this once even if multiple mismatched links

    # Suspicious TLDs in any embedded link
    for url_domain in parsed_email["url_domains"]:
        if any(url_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            score += 10
            reasons.append(f"Link uses a commonly-abused TLD: {url_domain}")
            break

    # Typosquatting heuristic - sender domain looks similar to a
    # well-known brand but isn't quite right (basic check: digit
    # substituted for a letter, e.g. paypa1 instead of paypal)
    if re.search(r"[a-z]*\d[a-z]*-?(security|support|verify|account)", sender_domain):
        score += 15
        reasons.append(f"Sender domain shows possible typosquatting pattern: {sender_domain}")

    score = min(score, 100)  # cap at 100

    if score >= 60:
        verdict = "PHISHING"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY LEGITIMATE"

    return {
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons,
    }


# Quick manual test
if __name__ == "__main__":
    from email_parser import parse_eml

    for filename in ["sample_emails/phishing_sample.eml", "sample_emails/legit_sample.eml"]:
        parsed = parse_eml(filename)
        result = score_email(parsed)
        print(f"\n{filename}")
        print(f"  Verdict: {result['verdict']} (score: {result['risk_score']}/100)")
        for reason in result["reasons"]:
            print(f"    - {reason}")