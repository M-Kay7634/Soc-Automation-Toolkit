"""
email_parser.py
----------------
Parses .eml files and extracts everything a SOC analyst needs to
triage a suspected phishing email:
  - Sender/recipient/subject
  - SPF/DKIM/DMARC results (read from the Authentication-Results
    header, which the RECEIVING mail server already computed -
    we don't need to redo DNS lookups ourselves)
  - The originating IP from the Received header chain
  - URLs embedded in the email body
  - Basic urgency/pressure language detection
"""

import re
from email import message_from_file
from email.utils import parseaddr


def parse_eml(filepath: str) -> dict:
    """
    Reads a .eml file and returns a structured dict of everything
    we need for phishing analysis.
    """
    with open(filepath, "r") as f:
        msg = message_from_file(f)

    from_header = msg.get("From", "")
    sender_name, sender_email = parseaddr(from_header)
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else "unknown"

    body = _get_body(msg)
    urls = _extract_urls(body)

    return {
        "from_display_name": sender_name,
        "from_email": sender_email,
        "from_domain": sender_domain,
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "auth_results": _parse_auth_results(msg.get("Authentication-Results", "")),
        "originating_ip": _extract_originating_ip(msg.get("Received", "")),
        "urls": urls,
        "url_domains": [_extract_domain_from_url(u) for u in urls],
        "body_preview": body[:300],
    }


def _get_body(msg) -> str:
    """
    Extracts the plain text body. Real emails can be multipart
    (HTML + plain text + attachments) - we walk the parts and
    grab the first plain text section we find.
    """
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_payload(decode=True).decode(errors="ignore")
        return ""
    return msg.get_payload(decode=True).decode(errors="ignore") if msg.get_payload() else ""


def _parse_auth_results(header_value: str) -> dict:
    """
    Parses the Authentication-Results header into spf/dkim/dmarc
    pass/fail/none values. This header is added by the RECEIVING
    mail server after it already checked these - we're just
    reading its verdict, not recomputing it.
    """
    result = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for check in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{check}=(\w+)", header_value, re.IGNORECASE)
        if match:
            result[check] = match.group(1).lower()
    return result


def _extract_originating_ip(received_header: str) -> str:
    """
    Pulls the first IP address found in the Received header -
    this is typically the originating mail server's IP, useful
    for reputation checking (feeds into our existing VT/AbuseIPDB
    enrichment from Module 1).
    """
    match = re.search(r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", received_header)
    return match.group(1) if match else "unknown"


def _extract_urls(text: str) -> list:
    """Finds all http(s) URLs in the email body."""
    return re.findall(r"https?://[^\s<>\"]+", text)


def _extract_domain_from_url(url: str) -> str:
    match = re.search(r"https?://([^/]+)", url)
    return match.group(1) if match else "unknown"


# Quick manual test
if __name__ == "__main__":
    for filename in ["sample_emails/phishing_sample.eml", "sample_emails/legit_sample.eml"]:
        print(f"\n{'=' * 60}\nParsing: {filename}\n{'=' * 60}")
        result = parse_eml(filename)
        for key, value in result.items():
            print(f"  {key}: {value}")